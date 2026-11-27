//! `kubectl exec` target resolution.
//!
//! Port of release-1.35:
//! * `staging/src/k8s.io/kubectl/pkg/cmd/exec/exec.go` `ExecOptions.Complete/Validate/Run`
//!   (`TYPE/NAME` and `-f` targets, completed-pod check, `-q`, `--pod-running-timeout`);
//! * `pkg/polymorphichelpers/attachablepodforobject.go` `attachablePodForObject`;
//! * `pkg/polymorphichelpers/helpers.go` `SelectorsForObject`, `GetPodList`, `GetFirstPod`;
//! * `pkg/util/podutils/podutils.go` `ActivePods` (sorted in reverse);
//! * `pkg/cmd/util/podcmd/podcmd.go` `FindOrDefaultContainerByName`;
//! * `pkg/cmd/util/helpers.go` `GetPodRunningTimeoutFlag`.

use crate::websocket;
use anyhow::{anyhow, bail, Result};
use futures::StreamExt;
use kubernetes_rs_client::http::ApiClient;
use serde_json::Value;
use std::cmp::Ordering;
use std::time::Duration;

/// `defaultPodExecTimeout`.
pub const DEFAULT_POD_EXEC_TIMEOUT: &str = "1m0s";
/// `podcmd.DefaultContainerAnnotationName`.
pub const DEFAULT_CONTAINER_ANNOTATION_NAME: &str = "kubectl.kubernetes.io/default-container";

/// Parse a Go `time.Duration` string ("5s", "2m", "1h30m", "1m0s", "500ms").
pub fn parse_go_duration(s: &str) -> Result<Duration> {
    let orig = s;
    let mut rest = s.trim();
    if rest.is_empty() {
        bail!("invalid duration \"{orig}\"");
    }
    let neg = rest.starts_with('-');
    rest = rest.trim_start_matches(['-', '+']);
    if rest == "0" {
        return Ok(Duration::ZERO);
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let num_end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        if num_end == 0 {
            bail!("invalid duration \"{orig}\"");
        }
        let n: f64 = rest[..num_end]
            .parse()
            .map_err(|_| anyhow!("invalid duration \"{orig}\""))?;
        rest = &rest[num_end..];
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let mult = match &rest[..unit_end] {
            "ns" => 1e-9,
            "us" | "\u{b5}s" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "" => bail!("missing unit in duration \"{orig}\""),
            u => bail!("unknown unit \"{u}\" in duration \"{orig}\""),
        };
        total += n * mult;
        rest = &rest[unit_end..];
    }
    if neg {
        // Callers treat a non-positive timeout as invalid.
        return Ok(Duration::ZERO);
    }
    Ok(Duration::from_secs_f64(total))
}

/// `GetPodRunningTimeoutFlag`.
pub fn pod_running_timeout(flag: &str) -> Result<Duration> {
    let d = parse_go_duration(flag)?;
    if d.is_zero() {
        bail!("--pod-running-timeout must be higher than zero");
    }
    Ok(d)
}

/// `labels.Selector.String()` of `metav1.LabelSelectorAsSelector(selector)`:
/// requirements sorted by key, joined with `,`.
fn label_selector_string(sel: Option<&Value>) -> Result<String> {
    // A nil selector selects nothing (`labels.Nothing()`); upstream prints "" for it.
    let Some(sel) = sel.filter(|s| !s.is_null()) else {
        return Ok(String::new());
    };
    let mut reqs: Vec<(String, String)> = Vec::new();
    if let Some(ml) = sel.get("matchLabels").and_then(Value::as_object) {
        for (k, v) in ml {
            reqs.push((k.clone(), format!("{k}={}", v.as_str().unwrap_or(""))));
        }
    }
    if let Some(exprs) = sel.get("matchExpressions").and_then(Value::as_array) {
        for e in exprs {
            let key = e.get("key").and_then(Value::as_str).unwrap_or("");
            let op = e.get("operator").and_then(Value::as_str).unwrap_or("");
            let mut vals: Vec<&str> = e
                .get("values")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            vals.sort();
            let s = match op {
                "In" => format!("{key} in ({})", vals.join(",")),
                "NotIn" => format!("{key} notin ({})", vals.join(",")),
                "Exists" => key.to_string(),
                "DoesNotExist" => format!("!{key}"),
                other => bail!("\"{other}\" is not a valid label selector operator"),
            };
            reqs.push((key.to_string(), s));
        }
    }
    reqs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(reqs
        .into_iter()
        .map(|(_, s)| s)
        .collect::<Vec<_>>()
        .join(","))
}

/// `SelectorsForObject`: (namespace, label selector string) of the pods an
/// object controls.
pub fn selectors_for_object(obj: &Value) -> Result<(String, String)> {
    let kind = obj.get("kind").and_then(Value::as_str).unwrap_or("");
    let ns = obj
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let selector = match kind {
        "ReplicaSet" | "StatefulSet" | "DaemonSet" | "Deployment" | "Job" => {
            label_selector_string(obj.pointer("/spec/selector"))
                .map_err(|e| anyhow!("invalid label selector: {e}"))?
        }
        "ReplicationController" => map_selector_string(obj.pointer("/spec/selector")),
        "Service" => {
            let sel = obj.pointer("/spec/selector");
            if sel.and_then(Value::as_object).is_none_or(|m| m.is_empty()) {
                let name = obj
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                return Err(anyhow!(
                    "invalid service '{name}': Service is defined without a selector"
                ));
            }
            map_selector_string(sel)
        }
        other => bail!("selector for {other} not implemented"),
    };
    Ok((ns, selector))
}

/// `labels.SelectorFromSet(map).String()`: sorted `k=v` pairs.
fn map_selector_string(m: Option<&Value>) -> String {
    let mut pairs: Vec<String> = m
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
                .collect()
        })
        .unwrap_or_default();
    pairs.sort();
    pairs.join(",")
}

fn node_name(p: &Value) -> &str {
    p.pointer("/spec/nodeName")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn ready_condition(p: &Value) -> Option<&Value> {
    p.pointer("/status/conditions")?
        .as_array()?
        .iter()
        .find(|c| c.get("type").and_then(Value::as_str) == Some("Ready"))
}

fn is_ready(p: &Value) -> bool {
    ready_condition(p).and_then(|c| c.get("status").and_then(Value::as_str)) == Some("True")
}

fn ts(v: Option<&Value>) -> Option<chrono::DateTime<chrono::Utc>> {
    v.and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

fn ready_time(p: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    if !is_ready(p) {
        return None;
    }
    ts(ready_condition(p).and_then(|c| c.get("lastTransitionTime")))
}

fn max_restarts(p: &Value) -> (i64, i64) {
    let count = |c: &Value| c.get("restartCount").and_then(Value::as_i64).unwrap_or(0);
    let regular = p
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(count).max().unwrap_or(0))
        .unwrap_or(0);
    let sidecars: Vec<&str> = p
        .pointer("/spec/initContainers")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|c| c.get("restartPolicy").and_then(Value::as_str) == Some("Always"))
                .filter_map(|c| c.get("name").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let sidecar = p
        .pointer("/status/initContainerStatuses")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|c| {
                    c.get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|n| sidecars.contains(&n))
                })
                .map(count)
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0);
    (regular, sidecar)
}

/// `afterOrZero`: t1 is after t2; a zero time counts as after a non-zero one.
fn after_or_zero(
    t1: Option<chrono::DateTime<chrono::Utc>>,
    t2: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    match (t1, t2) {
        (Some(a), Some(b)) => a > b,
        (a, _) => a.is_none(),
    }
}

/// `ActivePods.Less(i, j)` (podutils.go:133-173).
pub fn active_pods_less(i: &Value, j: &Value) -> bool {
    // 1. Unassigned < assigned
    if node_name(i) != node_name(j) && (node_name(i).is_empty() || node_name(j).is_empty()) {
        return node_name(i).is_empty();
    }
    // 2. PodPending < PodUnknown < PodRunning
    let rank = |p: &Value| match p.pointer("/status/phase").and_then(Value::as_str) {
        Some("Unknown") => 1,
        Some("Running") => 2,
        _ => 0,
    };
    if rank(i) != rank(j) {
        return rank(i) < rank(j);
    }
    // 3. Not ready < ready
    if is_ready(i) != is_ready(j) {
        return !is_ready(i);
    }
    // 4. Deleting < Not deleting
    let del = |p: &Value| ts(p.pointer("/metadata/deletionTimestamp"));
    let deleting = |p: &Value| p.pointer("/metadata/deletionTimestamp").is_some();
    if deleting(i) != deleting(j) {
        return deleting(i);
    }
    // 5. Older deletion timestamp < newer deletion timestamp
    if deleting(i) && deleting(j) && del(i) != del(j) {
        return del(i) < del(j);
    }
    // 6. Been ready for empty time < less time < more time
    if is_ready(i) && is_ready(j) && ready_time(i) != ready_time(j) {
        return after_or_zero(ready_time(i), ready_time(j));
    }
    // 7. Pods with containers with higher restart counts < lower restart counts
    let (ri, si) = max_restarts(i);
    let (rj, sj) = max_restarts(j);
    if ri != rj {
        return ri > rj;
    }
    if si != sj {
        return si > sj;
    }
    // 8. Empty creation time pods < newer pods < older pods
    let created = |p: &Value| ts(p.pointer("/metadata/creationTimestamp"));
    if created(i) != created(j) {
        return after_or_zero(created(i), created(j));
    }
    false
}

/// `sort.Sort(sort.Reverse(podutils.ActivePods(pods)))`.
pub fn sort_active_pods_reverse(pods: &mut [Value]) {
    pods.sort_by(|a, b| {
        if active_pods_less(b, a) {
            Ordering::Less
        } else if active_pods_less(a, b) {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    });
}

/// `AllContainerNames`.
fn all_container_names(pod: &Value) -> String {
    let names = |ptr: &str, suffix: &str| -> Vec<String> {
        pod.pointer(ptr)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.get("name").and_then(Value::as_str))
                    .map(|n| format!("{n}{suffix}"))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut all = names("/spec/containers", "");
    all.extend(names("/spec/ephemeralContainers", " (ephem)"));
    all.extend(names("/spec/initContainers", " (init)"));
    all.join(", ")
}

fn find_container_by_name(pod: &Value, name: &str) -> bool {
    [
        "/spec/containers",
        "/spec/initContainers",
        "/spec/ephemeralContainers",
    ]
    .iter()
    .any(|ptr| {
        pod.pointer(ptr).and_then(Value::as_array).is_some_and(|a| {
            a.iter()
                .any(|c| c.get("name").and_then(Value::as_str) == Some(name))
        })
    })
}

/// `FindOrDefaultContainerByName`: the container name to use; the
/// "Defaulted container" notice goes to `warn`.
pub fn find_or_default_container(
    pod: &Value,
    name: &str,
    quiet: bool,
    warn: &mut dyn std::io::Write,
) -> Result<String> {
    let pod_name = pod
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !name.is_empty() {
        if !find_container_by_name(pod, name) {
            bail!("container {name} not found in pod {pod_name}");
        }
        return Ok(name.to_string());
    }
    let containers = pod
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if containers.is_empty() {
        let ns = pod
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("");
        bail!("pod {ns}/{pod_name} does not have any containers");
    }
    // KEP-2227 default-container annotation.
    if let Some(n) = pod
        .pointer("/metadata/annotations")
        .and_then(|a| a.get(DEFAULT_CONTAINER_ANNOTATION_NAME))
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
    {
        if find_container_by_name(pod, n) {
            return Ok(n.to_string());
        }
    }
    let first = containers[0]
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let has = |ptr: &str| {
        pod.pointer(ptr)
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
    };
    if !quiet
        && (containers.len() > 1 || has("/spec/initContainers") || has("/spec/ephemeralContainers"))
    {
        let _ = writeln!(
            warn,
            "Defaulted container \"{first}\" out of: {}",
            all_container_names(pod)
        );
    }
    Ok(first)
}

/// What `exec`/`attach` target: `TYPE/NAME` (or a bare pod name) and/or `-f` files.
pub struct Target<'a> {
    pub resource_name: Option<&'a str>,
    pub filenames: &'a [String],
    pub namespace: &'a str,
    pub timeout: Duration,
}

/// `Builder...Do().Object()` followed by `AttachablePodForObjectFn`.
/// `verb` is "exec" or "attach" (used in the multiple-objects error).
pub async fn resolve_pod(client: &ApiClient, t: &Target<'_>, verb: &str) -> Result<Value> {
    let mapper = crate::discovery::RestMapper::from_server(client).await?;
    let obj: Value;
    let mut ns = t.namespace.to_string();
    if !t.filenames.is_empty() {
        let mut objs = Vec::new();
        for f in t.filenames {
            let text = std::fs::read_to_string(f).map_err(|e| anyhow!("error reading {f}: {e}"))?;
            for doc in serde_yaml::Deserializer::from_str(&text) {
                let v: Value = serde::Deserialize::deserialize(doc)
                    .map_err(|e| anyhow!("error parsing {f}: {e}"))?;
                if !v.is_null() {
                    objs.push(v);
                }
            }
        }
        if objs.len() != 1 || objs[0].get("items").is_some() {
            bail!("cannot {verb} into multiple objects at a time");
        }
        obj = objs.remove(0);
        if let Some(n) = obj.pointer("/metadata/namespace").and_then(Value::as_str) {
            ns = n.to_string();
        }
    } else if let Some(r) = t.resource_name {
        let (rtype, name) = crate::commands::get::parse_resource_slash(r);
        let (rtype, name) = match name {
            Some(n) => (rtype, n),
            None => ("pods", r),
        };
        let mapping = mapper
            .resolve(rtype)
            .ok_or_else(|| anyhow!("the server doesn't have a resource type \"{rtype}\""))?;
        obj = crate::ops::get_value(client, mapping, Some(t.namespace), name).await?;
    } else {
        bail!("pod, type/name or --filename must be specified");
    }

    // attachablePodForObject
    if obj.get("kind").and_then(Value::as_str) == Some("Pod") {
        return Ok(obj);
    }
    let (sel_ns, selector) = selectors_for_object(&obj)
        .map_err(|e| anyhow!("cannot {verb} to {}: {e}", kind_of(&obj)))?;
    let sel_ns = if sel_ns.is_empty() { ns } else { sel_ns };
    get_first_pod(client, &sel_ns, &selector, t.timeout).await
}

fn kind_of(obj: &Value) -> String {
    obj.get("kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// `GetFirstPod`/`GetPodList`: the best pod matching the selector, waiting
/// (watch from the list's resourceVersion) for one to appear.
async fn get_first_pod(
    client: &ApiClient,
    namespace: &str,
    selector: &str,
    timeout: Duration,
) -> Result<Value> {
    let q = format!(
        "labelSelector={}",
        crate::commands::get::urlencoding::encode(selector)
    );
    let path = format!("/api/v1/namespaces/{namespace}/pods?{q}");
    let list: Value = client
        .get::<Value>(&path)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let mut pods: Vec<Value> = list
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !pods.is_empty() {
        sort_active_pods_reverse(&mut pods);
        return Ok(pods.remove(0));
    }
    // Watch until we observe a pod.
    let rv = list
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .unwrap_or("");
    let watch_path = format!("{path}&watch=true&resourceVersion={rv}");
    let wait = async {
        let resp = client
            .get_stream(&watch_path)
            .await
            .map_err(|e| anyhow!("{e:?}"))?;
        let mut stream = resp.bytes_stream();
        let mut buf = String::new();
        while let Some(chunk) = stream.next().await {
            buf.push_str(&String::from_utf8_lossy(&chunk?));
            while let Some(i) = buf.find('\n') {
                let line = buf[..i].trim().to_string();
                buf = buf[i + 1..].to_string();
                if let Ok(ev) = serde_json::from_str::<Value>(&line) {
                    let ty = ev.get("type").and_then(Value::as_str).unwrap_or("");
                    if ty == "ADDED" || ty == "MODIFIED" {
                        if let Some(o) = ev.get("object") {
                            return Ok(o.clone());
                        }
                    }
                }
            }
        }
        Err(anyhow!("watch closed before a pod was observed"))
    };
    match tokio::time::timeout(timeout, wait).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!("timed out waiting for the condition")),
    }
}

/// The completed-pod check (exec.go Run; attach.go Run uses "attach a").
pub fn check_pod_running(pod: &Value, what: &str) -> Result<()> {
    let phase = pod
        .pointer("/status/phase")
        .and_then(Value::as_str)
        .unwrap_or("");
    if phase == "Succeeded" || phase == "Failed" {
        bail!("cannot {what} a container in a completed pod; current phase is {phase}");
    }
    Ok(())
}

/// Execute a command in a container.
#[allow(clippy::too_many_arguments)]
pub async fn execute(
    client: &ApiClient,
    target: &Target<'_>,
    container: Option<&str>,
    command: &[String],
    tty: bool,
    stdin: bool,
    quiet: bool,
) -> Result<()> {
    if command.is_empty() {
        bail!("you must specify at least one command for the container");
    }
    let pod = resolve_pod(client, target, "exec").await?;
    check_pod_running(&pod, "exec into")?;
    let container_name =
        find_or_default_container(&pod, container.unwrap_or(""), quiet, &mut std::io::stderr())?;
    let pod_name = pod
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let pod_ns = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or(target.namespace);

    // Build the exec URL path
    let mut url_path = format!("/api/v1/namespaces/{pod_ns}/pods/{pod_name}/exec");
    let mut query_params = vec![];
    for cmd in command {
        query_params.push(format!("command={}", urlencoding::encode(cmd)));
    }
    query_params.push(format!("container={container_name}"));
    query_params.push("stdout=true".to_string());
    query_params.push("stderr=true".to_string());
    if stdin {
        query_params.push("stdin=true".to_string());
    }
    if tty {
        query_params.push("tty=true".to_string());
    }
    url_path.push('?');
    url_path.push_str(&query_params.join("&"));

    // Convert HTTP(S) URL to WebSocket URL
    let ws_url = client.get_ws_url(&url_path)?;

    // Execute with WebSocket streaming
    websocket::exec_stream(ws_url, stdin, tty).await
}

pub mod urlencoding {
    pub fn encode(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                ' ' => "+".to_string(),
                _ => format!("%{:02X}", c as u8),
            })
            .collect()
    }
}
