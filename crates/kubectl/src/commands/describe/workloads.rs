//! `kubectl describe` for ReplicationController and ReplicaSet, with the
//! shared pod-template machinery the other workload describers use.
//!
//! Ported from `staging/src/k8s.io/kubectl/pkg/describe/describe.go`:
//! `describeReplicationController` (:2200), `describeReplicaSet` (:2290),
//! `DescribePodTemplate` (:2231), `describeContainers` (:1803) and its
//! helpers, `describeVolumes` (:936), `describeTopologySpreadConstraints`
//! (:910), `describeWorkloadReference` (:1016),
//! `printPodTolerationsMultiline` (:5014), `printController` (:892),
//! `getPodStatusForController` (:4239) and `DescribeProbe` (:2056).
//! Each takes the already-fetched object; `events` is `None` when events were
//! not requested. Registration in `execute` is kubectl-P1-16.
//!
//! Not yet ported (kubectl-P1-12b): the volume source printers other than
//! hostPath, emptyDir, secret, configMap, projected, PVC, downwardAPI and
//! image; container status blocks (`describeContainerState`).

use super::events::{
    describe_events_at, print_annotations_multiline, print_labels_multiline, PrefixWriter, LEVEL_0,
    LEVEL_1,
};
use chrono::{DateTime, Utc};
use kubernetes_rs_common::quantity::Quantity;
use kubernetes_rs_common::resources::Event;
use serde_json::Value;
use std::collections::BTreeMap;

const LEVEL_2: usize = 2;
const LEVEL_3: usize = 3;

fn str_at<'a>(obj: &'a Value, ptr: &str) -> &'a str {
    obj.pointer(ptr).and_then(Value::as_str).unwrap_or("")
}

fn arr<'a>(obj: &'a Value, ptr: &str) -> &'a [Value] {
    obj.pointer(ptr)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn string_map(obj: &Value, ptr: &str) -> BTreeMap<String, String> {
    obj.pointer(ptr)
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn int_at(obj: &Value, ptr: &str) -> i64 {
    obj.pointer(ptr).and_then(Value::as_i64).unwrap_or(0)
}

fn bool_at(obj: &Value, ptr: &str) -> bool {
    obj.pointer(ptr).and_then(Value::as_bool).unwrap_or(false)
}

/// `labels.FormatLabels`: `k=v,k=v` sorted, `<none>` when empty.
fn format_labels(m: &BTreeMap<String, String>) -> String {
    if m.is_empty() {
        return "<none>".to_string();
    }
    m.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// `metav1.FormatLabelSelector`: `LabelSelectorAsSelector(...).String()` with
/// requirements sorted by key; matchLabels are `k=v`, expressions `k in (a,b)`,
/// `k notin (a,b)`, `k`, `!k`. `<none>` when empty, `<error>` on a bad operator.
pub fn format_label_selector(sel: &Value) -> String {
    let mut reqs: Vec<(String, String)> = Vec::new();
    if let Some(ml) = sel.get("matchLabels").and_then(Value::as_object) {
        for (k, v) in ml {
            reqs.push((k.clone(), format!("{k}={}", v.as_str().unwrap_or_default())));
        }
    }
    for e in arr(sel, "/matchExpressions") {
        let key = str_at(e, "/key");
        let mut values: Vec<&str> = arr(e, "/values").iter().filter_map(Value::as_str).collect();
        values.sort_unstable();
        let joined = values.join(",");
        let s = match str_at(e, "/operator") {
            "In" => format!("{key} in ({joined})"),
            "NotIn" => format!("{key} notin ({joined})"),
            "Exists" => key.to_string(),
            "DoesNotExist" => format!("!{key}"),
            _ => return "<error>".to_string(),
        };
        reqs.push((key.to_string(), s));
    }
    reqs.sort_by(|a, b| a.0.cmp(&b.0));
    let out = reqs.into_iter().map(|r| r.1).collect::<Vec<_>>().join(",");
    if out.is_empty() {
        "<none>".to_string()
    } else {
        out
    }
}

/// `printController`: `Kind/Name` of the controlling owner, else empty.
pub fn print_controller(obj: &Value) -> String {
    arr(obj, "/metadata/ownerReferences")
        .iter()
        .find(|r| r.get("controller").and_then(Value::as_bool) == Some(true))
        .map(|r| format!("{}/{}", str_at(r, "/kind"), str_at(r, "/name")))
        .unwrap_or_default()
}

/// `getPodStatusForController` counting: pods controlled by `uid`, by phase
/// (running, waiting = Pending, succeeded, failed).
pub fn pod_status_for_controller(pods: &[Value], uid: &str) -> (usize, usize, usize, usize) {
    let (mut running, mut waiting, mut succeeded, mut failed) = (0, 0, 0, 0);
    for pod in pods {
        // Skip pods that are orphans or owned by other controllers.
        let owned = arr(pod, "/metadata/ownerReferences").iter().any(|r| {
            r.get("controller").and_then(Value::as_bool) == Some(true) && str_at(r, "/uid") == uid
        });
        if !owned {
            continue;
        }
        match str_at(pod, "/status/phase") {
            "Running" => running += 1,
            "Pending" => waiting += 1,
            "Succeeded" => succeeded += 1,
            "Failed" => failed += 1,
            _ => {}
        }
    }
    (running, waiting, succeeded, failed)
}

fn port_str(p: &Value, field: &str) -> String {
    let mut s = format!("{}/{}", int_at(p, field), str_at(p, "/protocol"));
    let name = str_at(p, "/name");
    if !name.is_empty() {
        s = format!("{s} ({name})");
    }
    s
}

fn string_or_none(s: &str) -> &str {
    if s.is_empty() {
        "<none>"
    } else {
        s
    }
}

/// `IntOrString.String()`.
fn int_or_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => "0".to_string(),
    }
}

/// `DescribeProbe` (describe.go:2056-2083).
pub fn describe_probe(p: &Value) -> String {
    let attrs = format!(
        "delay={}s timeout={}s period={}s #success={} #failure={}",
        int_at(p, "/initialDelaySeconds"),
        int_at(p, "/timeoutSeconds"),
        int_at(p, "/periodSeconds"),
        int_at(p, "/successThreshold"),
        int_at(p, "/failureThreshold")
    );
    if let Some(exec) = p.get("exec") {
        let cmd: Vec<&str> = arr(exec, "/command")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        return format!("exec [{}] {attrs}", cmd.join(" "));
    }
    if let Some(http) = p.get("httpGet") {
        let host = str_at(http, "/host");
        let port = int_or_string(http.get("port"));
        // `net.JoinHostPort`: bracket a host containing a colon.
        let hostport = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let path = str_at(http, "/path");
        let path = if !path.is_empty() && !path.starts_with('/') {
            format!("/{path}")
        } else {
            path.to_string()
        };
        return format!(
            "http-get {}://{hostport}{path} {attrs}",
            str_at(http, "/scheme").to_lowercase()
        );
    }
    if let Some(tcp) = p.get("tcpSocket") {
        return format!(
            "tcp-socket {}:{} {attrs}",
            str_at(tcp, "/host"),
            int_or_string(tcp.get("port"))
        );
    }
    if let Some(grpc) = p.get("grpc") {
        return format!(
            "grpc <pod>:{} {} {attrs}",
            int_at(grpc, "/port"),
            str_at(grpc, "/service")
        );
    }
    format!("unknown {attrs}")
}

/// `describeResources` (:1932-1952): limits then requests, names sorted.
fn describe_resources(res: &Value, w: &mut PrefixWriter, level: usize) {
    for (title, ptr) in [("Limits", "/limits"), ("Requests", "/requests")] {
        let m = string_map(res, ptr);
        if m.is_empty() {
            continue;
        }
        w.write(level, &format!("{title}:\n"));
        for (name, q) in &m {
            let q = Quantity::parse(q)
                .map(|q| q.to_string())
                .unwrap_or_default();
            w.write(level + 1, &format!("{name}:\t{q}\n"));
        }
    }
}

/// `resourcehelper.ExtractContainerResourceValue` (kubectl/pkg/util/resource).
fn extract_container_resource_value(rfr: &Value, container: &Value) -> Option<String> {
    let divisor = rfr
        .get("divisor")
        .and_then(Value::as_str)
        .and_then(|d| Quantity::parse(d).ok())
        .filter(|d| !d.is_zero())
        .unwrap_or_else(|| Quantity::parse("1").unwrap());
    let resource = str_at(rfr, "/resource");
    let (section, name) = resource.split_once('.')?;
    if section != "limits" && section != "requests" {
        return None;
    }
    let q = container
        .pointer(&format!("/resources/{section}/{name}"))
        .and_then(Value::as_str)
        .and_then(|q| Quantity::parse(q).ok());
    let ceil_div = |a: i128, b: i128| -> String {
        // math.Ceil(float64(a) / float64(b))
        ((a as f64) / (b as f64))
            .ceil()
            .to_string()
            .replace(".0", "")
    };
    match name {
        "cpu" => Some(ceil_div(
            q.map(|q| q.milli_value()).unwrap_or(0),
            divisor.milli_value(),
        )),
        "memory" | "ephemeral-storage" => {
            Some(ceil_div(q.map(|q| q.value()).unwrap_or(0), divisor.value()))
        }
        n if n.starts_with("hugepages-") => {
            Some(ceil_div(q.map(|q| q.value()).unwrap_or(0), divisor.value()))
        }
        _ => None,
    }
}

fn describe_container_command(c: &Value, w: &mut PrefixWriter) {
    for (title, key) in [("Command", "/command"), ("Args", "/args")] {
        let items = arr(c, key);
        if items.is_empty() {
            continue;
        }
        w.write(LEVEL_2, &format!("{title}:\n"));
        for item in items {
            for s in item.as_str().unwrap_or("").split('\n') {
                w.write(LEVEL_3, &format!("{s}\n"));
            }
        }
    }
}

fn describe_container_env_from(c: &Value, w: &mut PrefixWriter) {
    w.write(LEVEL_2, "Environment Variables from:\n");
    for e in arr(c, "/envFrom") {
        let (from, r) = if let Some(r) = e.get("configMapRef") {
            ("ConfigMap", r)
        } else if let Some(r) = e.get("secretRef") {
            ("Secret", r)
        } else {
            ("", &Value::Null)
        };
        let name = str_at(r, "/name");
        let optional = bool_at(r, "/optional");
        let prefix = str_at(e, "/prefix");
        if prefix.is_empty() {
            w.write(LEVEL_3, &format!("{name}\t{from}\tOptional: {optional}\n"));
        } else {
            w.write(
                LEVEL_3,
                &format!("{name}\t{from} with prefix '{prefix}'\tOptional: {optional}\n"),
            );
        }
    }
}

fn describe_container_env_vars(c: &Value, w: &mut PrefixWriter) {
    let envs = arr(c, "/env");
    w.write(
        LEVEL_2,
        &format!(
            "Environment:{}\n",
            if envs.is_empty() { "\t<none>" } else { "" }
        ),
    );
    for e in envs {
        let name = str_at(e, "/name");
        let Some(vf) = e.get("valueFrom").filter(|v| !v.is_null()) else {
            for (i, s) in str_at(e, "/value").split('\n').enumerate() {
                if i == 0 {
                    w.write(LEVEL_3, &format!("{name}:\t{s}\n"));
                } else {
                    w.write(LEVEL_3, &format!("\t{s}\n"));
                }
            }
            continue;
        };
        if let Some(f) = vf.get("fieldRef") {
            // The resolver is nil for a template: the resolved value is empty.
            w.write(
                LEVEL_3,
                &format!("{name}:\t (%s:%s)\n")
                    .replacen("%s", str_at(f, "/apiVersion"), 1)
                    .replacen("%s", str_at(f, "/fieldPath"), 1),
            );
        } else if let Some(r) = vf.get("resourceFieldRef") {
            let mut v = extract_container_resource_value(r, c).unwrap_or_default();
            let resource = str_at(r, "/resource");
            if v == "0" && (resource == "limits.cpu" || resource == "limits.memory") {
                v = "node allocatable".to_string();
            }
            w.write(LEVEL_3, &format!("{name}:\t{v} ({resource})\n"));
        } else if let Some(r) = vf.get("secretKeyRef") {
            w.write(
                LEVEL_3,
                &format!(
                    "{name}:\t<set to the key '{}' in secret '{}'>\tOptional: {}\n",
                    str_at(r, "/key"),
                    str_at(r, "/name"),
                    bool_at(r, "/optional")
                ),
            );
        } else if let Some(r) = vf.get("configMapKeyRef") {
            w.write(
                LEVEL_3,
                &format!(
                    "{name}:\t<set to the key '{}' of config map '{}'>\tOptional: {}\n",
                    str_at(r, "/key"),
                    str_at(r, "/name"),
                    bool_at(r, "/optional")
                ),
            );
        }
    }
}

/// `describeContainerVolumes` (:1959-1987): mounts then devices, by path.
fn describe_container_volumes(c: &Value, w: &mut PrefixWriter) {
    let mut mounts: Vec<&Value> = arr(c, "/volumeMounts").iter().collect();
    let none = if mounts.is_empty() { "\t<none>" } else { "" };
    w.write(LEVEL_2, &format!("Mounts:{none}\n"));
    mounts.sort_by(|a, b| str_at(a, "/mountPath").cmp(str_at(b, "/mountPath")));
    for m in mounts {
        let mut flags = vec![if bool_at(m, "/readOnly") { "ro" } else { "rw" }.to_string()];
        let sub = str_at(m, "/subPath");
        if !sub.is_empty() {
            flags.push(format!("path={sub:?}"));
        }
        w.write(
            LEVEL_3,
            &format!(
                "{} from {} ({})\n",
                str_at(m, "/mountPath"),
                str_at(m, "/name"),
                flags.join(",")
            ),
        );
    }
    let mut devices: Vec<&Value> = arr(c, "/volumeDevices").iter().collect();
    if !devices.is_empty() {
        w.write(LEVEL_2, "Devices:\n");
        devices.sort_by(|a, b| str_at(a, "/devicePath").cmp(str_at(b, "/devicePath")));
        for d in devices {
            w.write(
                LEVEL_3,
                &format!("{} from {}\n", str_at(d, "/devicePath"), str_at(d, "/name")),
            );
        }
    }
}

/// `describeContainers` for a pod template (no container statuses, no env
/// resolver), `describeContainersLabel` and `describeContainerBasicInfo`.
fn describe_containers(label: &str, containers: &[Value], w: &mut PrefixWriter, space: &str) {
    let none = if containers.is_empty() { " <none>" } else { "" };
    w.write(LEVEL_0, &format!("{space}{label}:{none}\n"));
    let name_indent = if space.is_empty() { "" } else { " " };
    for c in containers {
        w.write(LEVEL_1, &format!("{name_indent}{}:\n", str_at(c, "/name")));
        w.write(LEVEL_2, &format!("Image:\t{}\n", str_at(c, "/image")));
        let ports = arr(c, "/ports");
        let port_string = ports
            .iter()
            .map(|p| port_str(p, "/containerPort"))
            .collect::<Vec<_>>()
            .join(", ");
        if port_string.contains(',') {
            w.write(LEVEL_2, &format!("Ports:\t{port_string}\n"));
        } else {
            w.write(
                LEVEL_2,
                &format!("Port:\t{}\n", string_or_none(&port_string)),
            );
        }
        let host_port_string = ports
            .iter()
            .map(|p| port_str(p, "/hostPort"))
            .collect::<Vec<_>>()
            .join(", ");
        if host_port_string.contains(',') {
            w.write(LEVEL_2, &format!("Host Ports:\t{host_port_string}\n"));
        } else {
            w.write(
                LEVEL_2,
                &format!("Host Port:\t{}\n", string_or_none(&host_port_string)),
            );
        }
        if let Some(sp) = c.pointer("/securityContext/seccompProfile") {
            let t = str_at(sp, "/type");
            w.write(LEVEL_2, &format!("SeccompProfile:\t{t}\n"));
            if t == "Localhost" {
                w.write(
                    LEVEL_3,
                    &format!("LocalhostProfile:\t{}\n", str_at(sp, "/localhostProfile")),
                );
            }
        }
        describe_container_command(c, w);
        if let Some(res) = c.get("resources") {
            describe_resources(res, w, LEVEL_2);
        }
        for (title, key) in [
            ("Liveness", "livenessProbe"),
            ("Readiness", "readinessProbe"),
            ("Startup", "startupProbe"),
        ] {
            if let Some(p) = c.get(key).filter(|p| !p.is_null()) {
                w.write(LEVEL_2, &format!("{title}:\t{}\n", describe_probe(p)));
            }
        }
        if !arr(c, "/envFrom").is_empty() {
            describe_container_env_from(c, w);
        }
        describe_container_env_vars(c, w);
        describe_container_volumes(c, w);
    }
}

/// `describeVolumes` (:936-1013) for the sources ported so far.
fn describe_volumes(volumes: &[Value], w: &mut PrefixWriter, space: &str) {
    if volumes.is_empty() {
        w.write(LEVEL_0, &format!("{space}Volumes:\t<none>\n"));
        return;
    }
    w.write(LEVEL_0, &format!("{space}Volumes:\n"));
    let name_indent = if space.is_empty() { "" } else { " " };
    for v in volumes {
        w.write(LEVEL_1, &format!("{name_indent}{}:\n", str_at(v, "/name")));
        if let Some(s) = v.get("hostPath") {
            let t = s.get("type").and_then(Value::as_str).unwrap_or("<none>");
            w.write(
                LEVEL_2,
                &format!(
                    "Type:\tHostPath (bare host directory volume)\n    Path:\t{}\n    HostPathType:\t{t}\n",
                    str_at(s, "/path")
                ),
            );
        } else if let Some(s) = v.get("emptyDir") {
            let size = s
                .get("sizeLimit")
                .and_then(Value::as_str)
                .and_then(|q| Quantity::parse(q).ok())
                .filter(|q| q.value() > 0)
                .map(|q| q.to_string())
                .unwrap_or_else(|| "<unset>".to_string());
            w.write(
                LEVEL_2,
                &format!(
                    "Type:\tEmptyDir (a temporary directory that shares a pod's lifetime)\n    Medium:\t{}\n    SizeLimit:\t{size}\n",
                    str_at(s, "/medium")
                ),
            );
        } else if let Some(s) = v.get("secret") {
            w.write(
                LEVEL_2,
                &format!(
                    "Type:\tSecret (a volume populated by a Secret)\n    SecretName:\t{}\n    Optional:\t{}\n",
                    str_at(s, "/secretName"),
                    bool_at(s, "/optional")
                ),
            );
        } else if let Some(s) = v.get("configMap") {
            w.write(
                LEVEL_2,
                &format!(
                    "Type:\tConfigMap (a volume populated by a ConfigMap)\n    Name:\t{}\n    Optional:\t{}\n",
                    str_at(s, "/name"),
                    bool_at(s, "/optional")
                ),
            );
        } else if let Some(s) = v.get("persistentVolumeClaim") {
            w.write(
                LEVEL_2,
                &format!(
                    "Type:\tPersistentVolumeClaim (a reference to a PersistentVolumeClaim in the same namespace)\n    ClaimName:\t{}\n    ReadOnly:\t{}\n",
                    str_at(s, "/claimName"),
                    bool_at(s, "/readOnly")
                ),
            );
        } else if let Some(s) = v.get("projected") {
            w.write(
                LEVEL_2,
                "Type:\tProjected (a volume that contains injected data from multiple sources)\n",
            );
            for src in arr(s, "/sources") {
                if let Some(x) = src.get("secret") {
                    w.write(
                        LEVEL_2,
                        &format!(
                            "SecretName:\t{}\n    Optional:\t{}\n",
                            str_at(x, "/name"),
                            bool_at(x, "/optional")
                        ),
                    );
                } else if src.get("downwardAPI").is_some() {
                    w.write(LEVEL_2, "DownwardAPI:\ttrue\n");
                } else if let Some(x) = src.get("configMap") {
                    w.write(
                        LEVEL_2,
                        &format!(
                            "ConfigMapName:\t{}\n    Optional:\t{}\n",
                            str_at(x, "/name"),
                            bool_at(x, "/optional")
                        ),
                    );
                } else if let Some(x) = src.get("serviceAccountToken") {
                    w.write(
                        LEVEL_2,
                        &format!(
                            "TokenExpirationSeconds:\t{}\n",
                            int_at(x, "/expirationSeconds")
                        ),
                    );
                }
            }
        } else if let Some(s) = v.get("downwardAPI") {
            w.write(
                LEVEL_2,
                "Type:\tDownwardAPI (a volume populated by information about the pod)\n    Items:\n",
            );
            for m in arr(s, "/items") {
                if let Some(f) = m.get("fieldRef") {
                    w.write(
                        LEVEL_3,
                        &format!("{} -> {}\n", str_at(f, "/fieldPath"), str_at(m, "/path")),
                    );
                }
                if let Some(f) = m.get("resourceFieldRef") {
                    w.write(
                        LEVEL_3,
                        &format!("{} -> {}\n", str_at(f, "/resource"), str_at(m, "/path")),
                    );
                }
            }
        } else if let Some(s) = v.get("image") {
            w.write(
                LEVEL_2,
                &format!(
                    "Type:\tImage (a container image or OCI artifact)\n    Reference:\t{}\n    PullPolicy:\t{}\n",
                    str_at(s, "/reference"),
                    str_at(s, "/pullPolicy")
                ),
            );
        }
    }
}

/// `describeTopologySpreadConstraints` (:910-934), sorted by topology key.
fn describe_topology_spread_constraints(tscs: &[Value], w: &mut PrefixWriter, space: &str) {
    if tscs.is_empty() {
        return;
    }
    let mut tscs: Vec<&Value> = tscs.iter().collect();
    tscs.sort_by(|a, b| str_at(a, "/topologyKey").cmp(str_at(b, "/topologyKey")));
    w.write(LEVEL_0, &format!("{space}Topology Spread Constraints:\t"));
    for (i, t) in tscs.iter().enumerate() {
        if i != 0 {
            w.write(LEVEL_0, space);
            w.write(LEVEL_0, "\t");
        }
        w.write(LEVEL_0, &format!("{}:", str_at(t, "/topologyKey")));
        w.write(LEVEL_0, str_at(t, "/whenUnsatisfiable"));
        w.write(
            LEVEL_0,
            &format!(" when max skew {} is exceeded", int_at(t, "/maxSkew")),
        );
        if let Some(sel) = t.get("labelSelector").filter(|s| !s.is_null()) {
            w.write(
                LEVEL_0,
                &format!(" for selector {}", format_label_selector(sel)),
            );
        }
        w.write(LEVEL_0, "\n");
    }
}

/// `printPodTolerationsMultiline` (:5014-5062), sorted by key.
fn print_pod_tolerations_multiline(w: &mut PrefixWriter, title: &str, tols: &[Value]) {
    w.write(LEVEL_0, &format!("{title}:\t"));
    if tols.is_empty() {
        w.write_line("<none>");
        return;
    }
    let mut tols: Vec<&Value> = tols.iter().collect();
    tols.sort_by(|a, b| str_at(a, "/key").cmp(str_at(b, "/key")));
    for (i, t) in tols.iter().enumerate() {
        if i != 0 {
            w.write(LEVEL_0, "\t");
        }
        let (key, value, effect) = (str_at(t, "/key"), str_at(t, "/value"), str_at(t, "/effect"));
        w.write(LEVEL_0, key);
        if !value.is_empty() {
            w.write(LEVEL_0, &format!("={value}"));
        }
        if !effect.is_empty() {
            w.write(LEVEL_0, &format!(":{effect}"));
        }
        // `operator: Exists` with no value tolerates everything.
        if str_at(t, "/operator") == "Exists" && value.is_empty() {
            if !key.is_empty() || !effect.is_empty() {
                w.write(LEVEL_0, " op=Exists");
            } else {
                w.write(LEVEL_0, "op=Exists");
            }
        }
        if let Some(secs) = t.get("tolerationSeconds").and_then(Value::as_i64) {
            w.write(LEVEL_0, &format!(" for {secs}s"));
        }
        w.write(LEVEL_0, "\n");
    }
}

/// `describeWorkloadReference` (:1016-1023).
fn describe_workload_reference(r: &Value, w: &mut PrefixWriter, space: &str) {
    w.write(LEVEL_0, &format!("{space}WorkloadRef:\n"));
    w.write(LEVEL_1, &format!("Name:\t{}\n", str_at(r, "/name")));
    w.write(LEVEL_1, &format!("PodGroup:\t{}\n", str_at(r, "/podGroup")));
    let key = str_at(r, "/podGroupReplicaKey");
    if !key.is_empty() {
        w.write(LEVEL_1, &format!("PodGroupReplicaKey:\t{key}\n"));
    }
}

/// `DescribePodTemplate` (:2231-2262); `template` is the PodTemplateSpec.
pub fn describe_pod_template(template: Option<&Value>, w: &mut PrefixWriter) {
    w.write(LEVEL_0, "Pod Template:\n");
    let Some(t) = template.filter(|t| !t.is_null()) else {
        w.write(LEVEL_1, "<unset>");
        return;
    };
    print_labels_multiline(w, "  Labels", &string_map(t, "/metadata/labels"));
    let annotations = string_map(t, "/metadata/annotations");
    if !annotations.is_empty() {
        print_annotations_multiline(w, "  Annotations", &annotations);
    }
    let sa = str_at(t, "/spec/serviceAccountName");
    if !sa.is_empty() {
        w.write(LEVEL_1, &format!("Service Account:\t{sa}\n"));
    }
    let init = arr(t, "/spec/initContainers");
    if !init.is_empty() {
        describe_containers("Init Containers", init, w, "  ");
    }
    describe_containers("Containers", arr(t, "/spec/containers"), w, "  ");
    describe_volumes(arr(t, "/spec/volumes"), w, "  ");
    describe_topology_spread_constraints(arr(t, "/spec/topologySpreadConstraints"), w, "  ");
    let pc = str_at(t, "/spec/priorityClassName");
    if !pc.is_empty() {
        w.write(LEVEL_1, &format!("Priority Class Name:\t{pc}\n"));
    }
    print_labels_multiline(w, "  Node-Selectors", &string_map(t, "/spec/nodeSelector"));
    print_pod_tolerations_multiline(w, "  Tolerations", arr(t, "/spec/tolerations"));
    if let Some(r) = t.pointer("/spec/workloadRef").filter(|r| !r.is_null()) {
        describe_workload_reference(r, w, "  ");
    }
}

/// The `Conditions` block shared by RC and RS (`%v \t%v\t%v`).
fn write_conditions(obj: &Value, w: &mut PrefixWriter) {
    let conditions = arr(obj, "/status/conditions");
    if conditions.is_empty() {
        return;
    }
    w.write(LEVEL_0, "Conditions:\n  Type\tStatus\tReason\n");
    w.write(LEVEL_1, "----\t------\t------\n");
    for c in conditions {
        w.write(
            LEVEL_1,
            &format!(
                "{} \t{}\t{}\n",
                str_at(c, "/type"),
                str_at(c, "/status"),
                str_at(c, "/reason")
            ),
        );
    }
}

/// `describeReplicationController` (describe.go:2200-2229). `pods` is the
/// `(running, waiting, succeeded, failed)` count of `pod_status_for_controller`.
pub fn describe_replication_controller(
    rc: &Value,
    events: Option<&[Event]>,
    pods: (usize, usize, usize, usize),
    now: DateTime<Utc>,
) -> String {
    let mut w = PrefixWriter::new();
    w.write(
        LEVEL_0,
        &format!("Name:\t{}\n", str_at(rc, "/metadata/name")),
    );
    w.write(
        LEVEL_0,
        &format!("Namespace:\t{}\n", str_at(rc, "/metadata/namespace")),
    );
    w.write(
        LEVEL_0,
        &format!(
            "Selector:\t{}\n",
            format_labels(&string_map(rc, "/spec/selector"))
        ),
    );
    print_labels_multiline(&mut w, "Labels", &string_map(rc, "/metadata/labels"));
    print_annotations_multiline(
        &mut w,
        "Annotations",
        &string_map(rc, "/metadata/annotations"),
    );
    w.write(
        LEVEL_0,
        &format!(
            "Replicas:\t{} current / {} desired\n",
            int_at(rc, "/status/replicas"),
            int_at(rc, "/spec/replicas")
        ),
    );
    let (running, waiting, succeeded, failed) = pods;
    w.write(
        LEVEL_0,
        &format!(
            "Pods Status:\t{running} Running / {waiting} Waiting / {succeeded} Succeeded / {failed} Failed\n"
        ),
    );
    describe_pod_template(rc.pointer("/spec/template"), &mut w);
    write_conditions(rc, &mut w);
    if let Some(events) = events {
        describe_events_at(events, &mut w, now);
    }
    w.finish()
}

/// `describeReplicaSet` (describe.go:2290-2325). `pods` is `Err(message)` when
/// listing the pods failed (`error in fetching pods: ...`).
pub fn describe_replica_set(
    rs: &Value,
    events: Option<&[Event]>,
    pods: Result<(usize, usize, usize, usize), String>,
    now: DateTime<Utc>,
) -> String {
    let mut w = PrefixWriter::new();
    w.write(
        LEVEL_0,
        &format!("Name:\t{}\n", str_at(rs, "/metadata/name")),
    );
    w.write(
        LEVEL_0,
        &format!("Namespace:\t{}\n", str_at(rs, "/metadata/namespace")),
    );
    let selector = rs
        .pointer("/spec/selector")
        .map(format_label_selector)
        .unwrap_or_else(|| "<none>".to_string());
    w.write(LEVEL_0, &format!("Selector:\t{selector}\n"));
    print_labels_multiline(&mut w, "Labels", &string_map(rs, "/metadata/labels"));
    print_annotations_multiline(
        &mut w,
        "Annotations",
        &string_map(rs, "/metadata/annotations"),
    );
    let controlled_by = print_controller(rs);
    if !controlled_by.is_empty() {
        w.write(LEVEL_0, &format!("Controlled By:\t{controlled_by}\n"));
    }
    w.write(
        LEVEL_0,
        &format!(
            "Replicas:\t{} current / {} desired\n",
            int_at(rs, "/status/replicas"),
            int_at(rs, "/spec/replicas")
        ),
    );
    w.write(LEVEL_0, "Pods Status:\t");
    match pods {
        Err(e) => w.write(LEVEL_0, &format!("error in fetching pods: {e}\n")),
        Ok((running, waiting, succeeded, failed)) => w.write(
            LEVEL_0,
            &format!(
                "{running} Running / {waiting} Waiting / {succeeded} Succeeded / {failed} Failed\n"
            ),
        ),
    }
    describe_pod_template(rs.pointer("/spec/template"), &mut w);
    write_conditions(rs, &mut w);
    if let Some(events) = events {
        describe_events_at(events, &mut w, now);
    }
    w.finish()
}
