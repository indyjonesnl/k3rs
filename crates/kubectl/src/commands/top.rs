//! `kubectl top node|pod`.
//!
//! Port of release-1.35 `staging/src/k8s.io/kubectl/pkg/cmd/top/{top.go,top_pod.go,top_node.go}`
//! and `pkg/metricsutil/{metrics_printer.go,metrics_sorter.go,metrics_resource_adder.go}`.
//! Not ported: `--use-protocol-buffers` (accepted, the metrics API is read as
//! JSON) and the fsnotify-free `klog` V(2) message in `checkPodAge`.

use crate::types::TopCommands;
use anyhow::{anyhow, bail, Result};
use kubernetes_rs_client::http::ApiClient;
use kubernetes_rs_common::quantity::Quantity;
use serde_json::Value;
use std::collections::BTreeMap;

/// `v1.ResourceList` restricted to the resources top reads.
pub type ResourceList = BTreeMap<String, Quantity>;

const RESOURCE_CPU: &str = "cpu";
const RESOURCE_MEMORY: &str = "memory";
/// `metricsutil.ResourceSwap`.
pub const RESOURCE_SWAP: &str = "swap";
const SORT_BY_CPU: &str = "cpu";
const SORT_BY_MEMORY: &str = "memory";
/// `top.go` `supportedMetricsAPIVersions`.
const SUPPORTED_METRICS_API_VERSIONS: [&str; 1] = ["v1beta1"];
/// `metricsCreationDelay` (top_pod.go).
const METRICS_CREATION_DELAY_SECS: i64 = 120;

#[derive(Debug, Clone)]
pub struct ContainerMetrics {
    pub name: String,
    pub usage: ResourceList,
}

#[derive(Debug, Clone)]
pub struct PodMetrics {
    pub namespace: String,
    pub name: String,
    pub containers: Vec<ContainerMetrics>,
}

#[derive(Debug, Clone)]
pub struct NodeMetrics {
    pub name: String,
    pub usage: ResourceList,
}

fn parse_resource_list(v: Option<&Value>) -> ResourceList {
    let mut out = ResourceList::new();
    if let Some(map) = v.and_then(Value::as_object) {
        for (k, q) in map {
            if let Some(q) = q.as_str().and_then(|s| Quantity::parse(s).ok()) {
                out.insert(k.clone(), q);
            }
        }
    }
    out
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(n) => cur = n,
            None => return "",
        }
    }
    cur.as_str().unwrap_or("")
}

impl PodMetrics {
    pub fn from_value(v: &Value) -> PodMetrics {
        PodMetrics {
            namespace: str_at(v, &["metadata", "namespace"]).to_string(),
            name: str_at(v, &["metadata", "name"]).to_string(),
            containers: v
                .get("containers")
                .and_then(Value::as_array)
                .map(|cs| {
                    cs.iter()
                        .map(|c| ContainerMetrics {
                            name: str_at(c, &["name"]).to_string(),
                            usage: parse_resource_list(c.get("usage")),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

impl NodeMetrics {
    pub fn from_value(v: &Value) -> NodeMetrics {
        NodeMetrics {
            name: str_at(v, &["metadata", "name"]).to_string(),
            usage: parse_resource_list(v.get("usage")),
        }
    }
}

fn zero() -> Quantity {
    Quantity::parse("0").expect("0 parses")
}

fn milli(l: &ResourceList, res: &str) -> i128 {
    l.get(res).map(Quantity::milli_value).unwrap_or(0)
}

fn value(l: &ResourceList, res: &str) -> i128 {
    l.get(res).map(Quantity::value).unwrap_or(0)
}

/// `getPodMetrics`: the sum over the containers of each measured resource.
fn get_pod_metrics(m: &PodMetrics, measured: &[&str]) -> ResourceList {
    let mut out: ResourceList = measured.iter().map(|r| (r.to_string(), zero())).collect();
    for c in &m.containers {
        for res in measured {
            if let Some(u) = c.usage.get(*res) {
                let cur = out.get(*res).cloned().unwrap_or_else(zero);
                out.insert(res.to_string(), cur.add(u).unwrap_or(cur));
            }
        }
    }
    out
}

/// `ResourceAdder` (metrics_resource_adder.go): totals over pods.
fn add_pod_metrics(total: &mut ResourceList, m: &PodMetrics, measured: &[&str]) {
    let pod = get_pod_metrics(m, measured);
    for res in measured {
        let cur = total.get(*res).cloned().unwrap_or_else(zero);
        if let Some(p) = pod.get(*res) {
            total.insert(res.to_string(), cur.add(p).unwrap_or(cur));
        }
    }
}

/// `TopCmdPrinter`.
pub struct TopCmdPrinter {
    measured_resources: Vec<&'static str>,
    node_columns: Vec<&'static str>,
    pod_columns: Vec<&'static str>,
    nodes_missing_resources: BTreeMap<String, Vec<String>>,
}

impl TopCmdPrinter {
    /// `NewTopCmdPrinter`.
    pub fn new(show_swap: bool) -> Self {
        let mut p = TopCmdPrinter {
            measured_resources: vec![RESOURCE_CPU, RESOURCE_MEMORY],
            node_columns: vec!["NAME", "CPU(cores)", "CPU(%)", "MEMORY(bytes)", "MEMORY(%)"],
            pod_columns: vec!["NAME", "CPU(cores)", "MEMORY(bytes)"],
            nodes_missing_resources: BTreeMap::new(),
        };
        if show_swap {
            p.measured_resources.push(RESOURCE_SWAP);
            p.node_columns.extend(["SWAP(bytes)", "SWAP(%)"]);
            p.pod_columns.push("SWAP(bytes)");
        }
        p
    }

    /// `RegisterMissingResource`.
    pub fn register_missing_resource(&mut self, node: &str, resource: &str) {
        let v = self
            .nodes_missing_resources
            .entry(node.to_string())
            .or_default();
        if !v.iter().any(|r| r == resource) {
            v.push(resource.to_string());
        }
    }

    /// `PrintNodeMetrics`; the tab-aligned text.
    pub fn print_node_metrics(
        &self,
        mut metrics: Vec<NodeMetrics>,
        mut available: BTreeMap<String, ResourceList>,
        no_headers: bool,
        sort_by: &str,
    ) -> String {
        if metrics.is_empty() {
            return String::new();
        }
        // NodeMetricsSorter
        metrics.sort_by(|a, b| match sort_by {
            SORT_BY_CPU => milli(&b.usage, RESOURCE_CPU).cmp(&milli(&a.usage, RESOURCE_CPU)),
            SORT_BY_MEMORY => {
                value(&b.usage, RESOURCE_MEMORY).cmp(&value(&a.usage, RESOURCE_MEMORY))
            }
            _ => a.name.cmp(&b.name),
        });
        let mut out = String::new();
        if !no_headers {
            print_column_names(&mut out, &self.node_columns);
        }
        for m in &metrics {
            let avail = available.remove(&m.name).unwrap_or_default();
            self.print_metrics_line(&mut out, &m.name, &m.usage, &avail);
        }
        // Lines for nodes whose metrics are unreachable (map order is random
        // in Go; sorted here).
        for node in available.keys() {
            print_value(&mut out, node);
            for _ in 0..self.measured_resources.len() {
                print_value(&mut out, "<unknown>");
                print_value(&mut out, "<unknown>");
            }
            out.push('\n');
        }
        crate::printers::table::tab_format(&out)
    }

    /// `PrintPodMetrics`; the tab-aligned text.
    pub fn print_pod_metrics(
        &self,
        mut metrics: Vec<PodMetrics>,
        print_containers: bool,
        with_namespace: bool,
        no_headers: bool,
        sort_by: &str,
        sum: bool,
    ) -> String {
        if metrics.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        let mut column_width = self.pod_columns.len();
        if !no_headers {
            if with_namespace {
                print_value(&mut out, "NAMESPACE");
                column_width += 1;
            }
            if print_containers {
                print_value(&mut out, "POD");
                column_width += 1;
            }
            print_column_names(&mut out, &self.pod_columns);
        }
        // PodMetricsSorter
        let measured = &self.measured_resources;
        let totals: Vec<ResourceList> = metrics
            .iter()
            .map(|m| get_pod_metrics(m, measured))
            .collect();
        let mut order: Vec<usize> = (0..metrics.len()).collect();
        order.sort_by(|&i, &j| match sort_by {
            SORT_BY_CPU => milli(&totals[j], RESOURCE_CPU).cmp(&milli(&totals[i], RESOURCE_CPU)),
            SORT_BY_MEMORY => {
                value(&totals[j], RESOURCE_MEMORY).cmp(&value(&totals[i], RESOURCE_MEMORY))
            }
            _ => {
                if with_namespace && metrics[i].namespace != metrics[j].namespace {
                    return metrics[i].namespace.cmp(&metrics[j].namespace);
                }
                metrics[i].name.cmp(&metrics[j].name)
            }
        });
        let mut sorted: Vec<PodMetrics> = order.iter().map(|&i| metrics[i].clone()).collect();
        std::mem::swap(&mut metrics, &mut sorted);

        let none = ResourceList::new();
        for m in metrics.iter_mut() {
            if print_containers {
                // ContainerMetricsSorter
                m.containers.sort_by(|a, b| match sort_by {
                    SORT_BY_CPU => {
                        milli(&b.usage, RESOURCE_CPU).cmp(&milli(&a.usage, RESOURCE_CPU))
                    }
                    SORT_BY_MEMORY => {
                        value(&b.usage, RESOURCE_MEMORY).cmp(&value(&a.usage, RESOURCE_MEMORY))
                    }
                    _ => a.name.cmp(&b.name),
                });
                for c in &m.containers {
                    if with_namespace {
                        print_value(&mut out, &m.namespace);
                    }
                    print_value(&mut out, &m.name);
                    self.print_metrics_line(&mut out, &c.name, &c.usage, &none);
                }
            } else {
                let pod = get_pod_metrics(m, measured);
                if with_namespace {
                    print_value(&mut out, &m.namespace);
                }
                self.print_metrics_line(&mut out, &m.name, &pod, &none);
            }
        }
        if sum {
            let mut total: ResourceList =
                measured.iter().map(|r| (r.to_string(), zero())).collect();
            for m in &metrics {
                add_pod_metrics(&mut total, m, measured);
            }
            // printPodResourcesSum
            for _ in 0..column_width.saturating_sub(2) {
                print_value(&mut out, "");
            }
            print_value(&mut out, "________");
            print_value(&mut out, "________");
            out.push('\n');
            for _ in 0..column_width.saturating_sub(3) {
                print_value(&mut out, "");
            }
            self.print_metrics_line(&mut out, "", &total, &none);
        }
        crate::printers::table::tab_format(&out)
    }

    /// `printMetricsLine` + `printAllResourceUsages`.
    fn print_metrics_line(
        &self,
        out: &mut String,
        name: &str,
        usage: &ResourceList,
        available: &ResourceList,
    ) {
        print_value(out, name);
        for res in &self.measured_resources {
            if self
                .nodes_missing_resources
                .get(name)
                .is_some_and(|m| m.iter().any(|r| r == res))
            {
                out.push_str("<unknown>\t<unknown>\t");
                continue;
            }
            let q = usage.get(*res).cloned().unwrap_or_else(zero);
            match *res {
                RESOURCE_CPU => out.push_str(&format!("{}m", q.milli_value())),
                RESOURCE_MEMORY | RESOURCE_SWAP => {
                    out.push_str(&format!("{}Mi", q.value() / (1024 * 1024)))
                }
                _ => out.push_str(&q.value().to_string()),
            }
            out.push('\t');
            if let Some(avail) = available.get(*res) {
                let fraction = if avail.is_zero() {
                    0.0
                } else {
                    q.milli_value() as f64 / avail.milli_value() as f64 * 100.0
                };
                out.push_str(&format!("{}%\t", fraction as i64));
            }
        }
        out.push('\n');
    }
}

fn print_value(out: &mut String, v: &str) {
    out.push_str(v);
    out.push('\t');
}

fn print_column_names(out: &mut String, names: &[&str]) {
    for n in names {
        print_value(out, n);
    }
    out.push('\n');
}

/// `SupportedMetricsAPIVersionAvailable` (top.go:84-98) over `/apis`.
pub fn supported_metrics_api_version_available(groups: &Value) -> bool {
    groups
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|g| g.get("name").and_then(Value::as_str) == Some("metrics.k8s.io"))
        .flat_map(|g| {
            g.get("versions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .any(|v| {
            v.get("version")
                .and_then(Value::as_str)
                .is_some_and(|ver| SUPPORTED_METRICS_API_VERSIONS.contains(&ver))
        })
}

fn validate_sort_by(sort_by: &Option<String>) -> Result<()> {
    if let Some(s) = sort_by.as_deref().filter(|s| !s.is_empty()) {
        if s != SORT_BY_CPU && s != SORT_BY_MEMORY {
            bail!("--sort-by accepts only cpu or memory");
        }
    }
    Ok(())
}

/// `TopPodOptions.Validate`.
pub fn validate_top_pod(
    sort_by: &Option<String>,
    name: &Option<String>,
    label_selector: &Option<String>,
    field_selector: &Option<String>,
) -> Result<()> {
    validate_sort_by(sort_by)?;
    let has = |o: &Option<String>| o.as_deref().is_some_and(|s| !s.is_empty());
    if has(name) && (has(label_selector) || has(field_selector)) {
        bail!("only one of NAME or selector can be provided");
    }
    Ok(())
}

/// `TopNodeOptions.Validate`.
pub fn validate_top_node(
    sort_by: &Option<String>,
    name: &Option<String>,
    selector: &Option<String>,
) -> Result<()> {
    validate_sort_by(sort_by)?;
    let has = |o: &Option<String>| o.as_deref().is_some_and(|s| !s.is_empty());
    if has(name) && has(selector) {
        bail!("only one of NAME or --selector can be provided");
    }
    Ok(())
}

/// `checkPodAge` (top_pod.go).
pub fn check_pod_age(pod: &Value, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    let created =
        chrono::DateTime::parse_from_rfc3339(str_at(pod, &["metadata", "creationTimestamp"]))
            .map(|t| t.with_timezone(&chrono::Utc))
            .unwrap_or(now);
    let age = now - created;
    if age.num_seconds() > METRICS_CREATION_DELAY_SECS {
        let nanos = age.num_nanoseconds().unwrap_or(i64::MAX);
        bail!(
            "Metrics not available for pod {}/{}, age: {}",
            str_at(pod, &["metadata", "namespace"]),
            str_at(pod, &["metadata", "name"]),
            kubernetes_rs_common::go_duration::format_go_duration(nanos)
        );
    }
    Ok(())
}

fn query(label: &Option<String>, field: &Option<String>) -> String {
    let enc = crate::commands::delete::urlencoding::encode;
    let mut parts = Vec::new();
    if let Some(l) = label.as_deref().filter(|s| !s.is_empty()) {
        parts.push(format!("labelSelector={}", enc(l)));
    }
    if let Some(f) = field.as_deref().filter(|s| !s.is_empty()) {
        parts.push(format!("fieldSelector={}", enc(f)));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

async fn require_metrics_api(client: &ApiClient) -> Result<()> {
    let groups: Value = client.get("/apis").await.map_err(|e| anyhow!("{e}"))?;
    if !supported_metrics_api_version_available(&groups) {
        bail!("Metrics API not available");
    }
    Ok(())
}

fn items_or_single(v: Value) -> Vec<Value> {
    match v.get("items").and_then(Value::as_array) {
        Some(items) => items.clone(),
        None => vec![v],
    }
}

/// Execute top commands for resource usage
pub async fn execute(
    client: &ApiClient,
    command: TopCommands,
    default_namespace: &str,
) -> Result<()> {
    match command {
        TopCommands::Node {
            name,
            selector,
            sort_by,
            no_headers,
            show_capacity,
            show_swap,
            use_protocol_buffers: _,
        } => {
            validate_top_node(&sort_by, &name, &selector)?;
            let mut printer = TopCmdPrinter::new(show_swap);
            require_metrics_api(client).await?;
            // getNodeMetricsFromMetricsAPI
            let path = match &name {
                Some(n) => format!("/apis/metrics.k8s.io/v1beta1/nodes/{n}"),
                None => format!(
                    "/apis/metrics.k8s.io/v1beta1/nodes{}",
                    query(&selector, &None)
                ),
            };
            let resp: Value = client.get(&path).await.map_err(|e| anyhow!("{e}"))?;
            let metrics: Vec<NodeMetrics> = items_or_single(resp)
                .iter()
                .map(NodeMetrics::from_value)
                .collect();
            if metrics.is_empty() {
                bail!("metrics not available yet");
            }
            let nodes: Vec<Value> = match &name {
                Some(n) => vec![client
                    .get::<Value>(&format!("/api/v1/nodes/{n}"))
                    .await
                    .map_err(|e| anyhow!("{e}"))?],
                None => {
                    let list: Value = client
                        .get(&format!("/api/v1/nodes{}", query(&selector, &None)))
                        .await
                        .map_err(|e| anyhow!("{e}"))?;
                    list.get("items")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                }
            };
            let mut available: BTreeMap<String, ResourceList> = BTreeMap::new();
            for n in &nodes {
                let node_name = str_at(n, &["metadata", "name"]).to_string();
                let key = if show_capacity {
                    "capacity"
                } else {
                    "allocatable"
                };
                let mut list = parse_resource_list(n.pointer(&format!("/status/{key}")));
                match n
                    .pointer("/status/nodeInfo/swap/capacity")
                    .and_then(Value::as_i64)
                {
                    Some(cap) => {
                        list.insert(
                            RESOURCE_SWAP.to_string(),
                            Quantity::from_value(
                                cap,
                                kubernetes_rs_common::quantity::Format::BinarySI,
                            ),
                        );
                    }
                    None => printer.register_missing_resource(&node_name, RESOURCE_SWAP),
                }
                available.insert(node_name, list);
            }
            print!(
                "{}",
                printer.print_node_metrics(
                    metrics,
                    available,
                    no_headers,
                    sort_by.as_deref().unwrap_or("")
                )
            );
        }
        TopCommands::Pod {
            name,
            namespace,
            all_namespaces,
            selector,
            containers,
            field_selector,
            sort_by,
            no_headers,
            sum,
            show_swap,
            use_protocol_buffers: _,
        } => {
            validate_top_pod(&sort_by, &name, &selector, &field_selector)?;
            let ns = namespace
                .as_deref()
                .unwrap_or(default_namespace)
                .to_string();
            let printer = TopCmdPrinter::new(show_swap);
            require_metrics_api(client).await?;
            // getMetricsFromMetricsAPI
            let base = if all_namespaces {
                "/apis/metrics.k8s.io/v1beta1/pods".to_string()
            } else {
                format!("/apis/metrics.k8s.io/v1beta1/namespaces/{ns}/pods")
            };
            // client-go omits the namespace segment when it is "" (all namespaces).
            let path = match &name {
                Some(n) => format!("{base}/{n}"),
                None => format!("{base}{}", query(&selector, &field_selector)),
            };
            let resp: Value = client.get(&path).await.map_err(|e| anyhow!("{e}"))?;
            let metrics: Vec<PodMetrics> = items_or_single(resp)
                .iter()
                .map(PodMetrics::from_value)
                .collect();
            if metrics.is_empty() {
                // verifyEmptyMetrics
                let now = chrono::Utc::now();
                match &name {
                    Some(n) => {
                        let pod: Value = client
                            .get(&format!("/api/v1/namespaces/{ns}/pods/{n}"))
                            .await
                            .map_err(|e| anyhow!("{e}"))?;
                        check_pod_age(&pod, now)?;
                        bail!("metrics not available yet");
                    }
                    None => {
                        let pods_path = if all_namespaces {
                            "/api/v1/pods".to_string()
                        } else {
                            format!("/api/v1/namespaces/{ns}/pods")
                        };
                        let list: Value = client
                            .get(&format!("{pods_path}{}", query(&selector, &field_selector)))
                            .await
                            .map_err(|e| anyhow!("{e}"))?;
                        let pods = list
                            .get("items")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        if !pods.is_empty() {
                            for p in &pods {
                                check_pod_age(p, now)?;
                            }
                            bail!("metrics not available yet");
                        }
                    }
                }
                if all_namespaces {
                    eprintln!("No resources found");
                } else {
                    eprintln!("No resources found in {ns} namespace.");
                }
            }
            print!(
                "{}",
                printer.print_pod_metrics(
                    metrics,
                    containers,
                    all_namespaces,
                    no_headers,
                    sort_by.as_deref().unwrap_or(""),
                    sum
                )
            );
        }
    }
    Ok(())
}
