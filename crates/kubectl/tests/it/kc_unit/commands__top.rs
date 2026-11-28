//! Ports of `staging/src/k8s.io/kubectl/pkg/metricsutil/metrics_printer_test.go`
//! (`TestPrintNodeMetrics`, `TestPrintPodMetrics`) and the `top` validation.
#![allow(non_snake_case)]

use kubernetes_rs_common::quantity::Quantity;
use kubernetes_rs_kubectl::commands::top::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn node(name: &str, cpu: &str, mem: &str) -> NodeMetrics {
    NodeMetrics::from_value(&json!({
        "metadata": {"name": name}, "usage": {"cpu": cpu, "memory": mem}
    }))
}

fn available(names: &[&str]) -> BTreeMap<String, ResourceList> {
    names
        .iter()
        .map(|n| {
            let mut l = ResourceList::new();
            l.insert("cpu".into(), Quantity::parse("10").unwrap());
            l.insert("memory".into(), Quantity::parse("10Gi").unwrap());
            (n.to_string(), l)
        })
        .collect()
}

fn pod(name: &str, containers: &[(&str, &str, &str)]) -> PodMetrics {
    let cs: Vec<Value> = containers
        .iter()
        .map(|(n, c, m)| json!({"name": n, "usage": {"cpu": c, "memory": m}}))
        .collect();
    PodMetrics::from_value(&json!({
        "metadata": {"name": name, "namespace": "default"}, "containers": cs
    }))
}

#[test]
fn top_print_node_metrics() {
    let p = TopCmdPrinter::new(false);
    let one = vec![node("node1", "1", "1Gi")];
    assert_eq!(
        p.print_node_metrics(one.clone(), available(&["node1"]), false, ""),
        "NAME    CPU(cores)   CPU(%)   MEMORY(bytes)   MEMORY(%)   \nnode1   1000m        10%      1024Mi          10%         \n"
    );
    assert_eq!(
        p.print_node_metrics(one.clone(), available(&["node1"]), true, ""),
        "node1   1000m   10%   1024Mi   10%   \n"
    );
    // A node without metrics prints <unknown>.
    assert_eq!(
        p.print_node_metrics(one, available(&["node1", "node2"]), false, ""),
        "NAME    CPU(cores)   CPU(%)      MEMORY(bytes)   MEMORY(%)   \nnode1   1000m        10%         1024Mi          10%         \nnode2   <unknown>    <unknown>   <unknown>       <unknown>   \n"
    );
    let two = vec![node("node1", "1", "1Gi"), node("node2", "2", "5Gi")];
    assert_eq!(
        p.print_node_metrics(two, available(&["node1", "node2"]), false, "memory"),
        "NAME    CPU(cores)   CPU(%)   MEMORY(bytes)   MEMORY(%)   \nnode2   2000m        20%      5120Mi          50%         \nnode1   1000m        10%      1024Mi          10%         \n"
    );
}

fn two_containers() -> PodMetrics {
    pod(
        "test",
        &[("container1", "0.2", "1Gi"), ("container2", "0.2", "1Gi")],
    )
}

#[test]
fn top_print_pod_metrics() {
    let p = TopCmdPrinter::new(false);
    assert_eq!(
        p.print_pod_metrics(vec![two_containers()], false, false, false, "", false),
        "NAME   CPU(cores)   MEMORY(bytes)   \ntest   400m         2048Mi          \n"
    );
    assert_eq!(
        p.print_pod_metrics(vec![two_containers()], true, false, false, "", false),
        "POD    NAME         CPU(cores)   MEMORY(bytes)   \ntest   container1   200m         1024Mi          \ntest   container2   200m         1024Mi          \n"
    );
    assert_eq!(
        p.print_pod_metrics(vec![two_containers()], false, false, true, "", false),
        "test   400m   2048Mi   \n"
    );
    let test1 = pod(
        "test-1",
        &[("container1", "0.2", "3Gi"), ("container2", "0.2", "2Gi")],
    );
    assert_eq!(
        p.print_pod_metrics(vec![two_containers(), test1.clone()], false, false, false, "memory", false),
        "NAME     CPU(cores)   MEMORY(bytes)   \ntest-1   400m         5120Mi          \ntest     400m         2048Mi          \n"
    );
    assert_eq!(
        p.print_pod_metrics(vec![two_containers(), test1], false, false, false, "", true),
        "NAME     CPU(cores)   MEMORY(bytes)   \ntest     400m         2048Mi          \ntest-1   400m         5120Mi          \n         ________     ________        \n         800m         7168Mi          \n"
    );
}

#[test]
fn top_print_pod_metrics_with_namespace() {
    let p = TopCmdPrinter::new(false);
    let out = p.print_pod_metrics(vec![two_containers()], false, true, false, "", false);
    assert!(
        out.starts_with(
            "NAMESPACE   NAME   CPU(cores)   MEMORY(bytes)   \ndefault     test   400m"
        ),
        "{out}"
    );
}

#[test]
fn top_validate() {
    let s = |v: &str| Some(v.to_string());
    assert!(validate_top_pod(&s("cpu"), &None, &None, &None).is_ok());
    assert_eq!(
        validate_top_pod(&s("disk"), &None, &None, &None)
            .unwrap_err()
            .to_string(),
        "--sort-by accepts only cpu or memory"
    );
    assert_eq!(
        validate_top_pod(&None, &s("p"), &s("a=b"), &None)
            .unwrap_err()
            .to_string(),
        "only one of NAME or selector can be provided"
    );
    assert_eq!(
        validate_top_node(&None, &s("n"), &s("a=b"))
            .unwrap_err()
            .to_string(),
        "only one of NAME or --selector can be provided"
    );
}

#[test]
fn top_metrics_api_availability() {
    let with =
        json!({"groups": [{"name": "metrics.k8s.io", "versions": [{"version": "v1beta1"}]}]});
    let wrong = json!({"groups": [{"name": "metrics.k8s.io", "versions": [{"version": "v1"}]}]});
    let other = json!({"groups": [{"name": "apps", "versions": [{"version": "v1beta1"}]}]});
    assert!(supported_metrics_api_version_available(&with));
    assert!(!supported_metrics_api_version_available(&wrong));
    assert!(!supported_metrics_api_version_available(&other));
}

#[test]
fn top_check_pod_age() {
    let now = chrono::Utc::now();
    let mk = |secs: i64| {
        json!({"metadata": {"name": "p", "namespace": "ns",
            "creationTimestamp": (now - chrono::Duration::seconds(secs)).to_rfc3339()}})
    };
    assert!(check_pod_age(&mk(30), now).is_ok());
    let e = check_pod_age(&mk(300), now).unwrap_err().to_string();
    assert!(
        e.starts_with("Metrics not available for pod ns/p, age: 5m0"),
        "{e}"
    );
}
