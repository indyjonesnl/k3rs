//! Ports of `pkg/kubelet/lifecycle/predicate_test.go`
//! (TestRejectPodAdmissionBasedOnOSSelector, ...OSField, TestGeneralPredicates,
//! TestPodAdmissionBasedOnSupplementalGroupsPolicy) plus taint/port cases.

use kubernetes_rs_common::resources::{Node, Pod};
use kubernetes_rs_kubelet::lifecycle_predicate::*;
use serde_json::{json, Value};

fn node(v: Value) -> Node {
    let mut base = json!({"apiVersion":"v1","kind":"Node","metadata":{"name":"machine"}});
    for (k, val) in v.as_object().unwrap() {
        base[k] = val.clone();
    }
    serde_json::from_value(base).unwrap()
}

fn alloc_node(cpu: &str, mem: &str, pods: &str) -> Node {
    node(json!({"status":{"allocatable":{"cpu":cpu,"memory":mem,"pods":pods}}}))
}

fn pod(v: Value) -> Pod {
    let mut base = json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"d"},
        "spec":{"containers":[{"name":"c","image":"i"}]}});
    if let Some(m) = v.get("metadata") {
        for (k, val) in m.as_object().unwrap() {
            base["metadata"][k] = val.clone();
        }
    }
    if let Some(s) = v.get("spec") {
        for (k, val) in s.as_object().unwrap() {
            base["spec"][k] = val.clone();
        }
    }
    serde_json::from_value(base).unwrap()
}

fn req_pod(cpu: &str, mem: &str) -> Pod {
    pod(json!({"spec":{"containers":[{"name":"c","image":"i",
        "resources":{"requests":{"cpu":cpu,"memory":mem}}}]}}))
}

fn run(p: &Pod, others: &[Pod], n: Node) -> PodAdmitResult {
    admit(
        &PodAdmitAttributes {
            pod: p,
            other_pods: others,
        },
        |_| Ok(n.clone()),
    )
}

#[test]
fn kubelet_predicates_os_selector() {
    let n = alloc_node("10", "10G", "10");
    let ok = pod(json!({"metadata":{"labels":{"kubernetes.io/os":"linux"}}}));
    assert!(run(&ok, &[], n.clone()).admit);
    let bad = pod(json!({"metadata":{"labels":{"kubernetes.io/os":"windows"}}}));
    let r = run(&bad, &[], n);
    assert!(!r.admit);
    assert_eq!(r.reason, POD_OS_SELECTOR_NODE_LABEL_DOES_NOT_MATCH);
    assert_eq!(
        r.message,
        "Failed to admit pod as the `kubernetes.io/os` label doesn't match node label"
    );
}

#[test]
fn kubelet_predicates_os_field() {
    let n = alloc_node("10", "10G", "10");
    assert!(
        run(
            &pod(json!({"spec":{"os":{"name":"linux"}}})),
            &[],
            n.clone()
        )
        .admit
    );
    let r = run(&pod(json!({"spec":{"os":{"name":"windows"}}})), &[], n);
    assert!(!r.admit);
    assert_eq!(r.reason, POD_OS_NOT_SUPPORTED);
    assert_eq!(
        r.message,
        "Failed to admit pod as the OS field doesn't match node OS"
    );
}

#[test]
fn kubelet_predicates_supplemental_groups_policy() {
    let strict = pod(json!({"spec":{"securityContext":{"supplementalGroupsPolicy":"Strict"}}}));
    let merge = pod(json!({"spec":{"securityContext":{"supplementalGroupsPolicy":"Merge"}}}));
    let unsupported = alloc_node("10", "10G", "10");
    let supported = node(
        json!({"status":{"allocatable":{"cpu":"10","memory":"10G","pods":"10"},
        "features":{"supplementalGroupsPolicy":true}}}),
    );
    assert!(!run(&strict, &[], unsupported.clone()).admit);
    assert_eq!(
        run(&strict, &[], unsupported.clone()).reason,
        SUPPLEMENTAL_GROUPS_POLICY_NOT_SUPPORTED
    );
    assert!(run(&strict, &[], supported).admit);
    assert!(run(&merge, &[], unsupported.clone()).admit);
    assert!(run(&pod(json!({})), &[], unsupported).admit);
}

#[test]
fn kubelet_predicates_resources() {
    let n = alloc_node("10", "100", "32");
    let existing = req_pod("5", "50");
    // fits
    assert!(
        run(
            &req_pod("5", "50"),
            std::slice::from_ref(&existing),
            n.clone()
        )
        .admit
    );
    // cpu: requested 6000m, used 5000m, capacity 10000m
    let r = run(
        &req_pod("6", "1"),
        std::slice::from_ref(&existing),
        n.clone(),
    );
    assert_eq!(r.reason, OUT_OF_CPU);
    assert_eq!(
        r.message,
        "Node didn't have enough resource: cpu, requested: 6000, used: 5000, capacity: 10000"
    );
    let r = run(&req_pod("1", "60"), &[existing], n);
    assert_eq!(r.reason, OUT_OF_MEMORY);
    assert_eq!(
        r.message,
        "Node didn't have enough resource: memory, requested: 60, used: 50, capacity: 100"
    );
}

#[test]
fn kubelet_predicates_too_many_pods() {
    let n = alloc_node("10", "10G", "1");
    let r = run(&pod(json!({})), &[pod(json!({}))], n);
    assert_eq!(r.reason, OUT_OF_PODS);
    assert_eq!(
        r.message,
        "Node didn't have enough resource: pods, requested: 1, used: 1, capacity: 1"
    );
}

#[test]
fn kubelet_predicates_missing_extended_resource_ignored() {
    let n = alloc_node("10", "10G", "10");
    let p = pod(json!({"spec":{"containers":[{"name":"c","image":"i",
        "resources":{"requests":{"example.com/gpu":"1"}}}]}}));
    assert!(run(&p, &[], n).admit);
    // Advertised but exhausted: rejected with OutOf<name>.
    let n = node(
        json!({"status":{"allocatable":{"cpu":"10","memory":"10G","pods":"10",
        "example.com/gpu":"0"}}}),
    );
    let r = run(&p, &[], n);
    assert_eq!(r.reason, "OutOfexample.com/gpu");
}

#[test]
fn kubelet_predicates_node_name_and_selector() {
    let n = alloc_node("10", "10G", "10");
    let r = run(&pod(json!({"spec":{"nodeName":"other"}})), &[], n.clone());
    assert_eq!(r.reason, "NodeName");
    assert_eq!(
        r.message,
        "Predicate NodeName failed: node(s) didn't match the requested node name"
    );
    let r = run(&pod(json!({"spec":{"nodeSelector":{"a":"b"}}})), &[], n);
    assert_eq!(r.reason, "NodeAffinity");
    assert_eq!(
        r.message,
        "Predicate NodeAffinity failed: node(s) didn't match Pod's node affinity/selector"
    );
}

#[test]
fn kubelet_predicates_node_affinity_refetches_node() {
    let stale = alloc_node("10", "10G", "10");
    let fresh = node(json!({"metadata":{"name":"machine","labels":{"a":"b"}},
        "status":{"allocatable":{"cpu":"10","memory":"10G","pods":"10"}}}));
    let p = pod(json!({"spec":{"nodeSelector":{"a":"b"}}}));
    let mut calls = vec![];
    let r = admit(
        &PodAdmitAttributes {
            pod: &p,
            other_pods: &[],
        },
        |cached| {
            calls.push(cached);
            Ok(if cached { stale.clone() } else { fresh.clone() })
        },
    );
    assert!(r.admit);
    assert_eq!(calls, vec![true, false]);
}

#[test]
fn kubelet_predicates_host_ports() {
    let n = alloc_node("10", "10G", "10");
    let with_port = |ip: Option<&str>| {
        let mut port = json!({"containerPort":80,"hostPort":8080,"protocol":"TCP"});
        if let Some(ip) = ip {
            port["hostIP"] = json!(ip);
        }
        pod(json!({"spec":{"containers":[{"name":"c","image":"i","ports":[port]}]}}))
    };
    let r = run(&with_port(None), &[with_port(Some("10.0.0.1"))], n.clone());
    assert_eq!(r.reason, "NodePorts");
    assert!(
        run(
            &with_port(Some("10.0.0.2")),
            &[with_port(Some("10.0.0.1"))],
            n.clone()
        )
        .admit
    );
    let udp = pod(json!({"spec":{"containers":[{"name":"c","image":"i",
        "ports":[{"containerPort":80,"hostPort":8080,"protocol":"UDP"}]}]}}));
    assert!(run(&udp, &[with_port(None)], n).admit);
}

#[test]
fn kubelet_predicates_noexecute_taint() {
    let n = node(
        json!({"spec":{"taints":[{"key":"k","value":"v","effect":"NoExecute"},
        {"key":"x","effect":"NoSchedule"}]},
        "status":{"allocatable":{"cpu":"10","memory":"10G","pods":"10"}}}),
    );
    let r = run(&pod(json!({})), &[], n.clone());
    assert_eq!(r.reason, "TaintToleration");
    assert_eq!(
        r.message,
        "Predicate TaintToleration failed: node(s) had taints that the pod didn't tolerate"
    );
    let tolerating = pod(
        json!({"spec":{"tolerations":[{"key":"k","operator":"Equal","value":"v","effect":"NoExecute"}]}}),
    );
    assert!(run(&tolerating, &[], n.clone()).admit);
    // Static pods skip the taint check.
    let stat = pod(json!({"metadata":{"annotations":{"kubernetes.io/config.source":"file"}}}));
    assert!(run(&stat, &[], n.clone()).admit);
    let api = pod(json!({"metadata":{"annotations":{"kubernetes.io/config.source":"api"}}}));
    assert!(!run(&api, &[], n).admit);
}

#[test]
fn kubelet_predicates_invalid_node_info() {
    let p = pod(json!({}));
    let r = admit(
        &PodAdmitAttributes {
            pod: &p,
            other_pods: &[],
        },
        |_| Err("boom".into()),
    );
    assert_eq!(r.reason, INVALID_NODE_INFO);
    assert_eq!(r.message, "Kubelet cannot get node info.");
}
