//! Port of `pkg/kubelet/qos/policy_test.go` `TestGetContainerOOMScoreAdjust`
//! (subset: every container-level case plus the pod-level-resources cases
//! derived from `burstablePodResources*`).

use kubernetes_rs_common::resources::pod::Pod;
use kubernetes_rs_kubelet::qos_policy::get_container_oom_score_adjust;
use serde_json::{json, Value};

const STANDARD_MEMORY_AMOUNT: i64 = 8_000_000_000;

fn pod(spec: Value) -> Pod {
    serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "p", "namespace": "ns"},
        "spec": spec,
    }))
    .unwrap()
}

fn mem(req: Option<i64>, lim: Option<i64>) -> Value {
    let mut r = serde_json::Map::new();
    if let Some(v) = req {
        r.insert("requests".into(), json!({"memory": v.to_string()}));
    }
    if let Some(v) = lim {
        r.insert("limits".into(), json!({"memory": v.to_string()}));
    }
    Value::Object(r)
}

fn container(name: &str, resources: Value) -> Value {
    json!({"name": name, "image": "i", "resources": resources})
}

fn sidecar(name: &str, req: i64) -> Value {
    let mut c = container(
        name,
        mem(Some(req), Some(1000 + STANDARD_MEMORY_AMOUNT / 8)),
    );
    c["restartPolicy"] = json!("Always");
    c
}

/// `oomTest`: every (init + regular) container must land in `[low, high]`.
fn check(name: &str, p: &Pod, capacity: i64, want: &[(&str, i64, i64)]) {
    let spec = p.spec.as_ref().unwrap();
    for c in spec
        .init_containers
        .iter()
        .flatten()
        .chain(spec.containers.iter())
    {
        let (_, low, high) = want
            .iter()
            .find(|(n, _, _)| *n == c.name)
            .unwrap_or_else(|| panic!("{name}: no expectation for {}", c.name));
        let got = get_container_oom_score_adjust(p, c, capacity);
        assert!(
            (*low..=*high).contains(&got),
            "{name}/{}: oom_score_adj should be between {low} and {high}, but was {got}",
            c.name
        );
    }
}

#[test]
fn oom_score_adjust_container_level_cases() {
    let sample_req = STANDARD_MEMORY_AMOUNT / 8;
    let sample_lim = 1000 + STANDARD_MEMORY_AMOUNT / 8;
    let sample = || container("main-1", mem(Some(sample_req), Some(sample_lim)));
    let init = || container("init-container", mem(Some(sample_req), Some(sample_lim)));

    check(
        "cpu-limit",
        &pod(json!({"containers": [container("cpu-limit", json!({"limits": {"cpu": "10"}}))]})),
        4_000_000_000,
        &[("cpu-limit", 999, 999)],
    );
    check(
        "memory-limit-cpu-request",
        &pod(json!({"containers": [container("memory-limit-cpu-request",
            json!({"requests": {"cpu": "0"}, "limits": {"memory": "10G"}}))]})),
        8_000_000_000,
        &[("memory-limit-cpu-request", 999, 999)],
    );
    check(
        "zero-memory-limit",
        &pod(
            json!({"containers": [container("zero-memory-limit", json!({"limits": {"memory": "0"}}))]}),
        ),
        7_230_457_451,
        &[("zero-memory-limit", 1000, 1000)],
    );
    check(
        "no-request-limit",
        &pod(json!({"containers": [container("no-request-limit", json!({}))]})),
        4_000_000_000,
        &[("no-request-limit", 1000, 1000)],
    );
    check(
        "equal-request-limit-cpu-memory",
        &pod(
            json!({"containers": [container("equal-request-limit-cpu-memory", json!({
            "requests": {"memory": "10G", "cpu": "5m"}, "limits": {"cpu": "5m", "memory": "10G"}}))]}),
        ),
        123_456_789,
        &[("equal-request-limit-cpu-memory", -997, -997)],
    );
    check(
        "cpu-unlimited-memory-limited-with-requests",
        &pod(
            json!({"containers": [container("cpu-unlimited-memory-limited-with-requests", json!({
            "requests": {"memory": (STANDARD_MEMORY_AMOUNT / 2).to_string(), "cpu": "5m"},
            "limits": {"memory": "10G"}}))]}),
        ),
        STANDARD_MEMORY_AMOUNT,
        &[("cpu-unlimited-memory-limited-with-requests", 495, 505)],
    );
    check(
        "request-no-limit",
        &pod(json!({"containers": [container("request-no-limit", json!({
            "requests": {"memory": (STANDARD_MEMORY_AMOUNT - 1).to_string(), "cpu": "5m"}}))]})),
        STANDARD_MEMORY_AMOUNT,
        &[("request-no-limit", 3, 3)],
    );
    check(
        "cluster-critical",
        &pod(
            json!({"priorityClassName": "system-cluster-critical", "priority": 2_000_000_000,
            "containers": [container("cluster-critical", json!({}))]}),
        ),
        4_000_000_000,
        &[("cluster-critical", 1000, 1000)],
    );
    check(
        "node-critical",
        &pod(
            json!({"priorityClassName": "system-node-critical", "priority": 2_000_001_000i64,
            "containers": [container("node-critical", json!({}))]}),
        ),
        4_000_000_000,
        &[("node-critical", -997, -997)],
    );
    check(
        "burstable-unique-container-pod",
        &pod(
            json!({"containers": [container("burstable-unique-container",
            mem(Some(sample_req), Some(sample_lim)))]}),
        ),
        STANDARD_MEMORY_AMOUNT,
        &[("burstable-unique-container", 875, 880)],
    );
    check(
        "burstable-mixed-unique-main-container-pod",
        &pod(json!({"initContainers": [init()], "containers": [sample()]})),
        STANDARD_MEMORY_AMOUNT,
        &[("init-container", 875, 880), ("main-1", 875, 880)],
    );
    check(
        "burstable-mixed-multi-container-small-sidecar-pod",
        &pod(
            json!({"initContainers": [init(), sidecar("sidecar-small-container", STANDARD_MEMORY_AMOUNT / 20)],
            "containers": [sample()]}),
        ),
        STANDARD_MEMORY_AMOUNT,
        &[
            ("init-container", 875, 880),
            ("sidecar-small-container", 875, 875),
            ("main-1", 875, 875),
        ],
    );
    check(
        "burstable-mixed-multi-container-sample-request-pod",
        &pod(
            json!({"initContainers": [init(), sidecar("sidecar-container", sample_req)],
            "containers": [sample()]}),
        ),
        STANDARD_MEMORY_AMOUNT,
        &[
            ("init-container", 875, 880),
            ("sidecar-container", 875, 875),
            ("main-1", 875, 875),
        ],
    );
    check(
        "burstable-mixed-multi-container-big-sidecar-container-pod",
        &pod(
            json!({"initContainers": [init(), sidecar("sidecar-big-container", STANDARD_MEMORY_AMOUNT / 2)],
            "containers": [sample()]}),
        ),
        STANDARD_MEMORY_AMOUNT,
        &[
            ("init-container", 875, 880),
            ("sidecar-big-container", 500, 500),
            ("main-1", 875, 875),
        ],
    );
}

#[test]
fn oom_score_adjust_pod_level_resources_cases() {
    let pod_req = STANDARD_MEMORY_AMOUNT / 4;
    let no_res = |n: &str| container(n, json!({}));
    // burstablePodResourcesNoContainerResources: pod-level request only, split
    // across both containers: 1000 - 1000*(1e9)/4e9 = 750.
    check(
        "burstable-pod-resources-no-container-resources",
        &pod(json!({
            "resources": {"requests": {"cpu": "5m", "memory": pod_req.to_string()}},
            "containers": [no_res("no-request-limit-1"), no_res("no-request-limit-2")]})),
        4_000_000_000,
        &[
            ("no-request-limit-1", 750, 750),
            ("no-request-limit-2", 750, 750),
        ],
    );
    // burstablePodResourcesUnequalContainerRequests (policy_test.go:480).
    check(
        "burstable-pod-resources-unequal-container-requests",
        &pod(json!({
            "resources": {"requests": {"cpu": "5m", "memory": pod_req.to_string()},
                          "limits": {"cpu": "5m", "memory": (1000 + pod_req).to_string()}},
            "containers": [
                container("burstable-container", json!({
                    "requests": {"cpu": "3m", "memory": (STANDARD_MEMORY_AMOUNT / 8).to_string()},
                    "limits": {"cpu": "5m", "memory": (STANDARD_MEMORY_AMOUNT / 8).to_string()}})),
                no_res("best-effort-container")]})),
        4_000_000_000,
        &[
            ("burstable-container", 625, 625),
            ("best-effort-container", 875, 875),
        ],
    );
}
