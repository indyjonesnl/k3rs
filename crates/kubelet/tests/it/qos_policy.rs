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

/// The remaining pod-level-resources cases of `TestGetContainerOOMScoreAdjust`
/// (policy_test.go:310-656 fixtures, :766-851 table), all at memory capacity
/// 4000000000 with `PodLevelResources` on (its 1.35 default).
#[test]
fn oom_score_adjust_pod_level_resources_remaining_cases() {
    let cap = 4_000_000_000;
    let req = STANDARD_MEMORY_AMOUNT / 8; // sampleDefaultMemRequest
    let lim = 1000 + STANDARD_MEMORY_AMOUNT / 8; // sampleDefaultMemLimit
    let pod_req = STANDARD_MEMORY_AMOUNT / 4; // sampleDefaultPodMemRequest
    let pod_lim = 1000 + STANDARD_MEMORY_AMOUNT / 4; // sampleDefaultPodMemLimit
    let q = |v: i64| v.to_string();
    let none = |n: &str| container(n, json!({}));
    let cr = |n: &str, cpu: &str, mreq: i64, mlim: i64| {
        container(
            n,
            json!({"requests": {"cpu": cpu, "memory": q(mreq)},
                   "limits": {"cpu": "5m", "memory": q(mlim)}}),
        )
    };
    let pod_res = |mreq: i64, mlim: i64| {
        json!({"requests": {"cpu": "5m", "memory": q(mreq)},
               "limits": {"cpu": "5m", "memory": q(mlim)}})
    };
    let always = |mut c: Value| {
        c["restartPolicy"] = json!("Always");
        c
    };

    // guaranteedPodResourcesNoContainerResources: Guaranteed -> -997.
    check(
        "guaranteed-pod-resources-no-container-resources",
        &pod(json!({"resources": pod_res(pod_req, pod_req),
            "containers": [none("no-request-limit-1"), none("no-request-limit-2")]})),
        cap,
        &[
            ("no-request-limit-1", -997, -997),
            ("no-request-limit-2", -997, -997),
        ],
    );
    // guaranteedPodResourcesEqualContainerRequests.
    check(
        "guaranteed-pod-resources-equal-container-resources",
        &pod(json!({"resources": pod_res(pod_req, pod_req),
            "containers": [cr("guaranteed-container-1", "5m", req, req),
                           cr("guaranteed-container-2", "5m", req, req)]})),
        cap,
        &[
            ("guaranteed-container-1", -997, -997),
            ("guaranteed-container-2", -997, -997),
        ],
    );
    // guaranteedPodResourcesUnequalContainerRequests.
    check(
        "guaranteed-pod-resources-unequal-container-requests",
        &pod(json!({"resources": pod_res(pod_req, pod_req),
            "containers": [cr("burstable-container", "3m", req, lim), none("best-effort-container")]})),
        cap,
        &[
            ("burstable-container", -997, -997),
            ("best-effort-container", -997, -997),
        ],
    );
    // burstablePodResourcesEqualContainerRequests: pod limit = podMemLimit.
    check(
        "burstable-pod-resources-equal-container-requests",
        &pod(json!({"resources": pod_res(pod_req, pod_lim),
            "containers": [cr("guaranteed-container-1", "5m", req, req),
                           cr("guaranteed-container-2", "5m", req, req)]})),
        cap,
        &[
            ("guaranteed-container-1", 750, 750),
            ("guaranteed-container-2", 750, 750),
        ],
    );
    // burstablePodResourcesNoContainerResourcesWithSidecar.
    check(
        "burstable-pod-resources-no-container-resources-with-sidecar",
        &pod(json!({"resources": pod_res(pod_req, pod_lim),
            "containers": [none("no-request-limit")],
            "initContainers": [always(none("no-request-limit-sidecar"))]})),
        cap,
        &[
            ("no-request-limit", 750, 750),
            ("no-request-limit-sidecar", 750, 750),
        ],
    );
    // burstablePodResourcesEqualContainerRequestsWithSidecar.
    check(
        "burstable-pod-resources-equal-container-requests-with-sidecar",
        &pod(json!({"resources": pod_res(pod_req, pod_lim),
            "containers": [cr("burstable-container", "5m", req, lim)],
            "initContainers": [always(cr("burstable-sidecar", "5m", req, lim))]})),
        cap,
        &[
            ("burstable-container", 750, 750),
            ("burstable-sidecar", 750, 750),
        ],
    );
    // burstablePodResourcesUnequalContainerRequestsWithSidecar.
    check(
        "burstable-pod-resources-unequal-container-requests-with-sidecar",
        &pod(json!({"resources": pod_res(2_000_000_000, pod_lim),
            "containers": [cr("burstable-container-1", "5m", 1_000_000_000, pod_lim),
                           cr("burstable-container-2", "5m", 500_000_000, pod_lim)],
            "initContainers": [always(cr("burstable-sidecar", "5m", 200_000_000, pod_lim))]})),
        cap,
        &[
            ("burstable-container-1", 725, 725),
            ("burstable-container-2", 850, 850),
            ("burstable-sidecar", 850, 850),
        ],
    );
}
