//! Ports of `TestUpdatePodFromAllocation` (pkg/kubelet/allocation/allocation_manager_test.go:60)
//! plus the state-backed accessors of allocation_manager.go.

use kubernetes_rs_common::resources::Pod;
use kubernetes_rs_kubelet::allocation::manager::*;
use kubernetes_rs_kubelet::allocation::state::{PodResourceInfo, ResourceRequirements};
use serde_json::{json, Value};

fn res(req_cpu: &str, req_mem: &str, lim_cpu: &str, lim_mem: &str) -> Value {
    json!({"requests": {"cpu": req_cpu, "memory": req_mem}, "limits": {"cpu": lim_cpu, "memory": lim_mem}})
}

fn base_pod() -> Value {
    json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"uid": "12345", "name": "test", "namespace": "default"},
        "spec": {
            "containers": [
                {"name": "c1", "resources": res("100m", "200", "300m", "400")},
                {"name": "c2", "resources": res("500m", "600", "700m", "800")}
            ],
            "initContainers": [
                {"name": "c1-restartable-init", "restartPolicy": "Always",
                 "resources": res("200m", "300", "400m", "500")},
                {"name": "c1-init", "resources": res("500m", "600", "700m", "800")}
            ]
        }
    })
}

fn pod(v: &Value) -> Pod {
    serde_json::from_value(v.clone()).unwrap()
}

fn rr(v: &Value) -> ResourceRequirements {
    let m = |k: &str| -> Vec<(String, String)> {
        v[k].as_object()
            .map(|o| {
                o.iter()
                    .map(|(a, b)| (a.clone(), b.as_str().unwrap().to_string()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let req = m("requests");
    let lim = m("limits");
    ResourceRequirements::new(
        req.iter().map(|(a, b)| (a.as_str(), b.as_str())),
        lim.iter().map(|(a, b)| (a.as_str(), b.as_str())),
    )
}

fn alloc_of(p: &Value, pod_level: Option<&Value>) -> PodResourceInfo {
    let mut a = PodResourceInfo::default();
    for c in p["spec"]["containers"].as_array().unwrap() {
        a.container_resources
            .insert(c["name"].as_str().unwrap().into(), rr(&c["resources"]));
    }
    for c in p["spec"]["initContainers"].as_array().unwrap() {
        a.container_resources
            .insert(c["name"].as_str().unwrap().into(), rr(&c["resources"]));
    }
    a.pod_level_resources = pod_level.map(rr);
    a
}

fn gates(pod_level: bool) -> Gates {
    Gates {
        in_place_pod_vertical_scaling: true,
        in_place_pod_level_resources_vertical_scaling: pod_level,
    }
}

#[test]
#[allow(clippy::type_complexity)]
fn allocation_state_update_pod_from_allocation() {
    let base = base_pod();
    let pl = res("1200m", "1700", "2", "2500");
    let mut with_plr = base.clone();
    with_plr["spec"]["resources"] = pl.clone();
    let mut no_container_res = base.clone();
    no_container_res["spec"]["containers"][0]["resources"] = json!({});
    no_container_res["spec"]["initContainers"][0]["resources"] = json!({});
    let mut resized = base.clone();
    resized["spec"]["containers"][0]["resources"]["requests"]["cpu"] = json!("200m");
    resized["spec"]["initContainers"][0]["resources"]["requests"]["cpu"] = json!("300m");
    let pl_resized = res("1500m", "1700", "2200m", "2500");
    let mut resized_plr = resized.clone();
    resized_plr["spec"]["resources"] = pl_resized.clone();

    // (name, pod, allocated, expect_update, expect_pod, pod-level gate)
    let cases: Vec<(&str, &Value, PodResourceInfo, bool, Option<&Value>, bool)> = vec![
        (
            "steady state",
            &base,
            alloc_of(&base, None),
            false,
            None,
            false,
        ),
        (
            "no allocations",
            &base,
            PodResourceInfo::default(),
            false,
            None,
            false,
        ),
        (
            "missing container allocation",
            &base,
            PodResourceInfo {
                container_resources: [(
                    "c2".to_string(),
                    rr(&base["spec"]["containers"][1]["resources"]),
                )]
                .into(),
                ..Default::default()
            },
            false,
            None,
            false,
        ),
        (
            "resized container",
            &base,
            alloc_of(&resized, None),
            true,
            Some(&resized),
            false,
        ),
        (
            "resized pod-level allocation",
            &base,
            alloc_of(&resized, Some(&pl_resized)),
            true,
            Some(&resized_plr),
            true,
        ),
        (
            "resized pod-level resources and allocation",
            &with_plr,
            alloc_of(&resized, Some(&pl_resized)),
            true,
            Some(&resized_plr),
            true,
        ),
        (
            "resized pod-level resources and no container resources",
            &no_container_res,
            alloc_of(&resized, Some(&pl_resized)),
            true,
            Some(&resized_plr),
            true,
        ),
        (
            "resized pod-level resources with feature gate disabled",
            &with_plr,
            alloc_of(&base, None),
            false,
            Some(&with_plr),
            false,
        ),
    ];
    for (name, p, alloc, expect_update, expect_pod, plr) in cases {
        let orig = pod(p);
        let (got, updated) = update_pod_from_allocation(&orig, &alloc, &gates(plr));
        assert_eq!(updated, expect_update, "{name}");
        if expect_update {
            // Compare via JSON with quantities canonicalised through the state form.
            let want = pod(expect_pod.unwrap());
            let canon = |p: &Pod| -> (Vec<ResourceRequirements>, Option<ResourceRequirements>) {
                let s = p.spec.as_ref().unwrap();
                let v: Vec<_> = s
                    .containers
                    .iter()
                    .chain(s.init_containers.iter().flatten())
                    .map(|c| {
                        c.resources
                            .as_ref()
                            .map(to_state_resources)
                            .unwrap_or_default()
                    })
                    .collect();
                (v, s.resources.as_ref().map(to_state_resources))
            };
            assert_eq!(canon(&got), canon(&want), "{name}");
            assert_ne!(canon(&got), canon(&orig), "{name}");
        } else {
            assert_eq!(
                serde_json::to_value(&got).unwrap(),
                serde_json::to_value(&orig).unwrap(),
                "{name}"
            );
        }
    }
}

#[test]
fn allocation_state_manager_set_get_remove() {
    let dir = tempfile::tempdir().unwrap();
    let m = Manager::new(dir.path(), gates(false));
    let p = pod(&base_pod());
    assert!(m.get_container_resource_allocation("12345", "c1").is_none());
    m.set_allocated_resources(&p).unwrap();
    let c1 = m.get_container_resource_allocation("12345", "c1").unwrap();
    assert_eq!(c1.requests.unwrap()["cpu"], "100m");
    // Restartable init containers are recorded, ordinary ones are not.
    assert!(m
        .get_container_resource_allocation("12345", "c1-restartable-init")
        .is_some());
    assert!(m
        .get_container_resource_allocation("12345", "c1-init")
        .is_none());
    assert_eq!(m.get_pod_level_resource_allocation("12345"), Some(None));
    // Allocation equals the spec: nothing to update (updatePodFromAllocation's `updated`).
    let (_, updated) = m.update_pod_from_allocation(&p);
    assert!(!updated);
    // The checkpoint survives a restart.
    let m2 = Manager::new(dir.path(), gates(false));
    assert!(m2
        .get_container_resource_allocation("12345", "c2")
        .is_some());
    m2.remove_pod("12345");
    assert!(m2
        .get_container_resource_allocation("12345", "c2")
        .is_none());
    m2.set_allocated_resources(&p).unwrap();
    m2.remove_orphaned_pods(&Default::default());
    assert!(m2
        .get_container_resource_allocation("12345", "c1")
        .is_none());
}

#[test]
fn allocation_state_manager_noop_without_inplace_scaling() {
    let dir = tempfile::tempdir().unwrap();
    let m = Manager::new(
        dir.path(),
        Gates {
            in_place_pod_vertical_scaling: false,
            in_place_pod_level_resources_vertical_scaling: false,
        },
    );
    let p = pod(&base_pod());
    m.set_allocated_resources(&p).unwrap();
    assert!(m.get_container_resource_allocation("12345", "c1").is_none());
    assert!(!dir.path().join(ALLOCATED_PODS_STATE_FILE).exists());
    // NewInMemoryManager keeps state but never writes a file.
    let mem = Manager::new_in_memory(gates(false));
    mem.set_allocated_resources(&p).unwrap();
    assert!(mem
        .get_container_resource_allocation("12345", "c1")
        .is_some());
}
