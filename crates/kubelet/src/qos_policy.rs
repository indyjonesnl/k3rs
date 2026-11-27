//! QoS-based OOM score adjustment for containers.
//!
//! Port of `pkg/kubelet/qos/policy.go` (`GetContainerOOMScoreAdjust`,
//! `isSidecarContainer`) and `pkg/kubelet/qos/helpers.go`
//! (`minRegularContainerMemory`, `remainingPodMemReqPerContainer`),
//! release-1.35. The kubelet sets the result on
//! `LinuxContainerResources.oom_score_adj`
//! (`kuberuntime_container_linux.go:145`, `generateLinuxContainerResources`).

use kubernetes_rs_common::feature_gates::{self, Feature};
use kubernetes_rs_common::qos::{get_pod_qos, QoSClass};
use kubernetes_rs_common::quantity::Quantity;
use kubernetes_rs_common::quota::{aggregate_container_resources, is_supported_pod_level_resource};
use kubernetes_rs_common::resources::pod::{Container, Pod};
use std::sync::OnceLock;

/// `KubeletOOMScoreAdj`.
pub const KUBELET_OOM_SCORE_ADJ: i64 = -999;
/// `KubeProxyOOMScoreAdj`.
pub const KUBE_PROXY_OOM_SCORE_ADJ: i64 = -999;
const GUARANTEED_OOM_SCORE_ADJ: i64 = -997;
const BESTEFFORT_OOM_SCORE_ADJ: i64 = 1000;

/// `scheduling.SystemNodeCritical`.
const SYSTEM_NODE_CRITICAL: &str = "system-node-critical";

/// `types.IsNodeCriticalPod` (`pkg/kubelet/types/pod_update.go:193`).
fn is_node_critical_pod(pod: &Pod) -> bool {
    crate::eviction::is_critical_pod(pod)
        && pod
            .spec
            .as_ref()
            .and_then(|s| s.priority_class_name.as_deref())
            == Some(SYSTEM_NODE_CRITICAL)
}

/// `container.Resources.Requests.Memory().Value()`.
fn container_memory_request(container: &Container) -> i64 {
    container
        .resources
        .as_ref()
        .and_then(|r| r.requests.as_ref())
        .and_then(|m| m.get("memory"))
        .and_then(|q| Quantity::parse(q).ok())
        .map_or(0, |q| q.value() as i64)
}

/// `isSidecarContainer`: a restartable init container.
fn is_sidecar_container(pod: &Pod, container: &Container) -> bool {
    container.restart_policy.as_deref() == Some("Always")
        && pod.spec.as_ref().is_some_and(|s| {
            s.init_containers
                .iter()
                .flatten()
                .any(|c| c.name == container.name)
        })
}

/// `minRegularContainerMemory` (helpers.go:36): the smallest memory request
/// over `spec.containers`.
fn min_regular_container_memory(pod: &Pod) -> i64 {
    pod.spec
        .as_ref()
        .map(|s| s.containers.iter().map(container_memory_request))
        .and_then(|it| it.min())
        .unwrap_or(0)
}

/// `resourcehelper.IsPodLevelRequestsSet`
/// (`component-helpers/resource/helpers.go:106`).
fn is_pod_level_requests_set(pod: &Pod) -> bool {
    pod.spec
        .as_ref()
        .and_then(|s| s.resources.as_ref())
        .and_then(|r| r.requests.as_ref())
        .is_some_and(|m| m.keys().any(|k| is_supported_pod_level_resource(k)))
}

/// `remainingPodMemReqPerContainer` (helpers.go:56): the pod-level memory
/// request not claimed by any container, split evenly across all containers.
fn remaining_pod_mem_req_per_container(pod: &Pod) -> i64 {
    let Some(spec) = pod.spec.as_ref() else {
        return 0;
    };
    let pod_mem = spec
        .resources
        .as_ref()
        .and_then(|r| r.requests.as_ref())
        .and_then(|m| m.get("memory"))
        .and_then(|q| Quantity::parse(q).ok())
        .map_or(0, |q| q.value() as i64);
    if pod_mem == 0 {
        return 0;
    }
    let num_containers =
        (spec.containers.len() + spec.init_containers.iter().flatten().count()) as i64;
    let aggregated = aggregate_container_resources(pod, true)
        .get("memory")
        .map_or(0, |q| q.value() as i64);
    (pod_mem - aggregated) / num_containers
}

/// `GetContainerOOMScoreAdjust` (policy.go:45): the amount by which the OOM
/// score of all processes in the container is adjusted. `memory_capacity` is
/// the machine's memory in bytes (`machineInfo.MemoryCapacity`).
pub fn get_container_oom_score_adjust(
    pod: &Pod,
    container: &Container,
    memory_capacity: i64,
) -> i64 {
    if is_node_critical_pod(pod) {
        // Only node critical pod should be the last to get killed.
        return GUARANTEED_OOM_SCORE_ADJ;
    }

    match get_pod_qos(pod) {
        // Guaranteed containers should be the last to get killed.
        QoSClass::Guaranteed => return GUARANTEED_OOM_SCORE_ADJ,
        QoSClass::BestEffort => return BESTEFFORT_OOM_SCORE_ADJ,
        QoSClass::Burstable => {}
    }

    // Burstable containers are a middle tier: protect those that consume less
    // memory than requested (policy.go:68-90).
    let container_mem_req = container_memory_request(container);
    let pod_level =
        feature_gates::enabled(Feature::PodLevelResources) && is_pod_level_requests_set(pod);
    let mut remaining_req_per_container = 0;
    let mut oom_score_adjust = if pod_level {
        remaining_req_per_container = remaining_pod_mem_req_per_container(pod);
        1000 - (1000 * (container_mem_req + remaining_req_per_container) / memory_capacity)
    } else {
        1000 - (1000 * container_mem_req) / memory_capacity
    };

    // A sidecar's adjustment matches or falls below the regular containers'
    // (policy.go:92-111).
    if is_sidecar_container(pod, container) {
        let mut min_memory_request = min_regular_container_memory(pod);
        if pod_level {
            min_memory_request += remaining_req_per_container;
        }
        let min_memory_oom_score_adjust = 1000 - (1000 * min_memory_request) / memory_capacity;
        if oom_score_adjust > min_memory_oom_score_adjust {
            oom_score_adjust = min_memory_oom_score_adjust;
        }
    }

    // A guaranteed pod using 100% of memory can have an OOM score of 10:
    // keep burstable pods above that.
    if oom_score_adjust < 1000 + GUARANTEED_OOM_SCORE_ADJ {
        return 1000 + GUARANTEED_OOM_SCORE_ADJ;
    }
    // Give burstable pods a higher chance of survival over besteffort pods.
    if oom_score_adjust == BESTEFFORT_OOM_SCORE_ADJ {
        return oom_score_adjust - 1;
    }
    oom_score_adjust
}

/// `machineInfo.MemoryCapacity`: `MemTotal` from `/proc/meminfo` in bytes
/// (cadvisor `getMemoryCapacity`), or 0 if it cannot be read.
pub fn machine_memory_capacity() -> i64 {
    static CAP: OnceLock<i64> = OnceLock::new();
    *CAP.get_or_init(|| {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    let rest = l.strip_prefix("MemTotal:")?;
                    let kb: i64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
                    Some(kb * 1024)
                })
            })
            .unwrap_or(0)
    })
}
