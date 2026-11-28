//! The allocation manager's checkpointed-state half.
//!
//! Port of `pkg/kubelet/allocation/allocation_manager.go` (release-1.35):
//! `allocatedPodsStateFile`, `NewManager` / `newStateImpl` (:142-190),
//! `NewInMemoryManager`, `GetContainerResourceAllocation`,
//! `GetPodLevelResourceAllocation`, `UpdatePodFromAllocation` /
//! `updatePodFromAllocation`, `SetAllocatedResources` / `allocationFromPod`,
//! `RemovePod` and `RemoveOrphanedPods` (:421-560).
//!
//! The rest of upstream's manager (admit handlers, `AddPod`, the pending
//! resize queue and `handlePodResourcesResize`) and the kubelet.rs wiring are
//! separate tasks (kubelet-P1-09c, -09d). Feature gates are read once at
//! construction into [`Gates`] instead of from the process-wide gate on each
//! call, so tests can pick them; production builds them with
//! [`Gates::from_feature_gates`].

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use kubernetes_rs_common::resources::Pod;
use kubernetes_rs_common::types::ResourceRequirements as PodRR;

use super::state::{
    NoopStateCheckpoint, PodResourceInfo, ResourceRequirements, State, StateCheckpoint, StateError,
    StateMemory,
};
use crate::cri_runtime::runtime::is_restartable_init_container;

/// `allocatedPodsStateFile`.
pub const ALLOCATED_PODS_STATE_FILE: &str = "allocated_pods_state";

/// The feature gates the manager reads.
#[derive(Debug, Clone, Copy)]
pub struct Gates {
    /// `features.InPlacePodVerticalScaling` (GA in 1.35).
    pub in_place_pod_vertical_scaling: bool,
    /// `features.InPlacePodLevelResourcesVerticalScaling` (Alpha in 1.35).
    pub in_place_pod_level_resources_vertical_scaling: bool,
}

impl Gates {
    pub fn from_feature_gates() -> Self {
        use kubernetes_rs_common::feature_gates as fg;
        Self {
            in_place_pod_vertical_scaling: fg::gate_enabled("InPlacePodVerticalScaling")
                .unwrap_or(false),
            in_place_pod_level_resources_vertical_scaling: fg::enabled(
                fg::Feature::InPlacePodLevelResourcesVerticalScaling,
            ),
        }
    }
}

/// `v1.ResourceRequirements` to the state's canonical form (nil and empty
/// maps are equal, as under `apiequality.Semantic`).
pub fn to_state_resources(rr: &PodRR) -> ResourceRequirements {
    let canon =
        |m: &Option<std::collections::HashMap<String, String>>| -> BTreeMap<String, String> {
            m.iter()
                .flatten()
                .map(|(k, v)| {
                    let v = kubernetes_rs_common::quantity::Quantity::parse(v)
                        .map(|q| q.canonical_string())
                        .unwrap_or_else(|_| v.clone());
                    (k.clone(), v)
                })
                .collect()
        };
    ResourceRequirements {
        limits: canon(&rr.limits),
        requests: canon(&rr.requests),
        claims: rr
            .claims
            .iter()
            .flatten()
            .filter_map(|c| serde_json::to_value(c).ok())
            .collect(),
    }
}

fn from_state_resources(rr: &ResourceRequirements) -> PodRR {
    let map = |m: &BTreeMap<String, String>| {
        (!m.is_empty()).then(|| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    };
    PodRR {
        limits: map(&rr.limits),
        requests: map(&rr.requests),
        claims: (!rr.claims.is_empty()).then(|| {
            rr.claims
                .iter()
                .filter_map(|c| serde_json::from_value(c.clone()).ok())
                .collect()
        }),
    }
}

fn container_state_resources(rr: &Option<PodRR>) -> ResourceRequirements {
    rr.as_ref().map(to_state_resources).unwrap_or_default()
}

/// `allocationFromPod`.
pub fn allocation_from_pod(pod: &Pod, gates: &Gates) -> PodResourceInfo {
    let mut alloc = PodResourceInfo::default();
    let spec = pod.spec.as_ref();
    if gates.in_place_pod_level_resources_vertical_scaling {
        if let Some(r) = spec.and_then(|s| s.resources.as_ref()) {
            alloc.pod_level_resources = Some(to_state_resources(r));
        }
    }
    for c in spec.map(|s| s.containers.as_slice()).unwrap_or_default() {
        alloc
            .container_resources
            .insert(c.name.clone(), container_state_resources(&c.resources));
    }
    for c in spec
        .and_then(|s| s.init_containers.as_deref())
        .unwrap_or_default()
    {
        if is_restartable_init_container(c) {
            alloc
                .container_resources
                .insert(c.name.clone(), container_state_resources(&c.resources));
        }
    }
    alloc
}

/// `updatePodFromAllocation`: the pod with its resources overwritten by the
/// allocation, and whether anything changed. Clones the pod only when needed.
pub fn update_pod_from_allocation(
    pod: &Pod,
    allocated: &PodResourceInfo,
    gates: &Gates,
) -> (Pod, bool) {
    let mut out: Option<Pod> = None;
    if gates.in_place_pod_level_resources_vertical_scaling {
        let cur = pod
            .spec
            .as_ref()
            .and_then(|s| s.resources.as_ref())
            .map(to_state_resources);
        if cur != allocated.pod_level_resources {
            let mut p = pod.clone();
            if let Some(s) = p.spec.as_mut() {
                s.resources = allocated
                    .pod_level_resources
                    .as_ref()
                    .map(from_state_resources);
            }
            out = Some(p);
        }
    }
    let Some(spec) = pod.spec.as_ref() else {
        return (out.unwrap_or_else(|| pod.clone()), false);
    };
    let differs = |name: &str, res: &Option<PodRR>| -> Option<PodRR> {
        let alloc = allocated.container_resources.get(name)?;
        (container_state_resources(res) != *alloc).then(|| from_state_resources(alloc))
    };
    // Compute the updates against the original spec, apply to the copy.
    let mut updates: Vec<(bool, usize, PodRR)> = Vec::new();
    for (i, c) in spec.containers.iter().enumerate() {
        if let Some(a) = differs(&c.name, &c.resources) {
            updates.push((false, i, a));
        }
    }
    for (i, c) in spec.init_containers.iter().flatten().enumerate() {
        if let Some(a) = differs(&c.name, &c.resources) {
            updates.push((true, i, a));
        }
    }
    if !updates.is_empty() {
        let p = out.get_or_insert_with(|| pod.clone());
        if let Some(s) = p.spec.as_mut() {
            for (init, i, a) in updates {
                if init {
                    if let Some(c) = s.init_containers.as_mut().and_then(|v| v.get_mut(i)) {
                        c.resources = Some(a);
                    }
                } else if let Some(c) = s.containers.get_mut(i) {
                    c.resources = Some(a);
                }
            }
        }
    }
    match out {
        Some(p) => (p, true),
        None => (pod.clone(), false),
    }
}

/// The state-backed part of upstream's `manager`.
pub struct Manager {
    allocated: Arc<dyn State>,
    gates: Gates,
}

impl Manager {
    /// `NewManager`'s state creation (`newStateImpl`): a no-op state without
    /// InPlacePodVerticalScaling, otherwise the checkpoint in
    /// `checkpoint_directory`. A checkpoint that cannot be initialised is a
    /// critical, non-recoverable failure upstream (`panic`), so it is here.
    pub fn new(checkpoint_directory: &Path, gates: Gates) -> Self {
        let allocated: Arc<dyn State> = if !gates.in_place_pod_vertical_scaling {
            Arc::new(NoopStateCheckpoint)
        } else {
            match StateCheckpoint::new(checkpoint_directory, ALLOCATED_PODS_STATE_FILE) {
                Ok(s) => Arc::new(s),
                Err(e) => panic!(
                    "Failed to initialize allocation checkpoint manager (checkpointPath {:?}): {e}",
                    checkpoint_directory.join(ALLOCATED_PODS_STATE_FILE)
                ),
            }
        };
        Self { allocated, gates }
    }

    /// `NewInMemoryManager`'s state: nothing persisted.
    pub fn new_in_memory(gates: Gates) -> Self {
        Self {
            allocated: Arc::new(StateMemory::new(None)),
            gates,
        }
    }

    /// `GetContainerResourceAllocation`.
    pub fn get_container_resource_allocation(
        &self,
        pod_uid: &str,
        container_name: &str,
    ) -> Option<PodRR> {
        self.allocated
            .get_container_resources(pod_uid, container_name)
            .map(|r| from_state_resources(&r))
    }

    /// `GetPodLevelResourceAllocation`: `Some(None)` is a known pod without
    /// pod-level resources.
    pub fn get_pod_level_resource_allocation(&self, pod_uid: &str) -> Option<Option<PodRR>> {
        self.allocated
            .get_pod_level_resources(pod_uid)
            .map(|o| o.as_ref().map(from_state_resources))
    }

    /// `UpdatePodFromAllocation`: the updated (or original) pod and whether an
    /// allocation was stored for it.
    pub fn update_pod_from_allocation(&self, pod: &Pod) -> (Pod, bool) {
        match self.allocated.get_pod_resource_info(&pod.metadata.uid) {
            None => (pod.clone(), false),
            Some(a) => update_pod_from_allocation(pod, &a, &self.gates),
        }
    }

    /// `SetAllocatedResources`: checkpoints the resources allocated to a pod.
    pub fn set_allocated_resources(&self, pod: &Pod) -> Result<(), StateError> {
        self.allocated
            .set_pod_resource_info(&pod.metadata.uid, allocation_from_pod(pod, &self.gates))
    }

    /// `RemovePod`.
    pub fn remove_pod(&self, uid: &str) {
        if let Err(e) = self.allocated.remove_pod(uid) {
            tracing::error!(pod_uid = uid, error = %e, "Failed to remove pod from allocation state");
        }
    }

    /// `RemoveOrphanedPods`.
    pub fn remove_orphaned_pods(&self, remaining_pods: &HashSet<String>) {
        self.allocated.remove_orphaned_pods(remaining_pods);
    }
}
