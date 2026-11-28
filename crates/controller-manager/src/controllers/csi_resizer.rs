//! The CSI external-resizer driver call and its PVC condition helpers.
//!
//! Ported from kubernetes-csi/external-resizer (v1.x, `master`):
//! - `pkg/resizer/csi_resizer.go`: `CanSupport`, `Resize`,
//!   `getVolumeCapabilities`, `GetVolumeCapabilities`.
//! - `pkg/util/util.go`: `IsFinalError`, `IsInfeasibleError`,
//!   `MergeResizeConditionsOfPVC`, `MergePVCConditions`, the
//!   `VolumeResizerKey` / `AnnPreResizeCapacity` / `NodeExpansionNotRequired`
//!   constants.
//!
//! Hand-off from the in-tree expand controller: for a CSI volume
//! `pkg/controller/volume/expand/expand_controller.go` only annotates the PVC
//! with `volume.kubernetes.io/storage-resizer` and records "waiting for an
//! external controller to expand this PVC" (already done by
//! `volume_expansion.rs`); this module is the external controller's driver
//! side. The sync loop, slow-set, in-use tracking, events and wiring are the
//! follow-up task csi-P1-04b.
//!
//! The second half of the file is the recovery state machine ported from
//! `pkg/controller/expand_and_recover.go` (`expandAndRecover`,
//! `callResizeOnPlugin`, `markForSlowRetry`, `pvCanBeExpanded`) and
//! `pkg/controller/resize_status.go` (`markControllerResizeInProgress`,
//! `markForPendingNodeExpansion`, `markControllerExpansionInfeasible`,
//! `markControllerExpansionFailedCondition`, `markOverallExpansionAsFinished`,
//! `mergeStorageResourceStatus`, `mergeStorageAllocatedResources`) and
//! `controller.go` (`updatePVCapacity`, the final-error set). It maintains
//! `status.allocatedResources` / `status.allocatedResourceStatuses`. The
//! functions are pure over the objects: they return the updated PVC / PV and
//! the events to record; PATCHing them (`util.PatchClaim`, `patchPersistentVolume`),
//! the in-use PVC store and the timed slow set are csi-P1-04b.

use anyhow::{anyhow, Result};
use kubernetes_rs_common::quantity::{Format, Quantity};
use kubernetes_rs_common::resources::volume::{
    PersistentVolumeAccessMode, PersistentVolumeClaim, PersistentVolumeClaimCondition,
    PersistentVolumeClaimStatus, PersistentVolumeMode, PersistentVolumeSpec,
};
use kubernetes_rs_common::resources::PersistentVolume;
use kubernetes_rs_csi::controller_client::{ControllerError, CsiControllerClient};
use kubernetes_rs_csi::proto::controller_service_capability::rpc::Type as ControllerRpc;
use kubernetes_rs_csi::proto::volume_capability::{
    AccessMode, AccessType, BlockVolume, MountVolume,
};
use kubernetes_rs_csi::proto::{CapacityRange, ControllerExpandVolumeRequest, VolumeCapability};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::csi_provisioner::to_csi_access_mode;

/// `util.VolumeResizerKey` (pkg/util/util.go:31).
pub const VOLUME_RESIZER_KEY: &str = "volume.kubernetes.io/storage-resizer";
/// `util.AnnPreResizeCapacity` (pkg/util/util.go:49).
pub const ANN_PRE_RESIZE_CAPACITY: &str = "volume.alpha.kubernetes.io/pre-resize-capacity";
/// `util.NodeExpansionNotRequired` (pkg/util/util.go:51).
pub const NODE_EXPANSION_NOT_REQUIRED: &str = "volume.kubernetes.io/node-expansion-not-required";

/// `v1.PersistentVolumeClaimResizing`.
pub const CONDITION_RESIZING: &str = "Resizing";
/// `v1.PersistentVolumeClaimFileSystemResizePending`.
pub const CONDITION_FILE_SYSTEM_RESIZE_PENDING: &str = "FileSystemResizePending";
/// `v1.PersistentVolumeClaimControllerResizeError`.
pub const CONDITION_CONTROLLER_RESIZE_ERROR: &str = "ControllerResizeError";
/// `v1.PersistentVolumeClaimNodeResizeError`.
pub const CONDITION_NODE_RESIZE_ERROR: &str = "NodeResizeError";

/// `knownResizeConditions` (pkg/util/util.go:39-44).
fn is_known_resize_condition(t: &str) -> bool {
    matches!(
        t,
        CONDITION_RESIZING
            | CONDITION_FILE_SYSTEM_RESIZE_PENDING
            | CONDITION_CONTROLLER_RESIZE_ERROR
            | CONDITION_NODE_RESIZE_ERROR
    )
}

/// `MergeResizeConditionsOfPVC` (pkg/util/util.go:57-91): replace resize
/// conditions by the new ones, keep every non-resize condition, and (unless
/// `keep_old_resize_conditions`) drop old resize conditions that have no
/// replacement.
pub fn merge_resize_conditions_of_pvc(
    old: &[PersistentVolumeClaimCondition],
    new: &[PersistentVolumeClaimCondition],
    keep_old_resize_conditions: bool,
) -> Vec<PersistentVolumeClaimCondition> {
    let mut pending: Vec<&PersistentVolumeClaimCondition> = new.iter().collect();
    let mut result = Vec::new();
    for c in old {
        if !is_known_resize_condition(&c.r#type) {
            result.push(c.clone());
            continue;
        }
        if let Some(i) = pending.iter().position(|n| n.r#type == c.r#type) {
            result.push(pending.remove(i).clone());
        } else if keep_old_resize_conditions {
            result.push(c.clone());
        }
    }
    result.extend(pending.into_iter().cloned());
    result
}

/// `MergePVCConditions` (pkg/util/util.go:93-127): replace same-type
/// conditions, keep the rest, and set `lastTransitionTime` (to the new
/// `lastProbeTime` when reason or status changed, else the old value).
pub fn merge_pvc_conditions(
    old: &[PersistentVolumeClaimCondition],
    new: &[PersistentVolumeClaimCondition],
) -> Vec<PersistentVolumeClaimCondition> {
    let mut used = vec![false; new.len()];
    let mut result = Vec::new();
    for o in old {
        match new.iter().position(|n| n.r#type == o.r#type) {
            None => result.push(o.clone()),
            Some(i) => {
                let mut n = new[i].clone();
                n.last_transition_time = if n.reason != o.reason || n.status != o.status {
                    n.last_probe_time.clone()
                } else {
                    o.last_transition_time.clone()
                };
                used[i] = true;
                result.push(n);
            }
        }
    }
    for (i, n) in new.iter().enumerate() {
        if !used[i] {
            let mut n = n.clone();
            n.last_transition_time = n.last_probe_time.clone();
            result.push(n);
        }
    }
    result
}

/// `IsFinalError` (pkg/util/util.go:242-267): the operation either did not
/// start or failed, it is certainly not still running. A non-gRPC error (no
/// RPC was sent) is not final: be on the safe side.
pub fn is_final_error(err: &ControllerError) -> bool {
    use tonic::Code::*;
    match err.status() {
        None => false,
        Some(s) => !matches!(
            s.code(),
            Cancelled | DeadlineExceeded | Unavailable | ResourceExhausted | Aborted
        ),
    }
}

/// `IsInfeasibleError` (pkg/util/util.go:269-285): a subset of the final
/// errors that mark the requested size as infeasible.
pub fn is_infeasible_error(err: &ControllerError) -> bool {
    use tonic::Code::*;
    matches!(
        err.status().map(|s| s.code()),
        Some(InvalidArgument | OutOfRange | NotFound)
    )
}

/// What `csiResizer.Resize` returns on success.
#[derive(Debug, Clone, PartialEq)]
pub struct ResizeOutcome {
    /// The size the driver reports (`capacity_bytes`), `BinarySI`.
    pub new_size: Quantity,
    /// `node_expansion_required`.
    pub node_resize_required: bool,
}

/// A failed `Resize`. The caller keeps the old size (upstream returns it
/// alongside the error).
#[derive(Debug)]
pub enum ResizeError {
    /// Failed before any RPC (translation, empty handle, capabilities).
    Local(String),
    Driver(ControllerError),
}

impl std::fmt::Display for ResizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResizeError::Local(m) => f.write_str(m),
            ResizeError::Driver(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ResizeError {}

impl From<ControllerError> for ResizeError {
    fn from(e: ControllerError) -> Self {
        ResizeError::Driver(e)
    }
}

impl ResizeError {
    pub fn is_final(&self) -> bool {
        matches!(self, ResizeError::Driver(e) if is_final_error(e))
    }
    pub fn is_infeasible(&self) -> bool {
        matches!(self, ResizeError::Driver(e) if is_infeasible_error(e))
    }
}

/// `csiResizer` (pkg/resizer/csi_resizer.go): one CSI driver.
pub struct CsiResizer {
    name: String,
    client: Arc<CsiControllerClient>,
}

impl CsiResizer {
    pub fn new(name: impl Into<String>, client: Arc<CsiControllerClient>) -> Self {
        Self {
            name: name.into(),
            client,
        }
    }

    /// `CanSupport` (csi_resizer.go:112-132), minus the in-tree migration
    /// branch (no in-tree plugins here): a CSI PV of this driver.
    pub fn can_support(&self, pv: &PersistentVolume) -> bool {
        match pv.spec.csi.as_ref() {
            None => false,
            Some(source) => source.driver == self.name,
        }
    }

    /// `Resize` (csi_resizer.go:138-203). `secrets` are the resolved
    /// `controllerExpandSecretRef` credentials (`getCredentials`), supplied
    /// by the caller.
    pub async fn resize(
        &self,
        pv: &PersistentVolume,
        request_size: &Quantity,
        secrets: HashMap<String, String>,
    ) -> std::result::Result<ResizeOutcome, ResizeError> {
        let Some(source) = pv.spec.csi.as_ref() else {
            return Err(ResizeError::Local(format!(
                "volume {} is not migrated to CSI",
                pv.metadata.name
            )));
        };
        let volume_id = source.volume_handle.as_deref().unwrap_or_default();
        if volume_id.is_empty() {
            return Err(ResizeError::Local("empty volume handle".into()));
        }
        let capability = self.volume_capabilities(&pv.spec).await.map_err(|e| {
            ResizeError::Local(format!(
                "failed to get capabilities of volume {} with {e}",
                pv.metadata.name
            ))
        })?;
        let resp = self
            .client
            .controller_expand_volume(ControllerExpandVolumeRequest {
                volume_id: volume_id.to_string(),
                capacity_range: Some(CapacityRange {
                    required_bytes: i64::try_from(request_size.value()).unwrap_or(i64::MAX),
                    limit_bytes: 0,
                }),
                secrets,
                volume_capability: Some(capability),
            })
            .await?;
        Ok(ResizeOutcome {
            new_size: Quantity::from_value(resp.capacity_bytes, Format::BinarySI),
            node_resize_required: resp.node_expansion_required,
        })
    }

    /// `getVolumeCapabilities` (csi_resizer.go:278-285).
    async fn volume_capabilities(&self, spec: &PersistentVolumeSpec) -> Result<VolumeCapability> {
        let caps = self.client.get_driver_capabilities().await?;
        get_volume_capabilities(
            spec,
            caps.controller
                .contains(&ControllerRpc::SingleNodeMultiWriter),
        )
    }
}

/// `GetVolumeCapabilities` (csi_resizer.go:287-324): block or mount access
/// type from the volume mode, access mode from every PV access mode.
pub fn get_volume_capabilities(
    spec: &PersistentVolumeSpec,
    single_node_multi_writer_capable: bool,
) -> Result<VolumeCapability> {
    let source = spec
        .csi
        .as_ref()
        .ok_or_else(|| anyhow!("CSI volume source was nil"))?;
    let access_type = if matches!(spec.volume_mode, Some(PersistentVolumeMode::Block)) {
        AccessType::Block(BlockVolume {})
    } else {
        AccessType::Mount(MountVolume {
            fs_type: source.fs_type.clone().unwrap_or_default(),
            mount_flags: spec.mount_options.clone().unwrap_or_default(),
            volume_mount_group: String::new(),
        })
    };
    let modes: &[PersistentVolumeAccessMode] = &spec.access_modes;
    let mode =
        to_csi_access_mode(modes, single_node_multi_writer_capable).map_err(|e| anyhow!(e))?;
    Ok(VolumeCapability {
        access_type: Some(access_type),
        access_mode: Some(AccessMode { mode: mode as i32 }),
    })
}

// ---------------------------------------------------------------------------
// Recovery state machine (expand_and_recover.go, resize_status.go)
// ---------------------------------------------------------------------------

/// `v1.ResourceStorage`.
pub const RESOURCE_STORAGE: &str = "storage";
/// `v1.PersistentVolumeClaimControllerResizeInProgress` (core/v1 types.go:685).
pub const CLAIM_CONTROLLER_RESIZE_IN_PROGRESS: &str = "ControllerResizeInProgress";
/// `v1.PersistentVolumeClaimControllerResizeInfeasible` (:690).
pub const CLAIM_CONTROLLER_RESIZE_INFEASIBLE: &str = "ControllerResizeInfeasible";
/// `v1.PersistentVolumeClaimNodeResizePending` (:694).
pub const CLAIM_NODE_RESIZE_PENDING: &str = "NodeResizePending";
/// `v1.PersistentVolumeClaimNodeResizeInProgress` (:696).
pub const CLAIM_NODE_RESIZE_IN_PROGRESS: &str = "NodeResizeInProgress";
/// `v1.PersistentVolumeClaimNodeResizeInfeasible` (:699).
pub const CLAIM_NODE_RESIZE_INFEASIBLE: &str = "NodeResizeInfeasible";

/// pkg/util/events.go.
pub const EVENT_VOLUME_RESIZING: &str = "Resizing";
pub const EVENT_VOLUME_RESIZE_FAILED: &str = "VolumeResizeFailed";
pub const EVENT_VOLUME_RESIZE_SUCCESS: &str = "VolumeResizeSuccessful";
pub const EVENT_FILE_SYSTEM_RESIZE_REQUIRED: &str = "FileSystemResizeRequired";

/// An event `expand_and_recover` asks the caller to record on the PVC
/// (`ctrl.eventRecorder.Event`): `(type, reason, message)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ResizeEvent {
    pub event_type: &'static str,
    pub reason: &'static str,
    pub message: String,
}

/// The controller state `expandAndRecover` reads and writes: `finalErrorPVCs`
/// (controller.go:68) and the slow-retry set. The slow set is membership only
/// here; its timed back-off (`TimeRemaining`) belongs to csi-P1-04b.
#[derive(Debug, Default)]
pub struct ResizeState {
    pub final_error_pvcs: HashSet<String>,
    pub slow_set: HashSet<String>,
}

/// What the resizer reports about itself and this PV.
#[derive(Debug, Clone, Copy)]
pub struct ResizerInfo<'a> {
    /// The controller's (driver) name (`ctrl.name`).
    pub name: &'a str,
    /// `resizer.CanSupport(pv, pvc)` ([`CsiResizer::can_support`]).
    pub can_support: bool,
    /// `resizer.DriverSupportsControlPlaneExpansion()`.
    pub driver_supports_control_plane_expansion: bool,
}

/// `expandAndRecover`'s four results: the updated objects, the error, and
/// whether the plugin's resize was called.
#[derive(Debug)]
pub struct ExpandResult {
    pub pvc: PersistentVolumeClaim,
    pub pv: PersistentVolume,
    pub error: Option<String>,
    pub resize_called: bool,
    pub events: Vec<ResizeEvent>,
}

fn ts(now: chrono::DateTime<chrono::Utc>) -> String {
    now.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn pvc_status_mut(pvc: &mut PersistentVolumeClaim) -> &mut PersistentVolumeClaimStatus {
    pvc.status.get_or_insert_with(Default::default)
}

fn parse_q(s: &str) -> Option<Quantity> {
    Quantity::parse(s).ok()
}

fn zero() -> Quantity {
    Quantity::from_value(0, Format::DecimalSI)
}

/// `GetObjectKey` (namespace/name).
fn pvc_key(pvc: &PersistentVolumeClaim) -> String {
    format!(
        "{}/{}",
        pvc.metadata.namespace.as_deref().unwrap_or(""),
        pvc.metadata.name
    )
}

/// `util.HasFileSystemResizePendingCondition`.
pub fn has_file_system_resize_pending_condition(pvc: &PersistentVolumeClaim) -> bool {
    pvc.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|cs| {
            cs.iter()
                .any(|c| c.r#type == CONDITION_FILE_SYSTEM_RESIZE_PENDING && c.status == "True")
        })
}

/// `mergeStorageResourceStatus` (resize_status.go:211-221).
pub fn merge_storage_resource_status(pvc: &mut PersistentVolumeClaim, status: &str) {
    pvc_status_mut(pvc)
        .allocated_resource_statuses
        .get_or_insert_with(HashMap::new)
        .insert(RESOURCE_STORAGE.to_string(), status.to_string());
}

/// `mergeStorageAllocatedResources` (resize_status.go:223-233).
pub fn merge_storage_allocated_resources(pvc: &mut PersistentVolumeClaim, size: &Quantity) {
    pvc_status_mut(pvc)
        .allocated_resources
        .get_or_insert_with(HashMap::new)
        .insert(RESOURCE_STORAGE.to_string(), size.canonical_string());
}

/// `removeNodeExpansionNotRequiredAnnotation` (expand_and_recover.go:177-185).
pub fn remove_node_expansion_not_required_annotation(pvc: &mut PersistentVolumeClaim) {
    if let Some(a) = pvc.metadata.annotations.as_mut() {
        a.remove(NODE_EXPANSION_NOT_REQUIRED);
    }
}

/// `addNodeExpansionNotRequiredAnnotation` (:187-199).
pub fn add_node_expansion_not_required_annotation(pvc: &mut PersistentVolumeClaim) {
    pvc.metadata
        .annotations
        .get_or_insert_with(HashMap::new)
        .insert(NODE_EXPANSION_NOT_REQUIRED.to_string(), "true".to_string());
}

fn condition(
    ty: &str,
    now: chrono::DateTime<chrono::Utc>,
    message: Option<String>,
) -> PersistentVolumeClaimCondition {
    PersistentVolumeClaimCondition {
        r#type: ty.to_string(),
        status: "True".to_string(),
        last_probe_time: None,
        last_transition_time: Some(ts(now)),
        reason: None,
        message,
    }
}

fn merge_conditions(
    pvc: &mut PersistentVolumeClaim,
    new: Vec<PersistentVolumeClaimCondition>,
    keep_old_resize_conditions: bool,
) {
    let st = pvc_status_mut(pvc);
    let old = st.conditions.take().unwrap_or_default();
    st.conditions = Some(merge_resize_conditions_of_pvc(
        &old,
        &new,
        keep_old_resize_conditions,
    ));
}

/// `markControllerResizeInProgress` (resize_status.go:30-66), minus the patch.
pub fn mark_controller_resize_in_progress(
    pvc: &PersistentVolumeClaim,
    new_size: &Quantity,
    update_status: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistentVolumeClaim {
    let mut p = pvc.clone();
    // If we are not updating status then older conditions are preserved.
    merge_conditions(
        &mut p,
        vec![condition(CONDITION_RESIZING, now, None)],
        !update_status,
    );
    remove_node_expansion_not_required_annotation(&mut p);
    if update_status {
        merge_storage_resource_status(&mut p, CLAIM_CONTROLLER_RESIZE_IN_PROGRESS);
    }
    merge_storage_allocated_resources(&mut p, new_size);
    p
}

/// `markForPendingNodeExpansion` (resize_status.go:69-100), minus the patch;
/// the `FileSystemResizeRequired` event is returned.
pub fn mark_for_pending_node_expansion(
    pvc: &PersistentVolumeClaim,
    now: chrono::DateTime<chrono::Utc>,
) -> (PersistentVolumeClaim, ResizeEvent) {
    let mut p = pvc.clone();
    merge_conditions(
        &mut p,
        vec![condition(
            CONDITION_FILE_SYSTEM_RESIZE_PENDING,
            now,
            Some(
                "Waiting for user to (re-)start a pod to finish file system resize of volume on node."
                    .to_string(),
            ),
        )],
        true,
    );
    // Make sure any previously added annotation is removed.
    remove_node_expansion_not_required_annotation(&mut p);
    merge_storage_resource_status(&mut p, CLAIM_NODE_RESIZE_PENDING);
    (
        p,
        ResizeEvent {
            event_type: "Normal",
            reason: EVENT_FILE_SYSTEM_RESIZE_REQUIRED,
            message: "Require file system resize of volume on node".to_string(),
        },
    )
}

/// `markControllerExpansionInfeasible` (resize_status.go:102-130), minus the patch.
pub fn mark_controller_expansion_infeasible(
    pvc: &PersistentVolumeClaim,
    err: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistentVolumeClaim {
    let mut p = pvc.clone();
    merge_storage_resource_status(&mut p, CLAIM_CONTROLLER_RESIZE_INFEASIBLE);
    merge_conditions(
        &mut p,
        vec![condition(
            CONDITION_CONTROLLER_RESIZE_ERROR,
            now,
            Some(format!("failed to expand pvc with {err}")),
        )],
        true,
    );
    p
}

/// `markControllerExpansionFailedCondition` (resize_status.go:132-158), minus the patch.
pub fn mark_controller_expansion_failed_condition(
    pvc: &PersistentVolumeClaim,
    err: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistentVolumeClaim {
    let mut p = pvc.clone();
    merge_conditions(
        &mut p,
        vec![condition(
            CONDITION_CONTROLLER_RESIZE_ERROR,
            now,
            Some(format!("failed to expand pvc with {err}")),
        )],
        true,
    );
    p
}

/// `markOverallExpansionAsFinished` (resize_status.go:160-199), minus the
/// patch; the `VolumeResizeSuccessful` event is returned.
pub fn mark_overall_expansion_as_finished(
    pvc: &PersistentVolumeClaim,
    new_size: &Quantity,
) -> (PersistentVolumeClaim, ResizeEvent) {
    let mut p = pvc.clone();
    let st = pvc_status_mut(&mut p);
    st.capacity
        .get_or_insert_with(HashMap::new)
        .insert(RESOURCE_STORAGE.to_string(), new_size.canonical_string());
    let old = st.conditions.take().unwrap_or_default();
    st.conditions = Some(merge_resize_conditions_of_pvc(&old, &[], false));
    if let Some(m) = st.allocated_resource_statuses.as_mut() {
        m.remove(RESOURCE_STORAGE);
        if m.is_empty() {
            st.allocated_resource_statuses = None;
        }
    }
    // Ensures kubelet does not try to resize the volume again.
    add_node_expansion_not_required_annotation(&mut p);
    (
        p,
        ResizeEvent {
            event_type: "Normal",
            reason: EVENT_VOLUME_RESIZE_SUCCESS,
            message: "Resize volume succeeded".to_string(),
        },
    )
}

/// `updatePVCapacity` (controller.go:450-474) with the `AnnotateFsResize`
/// gate on (GA), minus the patch.
pub fn update_pv_capacity(
    pv: &PersistentVolume,
    old_capacity: &Quantity,
    new_capacity: &Quantity,
    fs_resize_required: bool,
) -> PersistentVolume {
    let mut p = pv.clone();
    p.spec.capacity.insert(
        RESOURCE_STORAGE.to_string(),
        new_capacity.canonical_string(),
    );
    if fs_resize_required
        && !p
            .metadata
            .annotations
            .as_ref()
            .is_some_and(|a| a.contains_key(ANN_PRE_RESIZE_CAPACITY))
    {
        p.metadata
            .annotations
            .get_or_insert_with(HashMap::new)
            .insert(
                ANN_PRE_RESIZE_CAPACITY.to_string(),
                old_capacity.canonical_string(),
            );
    }
    p
}

/// `pvCanBeExpanded` (expand_and_recover.go:289-304).
fn pv_can_be_expanded(
    info: &ResizerInfo<'_>,
    pv: &PersistentVolume,
    pvc: &PersistentVolumeClaim,
) -> bool {
    if !info.can_support {
        return false;
    }
    match pv.spec.claim_ref.as_ref() {
        None => false,
        Some(r) => {
            r.namespace.as_deref().unwrap_or("") == pvc.metadata.namespace.as_deref().unwrap_or("")
                && r.uid.as_deref().unwrap_or("") == pvc.metadata.uid
        }
    }
}

/// `expandAndRecover` (expand_and_recover.go:35-175) with `callResizeOnPlugin`
/// (:213-286): decide the size to expand to from `allocatedResources` and
/// `allocatedResourceStatuses`, mark the PVC, call the driver through `resize`
/// and mark the outcome. Kept verbose like upstream so each case stays explicit.
pub async fn expand_and_recover<F, Fut>(
    state: &mut ResizeState,
    info: ResizerInfo<'_>,
    pvc: &PersistentVolumeClaim,
    pv: &PersistentVolume,
    now: chrono::DateTime<chrono::Utc>,
    resize: F,
) -> ExpandResult
where
    F: FnOnce(PersistentVolume, Quantity) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<ResizeOutcome, ResizeError>>,
{
    let mut events = Vec::new();
    let unchanged = |pvc: &PersistentVolumeClaim, error: Option<String>, events| ExpandResult {
        pvc: pvc.clone(),
        pv: pv.clone(),
        error,
        resize_called: false,
        events,
    };
    if !pv_can_be_expanded(&info, pv, pvc) {
        return unchanged(pvc, None, events);
    }
    // pvc.Spec.Size > pvc.Status.Size is already implied by the caller.
    let get = |m: Option<&HashMap<String, String>>| {
        m.and_then(|m| m.get(RESOURCE_STORAGE))
            .and_then(|s| parse_q(s))
    };
    let pvc_spec_size = get(pvc.spec.resources.requests.as_ref()).unwrap_or_else(zero);
    let status = pvc.status.as_ref();
    let pvc_status_size = get(status.and_then(|s| s.capacity.as_ref())).unwrap_or_else(zero);
    let pv_size = pv
        .spec
        .capacity
        .get(RESOURCE_STORAGE)
        .and_then(|s| parse_q(s))
        .unwrap_or_else(zero);
    let resize_status: &str = status
        .and_then(|s| s.allocated_resource_statuses.as_ref())
        .and_then(|m| m.get(RESOURCE_STORAGE))
        .map(String::as_str)
        .unwrap_or("");
    let allocated_size = get(status.and_then(|s| s.allocated_resources.as_ref()));
    let key = pvc_key(pvc);
    let in_slow_set = state.slow_set.contains(&key);
    let mut update_status = true;
    // markForSlowRetry (:201-207).
    if resize_status == CLAIM_CONTROLLER_RESIZE_INFEASIBLE {
        state.slow_set.insert(key.clone());
    }

    use std::cmp::Ordering::{Equal, Less};
    let mut new_size = pvc_spec_size;
    if pv_size.cmp_value(&pvc_spec_size) == Less {
        // PV is smaller than the requested size: some control-plane expansion
        // is needed, but an earlier operation must finish first.
        match resize_status {
            CLAIM_NODE_RESIZE_INFEASIBLE => {
                if let Some(a) = &allocated_size {
                    new_size = *a;
                }
            }
            CLAIM_NODE_RESIZE_PENDING | CLAIM_NODE_RESIZE_IN_PROGRESS => {
                if let Some(a) = &allocated_size {
                    new_size = *a;
                }
                // Idempotent, but avoids an unnecessary RPC.
                if pv_size.cmp_value(&new_size) != Less {
                    return unchanged(pvc, None, events);
                }
            }
            CLAIM_CONTROLLER_RESIZE_IN_PROGRESS => {
                // Either the previous operation failed with an uncertain error
                // (let it finish) or with a final error we did not record.
                if state.final_error_pvcs.contains(&key) {
                    new_size = pvc_spec_size;
                } else if let Some(a) = &allocated_size {
                    new_size = *a;
                }
            }
            _ => new_size = pvc_spec_size,
        }
    } else {
        // PV is already expanded.
        match resize_status {
            CLAIM_NODE_RESIZE_IN_PROGRESS | CLAIM_NODE_RESIZE_PENDING => {
                return unchanged(pvc, None, events);
            }
            CLAIM_NODE_RESIZE_INFEASIBLE => {
                // Reset so kubelet can safely retry.
                new_size = match &allocated_size {
                    Some(a) if info.driver_supports_control_plane_expansion => *a,
                    _ => pvc_spec_size,
                };
            }
            CLAIM_CONTROLLER_RESIZE_IN_PROGRESS | CLAIM_CONTROLLER_RESIZE_INFEASIBLE => {
                if let Some(a) = &allocated_size {
                    new_size = *a;
                }
            }
            _ => {
                match allocated_size {
                    Some(a) if resize_status.is_empty() => new_size = a,
                    _ => {
                        // Older api-server without the recovery feature.
                        if has_file_system_resize_pending_condition(pvc) {
                            return unchanged(pvc, None, events);
                        }
                        new_size = pvc_spec_size;
                    }
                }
            }
        }
    }
    // Same size as before: no point in changing the status fields again.
    if allocated_size
        .as_ref()
        .is_some_and(|a| a.cmp_value(&new_size) == Equal)
    {
        if in_slow_set {
            let msg = format!(
                "skipping volume expansion for pvc {key}, because expansion previously failed with infeasible error"
            );
            return unchanged(pvc, Some(msg), events);
        }
        update_status = false;
    }

    let pvc = mark_controller_resize_in_progress(pvc, &new_size, update_status, now);
    // (hasInUseErrors / checkForUse: in-use PVC store, csi-P1-04b.)
    events.push(ResizeEvent {
        event_type: "Normal",
        reason: EVENT_VOLUME_RESIZING,
        message: format!("External resizer is resizing volume {}", pv.metadata.name),
    });

    // callResizeOnPlugin (:213-286).
    let outcome = resize(pv.clone(), new_size).await;
    match outcome {
        Err(err) => {
            let mut pvc = pvc;
            let mut extra = String::new();
            if err.is_final() {
                state.final_error_pvcs.insert(key.clone());
                if err.is_infeasible() {
                    pvc = mark_controller_expansion_infeasible(&pvc, &err.to_string(), now);
                } else {
                    // Not infeasible: out of the slow set.
                    state.slow_set.remove(&key);
                    pvc = mark_controller_expansion_failed_condition(&pvc, &err.to_string(), now);
                }
            } else {
                state.slow_set.remove(&key);
                state.final_error_pvcs.remove(&key);
            }
            extra.push_str(&format!(
                "resize volume {:?} by resizer {:?} failed: {err}",
                pv.metadata.name, info.name
            ));
            events.push(ResizeEvent {
                event_type: "Warning",
                reason: EVENT_VOLUME_RESIZE_FAILED,
                message: extra.clone(),
            });
            ExpandResult {
                pvc,
                pv: pv.clone(),
                error: Some(extra),
                resize_called: true,
                events,
            }
        }
        Ok(done) => {
            state.final_error_pvcs.remove(&key);
            state.slow_set.remove(&key);
            let new_pv = update_pv_capacity(
                pv,
                &pvc_status_size,
                &done.new_size,
                done.node_resize_required,
            );
            let pvc = if done.node_resize_required {
                let (p, ev) = mark_for_pending_node_expansion(&pvc, now);
                events.push(ev);
                p
            } else {
                let (p, ev) = mark_overall_expansion_as_finished(&pvc, &done.new_size);
                events.push(ev);
                p
            };
            ExpandResult {
                pvc,
                pv: new_pv,
                error: None,
                resize_called: true,
                events,
            }
        }
    }
}
