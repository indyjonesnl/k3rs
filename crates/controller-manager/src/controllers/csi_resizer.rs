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

use anyhow::{anyhow, Result};
use kubernetes_rs_common::quantity::{Format, Quantity};
use kubernetes_rs_common::resources::volume::{
    PersistentVolumeAccessMode, PersistentVolumeClaimCondition, PersistentVolumeMode,
    PersistentVolumeSpec,
};
use kubernetes_rs_common::resources::PersistentVolume;
use kubernetes_rs_csi::controller_client::{ControllerError, CsiControllerClient};
use kubernetes_rs_csi::proto::controller_service_capability::rpc::Type as ControllerRpc;
use kubernetes_rs_csi::proto::volume_capability::{
    AccessMode, AccessType, BlockVolume, MountVolume,
};
use kubernetes_rs_csi::proto::{CapacityRange, ControllerExpandVolumeRequest, VolumeCapability};
use std::collections::HashMap;
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
// VolumeAttributesClass ModifyVolume path.
//
// Ported from kubernetes-csi/external-resizer (`master`, 1bc6d98):
// - `pkg/modifycontroller/modify_volume.go`: `modify`, `rolledBack`,
//   `getTargetVAC`, `validateVACAndModifyVolumeWithTarget`,
//   `controllerModifyVolumeWithTarget`, `callModifyVolumeOnPlugin`,
//   `delayModificationIfRecentlyInfeasible`, `markForSlowRetry`.
// - `pkg/modifycontroller/modify_status.go`: `markControllerModifyVolumeStatus`,
//   `markControllerModifyVolumeCompleted`, `clearModifyVolumeConditions`,
//   `markRolledBack`.
// - `pkg/modifier/csi_modifier.go`: `Modify`, `getModifyCredentials`.
// - `pkg/util/events.go`, `pkg/util/errors.go` (`DelayRetryError`),
//   `csi-lib-utils/slowset/slowset.go`.
// The informer/queue wiring (`controller.go`) is csi-P1-06b.
// ---------------------------------------------------------------------------

use kubernetes_rs_common::resources::csi::VolumeAttributesClass;
use kubernetes_rs_common::resources::volume::{ModifyVolumeStatus, PersistentVolumeClaim};
use kubernetes_rs_csi::proto::ControllerModifyVolumeRequest;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `pvcNameKey`, `pvcNamespaceKey`, `pvNameKey` (modify_volume.go:41-43).
pub const PVC_NAME_KEY: &str = "csi.storage.k8s.io/pvc/name";
pub const PVC_NAMESPACE_KEY: &str = "csi.storage.k8s.io/pvc/namespace";
pub const PV_NAME_KEY: &str = "csi.storage.k8s.io/pv/name";

/// `modifySecretNameAnn` / `modifySecretNamespaceAnn` (csi_modifier.go:35-36).
pub const MODIFY_SECRET_NAME_ANN: &str = "volume.kubernetes.io/controller-modify-secret-name";
pub const MODIFY_SECRET_NAMESPACE_ANN: &str =
    "volume.kubernetes.io/controller-modify-secret-namespace";

/// `v1.PersistentVolumeClaimVolumeModifyVolumeError` / `...ModifyingVolume`.
pub const CONDITION_MODIFY_VOLUME_ERROR: &str = "ModifyVolumeError";
pub const CONDITION_MODIFYING_VOLUME: &str = "ModifyingVolume";

/// `v1.PersistentVolumeClaimModifyVolume{Pending,InProgress,Infeasible}`.
pub const MODIFY_PENDING: &str = "Pending";
pub const MODIFY_IN_PROGRESS: &str = "InProgress";
pub const MODIFY_INFEASIBLE: &str = "Infeasible";

/// Event reasons (pkg/util/events.go:24-27).
pub const EVENT_VOLUME_MODIFY: &str = "VolumeModify";
pub const EVENT_VOLUME_MODIFY_FAILED: &str = "VolumeModifyFailed";
pub const EVENT_VOLUME_MODIFY_SUCCESS: &str = "VolumeModifySuccessful";
pub const EVENT_VOLUME_MODIFY_CANCELLED: &str = "VolumeModifyCanceled";

/// A failure of the modify path. Upstream passes plain `error`s around; the
/// gRPC status is recovered with `status.FromError`, so only `Driver` has one.
#[derive(Debug)]
pub enum ModifyError {
    /// `util.DelayRetryError`: retry after `try_after`.
    DelayRetry { msg: String, try_after: Duration },
    /// A CSI driver call failure (carries a gRPC status unless it was local).
    Driver(ControllerError),
    /// Any other error (no gRPC status): store, lister or local failures.
    Other(String),
}

impl std::fmt::Display for ModifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModifyError::DelayRetry { msg, .. } => f.write_str(msg),
            ModifyError::Driver(e) => e.fmt(f),
            ModifyError::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ModifyError {}

impl ModifyError {
    /// `util.IsDelayRetryError`.
    pub fn is_delay_retry(&self) -> bool {
        matches!(self, ModifyError::DelayRetry { .. })
    }
}

/// `slowset.SlowSet`: keys retried at a slower rate. An entry stays for
/// `retention`; `Run`'s 100ms expiry sweep is done lazily on access.
pub struct SlowSet {
    retention: Duration,
    set: Mutex<HashMap<String, Instant>>,
}

impl SlowSet {
    pub fn new(retention: Duration) -> Self {
        Self {
            retention,
            set: Mutex::new(HashMap::new()),
        }
    }

    /// `Add`: does not overwrite a live entry.
    pub fn add(&self, key: &str) -> bool {
        let mut set = self.set.lock().unwrap();
        if let Some(t) = set.get(key) {
            if t.elapsed() <= self.retention {
                return false;
            }
        }
        set.insert(key.to_string(), Instant::now());
        true
    }

    /// `Contains`: present and younger than the retention time.
    pub fn contains(&self, key: &str) -> bool {
        self.set
            .lock()
            .unwrap()
            .get(key)
            .is_some_and(|t| t.elapsed() < self.retention)
    }

    pub fn remove(&self, key: &str) {
        self.set.lock().unwrap().remove(key);
    }

    /// `TimeRemaining`.
    pub fn time_remaining(&self, key: &str) -> Duration {
        self.set
            .lock()
            .unwrap()
            .get(key)
            .map(|t| self.retention.saturating_sub(t.elapsed()))
            .unwrap_or_default()
    }
}

/// The `modifier.Modifier` seam: one `ControllerModifyVolume` call.
#[async_trait::async_trait]
pub trait Modifier: Send + Sync {
    async fn modify(
        &self,
        pv: &PersistentVolume,
        mutable_parameters: HashMap<String, String>,
    ) -> std::result::Result<(), ControllerError>;
}

/// The API-server side of the modify controller: the VAC lister, `PatchClaim`,
/// `PatchPersistentVolume` and the event recorder.
#[async_trait::async_trait]
pub trait ModifyStore: Send + Sync {
    /// `vacLister.Get`: `Ok(None)` is NotFound.
    async fn get_vac(
        &self,
        name: &str,
    ) -> std::result::Result<Option<VolumeAttributesClass>, String>;
    /// `util.PatchClaim` (a status patch); `check_resource_version` is
    /// `addResourceVersionCheck`.
    async fn patch_claim(
        &self,
        old: &PersistentVolumeClaim,
        new: &PersistentVolumeClaim,
        check_resource_version: bool,
    ) -> std::result::Result<PersistentVolumeClaim, String>;
    /// `util.PatchPersistentVolume`.
    async fn patch_pv(
        &self,
        old: &PersistentVolume,
        new: &PersistentVolume,
    ) -> std::result::Result<PersistentVolume, String>;
    /// `eventRecorder.Event(f)` on the PVC; `event_type` is Normal or Warning.
    async fn record_event(
        &self,
        pvc: &PersistentVolumeClaim,
        event_type: &str,
        reason: &str,
        message: String,
    );
}

#[async_trait::async_trait]
impl<T: Modifier + ?Sized> Modifier for Arc<T> {
    async fn modify(
        &self,
        pv: &PersistentVolume,
        mutable_parameters: HashMap<String, String>,
    ) -> std::result::Result<(), ControllerError> {
        (**self).modify(pv, mutable_parameters).await
    }
}

#[async_trait::async_trait]
impl<T: ModifyStore + ?Sized> ModifyStore for Arc<T> {
    async fn get_vac(
        &self,
        name: &str,
    ) -> std::result::Result<Option<VolumeAttributesClass>, String> {
        (**self).get_vac(name).await
    }
    async fn patch_claim(
        &self,
        old: &PersistentVolumeClaim,
        new: &PersistentVolumeClaim,
        check_resource_version: bool,
    ) -> std::result::Result<PersistentVolumeClaim, String> {
        (**self).patch_claim(old, new, check_resource_version).await
    }
    async fn patch_pv(
        &self,
        old: &PersistentVolume,
        new: &PersistentVolume,
    ) -> std::result::Result<PersistentVolume, String> {
        (**self).patch_pv(old, new).await
    }
    async fn record_event(
        &self,
        pvc: &PersistentVolumeClaim,
        event_type: &str,
        reason: &str,
        message: String,
    ) {
        (**self)
            .record_event(pvc, event_type, reason, message)
            .await
    }
}

/// `csiModifier.getModifyCredentials` (csi_modifier.go:107-117): the secret
/// named by the PV's modify annotations, else the PV's
/// `controllerExpandSecretRef`. `None` means no credentials.
pub fn modify_secret_ref(pv: &PersistentVolume) -> Option<(String, String)> {
    let ann = |k: &str| {
        pv.metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(k))
            .cloned()
            .unwrap_or_default()
    };
    let (name, ns) = (
        ann(MODIFY_SECRET_NAME_ANN),
        ann(MODIFY_SECRET_NAMESPACE_ANN),
    );
    if !ns.is_empty() && !name.is_empty() {
        return Some((ns, name));
    }
    let r = pv
        .spec
        .csi
        .as_ref()?
        .controller_expand_secret_ref
        .as_ref()?;
    Some((
        r.namespace.clone().unwrap_or_default(),
        r.name.clone().unwrap_or_default(),
    ))
}

/// `csiModifier.Modify` (csi_modifier.go:70-100) with the credentials already
/// resolved by the caller (`getModifyCredentials`).
pub async fn csi_modify(
    client: &CsiControllerClient,
    pv: &PersistentVolume,
    secrets: HashMap<String, String>,
    mutable_parameters: HashMap<String, String>,
) -> std::result::Result<(), ModifyError> {
    let Some(source) = pv.spec.csi.as_ref() else {
        return Err(ModifyError::Other(format!(
            "volume {} is not a CSI volumes, modify volume feature only supports CSI volumes",
            pv.metadata.name
        )));
    };
    let volume_id = source.volume_handle.clone().unwrap_or_default();
    if volume_id.is_empty() {
        return Err(ModifyError::Other("empty volume handle".into()));
    }
    client
        .controller_modify_volume(ControllerModifyVolumeRequest {
            volume_id,
            secrets,
            mutable_parameters,
        })
        .await
        .map_err(ModifyError::Driver)
}

/// `modifyController` state (controller.go:60-75) and the `modify` path.
pub struct ModifyController<M: Modifier, S: ModifyStore> {
    modifier: M,
    store: S,
    extra_modify_metadata: bool,
    /// PVCs whose last `ControllerModifyVolume` failed with a non-final error.
    uncertain: Mutex<HashSet<String>>,
    /// PVCs whose modification failed as infeasible: retried at a slower rate.
    slow_set: SlowSet,
}

fn pvc_key(pvc: &PersistentVolumeClaim) -> String {
    format!(
        "{}/{}",
        pvc.metadata.namespace.as_deref().unwrap_or_default(),
        pvc.metadata.name
    )
}

fn now_rfc3339() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// `clearModifyVolumeConditions` (modify_status.go:111-115).
pub fn clear_modify_volume_conditions(
    conditions: Vec<PersistentVolumeClaimCondition>,
) -> Vec<PersistentVolumeClaimCondition> {
    conditions
        .into_iter()
        .filter(|c| {
            c.r#type != CONDITION_MODIFY_VOLUME_ERROR && c.r#type != CONDITION_MODIFYING_VOLUME
        })
        .collect()
}

impl<M: Modifier, S: ModifyStore> ModifyController<M, S> {
    /// `NewModifyController` (controller.go:79-120). `max_retry_interval` is
    /// the slow-set retention.
    pub fn new(
        modifier: M,
        store: S,
        extra_modify_metadata: bool,
        max_retry_interval: Duration,
    ) -> Self {
        Self {
            modifier,
            store,
            extra_modify_metadata,
            uncertain: Mutex::new(HashSet::new()),
            slow_set: SlowSet::new(max_retry_interval),
        }
    }

    /// `initUncertainPVCs` (controller.go:130-148): every InProgress PVC is
    /// uncertain after a restart.
    pub fn init_uncertain_pvcs(&self, pvcs: &[PersistentVolumeClaim]) {
        let mut u = self.uncertain.lock().unwrap();
        for pvc in pvcs {
            let in_progress = pvc
                .status
                .as_ref()
                .and_then(|s| s.modify_volume_status.as_ref())
                .is_some_and(|m| m.status == MODIFY_IN_PROGRESS);
            if in_progress {
                u.insert(pvc_key(pvc));
            }
        }
    }

    pub fn is_uncertain(&self, key: &str) -> bool {
        self.uncertain.lock().unwrap().contains(key)
    }

    pub fn slow_set(&self) -> &SlowSet {
        &self.slow_set
    }

    /// `modify` (modify_volume.go:49-107). Returns the (possibly updated) PVC
    /// and PV, the error, and whether `ControllerModifyVolume` completed (the
    /// Go `bool` sentinel).
    pub async fn modify(
        &self,
        pvc: PersistentVolumeClaim,
        pv: PersistentVolume,
    ) -> (
        PersistentVolumeClaim,
        PersistentVolume,
        Option<ModifyError>,
        bool,
    ) {
        let key = pvc_key(&pvc);
        // Requeue PVC if modification recently failed with infeasible error.
        if let Some(e) = self.delay_modification_if_recently_infeasible(&pvc, &key) {
            return (pvc, pv, Some(e), false);
        }

        let spec_vac = pvc
            .spec
            .volume_attributes_class_name
            .clone()
            .unwrap_or_default();
        let status = pvc
            .status
            .as_ref()
            .and_then(|s| s.modify_volume_status.clone());
        let cur_vac = pvc
            .status
            .as_ref()
            .and_then(|s| s.current_volume_attributes_class_name.clone())
            .unwrap_or_default();

        if status.is_none() && spec_vac == cur_vac {
            // No modification required, already reached target state.
            return (pvc, pv, None, false);
        }

        // Last modification failed with non-infeasible error.
        let in_progress = status
            .as_ref()
            .is_some_and(|s| s.status == MODIFY_IN_PROGRESS);

        if spec_vac.is_empty() && !in_progress {
            // User doesn't care about the target state; stay in the current one.
            return match self.rolled_back(pvc.clone()).await {
                Ok(pvc) => (pvc, pv, None, false),
                Err(e) => (pvc, pv, Some(ModifyError::Other(e)), false),
            };
        }

        let in_uncertain_state = in_progress && self.is_uncertain(&key);
        // Check if we should change our target.
        if in_uncertain_state || spec_vac.is_empty() {
            // No. Continue our previous modification. (`status` is set here:
            // an empty spec VAC with no status returned above as rolled back.)
            let target = status
                .and_then(|s| s.target_volume_attributes_class_name)
                .unwrap_or_default();
            return match self.get_target_vac(&pvc, &target).await {
                Ok(vac) => {
                    self.controller_modify_volume_with_target(pvc, pv, vac)
                        .await
                }
                Err(e) => (pvc, pv, Some(e), false),
            };
        }

        self.validate_vac_and_modify_volume_with_target(pvc, pv)
            .await
    }

    /// `rolledBack` (modify_volume.go:109-122).
    async fn rolled_back(
        &self,
        pvc: PersistentVolumeClaim,
    ) -> std::result::Result<PersistentVolumeClaim, String> {
        let modifying = pvc
            .status
            .as_ref()
            .and_then(|s| s.conditions.as_ref())
            .is_some_and(|cs| cs.iter().any(|c| c.r#type == CONDITION_MODIFYING_VOLUME));
        if modifying {
            self.store
                .record_event(
                    &pvc,
                    "Normal",
                    EVENT_VOLUME_MODIFY_CANCELLED,
                    "Cancelled modify.".into(),
                )
                .await;
            return self.mark_rolled_back(&pvc).await;
        }
        // Don't try to revert Status.ModifyVolumeStatus here: only the result of
        // the last modification is recorded.
        Ok(pvc)
    }

    /// `getTargetVAC` (modify_volume.go:124-134).
    async fn get_target_vac(
        &self,
        pvc: &PersistentVolumeClaim,
        vac_name: &str,
    ) -> std::result::Result<VolumeAttributesClass, ModifyError> {
        match self.store.get_vac(vac_name).await {
            Ok(Some(vac)) => Ok(vac),
            Ok(None) => {
                self.store
                    .record_event(
                        pvc,
                        "Warning",
                        EVENT_VOLUME_MODIFY_FAILED,
                        format!("VAC {vac_name:?} does not exist."),
                    )
                    .await;
                Err(ModifyError::Other(format!(
                    "get VAC with vac name {vac_name} in VACInformer cache failed: volumeattributesclass.storage.k8s.io \"{vac_name}\" not found"
                )))
            }
            Err(e) => Err(ModifyError::Other(format!(
                "get VAC with vac name {vac_name} in VACInformer cache failed: {e}"
            ))),
        }
    }

    /// `validateVACAndModifyVolumeWithTarget` (modify_volume.go:136-163).
    async fn validate_vac_and_modify_volume_with_target(
        &self,
        pvc: PersistentVolumeClaim,
        pv: PersistentVolume,
    ) -> (
        PersistentVolumeClaim,
        PersistentVolume,
        Option<ModifyError>,
        bool,
    ) {
        let name = pvc
            .spec
            .volume_attributes_class_name
            .clone()
            .unwrap_or_default();
        let vac = match self.get_target_vac(&pvc, &name).await {
            Ok(v) => v,
            Err(_) => {
                // Mark pvc.Status.ModifyVolumeStatus as pending.
                return match self
                    .mark_controller_modify_volume_status(&pvc, MODIFY_PENDING, None)
                    .await
                {
                    Ok(p) => (p, pv, None, false),
                    Err(e) => (pvc, pv, Some(ModifyError::Other(e)), false),
                };
            }
        };
        // Mark pvc.Status.ModifyVolumeStatus as in progress.
        let pvc = match self
            .mark_controller_modify_volume_status(&pvc, MODIFY_IN_PROGRESS, None)
            .await
        {
            Ok(p) => p,
            Err(e) => return (pvc, pv, Some(ModifyError::Other(e)), false),
        };
        // Record an event to indicate that external resizer is modifying this volume.
        self.store
            .record_event(
                &pvc,
                "Normal",
                EVENT_VOLUME_MODIFY,
                format!(
                    "external resizer is modifying volume {} with vac {}",
                    pvc.metadata.name, vac.metadata.name
                ),
            )
            .await;
        self.controller_modify_volume_with_target(pvc, pv, vac)
            .await
    }

    /// `controllerModifyVolumeWithTarget` (modify_volume.go:165-210).
    async fn controller_modify_volume_with_target(
        &self,
        pvc: PersistentVolumeClaim,
        pv: PersistentVolume,
        vac: VolumeAttributesClass,
    ) -> (
        PersistentVolumeClaim,
        PersistentVolume,
        Option<ModifyError>,
        bool,
    ) {
        let (pvc, pv, result) = self.call_modify_volume_on_plugin(pvc, pv, &vac).await;
        let err = match result {
            Ok(()) => {
                self.store
                    .record_event(
                        &pvc,
                        "Normal",
                        EVENT_VOLUME_MODIFY_SUCCESS,
                        format!(
                            "external resizer modified volume {} with vac {} successfully",
                            pvc.metadata.name, vac.metadata.name
                        ),
                    )
                    .await;
                return (pvc, pv, None, true);
            }
            Err(e) => e,
        };
        let ModifyError::Driver(driver_err) = &err else {
            // `status.FromError` failed: not a gRPC error.
            return (
                pvc,
                pv,
                Some(ModifyError::Other(format!(
                    "cannot get error status from modify volume err: {err}"
                ))),
                false,
            );
        };
        let Some(code) = driver_err.status().map(|s| s.code()) else {
            // A local driver-client failure carries no gRPC status either.
            return (
                pvc,
                pv,
                Some(ModifyError::Other(format!(
                    "cannot get error status from modify volume err: {err}"
                ))),
                false,
            );
        };
        let mut err_msg = err.to_string();
        let mut target_status = MODIFY_IN_PROGRESS;
        let key = pvc_key(&pvc);
        if !is_final_error(driver_err) {
            // Update conditions and cache the PVC as uncertain.
            self.uncertain.lock().unwrap().insert(key.clone());
            err_msg.push_str(&format!(". Still modifying to VAC {}", vac.metadata.name));
        } else {
            // Only InvalidArgument can be set to Infeasible; other final errors
            // stay InProgress.
            if code == tonic::Code::InvalidArgument {
                target_status = MODIFY_INFEASIBLE;
            }
            self.uncertain.lock().unwrap().remove(&key);
        }
        let pvc = match self
            .mark_controller_modify_volume_status(&pvc, target_status, Some(driver_err))
            .await
        {
            Ok(p) => p,
            Err(e) => return (pvc, pv, Some(ModifyError::Other(e)), false),
        };
        self.mark_for_slow_retry(&pvc, &key);
        // Record an event to indicate that modify operation is failed.
        self.store
            .record_event(&pvc, "Warning", EVENT_VOLUME_MODIFY_FAILED, err_msg)
            .await;
        (pvc, pv, Some(err), false)
    }

    /// `callModifyVolumeOnPlugin` (modify_volume.go:212-244).
    async fn call_modify_volume_on_plugin(
        &self,
        pvc: PersistentVolumeClaim,
        pv: PersistentVolume,
        vac: &VolumeAttributesClass,
    ) -> (
        PersistentVolumeClaim,
        PersistentVolume,
        std::result::Result<(), ModifyError>,
    ) {
        let mut parameters = vac.parameters.clone().unwrap_or_default();
        if self.extra_modify_metadata {
            parameters.insert(PVC_NAME_KEY.into(), pvc.metadata.name.clone());
            parameters.insert(
                PVC_NAMESPACE_KEY.into(),
                pvc.metadata.namespace.clone().unwrap_or_default(),
            );
            parameters.insert(PV_NAME_KEY.into(), pv.metadata.name.clone());
        }
        if let Err(e) = self.modifier.modify(&pv, parameters).await {
            return (pvc, pv, Err(ModifyError::Driver(e)));
        }
        match self
            .mark_controller_modify_volume_completed(&pvc, &pv)
            .await
        {
            Ok((pvc, pv)) => (pvc, pv, Ok(())),
            Err(e) => {
                let msg = format!(
                    "modify volume failed to mark pvc {} modify volume completed: {e} ",
                    pvc.metadata.name
                );
                (pvc, pv, Err(ModifyError::Other(msg)))
            }
        }
    }

    /// `delayModificationIfRecentlyInfeasible` (modify_volume.go:246-266).
    fn delay_modification_if_recently_infeasible(
        &self,
        pvc: &PersistentVolumeClaim,
        key: &str,
    ) -> Option<ModifyError> {
        // Do not delay modification if the PVC was updated with a new VAC.
        let s = pvc
            .status
            .as_ref()
            .and_then(|s| s.modify_volume_status.as_ref());
        let spec_vac = pvc.spec.volume_attributes_class_name.as_deref();
        let Some(s) = s else {
            self.slow_set.remove(key);
            return None;
        };
        if spec_vac.is_none()
            || s.target_volume_attributes_class_name
                .as_deref()
                .unwrap_or_default()
                != spec_vac.unwrap_or_default()
        {
            // The new VAC may be feasible.
            self.slow_set.remove(key);
            return None;
        }
        let in_slow_set = self.slow_set.contains(key);
        self.mark_for_slow_retry(pvc, key);
        if in_slow_set {
            return Some(ModifyError::DelayRetry {
                msg: format!(
                    "skipping volume modification for pvc {key}, because modification previously failed with infeasible error"
                ),
                try_after: self.slow_set.time_remaining(key),
            });
        }
        None
    }

    /// `markForSlowRetry` (modify_volume.go:268-275): only an Infeasible PVC.
    fn mark_for_slow_retry(&self, pvc: &PersistentVolumeClaim, key: &str) {
        let infeasible = pvc
            .status
            .as_ref()
            .and_then(|s| s.modify_volume_status.as_ref())
            .is_some_and(|s| s.status == MODIFY_INFEASIBLE);
        if infeasible {
            self.slow_set.add(key);
        }
    }

    /// `markControllerModifyVolumeStatus` (modify_status.go:30-76).
    async fn mark_controller_modify_volume_status(
        &self,
        pvc: &PersistentVolumeClaim,
        modify_volume_status: &str,
        err: Option<&ControllerError>,
    ) -> std::result::Result<PersistentVolumeClaim, String> {
        let mut new_pvc = pvc.clone();
        let status = new_pvc.status.get_or_insert_with(Default::default);
        let mvs = status
            .modify_volume_status
            .get_or_insert_with(|| ModifyVolumeStatus {
                target_volume_attributes_class_name: None,
                status: String::new(),
            });
        mvs.status = modify_volume_status.to_string();

        // Do not change conditions for pending modifications.
        if modify_volume_status != MODIFY_PENDING {
            let now = now_rfc3339();
            let target_vac = mvs
                .target_volume_attributes_class_name
                .clone()
                .unwrap_or_default();
            let mut modifying = PersistentVolumeClaimCondition {
                r#type: CONDITION_MODIFYING_VOLUME.into(),
                status: "True".into(),
                last_probe_time: Some(now.clone()),
                last_transition_time: None,
                reason: None,
                message: None,
            };
            let mut conditions = Vec::new();
            match err {
                None => {
                    let target = pvc
                        .spec
                        .volume_attributes_class_name
                        .clone()
                        .unwrap_or_default();
                    mvs.target_volume_attributes_class_name = Some(target.clone());
                    modifying.message =
                        Some(format!("Modifying volume to {target:?} is in progress."));
                    conditions.push(modifying);
                }
                Some(e) => {
                    modifying.message = Some(if is_final_error(e) {
                        format!("Modifying volume to {target_vac:?} failed. Waiting for retry.")
                    } else {
                        format!("Modifying volume to {target_vac:?} is still in progress.")
                    });
                    conditions.push(modifying);
                    // `status.FromError(err)`: Unknown with the message for a
                    // non-gRPC error.
                    let (reason, message) = match e.status() {
                        Some(s) => (format!("{:?}", s.code()), s.message().to_string()),
                        None => ("Unknown".to_string(), e.to_string()),
                    };
                    conditions.push(PersistentVolumeClaimCondition {
                        r#type: CONDITION_MODIFY_VOLUME_ERROR.into(),
                        status: "True".into(),
                        last_probe_time: Some(now),
                        last_transition_time: None,
                        reason: Some(reason),
                        message: Some(message),
                    });
                }
            }
            let old = status.conditions.take().unwrap_or_default();
            status.conditions = Some(merge_pvc_conditions(&old, &conditions));
        }

        self.store
            .patch_claim(pvc, &new_pvc, true)
            .await
            .map_err(|e| {
                format!(
                    "mark PVC {:?} as modify volume failed, errored with: {e}",
                    pvc.metadata.name
                )
            })
    }

    /// `markControllerModifyVolumeCompleted` (modify_status.go:79-108): clear
    /// the status, set the current VAC and the PV's VAC. The PV is patched
    /// before the PVC so a PVC is never ahead of its PV.
    async fn mark_controller_modify_volume_completed(
        &self,
        pvc: &PersistentVolumeClaim,
        pv: &PersistentVolume,
    ) -> std::result::Result<(PersistentVolumeClaim, PersistentVolume), String> {
        let modified_vac = pvc
            .status
            .as_ref()
            .and_then(|s| s.modify_volume_status.as_ref())
            .and_then(|m| m.target_volume_attributes_class_name.clone())
            .unwrap_or_default();

        let mut new_pvc = pvc.clone();
        let status = new_pvc.status.get_or_insert_with(Default::default);
        status.modify_volume_status = None;
        status.current_volume_attributes_class_name = Some(modified_vac.clone());
        status.conditions = status.conditions.take().map(clear_modify_volume_conditions);

        let mut new_pv = pv.clone();
        new_pv.spec.volume_attributes_class_name = Some(modified_vac);

        let updated_pv = self.store.patch_pv(pv, &new_pv).await.map_err(|e| {
            format!(
                "update pv.Spec.VolumeAttributesClassName for PVC {:?} failed, errored with: {e}",
                pvc.metadata.name
            )
        })?;
        let updated_pvc = self
            .store
            .patch_claim(pvc, &new_pvc, false)
            .await
            .map_err(|e| {
                format!(
                    "mark PVC {:?} as ModifyVolumeCompleted failed, errored with: {e}",
                    pvc.metadata.name
                )
            })?;
        Ok((updated_pvc, updated_pv))
    }

    /// `markRolledBack` (modify_status.go:118-128): drop the Modifying condition.
    async fn mark_rolled_back(
        &self,
        pvc: &PersistentVolumeClaim,
    ) -> std::result::Result<PersistentVolumeClaim, String> {
        let mut new_pvc = pvc.clone();
        if let Some(s) = new_pvc.status.as_mut() {
            if let Some(cs) = s.conditions.as_mut() {
                cs.retain(|c| c.r#type != CONDITION_MODIFYING_VOLUME);
            }
        }
        self.store
            .patch_claim(pvc, &new_pvc, false)
            .await
            .map_err(|e| {
                format!(
                    "mark PVC {:?} as rolled back failed: {e}",
                    pvc.metadata.name
                )
            })
    }
}
