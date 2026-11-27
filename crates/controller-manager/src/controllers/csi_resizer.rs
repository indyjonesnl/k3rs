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
