//! Adopt/release of controllees: `ClaimObject` and the per-kind managers.
//!
//! Ported from `pkg/controller/controller_ref_manager.go`
//! (release-1.35): `BaseControllerRefManager.CanAdopt` (:45),
//! `ClaimObject` (:69), `PodControllerRefManager` (`ClaimPods` :183,
//! `AdoptPod` :222, `ReleasePod` :238), `ReplicaSetControllerRefManager`
//! (:288-363), `ControllerRevisionControllerRefManager` (:426-501),
//! `RecheckDeletionTimestamp` (:391), `ownerRefControllerPatch` (:536) and
//! `GenerateDeleteOwnerRefStrategicMergeBytes` (:572).
//!
//! Upstream has three near-identical managers that differ only in the typed
//! client they call. They are one generic [`ControllerRefManager`] here over a
//! [`PatchControl`] (`PodControlInterface.PatchPod`,
//! `RSControlInterface.PatchReplicaSet`,
//! `ControllerRevisionControlInterface.PatchControllerRevision`); the
//! pod-only `finalizers` are empty for the other kinds, as upstream passes none.

use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use kubernetes_rs_common::types::{ObjectMeta, OwnerReference, Selector};
use kubernetes_rs_common::{Error, Result};
use serde_json::{json, Value};
use tokio::sync::OnceCell;

/// The `Patch*` verb of upstream's `*ControlInterface`: a strategic-merge
/// patch of one namespaced object.
#[async_trait]
pub trait PatchControl: Send + Sync {
    async fn patch(&self, namespace: &str, name: &str, patch: &Value) -> Result<()>;
}

/// `canAdopt func(ctx) error`.
pub type CanAdoptFn =
    Box<dyn Fn() -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync>;

/// `GroupVersionKind` of the controller (`controllerKind`).
#[derive(Debug, Clone)]
pub struct ControllerKind {
    /// `GroupVersion().String()`, e.g. `apps/v1`.
    pub api_version: String,
    pub kind: String,
}

/// `metav1.GetControllerOfNoCopy`: the first owner reference with
/// `controller: true`.
pub fn get_controller_of(meta: &ObjectMeta) -> Option<&OwnerReference> {
    meta.owner_references
        .iter()
        .flatten()
        .find(|r| r.controller == Some(true))
}

fn is_not_found(e: &Error) -> bool {
    matches!(e, Error::NotFound(_))
}

fn is_invalid(e: &Error) -> bool {
    matches!(e, Error::Invalid(_) | Error::InvalidResource(_))
}

/// `utilerrors.NewAggregate`: `None` for no errors, the error itself for one,
/// `[a, b]` for several.
pub fn aggregate(mut errs: Vec<Error>) -> Option<Error> {
    match errs.len() {
        0 => None,
        1 => errs.pop(),
        _ => Some(Error::Internal(format!(
            "[{}]",
            errs.iter()
                .map(inner_message)
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

pub struct ControllerRefManager {
    /// `BaseControllerRefManager.Controller`.
    pub controller: ObjectMeta,
    /// `BaseControllerRefManager.Selector`.
    pub selector: Selector,
    controller_kind: ControllerKind,
    control: Arc<dyn PatchControl>,
    finalizers: Vec<String>,
    /// Kind of the controllees in the `can't adopt` message ("Pod",
    /// "ReplicaSet", "ControllerRevision").
    controllee_kind: &'static str,
    can_adopt_fn: Option<CanAdoptFn>,
    /// `canAdoptOnce` + `canAdoptErr`: the check runs at most once.
    can_adopt: OnceCell<std::result::Result<(), String>>,
}

impl ControllerRefManager {
    /// `NewPodControllerRefManager` (:131); pass no finalizers for the
    /// ReplicaSet / ControllerRevision flavours (:322, :460).
    pub fn new(
        control: Arc<dyn PatchControl>,
        controller: ObjectMeta,
        selector: Selector,
        controller_kind: ControllerKind,
        can_adopt: Option<CanAdoptFn>,
        finalizers: Vec<String>,
    ) -> Self {
        Self {
            controller,
            selector,
            controller_kind,
            control,
            finalizers,
            controllee_kind: "Pod",
            can_adopt_fn: can_adopt,
            can_adopt: OnceCell::new(),
        }
    }

    /// Names the controllee kind used in the `can't adopt` error.
    pub fn with_controllee_kind(mut self, kind: &'static str) -> Self {
        self.controllee_kind = kind;
        self
    }

    /// `CanAdopt` (:45): runs `CanAdoptFunc` once and remembers its error.
    pub async fn can_adopt(&self) -> Result<()> {
        let r = self
            .can_adopt
            .get_or_init(|| async {
                match &self.can_adopt_fn {
                    Some(f) => f().await.map_err(|e| inner_message(&e)),
                    None => Ok(()),
                }
            })
            .await;
        r.clone().map_err(Error::Internal)
    }

    /// `ClaimObject` (:69). `Ok(true)` when the object is now owned.
    pub async fn claim_object<M, A, AF, R, RF>(
        &self,
        obj: &ObjectMeta,
        match_fn: M,
        adopt: A,
        release: R,
    ) -> Result<bool>
    where
        M: Fn(&ObjectMeta) -> bool,
        A: FnOnce() -> AF,
        AF: Future<Output = Result<()>>,
        R: FnOnce() -> RF,
        RF: Future<Output = Result<()>>,
    {
        if let Some(controller_ref) = get_controller_of(obj) {
            if controller_ref.uid != self.controller.uid {
                // Owned by someone else. Ignore.
                return Ok(false);
            }
            if match_fn(obj) {
                // Already ours and the selector matches; claimed before the
                // deletion-timestamp check, it needs no action.
                return Ok(true);
            }
            // Owned by us but the selector doesn't match: release unless we
            // are being deleted.
            if self.controller.deletion_timestamp.is_some() {
                return Ok(false);
            }
            return match release().await {
                Ok(()) => Ok(false),
                Err(e) if is_not_found(&e) => Ok(false),
                Err(e) => Err(e),
            };
        }

        // An orphan.
        if self.controller.deletion_timestamp.is_some() || !match_fn(obj) {
            return Ok(false);
        }
        if obj.deletion_timestamp.is_some() {
            return Ok(false);
        }
        if self
            .controller
            .namespace
            .as_deref()
            .is_some_and(|ns| !ns.is_empty() && Some(ns) != obj.namespace.as_deref())
        {
            return Ok(false);
        }
        match adopt().await {
            Ok(()) => Ok(true),
            Err(e) if is_not_found(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `ClaimPods` / `ClaimReplicaSets` / `ClaimControllerRevisions`
    /// (:183, :349, :487): the objects now owned, plus the aggregate error.
    /// `filters` must all pass, and run only after the selector matched.
    pub async fn claim_objects<'a>(
        &self,
        objs: &'a [ObjectMeta],
        filters: &[&(dyn Fn(&ObjectMeta) -> bool + Sync)],
    ) -> (Vec<&'a ObjectMeta>, Option<Error>) {
        let mut claimed = Vec::new();
        let mut errs = Vec::new();
        let match_fn = |o: &ObjectMeta| {
            self.selector.matches(o.labels.as_ref()) && filters.iter().all(|f| f(o))
        };
        for obj in objs {
            match self
                .claim_object(
                    obj,
                    match_fn,
                    || self.adopt_object(obj),
                    || self.release_object(obj),
                )
                .await
            {
                Ok(true) => claimed.push(obj),
                Ok(false) => {}
                Err(e) => errs.push(e),
            }
        }
        (claimed, aggregate(errs))
    }

    /// `AdoptPod` (:222) / `AdoptReplicaSet` (:325) /
    /// `AdoptControllerRevision` (:463): patch to take control.
    pub async fn adopt_object(&self, obj: &ObjectMeta) -> Result<()> {
        self.can_adopt().await.map_err(|e| {
            Error::Internal(format!(
                "can't adopt {} {}/{} ({}): {}",
                self.controllee_kind,
                obj.namespace.as_deref().unwrap_or(""),
                obj.name,
                obj.uid,
                inner_message(&e)
            ))
        })?;
        // ValidateOwnerReferences() rejects this if another controller
        // reference exists.
        let patch = owner_ref_controller_patch(
            &self.controller,
            &self.controller_kind,
            &obj.uid,
            &self.finalizers,
        );
        self.control
            .patch(obj.namespace.as_deref().unwrap_or(""), &obj.name, &patch)
            .await
    }

    /// `ReleasePod` (:238) / `ReleaseReplicaSet` (:339) /
    /// `ReleaseControllerRevision` (:477): patch to free the object. 404 and
    /// 422 are ignored.
    pub async fn release_object(&self, obj: &ObjectMeta) -> Result<()> {
        let patch = generate_delete_owner_ref_strategic_merge_bytes(
            &obj.uid,
            &[self.controller.uid.as_str()],
            &self.finalizers,
        );
        match self
            .control
            .patch(obj.namespace.as_deref().unwrap_or(""), &obj.name, &patch)
            .await
        {
            // The object no longer exists.
            Err(e) if is_not_found(&e) => Ok(()),
            // Invalid: the object has no owner reference, or its uid differs
            // (deleted and recreated). Either way ignorable.
            Err(e) if is_invalid(&e) => Ok(()),
            other => other,
        }
    }
}

fn inner_message(e: &Error) -> String {
    match e {
        Error::Internal(m) => m.clone(),
        other => other.to_string(),
    }
}

/// `RecheckDeletionTimestamp` (:391): a `CanAdopt` function that re-reads the
/// controller and denies adoption once it has a deletion timestamp.
pub fn recheck_deletion_timestamp<F, Fut>(get_object: F) -> CanAdoptFn
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ObjectMeta>> + Send + 'static,
{
    Box::new(move || {
        let fut = get_object();
        Box::pin(async move {
            let obj = fut
                .await
                .map_err(|e| Error::Internal(format!("can't recheck DeletionTimestamp: {e}")))?;
            if let Some(ts) = obj.deletion_timestamp {
                return Err(Error::Internal(format!(
                    "{}/{} has just been deleted at {}",
                    obj.namespace.as_deref().unwrap_or(""),
                    obj.name,
                    ts
                )));
            }
            Ok(())
        })
    })
}

/// `ownerRefControllerPatch` (:536): the adopt patch. Carries
/// `metadata.uid` as the precondition and, for pods, the finalizers.
pub fn owner_ref_controller_patch(
    controller: &ObjectMeta,
    kind: &ControllerKind,
    uid: &str,
    finalizers: &[String],
) -> Value {
    let mut metadata = json!({
        "uid": uid,
        "ownerReferences": [{
            "apiVersion": kind.api_version,
            "kind": kind.kind,
            "name": controller.name,
            "uid": controller.uid,
            "controller": true,
            "blockOwnerDeletion": true,
        }],
    });
    if !finalizers.is_empty() {
        metadata["finalizers"] = json!(finalizers);
    }
    json!({ "metadata": metadata })
}

/// `GenerateDeleteOwnerRefStrategicMergeBytes` (:572): the release patch,
/// one `$patch: delete` entry per owner UID.
pub fn generate_delete_owner_ref_strategic_merge_bytes(
    dependent_uid: &str,
    owner_uids: &[&str],
    finalizers: &[String],
) -> Value {
    let owners: Vec<Value> = owner_uids
        .iter()
        .map(|u| json!({ "$patch": "delete", "uid": u }))
        .collect();
    let mut metadata = json!({ "uid": dependent_uid, "ownerReferences": owners });
    if !finalizers.is_empty() {
        metadata["$deleteFromPrimitiveList/finalizers"] = json!(finalizers);
    }
    json!({ "metadata": metadata })
}
