//! The garbage collector's workers: `attemptToDeleteItem`, `isDangling`,
//! `classifyReferences`, `processDeletingDependentsItem`, `orphanDependents`
//! and the two worker actions, over the dependency graph of `gc_graph`.
//!
//! Ported from Kubernetes release-1.35 `pkg/controller/garbagecollector`:
//! - `garbagecollector.go`: `attemptToDeleteWorker` (:322), `isDangling`
//!   (:383), `classifyReferences` (:464), `attemptToDeleteItem` (:503),
//!   `processDeletingDependentsItem` (:654), `orphanDependents` (:673),
//!   `attemptToOrphanWorker` (:739).
//! - `operations.go`: `deleteObject`, `getObject`, `removeFinalizer`,
//!   `resourceDefaultNamespace`.
//! - `patch.go`: `patch`, `deleteOwnerRefJSONMergePatch`,
//!   `unblockOwnerReferencesStrategicMergePatch`,
//!   `unblockOwnerReferencesJSONMergePatch`.
//! - `pkg/controller/controller_ref_manager.go`:
//!   `GenerateDeleteOwnerRefStrategicMergeBytes`.
//!
//! The API server and the REST mapper are behind [`GcApi`]. The queues are
//! the [`DirtyQueue`]s of the graph; the worker functions return the
//! [`WorkQueueItemAction`] the Go loop turns into `Forget` / `AddRateLimited`.
//! Nothing here is wired into [`super::garbage_collector::GarbageCollector`]
//! yet (cm-P1-10b); the legacy scan path stays until the conformance leg
//! passes with the graph path.
//!
//! Deliberate difference, Rust idiom only: workers take a node UID and read the
//! current node from the shared graph (upstream passes a `*node`, which the
//! graph mutates in place).

use super::gc_graph::{
    EventType, Graph, GraphChange, Node, ObjectReference, FINALIZER_DELETE_DEPENDENTS,
    FINALIZER_ORPHAN_DEPENDENTS,
};
use kubernetes_rs_common::types::{ObjectMeta, OwnerReference};
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::Duration;

/// A failed API call, by the status reasons the garbage collector branches on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    NotFound(String),
    Conflict(String),
    UnsupportedMediaType(String),
    Other(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::NotFound(m)
            | ApiError::Conflict(m)
            | ApiError::UnsupportedMediaType(m)
            | ApiError::Other(m) => f.write_str(m),
        }
    }
}

/// What the attempt functions return (`error` in Go).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcError {
    /// `enqueuedVirtualDeleteEventErr`.
    EnqueuedVirtualDeleteEvent,
    /// `namespacedOwnerOfClusterScopedObjectErr`.
    NamespacedOwnerOfClusterScopedObject,
    /// `restMappingError`.
    RestMapping {
        kind: String,
        version: String,
    },
    Api(ApiError),
    Other(String),
}

impl std::fmt::Display for GcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcError::EnqueuedVirtualDeleteEvent => f.write_str("enqueued virtual delete event"),
            GcError::NamespacedOwnerOfClusterScopedObject => {
                f.write_str("cluster-scoped objects cannot refer to namespaced owners")
            }
            // `restMappingError.Message` (errors.go:34).
            GcError::RestMapping { kind, version } => {
                let vk = format!("{version}/{kind}");
                write!(
                    f,
                    "unable to get REST mapping for {vk}.  If {vk} is an invalid resource, then you should manually remove ownerReferences that refer {vk} objects."
                )
            }
            GcError::Api(e) => e.fmt(f),
            GcError::Other(m) => f.write_str(m),
        }
    }
}

impl From<ApiError> for GcError {
    fn from(e: ApiError) -> Self {
        GcError::Api(e)
    }
}

/// `types.PatchType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchType {
    StrategicMerge,
    Merge,
}

/// `metav1.DeletionPropagation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Propagation {
    Orphan,
    Foreground,
    Background,
}

/// `metav1.Preconditions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preconditions {
    pub uid: String,
    pub resource_version: Option<String>,
}

/// The metadata client plus the REST mapper (`gc.metadataClient`, `gc.restMapper`).
#[async_trait::async_trait]
pub trait GcApi: Send + Sync {
    /// `gc.apiResource`: whether the kind is namespaced, or a REST mapping error.
    async fn is_namespaced(&self, api_version: &str, kind: &str) -> Result<bool, GcError>;
    /// A GET of the object (`namespace` already cleared for cluster-scoped kinds).
    async fn get(
        &self,
        api_version: &str,
        kind: &str,
        namespace: &str,
        name: &str,
    ) -> Result<ObjectMeta, ApiError>;
    async fn delete(
        &self,
        id: &ObjectReference,
        namespace: &str,
        preconditions: Preconditions,
        policy: Option<Propagation>,
    ) -> Result<(), ApiError>;
    async fn patch(
        &self,
        id: &ObjectReference,
        namespace: &str,
        patch: Value,
        patch_type: PatchType,
    ) -> Result<ObjectMeta, ApiError>;
}

/// `workQueueItemAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkQueueItemAction {
    Requeue,
    Forget,
}

/// `resourceDefaultNamespace` (operations.go:36-41).
fn resource_default_namespace(namespaced: bool, default_namespace: &str) -> String {
    if namespaced {
        default_namespace.to_string()
    } else {
        String::new()
    }
}

fn has_finalizer(meta: &ObjectMeta, f: &str) -> bool {
    meta.finalizers
        .as_ref()
        .is_some_and(|fs| fs.iter().any(|x| x == f))
}

/// `GenerateDeleteOwnerRefStrategicMergeBytes` (controller_ref_manager.go:572).
pub fn generate_delete_owner_ref_strategic_merge(
    dependent_uid: &str,
    owner_uids: &[String],
) -> Value {
    let refs: Vec<Value> = owner_uids
        .iter()
        .map(|u| json!({"$patch": "delete", "uid": u}))
        .collect();
    json!({"metadata": {
        "uid": dependent_uid,
        "ownerReferences": if refs.is_empty() { Value::Null } else { Value::Array(refs) },
    }})
}

/// `node.unblockOwnerReferencesStrategicMergePatch` (patch.go:114-127).
pub fn unblock_owner_references_strategic_merge_patch(n: &Node) -> Value {
    let blocking: Vec<Value> = n
        .owners
        .iter()
        .filter(|o| o.block_owner_deletion == Some(true))
        .map(|o| {
            let mut r = o.clone();
            r.block_owner_deletion = Some(false);
            serde_json::to_value(r).unwrap_or(Value::Null)
        })
        .collect();
    let mut meta = json!({"uid": n.identity.uid});
    if !blocking.is_empty() {
        meta["ownerReferences"] = Value::Array(blocking);
    }
    json!({"metadata": meta})
}

/// `deleteOwnerRefJSONMergePatch`'s body (patch.go:92-110) over the live object.
fn delete_owner_ref_json_merge_patch_for(live: &ObjectMeta, owner_uids: &[String]) -> Value {
    let kept: Vec<&OwnerReference> = live
        .owner_references
        .iter()
        .flatten()
        .filter(|r| !owner_uids.contains(&r.uid))
        .collect();
    json!({"metadata": {
        "resourceVersion": live.resource_version.clone().unwrap_or_default(),
        "ownerReferences": if kept.is_empty() { Value::Null } else { serde_json::to_value(kept).unwrap_or(Value::Null) },
    }})
}

/// `unblockOwnerReferencesJSONMergePatch` (patch.go:140-155).
fn unblock_owner_references_json_merge_patch_for(live: &ObjectMeta, n: &Node) -> Value {
    let owners: Vec<Value> = n
        .owners
        .iter()
        .map(|o| {
            let mut r = o.clone();
            r.block_owner_deletion = Some(false);
            serde_json::to_value(r).unwrap_or(Value::Null)
        })
        .collect();
    json!({"metadata": {
        "resourceVersion": live.resource_version.clone().unwrap_or_default(),
        "ownerReferences": if owners.is_empty() { Value::Null } else { Value::Array(owners) },
    }})
}

/// The worker state: the graph and the API.
pub struct GcWorkers<A: GcApi> {
    pub graph: Mutex<Graph>,
    /// Virtual delete events for the graph builder to process
    /// (`enqueueVirtualDeleteEvent`).
    pub graph_changes: Mutex<Vec<GraphChange>>,
    api: A,
}

/// `retry.DefaultBackoff`: 4 steps, 10ms, factor 5.
const RETRY_STEPS: u32 = 4;
const RETRY_BASE: Duration = Duration::from_millis(10);

impl<A: GcApi> GcWorkers<A> {
    pub fn new(graph: Graph, api: A) -> Self {
        Self {
            graph: Mutex::new(graph),
            graph_changes: Mutex::new(Vec::new()),
            api,
        }
    }

    pub fn api(&self) -> &A {
        &self.api
    }

    fn node_snapshot(&self, uid: &str) -> Option<Node> {
        self.graph.lock().unwrap().node(uid).cloned()
    }

    /// `getObject` (operations.go:84-96).
    async fn get_object(&self, item: &ObjectReference) -> Result<ObjectMeta, GcError> {
        let namespaced = self
            .api
            .is_namespaced(&item.api_version, &item.kind)
            .await?;
        let namespace = resource_default_namespace(namespaced, &item.namespace);
        if namespaced && namespace.is_empty() {
            // The only way this can happen is a cluster-scoped object that
            // referenced this type as an owner.
            return Err(GcError::NamespacedOwnerOfClusterScopedObject);
        }
        Ok(self
            .api
            .get(&item.api_version, &item.kind, &namespace, &item.name)
            .await?)
    }

    /// `deleteObject` (operations.go:51-82).
    async fn delete_object(
        &self,
        item: &ObjectReference,
        resource_version: &str,
        owners_at_resource_version: &[OwnerReference],
        policy: Option<Propagation>,
    ) -> Result<(), GcError> {
        let mut resource_version = resource_version.to_string();
        let mut owners = owners_at_resource_version.to_vec();
        loop {
            let namespaced = self
                .api
                .is_namespaced(&item.api_version, &item.kind)
                .await?;
            let namespace = resource_default_namespace(namespaced, &item.namespace);
            let preconditions = Preconditions {
                uid: item.uid.clone(),
                resource_version: (!resource_version.is_empty()).then(|| resource_version.clone()),
            };
            let err = match self
                .api
                .delete(item, &namespace, preconditions, policy)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => e,
            };
            if matches!(err, ApiError::Conflict(_)) && !resource_version.is_empty() {
                // Check if the ownerReferences changed.
                match self
                    .api
                    .get(&item.api_version, &item.kind, &namespace, &item.name)
                    .await
                {
                    // The object we wanted to delete is gone, success!
                    Err(ApiError::NotFound(_)) => return Ok(()),
                    Ok(live)
                        if live.uid == item.uid
                            && live.resource_version.as_deref().unwrap_or("")
                                != resource_version
                            && live.owner_references.clone().unwrap_or_default() == owners =>
                    {
                        // The object changed, causing a conflict, but ownerReferences
                        // did not: retry without the resourceVersion precondition so
                        // rapid unrelated updates do not starve the garbage collector.
                        resource_version.clear();
                        owners.clear();
                        continue;
                    }
                    _ => {}
                }
            }
            return Err(err.into());
        }
    }

    /// `patch` (patch.go:73-88): strategic merge first, JSON merge when the
    /// server does not support it.
    async fn patch_with_fallback(
        &self,
        item: &Node,
        smp: Value,
        jmp: impl FnOnce(&ObjectMeta) -> Value,
    ) -> Result<ObjectMeta, GcError> {
        let id = &item.identity;
        let namespaced = self.api.is_namespaced(&id.api_version, &id.kind).await?;
        let namespace = resource_default_namespace(namespaced, &id.namespace);
        match self
            .api
            .patch(id, &namespace, smp, PatchType::StrategicMerge)
            .await
        {
            Ok(m) => Ok(m),
            Err(ApiError::UnsupportedMediaType(_)) => {
                let live = self
                    .api
                    .get(&id.api_version, &id.kind, &namespace, &id.name)
                    .await?;
                Ok(self
                    .api
                    .patch(id, &namespace, jmp(&live), PatchType::Merge)
                    .await?)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// `removeFinalizer` (operations.go:107-148), `retry.RetryOnConflict`.
    async fn remove_finalizer(
        &self,
        owner: &ObjectReference,
        target_finalizer: &str,
    ) -> Result<(), GcError> {
        let mut delay = RETRY_BASE;
        let mut last = None;
        for step in 0..RETRY_STEPS {
            if step > 0 {
                tokio::time::sleep(delay).await;
                delay *= 5;
            }
            let object = match self.get_object(owner).await {
                Err(GcError::Api(ApiError::NotFound(_))) => return Ok(()),
                Err(e) => {
                    return Err(GcError::Other(format!(
                        "cannot finalize owner {owner}, because cannot get it: {e}. The garbage collector will retry later"
                    )))
                }
                Ok(o) => o,
            };
            let finalizers = object.finalizers.clone().unwrap_or_default();
            let new_finalizers: Vec<&String> = finalizers
                .iter()
                .filter(|f| *f != target_finalizer)
                .collect();
            if new_finalizers.len() == finalizers.len() {
                // Finalizer already removed from the object.
                return Ok(());
            }
            let namespaced = self
                .api
                .is_namespaced(&owner.api_version, &owner.kind)
                .await?;
            let namespace = resource_default_namespace(namespaced, &owner.namespace);
            let patch = json!({"metadata": {
                "resourceVersion": object.resource_version.clone().unwrap_or_default(),
                "finalizers": new_finalizers,
            }});
            match self
                .api
                .patch(owner, &namespace, patch, PatchType::Merge)
                .await
            {
                Ok(_) => return Ok(()),
                Err(ApiError::Conflict(m)) => last = Some(m),
                Err(e) => return Err(e.into()),
            }
        }
        let _ = last;
        Err(GcError::Other(format!(
            "updateMaxRetries({RETRY_STEPS}) has reached. The garbage collector will retry later for owner {owner}"
        )))
    }

    /// `isDangling` (garbagecollector.go:383-461): the owner is absent, or the
    /// live owner with its metadata.
    async fn is_dangling(
        &self,
        reference: &OwnerReference,
        item: &Node,
    ) -> Result<(bool, Option<ObjectMeta>), GcError> {
        // Check for a recorded absent cluster-scoped parent, then namespaced.
        let mut key = ObjectReference {
            api_version: reference.api_version.clone(),
            kind: reference.kind.clone(),
            name: reference.name.clone(),
            uid: reference.uid.clone(),
            namespace: String::new(),
        };
        {
            let g = self.graph.lock().unwrap();
            if g.absent_owner_cache.contains(&key) {
                return Ok((true, None));
            }
            key.namespace = item.identity.namespace.clone();
            if g.absent_owner_cache.contains(&key) {
                return Ok((true, None));
            }
        }
        let namespaced = self
            .api
            .is_namespaced(&reference.api_version, &reference.kind)
            .await?;
        if !namespaced {
            key.namespace = String::new();
        }
        if item.identity.namespace.is_empty() && namespaced {
            // A cluster-scoped item referring to a namespaced owner is not valid:
            // return a marker error rather than retrying the lookup forever.
            return Err(GcError::NamespacedOwnerOfClusterScopedObject);
        }
        let namespace = resource_default_namespace(namespaced, &item.identity.namespace);
        match self
            .api
            .get(
                &reference.api_version,
                &reference.kind,
                &namespace,
                &reference.name,
            )
            .await
        {
            Err(ApiError::NotFound(_)) => {
                self.graph.lock().unwrap().absent_owner_cache.insert(key);
                Ok((true, None))
            }
            Err(e) => Err(e.into()),
            Ok(owner) => {
                if owner.uid != reference.uid {
                    self.graph.lock().unwrap().absent_owner_cache.insert(key);
                    return Ok((true, None));
                }
                Ok((false, Some(owner)))
            }
        }
    }

    /// `classifyReferences` (garbagecollector.go:464-487): solid, dangling,
    /// waitingForDependentsDeletion.
    pub async fn classify_references(
        &self,
        item: &Node,
        latest: &[OwnerReference],
    ) -> Result<
        (
            Vec<OwnerReference>,
            Vec<OwnerReference>,
            Vec<OwnerReference>,
        ),
        GcError,
    > {
        let (mut solid, mut dangling, mut waiting) = (vec![], vec![], vec![]);
        for reference in latest {
            let (is_dangling, owner) = self.is_dangling(reference, item).await?;
            if is_dangling {
                dangling.push(reference.clone());
                continue;
            }
            let owner = owner.unwrap_or_default();
            if owner.deletion_timestamp.is_some()
                && has_finalizer(&owner, FINALIZER_DELETE_DEPENDENTS)
            {
                waiting.push(reference.clone());
            } else {
                solid.push(reference.clone());
            }
        }
        Ok((solid, dangling, waiting))
    }

    /// `attemptToDeleteItem` (garbagecollector.go:503-651).
    pub async fn attempt_to_delete_item(&self, item_uid: &str) -> Result<(), GcError> {
        let Some(item) = self.node_snapshot(item_uid) else {
            return Ok(());
        };
        // "being deleted" is a one-way trip to the final deletion: wait for it,
        // then process the object's dependents.
        if item.is_being_deleted() && !item.is_deleting_dependents() {
            return Ok(());
        }
        let latest = match self.get_object(&item.identity).await {
            Err(GcError::Api(ApiError::NotFound(_))) => {
                // The graph builder can add a "virtual" node for an owner that
                // doesn't exist yet: enqueue a virtual Delete event to remove it.
                self.enqueue_virtual_delete_event(&item.identity);
                return Err(GcError::EnqueuedVirtualDeleteEvent);
            }
            Err(e) => return Err(e),
            Ok(l) => l,
        };
        if latest.uid != item.identity.uid {
            self.enqueue_virtual_delete_event(&item.identity);
            return Err(GcError::EnqueuedVirtualDeleteEvent);
        }
        if item.is_deleting_dependents() {
            return self.process_deleting_dependents_item(&item).await;
        }

        // Compute if we should delete the item.
        let owner_references = latest.owner_references.clone().unwrap_or_default();
        if owner_references.is_empty() {
            return Ok(());
        }
        let (solid, dangling, waiting) = self.classify_references(&item, &owner_references).await?;

        if !solid.is_empty() {
            if dangling.is_empty() && waiting.is_empty() {
                return Ok(());
            }
            // waitingForDependentsDeletion must be removed from the
            // ownerReferences, otherwise the referenced objects would be stuck
            // with the foregroundDeletion finalizer and never get deleted.
            let owner_uids: Vec<String> = dangling
                .iter()
                .chain(waiting.iter())
                .map(|r| r.uid.clone())
                .collect();
            let p = generate_delete_owner_ref_strategic_merge(&item.identity.uid, &owner_uids);
            self.patch_with_fallback(&item, p, |live| {
                delete_owner_ref_json_merge_patch_for(live, &owner_uids)
            })
            .await?;
            return Ok(());
        }
        if !waiting.is_empty() && item.dependents_length() != 0 {
            let deps: Vec<Node> = {
                let g = self.graph.lock().unwrap();
                item.dependents()
                    .filter_map(|d| g.node(d).cloned())
                    .collect()
            };
            if deps.iter().any(|d| d.is_deleting_dependents()) {
                // Circle detection (with false positives upstream accepts): make
                // the item's ownerReferences non-blocking, then delete it with
                // Foreground.
                let patch = unblock_owner_references_strategic_merge_patch(&item);
                let owners_item = item.clone();
                self.patch_with_fallback(&item, patch, move |live| {
                    unblock_owner_references_json_merge_patch_for(live, &owners_item)
                })
                .await?;
            }
            // The deletion event will be observed by the graph builder, so the item
            // is processed again in processDeletingDependentsItem.
            return self
                .delete_object(
                    &item.identity,
                    latest.resource_version.as_deref().unwrap_or(""),
                    &owner_references,
                    Some(Propagation::Foreground),
                )
                .await;
        }
        // No solid owner, and no owner waiting for its dependents: collect it,
        // honouring an existing finalizer for the propagation policy.
        let policy = if has_finalizer(&latest, FINALIZER_ORPHAN_DEPENDENTS) {
            Propagation::Orphan
        } else if has_finalizer(&latest, FINALIZER_DELETE_DEPENDENTS) {
            Propagation::Foreground
        } else {
            Propagation::Background
        };
        self.delete_object(
            &item.identity,
            latest.resource_version.as_deref().unwrap_or(""),
            &owner_references,
            Some(policy),
        )
        .await
    }

    /// `enqueueVirtualDeleteEvent` (graph_builder.go:424).
    fn enqueue_virtual_delete_event(&self, r: &ObjectReference) {
        self.graph_changes
            .lock()
            .unwrap()
            .push(GraphChange::virtual_delete(r));
    }

    /// `processDeletingDependentsItem` (garbagecollector.go:654-671).
    async fn process_deleting_dependents_item(&self, item: &Node) -> Result<(), GcError> {
        let (none_blocking, to_add): (bool, Vec<String>) = {
            let g = self.graph.lock().unwrap();
            let blocking = g.blocking_dependents(&item.identity.uid);
            (
                blocking.is_empty(),
                blocking
                    .iter()
                    .filter(|d| !d.is_deleting_dependents())
                    .map(|d| d.identity.uid.clone())
                    .collect(),
            )
        };
        if none_blocking {
            return self
                .remove_finalizer(&item.identity, FINALIZER_DELETE_DEPENDENTS)
                .await;
        }
        let mut g = self.graph.lock().unwrap();
        for uid in to_add {
            g.attempt_to_delete.add(&uid);
        }
        Ok(())
    }

    /// `attemptToDeleteWorker` (garbagecollector.go:322-381).
    pub async fn attempt_to_delete_worker(&self, uid: &str) -> WorkQueueItemAction {
        let Some(n) = self.node_snapshot(uid) else {
            // No longer in the graph: it can happen if a requeued virtual node's
            // real object was observed deleted meanwhile.
            return WorkQueueItemAction::Forget;
        };
        match self.attempt_to_delete_item(uid).await {
            Err(GcError::EnqueuedVirtualDeleteEvent) => WorkQueueItemAction::Forget,
            // Will not resolve on retry.
            Err(GcError::NamespacedOwnerOfClusterScopedObject) => WorkQueueItemAction::Forget,
            // Retry if garbage collection of an object failed.
            Err(_) => WorkQueueItemAction::Requeue,
            // Requeue if the item hasn't been observed via an informer event yet,
            // otherwise a virtual node for an item added AND removed during watch
            // reestablishment can get stuck (kubernetes/kubernetes#56121).
            Ok(()) if !n.is_observed() => WorkQueueItemAction::Requeue,
            Ok(()) => WorkQueueItemAction::Forget,
        }
    }

    /// `orphanDependents` (garbagecollector.go:673-709).
    pub async fn orphan_dependents(
        &self,
        owner: &ObjectReference,
        dependents: &[Node],
    ) -> Result<(), GcError> {
        let futures = dependents.iter().map(|dependent| async move {
            // The dependent's UID is the precondition.
            let p = generate_delete_owner_ref_strategic_merge(
                &dependent.identity.uid,
                std::slice::from_ref(&owner.uid),
            );
            let uid = owner.uid.clone();
            let r = self
                .patch_with_fallback(dependent, p, move |live| {
                    delete_owner_ref_json_merge_patch_for(live, std::slice::from_ref(&uid))
                })
                .await;
            // If the target ownerReference doesn't exist in the dependent, the
            // strategic merge patch does not error.
            match r {
                Err(GcError::Api(ApiError::NotFound(_))) | Ok(_) => None,
                Err(e) => Some(format!("orphaning {} failed, {e}", dependent.identity)),
            }
        });
        let errors: Vec<String> = futures::future::join_all(futures)
            .await
            .into_iter()
            .flatten()
            .collect();
        if errors.is_empty() {
            return Ok(());
        }
        Err(GcError::Other(format!(
            "failed to orphan dependents of owner {owner}, got errors: {}",
            errors.join(", ")
        )))
    }

    /// `attemptToOrphanWorker` (garbagecollector.go:739-768).
    pub async fn attempt_to_orphan_worker(&self, uid: &str) -> WorkQueueItemAction {
        let (owner, dependents) = {
            let g = self.graph.lock().unwrap();
            let Some(owner) = g.node(uid).cloned() else {
                return WorkQueueItemAction::Forget;
            };
            let deps: Vec<Node> = owner
                .dependents()
                .filter_map(|d| g.node(d).cloned())
                .collect();
            (owner, deps)
        };
        if self
            .orphan_dependents(&owner.identity, &dependents)
            .await
            .is_err()
        {
            return WorkQueueItemAction::Requeue;
        }
        // Update the owner, removing the "orphan" finalizer.
        if self
            .remove_finalizer(&owner.identity, FINALIZER_ORPHAN_DEPENDENTS)
            .await
            .is_err()
        {
            return WorkQueueItemAction::Requeue;
        }
        WorkQueueItemAction::Forget
    }
}

/// `EventType` is re-exported for callers draining `graph_changes`.
pub type VirtualEventType = EventType;
