//! The garbage collector's dependency graph: `uidToNode` and
//! `processGraphChanges`.
//!
//! Ported from Kubernetes release-1.35 `pkg/controller/garbagecollector`:
//! - `graph.go`: `objectReference`, `node`, `blockingDependents`,
//!   `ownerReferenceCoordinates`, `ownerReferenceMatchesCoordinates`.
//! - `graph_builder.go`: `GraphBuilder.processGraphChanges`,
//!   `addDependentToOwners`, `insertNode`, `removeNode`,
//!   `removeDependentFromOwners`, `addUnblockedOwnersToDeleteQueue`,
//!   `processTransitions`, `referencesDiffs`, `partitionDependents`,
//!   `getAlternateOwnerIdentity`, `referenceLessThan`, `identityFromEvent`,
//!   `reportInvalidNamespaceOwnerRef`.
//!
//! Pure data structure, no controller integration: the monitors feed
//! [`GraphChange`]s in, the garbage collector drains `attempt_to_delete` /
//! `attempt_to_orphan` (the workqueues of upstream).
//!
//! Deliberate deviations from upstream, all Rust-idiom, none behavioural:
//! - Upstream's `node.dependents` is a set of `*node`, so replacing a node by a
//!   clone (virtual to observed) leaves stale pointers in other nodes'
//!   dependents sets. Here dependents are keyed by UID, which always resolves
//!   to the current node. The graph is single-writer (`&mut self`), so the
//!   per-field locks of `node` are not needed.
//! - The event recorder is a list of [`InvalidNamespaceOwnerRefEvent`]s to
//!   drain, and the workqueues are [`DirtyQueue`]s (insertion order, deduped,
//!   like a workqueue's dirty set).

use kubernetes_rs_common::types::{ObjectMeta, OwnerReference};
use std::collections::{BTreeSet, HashMap, HashSet};

/// `metav1.FinalizerDeleteDependents`.
pub const FINALIZER_DELETE_DEPENDENTS: &str = "foregroundDeletion";
/// `metav1.FinalizerOrphanDependents`.
pub const FINALIZER_ORPHAN_DEPENDENTS: &str = "orphan";

/// `objectReference` (graph.go:34-37): an owner reference plus the namespace
/// the dynamic client needs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ObjectReference {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    pub namespace: String,
}

impl std::fmt::Display for ObjectReference {
    /// `objectReference.String` (graph.go:40-42).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}/{}, namespace: {}, name: {}, uid: {}]",
            self.api_version, self.kind, self.namespace, self.name, self.uid
        )
    }
}

impl ObjectReference {
    fn coordinates(owner: &OwnerReference, namespace: &str) -> Self {
        Self {
            api_version: owner.api_version.clone(),
            kind: owner.kind.clone(),
            name: owner.name.clone(),
            uid: owner.uid.clone(),
            namespace: namespace.to_string(),
        }
    }
}

/// `ownerReferenceMatchesCoordinates` (graph.go:204-206).
pub fn owner_reference_matches_coordinates(a: &OwnerReference, b: &ObjectReference) -> bool {
    a.uid == b.uid && a.name == b.name && a.kind == b.kind && a.api_version == b.api_version
}

/// `referenceLessThan` (graph_builder.go:850-872).
fn reference_less_than(a: &ObjectReference, b: &ObjectReference) -> bool {
    (&a.kind, &a.api_version, &a.namespace, &a.name, &a.uid)
        < (&b.kind, &b.api_version, &b.namespace, &b.name, &b.uid)
}

/// `node` (graph.go:60-82).
#[derive(Debug, Clone)]
pub struct Node {
    pub identity: ObjectReference,
    /// UIDs of the nodes that have `identity` as a `metadata.ownerReference`.
    dependents: BTreeSet<String>,
    /// Set when the object has a deletionTimestamp and the
    /// `foregroundDeletion` finalizer.
    deleting_dependents: bool,
    being_deleted: bool,
    /// Constructed virtually and never observed through an informer event.
    virtual_node: bool,
    /// The owners recorded in the graph, compared with the owners of an update.
    pub owners: Vec<OwnerReference>,
}

impl Node {
    pub fn is_being_deleted(&self) -> bool {
        self.being_deleted
    }
    pub fn is_observed(&self) -> bool {
        !self.virtual_node
    }
    pub fn is_deleting_dependents(&self) -> bool {
        self.deleting_dependents
    }
    pub fn dependents(&self) -> impl Iterator<Item = &str> {
        self.dependents.iter().map(String::as_str)
    }
    pub fn dependents_length(&self) -> usize {
        self.dependents.len()
    }
}

/// A workqueue's dirty set: insertion ordered, deduplicated.
#[derive(Debug, Default)]
pub struct DirtyQueue {
    order: Vec<String>,
    set: HashSet<String>,
    /// UIDs that were added through `AddRateLimited`.
    rate_limited: HashSet<String>,
}

impl DirtyQueue {
    pub fn add(&mut self, uid: &str) {
        if self.set.insert(uid.to_string()) {
            self.order.push(uid.to_string());
        }
    }
    pub fn add_rate_limited(&mut self, uid: &str) {
        self.rate_limited.insert(uid.to_string());
        self.add(uid);
    }
    pub fn contains(&self, uid: &str) -> bool {
        self.set.contains(uid)
    }
    pub fn was_rate_limited(&self, uid: &str) -> bool {
        self.rate_limited.contains(uid)
    }
    pub fn len(&self) -> usize {
        self.order.len()
    }
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
    /// Take everything queued so far, in insertion order.
    pub fn drain(&mut self) -> Vec<String> {
        self.set.clear();
        self.rate_limited.clear();
        std::mem::take(&mut self.order)
    }
}

/// `eventType` (graph_builder.go:62-66).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Add,
    Update,
    Delete,
}

/// `event` (graph_builder.go:68-76), with the object reduced to the metadata
/// the graph reads (the garbage collector only watches metadata).
#[derive(Debug, Clone)]
pub struct GraphChange {
    /// Not from an informer but constructed artificially.
    pub virtual_event: bool,
    pub event_type: EventType,
    pub api_version: String,
    pub kind: String,
    pub meta: ObjectMeta,
    /// The previous object of an update, when known.
    pub old_meta: Option<ObjectMeta>,
}

impl GraphChange {
    /// `enqueueVirtualDeleteEvent` (graph_builder.go:424-437).
    pub fn virtual_delete(r: &ObjectReference) -> Self {
        Self {
            virtual_event: true,
            event_type: EventType::Delete,
            api_version: r.api_version.clone(),
            kind: r.kind.clone(),
            meta: ObjectMeta {
                name: r.name.clone(),
                namespace: (!r.namespace.is_empty()).then(|| r.namespace.clone()),
                uid: r.uid.clone(),
                ..Default::default()
            },
            old_meta: None,
        }
    }

    /// `identityFromEvent` (graph_builder.go:700-711).
    fn identity(&self) -> ObjectReference {
        ObjectReference {
            api_version: self.api_version.clone(),
            kind: self.kind.clone(),
            name: self.meta.name.clone(),
            uid: self.meta.uid.clone(),
            namespace: self.meta.namespace.clone().unwrap_or_default(),
        }
    }
}

/// The Warning event `reportInvalidNamespaceOwnerRef` records
/// (graph_builder.go:504-536), reason `OwnerRefInvalidNamespace`.
#[derive(Debug, Clone, PartialEq)]
pub struct InvalidNamespaceOwnerRefEvent {
    /// The dependent the event is recorded against.
    pub involved: ObjectReference,
    pub message: String,
}

/// `ownerRefPair` (graph_builder.go:562-565).
#[derive(Debug, Clone, PartialEq)]
pub struct OwnerRefPair {
    pub old_ref: OwnerReference,
    pub new_ref: OwnerReference,
}

/// `referencesDiffs` (graph_builder.go:567-590). `removed` follows the order
/// of `old`.
pub fn references_diffs(
    old: &[OwnerReference],
    new: &[OwnerReference],
) -> (Vec<OwnerReference>, Vec<OwnerReference>, Vec<OwnerRefPair>) {
    let old_by_uid: HashMap<&str, &OwnerReference> =
        old.iter().map(|r| (r.uid.as_str(), r)).collect();
    let mut remaining: HashSet<&str> = old_by_uid.keys().copied().collect();
    let (mut added, mut changed) = (Vec::new(), Vec::new());
    for value in new {
        if remaining.remove(value.uid.as_str()) {
            let old_ref = old_by_uid[value.uid.as_str()];
            if old_ref != value {
                changed.push(OwnerRefPair {
                    old_ref: old_ref.clone(),
                    new_ref: value.clone(),
                });
            }
        } else {
            added.push(value.clone());
        }
    }
    let removed = old
        .iter()
        .filter(|r| remaining.contains(r.uid.as_str()))
        .cloned()
        .collect();
    (added, removed, changed)
}

fn being_deleted(meta: &ObjectMeta) -> bool {
    meta.deletion_timestamp.is_some()
}

fn has_finalizer(meta: &ObjectMeta, finalizer: &str) -> bool {
    meta.finalizers
        .as_deref()
        .is_some_and(|f| f.iter().any(|x| x == finalizer))
}

/// `deletionStartsWithFinalizer` (graph_builder.go:592-613).
fn deletion_starts_with_finalizer(
    old: Option<&ObjectMeta>,
    new: &ObjectMeta,
    finalizer: &str,
) -> bool {
    if !being_deleted(new) || !has_finalizer(new, finalizer) {
        return false;
    }
    match old {
        None => true,
        Some(old) => !being_deleted(old) || !has_finalizer(old, finalizer),
    }
}

fn blocks_owner_deletion(r: &OwnerReference) -> bool {
    r.block_owner_deletion == Some(true)
}

/// The graph (`GraphBuilder.uidToNode`) and the queues `processGraphChanges`
/// feeds.
#[derive(Debug, Default)]
pub struct Graph {
    uid_to_node: HashMap<String, Node>,
    pub attempt_to_delete: DirtyQueue,
    pub attempt_to_orphan: DirtyQueue,
    /// `absentOwnerCache`: owners confirmed absent.
    pub absent_owner_cache: HashSet<ObjectReference>,
    events: Vec<InvalidNamespaceOwnerRefEvent>,
}

impl Graph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node(&self, uid: &str) -> Option<&Node> {
        self.uid_to_node.get(uid)
    }

    pub fn len(&self) -> usize {
        self.uid_to_node.len()
    }

    pub fn is_empty(&self) -> bool {
        self.uid_to_node.is_empty()
    }

    /// Take the recorded `OwnerRefInvalidNamespace` events.
    pub fn take_events(&mut self) -> Vec<InvalidNamespaceOwnerRefEvent> {
        std::mem::take(&mut self.events)
    }

    /// `blockingDependents` (graph.go:176-190): the dependents with an
    /// ownerReference to `uid` whose `blockOwnerDeletion` is true.
    pub fn blocking_dependents(&self, uid: &str) -> Vec<&Node> {
        let Some(n) = self.uid_to_node.get(uid) else {
            return vec![];
        };
        n.dependents
            .iter()
            .filter_map(|d| self.uid_to_node.get(d))
            .filter(|dep| {
                dep.owners
                    .iter()
                    .any(|o| o.uid == uid && blocks_owner_deletion(o))
            })
            .collect()
    }

    /// `addDependentToOwners` (graph_builder.go:441-502).
    fn add_dependent_to_owners(&mut self, uid: &str, owners: &[OwnerReference]) {
        let namespace = self.uid_to_node[uid].identity.namespace.clone();
        let mut has_potentially_invalid_owner_reference = false;
        for owner in owners {
            let existed = self.uid_to_node.contains_key(&owner.uid);
            if !existed {
                // A "virtual" node stands in for the owner until the API
                // server confirms it.
                self.uid_to_node.insert(
                    owner.uid.clone(),
                    Node {
                        identity: ObjectReference::coordinates(owner, &namespace),
                        dependents: BTreeSet::new(),
                        deleting_dependents: false,
                        being_deleted: false,
                        virtual_node: true,
                        owners: vec![],
                    },
                );
            }
            let owner_node = self.uid_to_node.get_mut(&owner.uid).expect("just ensured");
            owner_node.dependents.insert(uid.to_string());
            if !existed {
                self.attempt_to_delete.add(&owner.uid);
            } else if !has_potentially_invalid_owner_reference {
                let owner_is_namespaced = !owner_node.identity.namespace.is_empty();
                let owner_identity = owner_node.identity.clone();
                let observed = owner_node.is_observed();
                if owner_is_namespaced && owner_identity.namespace != namespace {
                    if observed {
                        // Definitely wrong: a cluster-scoped owner may be
                        // referenced from any namespace, a namespaced one not.
                        self.report_invalid_namespace_owner_ref(uid, &owner.uid);
                    }
                    has_potentially_invalid_owner_reference = true;
                } else if !owner_reference_matches_coordinates(owner, &owner_identity) {
                    has_potentially_invalid_owner_reference = true;
                } else if !owner_is_namespaced && owner_identity.namespace != namespace && !observed
                {
                    // Cluster-scoped virtual owner that does not match the
                    // child's namespace: could be a missing namespaced owner
                    // referenced by a cluster-scoped child (issue #98040).
                    has_potentially_invalid_owner_reference = true;
                }
            }
        }
        if has_potentially_invalid_owner_reference {
            self.attempt_to_delete.add(uid);
        }
    }

    /// `reportInvalidNamespaceOwnerRef` (graph_builder.go:504-536).
    fn report_invalid_namespace_owner_ref(&mut self, uid: &str, invalid_owner_uid: &str) {
        let Some(n) = self.uid_to_node.get(uid) else {
            return;
        };
        let Some(r) = n.owners.iter().find(|o| o.uid == invalid_owner_uid) else {
            return;
        };
        let invalid = ObjectReference::coordinates(r, &n.identity.namespace);
        self.events.push(InvalidNamespaceOwnerRefEvent {
            involved: n.identity.clone(),
            message: format!(
                "ownerRef {invalid} does not exist in namespace \"{}\"",
                n.identity.namespace
            ),
        });
    }

    /// `insertNode` (graph_builder.go:538-542).
    fn insert_node(&mut self, n: Node) {
        let uid = n.identity.uid.clone();
        let owners = n.owners.clone();
        self.uid_to_node.insert(uid.clone(), n);
        self.add_dependent_to_owners(&uid, &owners);
    }

    /// `removeDependentFromOwners` (graph_builder.go:544-554).
    fn remove_dependent_from_owners(&mut self, uid: &str, owners: &[OwnerReference]) {
        for owner in owners {
            if let Some(o) = self.uid_to_node.get_mut(&owner.uid) {
                o.dependents.remove(uid);
            }
        }
    }

    /// `removeNode` (graph_builder.go:556-560).
    fn remove_node(&mut self, uid: &str) -> Option<Node> {
        let n = self.uid_to_node.remove(uid)?;
        self.remove_dependent_from_owners(uid, &n.owners);
        Some(n)
    }

    /// `addUnblockedOwnersToDeleteQueue` (graph_builder.go:646-669).
    fn add_unblocked_owners_to_delete_queue(
        &mut self,
        removed: &[OwnerReference],
        changed: &[OwnerRefPair],
    ) {
        for r in removed {
            if blocks_owner_deletion(r) && self.uid_to_node.contains_key(&r.uid) {
                self.attempt_to_delete.add(&r.uid);
            }
        }
        for c in changed {
            let was_blocked = blocks_owner_deletion(&c.old_ref);
            let is_unblocked = !blocks_owner_deletion(&c.new_ref);
            if was_blocked && is_unblocked && self.uid_to_node.contains_key(&c.new_ref.uid) {
                self.attempt_to_delete.add(&c.new_ref.uid);
            }
        }
    }

    /// `processTransitions` (graph_builder.go:671-686).
    fn process_transitions(&mut self, old: Option<&ObjectMeta>, new: &ObjectMeta, uid: &str) {
        if deletion_starts_with_finalizer(old, new, FINALIZER_ORPHAN_DEPENDENTS) {
            self.attempt_to_orphan.add(uid);
            return;
        }
        if deletion_starts_with_finalizer(old, new, FINALIZER_DELETE_DEPENDENTS) {
            // A virtual node never had deletingDependents set, so set it here.
            let deps: Vec<String> = {
                let n = self.uid_to_node.get_mut(uid).expect("node exists");
                n.deleting_dependents = true;
                n.dependents.iter().cloned().collect()
            };
            for dep in deps {
                self.attempt_to_delete.add(&dep);
            }
            self.attempt_to_delete.add(uid);
        }
    }

    /// `partitionDependents` (graph_builder.go:812-848): the dependents with
    /// an ownerReference matching `owner` on all coordinates, and those with a
    /// reference to the same UID that does not. A dependent with several
    /// references to the UID can end up in both.
    fn partition_dependents(
        &self,
        dependents: &[String],
        owner: &ObjectReference,
    ) -> (Vec<String>, Vec<String>) {
        let owner_is_namespaced = !owner.namespace.is_empty();
        let (mut matching, mut nonmatching) = (vec![], vec![]);
        for d in dependents {
            let Some(dep) = self.uid_to_node.get(d) else {
                continue;
            };
            let (mut found_match, mut found_mismatch) = (false, false);
            if owner_is_namespaced && owner.namespace != dep.identity.namespace {
                found_mismatch = true;
            } else {
                for r in dep.owners.iter().filter(|r| r.uid == owner.uid) {
                    if owner_reference_matches_coordinates(r, owner) {
                        found_match = true;
                    } else {
                        found_mismatch = true;
                    }
                }
            }
            if found_match {
                matching.push(d.clone());
            }
            if found_mismatch {
                nonmatching.push(d.clone());
            }
        }
        (matching, nonmatching)
    }

    /// `getAlternateOwnerIdentity` (graph_builder.go:874-940).
    fn get_alternate_owner_identity(
        &self,
        deps: &[String],
        verified_absent: &ObjectReference,
    ) -> Option<ObjectReference> {
        let absent_is_cluster_scoped = verified_absent.namespace.is_empty();
        let mut seen: HashSet<ObjectReference> = HashSet::from([verified_absent.clone()]);
        let mut first: Option<ObjectReference> = None;
        let mut first_following: Option<ObjectReference> = None;
        for dep in deps.iter().filter_map(|d| self.uid_to_node.get(d)) {
            for owner_ref in dep.owners.iter().filter(|r| r.uid == verified_absent.uid) {
                if owner_reference_matches_coordinates(owner_ref, verified_absent)
                    && (absent_is_cluster_scoped
                        || verified_absent.namespace == dep.identity.namespace)
                {
                    continue;
                }
                let mut r = ObjectReference::coordinates(owner_ref, &dep.identity.namespace);
                if absent_is_cluster_scoped
                    && r.api_version == verified_absent.api_version
                    && r.kind == verified_absent.kind
                {
                    // Known cluster-scoped from verified_absent.
                    r.namespace.clear();
                }
                if !seen.insert(r.clone()) {
                    continue;
                }
                if first.as_ref().is_none_or(|f| reference_less_than(&r, f)) {
                    first = Some(r.clone());
                }
                if reference_less_than(verified_absent, &r)
                    && first_following
                        .as_ref()
                        .is_none_or(|f| reference_less_than(&r, f))
                {
                    first_following = Some(r);
                }
            }
        }
        first_following.or(first)
    }

    fn dependents_vec(&self, uid: &str) -> Vec<String> {
        self.uid_to_node
            .get(uid)
            .map(|n| n.dependents.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// `processGraphChanges` (graph_builder.go:706-1010), one event.
    pub fn process_graph_change(&mut self, event: &GraphChange) {
        let uid = event.meta.uid.clone();
        let found = self.uid_to_node.contains_key(&uid);

        // Mark a virtual node as observed through an informer event.
        if found && !event.virtual_event && !self.uid_to_node[&uid].is_observed() {
            let observed = event.identity();
            if observed != self.uid_to_node[&uid].identity {
                // Dependents that don't match the observed identity are
                // enqueued; if their owners are still solid the attempt is a
                // no-op. (good parent -> bad child is addDependentToOwners.)
                let deps = self.dependents_vec(&uid);
                let (_, potentially_invalid) = self.partition_dependents(&deps, &observed);
                for dep in potentially_invalid {
                    let dep_ns = self.uid_to_node[&dep].identity.namespace.clone();
                    if !observed.namespace.is_empty() && dep_ns != observed.namespace {
                        self.report_invalid_namespace_owner_ref(&dep, &observed.uid);
                    }
                    self.attempt_to_delete.add(&dep);
                }
                self.uid_to_node.get_mut(&uid).expect("found").identity = observed;
            }
            self.uid_to_node.get_mut(&uid).expect("found").virtual_node = false;
        }

        match event.event_type {
            EventType::Add | EventType::Update if !found => {
                let n = Node {
                    identity: event.identity(),
                    dependents: BTreeSet::new(),
                    deleting_dependents: being_deleted(&event.meta)
                        && has_finalizer(&event.meta, FINALIZER_DELETE_DEPENDENTS),
                    being_deleted: being_deleted(&event.meta),
                    virtual_node: false,
                    owners: event.meta.owner_references.clone().unwrap_or_default(),
                };
                self.insert_node(n);
                // The delta fifo may combine a creation and a deletion into
                // one event, so process the transitions too.
                self.process_transitions(event.old_meta.as_ref(), &event.meta, &uid);
            }
            EventType::Add | EventType::Update => {
                let new_owners = event.meta.owner_references.clone().unwrap_or_default();
                let (added, removed, changed) =
                    references_diffs(&self.uid_to_node[&uid].owners, &new_owners);
                if !added.is_empty() || !removed.is_empty() || !changed.is_empty() {
                    // The changed graph may unblock owners waiting for the
                    // deletion of their dependents.
                    self.add_unblocked_owners_to_delete_queue(&removed, &changed);
                    self.uid_to_node.get_mut(&uid).expect("found").owners = new_owners;
                    self.add_dependent_to_owners(&uid, &added);
                    self.remove_dependent_from_owners(&uid, &removed);
                }
                if being_deleted(&event.meta) {
                    self.uid_to_node.get_mut(&uid).expect("found").being_deleted = true;
                }
                self.process_transitions(event.old_meta.as_ref(), &event.meta, &uid);
            }
            EventType::Delete => {
                if !found {
                    // "item doesn't exist in the graph, this shouldn't happen"
                    return;
                }
                self.process_delete(event, &uid);
            }
        }
    }

    fn process_delete(&mut self, event: &GraphChange, uid: &str) {
        let mut remove_existing_node = true;
        if event.virtual_event {
            // A virtual delete event, not one observed from an informer.
            let deleted = event.identity();
            let existing = self.uid_to_node[uid].clone();
            let deps = self.dependents_vec(uid);
            if existing.virtual_node {
                // Our node is also virtual and its coordinates are uncertain:
                // see whether dependents reference it with other coordinates.
                let (matching, nonmatching) = self.partition_dependents(&deps, &deleted);
                if !nonmatching.is_empty() {
                    // Some dependents disagree on our coordinates: keep the node.
                    remove_existing_node = false;
                    if !matching.is_empty() {
                        self.absent_owner_cache.insert(deleted.clone());
                        for dep in &matching {
                            self.attempt_to_delete.add(dep);
                        }
                    }
                    if existing.identity == deleted {
                        // Replace the identity by one the other dependents use.
                        if let Some(replacement) =
                            self.get_alternate_owner_identity(&nonmatching, &deleted)
                        {
                            self.uid_to_node.get_mut(uid).expect("found").identity = replacement;
                            self.attempt_to_delete.add_rate_limited(uid);
                        }
                    }
                }
            } else if existing.identity != deleted {
                // Do not remove a real node because of a virtual delete event.
                remove_existing_node = false;
                let (matching, _) = self.partition_dependents(&deps, &deleted);
                if !matching.is_empty() {
                    self.absent_owner_cache.insert(deleted);
                    for dep in &matching {
                        self.attempt_to_delete.add(dep);
                    }
                }
            }
        }

        if remove_existing_node {
            let Some(existing) = self.remove_node(uid) else {
                return;
            };
            if !existing.dependents.is_empty() {
                self.absent_owner_cache.insert(event.identity());
            }
            for dep in &existing.dependents {
                self.attempt_to_delete.add(dep);
            }
            for owner in &existing.owners {
                // Let attemptToDeleteItem check whether all the owner's
                // dependents are gone, so the owner can be deleted.
                if self
                    .uid_to_node
                    .get(&owner.uid)
                    .is_some_and(Node::is_deleting_dependents)
                {
                    self.attempt_to_delete.add(&owner.uid);
                }
            }
        }
    }
}
