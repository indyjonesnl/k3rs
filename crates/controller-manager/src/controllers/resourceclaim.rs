//! ResourceClaim controller.
//!
//! Ported from `pkg/controller/resourceclaim/controller.go`, `uid_cache.go` and
//! `metrics/metrics.go` (release-1.35), launched like `newResourceClaimController`
//! (`cmd/kube-controller-manager/app/core.go:463-499`: name `resourceclaim-controller`,
//! `requiredFeatureGates: DynamicResourceAllocation`, 50 workers, the `DRAAdminAccess`
//! and `DRAPrioritizedList` gates handed over as `resourceclaim.Features`).
//!
//! What it does (and what it does NOT do: it never allocates devices, the scheduler's
//! `DynamicResources` plugin does that):
//! - creates a `ResourceClaim` for each `pod.spec.resourceClaims[]` entry that names a
//!   `ResourceClaimTemplate`, owned by the pod and annotated with
//!   `resource.kubernetes.io/pod-claim-name`, then records the generated names in
//!   `pod.status.resourceClaimStatuses` (a server-side apply status patch);
//! - reserves an allocated claim for a scheduled pod (`status.reservedFor`);
//! - removes `reservedFor` entries of pods that are gone, replaced or done, clears the
//!   allocation when the last consumer is gone and drops the `delete-protection`
//!   finalizer once nothing needs it;
//! - deletes generated claims of pods that will not run.
//!
//! Ported 1:1: the two key kinds (`claim:ns/name`, `pod:ns/name`), `enqueuePod` /
//! `podNeedsClaims` / `podNeedsWork`, `enqueueResourceClaim`, `syncHandler`,
//! `syncPod`, `handleClaim` (incl. the orphan search through the claim owner index,
//! the generate-name truncation, the admin-access and prioritized-list gates),
//! `findPodResourceClaim`, `reserveForPod`, `syncClaim`, `owningPod`, `isPodDone`,
//! both index functions, the LRU of deleted pod UIDs (500 entries) and the metrics
//! (`resourceclaim_controller_creates_total`, `resourceclaim_controller_resource_claims`).
//!
//! The informers are [`Reflector`]s over [`Storage`] (via `StorageListWatch`), so the
//! lister reads cost no storage round trip. The pod and claim indexes
//! (`podResourceClaimIndex`, `claimPodOwnerIndex`) are maintained from the event
//! stream. `claimCache` is `NewIntegerResourceVersionMutationCache(…, time.Hour, true)`:
//! a created claim stays visible to `findPodResourceClaim` until the informer's copy
//! has caught up.
//!
//! Deviations:
//! - The reflector emits no events for the initial list (an upstream informer delivers
//!   them as `AddFunc` calls), so after the caches sync the indexes are built and every
//!   pod and claim is enqueued from the stores. A lagged subscription does the same.
//! - Direct storage has no API server to fill `generateName`: the 5-character suffix
//!   is drawn here from the alphabet of `apimachinery/pkg/util/rand`.
//! - The pod status patch (`ApplyStatus` with `Force`) goes through [`Storage::apply`].
//! - Events are written through the in-process `EventRecorder`.

use crate::controllers::device_taint_eviction::{resource_claim_name, ClaimNameError};
use crate::controllers::storage_list_watch::StorageListWatch;
use crate::controllers::worker_pool::spawn_workers;
use anyhow::Result;
use kubernetes_rs_client::reflector::{Reflector, StoreEvent};
use kubernetes_rs_common::resources::dra::ResourceClaimConsumerReference;
use kubernetes_rs_common::resources::pod::PodResourceClaim;
use kubernetes_rs_common::resources::service_account::ObjectReference;
use kubernetes_rs_common::resources::{
    EventSource, EventType, Pod, ResourceClaim, ResourceClaimTemplate,
};
use kubernetes_rs_common::types::{ObjectMeta, OwnerReference, Phase};
use kubernetes_rs_common::Error;
use kubernetes_rs_storage::{build_key, build_prefix, EventRecorder, Storage, WorkQueue};
use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, LazyLock, Mutex, Once};
use std::time::{Duration, Instant};
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, error, info, warn};

/// `defaultResourceClaimControllerWorkers` (core.go:463).
pub const DEFAULT_WORKERS: usize = 50;

/// Queue name (`TypedRateLimitingQueueConfig{Name: "resource_claim"}`).
pub const QUEUE_NAME: &str = "resource_claim";

/// `podResourceClaimAnnotation`: the annotation generated claims get; its value is
/// `pod.spec.resourceClaims[].name`.
pub const POD_RESOURCE_CLAIM_ANNOTATION: &str = "resource.kubernetes.io/pod-claim-name";

/// `resourceapi.Finalizer` (staging/src/k8s.io/api/resource/v1/types.go:33).
pub const FINALIZER: &str = "resource.kubernetes.io/delete-protection";

/// `resourceapi.ExtendedResourceClaimAnnotation` (types.go:37).
pub const EXTENDED_RESOURCE_CLAIM_ANNOTATION: &str =
    "resource.kubernetes.io/extended-resource-claim";

/// `fieldManager`: used to update the pod status.
pub const FIELD_MANAGER: &str = "ResourceClaimController";

/// `maxUIDCacheEntries`.
pub const MAX_UID_CACHE_ENTRIES: usize = 500;

/// `claimKeyPrefix` / `podKeyPrefix`.
pub const CLAIM_KEY_PREFIX: &str = "claim:";
pub const POD_KEY_PREFIX: &str = "pod:";

/// `maxBaseLen`: room for a hyphen and 5 random characters in a 63-character name.
const MAX_BASE_LEN: usize = 57;

/// The mutation cache's time to live (`time.Hour`).
const MUTATION_TTL: Duration = Duration::from_secs(3600);

/// `ResourceClaimSubsystem`.
pub const SUBSYSTEM: &str = "resourceclaim_controller";

/// `resourceclaim.Features`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Features {
    pub admin_access: bool,
    pub prioritized_list: bool,
}

impl Features {
    /// What `newResourceClaimController` reads from the default feature gate.
    pub fn from_gates() -> Self {
        use kubernetes_rs_common::feature_gates::{enabled, Feature};
        Self {
            admin_access: enabled(Feature::DRAAdminAccess),
            prioritized_list: enabled(Feature::DRAPrioritizedList),
        }
    }
}

/// The descriptor's `requiredFeatureGates` (core.go:465-474): `DynamicResourceAllocation`.
pub fn feature_enabled() -> bool {
    kubernetes_rs_common::feature_gates::enabled(
        kubernetes_rs_common::feature_gates::Feature::DynamicResourceAllocation,
    )
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// `ResourceClaimCreate`.
static RESOURCE_CLAIM_CREATE: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    let c = prometheus::IntCounterVec::new(
        prometheus::Opts::new(
            "creates_total",
            "Number of ResourceClaims creation requests, categorized by creation status and admin access",
        )
        .subsystem(SUBSYSTEM),
        &["status", "admin_access"],
    )
    .expect("valid opts");
    let _ = prometheus::default_registry().register(Box::new(c.clone()));
    c
});

/// Value of `resourceclaim_controller_creates_total{status, admin_access}` (tests).
pub fn creates_total(status: &str, admin_access: &str) -> u64 {
    RESOURCE_CLAIM_CREATE
        .with_label_values(&[status, admin_access])
        .get()
}

const NUM_CLAIMS_HELP: &str = "Number of ResourceClaims, categorized by allocation status, admin access, and source. Source can be 'resource_claim_template' (created from a template), 'extended_resource' (extended resources), or empty (manually created by a user).";

fn num_claims_gauge() -> prometheus::GaugeVec {
    prometheus::GaugeVec::new(
        prometheus::Opts::new("resource_claims", NUM_CLAIMS_HELP).subsystem(SUBSYSTEM),
        &["allocated", "admin_access", "source"],
    )
    .expect("valid opts")
}

/// `customCollector` (controller.go): counts the claims in the lister at scrape time.
pub struct ClaimsCollector {
    claims: Arc<ClaimReflector>,
    desc: Desc,
}

impl ClaimsCollector {
    fn new(claims: Arc<ClaimReflector>) -> Self {
        let desc = num_claims_gauge()
            .desc()
            .into_iter()
            .next()
            .expect("one desc")
            .clone();
        Self { claims, desc }
    }

    /// `(allocated, admin_access, source)` -> number of claims.
    pub fn counts(&self) -> BTreeMap<(String, String, String), usize> {
        count_claims(&self.claims.store().items())
    }
}

/// `customCollector.Collect`'s grouping: `(allocated, admin_access, source)` -> number
/// of claims.
pub fn count_claims(items: &[ResourceClaim]) -> BTreeMap<(String, String, String), usize> {
    let mut m = BTreeMap::new();
    for rc in items {
        let allocated = if allocation_set(rc) { "true" } else { "false" };
        let admin_access = admin_access_metric_label(Some(rc));
        let annotations = rc.metadata.annotations.as_ref();
        let source = if annotations
            .and_then(|a| a.get(EXTENDED_RESOURCE_CLAIM_ANNOTATION))
            .is_some_and(|v| v == "true")
        {
            "extended_resource"
        } else if annotations
            .and_then(|a| a.get(POD_RESOURCE_CLAIM_ANNOTATION))
            .is_some_and(|v| !v.is_empty())
        {
            "resource_claim_template"
        } else {
            ""
        };
        *m.entry((
            allocated.to_string(),
            admin_access.to_string(),
            source.to_string(),
        ))
        .or_insert(0) += 1;
    }
    m
}

impl Collector for ClaimsCollector {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let g = num_claims_gauge();
        for ((allocated, admin_access, source), n) in self.counts() {
            g.with_label_values(&[&allocated, &admin_access, &source])
                .set(n as f64);
        }
        g.collect()
    }
}

/// `getAdminAccessMetricLabel`.
pub fn admin_access_metric_label(claim: Option<&ResourceClaim>) -> &'static str {
    let Some(claim) = claim else {
        return "false";
    };
    for request in &claim.spec.devices.requests {
        // Sub-requests in FirstAvailable don't have admin access.
        if request
            .exactly
            .as_ref()
            .is_some_and(|e| e.admin_access.unwrap_or(false))
        {
            return "true";
        }
    }
    "false"
}

// ---------------------------------------------------------------------------
// uidCache
// ---------------------------------------------------------------------------

/// `uidCache`: an LRU of pod UIDs that are known to have been deleted.
pub struct UidCache {
    max: usize,
    entries: Mutex<VecDeque<String>>,
}

impl UidCache {
    /// `newUIDCache`.
    pub fn new(max: usize) -> Self {
        Self {
            max,
            entries: Mutex::new(VecDeque::new()),
        }
    }

    /// `Add`.
    pub fn add(&self, uid: &str) {
        let mut e = self.entries.lock().expect("uid cache lock");
        if let Some(i) = e.iter().position(|u| u == uid) {
            e.remove(i);
        }
        e.push_front(uid.to_string());
        while e.len() > self.max {
            e.pop_back();
        }
    }

    /// `Has` (`lru.Cache.Get` also marks the entry as recently used).
    pub fn has(&self, uid: &str) -> bool {
        let mut e = self.entries.lock().expect("uid cache lock");
        match e.iter().position(|u| u == uid) {
            Some(i) => {
                let v = e.remove(i).expect("present");
                e.push_front(v);
                true
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Small upstream helpers
// ---------------------------------------------------------------------------

fn pod_ref(pod: &Pod) -> ObjectReference {
    ObjectReference {
        kind: Some("Pod".to_string()),
        namespace: pod.metadata.namespace.clone(),
        name: Some(pod.metadata.name.clone()),
        uid: Some(pod.metadata.uid.clone()),
        api_version: Some("v1".to_string()),
        resource_version: pod.metadata.resource_version.clone(),
        field_path: None,
    }
}

fn ns_of(meta: &ObjectMeta) -> &str {
    meta.namespace.as_deref().unwrap_or("")
}

/// `cache.MetaNamespaceKeyFunc`.
fn meta_key(meta: &ObjectMeta) -> String {
    match meta.namespace.as_deref() {
        Some(ns) if !ns.is_empty() => format!("{ns}/{}", meta.name),
        _ => meta.name.clone(),
    }
}

fn pod_key(p: &Pod) -> String {
    meta_key(&p.metadata)
}
fn claim_key(c: &ResourceClaim) -> String {
    meta_key(&c.metadata)
}
fn template_key(t: &ResourceClaimTemplate) -> String {
    meta_key(&t.metadata)
}

/// `cache.SplitMetaNamespaceKey`.
fn split_meta_namespace_key(key: &str) -> Result<(&str, &str), Error> {
    let parts: Vec<&str> = key.split('/').collect();
    match parts.as_slice() {
        [name] => Ok(("", name)),
        [ns, name] => Ok((ns, name)),
        _ => Err(Error::Internal(format!("unexpected key format: {key:?}"))),
    }
}

fn pod_claims(pod: &Pod) -> &[PodResourceClaim] {
    pod.spec
        .as_ref()
        .and_then(|s| s.resource_claims.as_deref())
        .unwrap_or(&[])
}

fn node_name(pod: &Pod) -> &str {
    pod.spec
        .as_ref()
        .and_then(|s| s.node_name.as_deref())
        .unwrap_or("")
}

/// `podutil.IsPodPhaseTerminal`.
fn is_pod_phase_terminal(pod: &Pod) -> bool {
    matches!(
        pod.status.as_ref().and_then(|s| s.phase.as_ref()),
        Some(Phase::Failed) | Some(Phase::Succeeded)
    )
}

/// `isPodDone`: certain that none of the containers are running and never will run.
pub fn is_pod_done(pod: &Pod) -> bool {
    is_pod_phase_terminal(pod)
        // Deleted and not scheduled:
        || (pod.metadata.deletion_timestamp.is_some() && node_name(pod).is_empty())
}

/// `resourceclaim.IsForPod`: the error text is upstream's.
fn is_for_pod(pod: &Pod, claim: &ResourceClaim) -> std::result::Result<(), String> {
    // `metav1.IsControlledBy` compares the controller reference's UID.
    let controlled = claim
        .metadata
        .owner_references
        .iter()
        .flatten()
        .any(|r| r.controller == Some(true) && r.uid == pod.metadata.uid);
    if ns_of(&claim.metadata) != ns_of(&pod.metadata) || !controlled {
        return Err(format!(
            "ResourceClaim {}/{} was not created for pod {}/{} (pod is not owner)",
            ns_of(&claim.metadata),
            claim.metadata.name,
            ns_of(&pod.metadata),
            pod.metadata.name
        ));
    }
    Ok(())
}

/// `resourceclaim.IsReservedForPod`.
fn is_reserved_for_pod(pod: &Pod, claim: &ResourceClaim) -> bool {
    claim
        .status
        .as_ref()
        .is_some_and(|s| s.reserved_for.iter().any(|r| r.uid == pod.metadata.uid))
}

/// `resourceclaim.CanBeReserved`: currently no restrictions on sharing.
fn can_be_reserved(_claim: &ResourceClaim) -> bool {
    true
}

fn allocation_set(claim: &ResourceClaim) -> bool {
    claim
        .status
        .as_ref()
        .is_some_and(|s| s.allocation.is_some())
}

/// `podNeedsClaims`: `true` means the pod still needs its claims (nothing to release).
fn pod_needs_claims(pod: &Pod, deleted: bool) -> (bool, &'static str) {
    if deleted {
        return (false, "pod got removed");
    }
    if is_pod_phase_terminal(pod) {
        return (false, "pod has terminated");
    }
    if pod.metadata.deletion_timestamp.is_some() && node_name(pod).is_empty() {
        return (false, "pod got deleted before scheduling");
    }
    // Still needs claims.
    (true, "pod might run")
}

/// `owningPod`.
fn owning_pod(claim: &ResourceClaim) -> (String, String) {
    for owner in claim.metadata.owner_references.iter().flatten() {
        if owner.controller == Some(true) && owner.api_version == "v1" && owner.kind == "Pod" {
            return (owner.name.clone(), owner.uid.clone());
        }
    }
    (String::new(), String::new())
}

/// `needsAdminAccess`.
fn needs_admin_access(t: &ResourceClaimTemplate) -> bool {
    t.spec.spec.devices.requests.iter().any(|r| {
        r.exactly
            .as_ref()
            .is_some_and(|e| e.admin_access.unwrap_or(false))
    })
}

/// `hasPrioritizedList`.
fn has_prioritized_list(t: &ResourceClaimTemplate) -> bool {
    t.spec
        .spec
        .devices
        .requests
        .iter()
        .any(|r| !r.first_available.is_empty())
}

/// The `generateName` of a claim generated for `pod_claim_name` of `pod_name`
/// (handleClaim: `pod.Name + "-" + podClaim.Name + "-"`, truncated proportionally to
/// leave room for the random suffix).
pub fn generate_name_for(pod_name: &str, pod_claim_name: &str) -> String {
    let generate_name = format!("{pod_name}-{pod_claim_name}-");
    if generate_name.len() > MAX_BASE_LEN {
        // We could leave truncation to the apiserver, but as it removes at the end, we
        // would lose everything from the pod claim name when the pod name is long.
        // Truncate both strings, proportional to their length.
        format!(
            "{}-{}",
            &pod_name[0..pod_name.len() * MAX_BASE_LEN / generate_name.len()],
            &pod_claim_name[0..pod_claim_name.len() * MAX_BASE_LEN / generate_name.len()]
        )
    } else {
        generate_name
    }
}

/// `rand.String(5)` (staging/src/k8s.io/apimachinery/pkg/util/rand/rand.go): the
/// alphabet leaves out vowels and look-alikes.
fn random_suffix() -> String {
    const ALPHANUMS: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";
    let u = uuid::Uuid::new_v4();
    u.as_bytes()
        .iter()
        .take(5)
        .map(|b| ALPHANUMS[*b as usize % ALPHANUMS.len()] as char)
        .collect()
}

fn is_not_found(e: &Error) -> bool {
    matches!(e, Error::NotFound(_))
}

fn rv_of(meta: &ObjectMeta) -> Option<u64> {
    meta.resource_version
        .as_deref()
        .and_then(|v| v.parse().ok())
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

type PodReflector = Reflector<Pod, fn(&Pod) -> String>;
type ClaimReflector = Reflector<ResourceClaim, fn(&ResourceClaim) -> String>;
type TemplateReflector = Reflector<ResourceClaimTemplate, fn(&ResourceClaimTemplate) -> String>;

/// The two cache indexes upstream installs on the informers.
#[derive(Default)]
struct Indexes {
    /// `podResourceClaimIndex`: claim key -> pod keys.
    pods_by_claim: HashMap<String, BTreeSet<String>>,
    /// The claim keys each pod is currently indexed under.
    claims_of_pod: HashMap<String, Vec<String>>,
    /// `claimPodOwnerIndex`: owner pod UID -> claim keys.
    claims_by_owner: HashMap<String, BTreeSet<String>>,
    /// The owner UIDs each claim is currently indexed under.
    owners_of_claim: HashMap<String, Vec<String>>,
}

/// `Controller`.
pub struct ResourceClaimController<S: Storage> {
    features: Features,
    storage: Arc<S>,
    /// `podLister` / `podIndexer`.
    pods: Arc<PodReflector>,
    /// `claimLister`.
    claims: Arc<ClaimReflector>,
    /// `templateLister`.
    templates: Arc<TemplateReflector>,
    queue: WorkQueue,
    indexes: Mutex<Indexes>,
    /// `claimCache`'s mutation layer.
    mutations: Mutex<HashMap<String, (ResourceClaim, Instant)>>,
    /// `deletedObjects`.
    deleted_objects: UidCache,
    recorder: EventRecorder<S>,
}

impl<S: Storage + 'static> ResourceClaimController<S> {
    /// `NewController`.
    pub fn new(storage: Arc<S>, features: Features) -> Self {
        let pods = Arc::new(Reflector::new(
            Arc::new(StorageListWatch::<S, Pod>::new(
                storage.clone(),
                build_prefix("pods", None),
            )),
            pod_key as fn(&Pod) -> String,
        ));
        let claims = Arc::new(Reflector::new(
            Arc::new(StorageListWatch::<S, ResourceClaim>::new(
                storage.clone(),
                build_prefix("resourceclaims", None),
            )),
            claim_key as fn(&ResourceClaim) -> String,
        ));
        let templates = Arc::new(Reflector::new(
            Arc::new(StorageListWatch::<S, ResourceClaimTemplate>::new(
                storage.clone(),
                build_prefix("resourceclaimtemplates", None),
            )),
            template_key as fn(&ResourceClaimTemplate) -> String,
        ));
        register_metrics(claims.clone());
        Self {
            features,
            recorder: EventRecorder::new(storage.clone()),
            storage,
            pods,
            claims,
            templates,
            queue: WorkQueue::named(QUEUE_NAME),
            indexes: Mutex::new(Indexes::default()),
            mutations: Mutex::new(HashMap::new()),
            deleted_objects: UidCache::new(MAX_UID_CACHE_ENTRIES),
        }
    }

    /// The controller's work queue (shared with tests).
    pub fn queue(&self) -> &WorkQueue {
        &self.queue
    }

    /// The `deletedObjects` cache (tests).
    pub fn deleted_objects(&self) -> &UidCache {
        &self.deleted_objects
    }

    // ----- indexes -----

    /// `podResourceClaimIndexFunc`: the claim keys (`ns/name`) a pod's claims resolve to.
    fn pod_index_keys(pod: &Pod) -> Vec<String> {
        let mut keys = Vec::new();
        for pc in pod_claims(pod) {
            // Index functions are not supposed to fail: for both error reasons (claim
            // not created yet, unknown API) the pod is simply not indexed.
            if let Ok(Some((name, _))) = resource_claim_name(pod, pc) {
                keys.push(format!("{}/{}", ns_of(&pod.metadata), name));
            }
        }
        keys
    }

    /// `claimPodOwnerIndexFunc`: the UIDs of the pods that own (control) the claim.
    fn claim_owner_keys(claim: &ResourceClaim) -> Vec<String> {
        claim
            .metadata
            .owner_references
            .iter()
            .flatten()
            .filter(|o| o.controller == Some(true) && o.api_version == "v1" && o.kind == "Pod")
            .map(|o| o.uid.clone())
            .collect()
    }

    fn index_pod(&self, pod: &Pod) {
        let key = pod_key(pod);
        let new = Self::pod_index_keys(pod);
        let mut ix = self.indexes.lock().expect("indexes lock");
        Self::drop_pod_index(&mut ix, &key);
        for c in &new {
            ix.pods_by_claim
                .entry(c.clone())
                .or_default()
                .insert(key.clone());
        }
        ix.claims_of_pod.insert(key, new);
    }

    fn drop_pod_index(ix: &mut Indexes, key: &str) {
        if let Some(old) = ix.claims_of_pod.remove(key) {
            for c in old {
                if let Some(set) = ix.pods_by_claim.get_mut(&c) {
                    set.remove(key);
                    if set.is_empty() {
                        ix.pods_by_claim.remove(&c);
                    }
                }
            }
        }
    }

    fn unindex_pod(&self, pod: &Pod) {
        let mut ix = self.indexes.lock().expect("indexes lock");
        Self::drop_pod_index(&mut ix, &pod_key(pod));
    }

    fn index_claim(&self, claim: &ResourceClaim) {
        let key = claim_key(claim);
        let new = Self::claim_owner_keys(claim);
        let mut ix = self.indexes.lock().expect("indexes lock");
        Self::drop_claim_index(&mut ix, &key);
        for o in &new {
            ix.claims_by_owner
                .entry(o.clone())
                .or_default()
                .insert(key.clone());
        }
        ix.owners_of_claim.insert(key, new);
    }

    fn drop_claim_index(ix: &mut Indexes, key: &str) {
        if let Some(old) = ix.owners_of_claim.remove(key) {
            for o in old {
                if let Some(set) = ix.claims_by_owner.get_mut(&o) {
                    set.remove(key);
                    if set.is_empty() {
                        ix.claims_by_owner.remove(&o);
                    }
                }
            }
        }
    }

    fn unindex_claim(&self, claim: &ResourceClaim) {
        let mut ix = self.indexes.lock().expect("indexes lock");
        Self::drop_claim_index(&mut ix, &claim_key(claim));
    }

    /// `claimCache.Mutation(claim)`.
    fn mutation(&self, claim: &ResourceClaim) {
        self.mutations
            .lock()
            .expect("mutations lock")
            .insert(claim_key(claim), (claim.clone(), Instant::now()));
    }

    /// `claimCache.ByIndex(claimPodOwnerIndex, podUID)`: the informer's claims owned by
    /// the pod plus the ones created by this controller that the informer has not caught
    /// up with yet (`NewIntegerResourceVersionMutationCache`: the mutated object is
    /// forgotten once the informer's copy is as new or after the TTL).
    fn claims_owned_by(&self, pod_uid: &str) -> Vec<ResourceClaim> {
        let store = self.claims.store();
        let keys: Vec<String> = {
            let ix = self.indexes.lock().expect("indexes lock");
            ix.claims_by_owner
                .get(pod_uid)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default()
        };
        let mut out: BTreeMap<String, ResourceClaim> = BTreeMap::new();
        for k in keys {
            if let Some(c) = store.get(&k) {
                out.insert(k, c);
            }
        }
        let mut muts = self.mutations.lock().expect("mutations lock");
        muts.retain(|k, (m, at)| {
            if at.elapsed() > MUTATION_TTL {
                return false;
            }
            match store.get(k) {
                // The informer has caught up (or is ahead): forget the mutation.
                Some(s) if rv_of(&s.metadata) >= rv_of(&m.metadata) => false,
                _ => true,
            }
        });
        for (k, (m, _)) in muts.iter() {
            if Self::claim_owner_keys(m).iter().any(|u| u == pod_uid) {
                out.insert(k.clone(), m.clone());
            }
        }
        out.into_values().collect()
    }

    // ----- event handlers -----

    /// The pod informer's `AddFunc` / `UpdateFunc` / `DeleteFunc`.
    pub async fn on_pod_event(&self, event: &StoreEvent<Pod>) {
        match event {
            StoreEvent::Added(p) | StoreEvent::Modified(p) => {
                self.index_pod(p);
                self.enqueue_pod(p, false).await;
            }
            StoreEvent::Deleted(p) => {
                self.unindex_pod(p);
                self.enqueue_pod(p, true).await;
            }
        }
    }

    /// The claim informer's `AddFunc` / `UpdateFunc` / `DeleteFunc`.
    pub async fn on_claim_event(&self, event: &StoreEvent<ResourceClaim>) {
        match event {
            StoreEvent::Added(c) | StoreEvent::Modified(c) => {
                self.index_claim(c);
                self.enqueue_resource_claim(c, false).await;
            }
            StoreEvent::Deleted(c) => {
                self.unindex_claim(c);
                self.enqueue_resource_claim(c, true).await;
            }
        }
    }

    /// `enqueuePod`.
    pub async fn enqueue_pod(&self, pod: &Pod, deleted: bool) {
        // Check if pod has any resource claims to process. Extended resource claims are
        // stored in pod.Status.ExtendedResourceClaimStatus, not in pod.Spec.ResourceClaims.
        let has_resource_claims = !pod_claims(pod).is_empty();
        // For cleanup of extended resource claims, claims present in pod status are
        // considered regardless of the current feature gate state.
        let extended = pod
            .status
            .as_ref()
            .and_then(|s| s.extended_resource_claim_status.as_ref());
        if !has_resource_claims && extended.is_none() {
            // Nothing to do for it at all.
            return;
        }

        if deleted {
            debug!("pod got deleted pod={}", pod_key(pod));
            self.deleted_objects.add(&pod.metadata.uid);
        }

        // Release reservations of a deleted or completed pod?
        let (needs_claims, reason) = pod_needs_claims(pod, deleted);
        if needs_claims {
            debug!("Not touching claims pod={} reason={reason}", pod_key(pod));
        } else {
            for pc in pod_claims(pod) {
                match resource_claim_name(pod, pc) {
                    // Either the claim was not created (nothing to do here) or the API
                    // changed. The latter will also get reported elsewhere.
                    Err(e) => debug!(
                        "Nothing to do for claim during pod change pod={} podClaim={} err={e:?} reason={reason}",
                        pod_key(pod),
                        pc.name
                    ),
                    Ok(Some((claim_name, _))) => {
                        let key =
                            format!("{CLAIM_KEY_PREFIX}{}/{claim_name}", ns_of(&pod.metadata));
                        debug!(
                            "Process claim pod={} key={key} reason={reason}",
                            pod_key(pod)
                        );
                        self.queue.add(key).await;
                    }
                    // Nothing to do, claim wasn't generated.
                    Ok(None) => debug!(
                        "Nothing to do for skipped claim during pod change pod={} podClaim={}",
                        pod_key(pod),
                        pc.name
                    ),
                }
            }
            // Extended resource claims are created by the scheduler and stored in
            // pod.Status.ExtendedResourceClaimStatus. Without this they would never be
            // cleaned up when pods complete.
            if let Some(ext) = extended {
                let key = format!(
                    "{CLAIM_KEY_PREFIX}{}/{}",
                    ns_of(&pod.metadata),
                    ext.resource_claim_name
                );
                debug!(
                    "Process extended resource claim pod={} key={key}",
                    pod_key(pod)
                );
                self.queue.add(key).await;
            }
        }

        let (needs_work, reason) = self.pod_needs_work(pod);
        if needs_work {
            debug!("enqueing pod pod={} reason={reason}", pod_key(pod));
            self.queue
                .add(format!(
                    "{POD_KEY_PREFIX}{}/{}",
                    ns_of(&pod.metadata),
                    pod.metadata.name
                ))
                .await;
            return;
        }
        debug!("not enqueing pod pod={} reason={reason}", pod_key(pod));
    }

    /// `podNeedsWork`: whether a new or modified pod needs to be processed further by a
    /// worker, with an explanation.
    pub fn pod_needs_work(&self, pod: &Pod) -> (bool, String) {
        if pod.metadata.deletion_timestamp.is_some() {
            // Nothing else to do for the pod.
            return (false, "pod is deleted".to_string());
        }
        let claims = self.claims.store();
        for pc in pod_claims(pod) {
            let (claim_name, check_owner) = match resource_claim_name(pod, pc) {
                Err(e) => return (true, format!("{e:?}")),
                // If the claim name is nil, then it has been determined before that the
                // claim is not needed.
                Ok(None) => return (false, "claim is not needed".to_string()),
                Ok(Some(v)) => v,
            };
            let Some(claim) = claims.get(&format!("{}/{claim_name}", ns_of(&pod.metadata))) else {
                if pc.resource_claim_template_name.is_some() {
                    return (true, "must create ResourceClaim from template".to_string());
                }
                // User needs to create claim.
                return (
                    false,
                    "claim is missing and must be created by user".to_string(),
                );
            };
            if check_owner {
                if let Err(e) = is_for_pod(pod, &claim) {
                    // Cannot proceed with the pod unless that other claim gets deleted.
                    return (false, e);
                }
            }
            // This check skips over the reasons below that only apply when a pod has
            // been scheduled already. We need to keep checking for more claims that
            // might need to be created.
            if node_name(pod).is_empty() {
                continue;
            }
            if allocation_set(&claim)
                && !is_reserved_for_pod(pod, &claim)
                && can_be_reserved(&claim)
            {
                // Need to reserve it.
                return (
                    true,
                    format!(
                        "need to reserve claim {}/{} for pod",
                        ns_of(&claim.metadata),
                        claim.metadata.name
                    ),
                );
            }
        }
        (false, "nothing to do".to_string())
    }

    /// `enqueueResourceClaim`.
    pub async fn enqueue_resource_claim(&self, claim: &ResourceClaim, deleted: bool) {
        if !deleted {
            // When starting up, we have to check all claims to find those with stale pods
            // in ReservedFor. During an update, a pod might get added that already no
            // longer exists.
            let key = format!(
                "{CLAIM_KEY_PREFIX}{}/{}",
                ns_of(&claim.metadata),
                claim.metadata.name
            );
            debug!("enqueing new or updated claim key={key}");
            self.queue.add(key).await;
        } else {
            debug!("not enqueing deleted claim claim={}", claim_key(claim));
        }

        // Also check whether this causes work for any of the currently known pods which
        // use the ResourceClaim.
        let pod_keys: Vec<String> = {
            let ix = self.indexes.lock().expect("indexes lock");
            ix.pods_by_claim
                .get(&claim_key(claim))
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default()
        };
        if pod_keys.is_empty() {
            debug!("unrelated to any known pod claim={}", claim_key(claim));
            return;
        }
        let store = self.pods.store();
        for k in pod_keys {
            if let Some(p) = store.get(&k) {
                self.enqueue_pod(&p, false).await;
            }
        }
    }

    /// Account for everything already in the stores (see the module deviation note).
    async fn resync_from_stores(&self) {
        for pod in self.pods.store().items() {
            self.index_pod(&pod);
        }
        for claim in self.claims.store().items() {
            self.index_claim(&claim);
        }
        for pod in self.pods.store().items() {
            self.enqueue_pod(&pod, false).await;
        }
        for claim in self.claims.store().items() {
            self.enqueue_resource_claim(&claim, false).await;
        }
    }

    /// List the pods, claims and templates into the stores once and build the indexes,
    /// without starting the watches or touching the queue: the state upstream's tests
    /// reach with `informerFactory.Start` + `WaitForCacheSync` (tests only).
    pub async fn prime_caches(&self) -> Result<()> {
        // `sync_once` lists, then watches until the stream ends: stop it once the list
        // is in the store.
        let pods = self.pods.clone();
        let claims = self.claims.clone();
        let templates = self.templates.clone();
        let tasks = [
            tokio::spawn(async move { pods.sync_once().await }),
            tokio::spawn(async move { claims.sync_once().await }),
            tokio::spawn(async move { templates.sync_once().await }),
        ];
        self.pods.wait_for_cache_sync().await;
        self.claims.wait_for_cache_sync().await;
        self.templates.wait_for_cache_sync().await;
        for t in tasks {
            t.abort();
        }
        for pod in self.pods.store().items() {
            self.index_pod(&pod);
        }
        for claim in self.claims.store().items() {
            self.index_claim(&claim);
        }
        Ok(())
    }

    /// `claimCache.Mutation(claim)` as a test seam (`ec.claimCache.Mutation(claim)`).
    pub fn add_mutation(&self, claim: &ResourceClaim) {
        self.mutation(claim);
    }

    /// Start the three informers and their event handlers. Subscriptions are taken
    /// before the reflectors run so no event is missed.
    pub fn start_informers(self: &Arc<Self>) {
        let mut pod_rx = self.pods.subscribe();
        let mut claim_rx = self.claims.subscribe();
        let p = self.pods.clone();
        tokio::spawn(async move { p.run().await });
        let c = self.claims.clone();
        tokio::spawn(async move { c.run().await });
        let t = self.templates.clone();
        tokio::spawn(async move { t.run().await });

        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match pod_rx.recv().await {
                    Ok(ev) => this.on_pod_event(&ev).await,
                    Err(RecvError::Lagged(n)) => {
                        warn!("resource-claim-controller pod events lagged {n}; resyncing");
                        this.resync_from_stores().await;
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match claim_rx.recv().await {
                    Ok(ev) => this.on_claim_event(&ev).await,
                    Err(RecvError::Lagged(n)) => {
                        warn!("resource-claim-controller claim events lagged {n}; resyncing");
                        this.resync_from_stores().await;
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });
    }

    /// `Run`: start the informers, wait for the caches (`podSynced`, `claimsSynced`,
    /// `templatesSynced`), then run `workers` workers over the one queue.
    pub async fn run_with_workers(self: Arc<Self>, workers: usize) -> Result<()> {
        info!("Starting resource claim controller");
        self.start_informers();
        self.pods.wait_for_cache_sync().await;
        self.claims.wait_for_cache_sync().await;
        self.templates.wait_for_cache_sync().await;
        self.resync_from_stores().await;

        spawn_workers(workers, &self.queue, {
            let this = Arc::clone(&self);
            move |_queue| {
                let this = Arc::clone(&this);
                async move { while this.process_next_work_item().await {} }
            }
        });
        // `<-ctx.Done()`: the workers run until the queue is shut down.
        std::future::pending::<()>().await;
        info!("Shutting down resource claim controller");
        Ok(())
    }

    /// `Run` with `defaultResourceClaimControllerWorkers`.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        self.run_with_workers(DEFAULT_WORKERS).await
    }

    /// `processNextWorkItem`: `false` when the queue is shut down.
    pub async fn process_next_work_item(&self) -> bool {
        let Some(key) = self.queue.get().await else {
            return false;
        };
        match self.sync_handler(&key).await {
            Ok(()) => self.queue.forget(&key).await,
            Err(e) => {
                error!("Work item failed item={key} err={e}");
                self.queue.requeue_rate_limited(key.clone()).await;
            }
        }
        self.queue.done(&key).await;
        true
    }

    /// `syncHandler`: invoked for each work item which might need to be processed. If an
    /// error is returned the item is requeued.
    pub async fn sync_handler(&self, key: &str) -> Result<(), Error> {
        let sep = key
            .find(':')
            .ok_or_else(|| Error::Internal(format!("unexpected key: {key}")))?;
        let (prefix, object) = (&key[..=sep], &key[sep + 1..]);
        let (namespace, name) = split_meta_namespace_key(object)?;
        match prefix {
            POD_KEY_PREFIX => self.sync_pod(namespace, name).await,
            CLAIM_KEY_PREFIX => self.sync_claim(namespace, name).await,
            _ => Err(Error::Internal(format!("unexpected key prefix: {prefix}"))),
        }
    }

    /// `syncPod`.
    pub async fn sync_pod(&self, namespace: &str, name: &str) -> Result<(), Error> {
        let Some(pod) = self.pods.store().get(&format!("{namespace}/{name}")) else {
            debug!("nothing to do for pod, it is gone pod={namespace}/{name}");
            return Ok(());
        };
        // Ignore pods which are already getting deleted.
        if pod.metadata.deletion_timestamp.is_some() {
            debug!("nothing to do for pod, it is marked for deletion pod={namespace}/{name}");
            return Ok(());
        }

        let mut new_pod_claims: BTreeMap<String, String> = BTreeMap::new();
        for pc in pod_claims(&pod) {
            if let Err(e) = self.handle_claim(&pod, pc, &mut new_pod_claims).await {
                self.record_pod_warning(
                    &pod,
                    "FailedResourceClaimCreation",
                    &format!("PodResourceClaim {}: {e}", pc.name),
                )
                .await;
                return Err(Error::Internal(format!(
                    "pod {namespace}/{name}, PodResourceClaim {}: {e}",
                    pc.name
                )));
            }
        }

        if !new_pod_claims.is_empty() {
            // Patch the pod status with the new information about generated ResourceClaims.
            let statuses: Vec<serde_json::Value> = new_pod_claims
                .iter()
                .map(|(pc, rc)| serde_json::json!({"name": pc, "resourceClaimName": rc}))
                .collect();
            let apply = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": name, "namespace": namespace},
                "status": {"resourceClaimStatuses": statuses},
            });
            let key = build_key("pods", Some(namespace), name);
            self.storage
                .apply::<Pod>(&key, &apply, FIELD_MANAGER, true, Some("status"))
                .await
                .map_err(|e| {
                    Error::Internal(format!(
                        "update pod {namespace}/{name} ResourceClaimStatuses: {e}"
                    ))
                })?;
        }

        if node_name(&pod).is_empty() {
            // Scheduler will handle reservations.
            debug!("nothing to do for pod, scheduler will deal with it pod={namespace}/{name}");
            return Ok(());
        }

        let claims = self.claims.store();
        for pc in pod_claims(&pod) {
            let (claim_name, check_owner) = match resource_claim_name(&pod, pc) {
                Err(e) => return Err(Error::Internal(format!("{e:?}"))),
                Ok(None) => continue,
                Ok(Some(v)) => v,
            };
            let Some(claim) = claims.get(&format!("{namespace}/{claim_name}")) else {
                return Ok(());
            };
            if check_owner {
                is_for_pod(&pod, &claim).map_err(Error::Internal)?;
            }
            if allocation_set(&claim)
                && !is_reserved_for_pod(&pod, &claim)
                && can_be_reserved(&claim)
            {
                debug!("reserve claim for pod resourceClaim={namespace}/{claim_name}");
                self.reserve_for_pod(&pod, &claim).await?;
            }
        }
        Ok(())
    }

    async fn record_pod_warning(&self, pod: &Pod, reason: &str, message: &str) {
        let source = EventSource {
            component: "resource_claim".to_string(),
            host: None,
        };
        if let Err(e) = self
            .recorder
            .event(&pod_ref(pod), &source, EventType::Warning, reason, message)
            .await
        {
            warn!("Failed to record {reason} event: {e}");
        }
    }

    /// `handleClaim`: invoked for each resource claim of a pod.
    async fn handle_claim(
        &self,
        pod: &Pod,
        pod_claim: &PodResourceClaim,
        new_pod_claims: &mut BTreeMap<String, String>,
    ) -> std::result::Result<(), String> {
        debug!("checking podClaim={}", pod_claim.name);
        // resourceclaim.Name checks for the situation that the client doesn't know some
        // future addition to the API. Therefore it gets called here even if there is no
        // template to work on.
        match resource_claim_name(pod, pod_claim) {
            Err(ClaimNameError::NotCreatedYet) => {
                // Continue below.
            }
            Err(e) => {
                return Err(format!("checking for claim before creating it: {e:?}"));
            }
            // Nothing to do, no claim needed.
            Ok(None) => return Ok(()),
            Ok(Some((claim_name, must_check_owner))) if !claim_name.is_empty() => {
                // The ResourceClaim should exist because it is recorded in the
                // pod.status.resourceClaimStatuses, but perhaps it was deleted
                // accidentally. In that case we re-create it.
                let claim = self
                    .claims
                    .store()
                    .get(&format!("{}/{claim_name}", ns_of(&pod.metadata)));
                if let Some(claim) = claim {
                    let err = if must_check_owner {
                        is_for_pod(pod, &claim).err()
                    } else {
                        None
                    };
                    match err {
                        None => {
                            // Already created, nothing more to do.
                            debug!(
                                "claim already created podClaim={} resourceClaim={claim_name}",
                                pod_claim.name
                            );
                            return Ok(());
                        }
                        Some(e) => error!(
                            "claim that was created for the pod is no longer owned by the pod, creating a new one podClaim={} resourceClaim={claim_name} err={e}",
                            pod_claim.name
                        ),
                    }
                }
            }
            // An empty name: fall through to the template handling.
            Ok(Some(_)) => {}
        }

        let Some(template_name) = pod_claim.resource_claim_template_name.as_deref() else {
            // Nothing to do.
            return Ok(());
        };

        // Before we create a new ResourceClaim, check if there is an orphaned one. This
        // covers the case that the controller has created it, but then fails before it
        // can update the pod status.
        let mut claim = self.find_pod_resource_claim(pod, pod_claim);
        if claim.is_none() {
            let template = self
                .templates
                .store()
                .get(&format!("{}/{template_name}", ns_of(&pod.metadata)))
                .ok_or_else(|| {
                    format!(
                        "resource claim template {template_name:?}: resourceclaimtemplate.resource.k8s.io \"{template_name}\" not found"
                    )
                })?;
            if !self.features.admin_access && needs_admin_access(&template) {
                return Err("admin access is requested, but the feature is disabled".to_string());
            }
            if !self.features.prioritized_list && has_prioritized_list(&template) {
                return Err(
                    "template includes a prioritized list of subrequests, but the feature is disabled"
                        .to_string(),
                );
            }

            // Create the ResourceClaim with pod as owner, with a generated name that uses
            // <pod>-<claim name> as base.
            let mut annotations = template
                .spec
                .metadata
                .annotations
                .clone()
                .unwrap_or_default();
            annotations.insert(
                POD_RESOURCE_CLAIM_ANNOTATION.to_string(),
                pod_claim.name.clone(),
            );
            let generate_name = generate_name_for(&pod.metadata.name, &pod_claim.name);
            let name = format!("{generate_name}{}", random_suffix());
            let mut meta = ObjectMeta::new(name.clone()).with_namespace(ns_of(&pod.metadata));
            meta.generate_name = Some(generate_name);
            // `metav1.NewControllerRef(pod, schema.GroupVersionKind{Version: "v1", Kind: "Pod"})`.
            let mut owner = OwnerReference::new(
                "v1",
                "Pod",
                pod.metadata.name.clone(),
                pod.metadata.uid.clone(),
            );
            owner.controller = Some(true);
            owner.block_owner_deletion = Some(true);
            meta.owner_references = Some(vec![owner]);
            meta.annotations = Some(annotations);
            meta.labels = template.spec.metadata.labels.clone();
            let new_claim = ResourceClaim {
                api_version: "resource.k8s.io/v1".to_string(),
                kind: "ResourceClaim".to_string(),
                metadata: meta,
                spec: template.spec.spec.clone(),
                status: None,
            };
            let metric_label = admin_access_metric_label(Some(&new_claim));
            let key = build_key("resourceclaims", Some(ns_of(&pod.metadata)), &name);
            match self.storage.create(&key, &new_claim).await {
                Ok(created) => {
                    RESOURCE_CLAIM_CREATE
                        .with_label_values(&["success", metric_label])
                        .inc();
                    debug!(
                        "Created ResourceClaim claim={}/{} pod={}",
                        ns_of(&created.metadata),
                        created.metadata.name,
                        pod_key(pod)
                    );
                    self.mutation(&created);
                    claim = Some(created);
                }
                Err(e) => {
                    RESOURCE_CLAIM_CREATE
                        .with_label_values(&["failure", metric_label])
                        .inc();
                    return Err(format!("create ResourceClaim {name}: {e}"));
                }
            }
        }

        // Remember the new ResourceClaim for a batch PodStatus update in our caller.
        let claim = claim.expect("set above");
        new_pod_claims.insert(pod_claim.name.clone(), claim.metadata.name);
        Ok(())
    }

    /// `findPodResourceClaim`: looks for an existing ResourceClaim with the right
    /// annotation (ties it to the pod claim) and the right ownership (ties it to the pod).
    pub fn find_pod_resource_claim(
        &self,
        pod: &Pod,
        pod_claim: &PodResourceClaim,
    ) -> Option<ResourceClaim> {
        // Only claims owned by the pod will get returned here.
        for claim in self.claims_owned_by(&pod.metadata.uid) {
            let Some(name) = claim
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get(POD_RESOURCE_CLAIM_ANNOTATION))
            else {
                // No annotation? Then it cannot be an automatically generated claim and we
                // need to ignore it.
                continue;
            };
            // Not the claim for this particular pod claim?
            if name != &pod_claim.name {
                continue;
            }
            // Pick the first one that matches. There shouldn't be more than one.
            return Some(claim);
        }
        None
    }

    /// `reserveForPod`.
    async fn reserve_for_pod(&self, pod: &Pod, claim: &ResourceClaim) -> Result<(), Error> {
        let mut claim = claim.clone();
        claim
            .status
            .get_or_insert_with(Default::default)
            .reserved_for
            .push(ResourceClaimConsumerReference {
                api_group: None,
                resource: "pods".to_string(),
                name: pod.metadata.name.clone(),
                uid: pod.metadata.uid.clone(),
            });
        let key = build_key(
            "resourceclaims",
            Some(ns_of(&claim.metadata)),
            &claim.metadata.name,
        );
        self.storage
            .update_status::<ResourceClaim>(&key, &claim)
            .await
            .map_err(|e| {
                Error::Internal(format!(
                    "reserve claim {}/{} for pod: {e}",
                    ns_of(&claim.metadata),
                    claim.metadata.name
                ))
            })?;
        Ok(())
    }

    /// `syncClaim`.
    pub async fn sync_claim(&self, namespace: &str, name: &str) -> Result<(), Error> {
        let Some(claim) = self.claims.store().get(&format!("{namespace}/{name}")) else {
            debug!("nothing to do for claim, it is gone claim={namespace}/{name}");
            return Ok(());
        };
        let reserved_for = claim
            .status
            .as_ref()
            .map(|s| s.reserved_for.clone())
            .unwrap_or_default();

        // Check if the ReservedFor entries are all still valid.
        let mut valid: Vec<ResourceClaimConsumerReference> = Vec::with_capacity(reserved_for.len());
        for rf in &reserved_for {
            if rf.api_group.as_deref().unwrap_or("").is_empty() && rf.resource == "pods" {
                // A pod falls into one of three categories:
                // - we have it in our cache -> don't remove it until we are told that it got removed
                // - we don't have it in our cache anymore, but we have seen it before -> it was deleted, remove it
                // - not in our cache, not seen -> double-check with API server before removal
                let mut keep_entry = true;
                // Tracking deleted pods in the LRU cache is an optimization: without it
                // the API call below would be needed for every deleted pod.
                if self.deleted_objects.has(&rf.uid) {
                    // We know that the pod was deleted.
                    keep_entry = false;
                } else {
                    match self.pods.store().get(&format!("{namespace}/{}", rf.name)) {
                        None => {
                            // We might not have it in our informer cache yet. Removing the
                            // pod while the scheduler is scheduling it would be bad: be
                            // absolutely sure and check with the API server.
                            let key = build_key("pods", Some(namespace), &rf.name);
                            let pod = match self.storage.get::<Pod>(&key).await {
                                Ok(p) => Some(p),
                                Err(e) if is_not_found(&e) => None,
                                Err(e) => return Err(e),
                            };
                            if pod.as_ref().is_none_or(|p| p.metadata.uid != rf.uid) {
                                debug!(
                                    "remove reservation because pod is gone or got replaced pod={namespace}/{} claim={namespace}/{name}",
                                    rf.name
                                );
                                keep_entry = false;
                            }
                        }
                        Some(pod) if pod.metadata.uid != rf.uid => {
                            debug!(
                                "remove reservation because pod got replaced with new instance pod={namespace}/{} claim={namespace}/{name}",
                                rf.name
                            );
                            keep_entry = false;
                        }
                        Some(pod) if is_pod_done(&pod) => {
                            debug!(
                                "remove reservation because pod will not run anymore pod={namespace}/{} claim={namespace}/{name}",
                                rf.name
                            );
                            keep_entry = false;
                        }
                        Some(_) => {}
                    }
                }
                if keep_entry {
                    valid.push(rf.clone());
                }
                continue;
            }
            // Upstream: "TODO: support generic object lookup".
            return Err(Error::Internal(format!(
                "unsupported ReservedFor entry: {rf:?}"
            )));
        }

        let finalizers = claim.metadata.finalizers.clone().unwrap_or_default();
        let has_finalizer = finalizers.iter().any(|f| f == FINALIZER);
        debug!(
            "claim reserved for counts currentCount={} claim={namespace}/{name} updatedCount={} builtinController={has_finalizer}",
            reserved_for.len(),
            valid.len()
        );
        let key = build_key("resourceclaims", Some(namespace), name);
        if valid.len() < reserved_for.len() {
            // This is not using a patch because we want the update to fail if anything
            // changed in the meantime.
            let mut updated = claim.clone();
            updated
                .status
                .get_or_insert_with(Default::default)
                .reserved_for = valid.clone();
            // DRA always performs delayed allocations. Relatedly, it also deallocates a
            // claim as soon as the last consumer stops using it, so the claim can be
            // allocated again as needed by some future consumer and the underlying
            // resources are released for other claims. This has to be triggered by the
            // transition from "was being used" to "is not used anymore".
            //
            // Sanity check: there shouldn't be any claims without this finalizer.
            if valid.is_empty() && has_finalizer {
                // Allocated by scheduler with structured parameters. We can
                // "deallocate" by clearing the allocation.
                updated
                    .status
                    .get_or_insert_with(Default::default)
                    .allocation = None;
            }
            let mut updated = self
                .storage
                .update_status::<ResourceClaim>(&key, &updated)
                .await?;
            // Now also remove the finalizer if it is not needed anymore.
            let fins = updated.metadata.finalizers.clone().unwrap_or_default();
            if fins.iter().any(|f| f == FINALIZER) && !allocation_set(&updated) {
                updated.metadata.finalizers =
                    Some(fins.into_iter().filter(|f| f != FINALIZER).collect());
                self.storage.update::<ResourceClaim>(&key, &updated).await?;
            }
        } else if has_finalizer && claim.metadata.deletion_timestamp.is_some() && valid.is_empty() {
            let mut updated = claim.clone();
            if allocation_set(&updated) {
                // This can happen when a claim with immediate allocation stopped being
                // used, remained allocated, and then got deleted. As above we then need to
                // clear the allocation.
                updated
                    .status
                    .get_or_insert_with(Default::default)
                    .allocation = None;
                updated = self
                    .storage
                    .update_status::<ResourceClaim>(&key, &updated)
                    .await?;
            }
            // Whether it was allocated or not, remove the finalizer to unblock removal.
            let fins = updated.metadata.finalizers.clone().unwrap_or_default();
            updated.metadata.finalizers =
                Some(fins.into_iter().filter(|f| f != FINALIZER).collect());
            self.storage.update::<ResourceClaim>(&key, &updated).await?;
        }

        if valid.is_empty() {
            // Claim is not reserved. If it was generated for a pod and that pod is not
            // going to run, the claim can be deleted. Normally the garbage collector does
            // that, but the pod itself might not get deleted for a while.
            let (pod_name, pod_uid) = owning_pod(&claim);
            if !pod_name.is_empty() {
                match self.pods.store().get(&format!("{namespace}/{pod_name}")) {
                    Some(pod) => {
                        // Pod already replaced or not going to run?
                        if pod.metadata.uid != pod_uid || is_pod_done(&pod) {
                            // We are certain that the owning pod is not going to need the
                            // claim and therefore remove the claim.
                            debug!(
                                "deleting unused generated claim claim={namespace}/{name} pod={namespace}/{pod_name}"
                            );
                            self.storage.delete(&key).await.map_err(|e| {
                                Error::Internal(format!("delete claim {namespace}/{name}: {e}"))
                            })?;
                        } else {
                            debug!(
                                "wrong pod content, not deleting claim claim={namespace}/{name} podUID={pod_uid}"
                            );
                        }
                    }
                    // We might not know the pod *yet*. Instead of doing an expensive API
                    // call, let the garbage collector handle the case that the pod is
                    // truly gone.
                    None => debug!(
                        "pod for claim not found claim={namespace}/{name} pod={namespace}/{pod_name}"
                    ),
                }
            } else {
                debug!("claim not generated for a pod claim={namespace}/{name}");
            }
        }
        Ok(())
    }
}

static REGISTER_COLLECTOR: Once = Once::new();

/// `RegisterMetrics`: the counter and the claims collector, once per process.
fn register_metrics(claims: Arc<ClaimReflector>) {
    LazyLock::force(&RESOURCE_CLAIM_CREATE);
    REGISTER_COLLECTOR.call_once(|| {
        let _ = prometheus::default_registry().register(Box::new(ClaimsCollector::new(claims)));
    });
}
