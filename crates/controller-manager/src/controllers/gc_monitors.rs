//! Metadata-only monitors for the garbage collector.
//!
//! Port of the monitor half of `pkg/controller/garbagecollector/graph_builder.go`
//! (`monitor`, `controllerFor` :188, `syncMonitors` :241, `startMonitors` :294,
//! `stopMonitors`, `IsResourceSynced` :351, `IsSynced` :362,
//! `DefaultIgnoredResources` :418) and `metaonly/types.go`
//! (`MetadataOnlyObject`).
//!
//! Upstream's monitors are shared metadata informers whose handlers push
//! add/update/delete events onto the `graphChanges` queue. Here each monitor
//! is a list+watch task over [`Storage`] (the same source every other
//! controller reads) decoding only `apiVersion`, `kind` and `metadata`, and
//! sending [`GraphEvent`]s on a channel for the graph builder (cm-P1-08).
//! Storage keys are by resource name only (`/registry/<resource>/...`), so the
//! group and version of a [`GroupVersionResource`] do not take part in key
//! construction.

use kubernetes_rs_common::types::{ObjectMeta, TypeMeta};
use kubernetes_rs_storage::{build_prefix, Storage, WatchEvent};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// `schema.GroupResource`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupResource {
    pub group: String,
    pub resource: String,
}

impl GroupResource {
    pub fn new(group: &str, resource: &str) -> Self {
        Self {
            group: group.into(),
            resource: resource.into(),
        }
    }
}

/// `schema.GroupVersionResource`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupVersionResource {
    pub group: String,
    pub version: String,
    pub resource: String,
}

impl GroupVersionResource {
    pub fn new(group: &str, version: &str, resource: &str) -> Self {
        Self {
            group: group.into(),
            version: version.into(),
            resource: resource.into(),
        }
    }

    /// `GroupResource()`.
    pub fn group_resource(&self) -> GroupResource {
        GroupResource::new(&self.group, &self.resource)
    }
}

/// `schema.GroupVersionKind`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupVersionKind {
    pub group: String,
    pub version: String,
    pub kind: String,
}

/// `ignoredResources` / `DefaultIgnoredResources` (graph_builder.go:411-420):
/// core and `events.k8s.io` events.
pub fn default_ignored_resources() -> HashSet<GroupResource> {
    [
        GroupResource::new("", "events"),
        GroupResource::new("events.k8s.io", "events"),
    ]
    .into()
}

/// `metaonly.MetadataOnlyObject`: decodes only `apiVersion`, `kind` and
/// `metadata`, dropping everything else (spec, status, data).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MetadataOnlyObject {
    #[serde(flatten)]
    pub type_meta: TypeMeta,
    #[serde(default)]
    pub metadata: ObjectMeta,
}

/// `eventType` (graph_builder.go:62-66).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphEventType {
    Add,
    Update,
    Delete,
}

/// `event` (graph_builder.go:68-77).
#[derive(Debug, Clone)]
pub struct GraphEvent {
    /// Constructed artificially rather than seen by a monitor.
    pub virtual_event: bool,
    pub event_type: GraphEventType,
    pub obj: MetadataOnlyObject,
    /// The previous object for an update (unused by the collector itself).
    pub old_obj: Option<MetadataOnlyObject>,
    pub gvk: GroupVersionKind,
}

/// Resync delay after a broken watch, before relisting.
const RELIST_BACKOFF: Duration = Duration::from_secs(1);

/// `monitor` (graph_builder.go:115-122). `task` is `None` until started
/// (upstream: `stopCh == nil`).
struct Monitor {
    gvk: GroupVersionKind,
    synced: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}

/// The monitors of a `GraphBuilder`.
pub struct Monitors<S: Storage + 'static> {
    storage: Arc<S>,
    ignored_resources: HashSet<GroupResource>,
    monitors: BTreeMap<GroupVersionResource, Monitor>,
    tx: UnboundedSender<GraphEvent>,
    /// `gb.running`: monitors only start once `run` has been called.
    running: bool,
}

/// `syncMonitors` counts, for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncMonitorsResult {
    pub added: usize,
    pub kept: usize,
    pub removed: usize,
}

impl<S: Storage + 'static> Monitors<S> {
    pub fn new(
        storage: Arc<S>,
        ignored_resources: HashSet<GroupResource>,
        tx: UnboundedSender<GraphEvent>,
    ) -> Self {
        Self {
            storage,
            ignored_resources,
            monitors: BTreeMap::new(),
            tx,
            running: false,
        }
    }

    /// `Run` sets `running`; `startMonitors` does nothing before it.
    pub fn set_running(&mut self, running: bool) {
        self.running = running;
    }

    /// `syncMonitors` (graph_builder.go:241): rebuild the monitor set from
    /// `resources`, keeping existing monitors, creating missing ones and
    /// stopping removed ones. Monitors are NOT started. Every resource gets an
    /// attempt; failures are returned together (`NewAggregate`).
    pub fn sync_monitors<F>(
        &mut self,
        resources: &BTreeSet<GroupVersionResource>,
        kind_for: F,
    ) -> (SyncMonitorsResult, Vec<String>)
    where
        F: Fn(&GroupVersionResource) -> Result<GroupVersionKind, String>,
    {
        let mut to_remove = std::mem::take(&mut self.monitors);
        let mut current = BTreeMap::new();
        let mut errs = Vec::new();
        let mut result = SyncMonitorsResult::default();
        for resource in resources {
            if self.ignored_resources.contains(&resource.group_resource()) {
                continue;
            }
            if let Some(m) = to_remove.remove(resource) {
                current.insert(resource.clone(), m);
                result.kept += 1;
                continue;
            }
            match kind_for(resource) {
                Ok(gvk) => {
                    current.insert(
                        resource.clone(),
                        Monitor {
                            gvk,
                            synced: Arc::new(AtomicBool::new(false)),
                            task: None,
                        },
                    );
                    result.added += 1;
                }
                Err(e) => errs.push(format!("couldn't look up resource {resource:?}: {e}")),
            }
        }
        self.monitors = current;
        result.removed = to_remove.len();
        for m in to_remove.into_values() {
            if let Some(t) = m.task {
                t.abort();
            }
        }
        debug!(
            "synced monitors: added {} kept {} removed {}",
            result.added, result.kept, result.removed
        );
        (result, errs)
    }

    /// `startMonitors` (graph_builder.go:294): start every monitor that is not
    /// yet running. Does nothing before `set_running(true)`. Returns how many
    /// were started.
    pub fn start_monitors(&mut self) -> usize {
        if !self.running {
            return 0;
        }
        let mut started = 0;
        for (resource, m) in self.monitors.iter_mut() {
            if m.task.is_some() {
                continue;
            }
            m.task = Some(tokio::spawn(run_monitor(
                Arc::clone(&self.storage),
                resource.resource.clone(),
                m.gvk.clone(),
                self.tx.clone(),
                Arc::clone(&m.synced),
            )));
            started += 1;
        }
        debug!(
            "started new monitors: new {started} current {}",
            self.monitors.len()
        );
        started
    }

    /// `stopMonitors`: stop everything and reset so the builder can be re-run.
    pub fn stop_monitors(&mut self) {
        self.running = false;
        for (_, m) in std::mem::take(&mut self.monitors) {
            if let Some(t) = m.task {
                t.abort();
            }
        }
    }

    /// `IsResourceSynced` (:351): a monitor exists and has synced.
    pub fn is_resource_synced(&self, resource: &GroupVersionResource) -> bool {
        self.monitors
            .get(resource)
            .is_some_and(|m| m.synced.load(Ordering::SeqCst))
    }

    /// `IsSynced` (:362): any monitors exist AND all of them have synced.
    pub fn is_synced(&self) -> bool {
        if self.monitors.is_empty() {
            debug!("garbage controller monitor not synced: no monitors");
            return false;
        }
        self.monitors
            .values()
            .all(|m| m.synced.load(Ordering::SeqCst))
    }

    pub fn len(&self) -> usize {
        self.monitors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.monitors.is_empty()
    }
}

impl<S: Storage + 'static> Drop for Monitors<S> {
    fn drop(&mut self) {
        for m in self.monitors.values_mut() {
            if let Some(t) = m.task.take() {
                t.abort();
            }
        }
    }
}

fn decode(raw: &str) -> Option<MetadataOnlyObject> {
    serde_json::from_str(raw).ok()
}

fn send(
    tx: &UnboundedSender<GraphEvent>,
    gvk: &GroupVersionKind,
    event_type: GraphEventType,
    obj: MetadataOnlyObject,
    old_obj: Option<MetadataOnlyObject>,
) {
    // A closed receiver means the builder is gone; the task is aborted soon.
    let _ = tx.send(GraphEvent {
        virtual_event: false,
        event_type,
        obj,
        old_obj,
        gvk: gvk.clone(),
    });
}

/// Add when unseen, Update when changed. An object identical to the stored
/// one (same resourceVersion included) is a replayed watch event or a relist of
/// an unchanged object, which an informer does not deliver as an update.
fn emit_upsert(
    tx: &UnboundedSender<GraphEvent>,
    gvk: &GroupVersionKind,
    obj: MetadataOnlyObject,
    old: Option<MetadataOnlyObject>,
) {
    match old {
        None => send(tx, gvk, GraphEventType::Add, obj, None),
        Some(old) if old == obj => {}
        Some(old) => send(tx, gvk, GraphEventType::Update, obj, Some(old)),
    }
}

/// A reflector over [`Storage`]: list, replace the store (emitting
/// add/update/delete for the difference, where a vanished object is
/// upstream's unwrapped `DeletedFinalStateUnknown`), mark synced, then apply
/// watch events until the stream breaks and relist.
async fn run_monitor<S: Storage + 'static>(
    storage: Arc<S>,
    resource: String,
    gvk: GroupVersionKind,
    tx: UnboundedSender<GraphEvent>,
    synced: Arc<AtomicBool>,
) {
    use futures::StreamExt;
    let prefix = build_prefix(&resource, None);
    // uid -> last seen object (the informer's store).
    let mut store: HashMap<String, MetadataOnlyObject> = HashMap::new();
    loop {
        let revision = storage.current_revision().await.ok();
        match storage.list::<MetadataOnlyObject>(&prefix).await {
            Ok(items) => {
                let mut seen = HashSet::new();
                for obj in items {
                    let uid = obj.metadata.uid.clone();
                    seen.insert(uid.clone());
                    let old = store.insert(uid, obj.clone());
                    emit_upsert(&tx, &gvk, obj, old);
                }
                let gone: Vec<String> = store
                    .keys()
                    .filter(|u| !seen.contains(*u))
                    .cloned()
                    .collect();
                for uid in gone {
                    if let Some(old) = store.remove(&uid) {
                        send(&tx, &gvk, GraphEventType::Delete, old, None);
                    }
                }
                synced.store(true, Ordering::SeqCst);
            }
            Err(e) => {
                warn!("garbage collector monitor for {resource}: list failed: {e}");
                tokio::time::sleep(RELIST_BACKOFF).await;
                continue;
            }
        }

        let stream = match revision {
            Some(rev) => storage.watch_from_revision(&prefix, rev).await,
            None => storage.watch(&prefix).await,
        };
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!("garbage collector monitor for {resource}: watch failed: {e}");
                tokio::time::sleep(RELIST_BACKOFF).await;
                continue;
            }
        };
        while let Some(ev) = stream.next().await {
            let ev = match ev {
                Ok(ev) => ev,
                Err(e) => {
                    warn!("garbage collector monitor for {resource}: watch error: {e}");
                    break;
                }
            };
            match ev {
                WatchEvent::Added(_, v) | WatchEvent::Modified(_, v) => {
                    let Some(obj) = decode(&v) else { continue };
                    let old = store.insert(obj.metadata.uid.clone(), obj.clone());
                    emit_upsert(&tx, &gvk, obj, old);
                }
                WatchEvent::Deleted(_, v) => {
                    let Some(prev) = decode(&v) else { continue };
                    store.remove(&prev.metadata.uid);
                    send(&tx, &gvk, GraphEventType::Delete, prev, None);
                }
            }
        }
        tokio::time::sleep(RELIST_BACKOFF).await;
    }
}
