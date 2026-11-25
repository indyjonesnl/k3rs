//! TTL controller.
//!
//! Ported from `pkg/controller/ttl/ttl_controller.go` (release-1.35), launched
//! like `newTTLController` (`cmd/kube-controller-manager/app/core.go:713-736`:
//! name `ttl-controller`, alias `ttl`, `ttlc.Run(ctx, 5)`).
//!
//! The controller sets the `node.alpha.kubernetes.io/ttl` annotation
//! (`v1.ObjectTTLAnnotationKey`) on every Node. Kubelets use it as a hint for
//! how long they may cache objects (Secrets, ConfigMaps) before re-reading
//! them. The desired value grows with the cluster size, in steps with
//! hysteresis ([`TTL_BOUNDARIES`]).
//!
//! Ported 1:1:
//! - the `ttlBoundaries` table and the `boundaryStep` walk in `addNode` /
//!   `deleteNode` (one step per event, as upstream);
//! - every Node add and update enqueues the Node ("processing all updates of
//!   nodes guarantees that we will update the ttl annotation, when cluster size
//!   changes"); a delete only adjusts the count;
//! - `updateNodeIfNeeded`: read the Node from the lister, skip it when the
//!   annotation already parses to the desired value, otherwise PATCH just the
//!   annotation (`patchNodeWithAnnotation`, a strategic merge patch computed
//!   from the old and new object, so only `metadata.annotations` is sent);
//! - an annotation that does not parse as an integer counts as absent;
//! - `processItem`: error -> `AddRateLimited`, success -> `Forget`; a missing
//!   Node is not an error.
//!
//! Deviations:
//! - The initial list is accounted for after the cache syncs (the reflector emits
//!   no events for it): the Nodes are counted from the store, `boundaryStep` is
//!   re-derived from the count, and every Node is enqueued.
//! - A lagged informer subscription recounts the Nodes from the store and
//!   re-derives `boundaryStep` from the count (smallest step whose `sizeMax`
//!   holds it), then re-enqueues every Node, instead of losing events. Upstream's
//!   informer never drops events.

use crate::controllers::storage_list_watch::StorageListWatch;
use crate::controllers::worker_pool::spawn_workers;
use anyhow::Result;
use kubernetes_rs_client::reflector::{Reflector, StoreEvent};
use kubernetes_rs_common::resources::Node;
use kubernetes_rs_common::Error;
use kubernetes_rs_storage::{build_key, build_prefix, Storage, WorkQueue};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, error, info, warn};

/// Workers draining the queue (`ttlc.Run(ctx, 5)`, core.go:733).
pub const WORKERS: usize = 5;

/// Queue name (`TypedRateLimitingQueueConfig{Name: "ttlcontroller"}`).
pub const QUEUE_NAME: &str = "ttlcontroller";

/// `v1.ObjectTTLAnnotationKey` (staging/src/k8s.io/api/core/v1/annotation_key_constants.go).
pub const OBJECT_TTL_ANNOTATION_KEY: &str = "node.alpha.kubernetes.io/ttl";

/// `ttlBoundary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlBoundary {
    pub size_min: i64,
    pub size_max: i64,
    pub ttl_seconds: i64,
}

/// `ttlBoundaries`: the ranges of cluster size and the TTL used within each.
/// Neighbouring ranges overlap so the TTL does not flap around a boundary.
pub const TTL_BOUNDARIES: [TtlBoundary; 5] = [
    TtlBoundary {
        size_min: 0,
        size_max: 100,
        ttl_seconds: 0,
    },
    TtlBoundary {
        size_min: 90,
        size_max: 500,
        ttl_seconds: 15,
    },
    TtlBoundary {
        size_min: 450,
        size_max: 1000,
        ttl_seconds: 30,
    },
    TtlBoundary {
        size_min: 900,
        size_max: 2000,
        ttl_seconds: 60,
    },
    TtlBoundary {
        size_min: 1800,
        size_max: i32::MAX as i64,
        ttl_seconds: 300,
    },
];

/// The mutable state guarded by `ttlc.lock`.
#[derive(Debug, Default)]
struct Sizing {
    /// `nodeCount`: number of nodes in the cluster.
    node_count: i64,
    /// `desiredTTLSeconds`: desired TTL for all nodes in the cluster.
    desired_ttl_seconds: i64,
    /// `boundaryStep`: in which interval of cluster size we currently are.
    boundary_step: usize,
}

fn node_key(n: &Node) -> String {
    n.metadata.name.clone()
}

type NodeReflector = Reflector<Node, fn(&Node) -> String>;

/// `Controller`.
pub struct TtlController<S: Storage> {
    storage: Arc<S>,
    /// `nodeInformer` (`nodeStore` reads its store).
    nodes: Arc<NodeReflector>,
    /// `queue`: Nodes that need to be synced.
    queue: WorkQueue,
    sizing: Mutex<Sizing>,
}

impl<S: Storage + 'static> TtlController<S> {
    /// `NewTTLController`.
    pub fn new(storage: Arc<S>) -> Self {
        let lw = StorageListWatch::<S, Node>::new(storage.clone(), build_prefix("nodes", None));
        Self {
            storage,
            nodes: Arc::new(Reflector::new(
                Arc::new(lw),
                node_key as fn(&Node) -> String,
            )),
            queue: WorkQueue::named(QUEUE_NAME),
            sizing: Mutex::new(Sizing::default()),
        }
    }

    /// Set `nodeCount`, `desiredTTLSeconds` and `boundaryStep` directly, as
    /// upstream's tests build a `Controller` literal; tests only.
    pub fn with_sizing(
        self,
        node_count: i64,
        desired_ttl_seconds: i64,
        boundary_step: usize,
    ) -> Self {
        *self.sizing.lock().expect("sizing lock") = Sizing {
            node_count,
            desired_ttl_seconds,
            boundary_step,
        };
        self
    }

    /// The controller's work queue (shared with tests).
    pub fn queue(&self) -> &WorkQueue {
        &self.queue
    }

    /// `getDesiredTTLSeconds`.
    pub fn desired_ttl_seconds(&self) -> i64 {
        self.sizing.lock().expect("sizing lock").desired_ttl_seconds
    }

    /// The current `(nodeCount, boundaryStep)` (tests).
    pub fn sizing(&self) -> (i64, usize) {
        let s = self.sizing.lock().expect("sizing lock");
        (s.node_count, s.boundary_step)
    }

    /// `addNode`'s count/step update.
    fn count_added(&self) {
        let mut s = self.sizing.lock().expect("sizing lock");
        s.node_count += 1;
        if s.node_count > TTL_BOUNDARIES[s.boundary_step].size_max {
            s.boundary_step += 1;
            s.desired_ttl_seconds = TTL_BOUNDARIES[s.boundary_step].ttl_seconds;
        }
    }

    /// `deleteNode`'s count/step update.
    fn count_deleted(&self) {
        let mut s = self.sizing.lock().expect("sizing lock");
        s.node_count -= 1;
        if s.node_count < TTL_BOUNDARIES[s.boundary_step].size_min {
            s.boundary_step -= 1;
            s.desired_ttl_seconds = TTL_BOUNDARIES[s.boundary_step].ttl_seconds;
        }
    }

    /// Recount from the store after a lagged subscription (see the module
    /// deviation note).
    fn recount(&self) {
        let count = self.nodes.store().items().len() as i64;
        let mut s = self.sizing.lock().expect("sizing lock");
        s.node_count = count;
        let mut step = 0;
        while step + 1 < TTL_BOUNDARIES.len() && count > TTL_BOUNDARIES[step].size_max {
            step += 1;
        }
        s.boundary_step = step;
        s.desired_ttl_seconds = TTL_BOUNDARIES[step].ttl_seconds;
    }

    /// The informer's `AddFunc` / `UpdateFunc` / `DeleteFunc`.
    pub async fn on_node_event(&self, event: &StoreEvent<Node>) {
        match event {
            StoreEvent::Added(node) => {
                self.count_added();
                self.enqueue(node).await;
            }
            // Processing all updates of nodes guarantees that we will update
            // the ttl annotation when cluster size changes.
            StoreEvent::Modified(node) => self.enqueue(node).await,
            // The Node is not processed: it no longer exists.
            StoreEvent::Deleted(_) => self.count_deleted(),
        }
    }

    async fn enqueue(&self, node: &Node) {
        self.queue.add(node_key(node)).await;
    }

    async fn enqueue_all(&self) {
        for node in self.nodes.store().items() {
            self.enqueue(&node).await;
        }
    }

    /// Start the informer and its event handler. The subscription is taken
    /// before the reflector runs so no event is missed.
    pub fn start_informer(self: &Arc<Self>) {
        let mut rx = self.nodes.subscribe();
        let r = self.nodes.clone();
        tokio::spawn(async move { r.run().await });
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => this.on_node_event(&ev).await,
                    Err(RecvError::Lagged(n)) => {
                        warn!("ttl-controller Node events lagged {n}; resyncing");
                        this.recount();
                        this.enqueue_all().await;
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });
    }

    /// `Run`: start the informer, wait for its cache to sync, then run
    /// `workers` workers over the one queue.
    pub async fn run_with_workers(self: Arc<Self>, workers: usize) -> Result<()> {
        info!("Starting TTL controller");
        self.start_informer();
        // `WaitForNamedCacheSyncWithContext(hasSynced)`.
        self.nodes.wait_for_cache_sync().await;
        // The reflector does not emit events for the initial list, which an
        // upstream informer delivers as `AddFunc` calls: count and enqueue
        // those Nodes here.
        self.recount();
        self.enqueue_all().await;

        spawn_workers(workers, &self.queue, {
            let this = Arc::clone(&self);
            move |_queue| {
                let this = Arc::clone(&this);
                async move { while this.process_item().await {} }
            }
        });
        // `<-ctx.Done()`: the workers run until the queue is shut down.
        std::future::pending::<()>().await;
        info!("Shutting down TTL controller");
        Ok(())
    }

    /// `Run` with the launcher's 5 workers.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        self.run_with_workers(WORKERS).await
    }

    /// `processItem`: `false` when the queue is shut down.
    pub async fn process_item(&self) -> bool {
        let Some(key) = self.queue.get().await else {
            return false;
        };
        match self.update_node_if_needed(&key).await {
            Ok(()) => self.queue.forget(&key).await,
            Err(e) => {
                error!("error syncing node TTL for {key}, will retry: {e}");
                self.queue.requeue_rate_limited(key.clone()).await;
            }
        }
        self.queue.done(&key).await;
        true
    }

    /// `updateNodeIfNeeded`.
    pub async fn update_node_if_needed(&self, key: &str) -> Result<(), Error> {
        // A Node that is gone from the lister is not an error.
        let Some(node) = self.nodes.store().get(key) else {
            return Ok(());
        };
        let desired = self.desired_ttl_seconds();
        if let Some(current) = int_from_annotation(&node, OBJECT_TTL_ANNOTATION_KEY) {
            if current == desired {
                return Ok(());
            }
        }
        self.patch_node_with_annotation(&node, OBJECT_TTL_ANNOTATION_KEY, desired)
            .await
    }

    /// `patchNodeWithAnnotation`: a strategic merge patch that only sets the
    /// one annotation (what `CreateTwoWayMergePatch(old, new)` yields).
    async fn patch_node_with_annotation(
        &self,
        node: &Node,
        annotation_key: &str,
        value: i64,
    ) -> Result<(), Error> {
        let patch = serde_json::json!({
            "metadata": { "annotations": { annotation_key: value.to_string() } }
        });
        let storage_key = build_key("nodes", None, &node.metadata.name);
        match self
            .storage
            .patch_strategic_merge::<Node>(&storage_key, &patch)
            .await
        {
            Ok(_) => {
                debug!(
                    "Changed ttl annotation node={} TTL={value}s",
                    node.metadata.name
                );
                Ok(())
            }
            Err(e) => {
                debug!(
                    "Failed to change ttl annotation for node node={} err={e}",
                    node.metadata.name
                );
                Err(e)
            }
        }
    }
}

/// `getIntFromAnnotation`: the annotation parsed with `strconv.Atoi`; absent or
/// unparsable is `None`.
pub fn int_from_annotation(node: &Node, annotation_key: &str) -> Option<i64> {
    let value = node.metadata.annotations.as_ref()?.get(annotation_key)?;
    match value.parse::<i64>() {
        Ok(v) => Some(v),
        Err(_) => {
            info!(
                "Could not convert the value with annotation key for the node annotationValue={value} annotationKey={annotation_key} node={}",
                node.metadata.name
            );
            None
        }
    }
}
