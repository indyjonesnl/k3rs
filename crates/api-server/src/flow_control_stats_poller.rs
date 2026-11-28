//! API Priority and Fairness: the producer of the object-count tracker.
//!
//! Port of `registry/generic/registry/store.go` `Store.startObservingCount`
//! (release-1.35, :1663-1682): every `CountMetricPollPeriod` (1m,
//! `server/options/etcd.go:87`, jitter 1.2 = `resourceCountPollPeriodJitter`,
//! store.go:263) it calls `Storage.Stats` for the resource and, on success,
//! `objectCountTracker.Set(resourceName, stats)`.

use std::sync::Arc;
use std::time::Duration;

use kubernetes_rs_storage::Storage;

use crate::flow_control_object_count::ObjectCountTracker;
use crate::flow_control_work_estimator::Stats;

pub use kubernetes_rs_storage::metrics::OBSERVED_RESOURCES;

/// `schema.GroupResource.String()`, the tracker's key.
fn group_resource(group: &str, resource: &str) -> String {
    if group.is_empty() {
        resource.to_string()
    } else {
        format!("{resource}.{group}")
    }
}

/// One poll of every observed resource (the body of the `JitterUntil`
/// closure, store.go:1668-1678): on a `Stats` error, log and skip; otherwise
/// `Set`.
pub async fn poll_once<S: Storage>(storage: &S, tracker: &ObjectCountTracker) {
    for (group, resource) in OBSERVED_RESOURCES {
        let prefix = kubernetes_rs_storage::build_prefix(resource, None);
        observe(storage, tracker, group, resource, &prefix).await;
    }
    for (group, plural) in registered_custom_resources(storage).await {
        // The storage type of `handlers/custom_resource.rs`.
        let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
        let prefix = kubernetes_rs_storage::build_prefix(&resource_type, None);
        observe(storage, tracker, &group, &plural, &prefix).await;
    }
}

/// The `Stats` call and `Set` of the `JitterUntil` closure, store.go:1668-1678.
async fn observe<S: Storage>(
    storage: &S,
    tracker: &ObjectCountTracker,
    group: &str,
    resource: &str,
    prefix: &str,
) {
    match storage.stats(prefix).await {
        Ok(st) => tracker.set(
            &group_resource(group, resource),
            Stats {
                object_count: st.object_count,
                estimated_average_object_size_bytes: st.estimated_average_object_size_bytes,
            },
        ),
        Err(e) => {
            tracing::debug!(resource, error = %e, "Failed to update storage count metric");
        }
    }
}

/// `(spec.group, spec.names.plural)` of every registered CRD. Upstream gives
/// each CRD version its own `genericregistry.Store`
/// (`apiextensions-apiserver/pkg/apiserver/customresource_handler.go:855`
/// `customresource.NewStorage`), and every Store starts its own observer
/// (`store.go:1638` `startObservingCount`), so custom
/// resources are counted exactly like built-ins. This server has no store
/// registry; the registered CRDs are read each poll, which also stops
/// observing a CRD once it is deleted (upstream's `destroy`).
async fn registered_custom_resources<S: Storage>(storage: &S) -> Vec<(String, String)> {
    let prefix = kubernetes_rs_storage::build_prefix("customresourcedefinitions", None);
    let crds: Vec<serde_json::Value> = match storage.list(&prefix).await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, "Failed to list CRDs for the object count poller");
            return Vec::new();
        }
    };
    crds.iter()
        .filter_map(|crd| {
            let group = crd.pointer("/spec/group")?.as_str()?;
            let plural = crd.pointer("/spec/names/plural")?.as_str()?;
            Some((group.to_string(), plural.to_string()))
        })
        .collect()
}

/// `CountMetricPollPeriod` default (server/options/etcd.go:87).
pub const COUNT_METRIC_POLL_PERIOD: Duration = Duration::from_secs(60);

/// `resourceCountPollPeriodJitter` (store.go:263).
const RESOURCE_COUNT_POLL_PERIOD_JITTER: f64 = 1.2;

/// `wait.JitterUntil(f, period, 1.2, sliding=true, stopCh)` (store.go:263):
/// runs `f` immediately, then after `period + rand*1.2*period`, until stopped.
pub async fn run<S: Storage>(
    storage: Arc<S>,
    tracker: Arc<ObjectCountTracker>,
    period: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let stopped = async move {
        loop {
            if *stop.borrow() || stop.changed().await.is_err() {
                return;
            }
        }
    };
    kubernetes_rs_common::wait::jitter_until(
        || poll_once(storage.as_ref(), &tracker),
        period,
        RESOURCE_COUNT_POLL_PERIOD_JITTER,
        true,
        stopped,
    )
    .await
}
