//! The EndpointSlice mirroring pass must surface failures so the key is
//! retried, as the upstream controller does.
//!
//! Upstream: `syncEndpoints` returns the error of `reconciler.reconcile`
//! (pkg/controller/endpointslicemirroring/endpointslicemirroring_controller.go:
//! 288-351), `finalize` returns create/update failures (reconciler.go:240-284)
//! and `handleErr` re-queues with `AddRateLimited` up to `maxRetries` = 15
//! (:271-286). Only NotFound on the Endpoints lister means "deleted" (:303-311).
//!
//! kubernetes-rs has no periodic resync (12h), so a swallowed error means the mirrored
//! slice is never created: conformance `EndpointSliceMirroring should mirror a
//! custom Endpoints resource` polls for 12s and fails.

use kubernetes_rs_common::resources::endpointslice::EndpointSlice;
use kubernetes_rs_common::resources::{Endpoints, Service};
use kubernetes_rs_controller_manager::controllers::endpointslice::EndpointSliceController;
use kubernetes_rs_storage::{build_key, build_prefix, memory::MemoryStorage, Storage, WatchStream};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// `MemoryStorage` that fails the first `create_failures` EndpointSlice
/// creates and the first `endpoints_get_failures` Endpoints GETs with a
/// transient (non-NotFound) error.
struct FlakyStorage {
    inner: MemoryStorage,
    create_failures: AtomicUsize,
    endpoints_get_failures: AtomicUsize,
}

impl FlakyStorage {
    fn new(create_failures: usize, endpoints_get_failures: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryStorage::new(),
            create_failures: AtomicUsize::new(create_failures),
            endpoints_get_failures: AtomicUsize::new(endpoints_get_failures),
        })
    }
}

fn take(counter: &AtomicUsize) -> bool {
    counter
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok()
}

#[async_trait::async_trait]
impl Storage for FlakyStorage {
    async fn create<T>(&self, key: &str, value: &T) -> kubernetes_rs_common::Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
    {
        if key.starts_with("/registry/endpointslices/") && take(&self.create_failures) {
            return Err(kubernetes_rs_common::Error::Storage("transient".into()));
        }
        self.inner.create(key, value).await
    }

    async fn get<T>(&self, key: &str) -> kubernetes_rs_common::Result<T>
    where
        T: serde::de::DeserializeOwned + Send + Sync,
    {
        if key.starts_with("/registry/endpoints/") && take(&self.endpoints_get_failures) {
            return Err(kubernetes_rs_common::Error::Storage("transient".into()));
        }
        self.inner.get(key).await
    }

    async fn update<T>(&self, key: &str, value: &T) -> kubernetes_rs_common::Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
    {
        self.inner.update(key, value).await
    }

    async fn update_raw(&self, key: &str, value: &Value) -> kubernetes_rs_common::Result<()> {
        self.inner.update_raw(key, value).await
    }

    async fn list<T>(&self, prefix: &str) -> kubernetes_rs_common::Result<Vec<T>>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
    {
        self.inner.list(prefix).await
    }

    async fn delete(&self, key: &str) -> kubernetes_rs_common::Result<()> {
        self.inner.delete(key).await
    }

    async fn watch(&self, prefix: &str) -> kubernetes_rs_common::Result<WatchStream> {
        self.inner.watch(prefix).await
    }

    async fn watch_from_revision(
        &self,
        prefix: &str,
        revision: i64,
    ) -> kubernetes_rs_common::Result<WatchStream> {
        self.inner.watch_from_revision(prefix, revision).await
    }

    async fn current_revision(&self) -> kubernetes_rs_common::Result<i64> {
        self.inner.current_revision().await
    }

    async fn is_revision_compacted(&self, revision: i64) -> kubernetes_rs_common::Result<bool> {
        self.inner.is_revision_compacted(revision).await
    }
}

async fn seed(storage: &FlakyStorage) {
    let svc: Service = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "custom", "namespace": "ns"},
        "spec": {"ports": [{"name": "example", "port": 80, "protocol": "TCP"}]}
    }))
    .unwrap();
    storage
        .inner
        .create(&build_key("services", Some("ns"), "custom"), &svc)
        .await
        .unwrap();
    let ep: Endpoints = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Endpoints",
        "metadata": {"name": "custom", "namespace": "ns"},
        "subsets": [{"addresses": [{"ip": "10.1.2.3"}], "ports": [{"port": 80}]}]
    }))
    .unwrap();
    storage
        .inner
        .create(&build_key("endpoints", Some("ns"), "custom"), &ep)
        .await
        .unwrap();
}

async fn slices(storage: &FlakyStorage) -> Vec<EndpointSlice> {
    storage
        .inner
        .list(&build_prefix("endpointslices", Some("ns")))
        .await
        .unwrap()
}

#[tokio::test]
async fn failed_slice_create_is_reported_so_the_key_is_retried() {
    let storage = FlakyStorage::new(1, 0);
    seed(&storage).await;
    let controller = EndpointSliceController::new(Arc::clone(&storage));

    assert!(
        controller.mirror_endpoint("ns", "custom").await.is_err(),
        "a failed create must fail the sync (finalize, reconciler.go:258)"
    );
    assert!(slices(&storage).await.is_empty());

    // The re-queued key succeeds once the backend recovers.
    controller.mirror_endpoint("ns", "custom").await.unwrap();
    assert_eq!(slices(&storage).await.len(), 1);
}

#[tokio::test]
async fn transient_endpoints_get_error_is_not_treated_as_deletion() {
    let storage = FlakyStorage::new(0, 1);
    seed(&storage).await;
    let controller = EndpointSliceController::new(Arc::clone(&storage));

    assert!(
        controller.mirror_endpoint("ns", "custom").await.is_err(),
        "only NotFound is a deletion (syncEndpoints, controller.go:303-311)"
    );
    controller.mirror_endpoint("ns", "custom").await.unwrap();
    assert_eq!(slices(&storage).await.len(), 1);
}
