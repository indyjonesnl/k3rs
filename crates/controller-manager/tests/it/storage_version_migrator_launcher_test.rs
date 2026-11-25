//! The launcher of the storage version migrator: `newSVMController`
//! (`cmd/kube-controller-manager/app/storageversionmigrator.go:33-110`).
//! Upstream has no unit test for the launcher itself; these pin its two
//! observable properties: it is registered only with the `StorageVersionMigrator`
//! gate on (`:42-44`), and it runs both controllers (`concurrentRun`, `:90-109`).

use kubernetes_rs_common::feature_gates::{with_feature, Feature};
use kubernetes_rs_common::resources::storageversionmigration::StorageVersionMigration;
use kubernetes_rs_controller_manager::controllers::storage_version_migrator::{
    feature_enabled, run_controllers,
};
use kubernetes_rs_storage::{build_key, memory::MemoryStorage, Storage};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

const PLURAL: &str = "storageversionmigrations";

/// `utilfeature.DefaultFeatureGate.Enabled(features.StorageVersionMigrator)`.
#[test]
fn registered_only_with_the_storage_version_migrator_gate() {
    {
        let _g = with_feature(Feature::StorageVersionMigrator, false);
        assert!(!feature_enabled());
    }
    {
        let _g = with_feature(Feature::StorageVersionMigrator, true);
        assert!(feature_enabled());
    }
}

/// Both controllers are started: the resource-version controller stamps
/// `status.resourceVersion` on a new migration (the SVM controller then waits
/// on that value).
#[tokio::test]
async fn runs_the_resource_version_controller_and_the_svm_controller() {
    let storage = Arc::new(MemoryStorage::new());
    storage
        .create(
            &build_key("customresourcedefinitions", None, "widgets.example.com"),
            &json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": {"name": "widgets.example.com"},
                "spec": {
                    "group": "example.com",
                    "scope": "Cluster",
                    "names": {"plural": "widgets", "singular": "widget", "kind": "Widget"},
                    "versions": [{"name": "v1", "served": true, "storage": true}],
                },
                "status": {"conditions": [{"type": "Established", "status": "True"}]},
            }),
        )
        .await
        .unwrap();
    storage
        .create(
            &build_key(PLURAL, None, "widgets"),
            &json!({
                "apiVersion": "storagemigration.k8s.io/v1beta1",
                "kind": "StorageVersionMigration",
                "metadata": {
                    "name": "widgets", "uid": "uid-widgets",
                    "creationTimestamp": chrono::Utc::now().to_rfc3339(),
                },
                "spec": {"resource": {"group": "example.com", "version": "v1", "resource": "widgets"}},
                "status": {"resourceVersion": "", "conditions": []},
            }),
        )
        .await
        .unwrap();

    let h = tokio::spawn(run_controllers(storage.clone()));
    let mut stamped = false;
    for _ in 0..100 {
        let s: StorageVersionMigration = storage
            .get(&build_key(PLURAL, None, "widgets"))
            .await
            .unwrap();
        if !s.status.resource_version.is_empty() {
            stamped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    h.abort();
    assert!(stamped, "the resource-version controller never ran");
}
