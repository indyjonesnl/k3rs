//! Storage version migrator: shared pieces (slice 1 of #3825).
//!
//! Port of `pkg/controller/storageversionmigrator` (release-1.35):
//! `util.go` (`setStatusConditions`) and the verb check of
//! `resourceversion.go` (`isResourceMigratable`, `verbsRequiredForMigration`).
//! The two controllers (`ResourceVersionController`, `SVMController`) that use
//! them live in `storage_version_migrator_rv.rs` / `_svm.rs`; this module also
//! holds their launcher, [`feature_enabled`] and [`run_controllers`]
//! (`newSVMController`, `cmd/kube-controller-manager/app/storageversionmigrator.go:33-110`).

use anyhow::Result;
use chrono::Utc;
use kubernetes_rs_common::resources::storageversionmigration::{
    StorageVersionMigration, MIGRATION_FAILED, MIGRATION_RUNNING, MIGRATION_SUCCEEDED,
};
use kubernetes_rs_common::types::Condition;

/// `storageversionmigrator.go:46`: `migrationSuccessStatusReason`.
pub const MIGRATION_SUCCESS_STATUS_REASON: &str = "StorageVersionMigrationSucceeded";
/// `migrationRunningStatusReason`.
pub const MIGRATION_RUNNING_STATUS_REASON: &str = "StorageVersionMigrationInProgress";
/// `migrationFailedStatusReason`.
pub const MIGRATION_FAILED_STATUS_REASON: &str = "StorageVersionMigrationFailed";

/// `verbsRequiredForMigration` (`resourceversion.go:51`).
pub const VERBS_REQUIRED_FOR_MIGRATION: [&str; 3] = ["update", "patch", "list"];

/// `isResourceMigratable`'s verb test (`resourceversion.go:313-316`):
/// `sets.NewString(resource.Verbs...).HasAll(verbsRequiredForMigration...)`.
pub fn has_required_verbs(verbs: &[String]) -> bool {
    VERBS_REQUIRED_FOR_MIGRATION
        .iter()
        .all(|required| verbs.iter().any(|v| v == required))
}

fn is_status_condition_set(svm: &StorageVersionMigration, condition_type: &str) -> bool {
    // meta.IsStatusConditionTrue || meta.IsStatusConditionFalse
    svm.status
        .conditions
        .iter()
        .any(|c| c.condition_type == condition_type && (c.status == "True" || c.status == "False"))
}

/// `setStatusConditions` (`util.go:29-58`).
pub fn set_status_conditions(
    svm: &mut StorageVersionMigration,
    condition_type: &str,
    reason: &str,
    message: &str,
) {
    // Cannot set the condition twice.
    if is_status_condition_set(svm, condition_type) {
        return;
    }

    if condition_type == MIGRATION_SUCCEEDED || condition_type == MIGRATION_FAILED {
        // set running condition to false if we're finished
        if let Some(running) = svm
            .status
            .conditions
            .iter_mut()
            .find(|c| c.condition_type == MIGRATION_RUNNING)
        {
            running.status = "False".to_string();
        }
    }

    svm.status.conditions.push(Condition {
        condition_type: condition_type.to_string(),
        status: "True".to_string(),
        observed_generation: None,
        last_transition_time: Some(Utc::now()),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
    });
}

/// `names.StorageVersionMigratorController`
/// (`cmd/kube-controller-manager/names/controller_names.go:89`); the name the
/// api-server's bootstrap policy seeds a role and binding for.
pub const CONTROLLER_NAME: &str = "storage-version-migrator-controller";

/// The launcher's gate (`newSVMController`, storageversionmigrator.go:42-44):
/// `StorageVersionMigrator` (Beta, off by default in 1.35) and client-go's
/// `InformerResourceVersion` (GA, always on in 1.35).
///
/// Not modelled, because they cannot be unmet here:
/// - `InOrderInformers` (storageversionmigrator.go:51-54, Beta, default on):
///   the informers are storage watches, which deliver in order.
/// - "requires garbage collector" (:46-48): the garbage collector is always
///   started alongside this controller (`spawn_controllers` and the standalone
///   binary both start it unconditionally).
pub fn feature_enabled() -> bool {
    kubernetes_rs_common::feature_gates::enabled(
        kubernetes_rs_common::feature_gates::Feature::StorageVersionMigrator,
    )
}

/// `concurrentRun(svm.NewSVMController(..).Run, svm.NewResourceVersionController(..).Run)`
/// (storageversionmigrator.go:90-109): both controllers run together; this
/// returns as soon as either stops.
///
/// Deviation: upstream builds a dedicated client with `QPS *= 20` and
/// `Burst *= 100` (:57-60, "svm controller can make a lot of requests during
/// migration, keep it fast"). Every `storage_for` handle the caller passes in
/// is that controller's own client, so the caller chooses the rate limit.
pub async fn run_controllers<S: kubernetes_rs_storage::Storage + 'static>(
    storage: std::sync::Arc<S>,
) -> Result<()> {
    let svm = std::sync::Arc::new(super::storage_version_migrator_svm::SvmController::new(
        storage.clone(),
        CONTROLLER_NAME,
    ));
    let rv = std::sync::Arc::new(
        super::storage_version_migrator_rv::ResourceVersionController::new(storage),
    );
    tokio::try_join!(svm.run(), rv.run())?;
    Ok(())
}
