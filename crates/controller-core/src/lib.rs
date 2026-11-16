//! Controllers shared between the kube-apiserver and the controller-manager.
//!
//! Upstream runs the aggregator's APIService availability controller and the
//! ClusterRole aggregation controller inside kube-apiserver (post-start hooks),
//! and the controller-manager hosts the rest. They live in this small crate so
//! the api-server does not have to depend on (and recompile with) the whole
//! controller-manager. `k3rs-controller-manager` re-exports these
//! modules at their original `controllers::*` paths.

pub mod apiservice;
pub mod clusterrole_aggregation;
pub mod worker_pool;

/// `MinResyncPeriod`, the floor of the informers' resync
/// (`staging/src/k8s.io/controller-manager/config/v1alpha1/defaults.go:31-33`:
/// 12h).
pub const INFORMER_RESYNC_PERIOD: std::time::Duration = std::time::Duration::from_secs(12 * 3600);

/// Port of `ResyncPeriod` (`cmd/kube-controller-manager/app/controllermanager.go:176-181`):
/// `MinResyncPeriod * (rand.Float64() + 1)`, so controllers do not resync in
/// lock-step. Drawn once per informer start, as upstream calls the returned
/// function once per informer.
pub fn resync_period() -> std::time::Duration {
    use rand::Rng;
    INFORMER_RESYNC_PERIOD.mul_f64(rand::rng().random::<f64>() + 1.0)
}
