//! `scheduler_cache_size` recorded by `cacheImpl.updateMetrics`
//! (`pkg/scheduler/backend/cache/cache.go:743,765-770`, release-1.35).

use std::time::{Duration, Instant};

use kubernetes_rs_common::resources::{Pod, PodSpec};
use kubernetes_rs_scheduler::cache::SchedulerCache;
use kubernetes_rs_scheduler::metrics::metrics;

fn pod(name: &str) -> Pod {
    let mut p = Pod::new(
        name,
        PodSpec {
            node_name: Some("n1".to_string()),
            ..Default::default()
        },
    );
    p.metadata.namespace = Some("default".to_string());
    p.metadata.uid = name.to_string();
    p
}

fn size(kind: &str) -> f64 {
    metrics().cache_size.with_label_values(&[kind]).get()
}

#[test]
fn scheduler_metrics_cache_size_reported_by_cleanup() {
    let c = SchedulerCache::new(Duration::from_secs(10));
    let (a, b) = (pod("a"), pod("b"));
    c.assume_pod(&a).unwrap();
    c.add_pod(&b).unwrap();
    // Nothing is recorded until the sweep runs (updateMetrics is deferred in
    // cleanupAssumedPods).
    assert_eq!(size("pods"), 0.0);
    let now = Instant::now();
    c.cleanup_assumed_pods(now);
    assert_eq!(size("pods"), 2.0);
    assert_eq!(size("assumed_pods"), 1.0);

    // The assumed pod expires after its binding finished and the deadline
    // passed; the metrics reflect the state after the removal.
    c.finish_binding_at(&a, now).unwrap();
    c.cleanup_assumed_pods(now + Duration::from_secs(11));
    assert_eq!(size("pods"), 1.0);
    assert_eq!(size("assumed_pods"), 0.0);
}
