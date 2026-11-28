//! Port of `staging/src/k8s.io/apiserver/pkg/cel/metrics/metrics_test.go`
//! (`TestObserveCompilation`, `TestObserveEvaluation`). The shared registry
//! cannot be reset, so the tests compare before/after.

use kubernetes_rs_common::cel_metrics::{observe_compilation, observe_evaluation};
use std::time::Duration;

fn gather(name: &str) -> (u64, f64) {
    let families = prometheus::default_registry().gather();
    let mf = families
        .iter()
        .find(|f| f.name() == name)
        .unwrap_or_else(|| panic!("metric not found: {name}"));
    mf.get_metric().iter().fold((0, 0.0), |(c, s), m| {
        let h = m.get_histogram();
        (c + h.get_sample_count(), s + h.get_sample_sum())
    })
}

#[test]
fn cel_metrics_observe_compilation() {
    observe_compilation(Duration::ZERO); // registers the collector
    let (c0, s0) = gather("apiserver_cel_compilation_duration_seconds");
    observe_compilation(Duration::from_secs(2));
    let (c1, s1) = gather("apiserver_cel_compilation_duration_seconds");
    assert_eq!(c1 - c0, 1);
    assert!(((s1 - s0) - 2.0).abs() < 1e-7);
}

#[test]
fn cel_metrics_observe_evaluation() {
    observe_evaluation(Duration::ZERO);
    let (c0, s0) = gather("apiserver_cel_evaluation_duration_seconds");
    observe_evaluation(Duration::from_secs(2));
    let (c1, s1) = gather("apiserver_cel_evaluation_duration_seconds");
    assert_eq!(c1 - c0, 1);
    assert!(((s1 - s0) - 2.0).abs() < 1e-7);
}
