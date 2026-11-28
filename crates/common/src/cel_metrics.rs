//! CEL compilation / evaluation duration metrics.
//!
//! Port of `staging/src/k8s.io/apiserver/pkg/cel/metrics/metrics.go`
//! (`newCelMetrics` :43-52, `ObserveCompilation`, `ObserveEvaluation`):
//! `apiserver_cel_compilation_duration_seconds` and
//! `apiserver_cel_evaluation_duration_seconds`, both BETA histograms with the
//! default buckets, registered in the process-wide registry
//! (`legacyregistry` upstream).

use prometheus::{register, Histogram, HistogramOpts};
use std::sync::LazyLock;
use std::time::Duration;

fn histogram(name: &str, help: &str) -> Histogram {
    let h = Histogram::with_opts(HistogramOpts::new(name, help)).expect("valid metric");
    let _ = register(Box::new(h.clone()));
    h
}

static COMPILATION_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    histogram(
        "apiserver_cel_compilation_duration_seconds",
        "[BETA] CEL compilation time in seconds.",
    )
});

static EVALUATION_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    histogram(
        "apiserver_cel_evaluation_duration_seconds",
        "[BETA] CEL evaluation time in seconds.",
    )
});

/// `CelMetrics.ObserveCompilation`: record a CEL compilation and how long it took.
pub fn observe_compilation(elapsed: Duration) {
    COMPILATION_TIME.observe(elapsed.as_secs_f64());
}

/// `CelMetrics.ObserveEvaluation`: record a CEL evaluation and how long it took.
pub fn observe_evaluation(elapsed: Duration) {
    EVALUATION_TIME.observe(elapsed.as_secs_f64());
}
