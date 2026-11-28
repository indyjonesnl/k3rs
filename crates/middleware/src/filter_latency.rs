//! Per-filter latency tracking: `apiserver_request_filter_duration_seconds`.
//!
//! Port of `staging/src/k8s.io/apiserver/pkg/endpoints/filterlatency/filterlatency.go`
//! (`TrackStarted`, `TrackCompleted`, `requestFilterRecord`,
//! `trackStarted`/`trackCompleted`) and of the metric in
//! `staging/src/k8s.io/apiserver/pkg/endpoints/metrics/metrics.go`
//! (`requestFilterDuration` :232-241, `RecordFilterLatency` :479).
//!
//! Chain filters as upstream's `DefaultBuildHandlerChain` does
//! (`pkg/server/config.go:1015-1057`): a [`track_started`] layer immediately
//! outside the filter `name`, and a [`track_completed`] layer immediately
//! inside it. Not ported: the OpenTelemetry span `tracer.Start(ctx, name)` and
//! the `fl_<name>` httplog key for filters slower than 100ms
//! (`minFilterLatencyToLog`, logged at klog V(3)).

use axum::{extract::Request, middleware::Next, response::Response};
use prometheus::{register, HistogramOpts, HistogramVec};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// `requestFilterRecord`: shared through the request so a later
/// `TrackStarted` re-uses (and overwrites) the record of an earlier one.
#[derive(Debug, Clone)]
pub struct RequestFilterRecord {
    pub name: &'static str,
    pub started_timestamp: Instant,
}

type SharedRecord = Arc<Mutex<RequestFilterRecord>>;

/// `requestFilterDuration`: buckets from metrics.go:237.
static REQUEST_FILTER_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "apiserver_request_filter_duration_seconds",
            "[ALPHA] Request filter latency distribution in seconds, for each filter type",
        )
        .buckets(vec![
            0.0001, 0.0003, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1.0, 5.0, 10.0, 15.0, 30.0,
        ]),
        &["filter"],
    )
    .expect("valid metric");
    let _ = register(Box::new(h.clone()));
    h
});

/// `metrics.RecordFilterLatency`.
pub fn record_filter_latency(name: &str, elapsed: Duration) {
    REQUEST_FILTER_DURATION
        .with_label_values(&[name])
        .observe(elapsed.as_secs_f64());
}

/// `trackStarted`: record when filter `name` started.
pub async fn track_started(name: &'static str, mut req: Request, next: Next) -> Response {
    let now = Instant::now();
    if let Some(fr) = req.extensions().get::<SharedRecord>() {
        let mut fr = fr.lock().unwrap_or_else(|e| e.into_inner());
        fr.name = name;
        fr.started_timestamp = now;
    } else {
        req.extensions_mut()
            .insert::<SharedRecord>(Arc::new(Mutex::new(RequestFilterRecord {
                name,
                started_timestamp: now,
            })));
    }
    next.run(req).await
}

/// `trackCompleted`: the previous filter has just completed; call `action`
/// with its record and the completion time, then run the rest of the chain.
pub async fn track_completed_with(
    action: impl FnOnce(&RequestFilterRecord, Instant),
    req: Request,
    next: Next,
) -> Response {
    let completed_at = Instant::now();
    if let Some(fr) = req.extensions().get::<SharedRecord>() {
        let fr = fr.lock().unwrap_or_else(|e| e.into_inner()).clone();
        action(&fr, completed_at);
    }
    next.run(req).await
}

/// `failedHandler = filterlatency.TrackCompleted(failedHandler)`
/// (server/config.go:1052): a request rejected by the filter that was just
/// started still observes that filter's latency, though the rest of the chain
/// never runs.
pub fn track_failed(req: &Request) {
    let completed_at = Instant::now();
    if let Some(fr) = req.extensions().get::<SharedRecord>() {
        let fr = fr.lock().unwrap_or_else(|e| e.into_inner()).clone();
        record_filter_latency(fr.name, completed_at.duration_since(fr.started_timestamp));
    }
}

/// Finish the `impersonation` filter (`TrackStarted(handler, "impersonation")`
/// ... `TrackCompleted`, server/config.go:1043-1048). Impersonation runs inside
/// the authentication middleware here rather than as its own layer, so its
/// duration since `started` is recorded under `impersonation` and taken out of
/// the enclosing filter's record (`authentication`), which upstream ends before
/// impersonation begins.
pub fn track_impersonation_completed(req: &Request, started: Instant) {
    let elapsed = started.elapsed();
    record_filter_latency("impersonation", elapsed);
    if let Some(fr) = req.extensions().get::<SharedRecord>() {
        let mut fr = fr.lock().unwrap_or_else(|e| e.into_inner());
        fr.started_timestamp += elapsed;
    }
}

/// `TrackCompleted`: observe `apiserver_request_filter_duration_seconds`.
pub async fn track_completed(req: Request, next: Next) -> Response {
    track_completed_with(
        |fr, completed_at| {
            record_filter_latency(fr.name, completed_at.duration_since(fr.started_timestamp))
        },
        req,
        next,
    )
    .await
}
