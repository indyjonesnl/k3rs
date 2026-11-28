//! Port of `filterlatency_test.go` (`TestTrackStartedWithTracerProvider` is
//! tracing-only and not ported; `TestFilterLatencyTrackStartedBefore*`
//! semantics are covered here).

use axum::{body::Body, extract::Request, middleware::from_fn, routing::get, Router};
use kubernetes_rs_middleware::filter_latency::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

fn samples(name: &str) -> u64 {
    prometheus::default_registry()
        .gather()
        .iter()
        .filter(|f| f.name() == "apiserver_request_filter_duration_seconds")
        .flat_map(|f| f.get_metric().to_vec())
        .filter(|m| m.get_label().iter().any(|l| l.value() == name))
        .map(|m| m.get_histogram().get_sample_count())
        .sum()
}

async fn slow() -> &'static str {
    tokio::time::sleep(Duration::from_millis(5)).await;
    "ok"
}

// Chain as DefaultBuildHandlerChain: started(outside) -> filter -> completed(inside).
fn app(name: &'static str) -> Router {
    Router::new()
        .route("/", get(slow))
        .layer(from_fn(track_completed))
        .layer(from_fn(move |r: Request, n| track_started(name, r, n)))
}

#[tokio::test]
async fn filter_latency_records_histogram_per_filter() {
    let before = samples("filter_latency_a");
    let r = app("filter_latency_a")
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(samples("filter_latency_a"), before + 1);
    assert_eq!(samples("filter_latency_unrelated"), 0);
}

#[tokio::test]
async fn filter_latency_completed_without_started_is_noop() {
    let seen = Arc::new(Mutex::new(0));
    let s = seen.clone();
    let app = Router::new()
        .route("/", get(slow))
        .layer(from_fn(move |r: Request, n| {
            let s = s.clone();
            async move { track_completed_with(move |_, _| *s.lock().unwrap() += 1, r, n).await }
        }));
    app.oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), 0);
}

// A second TrackStarted re-uses and overwrites the record: the latency of the
// later filter is measured from its own start.
#[tokio::test]
async fn filter_latency_second_started_overwrites_record() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    let app =
        Router::new()
            .route("/", get(slow))
            .layer(from_fn(move |r: Request, n| {
                let s = s.clone();
                async move {
                    track_completed_with(move |fr, _| s.lock().unwrap().push(fr.name), r, n).await
                }
            }))
            .layer(from_fn(|r: Request, n| track_started("second", r, n)))
            .layer(from_fn(|r: Request, n| track_started("first", r, n)));
    app.oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), vec!["second"]);
}
