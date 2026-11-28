//! `DefaultBuildHandlerChain` wraps authentication, audit, priority-and-fairness
//! and authorization in `filterlatency.TrackStarted` / `TrackCompleted`
//! (staging/src/k8s.io/apiserver/pkg/server/config.go:1015-1057), so a served
//! request observes `apiserver_request_filter_duration_seconds` per filter.

use kubernetes_rs_test_support::harness::TestApiServer;

fn samples(filter: &str) -> u64 {
    prometheus::gather()
        .iter()
        .filter(|f| f.name() == "apiserver_request_filter_duration_seconds")
        .flat_map(|f| f.get_metric().iter())
        .filter(|m| {
            m.get_label()
                .iter()
                .any(|l| l.name() == "filter" && l.value() == filter)
        })
        .map(|m| m.get_histogram().get_sample_count())
        .sum()
}

#[tokio::test]
async fn filter_latency_router_observes_each_filter() {
    let before: Vec<u64> = ["authentication", "audit", "authorization"]
        .iter()
        .map(|f| samples(f))
        .collect();
    let state = TestApiServer::new();
    let (status, _) = state.get("/api/v1/namespaces").await;
    assert!(status.is_success(), "{status}");
    for (i, f) in ["authentication", "audit", "authorization"]
        .iter()
        .enumerate()
    {
        assert!(
            samples(f) > before[i],
            "no apiserver_request_filter_duration_seconds sample for filter {f}"
        );
    }
}
