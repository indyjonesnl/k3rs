//! Router-level pin of `WithCacheControl` (filters/cachecontrol.go:25-35) next
//! to the aggregated-discovery handler (discovery/aggregated/handler.go
//! `ServeHTTP`, etag.go `ServeHTTPWithETag`): aggregated discovery keeps the
//! handler's `Cache-Control: public` + `ETag` + `Vary: Accept` and answers 304,
//! while every response without a `Cache-Control` of its own gets the default
//! `no-cache, private`.
use axum::http::StatusCode;
use kubernetes_rs_test_support::harness::TestApiServer;

const AGG: &str = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList";

#[tokio::test]
async fn discovery_etag_apply_aggregated_api_keeps_public_etag_vary() {
    let api = TestApiServer::new();
    let (status, h, _, _) = api
        .send_with_headers("GET", "/api", &[("accept", AGG)], None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h["cache-control"], "public");
    assert_eq!(h["vary"], "Accept");
    let etag = h["etag"].to_str().unwrap().to_string();
    assert!(etag.starts_with('"') && etag.ends_with('"'));

    let (status, h, body, _) = api
        .send_with_headers(
            "GET",
            "/api",
            &[("accept", AGG), ("if-none-match", &etag)],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_eq!(h["etag"].to_str().unwrap(), etag);
    assert_eq!(h["cache-control"], "public");
    assert!(body.is_empty());
}

#[tokio::test]
async fn discovery_etag_apply_aggregated_apis_keeps_public_etag_vary() {
    let api = TestApiServer::new();
    let (status, h, _, _) = api
        .send_with_headers("GET", "/apis", &[("accept", AGG)], None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h["cache-control"], "public");
    assert_eq!(h["vary"], "Accept");
    assert!(h.contains_key("etag"));
}

#[tokio::test]
async fn discovery_etag_apply_plain_discovery_is_no_cache_private() {
    let api = TestApiServer::new();
    for path in ["/api", "/apis", "/api/v1"] {
        let (status, h, _, _) = api.send_with_headers("GET", path, &[], None).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(h["cache-control"], "no-cache, private", "{path}");
        assert!(!h.contains_key("etag"), "{path}");
    }
}
