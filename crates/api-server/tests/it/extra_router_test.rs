//! `ApiServerConfig.extra_router`: supervisor routes (`/cacerts`, `/ping`,
//! `/v1-k3rs/*`) are merged into the api-server router so they share the
//! listener. They must stay reachable without credentials even when the
//! api-server enforces authentication (`skip_auth: false`), i.e. they sit
//! outside the authn/authz layers `build_router` wraps around its own routes.

use axum::{routing::get, Router};
use k3rs_api_server::{run, ApiServerConfig};
use k3rs_storage::{memory::MemoryStorage, StorageBackend};
use std::sync::Arc;
use std::time::Duration;

async fn start(skip_auth: bool, extra: Option<Router>) -> (String, tokio::task::JoinHandle<()>) {
    start_with(skip_auth, true, extra).await
}

async fn start_with(
    skip_auth: bool,
    anonymous_auth: bool,
    extra: Option<Router>,
) -> (String, tokio::task::JoinHandle<()>) {
    let storage = Arc::new(StorageBackend::Memory(Arc::new(MemoryStorage::new())));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let config = ApiServerConfig {
        bind_address: addr.to_string(),
        skip_auth,
        anonymous_auth,
        extra_router: extra,
        ..ApiServerConfig::default()
    };
    let server = tokio::spawn(async move {
        let _ = run(storage, config).await;
    });
    let base = format!("http://{addr}");
    for _ in 0..200 {
        // Any HTTP answer (with anonymous auth off, /healthz is 401).
        if reqwest::get(format!("{base}/healthz")).await.is_ok() {
            return (base, server);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("api-server did not come up");
}

fn cacerts() -> Router {
    Router::new().route("/cacerts", get(|| async { "pem" }))
}

#[tokio::test]
async fn extra_route_served_with_skip_auth() {
    let (base, server) = start(true, Some(cacerts())).await;
    let r = reqwest::get(format!("{base}/cacerts")).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "pem");
    let r = reqwest::get(format!("{base}/api/v1/namespaces"))
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    server.abort();
}

#[tokio::test]
async fn extra_route_unauthenticated_when_auth_enforced() {
    let (base, server) = start(false, Some(cacerts())).await;
    let r = reqwest::get(format!("{base}/cacerts")).await.unwrap();
    assert_eq!(r.status(), 200, "extra route must bypass authn");
    assert_eq!(r.text().await.unwrap(), "pem");
    // The built-in routes still run the authn layer: a bad bearer token is
    // rejected there, while the same bad token on the extra route is ignored.
    let c = reqwest::Client::new();
    let r = c
        .get(format!("{base}/api/v1/namespaces"))
        .bearer_auth("not-a-valid-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = c
        .get(format!("{base}/cacerts"))
        .bearer_auth("not-a-valid-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    server.abort();
}

/// `k3rs server` runs with `--anonymous-auth=false`: the built-in routes
/// answer an unauthenticated caller 401 (`WithAuthentication`'s
/// `Unauthorized`, staging/src/k8s.io/apiserver/pkg/endpoints/filters/
/// authentication.go), while the supervisor routes merged via `extra_router`
/// stay reachable without credentials (joining agents have none yet; k3s
/// serves `/cacerts` outside the apiserver authn chain,
/// pkg/server/handlers/router.go:69).
#[tokio::test]
async fn extra_route_unauthenticated_when_anonymous_disabled() {
    let (base, server) = start_with(false, false, Some(cacerts())).await;
    let r = reqwest::get(format!("{base}/cacerts")).await.unwrap();
    assert_eq!(r.status(), 200, "extra route must bypass authn");
    assert_eq!(r.text().await.unwrap(), "pem");
    let r = reqwest::get(format!("{base}/api/v1/namespaces"))
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "anonymous API route");
    let r = reqwest::get(format!("{base}/healthz")).await.unwrap();
    assert_eq!(r.status(), 401, "anonymous /healthz");
    server.abort();
}

#[tokio::test]
async fn no_extra_router_leaves_path_unrouted() {
    let (base, server) = start(true, None).await;
    let r = reqwest::get(format!("{base}/cacerts")).await.unwrap();
    assert_eq!(r.status(), 404);
    server.abort();
}

/// Overlapping an existing route is not special-cased: axum's `merge` panics,
/// and `run` surfaces that as a panic rather than silently shadowing.
#[tokio::test]
async fn overlapping_extra_route_is_not_silently_accepted() {
    let storage = Arc::new(StorageBackend::Memory(Arc::new(MemoryStorage::new())));
    let config = ApiServerConfig {
        bind_address: "127.0.0.1:0".to_string(),
        extra_router: Some(Router::new().route("/healthz", get(|| async { "x" }))),
        ..ApiServerConfig::default()
    };
    let h = tokio::spawn(run(storage, config));
    let res = tokio::time::timeout(Duration::from_secs(20), h)
        .await
        .expect("run must fail fast on overlap");
    assert!(res.is_err(), "overlap must panic (JoinError), got {res:?}");
}
