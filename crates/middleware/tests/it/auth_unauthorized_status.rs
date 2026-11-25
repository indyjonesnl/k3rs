//! Every authentication failure answers with a negotiated `Status`.
//!
//! Upstream `WithAuthentication` hands every failed request — an
//! authenticator error or "nothing authenticated it" — to the one `failed`
//! handler, `Unauthorized`
//! (staging/src/k8s.io/apiserver/pkg/endpoints/filters/authentication.go:73-78,
//! :127-149), which writes
//! `responsewriters.ErrorNegotiated(apierrors.NewUnauthorized("Unauthorized"))`.
//! No `WWW-Authenticate` header is set anywhere in that path.

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    middleware::from_fn,
    routing::get,
    Extension, Router,
};
use kubernetes_rs_common::auth::{BootstrapTokenManager, ServiceAccountClaims, TokenManager};
use kubernetes_rs_common::authz::{AlwaysAllowAuthorizer, Authorizer};
use kubernetes_rs_middleware::auth_middleware;
use kubernetes_rs_middleware::request_header::{FrontProxyConnection, RequestHeaderConfig};
use kubernetes_rs_storage::StorageBackend;
use serde_json::Value;
use tower::ServiceExt;

fn app(tokens: Arc<TokenManager>) -> Router {
    let authorizer: Arc<dyn Authorizer> = Arc::new(AlwaysAllowAuthorizer);
    Router::new()
        .route("/api/v1/pods", get(|| async { "ok" }))
        .layer(from_fn(auth_middleware))
        .layer(Extension(tokens))
        .layer(Extension(Arc::new(BootstrapTokenManager::new())))
        .layer(Extension(Arc::new(StorageBackend::new_memory())))
        .layer(Extension(authorizer))
}

async fn send(app: Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

fn assert_unauthorized_json(status: StatusCode, headers: &axum::http::HeaderMap, body: &[u8]) {
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/json",
        "401 must be a negotiated Status, not text/plain"
    );
    assert!(
        headers.get(header::WWW_AUTHENTICATE).is_none(),
        "upstream's Unauthorized handler sets no WWW-Authenticate"
    );
    let v: Value = serde_json::from_slice(body).expect("JSON Status body");
    assert_eq!(v["kind"], "Status");
    assert_eq!(v["apiVersion"], "v1");
    assert_eq!(v["status"], "Failure");
    assert_eq!(v["reason"], "Unauthorized");
    assert_eq!(v["message"], "Unauthorized");
    assert_eq!(v["code"], 401);
}

fn get_req(bearer: Option<&str>, accept: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri("/api/v1/pods");
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    if let Some(a) = accept {
        b = b.header(header::ACCEPT, a);
    }
    b.body(Body::empty()).unwrap()
}

/// Bearer token no authenticator accepts (token authenticator error).
#[tokio::test]
async fn invalid_bearer_token_is_negotiated_status() {
    let tm = Arc::new(TokenManager::new(b"secret"));
    let (s, h, b) = send(app(tm), get_req(Some("not-a-jwt"), None)).await;
    assert_unauthorized_json(s, &h, &b);
}

/// A JWT that verifies but whose ServiceAccount is gone
/// (`validator.Validate`, pkg/serviceaccount/claims.go) — the same 401.
#[tokio::test]
async fn service_account_token_for_missing_sa_is_negotiated_status() {
    let tm = Arc::new(TokenManager::new(b"secret"));
    let token = tm
        .generate_token(ServiceAccountClaims::new(
            "gone".into(),
            "default".into(),
            "uid-1".into(),
            1,
        ))
        .unwrap();
    let (s, h, b) = send(app(tm), get_req(Some(&token), None)).await;
    assert_unauthorized_json(s, &h, &b);
}

/// An authenticator error from the front-proxy (request-header) authenticator
/// with no other authenticator succeeding (`union.NewFailOnError`).
#[tokio::test]
async fn front_proxy_authenticator_error_is_negotiated_status() {
    let tm = Arc::new(TokenManager::new(b"secret"));
    let conn = FrontProxyConnection {
        config: Arc::new(RequestHeaderConfig::default()),
        presented: Arc::new(vec![vec![0x30, 0x00]]),
        verified_by_request_header_ca: false,
        verified_by_client_ca: None,
    };
    let mut req = get_req(None, None);
    req.extensions_mut().insert(Some(conn));
    let (s, h, b) = send(app(tm), req).await;
    assert_unauthorized_json(s, &h, &b);
}

/// The Status is negotiated per `Accept` (`ErrorNegotiated`).
#[tokio::test]
async fn invalid_token_status_honours_accept_yaml() {
    let tm = Arc::new(TokenManager::new(b"secret"));
    let (s, h, b) = send(
        app(tm),
        get_req(Some("not-a-jwt"), Some("application/yaml")),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(h.get(header::CONTENT_TYPE).unwrap(), "application/yaml");
    let v: Value = serde_yaml::from_slice(&b).expect("YAML Status body");
    assert_eq!(v["kind"], "Status");
    assert_eq!(v["reason"], "Unauthorized");
    assert_eq!(v["code"], 401);
}
