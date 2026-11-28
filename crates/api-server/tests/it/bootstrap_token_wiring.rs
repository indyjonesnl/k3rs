//! `--enable-bootstrap-token-auth` puts the bootstrap-token authenticator in
//! the authentication chain (pkg/kubeapiserver/authenticator/config.go:156,
//! after the service account tokens). Fails closed: unknown tokens, a wrong
//! secret and an expired token are all 401.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    middleware::from_fn,
    routing::get,
    Extension, Router,
};
use kubernetes_rs_api_server::bootstrap_token_authenticator::*;
use kubernetes_rs_common::auth::TokenManager;
use kubernetes_rs_common::authz::{AlwaysAllowAuthorizer, Authorizer};
use kubernetes_rs_common::resources::Secret;
use kubernetes_rs_middleware::{auth_middleware, set_bootstrap_token_authenticator, AuthContext};
use kubernetes_rs_storage::{build_key, Storage, StorageBackend};
use tower::ServiceExt;

async fn app() -> Router {
    set_bootstrap_token_authenticator(Arc::new(ChainBootstrapTokenAuthenticator));
    let storage = Arc::new(StorageBackend::new_memory());
    let data: HashMap<String, Vec<u8>> = [
        (BOOTSTRAP_TOKEN_ID_KEY, "abc123"),
        (BOOTSTRAP_TOKEN_SECRET_KEY, "0123456789abcdef"),
        (BOOTSTRAP_TOKEN_USAGE_AUTHENTICATION, "true"),
        (BOOTSTRAP_TOKEN_EXPIRATION_KEY, "2000-01-01T00:00:00Z"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
    .collect();
    let mut live = data.clone();
    live.remove(BOOTSTRAP_TOKEN_EXPIRATION_KEY);
    let mk = |id: &str, secret: &str, d: HashMap<String, Vec<u8>>| {
        let mut d = d;
        d.insert(BOOTSTRAP_TOKEN_ID_KEY.into(), id.as_bytes().to_vec());
        d.insert(
            BOOTSTRAP_TOKEN_SECRET_KEY.into(),
            secret.as_bytes().to_vec(),
        );
        Secret::new(format!("bootstrap-token-{id}"), "kube-system")
            .with_type(SECRET_TYPE_BOOTSTRAP_TOKEN)
            .with_data(d)
    };
    for s in [
        mk("abc123", "0123456789abcdef", live),
        mk("exp456", "0123456789abcdef", data),
    ] {
        let key = build_key("secrets", Some("kube-system"), &s.metadata.name);
        storage.create(&key, &s).await.unwrap();
    }
    let authorizer: Arc<dyn Authorizer> = Arc::new(AlwaysAllowAuthorizer);
    Router::new()
        .route(
            "/who",
            get(|Extension(c): Extension<AuthContext>| async move {
                format!("{} {}", c.user.username, c.user.groups.join(","))
            }),
        )
        .layer(from_fn(auth_middleware))
        .layer(Extension(Arc::new(TokenManager::new(b"secret"))))
        .layer(Extension(storage))
        .layer(Extension(authorizer))
}

async fn call(token: &str) -> (StatusCode, String) {
    let resp = app()
        .await
        .oneshot(
            Request::get("/who")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (st, String::from_utf8_lossy(&b).to_string())
}

#[tokio::test]
async fn bootstrap_token_wiring_valid_token_authenticates() {
    let (st, body) = call("abc123.0123456789abcdef").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(body.starts_with("system:bootstrap:abc123 "), "{body}");
    assert!(body.contains("system:bootstrappers"), "{body}");
    assert!(body.contains("system:authenticated"), "{body}");
}

#[tokio::test]
async fn bootstrap_token_wiring_rejects_bad_tokens() {
    for t in [
        "abc123.fedcba9876543210", // wrong secret
        "zzz999.0123456789abcdef", // unknown id
        "exp456.0123456789abcdef", // expired
        "not-a-token",
    ] {
        let (st, _) = call(t).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{t}");
    }
}
