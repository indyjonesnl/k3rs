//! `WithHSTS` (filters/hsts.go:26-41).
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::from_fn,
    routing::get,
    Router,
};
use kubernetes_rs_middleware::hsts::{hsts_header_value, with_hsts};
use std::sync::Arc;
use tower::ServiceExt;

fn app(directives: &[&str], handler_header: Option<&'static str>) -> Router {
    let directives: Vec<String> = directives.iter().map(|d| d.to_string()).collect();
    let value = hsts_header_value(&directives).map(Arc::new);
    Router::new()
        .route(
            "/",
            get(move || async move {
                let mut r = axum::response::Response::new(Body::empty());
                if let Some(h) = handler_header {
                    r.headers_mut()
                        .insert("strict-transport-security", h.parse().unwrap());
                }
                r
            }),
        )
        .layer(from_fn(move |req, next| {
            let value = value.clone();
            async move { with_hsts(value, req, next).await }
        }))
}

async fn header(app: Router) -> Option<String> {
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.headers()
        .get("strict-transport-security")
        .map(|v| v.to_str().unwrap().to_owned())
}

#[tokio::test]
async fn hsts_filter_empty_directives_installs_nothing() {
    assert!(hsts_header_value(&[]).is_none());
    assert_eq!(header(app(&[], None)).await, None);
}

#[tokio::test]
async fn hsts_filter_joins_directives_with_semicolon_space() {
    let h = header(app(
        &["max-age=31536000", "includeSubDomains", "preload"],
        None,
    ))
    .await;
    assert_eq!(
        h.as_deref(),
        Some("max-age=31536000; includeSubDomains; preload")
    );
}

#[tokio::test]
async fn hsts_filter_keeps_header_already_set() {
    let h = header(app(&["max-age=1"], Some("max-age=99"))).await;
    assert_eq!(h.as_deref(), Some("max-age=99"));
}
