//! `WithWarningRecorder` shares one recorder per request
//! (`staging/src/k8s.io/apiserver/pkg/endpoints/filters/warning.go`,
//! `warning.AddWarning(ctx, ...)` in `k8s.io/apiserver/pkg/warning/context.go`).

use axum::body::Body;
use axum::http::Request;
use axum::routing::get;
use axum::Router;
use kubernetes_rs_middleware::warning::*;
use tower::ServiceExt;

#[tokio::test]
async fn warning_task_local_recorder_dedups_with_extension_recorder() {
    let app = Router::new()
        .route(
            "/",
            get(|req: Request<Body>| async move {
                assert!(has_current_request_recorder());
                add_warning_to_current_request("", "route deprecated");
                add_warning(req.extensions(), "", "route deprecated");
                add_warning(req.extensions(), "", "other");
                "ok"
            }),
        )
        .layer(axum::middleware::from_fn(with_warning_recorder));
    let resp = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let n = resp.headers().get_all("warning").iter().count();
    assert_eq!(n, 2, "{:?}", resp.headers());
}

#[tokio::test]
async fn warning_no_current_recorder_outside_chain() {
    assert!(!has_current_request_recorder());
    assert!(!add_warning_to_current_request("", "x"));
}
