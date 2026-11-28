//! Unit tests moved from `src/deprecation/warnings.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use axum::extract::Request;
    pub use axum::http::{header, HeaderValue};
    pub use axum::middleware::Next;
    pub use axum::response::Response;
    pub use kubernetes_rs_api_server::deprecation::{
        is_deprecated, lookup, should_serve_for_version, warning_message, CURRENT_MAJOR_MINOR,
    };
}

mod tests {
    use super::__parent::*;
    use kubernetes_rs_api_server::deprecation::warnings::*;

    #[test]
    fn served_deprecated_kind_warns() {
        // resource.k8s.io/v1beta1 DeviceClass: deprecated 1.35, removed 1.38.
        let w = endpoint_warnings("resource.k8s.io", "v1beta1", "deviceclasses", "");
        assert_eq!(
            w,
            ["resource.k8s.io/v1beta1 DeviceClass is deprecated in v1.35+, unavailable in v1.38+"]
        );
    }

    /// `removeDeletedKinds`: a removed version has no route, so no warning.
    #[test]
    fn removed_kind_has_no_route_so_no_warning() {
        assert!(endpoint_warnings("apps", "v1beta1", "deployments", "").is_empty());
    }

    #[test]
    fn stable_kind_does_not_warn() {
        assert!(endpoint_warnings("apps", "v1", "deployments", "").is_empty());
    }

    #[test]
    fn parses_what_the_handlers_write() {
        let h =
            kubernetes_rs_api_server::handlers::validation::format_warning_header(r#"a "b" \c"#);
        assert_eq!(
            parse_warning_header(&h),
            Some(("-".to_string(), r#"a "b" \c"#.to_string()))
        );
    }

    async fn serve(uri: &str, handler_warnings: &'static [&'static str]) -> Vec<String> {
        use axum::{body::Body, http::Request, middleware, routing::get, Router};
        use tower::ServiceExt;
        let app = Router::new()
            .route(
                "/apis/resource.k8s.io/v1beta1/deviceclasses",
                get(move || async move {
                    let mut r = axum::response::Response::new(Body::empty());
                    for w in handler_warnings {
                        r.headers_mut().append(
                            header::WARNING,
                            HeaderValue::from_str(
                                &kubernetes_rs_api_server::handlers::validation::format_warning_header(w),
                            )
                            .unwrap(),
                        );
                    }
                    r
                }),
            )
            .route("/apis/apps/v1/deployments", get(|| async { "ok" }))
            .layer(middleware::from_fn(add_endpoint_warnings));
        let resp = app
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        resp.headers()
            .get_all(header::WARNING)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    /// AddWarningsHandler: the route's warning is added before the handler's
    /// own, and a repeated text is recorded once.
    #[tokio::test]
    async fn middleware_puts_route_warning_first_and_dedups() {
        const ROUTE: &str =
            "resource.k8s.io/v1beta1 DeviceClass is deprecated in v1.35+, unavailable in v1.38+";
        let got = serve(
            "/apis/resource.k8s.io/v1beta1/deviceclasses",
            &["handler says hi", ROUTE],
        )
        .await;
        assert_eq!(
            got,
            [
                format!("299 - \"{ROUTE}\""),
                "299 - \"handler says hi\"".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn middleware_leaves_stable_routes_alone() {
        assert!(serve("/apis/apps/v1/deployments", &[]).await.is_empty());
    }
}
