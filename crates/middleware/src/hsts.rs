//! HSTS filter, port of
//! `staging/src/k8s.io/apiserver/pkg/server/filters/hsts.go:26` `WithHSTS`
//! (installed at `pkg/server/config.go:1079`).
use axum::{
    extract::Request,
    http::{header::STRICT_TRANSPORT_SECURITY, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// hsts.go:27-32: with no directives no HSTS support is installed (`None`);
/// otherwise the directives are joined with `"; "` (hsts.go:31).
pub fn hsts_header_value(directives: &[String]) -> Option<HeaderValue> {
    if directives.is_empty() {
        return None;
    }
    // Returning None here would silently disable HSTS on a bad directive,
    // so an unrepresentable header value is a loud configuration error.
    Some(
        HeaderValue::from_str(&directives.join("; "))
            .expect("strict-transport-security directives must be a valid header value"),
    )
}

/// hsts.go:33-41: set `Strict-Transport-Security` unless the response (here:
/// the handler's response) already carries one, then serve the request.
///
/// Go sets the header before calling the handler and the handler may
/// overwrite it; the handler's own header therefore wins. Equivalent here:
/// insert after the handler only when absent.
pub async fn with_hsts(value: Option<Arc<HeaderValue>>, req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    if let Some(value) = value {
        if !response.headers().contains_key(STRICT_TRANSPORT_SECURITY) {
            response
                .headers_mut()
                .insert(STRICT_TRANSPORT_SECURITY, (*value).clone());
        }
    }
    response
}
