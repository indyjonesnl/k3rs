//! The endpoint-level deprecation `Warning:` header: port of
//! `staging/src/k8s.io/apiserver/pkg/endpoints/installer.go:781-797,814`
//! (`deprecation.WarningMessage` per route, `utilwarning.AddWarningsHandler`)
//! over the deduplicating, truncating recorder of
//! `staging/src/k8s.io/apiserver/pkg/endpoints/filters/warning.go`, which is
//! the central [`kubernetes_rs_middleware::warning::WarningRecorder`].
//!
//! Deviation (structural): upstream installs the warning on each route and the
//! per-request recorder is shared with every later `warning.AddWarning`. Here
//! handlers write their own `Warning` headers on the response
//! ([`crate::endpoints::handlers::rest::respond`]), so the route-level
//! middleware runs the same recorder over `[endpoint warnings, then the
//! headers the handler wrote]`, which yields the order and dedup upstream's
//! recorder produces (the route's warnings are added before the handler runs).
//!
//! Only routes upstream installs get a warning: `removeDeletedKinds`
//! (`server/deleted_kinds.go:184`) drops a kind once `ShouldServeForVersion`
//! is false, which for a GA build is `removed <= current`.

use axum::extract::Request;
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use kubernetes_rs_middleware::warning::WarningRecorder;

use super::{
    is_deprecated, lookup, should_serve_for_version, warning_message, CURRENT_MAJOR_MINOR,
};

/// The route's accumulated warnings (installer.go:781-797): the deprecation
/// message when the kind is deprecated and still served.
pub fn endpoint_warnings(
    group: &str,
    version: &str,
    resource: &str,
    subresource: &str,
) -> Vec<String> {
    let obj = lookup(group, version, resource, subresource);
    if let Some(removed) = obj.and_then(|l| l.removed) {
        if !should_serve_for_version(removed) {
            return Vec::new();
        }
    }
    let (major, minor) = CURRENT_MAJOR_MINOR;
    if is_deprecated(obj, major as i64, minor as i64) {
        vec![warning_message(obj)]
    } else {
        Vec::new()
    }
}

/// `(agent, text)` of a `299 <agent> "<quoted>"` header value.
pub fn parse_warning_header(value: &str) -> Option<(String, String)> {
    let rest = value.strip_prefix("299 ")?;
    let (agent, quoted) = rest.split_once(' ')?;
    let inner = quoted.strip_prefix('"')?.strip_suffix('"')?;
    let mut text = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            text.push(chars.next()?);
        } else {
            text.push(c);
        }
    }
    Some((agent.to_string(), text))
}

/// `AddWarningsHandler`: add the route's warnings before the handler runs
/// and merge them with the handler's own through the recorder.
pub async fn add_endpoint_warnings(req: Request, next: Next) -> Response {
    let meta = crate::apiserver_request_metrics::request_meta(&req);
    let warnings = if meta.is_resource_request {
        endpoint_warnings(
            &meta.api_group,
            &meta.api_version,
            &meta.resource,
            &meta.subresource,
        )
    } else {
        Vec::new()
    };
    let mut resp = next.run(req).await;
    if warnings.is_empty() {
        return resp;
    }
    let recorder = WarningRecorder::default();
    for w in &warnings {
        recorder.add_warning("", w);
    }
    for v in resp.headers().get_all(header::WARNING) {
        if let Some((agent, text)) = v.to_str().ok().and_then(parse_warning_header) {
            recorder.add_warning(&agent, &text);
        }
    }
    resp.headers_mut().remove(header::WARNING);
    for h in recorder.headers() {
        if let Ok(v) = HeaderValue::from_str(&h) {
            resp.headers_mut().append(header::WARNING, v);
        }
    }
    resp
}
