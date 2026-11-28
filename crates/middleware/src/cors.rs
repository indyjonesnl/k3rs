//! The CORS filter (`--cors-allowed-origins`).
//!
//! Ported from `staging/src/k8s.io/apiserver/pkg/server/filters/cors.go`
//! (`WithCORS` :36, `isOriginAllowed`, `allowedOriginRegexps`,
//! `compileRegexps`), release-1.35. Flag wiring comes with the api-server
//! flags batch.
//!
//! Install with `axum::middleware::from_fn_with_state(cors, with_cors)`.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use regex::Regex;

/// The default `Access-Control-Allow-Methods`.
pub const DEFAULT_ALLOWED_METHODS: &[&str] = &["POST", "GET", "OPTIONS", "PUT", "DELETE", "PATCH"];
/// The default `Access-Control-Allow-Headers`.
pub const DEFAULT_ALLOWED_HEADERS: &[&str] = &[
    "Content-Type",
    "Content-Length",
    "Accept-Encoding",
    "X-CSRF-Token",
    "Authorization",
    "X-Requested-With",
    "If-Modified-Since",
];
/// The default `Access-Control-Expose-Headers`.
pub const DEFAULT_EXPOSED_HEADERS: &[&str] = &["Date"];

/// The configured filter state of `WithCORS`.
#[derive(Debug)]
pub struct Cors {
    allowed_origin_patterns: Vec<Regex>,
    allow_methods: String,
    allow_headers: String,
    expose_headers: String,
    allow_credentials: String,
}

impl Cors {
    /// `WithCORS`'s set-up: `None` when `allowed_origin_patterns` is empty
    /// ("no CORS support is installed"). Pass `None` for the methods,
    /// headers or exposed headers to use the defaults. An invalid pattern is
    /// upstream's `klog.Fatalf("Invalid CORS allowed origin,
    /// --cors-allowed-origins flag was set to %v - %v")`, returned as `Err`.
    pub fn new(
        allowed_origin_patterns: &[String],
        allowed_methods: Option<&[String]>,
        allowed_headers: Option<&[String]>,
        exposed_headers: Option<&[String]>,
        allow_credentials: &str,
    ) -> Result<Option<Self>, String> {
        if allowed_origin_patterns.is_empty() {
            return Ok(None);
        }
        let res = compile_regexps(allowed_origin_patterns).map_err(|e| {
            format!(
                "Invalid CORS allowed origin, --cors-allowed-origins flag was set to {} - {}",
                allowed_origin_patterns.join(","),
                e
            )
        })?;
        let join = |custom: Option<&[String]>, default: &[&str]| match custom {
            Some(v) => v.join(", "),
            None => default.join(", "),
        };
        Ok(Some(Self {
            allowed_origin_patterns: res,
            allow_methods: join(allowed_methods, DEFAULT_ALLOWED_METHODS),
            allow_headers: join(allowed_headers, DEFAULT_ALLOWED_HEADERS),
            expose_headers: join(exposed_headers, DEFAULT_EXPOSED_HEADERS),
            allow_credentials: allow_credentials.to_string(),
        }))
    }

    /// `isOriginAllowed`: any pattern matching (unanchored) the Origin header
    /// value. An origin-list header (RFC 6454 section 7.2) is matched as one
    /// string.
    pub fn is_origin_allowed(&self, origin_header: &str) -> bool {
        self.allowed_origin_patterns
            .iter()
            .any(|re| re.is_match(origin_header))
    }
}

/// `compileRegexps`.
pub fn compile_regexps(patterns: &[String]) -> Result<Vec<Regex>, regex::Error> {
    patterns.iter().map(|p| Regex::new(p)).collect()
}

/// The handler `WithCORS` returns, as axum middleware.
pub async fn with_cors(State(cors): State<Arc<Cors>>, req: Request, next: Next) -> Response {
    let origin = match req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .filter(|o| !o.is_empty())
    {
        Some(o) => o.to_string(),
        None => return next.run(req).await,
    };
    if !cors.is_origin_allowed(&origin) {
        return next.run(req).await;
    }

    let is_preflight = req.method() == axum::http::Method::OPTIONS;
    let mut resp = if is_preflight {
        // Stop here if it's a preflight OPTIONS request.
        let mut r = Response::new(axum::body::Body::empty());
        *r.status_mut() = StatusCode::NO_CONTENT;
        r
    } else {
        // Dispatch to the next handler.
        next.run(req).await
    };
    let h = resp.headers_mut();
    let mut set = |name: &'static str, value: &str| {
        if let Ok(v) = HeaderValue::from_str(value) {
            h.insert(HeaderName::from_static(name), v);
        }
    };
    set("access-control-allow-origin", &origin);
    set("access-control-allow-methods", &cors.allow_methods);
    set("access-control-allow-headers", &cors.allow_headers);
    set("access-control-expose-headers", &cors.expose_headers);
    set("access-control-allow-credentials", &cors.allow_credentials);
    resp
}
