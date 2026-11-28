//! Ports of `staging/src/k8s.io/apiserver/pkg/server/filters/cors_test.go`
//! (TestCORSAllowedOrigins, TestCORSAllowedMethods, TestCompileRegex).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, Response};
use axum::routing::any;
use axum::Router;
use kubernetes_rs_middleware::cors::*;
use tower::ServiceExt;

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Sends one request through the filter; returns the response and how often
/// the wrapped handler ran.
async fn call(
    patterns: &[&str],
    methods: Option<&[&str]>,
    method: &str,
    origin: Option<&str>,
) -> (Response<Body>, usize) {
    let invoked = Arc::new(AtomicUsize::new(0));
    let i = invoked.clone();
    let mut app = Router::new().route(
        "/version",
        any(move || {
            let i = i.clone();
            async move {
                i.fetch_add(1, Ordering::SeqCst);
            }
        }),
    );
    let methods = methods.map(strs);
    if let Some(cors) = Cors::new(&strs(patterns), methods.as_deref(), None, None, "true").unwrap()
    {
        app = app.layer(axum::middleware::from_fn_with_state(
            Arc::new(cors),
            with_cors,
        ));
    }
    let mut req = Request::builder().method(method).uri("/version");
    if let Some(o) = origin {
        req = req.header("Origin", o);
    }
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    (resp, invoked.load(Ordering::SeqCst))
}

fn h<'a>(r: &'a Response<Body>, name: &str) -> &'a str {
    r.headers()
        .get(name)
        .map(|v| v.to_str().unwrap())
        .unwrap_or("")
}

#[tokio::test]
async fn cors_filter_allowed_origins() {
    // (name, allowed patterns, origins, allowed)
    let cases: Vec<(&str, Vec<&str>, Vec<&str>, bool)> = vec![
        (
            "allowed origins list is empty",
            vec![],
            vec!["example.com"],
            false,
        ),
        (
            "origin request header not set",
            vec!["example.com"],
            vec![""],
            false,
        ),
        (
            "allowed regexp is a match",
            vec!["example.com"],
            vec!["http://example.com", "example.com"],
            true,
        ),
        (
            "allowed regexp is not a match",
            vec!["example.com"],
            vec!["http://not-allowed.com", "not-allowed.com"],
            false,
        ),
        (
            "allowed list with multiple regex",
            vec!["not-matching.com", "example.com"],
            vec!["http://example.com", "example.com"],
            true,
        ),
        (
            "wildcard matching",
            vec![".*"],
            vec!["http://example.com", "example.com"],
            true,
        ),
        // CVE-2022-1996: an unpinned regexp matches example.com.hacker.org.
        (
            "regex does not pin, CVE-2022-1996 is not prevented",
            vec!["example.com"],
            vec![
                "http://example.com.hacker.org",
                "http://example.com.hacker.org:8080",
            ],
            true,
        ),
        (
            "regex pins to start/end of the host name, CVE-2022-1996 is prevented",
            vec![r"//example.com(:|$)"],
            vec![
                "http://example.com.hacker.org",
                "http://example.com.hacker.org:8080",
            ],
            false,
        ),
    ];
    for (name, patterns, origins, allowed) in cases {
        for origin in origins {
            let (resp, invoked) = call(&patterns, None, "GET", Some(origin)).await;
            let ctx = format!("{name}/origin/{origin}");
            assert_eq!(invoked, 1, "{ctx}");
            if allowed {
                assert_eq!(h(&resp, "access-control-allow-origin"), origin, "{ctx}");
                assert_ne!(h(&resp, "access-control-allow-credentials"), "", "{ctx}");
                assert_ne!(h(&resp, "access-control-allow-headers"), "", "{ctx}");
                assert_ne!(h(&resp, "access-control-allow-methods"), "", "{ctx}");
                assert_eq!(h(&resp, "access-control-expose-headers"), "Date", "{ctx}");
            } else {
                for hd in [
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                    "access-control-allow-headers",
                    "access-control-allow-methods",
                    "access-control-expose-headers",
                ] {
                    assert_eq!(h(&resp, hd), "", "{ctx}: {hd}");
                }
            }
        }
    }
}

#[tokio::test]
async fn cors_filter_allowed_methods() {
    let cases: [(Option<&[&str]>, &str, bool); 7] = [
        (None, "POST", true),
        (None, "GET", true),
        (None, "OPTIONS", true),
        (None, "PUT", true),
        (None, "DELETE", true),
        (None, "PATCH", true),
        (Some(&["GET", "POST"]), "PATCH", false),
    ];
    for (allowed_methods, method, allowed) in cases {
        let (resp, _) = call(&[".*"], allowed_methods, method, Some("allowed.com")).await;
        let listed = h(&resp, "access-control-allow-methods")
            .split(',')
            .any(|m| m.trim() == method);
        assert_eq!(listed, allowed, "{method} with {allowed_methods:?}");
    }
}

/// A preflight OPTIONS from an allowed origin is answered 204 by the filter
/// itself; the wrapped handler does not run.
#[tokio::test]
async fn cors_filter_preflight_stops_the_chain() {
    let (resp, invoked) = call(&[".*"], None, "OPTIONS", Some("http://x.io")).await;
    assert_eq!(resp.status(), 204);
    assert_eq!(invoked, 0);
    assert_eq!(h(&resp, "access-control-allow-origin"), "http://x.io");
    // A disallowed origin passes through untouched.
    let (resp, invoked) = call(&["^never$"], None, "OPTIONS", Some("http://x.io")).await;
    assert_eq!(invoked, 1);
    assert_eq!(h(&resp, "access-control-allow-origin"), "");
}

#[test]
fn cors_filter_compile_regex() {
    let patterns = strs(&["endsWithMe$", "^startingWithMe"]);
    let res = compile_regexps(&patterns).unwrap();
    assert_eq!(res.len(), 2);
    assert!(res[0].is_match("Something that endsWithMe"));
    assert!(!res[0].is_match("Something that doesn't endsWithMe."));
    assert!(res[1].is_match("startingWithMe is very important"));
    assert!(!res[1].is_match("not startingWithMe should fail"));
}

#[test]
fn cors_filter_invalid_pattern_and_empty_list() {
    let e = Cors::new(&strs(&["(unclosed"]), None, None, None, "true").unwrap_err();
    assert!(
        e.starts_with(
            "Invalid CORS allowed origin, --cors-allowed-origins flag was set to (unclosed - "
        ),
        "{e}"
    );
    // No patterns: no CORS support is installed.
    assert!(Cors::new(&[], None, None, None, "true").unwrap().is_none());
}
