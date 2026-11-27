//! Tests ported from `healthz_test.go` (release-1.35).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use kubernetes_rs_middleware::healthz::*;
use kubernetes_rs_middleware::lifecycle::LifecycleSignal;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

async fn get(router: &Router, uri: &str) -> (StatusCode, String, String) {
    let resp = router
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let ct = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, ct, String::from_utf8(body.to_vec()).unwrap())
}

fn ping() -> Arc<dyn HealthChecker> {
    Arc::new(Ping)
}

fn bad() -> Arc<dyn HealthChecker> {
    Arc::new(named_check("bad", || Err("this will fail".to_string())))
}

#[tokio::test]
async fn healthz_handler_install_path_handler() {
    let r = install_path_handler(Router::new(), "/healthz/test", vec![]);
    let r = install_path_handler(r, "/healthz/ready", vec![]);
    for p in ["/healthz/test", "/healthz/ready"] {
        let (s, ct, b) = get(&r, p).await;
        assert_eq!(
            (s, ct.as_str(), b.as_str()),
            (StatusCode::OK, "text/plain; charset=utf-8", "ok")
        );
    }
}

async fn multiple_checks(path: &str, name: &str) {
    let ok = StatusCode::OK;
    let err = StatusCode::INTERNAL_SERVER_ERROR;
    let cases: Vec<(&str, String, StatusCode, bool)> = vec![
        ("?verbose", format!("[+]ping ok\n{name} check passed\n"), ok, false),
        ("?exclude=dontexist", "ok".into(), ok, false),
        ("?exclude=bad", "ok".into(), ok, true),
        (
            "?verbose=true&exclude=bad",
            format!("[+]ping ok\n[+]bad excluded: ok\n{name} check passed\n"),
            ok,
            true,
        ),
        (
            "?verbose=true&exclude=dontexist",
            format!("[+]ping ok\nwarn: some health checks cannot be excluded: no matches for \"dontexist\"\n{name} check passed\n"),
            ok,
            false,
        ),
        ("/ping", "ok".into(), ok, false),
        ("", "ok".into(), ok, false),
        (
            "?verbose",
            format!("[+]ping ok\n[-]bad failed: reason withheld\n{name} check failed\n"),
            err,
            true,
        ),
        ("/ping", "ok".into(), ok, true),
        ("/bad", "internal server error: this will fail\n".into(), err, true),
        (
            "",
            format!("[+]ping ok\n[-]bad failed: reason withheld\n{name} check failed\n"),
            err,
            true,
        ),
    ];
    for (i, (suffix, want, status, add_bad)) in cases.into_iter().enumerate() {
        let mut checks = vec![ping()];
        if add_bad {
            checks.push(bad());
        }
        let r = install_path_handler(Router::new(), path, checks);
        let (s, ct, b) = get(&r, &format!("{path}{suffix}")).await;
        assert_eq!(s, status, "case[{i}]");
        assert_eq!(ct, "text/plain; charset=utf-8", "case[{i}]");
        assert_eq!(b, want, "case[{i}]");
    }
}

#[tokio::test]
async fn healthz_handler_multiple_checks() {
    multiple_checks("/healthz", "healthz").await;
    multiple_checks("/ready", "ready").await;
}

#[test]
fn healthz_handler_checker_names_and_format_quoted() {
    let c1: Arc<dyn HealthChecker> = Arc::new(named_check("n1", || Ok(())));
    let c2: Arc<dyn HealthChecker> = Arc::new(named_check("n2", || Ok(())));
    assert!(checker_names(&[]).is_empty());
    assert_eq!(checker_names(&[c2.clone(), c1.clone()]), ["n2", "n1"]);
    assert_eq!(format_quoted(&[]), "");
    assert_eq!(format_quoted(&["n1".into(), "n2".into()]), "\"n1\",\"n2\"");
}

#[test]
fn healthz_handler_excluded_checks() {
    assert!(get_excluded_checks(Some("verbose=true")).is_empty());
    assert!(get_excluded_checks(None).is_empty());
    let got: Vec<_> = get_excluded_checks(Some("exclude=ping&exclude=log"))
        .into_iter()
        .collect();
    assert_eq!(got, ["log", "ping"]);
}

#[tokio::test]
async fn healthz_handler_grouped_exclusion() {
    let g: Arc<dyn HealthChecker> =
        Arc::new(named_grouped_check(
            "etcd",
            "storage",
            || Err("down".into()),
        ));
    let r = install_path_handler(Router::new(), "/readyz", vec![ping(), g]);
    let (s, _, b) = get(&r, "/readyz?verbose&exclude=storage").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        b,
        "[+]ping ok\n[+]etcd excluded with storage: ok\nreadyz check passed\n"
    );
    let (s, _, _) = get(&r, "/readyz").await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn healthz_handler_first_time_healthy_once_and_shutdown_check() {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let sig = LifecycleSignal::new("ShutdownInitiated");
    let checks: Vec<Arc<dyn HealthChecker>> = vec![ping(), Arc::new(shutdown_healthz(sig.clone()))];
    let r = install_path_handler_with_healthy_func(
        Router::new(),
        "/readyz",
        Some(Arc::new(move || {
            n2.fetch_add(1, Ordering::SeqCst);
        })),
        checks,
    );
    for _ in 0..3 {
        assert_eq!(get(&r, "/readyz").await.0, StatusCode::OK);
    }
    assert_eq!(n.load(Ordering::SeqCst), 1);

    sig.signal();
    let (s, _, b) = get(&r, "/readyz").await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        b,
        "[+]ping ok\n[-]shutdown failed: reason withheld\nreadyz check failed\n"
    );
    let (s, _, b) = get(&r, "/readyz/shutdown").await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(b, "internal server error: process is shutting down\n");
    assert_eq!(n.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn healthz_handler_informer_sync() {
    let synced = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s2 = synced.clone();
    let c = informer_sync_healthz(move || {
        if s2.load(Ordering::SeqCst) {
            vec![]
        } else {
            vec!["a".into(), "b".into()]
        }
    });
    assert_eq!(c.name(), "informer-sync");
    assert_eq!(c.check().unwrap_err(), "2 informers not started yet: [a b]");
    synced.store(true, Ordering::SeqCst);
    assert!(c.check().is_ok());
}
