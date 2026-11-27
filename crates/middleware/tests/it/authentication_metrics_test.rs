//! Ported from `endpoints/filters/metrics_test.go` (`TestMetrics`) and
//! `authentication/token/cache/stats.go`. The registry is process-global, so
//! the tests serialize and reset the collectors first.

use kubernetes_rs_middleware::authentication_metrics::*;
use prometheus::{Encoder, TextEncoder};
use std::sync::Mutex;
use std::time::Duration;

static LOCK: Mutex<()> = Mutex::new(());

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// `testutil.GatherAndCompare` for the given metric names.
fn gather(names: &[&str]) -> String {
    let fams: Vec<_> = prometheus::gather()
        .into_iter()
        .filter(|f| names.contains(&f.name()))
        .collect();
    let mut buf = Vec::new();
    TextEncoder::new().encode(&fams, &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

const USER_HELP: &str = "# HELP authenticated_user_requests [ALPHA] Counter of authenticated requests broken out by username.\n# TYPE authenticated_user_requests counter\n";
const ATTEMPTS_HELP: &str = "# HELP authentication_attempts [ALPHA] Counter of authenticated attempts.\n# TYPE authentication_attempts counter\n";

#[test]
fn authentication_metrics_records_results_like_upstream() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    struct Case {
        desc: &'static str,
        resp: Option<(&'static str, Vec<String>)>,
        ok: bool,
        err: bool,
        api_audiences: Vec<String>,
        want: String,
    }
    let admin_ok = format!(
        "{USER_HELP}authenticated_user_requests{{username=\"admin\"}} 1\n{ATTEMPTS_HELP}authentication_attempts{{result=\"success\"}} 1\n"
    );
    let cases = vec![
        Case {
            desc: "auth ok",
            resp: Some(("admin", vec![])),
            ok: true,
            err: false,
            api_audiences: vec![],
            want: admin_ok.clone(),
        },
        Case {
            desc: "auth failed with error",
            resp: None,
            ok: false,
            err: true,
            api_audiences: vec![],
            want: format!("{ATTEMPTS_HELP}authentication_attempts{{result=\"error\"}} 1\n"),
        },
        Case {
            desc: "auth failed with status false",
            resp: None,
            ok: false,
            err: false,
            api_audiences: vec![],
            want: format!("{ATTEMPTS_HELP}authentication_attempts{{result=\"failure\"}} 1\n"),
        },
        Case {
            desc: "auth failed due to audiences not intersecting",
            resp: Some(("admin", s(&["audience-x"]))),
            ok: true,
            err: false,
            api_audiences: s(&["audience-y"]),
            want: format!("{ATTEMPTS_HELP}authentication_attempts{{result=\"error\"}} 1\n"),
        },
        Case {
            desc: "audiences not supplied in the response",
            resp: Some(("admin", vec![])),
            ok: true,
            err: false,
            api_audiences: s(&["audience-y"]),
            want: admin_ok.clone(),
        },
        Case {
            desc: "audiences not supplied to the handler",
            resp: Some(("admin", s(&["audience-x"]))),
            ok: true,
            err: false,
            api_audiences: vec![],
            want: admin_ok,
        },
    ];
    for c in cases {
        reset_for_tests();
        record_authentication_metrics(
            c.resp.as_ref().map(|(u, a)| AuthResponse {
                username: u,
                audiences: a,
            }),
            c.ok,
            c.err,
            &c.api_audiences,
            Duration::from_millis(3),
        );
        assert_eq!(
            gather(&["authenticated_user_requests", "authentication_attempts"]),
            c.want,
            "{}",
            c.desc
        );
    }
}

#[test]
fn authentication_metrics_duration_is_observed_per_result() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_for_tests();
    record_authentication_metrics(None, false, false, &[], Duration::from_millis(3));
    let out = gather(&["authentication_duration_seconds"]);
    assert!(
        out.contains("authentication_duration_seconds_count{result=\"failure\"} 1"),
        "{out}"
    );
    // ExponentialBuckets(0.001, 2, 15): 0.001 ... 16.384.
    assert!(out.contains("le=\"0.001\""), "{out}");
    assert!(out.contains("le=\"16.384\""), "{out}");
    assert!(
        out.contains("authentication_duration_seconds_bucket{result=\"failure\",le=\"0.004\"} 1"),
        "{out}"
    );
}

#[test]
fn authentication_metrics_compress_username() {
    for (u, want) in [
        ("admin", "admin"),
        ("client", "client"),
        ("kube_proxy", "kube_proxy"),
        ("kubelet", "kubelet"),
        (
            "system:serviceaccount:kube-system:default",
            "system:serviceaccount:kube-system:default",
        ),
        ("someone@example.com", "email_id"),
        ("system:serviceaccount:ns:custom", "other"),
        ("", "other"),
    ] {
        assert_eq!(compress_username(u), want, "{u}");
    }
}

#[test]
fn authentication_metrics_audiences_are_acceptable() {
    assert!(audiences_are_acceptable(&[], &s(&["a"])));
    assert!(audiences_are_acceptable(&s(&["a"]), &[]));
    assert!(audiences_are_acceptable(&s(&["a", "b"]), &s(&["b", "c"])));
    assert!(!audiences_are_acceptable(&s(&["a"]), &s(&["b"])));
}

#[test]
fn authentication_metrics_token_cache_stats() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_for_tests();
    token_cache_authenticating()(true);
    token_cache_authenticating()(false);
    token_cache_authenticating()(false);
    let fetched = token_cache_fetching();
    let blocked = token_cache_blocking();
    let mid = gather(&["authentication_token_cache_active_fetch_count"]);
    assert!(
        mid.contains("active_fetch_count{status=\"in_flight\"} 1"),
        "{mid}"
    );
    assert!(
        mid.contains("active_fetch_count{status=\"blocked\"} 1"),
        "{mid}"
    );
    fetched(true);
    token_cache_fetching()(false);
    drop(blocked);
    let out = gather(&[
        "authentication_token_cache_request_total",
        "authentication_token_cache_fetch_total",
        "authentication_token_cache_active_fetch_count",
    ]);
    for want in [
        "authentication_token_cache_request_total{status=\"hit\"} 1",
        "authentication_token_cache_request_total{status=\"miss\"} 2",
        "authentication_token_cache_fetch_total{status=\"ok\"} 1",
        "authentication_token_cache_fetch_total{status=\"error\"} 1",
        "authentication_token_cache_active_fetch_count{status=\"in_flight\"} 0",
        "authentication_token_cache_active_fetch_count{status=\"blocked\"} 0",
    ] {
        assert!(out.contains(want), "missing {want}\n{out}");
    }
}
