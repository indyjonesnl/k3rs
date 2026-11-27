//! Ports of rest/with_retry_test.go `TestIsNextRetry` and
//! `TestWrapPreviousError`.

use kubernetes_rs_client::with_retry::*;
use std::time::Duration;

fn fake() -> AttemptError {
    AttemptError::new("fake error")
}
fn only_fake(e: &AttemptError) -> bool {
    e.message == "fake error"
}
fn always(_: &AttemptError) -> bool {
    true
}
fn ra(attempt: u32, secs: u64, reason: &str) -> Option<RetryAfter> {
    Some(RetryAfter {
        wait: Duration::from_secs(secs),
        attempt,
        reason: reason.into(),
    })
}
fn bare(attempt: u32) -> Option<RetryAfter> {
    Some(RetryAfter {
        attempt,
        ..Default::default()
    })
}
fn resp(status: u16, retry_after: Option<&str>, uid: &str) -> RetryResponse {
    RetryResponse {
        status,
        retry_after: retry_after.map(String::from),
        flow_schema_uid: uid.into(),
    }
}

struct Case {
    name: &'static str,
    attempts: usize,
    max_retries: u32,
    response: Option<RetryResponse>,
    err: Option<AttemptError>,
    f: Option<fn(&AttemptError) -> bool>,
    retry_expected: Vec<bool>,
    retry_after_expected: Vec<Option<RetryAfter>>,
}

#[test]
fn with_retry_is_next_retry() {
    let cases = vec![
        Case {
            name: "bad input, response and err are nil",
            attempts: 1,
            max_retries: 2,
            response: None,
            err: None,
            f: None,
            retry_expected: vec![false],
            retry_after_expected: vec![None],
        },
        Case {
            name: "zero maximum retry",
            attempts: 1,
            max_retries: 0,
            response: Some(retry_after_response()),
            err: None,
            f: None,
            retry_expected: vec![false],
            retry_after_expected: vec![bare(1)],
        },
        Case {
            name: "server returned a retryable error",
            attempts: 1,
            max_retries: 3,
            response: None,
            err: Some(fake()),
            f: Some(only_fake),
            retry_expected: vec![true],
            retry_after_expected: vec![ra(
                1,
                1,
                "retries: 1, retry-after: 1s - retry-reason: due to retryable error, error: fake error",
            )],
        },
        Case {
            name: "retryable HTTP 429",
            attempts: 1,
            max_retries: 3,
            response: Some(resp(429, Some("2"), "fs-1")),
            err: None,
            f: None,
            retry_expected: vec![true],
            retry_after_expected: vec![ra(
                1,
                2,
                "retries: 1, retry-after: 2s - retry-reason: due to server-side throttling, FlowSchema UID: \"fs-1\"",
            )],
        },
        Case {
            name: "retryable HTTP 5xx",
            attempts: 1,
            max_retries: 3,
            response: Some(resp(503, Some("3"), "")),
            err: None,
            f: None,
            retry_expected: vec![true],
            retry_after_expected: vec![ra(1, 3, "retries: 1, retry-after: 3s - retry-reason: 503")],
        },
        Case {
            name: "no Retry-After header",
            attempts: 1,
            max_retries: 1,
            response: Some(resp(429, None, "")),
            err: None,
            f: None,
            retry_expected: vec![false],
            retry_after_expected: vec![bare(1)],
        },
        Case {
            name: "both response and err are set, err takes precedence",
            attempts: 1,
            max_retries: 1,
            response: Some(retry_after_response()),
            err: Some(fake()),
            f: Some(only_fake),
            retry_expected: vec![true],
            retry_after_expected: vec![ra(
                1,
                1,
                "retries: 1, retry-after: 1s - retry-reason: due to retryable error, error: fake error",
            )],
        },
        Case {
            name: "all retries are exhausted",
            attempts: 4,
            max_retries: 3,
            response: None,
            err: Some(fake()),
            f: Some(always),
            retry_expected: vec![true, true, true, false],
            retry_after_expected: vec![
                ra(1, 1, "retries: 1, retry-after: 1s - retry-reason: due to retryable error, error: fake error"),
                ra(2, 1, "retries: 2, retry-after: 1s - retry-reason: due to retryable error, error: fake error"),
                ra(3, 1, "retries: 3, retry-after: 1s - retry-reason: due to retryable error, error: fake error"),
                bare(4),
            ],
        },
    ];
    for c in cases {
        let mut r = WithRetry::new(c.max_retries);
        let mut got = vec![];
        let mut got_ra = vec![];
        for _ in 0..c.attempts {
            let f = c.f.as_ref().map(|f| f as &dyn Fn(&AttemptError) -> bool);
            got.push(r.is_next_retry(false, c.response.as_ref(), c.err.as_ref(), f));
            got_ra.push(r.retry_after.clone());
        }
        assert_eq!(got, c.retry_expected, "{}", c.name);
        assert_eq!(got_ra, c.retry_after_expected, "{}", c.name);
    }
}

#[test]
fn with_retry_opaque_body_is_never_retried() {
    let mut r = WithRetry::new(3);
    assert!(!r.is_next_retry(true, Some(&retry_after_response()), None, None));
    assert_eq!(r.retry_after, None);
}

#[test]
fn with_retry_check_wait_only_429_and_5xx() {
    assert_eq!(check_wait(&resp(404, Some("1"), "")), None);
    assert_eq!(check_wait(&resp(500, Some("x"), "")), None);
    assert_eq!(check_wait(&resp(429, Some("7"), "")), Some(7));
}

fn prev(e: AttemptError) -> WithRetry {
    let mut r = WithRetry::new(1);
    r.track_previous_error(Some(&e));
    // currentErr is set by the second call; mimic the Go struct literal
    // `withRetry{previousErr: e}` by shifting once more.
    r.track_previous_error(None);
    r
}

#[test]
fn with_retry_wrap_previous_error() {
    let eof = AttemptError::url_error("GET", "http://foo.bar", "EOF");
    let marker = "- error from a previous attempt: ";

    // current nil
    assert!(prev(AttemptError::new("x"))
        .wrap_previous_error::<AttemptError>(None)
        .is_none());
    // previous nil
    let r = WithRetry::new(1);
    assert!(matches!(
        r.wrap_previous_error(Some(eof.clone())),
        Some(Wrapped::Same(_))
    ));
    // same text
    let r = prev(AttemptError::url_error("GET", "http://foo.bar", "EOF"));
    assert!(matches!(
        r.wrap_previous_error(Some(eof.clone())),
        Some(Wrapped::Same(_))
    ));
    // different: wrapped
    let r = prev(AttemptError::new("unknown error"));
    let Some(Wrapped::Wrapped(w)) = r.wrap_previous_error(Some(eof.clone())) else {
        panic!("want wrapped")
    };
    assert!(w.to_string().contains(&format!("{marker}unknown error")));
    assert_eq!(w.current, eof);
    // previous url.Error is unwrapped to its inner error
    let r = prev(AttemptError {
        message: "Get \"\": unexpected EOF".into(),
        inner: Some("unexpected EOF".into()),
    });
    let Some(Wrapped::Wrapped(w)) = r.wrap_previous_error(Some(eof.clone())) else {
        panic!("want wrapped")
    };
    assert_eq!(
        w.to_string(),
        format!("{} - error from a previous attempt: unexpected EOF", eof)
    );
    // non-url previous error is kept whole
    let r = prev(AttemptError::new(
        "should be included in error message - EOF",
    ));
    let Some(Wrapped::Wrapped(w)) = r.wrap_previous_error(Some(eof)) else {
        panic!("want wrapped")
    };
    assert!(w
        .to_string()
        .ends_with("should be included in error message - EOF"));
}
