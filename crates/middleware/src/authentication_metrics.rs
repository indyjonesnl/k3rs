//! Authentication metrics.
//!
//! Ported from Kubernetes release-1.35 `staging/src/k8s.io/apiserver/pkg`:
//! - `endpoints/filters/metrics.go`: `authenticatedUserCounter` (:50-57),
//!   `authenticatedAttemptsCounter` (:59-66), `authenticationLatency` (:68-76),
//!   `recordAuthenticationMetrics` (:124-143), `compressUsername` (:145-166),
//!   called by `withAuthentication` (`filters/authentication.go:50-125`) with
//!   `audiencesAreAcceptable` (:152-158).
//! - `authentication/token/cache/stats.go`: `authentication_token_cache_*`
//!   (`requestLatency`, `requestCount`, `fetchCount`, `activeFetchCount`) and
//!   `statsCollector.{authenticating,blocking,fetching}`.
//!
//! The collectors are registered in the process-wide default registry (this
//! port's `legacyregistry`) on first use or by [`register_metrics`]. Nothing
//! calls the recorders yet: wiring into the authentication filter and the
//! token cache is separate.

use prometheus::{
    register, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, DEFAULT_BUCKETS,
};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// `successLabel` / `failureLabel` / `errorLabel` (metrics.go:37-39).
const SUCCESS: &str = "success";
const FAILURE: &str = "failure";
const ERROR: &str = "error";

fn counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(Opts::new(name, help), labels).expect("valid metric");
    let _ = register(Box::new(c.clone()));
    c
}

/// `metrics.ExponentialBuckets(0.001, 2, 15)`.
fn exponential_buckets() -> Vec<f64> {
    (0..15).map(|i| 0.001 * 2f64.powi(i)).collect()
}

static AUTHENTICATED_USER_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "authenticated_user_requests",
        "[ALPHA] Counter of authenticated requests broken out by username.",
        &["username"],
    )
});

static AUTHENTICATION_ATTEMPTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "authentication_attempts",
        "[ALPHA] Counter of authenticated attempts.",
        &["result"],
    )
});

static AUTHENTICATION_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "authentication_duration_seconds",
            "[ALPHA] Authentication duration in seconds broken out by result.",
        )
        .buckets(exponential_buckets()),
        &["result"],
    )
    .expect("valid metric");
    let _ = register(Box::new(h.clone()));
    h
});

static TOKEN_CACHE_REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "authentication_token_cache_request_duration_seconds",
            "[ALPHA]",
        )
        .buckets(DEFAULT_BUCKETS.to_vec()),
        &["status"],
    )
    .expect("valid metric");
    let _ = register(Box::new(h.clone()));
    h
});

static TOKEN_CACHE_REQUEST_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "authentication_token_cache_request_total",
        "[ALPHA]",
        &["status"],
    )
});

static TOKEN_CACHE_FETCH_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "authentication_token_cache_fetch_total",
        "[ALPHA]",
        &["status"],
    )
});

static TOKEN_CACHE_ACTIVE_FETCH_COUNT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let g = IntGaugeVec::new(
        Opts::new("authentication_token_cache_active_fetch_count", "[ALPHA]"),
        &["status"],
    )
    .expect("valid metric");
    let _ = register(Box::new(g.clone()));
    g
});

/// Register every collector, so they are exposed before the first request.
pub fn register_metrics() {
    LazyLock::force(&AUTHENTICATED_USER_REQUESTS);
    LazyLock::force(&AUTHENTICATION_ATTEMPTS);
    LazyLock::force(&AUTHENTICATION_DURATION);
    LazyLock::force(&TOKEN_CACHE_REQUEST_DURATION);
    LazyLock::force(&TOKEN_CACHE_REQUEST_TOTAL);
    LazyLock::force(&TOKEN_CACHE_FETCH_TOTAL);
    LazyLock::force(&TOKEN_CACHE_ACTIVE_FETCH_COUNT);
}

/// `authenticator.Response`, reduced to what the metrics read.
#[derive(Debug, Clone, Copy)]
pub struct AuthResponse<'a> {
    pub username: &'a str,
    /// `Response.Audiences`.
    pub audiences: &'a [String],
}

/// `audiencesAreAcceptable` (authentication.go:152-158): acceptable when
/// either side lists no audience, else when the lists intersect.
pub fn audiences_are_acceptable(api_audiences: &[String], response_audiences: &[String]) -> bool {
    if api_audiences.is_empty() || response_audiences.is_empty() {
        return true;
    }
    api_audiences.iter().any(|a| response_audiences.contains(a))
}

/// `compressUsername` (metrics.go:145-166): maps usernames onto a small set
/// of categories, to limit the cardinality of `authenticated_user_requests`
/// and to keep real usernames out of the metric.
pub fn compress_username(username: &str) -> &'static str {
    match username {
        "admin" => "admin",
        "client" => "client",
        "kube_proxy" => "kube_proxy",
        "kubelet" => "kubelet",
        "system:serviceaccount:kube-system:default" => "system:serviceaccount:kube-system:default",
        u if u.contains('@') => "email_id",
        _ => "other",
    }
}

/// `recordAuthenticationMetrics` (metrics.go:124-143). `errored` is
/// `err != nil`; `resp` is the authenticator response, when there was one.
pub fn record_authentication_metrics(
    resp: Option<AuthResponse<'_>>,
    ok: bool,
    errored: bool,
    api_audiences: &[String],
    elapsed: Duration,
) {
    let label =
        if errored || resp.is_some_and(|r| !audiences_are_acceptable(api_audiences, r.audiences)) {
            ERROR
        } else if !ok {
            FAILURE
        } else {
            if let Some(r) = resp {
                AUTHENTICATED_USER_REQUESTS
                    .with_label_values(&[compress_username(r.username)])
                    .inc();
            }
            SUCCESS
        };
    AUTHENTICATION_ATTEMPTS.with_label_values(&[label]).inc();
    AUTHENTICATION_DURATION
        .with_label_values(&[label])
        .observe(elapsed.as_secs_f64());
}

/// `statsCollector.authenticating` (stats.go:84-100): start timing a token
/// cache lookup; call the result with whether it was a hit. The latency is
/// truncated to milliseconds, as `float64(latency.Milliseconds()) / 1000`.
pub fn token_cache_authenticating() -> impl FnOnce(bool) {
    let start = Instant::now();
    move |hit| {
        let tag = if hit { "hit" } else { "miss" };
        let millis = start.elapsed().as_millis() as f64;
        TOKEN_CACHE_REQUEST_TOTAL.with_label_values(&[tag]).inc();
        TOKEN_CACHE_REQUEST_DURATION
            .with_label_values(&[tag])
            .observe(millis / 1000.0);
    }
}

/// The decrement `statsCollector.blocking` returns, as a guard.
pub struct BlockingGuard(());

impl Drop for BlockingGuard {
    fn drop(&mut self) {
        TOKEN_CACHE_ACTIVE_FETCH_COUNT
            .with_label_values(&["blocked"])
            .dec();
    }
}

/// `statsCollector.blocking` (stats.go:102-105): a request waits on another
/// request's fetch; `active_fetch_count{status="blocked"}` is up until the
/// guard drops.
pub fn token_cache_blocking() -> BlockingGuard {
    TOKEN_CACHE_ACTIVE_FETCH_COUNT
        .with_label_values(&["blocked"])
        .inc();
    BlockingGuard(())
}

/// `statsCollector.fetching` (stats.go:107-120): a fetch starts
/// (`active_fetch_count{status="in_flight"}` up); call the result with
/// whether it succeeded.
pub fn token_cache_fetching() -> impl FnOnce(bool) {
    TOKEN_CACHE_ACTIVE_FETCH_COUNT
        .with_label_values(&["in_flight"])
        .inc();
    |ok| {
        let tag = if ok { "ok" } else { "error" };
        TOKEN_CACHE_FETCH_TOTAL.with_label_values(&[tag]).inc();
        TOKEN_CACHE_ACTIVE_FETCH_COUNT
            .with_label_values(&["in_flight"])
            .dec();
    }
}

/// Reset the labelled collectors (`CounterVec.Reset`); upstream's tests do
/// this because the gatherer is process-global.
#[doc(hidden)]
pub fn reset_for_tests() {
    AUTHENTICATED_USER_REQUESTS.reset();
    AUTHENTICATION_ATTEMPTS.reset();
    AUTHENTICATION_DURATION.reset();
    TOKEN_CACHE_REQUEST_DURATION.reset();
    TOKEN_CACHE_REQUEST_TOTAL.reset();
    TOKEN_CACHE_FETCH_TOTAL.reset();
    TOKEN_CACHE_ACTIVE_FETCH_COUNT.reset();
}
