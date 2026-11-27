//! Client retry decision logic (no I/O).
//!
//! Port of `staging/src/k8s.io/client-go/rest/with_retry.go`: `withRetry`
//! (:105), `IsNextRetry` (:148), `WrapPreviousError` (:281), `checkWait`
//! (:309), `getRetryReason` (:322) and `retryAfterResponse` (:355), plus
//! `retryAfterSeconds` (request.go:1378).
//!
//! Not ported here (they need the HTTP stack and are wired in a later task):
//! `Before` (:195, backoff sleep + throttle), `After` (:238, metrics and
//! backoff update). Go's `httpReq == nil` input check has no Rust
//! counterpart: a request is always present.

use std::fmt;
use std::time::Duration;

use reqwest::header::HeaderMap;

/// `X-Kubernetes-PF-FlowSchema-UID` (with_retry.go:325).
const RESPONSE_HEADER_MATCHED_FLOW_SCHEMA_UID: &str = "X-Kubernetes-PF-FlowSchema-UID";

/// The parts of `*http.Response` the retry logic reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetryResponse {
    pub status: u16,
    /// Raw `Retry-After` header value, if any.
    pub retry_after: Option<String>,
    /// `X-Kubernetes-PF-FlowSchema-UID`, empty when absent.
    pub flow_schema_uid: String,
}

impl RetryResponse {
    pub fn from_headers(status: u16, headers: &HeaderMap) -> Self {
        let get = |n: &str| {
            headers
                .get(n)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Self {
            status,
            retry_after: get("retry-after"),
            flow_schema_uid: get(RESPONSE_HEADER_MATCHED_FLOW_SCHEMA_UID).unwrap_or_default(),
        }
    }
}

/// `retryAfterResponseWithCodeAndDelay` (:365): the artificial 500 with a
/// `Retry-After` that stands in for a retryable transport error.
pub fn retry_after_response_with_code_and_delay(code: u16, delay: &str) -> RetryResponse {
    RetryResponse {
        status: code,
        retry_after: Some(delay.to_string()),
        flow_schema_uid: String::new(),
    }
}

/// `retryAfterResponse` (:355): 500 with `Retry-After: 1`.
pub fn retry_after_response() -> RetryResponse {
    retry_after_response_with_code_and_delay(500, "1")
}

/// A transport error of one attempt. `inner` is the error a Go `*url.Error`
/// wraps (`urlErr.Unwrap()`), set only when the error is a `url.Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptError {
    pub message: String,
    pub inner: Option<String>,
}

impl AttemptError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            inner: None,
        }
    }

    /// A `*url.Error`: `Op "URL": inner` (net/url Error.Error()).
    pub fn url_error(op: &str, url: &str, inner: &str) -> Self {
        Self {
            message: format!("{op} \"{url}\": {inner}"),
            inner: Some(inner.to_string()),
        }
    }
}

impl fmt::Display for AttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AttemptError {}

/// `IsRetryableErrorFunc` (:35).
pub type IsRetryableErrorFunc<'a> = &'a dyn Fn(&AttemptError) -> bool;

/// `RetryAfter` (:93): parameters of the next retry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetryAfter {
    pub wait: Duration,
    pub attempt: u32,
    pub reason: String,
}

/// `withRetry` (:105).
#[derive(Debug, Default)]
pub struct WithRetry {
    pub max_retries: u32,
    attempts: u32,
    pub retry_after: Option<RetryAfter>,
    previous_err: Option<AttemptError>,
    current_err: Option<AttemptError>,
}

/// `wrapPreviousError` (:296). `source()` is the current error (`Unwrap`).
#[derive(Debug)]
pub struct WrappedPreviousError<E> {
    pub current: E,
    pub previous: String,
}

impl<E: fmt::Display> fmt::Display for WrappedPreviousError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} - error from a previous attempt: {}",
            self.current, self.previous
        )
    }
}

impl<E: std::error::Error + 'static> std::error::Error for WrappedPreviousError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.current)
    }
}

/// The result of `WrapPreviousError`.
#[derive(Debug)]
pub enum Wrapped<E> {
    /// Nothing to add: the current error is returned unchanged.
    Same(E),
    Wrapped(WrappedPreviousError<E>),
}

impl WithRetry {
    pub fn new(max_retries: u32) -> Self {
        Self {
            max_retries,
            ..Default::default()
        }
    }

    /// `trackPreviousError` (:129): keep the two most recent errors.
    pub fn track_previous_error(&mut self, err: Option<&AttemptError>) {
        if let Some(cur) = self.current_err.take() {
            self.previous_err = Some(cur);
        }
        self.current_err = err.cloned();
    }

    /// `IsNextRetry` (:148-193). `has_opaque_body` is `restReq.body != nil`:
    /// an opaque reader cannot be rewound, so the request is not retried.
    pub fn is_next_retry(
        &mut self,
        has_opaque_body: bool,
        resp: Option<&RetryResponse>,
        err: Option<&AttemptError>,
        f: Option<IsRetryableErrorFunc<'_>>,
    ) -> bool {
        let retry = self.is_next_retry_inner(has_opaque_body, resp, err, f);
        self.track_previous_error(err); // defer r.trackPreviousError(err)
        retry
    }

    fn is_next_retry_inner(
        &mut self,
        has_opaque_body: bool,
        resp: Option<&RetryResponse>,
        err: Option<&AttemptError>,
        f: Option<IsRetryableErrorFunc<'_>>,
    ) -> bool {
        if resp.is_none() && err.is_none() {
            return false; // bad input
        }
        if has_opaque_body {
            return false;
        }

        self.attempts += 1;
        self.retry_after = Some(RetryAfter {
            attempt: self.attempts,
            ..Default::default()
        });
        if self.attempts > self.max_retries {
            return false;
        }

        // the error takes precedence over the http response
        let artificial;
        let mut resp = resp;
        let mut err_is_retryable = false;
        if let (Some(f), Some(e)) = (f, err) {
            if f(e) {
                err_is_retryable = true;
                artificial = retry_after_response();
                resp = Some(&artificial);
            }
        }
        if err.is_some() && !err_is_retryable {
            return false;
        }

        let Some(resp) = resp else { return false };
        let Some(seconds) = check_wait(resp) else {
            return false;
        };
        if let Some(ra) = self.retry_after.as_mut() {
            ra.wait = Duration::from_secs(seconds.max(0) as u64);
            ra.reason = get_retry_reason(self.attempts, seconds, resp, err);
        }
        true
    }

    /// `WrapPreviousError` (:281-294).
    pub fn wrap_previous_error<E>(&self, current: Option<E>) -> Option<Wrapped<E>>
    where
        E: fmt::Display,
    {
        let current = current?;
        let Some(prev) = &self.previous_err else {
            return Some(Wrapped::Same(current));
        };
        // same text: no need to wrap
        if current.to_string() == prev.message {
            return Some(Wrapped::Same(current));
        }
        // a url.Error previous error is unwrapped to its inner error
        let previous = prev.inner.clone().unwrap_or_else(|| prev.message.clone());
        Some(Wrapped::Wrapped(WrappedPreviousError { current, previous }))
    }
}

/// `retryAfterSeconds` (request.go:1378): `strconv.Atoi` of the header.
pub fn retry_after_seconds(resp: &RetryResponse) -> Option<i64> {
    resp.retry_after
        .as_deref()
        .filter(|h| !h.is_empty())
        .and_then(|h| h.parse::<i64>().ok())
}

/// `checkWait` (:309): a wait only for 429 and any 5xx, and only when
/// `Retry-After` is a valid integer.
pub fn check_wait(resp: &RetryResponse) -> Option<i64> {
    if resp.status == 429 || resp.status >= 500 {
        retry_after_seconds(resp)
    } else {
        None
    }
}

/// `getRetryReason` (:322-340), strings verbatim.
pub fn get_retry_reason(
    retries: u32,
    seconds: i64,
    resp: &RetryResponse,
    err: Option<&AttemptError>,
) -> String {
    let message = format!("retries: {retries}, retry-after: {seconds}s");
    if resp.status == 429 {
        format!(
            "{message} - retry-reason: due to server-side throttling, FlowSchema UID: {:?}",
            resp.flow_schema_uid
        )
    } else if let Some(e) = err {
        format!("{message} - retry-reason: due to retryable error, error: {e}")
    } else {
        format!("{message} - retry-reason: {}", resp.status)
    }
}
