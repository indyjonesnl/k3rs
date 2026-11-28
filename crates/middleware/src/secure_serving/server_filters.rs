//! `WithWaitGroup`, `WithRetryAfter` and `WithWatchTerminationDuringShutdown`.
//!
//! Ported from `staging/src/k8s.io/apiserver/pkg/server/filters/`:
//! `waitgroup.go` (`RequestWaitGroup`, `WithWaitGroup`,
//! `waitGroupWriteRetryAfterToResponse`), `with_retry_after.go`
//! (`WithRetryAfter`, `isRequestExemptFromRetryAfter`) and
//! `watch_termination.go` (`WithWatchTerminationDuringShutdown`), plus
//! `apimachinery/pkg/util/waitgroup/waitgroup.go` (`SafeWaitGroup`).
//!
//! Library only: the three filters are not mounted in a handler chain yet.
//! Upstream reads `RequestInfo` from the request context; here the caller
//! supplies it through a [`RequestInfoFn`] (the middleware crate has no
//! `RequestInfo` type of its own). `WithWaitGroup` and `WithRetryAfter` MUST be
//! given the same exemptions (they share [`is_request_exempt_from_retry_after`]),
//! otherwise the wait group could wait forever on a request that is never
//! rejected.

use super::filters::{http_error, internal_error_response};
use crate::lifecycle::LifecycleSignal;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use http_body_util::BodyExt;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

/// Calls `wg.done()` when dropped.
struct DoneGuard(Arc<dyn RequestWaitGroup>);

impl Drop for DoneGuard {
    fn drop(&mut self) {
        self.0.done();
    }
}

/// `defer wg.Done()` around `handler.ServeHTTP`: upstream's call returns only
/// after a streamed (watch) body has been written, so `done` runs when the
/// response body is finished or dropped (client gone), not when the handler
/// returns the response head.
fn guard_response(resp: Response, wg: Arc<dyn RequestWaitGroup>) -> Response {
    let guard = DoneGuard(wg);
    let (parts, body) = resp.into_parts();
    let body = body.map_frame(move |frame| {
        let _alive = &guard;
        frame
    });
    Response::from_parts(parts, Body::new(body))
}

/// The fields of `apirequest.RequestInfo` these filters read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestInfoView {
    pub verb: String,
    pub is_resource_request: bool,
    pub subresource: String,
    pub path: String,
}

/// `apirequest.RequestInfoFrom(ctx)`: `None` is "no RequestInfo in the context".
pub type RequestInfoFn = Arc<dyn Fn(&Request) -> Option<RequestInfoView> + Send + Sync>;

/// `apirequest.LongRunningRequestCheck`.
pub type LongRunningCheck = Arc<dyn Fn(&Request, &RequestInfoView) -> bool + Send + Sync>;

/// `RequestWaitGroup` (waitgroup.go:34-44).
pub trait RequestWaitGroup: Send + Sync {
    /// `Add`: an error means the group is waiting, a positive delta is refused.
    fn add(&self, delta: i64) -> Result<(), String>;
    fn done(&self);
}

#[derive(Default)]
struct SafeWaitGroupState {
    wait: bool,
    count: i64,
}

/// `utilwaitgroup.SafeWaitGroup`: `Add` with a positive delta after `Wait` is
/// an error instead of a race.
#[derive(Default)]
pub struct SafeWaitGroup {
    state: Mutex<SafeWaitGroupState>,
    zero: Notify,
}

impl SafeWaitGroup {
    pub fn new() -> Self {
        Self::default()
    }

    /// `Wait`: refuses further adds, then blocks until the counter is zero.
    pub async fn wait(&self) {
        self.state.lock().unwrap().wait = true;
        loop {
            let notified = self.zero.notified();
            if self.state.lock().unwrap().count <= 0 {
                return;
            }
            notified.await;
        }
    }
}

impl RequestWaitGroup for SafeWaitGroup {
    fn add(&self, delta: i64) -> Result<(), String> {
        let mut s = self.state.lock().unwrap();
        if s.wait && delta > 0 {
            return Err("add with positive delta after Wait is forbidden".to_string());
        }
        s.count += delta;
        if s.count <= 0 {
            self.zero.notify_waiters();
        }
        Ok(())
    }

    fn done(&self) {
        let _ = self.add(-1);
    }
}

/// `pathPrefixesExemptFromRetryAfter` (with_retry_after.go:25-30).
const PATH_PREFIXES_EXEMPT_FROM_RETRY_AFTER: [&str; 4] =
    ["/readyz", "/livez", "/healthz", "/metrics"];

/// `isRequestExemptFromRetryAfter` (with_retry_after.go:107-109): the local
/// loopback user agent or a health/metrics path.
pub fn is_request_exempt_from_retry_after(req: &Request) -> bool {
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    ua.starts_with("kube-apiserver/")
        || PATH_PREFIXES_EXEMPT_FROM_RETRY_AFTER
            .iter()
            .any(|p| req.uri().path().starts_with(p))
}

/// State of [`with_retry_after`].
#[derive(Clone)]
pub struct RetryAfterState {
    /// `shutdownDelayDurationElapsedCh`; `None` is a nil channel (never fires).
    pub shutdown_delay_duration_elapsed: Option<LifecycleSignal>,
}

/// `WithRetryAfter` (with_retry_after.go:65-83, :85-105): once the shutdown
/// delay has elapsed, every non-exempt request gets a 429 with `Retry-After: 5`
/// and `Connection: close`.
pub async fn with_retry_after(state: RetryAfterState, req: Request, next: Next) -> Response {
    let send = state
        .shutdown_delay_duration_elapsed
        .as_ref()
        .is_some_and(|s| s.is_signaled());
    if !send || is_request_exempt_from_retry_after(&req) {
        return next.run(req).await;
    }
    let mut resp = http_error(
        StatusCode::TOO_MANY_REQUESTS,
        "The apiserver is shutting down, please try again later.",
    );
    // `params.TearDownConnection` is always true for the shutdown params.
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    resp
}

/// `waitGroupWriteRetryAfterToResponse` (waitgroup.go:92-99): 503 with
/// `Retry-After: 1` and a v1 `Status` for `NewServiceUnavailable`.
pub fn wait_group_retry_after_response() -> Response {
    let status = serde_json::json!({
        "kind": "Status", "apiVersion": "v1", "metadata": {},
        "status": "Failure", "message": "apiserver is shutting down",
        "reason": "ServiceUnavailable", "code": 503
    });
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(header::RETRY_AFTER, "1")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(format!("{status}\n")))
        .unwrap()
}

/// State of [`with_wait_group`].
#[derive(Clone)]
pub struct WaitGroupState {
    pub request_info: RequestInfoFn,
    pub long_running: LongRunningCheck,
    pub wg: Arc<dyn RequestWaitGroup>,
}

const NO_REQUEST_INFO: &str = "no RequestInfo found in the context";

/// `WithWaitGroup` (waitgroup.go:47-86): non-long-running requests are counted
/// for graceful shutdown; once the group is waiting a non-exempt request is
/// answered with [`wait_group_retry_after_response`].
pub async fn with_wait_group(state: WaitGroupState, req: Request, next: Next) -> Response {
    let Some(info) = (state.request_info)(&req) else {
        return internal_error_response(&req.uri().to_string(), NO_REQUEST_INFO);
    };
    if (state.long_running)(&req, &info) {
        return next.run(req).await;
    }
    if state.wg.add(1).is_err() {
        if is_request_exempt_from_retry_after(&req) {
            return next.run(req).await;
        }
        return wait_group_retry_after_response();
    }
    guard_response(next.run(req).await, state.wg.clone())
}

/// `apirequest.ServerShutdownSignal`.
pub trait ServerShutdownSignal: Send + Sync {
    /// `ShuttingDown()`; `None` is a nil channel.
    fn shutting_down(&self) -> Option<LifecycleSignal>;
}

/// `apirequest.WithServerShutdownSignal`: the request extension the watch
/// handler reads to return as soon as the server starts shutting down.
#[derive(Clone)]
pub struct ServerShutdownSignalExt(pub Arc<dyn ServerShutdownSignal>);

/// State of [`with_watch_termination_during_shutdown`].
#[derive(Clone)]
pub struct WatchTerminationState {
    pub request_info: RequestInfoFn,
    pub termination: Arc<dyn ServerShutdownSignal>,
    pub wg: Arc<dyn RequestWaitGroup>,
}

/// `WithWatchTerminationDuringShutdown` (watch_termination.go:28-65). Upstream
/// returns the handler undecorated when `termination` or `wg` is nil; here
/// those cannot be absent, so the caller simply does not mount the layer.
pub async fn with_watch_termination_during_shutdown(
    state: WatchTerminationState,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(info) = (state.request_info)(&req) else {
        return internal_error_response(&req.uri().to_string(), NO_REQUEST_INFO);
    };
    if info.verb != "watch" {
        return next.run(req).await;
    }
    if state.wg.add(1).is_err() {
        return wait_group_retry_after_response();
    }
    req.extensions_mut()
        .insert(ServerShutdownSignalExt(state.termination.clone()));
    guard_response(next.run(req).await, state.wg.clone())
}
