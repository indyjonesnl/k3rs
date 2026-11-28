//! API server lifecycle signals and shutdown sequencing.
//!
//! Ported from `staging/src/k8s.io/apiserver/pkg/server/lifecycle_signals.go`
//! (release-1.35): `lifecycleSignal`, `lifecycleSignals`,
//! `newLifecycleSignals`, `namedChannelWrapper`; and the `[graceful-termination]`
//! ordering of `preparedGenericAPIServer.RunWithContext`
//! (`genericapiserver.go:525-700`).
//!
//! Library only: no server is wired to these yet (the `WithWaitGroup` and
//! `WithRetryAfter` filters at the end of this file are ready to be layered;
//! the api-server run loop wiring and readyz are follow-ups). The caller supplies the
//! parts of `RunWithContext` that are server specific (running pre-shutdown
//! hooks, waiting for in-flight requests / watches, the listener stopping) as
//! futures in [`ShutdownHooks`]; [`ShutdownSequence::run`] implements the
//! ordering between them.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::debug;

/// A named, idempotent, one-shot event (`namedChannelWrapper`): once signaled
/// it stays signaled and immediately unblocks every waiter. Clones share state.
#[derive(Clone, Debug)]
pub struct LifecycleSignal {
    name: &'static str,
    tx: Arc<watch::Sender<bool>>,
}

impl LifecycleSignal {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            tx: Arc::new(watch::channel(false).0),
        }
    }

    /// `Signal`: idempotent.
    pub fn signal(&self) {
        self.tx.send_replace(true);
    }

    /// Whether the event has occurred (a non-blocking `Signaled()` receive).
    pub fn is_signaled(&self) -> bool {
        *self.tx.borrow()
    }

    /// `Signaled`: completes once the event has been signaled (immediately if
    /// it already was).
    pub async fn signaled(&self) {
        let mut rx = self.tx.subscribe();
        // The sender lives in `self`, so `wait_for` cannot observe a closed channel.
        let _ = rx.wait_for(|signaled| *signaled).await;
    }

    /// `Name`: useful for logging.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

/// `lifecycleSignals`: the events that transpire during the lifecycle of the
/// apiserver.
#[derive(Clone, Debug)]
pub struct LifecycleSignals {
    /// Shutdown has been initiated (the stop signal was received).
    pub shutdown_initiated: LifecycleSignal,
    /// `ShutdownDelayDuration` has elapsed since `shutdown_initiated`.
    pub after_shutdown_delay_duration: LifecycleSignal,
    /// All registered pre-shutdown hooks have finished running.
    pub pre_shutdown_hooks_stopped: LifecycleSignal,
    /// The server no longer accepts new requests; from here on any new
    /// request receives an error.
    pub not_accepting_new_request: LifecycleSignal,
    /// The requests in flight have completed (the signal to shut down the
    /// audit backends).
    pub in_flight_requests_drained: LifecycleSignal,
    /// The HTTP server has stopped listening on the underlying socket.
    pub http_server_stopped_listening: LifecycleSignal,
    /// The readyz endpoint succeeded for the first time.
    pub has_been_ready: LifecycleSignal,
    /// All known HTTP paths have been installed (avoids a 404 for a resource
    /// that exists but whose path is not installed yet).
    pub mux_and_discovery_complete: LifecycleSignal,
}

impl Default for LifecycleSignals {
    fn default() -> Self {
        Self::new()
    }
}

impl LifecycleSignals {
    /// `newLifecycleSignals`.
    pub fn new() -> Self {
        Self {
            shutdown_initiated: LifecycleSignal::new("ShutdownInitiated"),
            after_shutdown_delay_duration: LifecycleSignal::new("AfterShutdownDelayDuration"),
            pre_shutdown_hooks_stopped: LifecycleSignal::new("PreShutdownHooksStopped"),
            not_accepting_new_request: LifecycleSignal::new("NotAcceptingNewRequest"),
            in_flight_requests_drained: LifecycleSignal::new("InFlightRequestsDrained"),
            http_server_stopped_listening: LifecycleSignal::new("HTTPServerStoppedListening"),
            has_been_ready: LifecycleSignal::new("HasBeenReady"),
            mux_and_discovery_complete: LifecycleSignal::new("MuxAndDiscoveryComplete"),
        }
    }

    /// `ShuttingDown`: the signal exported to request handlers to indicate the
    /// server is shutting down (`NotAcceptingNewRequest`).
    pub fn shutting_down(&self) -> &LifecycleSignal {
        &self.not_accepting_new_request
    }
}

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// The server-specific pieces `RunWithContext` waits for.
pub struct ShutdownHooks<E> {
    /// `RunPreShutdownHooks`. `PreShutdownHooksStopped` is signaled when it
    /// finishes, whether or not it failed.
    pub run_pre_shutdown_hooks: BoxFuture<Result<(), E>>,
    /// `NonLongRunningRequestWaitGroup.Wait()`.
    pub non_long_running_requests_drained: BoxFuture<()>,
    /// The `ShutdownWatchTerminationGracePeriod` wait for active watches
    /// (completes immediately when the grace period is not positive).
    pub active_watches_drained: BoxFuture<()>,
    /// The listener stopped (`listenerStoppedCh`).
    pub listener_stopped: BoxFuture<()>,
}

/// The `[graceful-termination]` sequence of `RunWithContext`.
#[derive(Clone, Debug)]
pub struct ShutdownSequence {
    pub signals: LifecycleSignals,
    /// `ShutdownDelayDuration` (upstream default 70s).
    pub shutdown_delay_duration: Duration,
    /// `ShutdownSendRetryAfter`: keep listening (replying 429 + Retry-After)
    /// until the in-flight requests have drained, then stop the HTTP server.
    pub shutdown_send_retry_after: bool,
    /// Signaled when it is time to stop the HTTP server (`stopHTTPServer`):
    /// `NotAcceptingNewRequest`, or `InFlightRequestsDrained` when
    /// `shutdown_send_retry_after`.
    pub stop_http_server: LifecycleSignal,
}

/// `shutdownTimeout` actually handed to the HTTP server: 2s with
/// `ShutdownSendRetryAfter` (genericapiserver.go:582-590), else the configured
/// `ShutdownTimeout`.
pub fn http_server_shutdown_timeout(
    shutdown_send_retry_after: bool,
    shutdown_timeout: Duration,
) -> Duration {
    if shutdown_send_retry_after {
        Duration::from_secs(2)
    } else {
        shutdown_timeout
    }
}

impl ShutdownSequence {
    pub fn new(
        signals: LifecycleSignals,
        shutdown_delay_duration: Duration,
        shutdown_send_retry_after: bool,
    ) -> Self {
        Self {
            signals,
            shutdown_delay_duration,
            shutdown_send_retry_after,
            stop_http_server: LifecycleSignal::new("StopHTTPServer"),
        }
    }

    /// Runs the sequence after `stop` is signaled and returns once the
    /// in-flight requests have drained (`<-drainedCh`), or with the error of
    /// the pre-shutdown hooks. Mirrors the goroutines of `RunWithContext`:
    ///
    /// 1. `stop`: signal `ShutdownInitiated` (readyz goes red), wait
    ///    `shutdown_delay_duration`, signal `AfterShutdownDelayDuration`.
    /// 2. `NotAcceptingNewRequest` once the delay has elapsed AND the
    ///    pre-shutdown hooks have stopped.
    /// 3. After `NotAcceptingNewRequest`: wait for the non-long-running
    ///    requests and the active watches; then `InFlightRequestsDrained`.
    /// 4. The HTTP server is stopped at `NotAcceptingNewRequest`, or at
    ///    `InFlightRequestsDrained` with `shutdown_send_retry_after`.
    pub async fn run<E>(&self, stop: LifecycleSignal, hooks: ShutdownHooks<E>) -> Result<(), E> {
        let s = &self.signals;

        // delayedStopCh
        let (initiated, delayed) = (
            s.shutdown_initiated.clone(),
            s.after_shutdown_delay_duration.clone(),
        );
        let (stop_c, delay) = (stop.clone(), self.shutdown_delay_duration);
        tokio::spawn(async move {
            stop_c.signaled().await;
            initiated.signal();
            debug!(
                name = initiated.name(),
                "[graceful-termination] shutdown event"
            );
            tokio::time::sleep(delay).await;
            delayed.signal();
            debug!(
                name = delayed.name(),
                "[graceful-termination] shutdown event"
            );
        });

        // time to stop the HTTP server
        let (stop_http, trigger) = (
            self.stop_http_server.clone(),
            if self.shutdown_send_retry_after {
                s.in_flight_requests_drained.clone()
            } else {
                s.not_accepting_new_request.clone()
            },
        );
        tokio::spawn(async move {
            trigger.signaled().await;
            stop_http.signal();
        });

        // HTTPServerStoppedListening
        let (stopped_listening, listener_stopped) = (
            s.http_server_stopped_listening.clone(),
            hooks.listener_stopped,
        );
        tokio::spawn(async move {
            listener_stopped.await;
            stopped_listening.signal();
            debug!(
                name = stopped_listening.name(),
                "[graceful-termination] shutdown event"
            );
        });

        // NotAcceptingNewRequest: delay elapsed and pre-shutdown hooks finished
        let (not_accepting, delayed, hooks_done) = (
            s.not_accepting_new_request.clone(),
            s.after_shutdown_delay_duration.clone(),
            s.pre_shutdown_hooks_stopped.clone(),
        );
        tokio::spawn(async move {
            delayed.signaled().await;
            hooks_done.signaled().await;
            not_accepting.signal();
            debug!(
                name = not_accepting.name(),
                "[graceful-termination] shutdown event"
            );
        });

        // drained: non-long-running requests and active watches, both only
        // after NotAcceptingNewRequest
        let (not_accepting, drained) = (
            s.not_accepting_new_request.clone(),
            s.in_flight_requests_drained.clone(),
        );
        let (requests, watches) = (
            hooks.non_long_running_requests_drained,
            hooks.active_watches_drained,
        );
        tokio::spawn(async move {
            not_accepting.signaled().await;
            tokio::join!(requests, watches);
            drained.signal();
            debug!(
                name = drained.name(),
                "[graceful-termination] shutdown event"
            );
        });

        debug!("[graceful-termination] waiting for shutdown to be initiated");
        stop.signaled().await;

        // run shutdown hooks directly; PreShutdownHooksStopped is signaled
        // whether or not they failed
        let result = hooks.run_pre_shutdown_hooks.await;
        s.pre_shutdown_hooks_stopped.signal();
        debug!(
            name = s.pre_shutdown_hooks_stopped.name(),
            "[graceful-termination] pre-shutdown hooks completed"
        );
        result?;

        // wait for all requests in flight to drain
        s.in_flight_requests_drained.signaled().await;
        Ok(())
    }
}

// ---------------------------------------------------------------------
// WithWaitGroup / WithRetryAfter
// ---------------------------------------------------------------------

/// `SafeWaitGroup` (apimachinery/pkg/util/waitgroup/waitgroup.go:25-57): a
/// wait group whose `Add` fails once `Wait` has been called, so a request can
/// never join the group after the drain began.
#[derive(Clone, Default)]
pub struct SafeWaitGroup {
    inner: Arc<WaitGroupInner>,
}

#[derive(Default)]
struct WaitGroupInner {
    /// `(counter, wait)`.
    state: std::sync::Mutex<(usize, bool)>,
    zero: tokio::sync::Notify,
}

/// `Add` after `Wait`: "add with positive delta after Wait is forbidden".
#[derive(Debug, PartialEq, Eq)]
pub struct WaitGroupWaiting;

/// `Add(1)` held until dropped (`Done()`).
pub struct WaitGroupGuard(Arc<WaitGroupInner>);

impl Drop for WaitGroupGuard {
    fn drop(&mut self) {
        let mut st = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        st.0 -= 1;
        if st.0 == 0 {
            self.0.zero.notify_waiters();
        }
    }
}

impl SafeWaitGroup {
    pub fn new() -> Self {
        Self::default()
    }

    /// `Add(1)`: fails once [`Self::wait`] has been called.
    pub fn add(&self) -> Result<WaitGroupGuard, WaitGroupWaiting> {
        let mut st = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.1 {
            return Err(WaitGroupWaiting);
        }
        st.0 += 1;
        Ok(WaitGroupGuard(self.inner.clone()))
    }

    /// `Wait`: forbids further `add`s and blocks until the counter is zero.
    pub async fn wait(&self) {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner()).1 = true;
        loop {
            let notified = self.inner.zero.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.state.lock().unwrap_or_else(|e| e.into_inner()).0 == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// `pathPrefixesExemptFromRetryAfter` (with_retry_after.go:25-31).
const PATH_PREFIXES_EXEMPT_FROM_RETRY_AFTER: [&str; 4] =
    ["/readyz", "/livez", "/healthz", "/metrics"];

/// `isRequestExemptFromRetryAfter` (with_retry_after.go:113-131): the local
/// loopback user agent (`kube-apiserver/`) and the health and metrics paths
/// are neither rejected nor tracked. `WithWaitGroup` and `WithRetryAfter`
/// must use this same function, or the wait group could wait forever.
pub fn is_request_exempt_from_retry_after(req: &axum::extract::Request) -> bool {
    let ua = req
        .headers()
        .get(axum::http::header::USER_AGENT)
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
    /// `shutdownDelayDurationElapsedCh`: `AfterShutdownDelayDuration`.
    pub shutdown_delay_duration_elapsed: LifecycleSignal,
}

/// `WithRetryAfter` (with_retry_after.go:57-110): once the shutdown delay has
/// elapsed, a new request that is not exempt gets `429`, `Retry-After: 5`
/// and `Connection: close`. Use with `axum::middleware::from_fn_with_state`.
pub async fn with_retry_after(
    axum::extract::State(state): axum::extract::State<RetryAfterState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::{header, HeaderValue, StatusCode};
    if !state.shutdown_delay_duration_elapsed.is_signaled()
        || is_request_exempt_from_retry_after(&req)
    {
        return next.run(req).await;
    }
    // http.Error: text/plain body, `nosniff`, trailing newline.
    let mut resp = axum::response::Response::new(axum::body::Body::from(
        "The apiserver is shutting down, please try again later.\n",
    ));
    *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    let h = resp.headers_mut();
    h.insert(header::CONNECTION, HeaderValue::from_static("close"));
    h.insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

/// `LongRunningRequestCheck` over the request.
pub type LongRunningCheck = Arc<dyn Fn(&axum::extract::Request) -> bool + Send + Sync>;

/// State of [`with_wait_group`].
#[derive(Clone)]
pub struct WaitGroupState {
    /// `NonLongRunningRequestWaitGroup`.
    pub wait_group: SafeWaitGroup,
    pub long_running: LongRunningCheck,
}

/// `WithWaitGroup` (waitgroup.go:49-95): every non-long-running request joins
/// the wait group until its handler returns (axum returns at the response
/// head, so a streamed body is not tracked: more permissive than upstream). Once the group is waiting (`WithRetryAfter`
/// has started rejecting), a non-exempt request gets `503` + `Retry-After: 1`
/// with the `apiserver is shutting down` Status; exempt requests are served.
pub async fn with_wait_group(
    axum::extract::State(state): axum::extract::State<WaitGroupState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::{header, HeaderValue, StatusCode};
    if (state.long_running)(&req) {
        return next.run(req).await;
    }
    let _guard = match state.wait_group.add() {
        Ok(g) => g,
        Err(WaitGroupWaiting) => {
            if is_request_exempt_from_retry_after(&req) {
                return next.run(req).await;
            }
            // NewServiceUnavailable("apiserver is shutting down")
            let status = kubernetes_rs_common::types::Status::failure(
                "apiserver is shutting down",
                "ServiceUnavailable",
                503,
            );
            let mut body = serde_json::to_vec(&status).unwrap_or_default();
            body.push(b'\n');
            let mut resp = axum::response::Response::new(axum::body::Body::from(body));
            *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            let h = resp.headers_mut();
            h.insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            h.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            return resp;
        }
    };
    next.run(req).await
}
