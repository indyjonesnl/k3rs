//! Ports of `TestWithRetryAfter`
//! (`apiserver/pkg/server/filters/with_retry_after_test.go:28-185`) and the
//! `SafeWaitGroup` contract (`apimachinery/pkg/util/waitgroup/waitgroup.go`)
//! for the `WithWaitGroup` / `WithRetryAfter` graceful-termination filters.
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::from_fn_with_state,
    routing::get,
    Router,
};
use kubernetes_rs_middleware::lifecycle::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tower::ServiceExt;

fn app(elapsed: &LifecycleSignal, wg: &SafeWaitGroup, invoked: Arc<AtomicUsize>) -> Router {
    let handler = move || {
        let invoked = invoked.clone();
        async move {
            invoked.fetch_add(1, Ordering::SeqCst);
            "ok"
        }
    };
    // WithRetryAfter(WithWaitGroup(handler)): retry-after is the outer filter.
    Router::new()
        .fallback(get(handler))
        .layer(from_fn_with_state(
            WaitGroupState {
                wait_group: wg.clone(),
                long_running: Arc::new(|_| false),
            },
            with_wait_group,
        ))
        .layer(from_fn_with_state(
            RetryAfterState {
                shutdown_delay_duration_elapsed: elapsed.clone(),
            },
            with_retry_after,
        ))
}

struct Case {
    name: &'static str,
    elapsed: bool,
    url: &'static str,
    user_agent: &'static str,
    wg_waiting: bool,
    invoked: usize,
    close: &'static str,
    retry_after: &'static str,
    status: StatusCode,
}

#[tokio::test]
async fn graceful_termination_filters_with_retry_after_table() {
    let cases = [
        Case {
            name: "retry-after disabled",
            elapsed: false,
            url: "/api/v1/namespaces",
            user_agent: "foo",
            wg_waiting: false,
            invoked: 1,
            close: "",
            retry_after: "",
            status: StatusCode::OK,
        },
        Case {
            name: "retry-after enabled, request is not exempt",
            elapsed: true,
            url: "/api/v1/namespaces",
            user_agent: "foo",
            wg_waiting: false,
            invoked: 0,
            close: "close",
            retry_after: "5",
            status: StatusCode::TOO_MANY_REQUESTS,
        },
        Case {
            name: "exempt /metrics",
            elapsed: true,
            url: "/metrics?foo=bar",
            user_agent: "foo",
            wg_waiting: false,
            invoked: 1,
            close: "",
            retry_after: "",
            status: StatusCode::OK,
        },
        Case {
            name: "exempt /livez",
            elapsed: true,
            url: "/livez?verbose",
            user_agent: "foo",
            wg_waiting: false,
            invoked: 1,
            close: "",
            retry_after: "",
            status: StatusCode::OK,
        },
        Case {
            name: "exempt /readyz",
            elapsed: true,
            url: "/readyz?verbose",
            user_agent: "foo",
            wg_waiting: false,
            invoked: 1,
            close: "",
            retry_after: "",
            status: StatusCode::OK,
        },
        Case {
            name: "exempt /healthz",
            elapsed: true,
            url: "/healthz?verbose",
            user_agent: "foo",
            wg_waiting: false,
            invoked: 1,
            close: "",
            retry_after: "",
            status: StatusCode::OK,
        },
        Case {
            name: "exempt local loopback",
            elapsed: true,
            url: "/api/v1/namespaces",
            user_agent: "kube-apiserver/",
            wg_waiting: false,
            invoked: 1,
            close: "",
            retry_after: "",
            status: StatusCode::OK,
        },
        Case {
            name: "exempt /readyz, SafeWaitGroup is waiting",
            elapsed: true,
            url: "/readyz?verbose",
            user_agent: "foo",
            wg_waiting: true,
            invoked: 1,
            close: "",
            retry_after: "",
            status: StatusCode::OK,
        },
    ];
    for c in cases {
        let elapsed = LifecycleSignal::new("AfterShutdownDelayDuration");
        if c.elapsed {
            elapsed.signal();
        }
        let wg = SafeWaitGroup::new();
        if c.wg_waiting {
            wg.wait().await; // counter is zero: does not block
        }
        let invoked = Arc::new(AtomicUsize::new(0));
        let resp = app(&elapsed, &wg, invoked.clone())
            .oneshot(
                Request::builder()
                    .uri(c.url)
                    .header("user-agent", c.user_agent)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            invoked.load(Ordering::SeqCst),
            c.invoked,
            "{}: handler",
            c.name
        );
        assert_eq!(resp.status(), c.status, "{}: status", c.name);
        let hdr = |n: &str| {
            resp.headers()
                .get(n)
                .map(|v| v.to_str().unwrap())
                .unwrap_or("")
        };
        assert_eq!(hdr("connection"), c.close, "{}: Connection", c.name);
        assert_eq!(hdr("retry-after"), c.retry_after, "{}: Retry-After", c.name);
    }
}

#[tokio::test]
async fn graceful_termination_filters_retry_after_body_is_http_error_text() {
    let elapsed = LifecycleSignal::new("AfterShutdownDelayDuration");
    elapsed.signal();
    let resp = app(
        &elapsed,
        &SafeWaitGroup::new(),
        Arc::new(AtomicUsize::new(0)),
    )
    .oneshot(Request::builder().uri("/api").body(Body::empty()).unwrap())
    .await
    .unwrap();
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(
        &body[..],
        b"The apiserver is shutting down, please try again later.\n"
    );
}

#[tokio::test]
async fn graceful_termination_filters_wait_group_waiting_rejects_with_503_retry_after_1() {
    // Retry-After not yet active, but the wait group is waiting (drain began):
    // WithWaitGroup writes the 503 Status itself (waitgroup.go:81-88).
    let elapsed = LifecycleSignal::new("AfterShutdownDelayDuration");
    let wg = SafeWaitGroup::new();
    wg.wait().await;
    let invoked = Arc::new(AtomicUsize::new(0));
    let resp = app(&elapsed, &wg, invoked.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/pods")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers()["retry-after"], "1");
    assert_eq!(resp.headers()["content-type"], "application/json");
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["reason"], "ServiceUnavailable");
    assert_eq!(v["code"], 503);
    assert_eq!(v["message"], "apiserver is shutting down");
}

#[tokio::test]
async fn graceful_termination_filters_long_running_requests_are_not_tracked() {
    let wg = SafeWaitGroup::new();
    wg.wait().await;
    let router = Router::new()
        .fallback(get(|| async { "w" }))
        .layer(from_fn_with_state(
            WaitGroupState {
                wait_group: wg,
                long_running: Arc::new(|r| r.uri().path().ends_with("/watch")),
            },
            with_wait_group,
        ));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/x/watch")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn graceful_termination_filters_safe_wait_group_add_after_wait_is_forbidden() {
    let wg = SafeWaitGroup::new();
    let g = wg.add().unwrap();
    let waiter = {
        let wg = wg.clone();
        tokio::spawn(async move { wg.wait().await })
    };
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(
        !waiter.is_finished(),
        "Wait blocks while a request is in flight"
    );
    assert_eq!(wg.add().err(), Some(WaitGroupWaiting));
    drop(g);
    waiter.await.unwrap();
    assert_eq!(wg.add().err(), Some(WaitGroupWaiting));
}
