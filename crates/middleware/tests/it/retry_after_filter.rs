//! Ports of `TestWithRetryAfter` (with_retry_after_test.go) and
//! `TestWithWatchTerminationDuringShutdown` (watch_termination_test.go), plus
//! the `SafeWaitGroup` contract (apimachinery util/waitgroup).
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, Method, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::Response;
use axum::Router;
use kubernetes_rs_middleware::lifecycle::LifecycleSignal;
use kubernetes_rs_middleware::secure_serving::server_filters::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn info(verb: &str) -> RequestInfoFn {
    let verb = verb.to_string();
    Arc::new(move |_| {
        Some(RequestInfoView {
            verb: verb.clone(),
            ..Default::default()
        })
    })
}

async fn call(app: Router, url: &str, ua: &str) -> Response {
    let req = Request::builder()
        .method(Method::GET)
        .uri(url)
        .header(header::USER_AGENT, ua)
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap()
}

fn header_of(r: &Response, name: header::HeaderName) -> String {
    r.headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default()
}

struct Case {
    name: &'static str,
    elapsed: Option<bool>, // None: nil channel
    url: &'static str,
    ua: &'static str,
    waiting: bool,
    invoked: usize,
    close: &'static str,
    retry: &'static str,
    status: StatusCode,
}

#[tokio::test]
async fn retry_after_filter_table() {
    let ok = StatusCode::OK;
    let cases = [
        Case {
            name: "disabled",
            elapsed: Some(false),
            url: "/api/v1/namespaces",
            ua: "foo",
            waiting: false,
            invoked: 1,
            close: "",
            retry: "",
            status: ok,
        },
        Case {
            name: "enabled, not exempt",
            elapsed: Some(true),
            url: "/api/v1/namespaces",
            ua: "foo",
            waiting: false,
            invoked: 0,
            close: "close",
            retry: "5",
            status: StatusCode::TOO_MANY_REQUESTS,
        },
        Case {
            name: "exempt /metrics",
            elapsed: Some(true),
            url: "/metrics?foo=bar",
            ua: "foo",
            waiting: false,
            invoked: 1,
            close: "",
            retry: "",
            status: ok,
        },
        Case {
            name: "exempt /livez",
            elapsed: Some(true),
            url: "/livez?verbose",
            ua: "foo",
            waiting: false,
            invoked: 1,
            close: "",
            retry: "",
            status: ok,
        },
        Case {
            name: "exempt /readyz",
            elapsed: Some(true),
            url: "/readyz?verbose",
            ua: "foo",
            waiting: false,
            invoked: 1,
            close: "",
            retry: "",
            status: ok,
        },
        Case {
            name: "exempt /healthz",
            elapsed: Some(true),
            url: "/healthz?verbose",
            ua: "foo",
            waiting: false,
            invoked: 1,
            close: "",
            retry: "",
            status: ok,
        },
        Case {
            name: "exempt loopback UA",
            elapsed: Some(true),
            url: "/api/v1/namespaces",
            ua: "kube-apiserver/",
            waiting: false,
            invoked: 1,
            close: "",
            retry: "",
            status: ok,
        },
        Case {
            name: "nil channel",
            elapsed: None,
            url: "/api/v1/namespaces",
            ua: "foo",
            waiting: false,
            invoked: 1,
            close: "",
            retry: "",
            status: ok,
        },
        Case {
            name: "exempt /readyz, wait group waiting",
            elapsed: Some(true),
            url: "/readyz?verbose",
            ua: "foo",
            waiting: true,
            invoked: 1,
            close: "",
            retry: "",
            status: ok,
        },
    ];
    for c in cases {
        let invoked = Arc::new(AtomicUsize::new(0));
        let wg = Arc::new(SafeWaitGroup::new());
        if c.waiting {
            // Counter is zero, so this does not block.
            wg.wait().await;
        }
        let signal = LifecycleSignal::new("ShutdownDelayDurationElapsed");
        if c.elapsed == Some(true) {
            signal.signal();
        }
        let wg_state = WaitGroupState {
            request_info: info(""),
            long_running: Arc::new(|_, _| false),
            wg: wg.clone(),
        };
        let ra_state = RetryAfterState {
            shutdown_delay_duration_elapsed: c.elapsed.map(|_| signal.clone()),
        };
        let inv = invoked.clone();
        let app = Router::new()
            .fallback(move || {
                let inv = inv.clone();
                async move {
                    inv.fetch_add(1, Ordering::SeqCst);
                }
            })
            .layer(from_fn(move |req: Request, next: Next| {
                with_wait_group(wg_state.clone(), req, next)
            }))
            .layer(from_fn(move |req: Request, next: Next| {
                with_retry_after(ra_state.clone(), req, next)
            }));
        let r = call(app, c.url, c.ua).await;
        assert_eq!(invoked.load(Ordering::SeqCst), c.invoked, "{}", c.name);
        assert_eq!(r.status(), c.status, "{}", c.name);
        assert_eq!(header_of(&r, header::CONNECTION), c.close, "{}", c.name);
        assert_eq!(header_of(&r, header::RETRY_AFTER), c.retry, "{}", c.name);
    }
}

#[derive(Default)]
struct FakeWg {
    waiting: bool,
    invoked: AtomicUsize,
    inflight: Mutex<i64>,
}

impl RequestWaitGroup for FakeWg {
    fn add(&self, delta: i64) -> Result<(), String> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        if self.waiting {
            return Err("waitgroup is in waiting mode".into());
        }
        *self.inflight.lock().unwrap() += delta;
        Ok(())
    }
    fn done(&self) {
        *self.inflight.lock().unwrap() -= 1;
    }
}

struct FakeSignal;
impl ServerShutdownSignal for FakeSignal {
    fn shutting_down(&self) -> Option<LifecycleSignal> {
        None
    }
}

async fn watch_case(request_info: RequestInfoFn, wg: Arc<FakeWg>) -> (Response, usize, bool) {
    let handled = Arc::new(AtomicUsize::new(0));
    let attached = Arc::new(Mutex::new(false));
    let (h, a) = (handled.clone(), attached.clone());
    let state = WatchTerminationState {
        request_info,
        termination: Arc::new(FakeSignal),
        wg,
    };
    let app = Router::new()
        .fallback(move |req: Request| {
            let (h, a) = (h.clone(), a.clone());
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                *a.lock().unwrap() = req.extensions().get::<ServerShutdownSignalExt>().is_some();
            }
        })
        .layer(from_fn(move |req: Request, next: Next| {
            with_watch_termination_during_shutdown(state.clone(), req, next)
        }));
    let r = call(app, "/apis/groups.k8s.io/v1/namespaces", "x").await;
    let (n, at) = (handled.load(Ordering::SeqCst), *attached.lock().unwrap());
    (r, n, at)
}

#[tokio::test]
async fn retry_after_filter_watch_termination_no_request_info() {
    let wg = Arc::new(FakeWg::default());
    let (r, handled, _) = watch_case(Arc::new(|_| None), wg).await;
    assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(handled, 0);
}

#[tokio::test]
async fn retry_after_filter_watch_termination_not_a_watch() {
    let wg = Arc::new(FakeWg::default());
    let (r, handled, attached) = watch_case(info("get"), wg.clone()).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!((handled, attached), (1, false));
    assert_eq!(wg.invoked.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retry_after_filter_watch_termination_waiting() {
    let wg = Arc::new(FakeWg {
        waiting: true,
        ..Default::default()
    });
    let (r, handled, attached) = watch_case(info("watch"), wg.clone()).await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(header_of(&r, header::RETRY_AFTER), "1");
    assert_eq!(header_of(&r, header::CONTENT_TYPE), "application/json");
    assert_eq!((handled, attached), (0, false));
    assert_eq!(wg.invoked.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn retry_after_filter_watch_termination_accepting() {
    let wg = Arc::new(FakeWg::default());
    let (r, handled, attached) = watch_case(info("watch"), wg.clone()).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!((handled, attached), (1, true));
    assert_eq!(wg.invoked.load(Ordering::SeqCst), 1);
    drop(r);
    assert_eq!(*wg.inflight.lock().unwrap(), 0);
}

#[tokio::test]
async fn retry_after_filter_safe_wait_group() {
    let wg = SafeWaitGroup::new();
    assert!(wg.add(1).is_ok());
    let wg = Arc::new(wg);
    let waiter = {
        let wg = wg.clone();
        tokio::spawn(async move { wg.wait().await })
    };
    tokio::task::yield_now().await;
    // Waiting: positive adds are refused, negative deltas are not.
    for _ in 0..50 {
        if wg.add(1).is_err() {
            break;
        }
        wg.done();
        tokio::task::yield_now().await;
    }
    assert!(wg.add(1).is_err());
    assert!(!waiter.is_finished());
    wg.done();
    waiter.await.unwrap();
}
