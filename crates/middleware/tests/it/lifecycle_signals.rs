//! Tests for `src/lifecycle.rs`: the lifecycle signals and the
//! `[graceful-termination]` ordering of upstream `RunWithContext`
//! (`staging/src/k8s.io/apiserver/pkg/server/genericapiserver.go`,
//! `lifecycle_signals.go`; release-1.35).

use kubernetes_rs_middleware::lifecycle::*;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::sleep;

const DELAY: Duration = Duration::from_secs(70);

#[tokio::test(start_paused = true)]
async fn lifecycle_signals_names_match_upstream() {
    let s = LifecycleSignals::new();
    let names = [
        (&s.shutdown_initiated, "ShutdownInitiated"),
        (
            &s.after_shutdown_delay_duration,
            "AfterShutdownDelayDuration",
        ),
        (&s.pre_shutdown_hooks_stopped, "PreShutdownHooksStopped"),
        (&s.not_accepting_new_request, "NotAcceptingNewRequest"),
        (&s.in_flight_requests_drained, "InFlightRequestsDrained"),
        (
            &s.http_server_stopped_listening,
            "HTTPServerStoppedListening",
        ),
        (&s.has_been_ready, "HasBeenReady"),
        (&s.mux_and_discovery_complete, "MuxAndDiscoveryComplete"),
    ];
    for (sig, want) in names {
        assert_eq!(sig.name(), want);
        assert!(!sig.is_signaled());
    }
    assert_eq!(s.shutting_down().name(), "NotAcceptingNewRequest");
}

#[tokio::test(start_paused = true)]
async fn lifecycle_signals_signal_is_idempotent_and_unblocks_all_waiters() {
    let sig = LifecycleSignal::new("x");
    let (a, b) = (sig.clone(), sig.clone());
    let w1 = tokio::spawn(async move { a.signaled().await });
    let w2 = tokio::spawn(async move { b.signaled().await });
    sleep(Duration::from_millis(1)).await;
    assert!(!w1.is_finished() && !w2.is_finished());

    sig.signal();
    sig.signal(); // idempotent
    w1.await.unwrap();
    w2.await.unwrap();
    assert!(sig.is_signaled());
    // already signaled: later waiters return immediately
    tokio::time::timeout(Duration::from_millis(1), sig.signaled())
        .await
        .unwrap();
}

struct Harness {
    seq: ShutdownSequence,
    stop: LifecycleSignal,
    hooks_done: Option<oneshot::Sender<Result<(), String>>>,
    requests_done: Option<oneshot::Sender<()>>,
    watches_done: Option<oneshot::Sender<()>>,
    listener_stopped: Option<oneshot::Sender<()>>,
    hooks: Option<ShutdownHooks<String>>,
}

fn harness(send_retry_after: bool) -> Harness {
    let seq = ShutdownSequence::new(LifecycleSignals::new(), DELAY, send_retry_after);
    let (h_tx, h_rx) = oneshot::channel();
    let (r_tx, r_rx) = oneshot::channel();
    let (w_tx, w_rx) = oneshot::channel();
    let (l_tx, l_rx) = oneshot::channel();
    let hooks = ShutdownHooks {
        run_pre_shutdown_hooks: Box::pin(async move { h_rx.await.unwrap() }),
        non_long_running_requests_drained: Box::pin(async move {
            let _ = r_rx.await;
        }),
        active_watches_drained: Box::pin(async move {
            let _ = w_rx.await;
        }),
        listener_stopped: Box::pin(async move {
            let _ = l_rx.await;
        }),
    };
    Harness {
        seq,
        stop: LifecycleSignal::new("Stop"),
        hooks_done: Some(h_tx),
        requests_done: Some(r_tx),
        watches_done: Some(w_tx),
        listener_stopped: Some(l_tx),
        hooks: Some(hooks),
    }
}

#[tokio::test(start_paused = true)]
async fn lifecycle_signals_shutdown_sequence_order() {
    let mut h = harness(false);
    let s = h.seq.signals.clone();

    let seq = h.seq.clone();
    let stop = h.stop.clone();
    let hooks = h.hooks.take().unwrap();
    let run = tokio::spawn(async move { seq.run(stop, hooks).await });

    // Nothing happens before the stop signal.
    sleep(Duration::from_secs(5)).await;
    assert!(!s.shutdown_initiated.is_signaled());

    // T0: ShutdownInitiated; readyz would go red. Pre-shutdown hooks run at once
    // but finish late (after the delay).
    h.stop.signal();
    sleep(Duration::from_secs(1)).await;
    assert!(s.shutdown_initiated.is_signaled());
    assert!(!s.after_shutdown_delay_duration.is_signaled());

    // The hooks finish at T0+80s, after the 70s delay: NotAcceptingNewRequest
    // must wait for BOTH.
    sleep(Duration::from_secs(70)).await;
    assert!(s.after_shutdown_delay_duration.is_signaled());
    assert!(!s.not_accepting_new_request.is_signaled());
    sleep(Duration::from_secs(9)).await;
    h.hooks_done.take().unwrap().send(Ok(())).unwrap();
    sleep(Duration::from_millis(10)).await;
    assert!(s.pre_shutdown_hooks_stopped.is_signaled());
    assert!(s.not_accepting_new_request.is_signaled());
    // Without ShutdownSendRetryAfter the HTTP server stops right away...
    assert!(h.seq.stop_http_server.is_signaled());
    // ...but nothing is drained yet; both waits are needed.
    assert!(!s.in_flight_requests_drained.is_signaled());
    h.requests_done.take().unwrap().send(()).unwrap();
    sleep(Duration::from_millis(10)).await;
    assert!(!s.in_flight_requests_drained.is_signaled());
    h.watches_done.take().unwrap().send(()).unwrap();
    run.await.unwrap().unwrap();
    assert!(s.in_flight_requests_drained.is_signaled());

    h.listener_stopped.take().unwrap().send(()).unwrap();
    sleep(Duration::from_millis(10)).await;
    assert!(s.http_server_stopped_listening.is_signaled());
}

#[tokio::test(start_paused = true)]
async fn lifecycle_signals_send_retry_after_stops_http_server_only_after_drain() {
    // ShutdownSendRetryAfter: keep listening (429 + Retry-After) until the
    // in-flight requests have drained, then stop the HTTP server.
    let mut h = harness(true);
    let s = h.seq.signals.clone();
    let seq = h.seq.clone();
    let stop = h.stop.clone();
    let hooks = h.hooks.take().unwrap();
    let run = tokio::spawn(async move { seq.run(stop, hooks).await });

    h.stop.signal();
    h.hooks_done.take().unwrap().send(Ok(())).unwrap();
    sleep(DELAY + Duration::from_secs(1)).await;
    assert!(s.not_accepting_new_request.is_signaled());
    assert!(!h.seq.stop_http_server.is_signaled());

    h.requests_done.take().unwrap().send(()).unwrap();
    h.watches_done.take().unwrap().send(()).unwrap();
    run.await.unwrap().unwrap();
    sleep(Duration::from_millis(10)).await;
    assert!(s.in_flight_requests_drained.is_signaled());
    assert!(h.seq.stop_http_server.is_signaled());
}

#[tokio::test(start_paused = true)]
async fn lifecycle_signals_pre_shutdown_hook_error_is_returned_and_still_signals() {
    let mut h = harness(false);
    let s = h.seq.signals.clone();
    let seq = h.seq.clone();
    let stop = h.stop.clone();
    let hooks = h.hooks.take().unwrap();
    let run = tokio::spawn(async move { seq.run(stop, hooks).await });

    h.stop.signal();
    h.hooks_done
        .take()
        .unwrap()
        .send(Err("hook failed".to_string()))
        .unwrap();
    assert_eq!(run.await.unwrap().unwrap_err(), "hook failed");
    // PreShutdownHooksStopped is signaled even though the hooks failed.
    assert!(s.pre_shutdown_hooks_stopped.is_signaled());
    assert!(s.shutdown_initiated.is_signaled());
}

#[test]
fn lifecycle_signals_http_server_shutdown_timeout() {
    let configured = Duration::from_secs(60);
    assert_eq!(http_server_shutdown_timeout(false, configured), configured);
    assert_eq!(
        http_server_shutdown_timeout(true, configured),
        Duration::from_secs(2)
    );
}
