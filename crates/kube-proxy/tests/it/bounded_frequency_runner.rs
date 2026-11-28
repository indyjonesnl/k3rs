//! Ports of `pkg/proxy/runner/bounded_frequency_runner_test.go` (release-1.35).
//! The fake-clock tests run on tokio's paused clock; the `_RealClock` ones on
//! the real one.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kubernetes_rs_kube_proxy::runner::BoundedFrequencyRunner;
use tokio::sync::{mpsc, oneshot};

/// `receiver`: tracks calls to the managed function.
struct Receiver {
    counter: AtomicI32,
    tx: mpsc::UnboundedSender<i32>,
    result: Mutex<Option<String>>,
}

struct Handle {
    r: Arc<Receiver>,
    rx: mpsc::UnboundedReceiver<i32>,
    stop: Option<oneshot::Sender<()>>,
    runner: Arc<dyn Runs>,
}

trait Runs: Send + Sync {
    fn run(&self);
}
impl<F, Fut> Runs for BoundedFrequencyRunner<F>
where
    F: Fn() -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<(), String>> + Send,
{
    fn run(&self) {
        BoundedFrequencyRunner::run(self)
    }
}

fn start(min: Duration, retry: Duration, max: Duration) -> Handle {
    let (tx, rx) = mpsc::unbounded_channel();
    let r = Arc::new(Receiver {
        counter: AtomicI32::new(0),
        tx,
        result: Mutex::new(None),
    });
    let rr = r.clone();
    let runner = Arc::new(BoundedFrequencyRunner::new(
        "test-runner",
        move || {
            let rr = rr.clone();
            async move {
                let n = rr.counter.fetch_add(1, Ordering::SeqCst) + 1;
                let _ = rr.tx.send(n);
                match rr.result.lock().unwrap().clone() {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            }
        },
        min,
        retry,
        max,
    ));
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let l = runner.clone();
    tokio::spawn(async move {
        l.loop_(async {
            let _ = stop_rx.await;
        })
        .await
    });
    Handle {
        r,
        rx,
        stop: Some(stop_tx),
        runner,
    }
}

impl Handle {
    fn run(&self) {
        self.runner.run();
    }
    fn set_return(&self, e: Option<&str>) {
        *self.r.result.lock().unwrap() = e.map(str::to_string);
    }
    /// Let every ready task run (paused clock: time does not move).
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }
    async fn step(&self, d: Duration) {
        Self::settle().await;
        tokio::time::advance(d).await;
        Self::settle().await;
    }
    /// `assertCalls`: the total call count must now be `expected`.
    async fn assert_calls(&mut self, expected: i32) {
        Self::settle().await;
        let got = self
            .rx
            .try_recv()
            .unwrap_or_else(|_| panic!("expected call {expected}, none happened"));
        assert_eq!(got, expected);
    }
    /// `assertNoCalls`.
    async fn assert_no_calls(&mut self) {
        Self::settle().await;
        if let Ok(n) = self.rx.try_recv() {
            panic!("unexpected function execution (call count: {n})");
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

const MS: fn(u64) -> Duration = Duration::from_millis;
const S: fn(u64) -> Duration = Duration::from_secs;

#[tokio::test(start_paused = true)]
async fn bounded_frequency_runner_min_and_max_interval() {
    let (min, retry, max) = (S(1), S(5), S(10));
    let mut h = start(min, retry, max);

    // Run once, immediately.
    h.run();
    h.assert_calls(1).await;
    // Run again, before minInterval expires. No execution expected.
    h.step(MS(500)).await;
    h.run();
    h.assert_no_calls().await;
    h.step(MS(499)).await;
    h.run();
    h.assert_no_calls().await;
    // Do the deferred run.
    h.step(MS(1)).await;
    h.assert_calls(2).await;

    h.run();
    h.assert_no_calls().await;
    h.step(MS(1)).await;
    h.run();
    h.assert_no_calls().await;
    // Ensure that we don't run again early.
    h.step(MS(998)).await;
    h.assert_no_calls().await;
    // Do the deferred run.
    h.step(MS(1)).await;
    h.assert_calls(3).await;
    // Let minInterval pass, but there are no runs queued.
    h.step(S(1)).await;
    h.assert_no_calls().await;
    // Let maxInterval pass.
    h.step(max).await;
    h.assert_calls(4).await;
    h.step(MS(1)).await;
    h.run();
    h.assert_no_calls().await;
    // Let minInterval pass.
    h.step(MS(999)).await;
    h.assert_calls(5).await;
}

#[tokio::test(start_paused = true)]
async fn bounded_frequency_runner_retry() {
    let (min, retry, max) = (S(1), S(5), S(10));
    let mut h = start(min, retry, max);

    // Run once, immediately, and queue a retry.
    h.set_return(Some("sync error"));
    h.run();
    h.assert_calls(1).await;
    // next run will succeed
    h.set_return(None);
    h.assert_no_calls().await;
    // Nothing happens...
    h.step(min).await;
    h.assert_no_calls().await;
    // After retryInterval, function is called.
    h.step(S(4)).await;
    h.assert_calls(2).await;

    // Run again, before minInterval expires and trigger a retry.
    h.step(MS(499)).await;
    h.set_return(Some("sync error"));
    h.run();
    h.assert_no_calls().await;
    // Do the deferred run, queue another retry after it returns.
    h.step(MS(501)).await;
    h.assert_calls(3).await;
    // next run will succeed
    h.set_return(None);
    h.assert_no_calls().await;
    h.step(S(1)).await;
    h.assert_no_calls().await;
    // Now do another successful that aborts the retry.
    h.run();
    h.assert_calls(4).await;
    // Retry was cancelled because we already ran.
    h.step(S(4)).await;
    h.assert_no_calls().await;
    // New run will trigger a retry.
    h.set_return(Some("sync error"));
    h.run();
    h.assert_calls(5).await;
    // next run will succeed
    h.set_return(None);
    h.assert_no_calls().await;
    // Call Run again before minInterval passes.
    h.step(MS(100)).await;
    h.run();
    h.assert_no_calls().await;
    // Deferred run will run after minInterval passes.
    h.step(MS(900)).await;
    h.assert_calls(6).await;
    // Retry was cancelled because we already ran.
    h.step(S(4)).await;
    h.assert_no_calls().await;
    // Rerun happens after maxInterval.
    h.step(S(5)).await;
    h.assert_no_calls().await;
    h.step(S(1)).await;
    h.assert_calls(7).await;
}

#[tokio::test(start_paused = true)]
async fn bounded_frequency_runner_retry_shorter_than_min_interval() {
    let (min, retry, max) = (S(5), S(1), S(10));
    let mut h = start(min, retry, max);

    h.set_return(Some("sync error"));
    h.run();
    h.assert_calls(1).await;
    h.set_return(None);
    h.assert_no_calls().await;
    // Past retryInterval, but still within minInterval.
    h.step(retry).await;
    h.assert_no_calls().await;
    // Just before minInterval expires.
    h.step(min - retry - MS(1)).await;
    h.assert_no_calls().await;
    // Past minInterval: the retry triggers the run, respecting minInterval.
    h.step(MS(1)).await;
    h.assert_calls(2).await;
    // Let maxInterval pass without any Run() or retry.
    h.step(max).await;
    h.assert_calls(3).await;
}

#[test]
#[should_panic(expected = "maxInterval")]
fn bounded_frequency_runner_max_below_min_panics() {
    let _ = BoundedFrequencyRunner::new("bad", || async { Ok(()) }, S(2), S(1), S(1));
}

/// `_RealClock` tests, with upstream's short intervals.
async fn real_assert_calls(h: &mut Handle, expected: i32) {
    let got = tokio::time::timeout(S(1), h.rx.recv())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for call {expected}"))
        .unwrap();
    assert_eq!(got, expected);
}

async fn real_assert_no_calls(h: &mut Handle) {
    if let Ok(n) = tokio::time::timeout(MS(100), h.rx.recv()).await {
        panic!("unexpected function execution (call count: {n:?})");
    }
}

#[tokio::test]
async fn bounded_frequency_runner_run_again_after_min_interval_real_clock() {
    let min = MS(500);
    let mut h = start(min, MS(800), MS(1500));
    h.run();
    real_assert_calls(&mut h, 1).await;
    tokio::time::sleep(2 * min).await;
    real_assert_no_calls(&mut h).await;
    h.run();
    real_assert_calls(&mut h, 2).await;
}

#[tokio::test]
async fn bounded_frequency_runner_does_not_run_before_min_interval_real_clock() {
    let min = MS(500);
    let mut h = start(min, MS(800), MS(1500));
    h.run();
    real_assert_calls(&mut h, 1).await;
    tokio::time::sleep(min / 4).await;
    h.run();
    real_assert_no_calls(&mut h).await;
}

#[tokio::test]
async fn bounded_frequency_runner_run_after_max_interval_real_clock() {
    let max = MS(500);
    let mut h = start(MS(100), MS(200), max);
    real_assert_no_calls(&mut h).await;
    tokio::time::sleep(max).await;
    real_assert_calls(&mut h, 1).await;
}

#[tokio::test]
async fn bounded_frequency_runner_retry_real_clock() {
    let retry = MS(500);
    let mut h = start(MS(100), retry, S(10));
    h.set_return(Some("sync error"));
    h.run();
    real_assert_calls(&mut h, 1).await;
    tokio::time::sleep(retry / 4).await;
    real_assert_no_calls(&mut h).await;
    tokio::time::sleep(retry).await;
    real_assert_calls(&mut h, 2).await;
    tokio::time::sleep(retry).await;
    real_assert_calls(&mut h, 3).await;
    tokio::time::sleep(retry / 8).await;
    real_assert_no_calls(&mut h).await;
    tokio::time::sleep(retry).await;
    real_assert_calls(&mut h, 4).await;
}
