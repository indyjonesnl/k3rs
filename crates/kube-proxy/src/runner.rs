//! `BoundedFrequencyRunner`: runs of a work function with a minimum spacing,
//! a retry on failure and a maximum spacing.
//!
//! Ported from `pkg/proxy/runner/bounded_frequency_runner.go` (release-1.35),
//! including the `maxInterval < minInterval` panic, the single combined
//! `nextRunTimer` (max/retry), the "stop the timers, run, reset them" order
//! and the capacity-1 `run` channel that coalesces `Run()` calls. The work
//! function is async here (the proxier syncs without blocking the runtime);
//! a panic in it is caught like upstream's `utilruntime.HandleCrash` and
//! treated as a failed run's retry-less outcome (the loop goes on).
//!
//! Tokio's clock stands in for `clock.Clock`: tests run it paused.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures::FutureExt;
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};

/// `BoundedFrequencyRunner`.
pub struct BoundedFrequencyRunner<F> {
    name: String,
    min_interval: Duration,
    retry_interval: Duration,
    max_interval: Duration,
    run_tx: mpsc::Sender<()>,
    run_rx: std::sync::Mutex<Option<mpsc::Receiver<()>>>,
    f: F,
}

impl<F, Fut> BoundedFrequencyRunner<F>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    /// `NewBoundedFrequencyRunner`: at least `min_interval` between the end of
    /// one run and the start of the next, a run at least every
    /// `max_interval`, and after a failed run another no later than
    /// `retry_interval`.
    ///
    /// Panics when `max_interval < min_interval`, as upstream.
    pub fn new(
        name: &str,
        f: F,
        min_interval: Duration,
        retry_interval: Duration,
        max_interval: Duration,
    ) -> Self {
        assert!(
            max_interval >= min_interval,
            "{name}: maxInterval ({max_interval:?}) must be >= minInterval ({min_interval:?})"
        );
        let (run_tx, run_rx) = mpsc::channel(1);
        Self {
            name: name.to_string(),
            min_interval,
            retry_interval,
            max_interval,
            run_tx,
            run_rx: std::sync::Mutex::new(Some(run_rx)),
            f,
        }
    }

    /// `Run`: run the work function as soon as possible. Once a request is
    /// queued, further calls have no effect until it runs; while `loop_` is
    /// not running the call may be deferred indefinitely.
    pub fn run(&self) {
        // If the channel is empty push an element, otherwise do nothing.
        let _ = self.run_tx.try_send(());
    }

    /// `Loop`: handle the periodic timer and run requests until `stop`
    /// completes. May be called once.
    pub async fn loop_<S: Future<Output = ()>>(&self, stop: S) {
        tracing::debug!(runner = %self.name, "Loop running");
        let mut run_rx = self
            .run_rx
            .lock()
            .unwrap()
            .take()
            .expect("BoundedFrequencyRunner::loop_ called twice");
        tokio::pin!(stop);

        let min_timer = sleep(self.min_interval);
        tokio::pin!(min_timer);
        // The single timer for maxInterval and retryInterval.
        let next_run_timer = sleep(self.max_interval);
        tokio::pin!(next_run_timer);

        loop {
            tokio::select! {
                _ = &mut stop => {
                    tracing::debug!(runner = %self.name, "Loop stopping");
                    return;
                }
                _ = &mut next_run_timer => {}
                _ = run_rx.recv() => {}
            }

            // avoid crashing if the function executed crashes
            let result = AssertUnwindSafe((self.f)()).catch_unwind().await;
            let err = match result {
                Ok(r) => r.err(),
                Err(_) => {
                    tracing::error!(runner = %self.name, "work function panicked");
                    None
                }
            };

            // Determine the next interval based on the result.
            let mut next_interval = self.max_interval;
            if let Some(e) = &err {
                // If error, ensure next run is within retryInterval and
                // maxInterval.
                if self.retry_interval < next_interval {
                    next_interval = self.retry_interval;
                }
                tracing::debug!(runner = %self.name, interval = ?next_interval, error = %e, "scheduling retry");
            }
            // Reset the timers.
            let now = Instant::now();
            min_timer.as_mut().reset(now + self.min_interval);
            next_run_timer.as_mut().reset(now + next_interval);

            // Wait for minInterval before looping.
            tokio::select! {
                _ = &mut stop => {
                    tracing::debug!(runner = %self.name, "Loop stopping");
                    return;
                }
                _ = &mut min_timer => {}
            }
        }
    }
}
