//! Ports of `apimachinery/pkg/util/wait/wait_test.go`: TestBackoff_Step,
//! TestExponentialBackoff, TestExponentialBackoffManagerGetNextBackoff,
//! TestJitteredBackoffManagerGetNextBackoff, TestBackoffDelayWithReset*.

use kubernetes_rs_common::wait::*;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const S: Duration = Duration::from_secs(1);

struct FakeClock(Mutex<Instant>);
impl FakeClock {
    fn step(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
}
impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}
fn fake() -> Arc<FakeClock> {
    Arc::new(FakeClock(Mutex::new(Instant::now())))
}

fn b(duration: Duration, factor: f64, jitter: f64, steps: i64, cap: Duration) -> Backoff {
    Backoff {
        duration,
        factor,
        jitter,
        steps,
        cap,
    }
}

#[test]
fn wait_backoff_step_table() {
    let z = Duration::ZERO;
    let cases: Vec<(Backoff, Vec<Duration>)> = vec![
        (b(S, 0.0, 0.0, -1, z), vec![S, S, S]),
        (b(S, 0.0, 0.0, 0, z), vec![S, S, S]),
        (b(S, 0.0, 0.0, 1, z), vec![S, S, S]),
        (b(S, 1.0, 0.0, 1, z), vec![S, S, S]),
        (b(S, 2.0, 0.0, 3, z), vec![S, 2 * S, 4 * S]),
        (b(S, 2.0, 0.0, 3, 3 * S), vec![S, 2 * S, 3 * S]),
        (b(S, 2.0, 0.5, 2, 3 * S), vec![2 * S, 3 * S, 3 * S]),
        (
            b(S, 2.0, 4.0, 6, z),
            vec![S, 2 * S, 4 * S, 8 * S, 16 * S, 32 * S],
        ),
    ];
    for (init, want) in cases {
        let jitter = init.jitter;
        let mut bo = init.clone();
        for w in want {
            let got = bo.step();
            if jitter > 0.0 {
                let diff = (w.as_secs_f64() - got.as_secs_f64()) / w.as_secs_f64();
                assert!(diff <= jitter + 1e-9, "{got:?} vs {w:?}");
            } else {
                assert_eq!(got, w);
            }
        }
    }
}

#[test]
fn wait_backoff_cap_zeroes_steps() {
    let mut bo = b(S, 2.0, 0.0, 10, 3 * S);
    assert_eq!(bo.step(), S);
    assert_eq!(bo.step(), 2 * S);
    assert_eq!(bo.steps, 0);
    assert_eq!(bo.duration, 3 * S);
}

#[test]
fn wait_backoff_exponential_backoff_semantics() {
    // TestExponentialBackoff: steps=5 and an always-false condition runs 5
    // times, sleeps 4 times, then times out.
    let mut calls = 0;
    let mut sleeps = vec![];
    let r: Result<(), Option<()>> = exponential_backoff(
        b(Duration::from_millis(1), 1.0, 0.0, 5, Duration::ZERO),
        || {
            calls += 1;
            Ok(false)
        },
        |d| sleeps.push(d),
    );
    assert_eq!(r, Err(None));
    assert_eq!(calls, 5);
    assert_eq!(sleeps.len(), 4);
    // done on the 3rd try
    let mut n = 0;
    let r: Result<(), Option<()>> = exponential_backoff(
        b(Duration::from_millis(1), 1.0, 0.0, 5, Duration::ZERO),
        || {
            n += 1;
            Ok(n == 3)
        },
        |_| {},
    );
    assert_eq!(r, Ok(()));
    // error is returned as-is
    let r = exponential_backoff(
        b(Duration::from_millis(1), 1.0, 0.0, 5, Duration::ZERO),
        || Err::<bool, _>("boom"),
        |_| {},
    );
    assert_eq!(r, Err(Some("boom")));
    assert_eq!(ERR_WAIT_TIMEOUT, "timed out waiting for the condition");
}

#[test]
fn wait_backoff_exponential_manager_get_next_backoff() {
    let fc = fake();
    let n = Duration::from_nanos;
    let mut m = ExponentialBackoffManager::new(n(1), n(10), n(10), 2.0, 0.0, fc.clone());
    for want in [1, 2, 4, 8, 10, 10, 10] {
        assert_eq!(m.get_next_backoff(), n(want));
    }
    fc.step(n(11));
    assert_eq!(m.get_next_backoff(), n(1));
}

#[test]
fn wait_backoff_jittered_manager_get_next_backoff() {
    let n = Duration::from_nanos;
    let m = JitteredBackoffManager::new(S, 1.0);
    for _ in 0..5 {
        let d = m.get_next_backoff();
        assert!(d >= S && d <= 2 * S, "{d:?}");
    }
    // negative jitter: fixed backoff
    assert_eq!(
        JitteredBackoffManager::new(n(1), -1.0).get_next_backoff(),
        n(1)
    );
}

#[test]
fn wait_backoff_delay_with_reset_exponential() {
    let fc = fake();
    let n = Duration::from_nanos;
    let mut f = b(n(1), 2.0, 0.0, 10, n(10)).delay_with_reset(fc.clone(), n(10));
    for want in [1, 2, 4, 8, 10, 10, 10] {
        assert_eq!(f(), n(want));
    }
    fc.step(n(11));
    assert_eq!(f(), n(1));
}

#[test]
fn wait_backoff_delay_with_reset_empty_interval_is_fixed() {
    let fc = fake();
    let n = Duration::from_nanos;
    let mut f = b(n(1), 2.0, 0.0, 10, n(10)).delay_with_reset(fc, Duration::ZERO);
    for _ in 0..5 {
        assert_eq!(f(), n(1));
    }
}

#[test]
fn wait_backoff_jitter_bounds() {
    for _ in 0..50 {
        let d = jitter(S, 0.5);
        assert!(d >= S && d <= S + S / 2);
        // non-positive factor means 1.0
        let d = jitter(S, -1.0);
        assert!(d >= S && d <= 2 * S);
    }
}

mod loops {
    use kubernetes_rs_common::wait::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    const MS: Duration = Duration::from_millis(1);

    // TestPollImmediate: immediate runs the condition once first.
    #[tokio::test]
    async fn wait_backoff_poll_immediate_runs_condition_first() {
        let n = Arc::new(AtomicUsize::new(0));
        let c = n.clone();
        let r = poll_until_context_timeout(
            std::future::pending(),
            50 * MS,
            Duration::from_secs(5),
            true,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok::<_, ()>(true))
            },
        )
        .await;
        assert_eq!(r, Ok(()));
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }

    // TestPoll: not immediate waits one interval first.
    #[tokio::test]
    async fn wait_backoff_poll_not_immediate_waits_one_interval() {
        let start = std::time::Instant::now();
        let r = poll_until_context_timeout(
            std::future::pending(),
            30 * MS,
            Duration::from_secs(5),
            false,
            || std::future::ready(Ok::<_, ()>(true)),
        )
        .await;
        assert_eq!(r, Ok(()));
        assert!(start.elapsed() >= 30 * MS);
    }

    // TestPollError.
    #[tokio::test]
    async fn wait_backoff_poll_error_is_returned() {
        let r = poll_until_context_timeout(
            std::future::pending(),
            MS,
            Duration::from_secs(5),
            true,
            || std::future::ready(Err::<bool, _>("boom")),
        )
        .await;
        assert_eq!(r, Err(WaitError::Condition("boom")));
    }

    #[tokio::test]
    async fn wait_backoff_poll_timeout_is_deadline_exceeded() {
        let r = poll_until_context_timeout(std::future::pending(), MS, 20 * MS, false, || {
            std::future::ready(Ok::<_, ()>(false))
        })
        .await;
        assert_eq!(r, Err(WaitError::DeadlineExceeded));
    }

    #[tokio::test]
    async fn wait_backoff_poll_cancel_is_canceled() {
        let r = poll_until_context_cancel(tokio::time::sleep(20 * MS), MS, false, || {
            std::future::ready(Ok::<_, ()>(false))
        })
        .await;
        assert_eq!(r, Err(WaitError::Canceled));
    }

    // TestUntil: f keeps running until stop resolves.
    #[tokio::test]
    async fn wait_backoff_until_runs_until_stop() {
        let n = Arc::new(AtomicUsize::new(0));
        let c = n.clone();
        until(
            move || {
                c.fetch_add(1, Ordering::SeqCst);
                std::future::ready(())
            },
            5 * MS,
            tokio::time::sleep(60 * MS),
        )
        .await;
        assert!(n.load(Ordering::SeqCst) >= 3);
    }

    // TestUntilReturnsImmediately: an already-stopped context never runs f.
    #[tokio::test]
    async fn wait_backoff_until_returns_immediately_when_stopped() {
        let n = Arc::new(AtomicUsize::new(0));
        let c = n.clone();
        non_sliding_until(
            move || {
                c.fetch_add(1, Ordering::SeqCst);
                std::future::ready(())
            },
            5 * MS,
            std::future::ready(()),
        )
        .await;
        assert_eq!(n.load(Ordering::SeqCst), 0);
    }
}
