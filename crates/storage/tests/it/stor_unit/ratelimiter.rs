//! Ports of `client-go/util/workqueue/default_rate_limiters_test.go` plus the
//! bucket / default-controller limiter (rate.Limiter semantics).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use kubernetes_rs_storage::ratelimiter::*;

const MS: fn(u64) -> Duration = Duration::from_millis;
const S: fn(u64) -> Duration = Duration::from_secs;

#[test]
fn ratelimiter_item_exponential_failure() {
    let l = ItemExponentialFailureRateLimiter::<&str>::new(MS(1), S(1000));
    for e in [1, 2, 4, 8, 16] {
        assert_eq!(l.when(&"one"), MS(e));
    }
    assert_eq!(l.num_requeues(&"one"), 5);
    assert_eq!(l.when(&"two"), MS(1));
    assert_eq!(l.when(&"two"), MS(2));
    assert_eq!(l.num_requeues(&"two"), 2);
    l.forget(&"one");
    assert_eq!(l.num_requeues(&"one"), 0);
    assert_eq!(l.when(&"one"), MS(1));
}

#[test]
fn ratelimiter_item_exponential_failure_overflow() {
    let l = ItemExponentialFailureRateLimiter::<&str>::new(MS(1), S(1000));
    for _ in 0..5 {
        l.when(&"one");
    }
    assert_eq!(l.when(&"one"), MS(32));
    for _ in 0..1000 {
        l.when(&"overflow1");
    }
    assert_eq!(l.when(&"overflow1"), S(1000));

    let l = ItemExponentialFailureRateLimiter::<&str>::new(S(60), S(1000 * 3600));
    for _ in 0..2 {
        l.when(&"two");
    }
    assert_eq!(l.when(&"two"), S(240));
    for _ in 0..1000 {
        l.when(&"overflow2");
    }
    assert_eq!(l.when(&"overflow2"), S(1000 * 3600));
}

#[test]
fn ratelimiter_item_fast_slow() {
    let l = ItemFastSlowRateLimiter::<&str>::new(MS(5), S(10), 3);
    for _ in 0..3 {
        assert_eq!(l.when(&"one"), MS(5));
    }
    assert_eq!(l.when(&"one"), S(10));
    assert_eq!(l.when(&"one"), S(10));
    assert_eq!(l.num_requeues(&"one"), 5);
    assert_eq!(l.when(&"two"), MS(5));
    assert_eq!(l.when(&"two"), MS(5));
    assert_eq!(l.num_requeues(&"two"), 2);
    l.forget(&"one");
    assert_eq!(l.num_requeues(&"one"), 0);
    assert_eq!(l.when(&"one"), MS(5));
}

#[test]
fn ratelimiter_max_of() {
    let l = MaxOfRateLimiter::<&str>::new(vec![
        Box::new(ItemFastSlowRateLimiter::new(MS(5), S(3), 3)),
        Box::new(ItemExponentialFailureRateLimiter::new(MS(1), S(1))),
    ]);
    for _ in 0..3 {
        assert_eq!(l.when(&"one"), MS(5));
    }
    assert_eq!(l.when(&"one"), S(3));
    assert_eq!(l.when(&"one"), S(3));
    assert_eq!(l.num_requeues(&"one"), 5);
    assert_eq!(l.when(&"two"), MS(5));
    assert_eq!(l.when(&"two"), MS(5));
    assert_eq!(l.num_requeues(&"two"), 2);
    l.forget(&"one");
    assert_eq!(l.num_requeues(&"one"), 0);
    assert_eq!(l.when(&"one"), MS(5));
}

/// `StepRateLimiter` from the upstream test file.
struct Step {
    count: Mutex<usize>,
    base: Duration,
    max: Duration,
    threshold: usize,
}

impl RateLimiter<usize> for Step {
    fn when(&self, _: &usize) -> Duration {
        let mut c = self.count.lock().unwrap();
        *c += 1;
        if *c <= self.threshold {
            self.base
        } else {
            self.max
        }
    }
    fn forget(&self, _: &usize) {}
    fn num_requeues(&self, _: &usize) -> usize {
        0
    }
}

#[test]
fn ratelimiter_with_max_wait() {
    let l = WithMaxWaitRateLimiter::new(
        Box::new(Step {
            count: Mutex::new(0),
            base: MS(5),
            max: S(1000),
            threshold: 100,
        }),
        S(500),
    );
    for i in 0..100 {
        assert_eq!(l.when(&i), MS(5));
    }
    for i in 100..200 {
        assert_eq!(l.when(&i), S(500));
    }
}

/// rate.NewLimiter(10, 100): the burst is free, then each token costs 100ms.
#[test]
fn ratelimiter_bucket_burst_then_delay() {
    let b = BucketRateLimiter::new(10.0, 100);
    let t0 = Instant::now();
    for _ in 0..100 {
        assert_eq!(b.reserve_at(t0), Duration::ZERO);
    }
    let d = b.reserve_at(t0);
    assert!((d.as_secs_f64() - 0.1).abs() < 1e-6, "{d:?}");
    // Reserve takes the token even when it must wait: the next waits longer.
    let d = b.reserve_at(t0);
    assert!((d.as_secs_f64() - 0.2).abs() < 1e-6, "{d:?}");
    // After a second the debt of 2 tokens is repaid and 10 tokens accrued.
    let d = b.reserve_at(t0 + S(1));
    assert!(
        (d.as_secs_f64() - 0.1).abs() < 1e-6 || d == Duration::ZERO,
        "{d:?}"
    );
}

/// DefaultTypedControllerRateLimiter: exponential 5ms/1000s under the bucket.
#[test]
fn ratelimiter_default_controller() {
    let l = default_controller_rate_limiter::<String>();
    let a = "a".to_string();
    assert_eq!(l.when(&a), MS(5));
    assert_eq!(l.when(&a), MS(10));
    assert_eq!(l.num_requeues(&a), 2);
    l.forget(&a);
    assert_eq!(l.num_requeues(&a), 0);
    // 100 burst tokens are used up by distinct items, then the bucket wins.
    for i in 0..200 {
        l.when(&format!("k{i}"));
    }
    assert!(l.when(&"late".to_string()) > MS(1000));
}
