//! workqueue rate limiters.
//!
//! Port of `staging/src/k8s.io/client-go/util/workqueue/default_rate_limiters.go`
//! (release-1.35): `TypedRateLimiter` (:28), `DefaultTypedControllerRateLimiter`
//! (:44), `TypedBucketRateLimiter` (:59), `TypedItemExponentialFailureRateLimiter`
//! (:82), `TypedItemFastSlowRateLimiter` (:153), `TypedMaxOfRateLimiter` (:213)
//! and `TypedWithMaxWaitRateLimiter` (:263). The bucket reproduces
//! `rate.Limiter.Reserve().Delay()` (golang.org/x/time/rate).

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `TypedRateLimiter` (default_rate_limiters.go:28).
pub trait RateLimiter<T>: Send + Sync {
    /// How long to wait before `item` is processed again.
    fn when(&self, item: &T) -> Duration;
    /// Stop tracking `item` (it is not retried any more).
    fn forget(&self, item: &T);
    /// How many times `item` was requeued.
    fn num_requeues(&self, item: &T) -> usize;
}

/// `TypedBucketRateLimiter` (:59): an overall token bucket, `rate.NewLimiter`.
pub struct BucketRateLimiter {
    qps: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl BucketRateLimiter {
    /// `rate.NewLimiter(rate.Limit(qps), burst)`: starts full.
    pub fn new(qps: f64, burst: u32) -> Self {
        Self {
            qps,
            burst: f64::from(burst),
            state: Mutex::new((f64::from(burst), Instant::now())),
        }
    }

    /// `Limiter.Reserve().Delay()` at `now`: take one token (even when none is
    /// available) and report how long until it exists.
    pub fn reserve_at(&self, now: Instant) -> Duration {
        let mut st = self.state.lock().unwrap();
        let elapsed = now.saturating_duration_since(st.1).as_secs_f64();
        st.0 = (st.0 + elapsed * self.qps).min(self.burst);
        st.1 = now;
        st.0 -= 1.0;
        if st.0 >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-st.0 / self.qps)
        }
    }
}

impl<T> RateLimiter<T> for BucketRateLimiter {
    fn when(&self, _item: &T) -> Duration {
        self.reserve_at(Instant::now())
    }
    fn forget(&self, _item: &T) {}
    fn num_requeues(&self, _item: &T) -> usize {
        0
    }
}

/// `TypedItemExponentialFailureRateLimiter` (:82): `base * 2^failures`, capped.
pub struct ItemExponentialFailureRateLimiter<T> {
    failures: Mutex<HashMap<T, usize>>,
    base_delay: Duration,
    max_delay: Duration,
}

impl<T: Eq + Hash> ItemExponentialFailureRateLimiter<T> {
    /// `NewTypedItemExponentialFailureRateLimiter`.
    pub fn new(base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
            base_delay,
            max_delay,
        }
    }

    /// `DefaultTypedItemBasedRateLimiter` (:110): 1ms base, 1000s max.
    pub fn default_item_based() -> Self {
        Self::new(Duration::from_millis(1), Duration::from_secs(1000))
    }
}

impl<T: Eq + Hash + Clone + Send + Sync> RateLimiter<T> for ItemExponentialFailureRateLimiter<T> {
    fn when(&self, item: &T) -> Duration {
        let mut f = self.failures.lock().unwrap();
        let exp = *f.get(item).unwrap_or(&0);
        f.insert(item.clone(), exp + 1);
        // float64(base ns) * 2^exp; beyond MaxInt64 (or max) is maxDelay.
        let backoff =
            self.base_delay.as_nanos() as f64 * 2f64.powi(i32::try_from(exp).unwrap_or(i32::MAX));
        if backoff > i64::MAX as f64 {
            return self.max_delay;
        }
        let calculated = Duration::from_nanos(backoff as u64);
        calculated.min(self.max_delay)
    }
    fn forget(&self, item: &T) {
        self.failures.lock().unwrap().remove(item);
    }
    fn num_requeues(&self, item: &T) -> usize {
        *self.failures.lock().unwrap().get(item).unwrap_or(&0)
    }
}

/// `TypedItemFastSlowRateLimiter` (:153): `fast_delay` for the first
/// `max_fast_attempts`, then `slow_delay`.
pub struct ItemFastSlowRateLimiter<T> {
    failures: Mutex<HashMap<T, usize>>,
    max_fast_attempts: usize,
    fast_delay: Duration,
    slow_delay: Duration,
}

impl<T: Eq + Hash> ItemFastSlowRateLimiter<T> {
    /// `NewTypedItemFastSlowRateLimiter(fastDelay, slowDelay, maxFastAttempts)`.
    pub fn new(fast_delay: Duration, slow_delay: Duration, max_fast_attempts: usize) -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
            max_fast_attempts,
            fast_delay,
            slow_delay,
        }
    }
}

impl<T: Eq + Hash + Clone + Send + Sync> RateLimiter<T> for ItemFastSlowRateLimiter<T> {
    fn when(&self, item: &T) -> Duration {
        let mut f = self.failures.lock().unwrap();
        let n = f.entry(item.clone()).or_insert(0);
        *n += 1;
        if *n <= self.max_fast_attempts {
            self.fast_delay
        } else {
            self.slow_delay
        }
    }
    fn forget(&self, item: &T) {
        self.failures.lock().unwrap().remove(item);
    }
    fn num_requeues(&self, item: &T) -> usize {
        *self.failures.lock().unwrap().get(item).unwrap_or(&0)
    }
}

/// `TypedMaxOfRateLimiter` (:213): the worst (longest) of its limiters.
pub struct MaxOfRateLimiter<T> {
    limiters: Vec<Box<dyn RateLimiter<T>>>,
}

impl<T> MaxOfRateLimiter<T> {
    /// `NewTypedMaxOfRateLimiter`.
    pub fn new(limiters: Vec<Box<dyn RateLimiter<T>>>) -> Self {
        Self { limiters }
    }
}

impl<T: Send + Sync> RateLimiter<T> for MaxOfRateLimiter<T> {
    /// Every limiter is consulted (and so advanced); the maximum wins.
    fn when(&self, item: &T) -> Duration {
        self.limiters
            .iter()
            .map(|l| l.when(item))
            .fold(Duration::ZERO, Duration::max)
    }
    fn forget(&self, item: &T) {
        self.limiters.iter().for_each(|l| l.forget(item));
    }
    fn num_requeues(&self, item: &T) -> usize {
        self.limiters
            .iter()
            .map(|l| l.num_requeues(item))
            .max()
            .unwrap_or(0)
    }
}

/// `TypedWithMaxWaitRateLimiter` (:263): caps another limiter's delay.
pub struct WithMaxWaitRateLimiter<T> {
    limiter: Box<dyn RateLimiter<T>>,
    max_delay: Duration,
}

impl<T> WithMaxWaitRateLimiter<T> {
    /// `NewTypedWithMaxWaitRateLimiter`.
    pub fn new(limiter: Box<dyn RateLimiter<T>>, max_delay: Duration) -> Self {
        Self { limiter, max_delay }
    }
}

impl<T: Send + Sync> RateLimiter<T> for WithMaxWaitRateLimiter<T> {
    fn when(&self, item: &T) -> Duration {
        self.limiter.when(item).min(self.max_delay)
    }
    fn forget(&self, item: &T) {
        self.limiter.forget(item);
    }
    fn num_requeues(&self, item: &T) -> usize {
        self.limiter.num_requeues(item)
    }
}

/// `DefaultTypedControllerRateLimiter` (:44): the max of a per-item
/// exponential back-off (5ms .. 1000s) and an overall bucket (10 qps, burst 100).
pub fn default_controller_rate_limiter<T>() -> MaxOfRateLimiter<T>
where
    T: Eq + Hash + Clone + Send + Sync + 'static,
{
    MaxOfRateLimiter::new(vec![
        Box::new(ItemExponentialFailureRateLimiter::<T>::new(
            Duration::from_millis(5),
            Duration::from_secs(1000),
        )),
        Box::new(BucketRateLimiter::new(10.0, 100)),
    ])
}
