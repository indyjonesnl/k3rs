//! Per-host exponential backoff for REST requests.
//!
//! Port of staging/src/k8s.io/client-go/rest/urlbackoff.go (`URLBackoff`,
//! `NoBackoff`, `serverIsOverloadedSet`, `maxResponseCode`),
//! util/flowcontrol/backoff.go (`Backoff`: `Get`, `Next`, `Reset`,
//! `IsInBackOffSince`, `IsInBackOffSinceUpdate`, `GC`, `hasExpired`, jitter)
//! and rest/client.go `readExpBackoffConfig` (`KUBE_CLIENT_BACKOFF_BASE`,
//! `KUBE_CLIENT_BACKOFF_DURATION`), release-1.35.
//!
//! Nothing calls this yet; wiring it into the HTTP client is a follow-up.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `k8s.io/utils/clock.Clock` (the parts backoff uses).
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn since(&self, t: Instant) -> Duration {
        self.now().saturating_duration_since(t)
    }
}

/// `clock.RealClock`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// `testingclock.FakeClock`: time only moves on [`FakeClock::step`].
#[derive(Debug, Clone)]
pub struct FakeClock {
    now: Arc<Mutex<Instant>>,
}

impl Default for FakeClock {
    fn default() -> Self {
        Self {
            now: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

impl FakeClock {
    pub fn step(&self, d: Duration) {
        *self.now.lock().unwrap() += d;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.now.lock().unwrap()
    }
}

struct BackoffEntry {
    backoff: Duration,
    last_update: Instant,
}

/// `HasExpiredFunc`: (eventTime, lastUpdate, maxDuration) -> expired.
pub type HasExpiredFunc = Box<dyn Fn(Instant, Instant, Duration) -> bool + Send + Sync>;

/// `flowcontrol.Backoff`.
pub struct Backoff {
    clock: Arc<dyn Clock>,
    /// If `None`, the entry restarts once time since the last update exceeds
    /// 2*maxDuration (`hasExpired`).
    pub has_expired_func: Option<HasExpiredFunc>,
    default_duration: Duration,
    max_duration: Duration,
    per_item_backoff: Mutex<HashMap<String, BackoffEntry>>,
    /// Zero disables jitter (the current upstream behaviour by default).
    max_jitter_factor: f64,
    rng: Mutex<u64>,
}

impl Backoff {
    /// `NewBackOff`.
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self::new_with_jitter(initial, max, 0.0)
    }

    /// `NewBackOffWithJitter`.
    pub fn new_with_jitter(initial: Duration, max: Duration, max_jitter_factor: f64) -> Self {
        Self::with_clock(Arc::new(RealClock), initial, max, max_jitter_factor)
    }

    /// `NewFakeBackOff` / `NewFakeBackOffWithJitter` (`newBackoff`).
    pub fn with_clock(
        clock: Arc<dyn Clock>,
        initial: Duration,
        max: Duration,
        max_jitter_factor: f64,
    ) -> Self {
        // `rand.NewSource(clock.Now().UnixNano())`: any non-zero seed.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1;
        Self {
            clock,
            has_expired_func: None,
            default_duration: initial,
            max_duration: max,
            per_item_backoff: Mutex::new(HashMap::new()),
            max_jitter_factor,
            rng: Mutex::new(seed),
        }
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// `Get`: the current backoff duration (zero when none).
    pub fn get(&self, id: &str) -> Duration {
        self.per_item_backoff
            .lock()
            .unwrap()
            .get(id)
            .map(|e| e.backoff)
            .unwrap_or_default()
    }

    /// `Next`: move the backoff to the next mark, capping at maxDuration.
    pub fn next(&self, id: &str, event_time: Instant) {
        let mut map = self.per_item_backoff.lock().unwrap();
        let expired = match map.get(id) {
            None => true,
            Some(e) => self.has_expired(event_time, e.last_update, self.max_duration),
        };
        if expired {
            let mut backoff = self.default_duration;
            backoff += self.jitter(backoff);
            map.insert(
                id.to_string(),
                BackoffEntry {
                    backoff,
                    last_update: self.clock.now(),
                },
            );
        } else {
            let e = map.get_mut(id).expect("checked above");
            let mut delay = e.backoff * 2; // exponential
            delay += self.jitter(e.backoff); // add some jitter to the delay
            e.backoff = delay.min(self.max_duration);
            e.last_update = self.clock.now();
        }
    }

    /// `Reset`: forget all backoff data for the key.
    pub fn reset(&self, id: &str) {
        self.per_item_backoff.lock().unwrap().remove(id);
    }

    /// `IsInBackOffSince`: the time since `event_time` is within the window.
    pub fn is_in_back_off_since(&self, id: &str, event_time: Instant) -> bool {
        let map = self.per_item_backoff.lock().unwrap();
        let Some(e) = map.get(id) else { return false };
        if self.has_expired(event_time, e.last_update, self.max_duration) {
            return false;
        }
        self.clock.since(event_time) < e.backoff
    }

    /// `IsInBackOffSinceUpdate`: the time since the last update is within
    /// the window.
    pub fn is_in_back_off_since_update(&self, id: &str, event_time: Instant) -> bool {
        let map = self.per_item_backoff.lock().unwrap();
        let Some(e) = map.get(id) else { return false };
        if self.has_expired(event_time, e.last_update, self.max_duration) {
            return false;
        }
        event_time.saturating_duration_since(e.last_update) < e.backoff
    }

    /// `GC`: drop entries that have aged past their expiration.
    pub fn gc(&self) {
        let now = self.clock.now();
        let max = self.max_duration;
        let mut map = self.per_item_backoff.lock().unwrap();
        map.retain(|_, e| !self.has_expired(now, e.last_update, max));
    }

    /// `DeleteEntry`.
    pub fn delete_entry(&self, id: &str) {
        self.per_item_backoff.lock().unwrap().remove(id);
    }

    fn jitter(&self, delay: Duration) -> Duration {
        if self.max_jitter_factor <= 0.0 {
            return Duration::ZERO;
        }
        // xorshift64* -> float in [0,1).
        let mut s = self.rng.lock().unwrap();
        *s ^= *s >> 12;
        *s ^= *s << 25;
        *s ^= *s >> 27;
        let r = (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 / (1u64 << 53) as f64;
        Duration::from_secs_f64(r * self.max_jitter_factor * delay.as_secs_f64())
    }

    /// `hasExpired`: unless overridden, after 2*maxDuration the backoff
    /// factor restarts.
    fn has_expired(&self, event_time: Instant, last_update: Instant, max: Duration) -> bool {
        if let Some(f) = &self.has_expired_func {
            return f(event_time, last_update, max);
        }
        event_time.saturating_duration_since(last_update) > max * 2
    }
}

/// `BackoffManager` / `BackoffManagerWithContext`.
pub trait BackoffManager: Send + Sync {
    /// `UpdateBackoff`: `response_code` 0 means no response (transport error).
    fn update_backoff(&self, actual_url: &reqwest::Url, err: Option<&str>, response_code: u16);
    /// `CalculateBackoff`.
    fn calculate_backoff(&self, actual_url: &reqwest::Url) -> Duration;
}

/// `NoBackoff`: the default when no backoff is configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoBackoff;

impl BackoffManager for NoBackoff {
    fn update_backoff(&self, _: &reqwest::Url, _: Option<&str>, _: u16) {}
    fn calculate_backoff(&self, _: &reqwest::Url) -> Duration {
        Duration::ZERO
    }
}

/// `maxResponseCode` (urlbackoff.go).
const MAX_RESPONSE_CODE: u16 = 499;

/// `serverIsOverloadedSet` has only 429 (urlbackoff.go).
fn server_is_overloaded(code: u16) -> bool {
    code == 429
}

/// `URLBackoff`: per-host semantics on top of [`Backoff`].
pub struct UrlBackoff {
    pub backoff: Backoff,
}

impl UrlBackoff {
    pub fn new(backoff: Backoff) -> Self {
        Self { backoff }
    }

    /// `Disable`: make the backoff trivial (zero).
    pub fn disable(&mut self) {
        self.backoff = Backoff::new(Duration::ZERO, Duration::ZERO);
    }

    /// `baseUrlKey`: the host (with an explicit port), e.g.
    /// `127.0.0.1:8080/api/v2/abcde` -> `127.0.0.1:8080`.
    pub fn base_url_key(raw: &reqwest::Url) -> String {
        let host = raw.host_str().unwrap_or("");
        match raw.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        }
    }

    /// `SleepWithContext`: sleep `d` unless `ctx_done` resolves first.
    pub async fn sleep_with_context<F: Future<Output = ()>>(&self, d: Duration, ctx_done: F) {
        if d.is_zero() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(d) => {}
            _ = ctx_done => {}
        }
    }
}

impl BackoffManager for UrlBackoff {
    fn update_backoff(&self, actual_url: &reqwest::Url, _err: Option<&str>, response_code: u16) {
        let key = Self::base_url_key(actual_url);
        if response_code > MAX_RESPONSE_CODE || server_is_overloaded(response_code) {
            self.backoff.next(&key, self.backoff.clock().now());
            return;
        }
        // Not an overload signal: no backoff required for this URL anymore.
        // (Upstream also logs at V(4) for code >= 300 or err != nil.)
        self.backoff.reset(&key);
    }

    fn calculate_backoff(&self, actual_url: &reqwest::Url) -> Duration {
        self.backoff.get(&Self::base_url_key(actual_url))
    }
}

/// `envBackoffBase` / `envBackoffDuration` (rest/client.go).
pub const ENV_BACKOFF_BASE: &str = "KUBE_CLIENT_BACKOFF_BASE";
pub const ENV_BACKOFF_DURATION: &str = "KUBE_CLIENT_BACKOFF_DURATION";

/// `readExpBackoffConfig` with the two values injected (seconds, as parsed
/// from the environment); `NoBackoff` unless both parse.
pub fn exp_backoff_config(base: Option<&str>, duration: Option<&str>) -> Box<dyn BackoffManager> {
    let parse = |v: Option<&str>| v.and_then(|s| s.parse::<i64>().ok());
    match (parse(base), parse(duration)) {
        (Some(b), Some(d)) => Box::new(UrlBackoff::new(Backoff::new(
            Duration::from_secs(b.max(0) as u64),
            Duration::from_secs(d.max(0) as u64),
        ))),
        _ => Box::new(NoBackoff),
    }
}

/// `readExpBackoffConfig` reading the process environment.
pub fn read_exp_backoff_config() -> Box<dyn BackoffManager> {
    exp_backoff_config(
        std::env::var(ENV_BACKOFF_BASE).ok().as_deref(),
        std::env::var(ENV_BACKOFF_DURATION).ok().as_deref(),
    )
}
