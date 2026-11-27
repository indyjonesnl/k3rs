//! `k8s.io/apimachinery/pkg/util/wait` backoff, shared by the webhook-style
//! delegating clients (api-server authorization webhook, kubelet BuildAuth).

use std::sync::Arc;
use std::time::{Duration, Instant};

/// `wait.Backoff`.
#[derive(Debug, Clone)]
pub struct Backoff {
    pub duration: Duration,
    pub factor: f64,
    pub jitter: f64,
    pub steps: i64,
    /// Upper bound on `duration`; zero means no cap (`Backoff.Cap`).
    pub cap: Duration,
}

impl Backoff {
    /// `DefaultAuthWebhookRetryBackoff`
    /// (`apiserver/pkg/server/options/authentication.go:46`) ==
    /// `DefaultRetryBackoffWithInitialDelay(500ms)`.
    pub fn default_auth_webhook() -> Self {
        Self {
            duration: Duration::from_millis(500),
            factor: 1.5,
            jitter: 0.2,
            steps: 5,
            cap: Duration::ZERO,
        }
    }

    /// `Backoff.Step` (`apimachinery/pkg/util/wait/backoff.go`): the next
    /// sleep, then grow, honouring `cap` and `steps` via [`delay`].
    pub fn step(&mut self) -> Duration {
        let (next_duration, duration, steps) = delay(
            self.steps,
            self.duration,
            self.cap,
            self.factor,
            self.jitter,
        );
        self.duration = duration;
        self.steps = steps;
        next_duration
    }

    /// `Backoff.DelayFunc`: a closure over a private copy of the backoff.
    pub fn delay_func(&self) -> impl FnMut() -> Duration + Send + 'static {
        let mut b = self.clone();
        move || b.step()
    }

    /// `Backoff.DelayWithReset` (`backoff.go`): exponential delays that start
    /// over once `reset_interval` has passed since the last reset.
    pub fn delay_with_reset(
        &self,
        clock: Arc<dyn Clock>,
        reset_interval: Duration,
    ) -> Box<dyn FnMut() -> Duration + Send> {
        let mut b = self.clone();
        if b.factor <= 0.0 {
            return Box::new(self.delay_func());
        }
        if reset_interval.is_zero() {
            b.steps = 0;
            b.factor = 0.0;
            return Box::new(b.delay_func());
        }
        let initial = b.clone();
        let mut last_start = clock.now();
        Box::new(move || {
            // backoffManager.Step
            if clock.now().saturating_duration_since(last_start) > reset_interval {
                b = initial.clone();
                last_start = clock.now();
            }
            b.step()
        })
    }
}

/// `wait.Jitter` (`wait.go`): `duration + rand*maxFactor*duration`; a
/// non-positive `max_factor` means 1.0.
pub fn jitter(duration: Duration, max_factor: f64) -> Duration {
    let max_factor = if max_factor <= 0.0 { 1.0 } else { max_factor };
    duration + duration.mul_f64(rand::random::<f64>() * max_factor)
}

/// `delay` (`backoff.go`): returns (sleep, next duration, remaining steps).
/// A `steps` below 1 stops growth; a `cap` that is hit zeroes the steps.
pub fn delay(
    mut steps: i64,
    duration: Duration,
    cap: Duration,
    factor: f64,
    jitter_factor: f64,
) -> (Duration, Duration, i64) {
    if steps < 1 {
        if jitter_factor > 0.0 {
            return (jitter(duration, jitter_factor), duration, 0);
        }
        return (duration, duration, 0);
    }
    steps -= 1;
    let next = if factor != 0.0 {
        let n = duration.mul_f64(factor);
        if !cap.is_zero() && n > cap {
            steps = 0;
            cap
        } else {
            n
        }
    } else {
        duration
    };
    let sleep = if jitter_factor > 0.0 {
        jitter(duration, jitter_factor)
    } else {
        duration
    };
    (sleep, next, steps)
}

/// `k8s.io/utils/clock.Clock` (only `Now`).
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// `clock.RealClock`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// `wait.BackoffManager` (`backoff.go`): yields how long to wait next. Go
/// returns a `clock.Timer`; here the caller sleeps for the returned duration.
pub trait BackoffManager: Send {
    fn backoff(&mut self) -> Duration;
}

/// `exponentialBackoffManagerImpl` / `NewExponentialBackoffManager`.
pub struct ExponentialBackoffManager {
    backoff: Backoff,
    last_backoff_start: Instant,
    initial_backoff: Duration,
    backoff_reset_duration: Duration,
    clock: Arc<dyn Clock>,
}

impl ExponentialBackoffManager {
    pub fn new(
        init_backoff: Duration,
        max_backoff: Duration,
        reset_duration: Duration,
        backoff_factor: f64,
        jitter: f64,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            backoff: Backoff {
                duration: init_backoff,
                factor: backoff_factor,
                jitter,
                steps: i32::MAX as i64,
                cap: max_backoff,
            },
            last_backoff_start: clock.now(),
            initial_backoff: init_backoff,
            backoff_reset_duration: reset_duration,
            clock,
        }
    }

    /// `getNextBackoff`.
    pub fn get_next_backoff(&mut self) -> Duration {
        if self
            .clock
            .now()
            .saturating_duration_since(self.last_backoff_start)
            > self.backoff_reset_duration
        {
            self.backoff.steps = i32::MAX as i64;
            self.backoff.duration = self.initial_backoff;
        }
        self.last_backoff_start = self.clock.now();
        self.backoff.step()
    }
}

impl BackoffManager for ExponentialBackoffManager {
    fn backoff(&mut self) -> Duration {
        self.get_next_backoff()
    }
}

/// `jitteredBackoffManagerImpl` / `NewJitteredBackoffManager`.
pub struct JitteredBackoffManager {
    duration: Duration,
    jitter: f64,
}

impl JitteredBackoffManager {
    pub fn new(duration: Duration, jitter: f64) -> Self {
        Self { duration, jitter }
    }

    /// `getNextBackoff`.
    pub fn get_next_backoff(&self) -> Duration {
        if self.jitter > 0.0 {
            jitter(self.duration, self.jitter)
        } else {
            self.duration
        }
    }
}

impl BackoffManager for JitteredBackoffManager {
    fn backoff(&mut self) -> Duration {
        self.get_next_backoff()
    }
}

/// `wait.ErrWaitTimeout` text.
pub const ERR_WAIT_TIMEOUT: &str = "timed out waiting for the condition";

/// `wait.ExponentialBackoff` (`backoff.go`): run `condition` until it reports
/// done or errors; sleep `backoff.step()` between tries; after the last step
/// return [`ERR_WAIT_TIMEOUT`].
pub fn exponential_backoff<E>(
    mut backoff: Backoff,
    mut condition: impl FnMut() -> Result<bool, E>,
    mut sleep: impl FnMut(Duration),
) -> Result<(), Option<E>> {
    while backoff.steps > 0 {
        match condition() {
            Err(e) => return Err(Some(e)),
            Ok(true) => return Ok(()),
            Ok(false) => {}
        }
        if backoff.steps == 1 {
            break;
        }
        sleep(backoff.step());
    }
    // None == ErrWaitTimeout
    Err(None)
}
