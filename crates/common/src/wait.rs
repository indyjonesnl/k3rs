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

// ---------------------------------------------------------------------
// loop.go / poll.go / timer.go
// ---------------------------------------------------------------------

use std::future::Future;
use std::pin::Pin;
use tokio::time::{Instant as TokioInstant, Interval, MissedTickBehavior, Sleep};

/// The failure of a wait loop. Go returns `ctx.Err()` (`context.Canceled` /
/// `context.DeadlineExceeded`) or the condition's own error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitError<E> {
    /// `context.Canceled`.
    Canceled,
    /// `context.DeadlineExceeded`.
    DeadlineExceeded,
    /// The condition returned an error.
    Condition(E),
    /// `wait.ErrWaitTimeout` ([`ERR_WAIT_TIMEOUT`]), returned by the legacy
    /// `Poll*` family and by `ExponentialBackoff*` when the steps run out.
    WaitTimeout,
}

/// `wait.Timer` (`timer.go`): `noopTimer`, `variableTimer`, `fixedTimer`.
pub enum Timer {
    Noop,
    Variable {
        f: Box<dyn FnMut() -> Duration + Send>,
        t: Option<Pin<Box<Sleep>>>,
    },
    Fixed {
        interval: Duration,
        t: Option<Interval>,
    },
}

impl Timer {
    /// `Backoff.Timer`.
    pub fn from_backoff(b: &Backoff) -> Timer {
        if b.steps > 1 || b.jitter != 0.0 {
            return Timer::Variable {
                f: Box::new(b.delay_func()),
                t: None,
            };
        }
        if !b.duration.is_zero() {
            return Timer::Fixed {
                interval: b.duration,
                t: None,
            };
        }
        Timer::Noop
    }

    /// `Timer.C()`: resolves when the timer fires. Cancel safe.
    pub async fn tick(&mut self) {
        match self {
            Timer::Noop => {}
            Timer::Variable { f, t } => {
                let sleep = t.get_or_insert_with(|| Box::pin(tokio::time::sleep(f())));
                sleep.as_mut().await;
            }
            Timer::Fixed { interval, t } => {
                let iv = t.get_or_insert_with(|| {
                    let mut iv =
                        tokio::time::interval_at(TokioInstant::now() + *interval, *interval);
                    // Go tickers drop ticks for slow receivers.
                    iv.set_missed_tick_behavior(MissedTickBehavior::Skip);
                    iv
                });
                iv.tick().await;
            }
        }
    }

    /// `Timer.Next()`.
    pub fn next(&mut self) {
        if let Timer::Variable { f, t: Some(t) } = self {
            t.as_mut().reset(TokioInstant::now() + f());
        }
    }
}

/// `loopConditionUntilContext` (`loop.go`). `done` is the context's
/// cancellation (resolves when cancelled); `deadline` reports whether a
/// resolved `done` means the deadline passed rather than a cancel.
pub async fn loop_condition_until_context<E, Fut>(
    mut done: Pin<&mut impl Future<Output = WaitError<E>>>,
    mut t: Timer,
    immediate: bool,
    sliding: bool,
    mut condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    if immediate {
        match condition().await {
            Err(e) => return Err(WaitError::Condition(e)),
            Ok(true) => return Ok(()),
            Ok(false) => {}
        }
    }
    loop {
        tokio::select! {
            biased;
            err = &mut done => return Err(err),
            _ = t.tick() => {}
        }
        if !sliding {
            t.next();
        }
        match condition().await {
            Err(e) => return Err(WaitError::Condition(e)),
            Ok(true) => return Ok(()),
            Ok(false) => {}
        }
        if sliding {
            t.next();
        }
    }
}

/// `PollUntilContextTimeout` (`poll.go`): poll every `interval` until the
/// condition is done, errors, `cancel` resolves or `timeout` passes.
pub async fn poll_until_context_timeout<E, Fut>(
    cancel: impl Future<Output = ()>,
    interval: Duration,
    timeout: Duration,
    immediate: bool,
    condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    let done = async {
        tokio::select! {
            _ = cancel => WaitError::Canceled,
            _ = tokio::time::sleep(timeout) => WaitError::DeadlineExceeded,
        }
    };
    tokio::pin!(done);
    let t = Timer::from_backoff(&Backoff {
        duration: interval,
        factor: 0.0,
        jitter: 0.0,
        steps: 0,
        cap: Duration::ZERO,
    });
    loop_condition_until_context(done.as_mut(), t, immediate, false, condition).await
}

/// `PollUntilContextCancel` (`poll.go`): no timeout.
pub async fn poll_until_context_cancel<E, Fut>(
    cancel: impl Future<Output = ()>,
    interval: Duration,
    immediate: bool,
    condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    let done = async {
        cancel.await;
        WaitError::Canceled
    };
    tokio::pin!(done);
    let t = Timer::from_backoff(&Backoff {
        duration: interval,
        factor: 0.0,
        jitter: 0.0,
        steps: 0,
        cap: Duration::ZERO,
    });
    loop_condition_until_context(done.as_mut(), t, immediate, false, condition).await
}

/// `BackoffUntilWithContext` / `JitterUntil` / `Until` (`backoff.go`): run
/// `f` repeatedly, waiting `backoff.backoff()` between runs (before `f` when
/// not `sliding`, after it when `sliding`), until `stop` resolves.
pub async fn backoff_until<Fut>(
    mut f: impl FnMut() -> Fut,
    mut backoff: impl BackoffManager,
    sliding: bool,
    stop: impl Future<Output = ()>,
) where
    Fut: Future<Output = ()>,
{
    tokio::pin!(stop);
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => return,
            _ = std::future::ready(()) => {}
        }
        // A non-sliding timer starts before `f` runs, a sliding one after.
        let mut fire_at = TokioInstant::now();
        if !sliding {
            fire_at += backoff.backoff();
        }
        f().await;
        if sliding {
            fire_at = TokioInstant::now() + backoff.backoff();
        }
        tokio::select! {
            _ = &mut stop => return,
            _ = tokio::time::sleep_until(fire_at) => {}
        }
    }
}

/// `JitterUntil` (`backoff.go`).
pub async fn jitter_until<Fut>(
    f: impl FnMut() -> Fut,
    period: Duration,
    jitter_factor: f64,
    sliding: bool,
    stop: impl Future<Output = ()>,
) where
    Fut: Future<Output = ()>,
{
    backoff_until(
        f,
        JitteredBackoffManager::new(period, jitter_factor),
        sliding,
        stop,
    )
    .await
}

/// `Until` (`backoff.go`): `JitterUntil(f, period, 0.0, true, stop)`.
pub async fn until<Fut>(f: impl FnMut() -> Fut, period: Duration, stop: impl Future<Output = ()>)
where
    Fut: Future<Output = ()>,
{
    jitter_until(f, period, 0.0, true, stop).await
}

/// `NonSlidingUntil` (`backoff.go`).
pub async fn non_sliding_until<Fut>(
    f: impl FnMut() -> Fut,
    period: Duration,
    stop: impl Future<Output = ()>,
) where
    Fut: Future<Output = ()>,
{
    jitter_until(f, period, 0.0, false, stop).await
}

/// `ExponentialBackoffWithContext` (`backoff.go:493-518`). `done` is the
/// context's `Err()` future, as in [`loop_condition_until_context`]. The
/// condition runs at most `backoff.steps` times; an error from it ends the
/// loop at once; running out of steps is [`WaitError::WaitTimeout`].
pub async fn exponential_backoff_with_context<E, Fut>(
    done: impl Future<Output = WaitError<E>>,
    mut backoff: Backoff,
    mut condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    tokio::pin!(done);
    while backoff.steps > 0 {
        // `select { case <-ctx.Done(): return ctx.Err(); default: }`
        tokio::select! {
            biased;
            err = &mut done => return Err(err),
            _ = std::future::ready(()) => {}
        }
        match condition().await {
            Err(e) => return Err(WaitError::Condition(e)),
            Ok(true) => return Ok(()),
            Ok(false) => {}
        }
        if backoff.steps == 1 {
            break;
        }
        let wait_before_retry = backoff.step();
        tokio::select! {
            err = &mut done => return Err(err),
            _ = tokio::time::sleep(wait_before_retry) => {}
        }
    }
    Err(WaitError::WaitTimeout)
}

/// `poll` + `poller` + `waitForWithContext` (`poll.go:243-318`, `wait.go`),
/// the engine of the deprecated `Poll*` family. A `timeout` of zero means no
/// timeout. When the timeout passes the condition runs one last time (the
/// closed tick channel still wakes `waitForWithContext`) before
/// [`WaitError::WaitTimeout`]; a cancelled context is `WaitTimeout` too, as
/// the Go code keeps `ErrWaitTimeout` for backward compatibility.
pub async fn poll<E, Fut>(
    cancel: impl Future<Output = ()>,
    immediate: bool,
    interval: Duration,
    timeout: Duration,
    mut condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    tokio::pin!(cancel);
    if immediate {
        match condition().await {
            Err(e) => return Err(WaitError::Condition(e)),
            Ok(true) => return Ok(()),
            Ok(false) => {}
        }
    }
    tokio::select! {
        biased;
        _ = &mut cancel => return Err(WaitError::WaitTimeout),
        _ = std::future::ready(()) => {}
    }
    let mut tick = tokio::time::interval_at(TokioInstant::now() + interval, interval);
    // `poller` drops ticks nobody is ready to receive.
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let after = async {
        if timeout.is_zero() {
            std::future::pending::<()>().await
        } else {
            tokio::time::sleep(timeout).await
        }
    };
    tokio::pin!(after);
    loop {
        let open = tokio::select! {
            _ = &mut cancel => return Err(WaitError::WaitTimeout),
            _ = tick.tick() => true,
            _ = &mut after => false,
        };
        match condition().await {
            Err(e) => return Err(WaitError::Condition(e)),
            Ok(true) => return Ok(()),
            Ok(false) => {}
        }
        if !open {
            return Err(WaitError::WaitTimeout);
        }
    }
}

/// `Poll` / `PollWithContext` (`poll.go:65`, `:84`).
pub async fn poll_with_context<E, Fut>(
    cancel: impl Future<Output = ()>,
    interval: Duration,
    timeout: Duration,
    condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    poll(cancel, false, interval, timeout, condition).await
}

/// `PollUntilWithContext` (`poll.go:110`): no timeout, waits first.
pub async fn poll_until_with_context<E, Fut>(
    cancel: impl Future<Output = ()>,
    interval: Duration,
    condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    poll(cancel, false, interval, Duration::ZERO, condition).await
}

/// `PollInfiniteWithContext` (`poll.go:138`): same as `PollUntilWithContext`.
pub async fn poll_infinite_with_context<E, Fut>(
    cancel: impl Future<Output = ()>,
    interval: Duration,
    condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    poll_until_with_context(cancel, interval, condition).await
}

/// `PollImmediate` / `PollImmediateWithContext` (`poll.go:156`, `:174`).
pub async fn poll_immediate_with_context<E, Fut>(
    cancel: impl Future<Output = ()>,
    interval: Duration,
    timeout: Duration,
    condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    poll(cancel, true, interval, timeout, condition).await
}

/// `PollImmediateUntilWithContext` (`poll.go:199`).
pub async fn poll_immediate_until_with_context<E, Fut>(
    cancel: impl Future<Output = ()>,
    interval: Duration,
    condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    poll(cancel, true, interval, Duration::ZERO, condition).await
}

/// `PollImmediateInfiniteWithContext` (`poll.go:228`).
pub async fn poll_immediate_infinite_with_context<E, Fut>(
    cancel: impl Future<Output = ()>,
    interval: Duration,
    condition: impl FnMut() -> Fut,
) -> Result<(), WaitError<E>>
where
    Fut: Future<Output = Result<bool, E>>,
{
    poll_immediate_until_with_context(cancel, interval, condition).await
}
