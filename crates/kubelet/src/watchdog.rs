//! systemd watchdog driven by the kubelet's health checks.
//!
//! Port of `pkg/kubelet/watchdog/watchdog_linux.go` (`NewHealthChecker`,
//! `Start`, `doCheck`, `SetHealthCheckers`) and `types.go`; `SdWatchdogEnabled`
//! and `SdNotify` follow `coreos/go-systemd/v22/daemon` (`watchdog.go`,
//! `sdnotify.go`). Wired in upstream by `cmd/kubelet/app/server.go:606-612`.

use std::future::Future;
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use kubernetes_rs_common::wait::{exponential_backoff, until, Backoff};

/// `daemon.SdNotifyWatchdog`.
pub const SD_NOTIFY_WATCHDOG: &str = "WATCHDOG=1";

/// `minimalNotifyInterval`.
const MINIMAL_NOTIFY_INTERVAL: Duration = Duration::from_secs(1);

/// `WatchdogClient`.
pub trait WatchdogClient: Send + Sync {
    fn sd_watchdog_enabled(&self, unset_environment: bool) -> Result<Duration, String>;
    fn sd_notify(&self, unset_environment: bool) -> Result<bool, String>;
}

/// `DefaultWatchdogClient`: the real systemd functions.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultWatchdogClient;

impl WatchdogClient for DefaultWatchdogClient {
    fn sd_watchdog_enabled(&self, unset_environment: bool) -> Result<Duration, String> {
        sd_watchdog_enabled(unset_environment)
    }
    fn sd_notify(&self, unset_environment: bool) -> Result<bool, String> {
        sd_notify(unset_environment, SD_NOTIFY_WATCHDOG)
    }
}

/// go-systemd `SdWatchdogEnabled`: `WATCHDOG_USEC` is the interval in
/// microseconds, `WATCHDOG_PID` (when set) must be this process.
pub fn sd_watchdog_enabled(unset_environment: bool) -> Result<Duration, String> {
    let wusec = std::env::var("WATCHDOG_USEC").unwrap_or_default();
    let wpid = std::env::var("WATCHDOG_PID").unwrap_or_default();
    if unset_environment {
        std::env::remove_var("WATCHDOG_USEC");
        std::env::remove_var("WATCHDOG_PID");
    }
    if wusec.is_empty() {
        return Ok(Duration::ZERO);
    }
    let s: i64 = wusec
        .parse()
        .map_err(|e| format!("error converting WATCHDOG_USEC: {e}"))?;
    if s <= 0 {
        return Err("error WATCHDOG_USEC must be a positive number".into());
    }
    let interval = Duration::from_micros(s as u64);
    if wpid.is_empty() {
        return Ok(interval);
    }
    let p: i64 = wpid
        .parse()
        .map_err(|e| format!("error converting WATCHDOG_PID: {e}"))?;
    if i64::from(std::process::id()) != p {
        return Ok(Duration::ZERO);
    }
    Ok(interval)
}

/// go-systemd `SdNotify`: write `state` to the datagram socket named by
/// `NOTIFY_SOCKET` (a leading `@` is an abstract socket). `Ok(false)` when
/// the variable is unset.
pub fn sd_notify(unset_environment: bool, state: &str) -> Result<bool, String> {
    let name = std::env::var("NOTIFY_SOCKET").unwrap_or_default();
    if name.is_empty() {
        return Ok(false);
    }
    if unset_environment {
        std::env::remove_var("NOTIFY_SOCKET");
    }
    let sock = UnixDatagram::unbound().map_err(|e| e.to_string())?;
    if let Some(abstract_name) = name.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())
            .map_err(|e| e.to_string())?;
        sock.connect_addr(&addr).map_err(|e| e.to_string())?;
        sock.send(state.as_bytes()).map_err(|e| e.to_string())?;
    } else {
        sock.connect(&name).map_err(|e| e.to_string())?;
        sock.send(state.as_bytes()).map_err(|e| e.to_string())?;
    }
    Ok(true)
}

/// A named health check (`healthz.HealthChecker`).
#[derive(Clone)]
pub struct NamedCheck {
    pub name: String,
    pub check: Arc<dyn Fn() -> Result<(), String> + Send + Sync>,
}

impl NamedCheck {
    pub fn new(name: &str, check: impl Fn() -> Result<(), String> + Send + Sync + 'static) -> Self {
        Self {
            name: name.to_string(),
            check: Arc::new(check),
        }
    }
}

/// `healthChecker`.
pub struct HealthChecker {
    checkers: RwLock<Vec<NamedCheck>>,
    retry_backoff: Backoff,
    interval: Duration,
    watchdog: Arc<dyn WatchdogClient>,
}

impl HealthChecker {
    /// `NewHealthChecker`: errors when the watchdog configuration is wrong; a
    /// disabled watchdog yields a checker whose `start` does nothing.
    pub fn new(watchdog: Arc<dyn WatchdogClient>) -> Result<Self, String> {
        let val = watchdog
            .sd_watchdog_enabled(false)
            .map_err(|e| format!("configure watchdog: {e}"))?;
        if val.is_zero() {
            tracing::info!("Systemd watchdog is not enabled");
            return Ok(Self::disabled(watchdog));
        }
        if val <= MINIMAL_NOTIFY_INTERVAL {
            return Err(format!("configure watchdog timeout too small: {val:?}"));
        }
        Ok(Self {
            checkers: RwLock::new(Vec::new()),
            retry_backoff: Backoff {
                duration: Duration::from_secs(1),
                factor: 2.0,
                jitter: 0.1,
                steps: 2,
                cap: Duration::ZERO,
            },
            interval: val / 2,
            watchdog,
        })
    }

    fn disabled(watchdog: Arc<dyn WatchdogClient>) -> Self {
        Self {
            checkers: RwLock::new(Vec::new()),
            retry_backoff: Backoff {
                duration: Duration::ZERO,
                factor: 0.0,
                jitter: 0.0,
                steps: 0,
                cap: Duration::ZERO,
            },
            interval: Duration::ZERO,
            watchdog,
        }
    }

    /// `SetHealthCheckers`: ping, log and the sync loop check always run,
    /// followed by `checkers`.
    pub fn set_health_checkers(
        &self,
        sync_loop: impl Fn() -> Result<(), String> + Send + Sync + 'static,
        checkers: Vec<NamedCheck>,
    ) {
        let mut combined = vec![
            NamedCheck::new("ping", || Ok(())),
            NamedCheck::new("log", || Ok(())),
            NamedCheck::new("syncloop", sync_loop),
        ];
        combined.extend(checkers);
        *self.checkers.write().unwrap() = combined;
    }

    /// `doCheck`.
    pub fn do_check(&self) -> Result<(), String> {
        for c in self.checkers.read().unwrap().iter() {
            (c.check)().map_err(|e| format!("checker {} failed: {e}", c.name))?;
        }
        Ok(())
    }

    /// The `Start` loop body: check health, then notify systemd with the
    /// retry backoff. `Err` carries what `Start` logs.
    pub fn notify_once(&self) -> Result<(), String> {
        if let Err(e) = self.do_check() {
            tracing::error!(
                "Do not notify watchdog this iteration as the kubelet is reportedly not healthy: {e}"
            );
            return Ok(());
        }
        let r = exponential_backoff(
            self.retry_backoff.clone(),
            || {
                match self.watchdog.sd_notify(false) {
                Err(e) => {
                    tracing::debug!("Failed to notify systemd watchdog, retrying: {e}");
                    Ok(false)
                }
                Ok(false) => Err("failed to notify systemd watchdog, notification not supported - (i.e. NOTIFY_SOCKET is unset)".to_string()),
                Ok(true) => {
                    tracing::debug!("Watchdog plugin notified");
                    Ok(true)
                }
            }
            },
            std::thread::sleep,
        );
        match r {
            Ok(()) => Ok(()),
            Err(Some(e)) => Err(e),
            Err(None) => Err(kubernetes_rs_common::wait::ERR_WAIT_TIMEOUT.to_string()),
        }
    }

    /// `Start`: run `notify_once` every `interval` until `stop` resolves.
    pub fn start(
        self: Arc<Self>,
        stop: impl Future<Output = ()> + Send + 'static,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if self.interval.is_zero() {
            tracing::info!("Systemd watchdog is not enabled or the interval is invalid, so health checking will not be started.");
            return None;
        }
        tracing::info!(
            "Starting systemd watchdog with interval {:?}",
            self.interval
        );
        let interval = self.interval;
        Some(tokio::spawn(async move {
            until(
                move || {
                    let hc = self.clone();
                    async move {
                        // The notify retry sleeps; keep it off the reactor.
                        let r = tokio::task::spawn_blocking(move || hc.notify_once()).await;
                        if let Ok(Err(e)) = r {
                            tracing::error!("Failed to notify watchdog: {e}");
                        }
                    }
                },
                interval,
                stop,
            )
            .await;
        }))
    }
}
