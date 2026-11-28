//! Ports of `pkg/kubelet/watchdog/watchdog_linux_test.go`:
//! TestNewHealthChecker and the TestHealthCheckerStart cases (asserted on
//! `notify_once` outcomes and call counts rather than log text).

use kubernetes_rs_kubelet::watchdog::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Mock {
    enabled: Duration,
    enabled_err: Option<String>,
    ack: bool,
    notify_err: Option<String>,
    notifies: AtomicUsize,
}

impl Mock {
    fn new(enabled: Duration, ack: bool, notify_err: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            enabled,
            enabled_err: None,
            ack,
            notify_err: notify_err.map(String::from),
            notifies: AtomicUsize::new(0),
        })
    }
}

impl WatchdogClient for Mock {
    fn sd_watchdog_enabled(&self, _: bool) -> Result<Duration, String> {
        match &self.enabled_err {
            Some(e) => Err(e.clone()),
            None => Ok(self.enabled),
        }
    }
    fn sd_notify(&self, _: bool) -> Result<bool, String> {
        self.notifies.fetch_add(1, Ordering::SeqCst);
        match &self.notify_err {
            Some(e) => Err(e.clone()),
            None => Ok(self.ack),
        }
    }
}

const INTERVAL: Duration = Duration::from_secs(4);

#[test]
fn watchdog_new_health_checker() {
    assert!(HealthChecker::new(Mock::new(INTERVAL, true, None)).is_ok());
    assert!(HealthChecker::new(Mock::new(Duration::ZERO, true, None)).is_ok());
    let mut m = Mock::new(INTERVAL, true, None);
    Arc::get_mut(&mut m).unwrap().enabled_err = Some("mock error".into());
    assert_eq!(
        HealthChecker::new(m).err().unwrap(),
        "configure watchdog: mock error"
    );
    assert_eq!(
        HealthChecker::new(Mock::new(Duration::from_secs(1), true, None))
            .err()
            .unwrap(),
        "configure watchdog timeout too small: 1s"
    );
}

#[test]
fn watchdog_notify_succeeds() {
    let m = Mock::new(INTERVAL, true, None);
    let hc = HealthChecker::new(m.clone()).unwrap();
    hc.set_health_checkers(|| Ok(()), vec![]);
    assert_eq!(hc.notify_once(), Ok(()));
    assert_eq!(m.notifies.load(Ordering::SeqCst), 1);
}

#[test]
fn watchdog_notify_not_supported_when_no_ack() {
    let m = Mock::new(INTERVAL, false, None);
    let hc = HealthChecker::new(m).unwrap();
    hc.set_health_checkers(|| Ok(()), vec![]);
    let e = hc.notify_once().unwrap_err();
    assert!(e.contains("notification not supported"), "{e}");
}

#[test]
fn watchdog_notify_transmission_failure_retries_then_fails() {
    let m = Mock::new(INTERVAL, false, Some("mock notify error"));
    let hc = HealthChecker::new(m.clone()).unwrap();
    hc.set_health_checkers(|| Ok(()), vec![]);
    let e = hc.notify_once().unwrap_err();
    assert_eq!(e, "timed out waiting for the condition");
    // steps=2: two attempts
    assert_eq!(m.notifies.load(Ordering::SeqCst), 2);
}

#[test]
fn watchdog_unhealthy_does_not_notify() {
    let m = Mock::new(INTERVAL, true, None);
    let hc = HealthChecker::new(m.clone()).unwrap();
    hc.set_health_checkers(|| Err("mock healthy error".into()), vec![]);
    assert_eq!(
        hc.do_check().unwrap_err(),
        "checker syncloop failed: mock healthy error"
    );
    assert_eq!(hc.notify_once(), Ok(()));
    assert_eq!(m.notifies.load(Ordering::SeqCst), 0);
}

#[test]
fn watchdog_no_checkers_notifies() {
    let m = Mock::new(INTERVAL, true, None);
    let hc = HealthChecker::new(m.clone()).unwrap();
    assert_eq!(hc.notify_once(), Ok(()));
    assert_eq!(m.notifies.load(Ordering::SeqCst), 1);
}

#[test]
fn watchdog_sd_notify_unset_socket_is_false() {
    // NOTIFY_SOCKET is unset in the test environment.
    if std::env::var("NOTIFY_SOCKET").is_err() {
        assert_eq!(sd_notify(false, SD_NOTIFY_WATCHDOG), Ok(false));
    }
}

#[test]
fn watchdog_sd_notify_writes_to_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notify.sock");
    let srv = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
    srv.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    std::env::set_var("NOTIFY_SOCKET", &path);
    assert_eq!(sd_notify(true, SD_NOTIFY_WATCHDOG), Ok(true));
    assert!(std::env::var("NOTIFY_SOCKET").is_err());
    let mut buf = [0u8; 32];
    let n = srv.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"WATCHDOG=1");
}

#[tokio::test]
async fn watchdog_start_disabled_is_noop() {
    let hc = Arc::new(HealthChecker::new(Mock::new(Duration::ZERO, true, None)).unwrap());
    assert!(hc.start(std::future::pending()).is_none());
}
