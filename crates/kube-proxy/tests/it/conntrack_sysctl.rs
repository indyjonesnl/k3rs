//! Ports of `TestGetConntrackMax` and `TestSetupConntrack`
//! (`cmd/kube-proxy/app/server_linux_test.go:559-800`, release-1.35) plus the
//! `realConntracker` file handling.

use std::cell::RefCell;

use kubernetes_rs_kube_proxy::config::{Duration, KubeProxyConntrackConfiguration};
use kubernetes_rs_kube_proxy::conntrack_sysctl::*;

#[test]
fn conntrack_sysctl_get_conntrack_max() {
    let cases: [(i32, i32, i64); 4] = [
        // (min, max_per_core, expected) for 4 cores
        (0, 0, 0),
        (1, 67890, 67890 * 4), // use this if Max is 0
        (123456, 1, 123456),   // ensure that Min is considered
        (123456, 0, 0),        // leave system setting
    ];
    for (i, (min, per_core, expected)) in cases.into_iter().enumerate() {
        let cfg = KubeProxyConntrackConfiguration {
            min: Some(min),
            max_per_core: Some(per_core),
            ..Default::default()
        };
        assert_eq!(get_conntrack_max_for_cpus(&cfg, 4), expected, "[{i}]");
    }
}

#[derive(Default)]
struct Fake {
    called: RefCell<Vec<String>>,
    fail: bool,
    read_only: bool,
}

impl Fake {
    fn rec(&self, s: String) -> Result<(), ConntrackError> {
        self.called.borrow_mut().push(s);
        if self.fail {
            return Err(ConntrackError::Other(anyhow::anyhow!("random error")));
        }
        Ok(())
    }
}

impl Conntracker for Fake {
    fn set_max(&self, _max: i64) -> Result<(), ConntrackError> {
        self.called.borrow_mut().push("SetMax".into());
        if self.read_only {
            return Err(ConntrackError::ReadOnlySysFs);
        }
        Ok(())
    }
    fn set_tcp_established_timeout(&self, s: i64) -> Result<(), ConntrackError> {
        self.rec(format!("SetTCPEstablishedTimeout({s})"))
    }
    fn set_tcp_close_wait_timeout(&self, s: i64) -> Result<(), ConntrackError> {
        self.rec(format!("SetTCPCloseWaitTimeout({s})"))
    }
    fn set_tcp_be_liberal(&self, v: i64) -> Result<(), ConntrackError> {
        self.rec(format!("SetTCPBeLiberal({v})"))
    }
    fn set_udp_timeout(&self, s: i64) -> Result<(), ConntrackError> {
        self.rec(format!("SetUDPTimeout({s})"))
    }
    fn set_udp_stream_timeout(&self, s: i64) -> Result<(), ConntrackError> {
        self.rec(format!("SetUDPStreamTimeout({s})"))
    }
}

type C = KubeProxyConntrackConfiguration;

#[test]
fn conntrack_sysctl_setup_conntrack_calls() {
    let cases: Vec<(&str, C, Vec<&str>)> = vec![
        (
            "do nothing if conntrack config is empty",
            C::default(),
            vec![],
        ),
        (
            "SetMax is called if maxPerCore is specified",
            C {
                max_per_core: Some(12),
                ..Default::default()
            },
            vec!["SetMax"],
        ),
        (
            "SetMax is not called if maxPerCore is 0",
            C {
                max_per_core: Some(0),
                ..Default::default()
            },
            vec![],
        ),
        (
            "SetTCPEstablishedTimeout is called if specified",
            C {
                tcp_established_timeout: Some(Duration::secs(5)),
                ..Default::default()
            },
            vec!["SetTCPEstablishedTimeout(5)"],
        ),
        (
            "SetTCPEstablishedTimeout is not called if 0",
            C {
                tcp_established_timeout: Some(Duration::secs(0)),
                ..Default::default()
            },
            vec![],
        ),
        (
            "SetTCPCloseWaitTimeout is called if specified",
            C {
                tcp_close_wait_timeout: Some(Duration::secs(5)),
                ..Default::default()
            },
            vec!["SetTCPCloseWaitTimeout(5)"],
        ),
        (
            "SetTCPCloseWaitTimeout is not called if 0",
            C {
                tcp_close_wait_timeout: Some(Duration::secs(0)),
                ..Default::default()
            },
            vec![],
        ),
        (
            "SetTCPBeLiberal is called if true",
            C {
                tcp_be_liberal: true,
                ..Default::default()
            },
            vec!["SetTCPBeLiberal(1)"],
        ),
        (
            "SetUDPTimeout is called if specified",
            C {
                udp_timeout: Duration::secs(5),
                ..Default::default()
            },
            vec!["SetUDPTimeout(5)"],
        ),
        (
            "SetUDPStreamTimeout is called if specified",
            C {
                udp_stream_timeout: Duration::secs(5),
                ..Default::default()
            },
            vec!["SetUDPStreamTimeout(5)"],
        ),
    ];
    for (name, cfg, expect) in cases {
        let fc = Fake::default();
        setup_conntrack_for_test(&fc, &cfg, 4).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(*fc.called.borrow(), expect, "{name}");
    }
}

#[test]
fn conntrack_sysctl_setup_conntrack_error_is_returned() {
    let fc = Fake {
        fail: true,
        ..Default::default()
    };
    let cfg = C {
        tcp_established_timeout: Some(Duration::secs(5)),
        ..Default::default()
    };
    assert!(setup_conntrack_for_test(&fc, &cfg, 4).is_err());
    assert_eq!(*fc.called.borrow(), ["SetTCPEstablishedTimeout(5)"]);
}

/// `errReadOnlySysFS` from SetMax is ignored (warn only) and the remaining
/// sysctls are still applied.
#[test]
fn conntrack_sysctl_read_only_sysfs_is_a_warning() {
    let fc = Fake {
        read_only: true,
        ..Default::default()
    };
    let cfg = C {
        max_per_core: Some(10),
        tcp_be_liberal: true,
        ..Default::default()
    };
    assert!(setup_conntrack_for_test(&fc, &cfg, 2).unwrap());
    assert_eq!(*fc.called.borrow(), ["SetMax", "SetTCPBeLiberal(1)"]);
}

fn real(dir: &std::path::Path, mounts: &str, hashsize: &str) -> RealConntracker {
    std::fs::create_dir_all(dir.join("proc_sys/net/netfilter")).unwrap();
    std::fs::write(dir.join("hashsize"), hashsize).unwrap();
    std::fs::write(dir.join("mounts"), mounts).unwrap();
    RealConntracker {
        proc_sys: dir.join("proc_sys"),
        hashsize_file: dir.join("hashsize"),
        mounts_file: dir.join("mounts"),
    }
}

#[test]
fn conntrack_sysctl_real_writes_sysctl_and_grows_hashsize() {
    let d = tempfile::tempdir().unwrap();
    let ct = real(d.path(), "sysfs /sys sysfs rw,nosuid 0 0\n", "100\n");
    let nf = d.path().join("proc_sys/net/netfilter");
    ct.set_max(4000).unwrap();
    assert_eq!(
        std::fs::read_to_string(nf.join("nf_conntrack_max")).unwrap(),
        "4000"
    );
    // hashsize 100 < 4000/4: raised to max/4.
    assert_eq!(
        std::fs::read_to_string(d.path().join("hashsize")).unwrap(),
        "1000"
    );
    ct.set_udp_stream_timeout(7).unwrap();
    assert_eq!(
        std::fs::read_to_string(nf.join("nf_conntrack_udp_timeout_stream")).unwrap(),
        "7"
    );
}

#[test]
fn conntrack_sysctl_real_leaves_a_large_enough_hashsize() {
    let d = tempfile::tempdir().unwrap();
    let ct = real(d.path(), "sysfs /sys sysfs ro 0 0\n", "1000\n");
    // hashsize >= max/4: sysfs is not even consulted.
    ct.set_max(4000).unwrap();
    assert_eq!(
        std::fs::read_to_string(d.path().join("hashsize")).unwrap(),
        "1000\n"
    );
}

#[test]
fn conntrack_sysctl_real_read_only_sysfs_and_no_sysfs() {
    let d = tempfile::tempdir().unwrap();
    let ct = real(d.path(), "sysfs /sys sysfs ro,nosuid 0 0\n", "1\n");
    assert!(matches!(
        ct.set_max(4000),
        Err(ConntrackError::ReadOnlySysFs)
    ));
    // The sysctl itself was still written before the hashsize check.
    assert_eq!(
        std::fs::read_to_string(d.path().join("proc_sys/net/netfilter/nf_conntrack_max")).unwrap(),
        "4000"
    );
    let ct = real(d.path(), "proc /proc proc rw 0 0\n", "1\n");
    let e = ct.set_max(4000).unwrap_err();
    assert!(e.to_string().contains("no sysfs mounted"), "{e}");
}
