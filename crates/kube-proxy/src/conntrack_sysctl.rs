//! Conntrack sysctl tuning at start-up.
//!
//! Ported from `cmd/kube-proxy/app/conntrack.go` (`Conntracker`,
//! `realConntracker`, `errReadOnlySysFS`, `isSysFSWritable`) and
//! `cmd/kube-proxy/app/server_linux.go` (`setupConntrack` :299,
//! `getConntrackMax` :356, `detectNumCPU` :373), release-1.35.
//!
//! Descriptions of the sysctls:
//! <https://www.kernel.org/doc/Documentation/networking/nf_conntrack-sysctl.txt>
//!
//! Where upstream goes through `sysctl.New()` (`/proc/sys`), the sysfs
//! `hashsize` parameter and `mount.List()` (`/proc/mounts`), the roots are
//! fields of [`RealConntracker`] so a test can point them at a directory.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::config::KubeProxyConntrackConfiguration;

/// Errors of a [`Conntracker`].
#[derive(Debug)]
pub enum ConntrackError {
    /// `errReadOnlySysFS`: a known container runtime bug (kubernetes#134108);
    /// the caller warns the admin and carries on.
    ReadOnlySysFs,
    Other(anyhow::Error),
}

impl fmt::Display for ConntrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConntrackError::ReadOnlySysFs => f.write_str("readOnlySysFS"),
            ConntrackError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConntrackError {}

impl From<std::io::Error> for ConntrackError {
    fn from(e: std::io::Error) -> Self {
        ConntrackError::Other(e.into())
    }
}

impl From<anyhow::Error> for ConntrackError {
    fn from(e: anyhow::Error) -> Self {
        ConntrackError::Other(e)
    }
}

/// `Conntracker`: the global conntrack sysctls.
pub trait Conntracker {
    /// `nf_conntrack_max`.
    fn set_max(&self, max: i64) -> Result<(), ConntrackError>;
    /// `nf_conntrack_tcp_timeout_established`.
    fn set_tcp_established_timeout(&self, seconds: i64) -> Result<(), ConntrackError>;
    /// `nf_conntrack_tcp_timeout_close_wait`.
    fn set_tcp_close_wait_timeout(&self, seconds: i64) -> Result<(), ConntrackError>;
    /// `nf_conntrack_tcp_be_liberal`.
    fn set_tcp_be_liberal(&self, value: i64) -> Result<(), ConntrackError>;
    /// `nf_conntrack_udp_timeout`.
    fn set_udp_timeout(&self, seconds: i64) -> Result<(), ConntrackError>;
    /// `nf_conntrack_udp_timeout_stream`.
    fn set_udp_stream_timeout(&self, seconds: i64) -> Result<(), ConntrackError>;
}

/// `realConntracker`, with the filesystem roots injectable.
#[derive(Debug, Clone)]
pub struct RealConntracker {
    /// `/proc/sys`.
    pub proc_sys: PathBuf,
    /// `/sys/module/nf_conntrack/parameters/hashsize`.
    pub hashsize_file: PathBuf,
    /// `/proc/mounts`.
    pub mounts_file: PathBuf,
}

impl Default for RealConntracker {
    fn default() -> Self {
        Self {
            proc_sys: "/proc/sys".into(),
            hashsize_file: "/sys/module/nf_conntrack/parameters/hashsize".into(),
            mounts_file: "/proc/mounts".into(),
        }
    }
}

impl RealConntracker {
    /// `setIntSysCtl`: write `net/netfilter/<name>` unless it already holds
    /// `value` (a failed read counts as "differs", as `val, _ :=`).
    fn set_int_sysctl(&self, name: &str, value: i64) -> Result<(), ConntrackError> {
        let path = self.proc_sys.join("net/netfilter").join(name);
        if read_int_string_file(&path).ok() != Some(value) {
            tracing::info!(entry = %format!("net/netfilter/{name}"), value, "Set sysctl");
            std::fs::write(&path, value.to_string())?;
        }
        Ok(())
    }

    /// `isSysFSWritable`: the first `sysfs` mount point in `/proc/mounts`
    /// must have `rw` as its first option.
    fn is_sysfs_writable(&self) -> Result<bool, ConntrackError> {
        let mounts = std::fs::read_to_string(&self.mounts_file).map_err(|e| {
            tracing::error!(error = %e, "Failed to list mount points");
            ConntrackError::from(e)
        })?;
        for line in mounts.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 || f[2] != "sysfs" {
                continue;
            }
            if f[3].split(',').next() == Some("rw") {
                return Ok(true);
            }
            tracing::error!(mount_options = f[3], "Sysfs is not writable");
            return Err(ConntrackError::ReadOnlySysFs);
        }
        Err(ConntrackError::Other(anyhow::anyhow!("no sysfs mounted")))
    }
}

impl Conntracker for RealConntracker {
    fn set_max(&self, max: i64) -> Result<(), ConntrackError> {
        tracing::info!(nf_conntrack_max = max, "Setting nf_conntrack_max");
        self.set_int_sysctl("nf_conntrack_max", max)?;

        // Check if hashsize is large enough for the nf_conntrack_max value.
        let hashsize = read_int_string_file(&self.hashsize_file)?;
        if hashsize >= max / 4 {
            return Ok(());
        }

        // sysfs is expected to be mounted 'rw', but docker may mount it 'ro'
        // (kubernetes#134108): then a special error the caller deals with.
        if !self.is_sysfs_writable()? {
            return Err(ConntrackError::ReadOnlySysFs);
        }

        tracing::info!(conntrack_hashsize = max / 4, "Setting conntrack hashsize");
        write_int_string_file(&self.hashsize_file, max / 4)?;
        Ok(())
    }

    fn set_tcp_established_timeout(&self, seconds: i64) -> Result<(), ConntrackError> {
        self.set_int_sysctl("nf_conntrack_tcp_timeout_established", seconds)
    }

    fn set_tcp_close_wait_timeout(&self, seconds: i64) -> Result<(), ConntrackError> {
        self.set_int_sysctl("nf_conntrack_tcp_timeout_close_wait", seconds)
    }

    fn set_tcp_be_liberal(&self, value: i64) -> Result<(), ConntrackError> {
        self.set_int_sysctl("nf_conntrack_tcp_be_liberal", value)
    }

    fn set_udp_timeout(&self, seconds: i64) -> Result<(), ConntrackError> {
        self.set_int_sysctl("nf_conntrack_udp_timeout", seconds)
    }

    fn set_udp_stream_timeout(&self, seconds: i64) -> Result<(), ConntrackError> {
        self.set_int_sysctl("nf_conntrack_udp_timeout_stream", seconds)
    }
}

/// `readIntStringFile`.
fn read_int_string_file(path: &Path) -> std::io::Result<i64> {
    std::fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// `writeIntStringFile`.
fn write_int_string_file(path: &Path, value: i64) -> std::io::Result<()> {
    std::fs::write(path, value.to_string())
}

/// `detectNumCPU` (server_linux.go:373): the CPU count from sysfs first (a
/// known issue, kubernetes#99225), `runtime.NumCPU` when that fails.
pub fn detect_num_cpu() -> i64 {
    detect_num_cpu_from(Path::new("/sys/devices/system/cpu"))
}

fn detect_num_cpu_from(sys_cpu: &Path) -> i64 {
    let n = std::fs::read_dir(sys_cpu)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .and_then(|n| n.strip_prefix("cpu"))
                        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
                })
                .count() as i64
        })
        .unwrap_or(0);
    if n >= 1 {
        n
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get() as i64)
            .unwrap_or(1)
    }
}

/// `getConntrackMax` (server_linux.go:356-371) with the CPU count given:
/// `maxPerCore * numCPU` when that exceeds `min`, else `min`; 0 (leave the
/// system setting) when `maxPerCore` is unset or not positive.
pub fn get_conntrack_max_for_cpus(config: &KubeProxyConntrackConfiguration, num_cpu: i64) -> i64 {
    match config.max_per_core {
        Some(per_core) if per_core > 0 => {
            let floor = config.min.map(i64::from).unwrap_or(0);
            let scaled = i64::from(per_core) * num_cpu;
            if scaled > floor {
                tracing::debug!("GetConntrackMax: using scaled conntrack-max-per-core");
                scaled
            } else {
                tracing::debug!("GetConntrackMax: using conntrack-min");
                floor
            }
        }
        _ => 0,
    }
}

/// `getConntrackMax`.
pub fn get_conntrack_max(config: &KubeProxyConntrackConfiguration) -> i64 {
    get_conntrack_max_for_cpus(config, detect_num_cpu())
}

/// The warning `setupConntrack` records as an event on the node when `/sys`
/// is read-only (`Recorder.Eventf(NodeRef, nil, Warning, err.Error(),
/// "StartKubeProxy", message)`).
pub const READ_ONLY_SYSFS_MESSAGE: &str = "CRI error: /sys is read-only: cannot modify conntrack limits, problems may arise later (If running Docker, see docker issue #24000)";

/// `setupConntrack` (server_linux.go:299-354). `Ok(true)` when the read-only
/// sysfs bug was hit: the caller emits a Warning event with reason
/// `readOnlySysFS`, action `StartKubeProxy` and [`READ_ONLY_SYSFS_MESSAGE`]
/// (the failure is otherwise ignored, for historical reasons).
pub fn setup_conntrack(
    ct: &dyn Conntracker,
    config: &KubeProxyConntrackConfiguration,
) -> Result<bool, ConntrackError> {
    setup_conntrack_with_max(ct, config, get_conntrack_max(config))
}

fn setup_conntrack_with_max(
    ct: &dyn Conntracker,
    config: &KubeProxyConntrackConfiguration,
    max: i64,
) -> Result<bool, ConntrackError> {
    let mut read_only_sysfs = false;
    if max > 0 {
        match ct.set_max(max) {
            Ok(()) => {}
            Err(ConntrackError::ReadOnlySysFs) => read_only_sysfs = true,
            Err(e) => return Err(e),
        }
    }

    const SECOND: i64 = 1_000_000_000;
    if let Some(d) = config.tcp_established_timeout.filter(|d| d.0 > 0) {
        ct.set_tcp_established_timeout(d.0 / SECOND)?;
    }
    if let Some(d) = config.tcp_close_wait_timeout.filter(|d| d.0 > 0) {
        ct.set_tcp_close_wait_timeout(d.0 / SECOND)?;
    }
    if config.tcp_be_liberal {
        ct.set_tcp_be_liberal(1)?;
    }
    if config.udp_timeout.0 > 0 {
        ct.set_udp_timeout(config.udp_timeout.0 / SECOND)?;
    }
    if config.udp_stream_timeout.0 > 0 {
        ct.set_udp_stream_timeout(config.udp_stream_timeout.0 / SECOND)?;
    }
    Ok(read_only_sysfs)
}

/// Test seam for [`setup_conntrack`] with a fixed maximum, so a test need not
/// know the host's CPU count.
#[doc(hidden)]
pub fn setup_conntrack_for_test(
    ct: &dyn Conntracker,
    config: &KubeProxyConntrackConfiguration,
    num_cpu: i64,
) -> Result<bool, ConntrackError> {
    setup_conntrack_with_max(ct, config, get_conntrack_max_for_cpus(config, num_cpu))
}
