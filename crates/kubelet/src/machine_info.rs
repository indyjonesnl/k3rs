//! Machine information for node status: CPU, memory, hugepages, identifiers,
//! kernel and OS image, architecture.
//!
//! Ported from:
//! - `pkg/kubelet/nodestatus/setters.go`: `MachineInfo` :195 (capacity, pods
//!   capacity with `podsPerCore`, allocatable = capacity minus reservation,
//!   hugepages subtracted from allocatable memory), `VersionInfo` :342
//!   (kernel, OS image), `GoRuntime` :422 (OS, architecture).
//! - `pkg/kubelet/cadvisor/util.go`: `CapacityFromMachineInfo`.
//! - google/cadvisor (vendored in `../kubernetes/vendor`): `machine/info.go`
//!   `Info`, `getInfoFromFiles`; `machine/machine.go`
//!   `GetMachineMemoryCapacity`, `GetMachineSwapCapacity`, `parseCapacity`;
//!   `machine/operatingsystem_unix.go` `getOperatingSystem`;
//!   `utils/sysinfo/sysinfo.go` `GetHugePagesInfo`, `GetNodesInfo`,
//!   `getCPUTopology`, `getCoresInfo`; `utils/sysfs/sysfs.go`
//!   `GetSystemUUID`, `IsCPUOnline`.
//!
//! Every path is read below a `root` so tests can fake `/proc`, `/sys` and
//! `/etc`; production passes `/`. Wiring into `kubelet.rs` (which hardcodes
//! 4 CPU / 8Gi / amd64 today) is the next task.
//!
//! Simplifications against cadvisor: NUMA/cache/disk/network topology and the
//! cloud-provider probes are not read (node status does not use them), and
//! `NumCores` counts the online CPUs that expose a `core_id` and
//! `physical_package_id`, which is what `getCoresInfo` sums over the nodes.

use kubernetes_rs_common::quantity::{Format, Quantity};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// `cadvisorapi.HugePagesInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HugePagesInfo {
    /// Page size in kB.
    pub page_size: u64,
    pub num_pages: u64,
}

/// The part of `cadvisorapi.MachineInfo` node status reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineInfo {
    pub num_cores: u64,
    /// Bytes.
    pub memory_capacity: u64,
    /// Bytes.
    pub swap_capacity: u64,
    pub huge_pages: Vec<HugePagesInfo>,
    pub machine_id: String,
    pub system_uuid: String,
    pub boot_id: String,
}

/// `cadvisorapiv1.VersionInfo` as `VersionInfo` copies it onto the node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionInfo {
    pub kernel_version: String,
    pub container_os_version: String,
}

fn at(root: &Path, p: &str) -> PathBuf {
    root.join(p.trim_start_matches('/'))
}

/// `parseCapacity` (machine.go:229-243): `<key>: N kB` as bytes.
fn parse_capacity(meminfo: &str, key: &str) -> Result<u64, String> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix(key).and_then(|r| r.strip_prefix(':')) {
            let rest = rest.trim();
            if let Some(n) = rest.strip_suffix(" kB") {
                let kb: u64 = n.trim().parse().map_err(|e| format!("{e}"))?;
                return Ok(kb * 1024);
            }
        }
    }
    Err(format!("failed to match regexp in output: {meminfo:?}"))
}

/// `getInfoFromFiles` (info.go:43-55): the first readable file, trimmed.
fn info_from_files(root: &Path, files: &[&str]) -> String {
    files
        .iter()
        .find_map(|f| std::fs::read_to_string(at(root, f)).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// `realSysFs.GetSystemUUID` (sysfs.go:442-454), the x86/ppc/s390x sources.
fn system_uuid(root: &Path) -> String {
    let trim_nul = |s: String| s.trim_end_matches('\0').trim().to_string();
    if let Ok(s) = std::fs::read_to_string(at(root, "/sys/class/dmi/id/product_uuid")) {
        return s.trim().to_string();
    }
    for p in ["/proc/device-tree/system-id", "/proc/device-tree/vm,uuid"] {
        if let Ok(s) = std::fs::read_to_string(at(root, p)) {
            return trim_nul(s);
        }
    }
    std::fs::read_to_string(at(root, "/etc/machine-id"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// `GetHugePagesInfo` (sysinfo.go:165-201): `hugepages-<N>kB/nr_hugepages`.
/// A missing directory is not an error (huge pages can be disabled).
fn huge_pages(root: &Path) -> Result<Vec<HugePagesInfo>, String> {
    let dir = at(root, "/sys/kernel/mm/hugepages");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Ok(vec![]);
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let Some(size) = name.split('-').nth(1).and_then(|s| s.strip_suffix("kB")) else {
            continue;
        };
        let page_size: u64 = size.parse().map_err(|e| format!("{e}"))?;
        let nr = std::fs::read_to_string(dir.join(&name).join("nr_hugepages"))
            .map_err(|e| e.to_string())?;
        let num_pages: u64 = nr
            .split_whitespace()
            .next()
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| {
                format!("could not parse file nr_hugepage for {name}, contents {nr:?}")
            })?;
        out.push(HugePagesInfo {
            page_size,
            num_pages,
        });
    }
    Ok(out)
}

/// `IsCPUOnline` (sysfs.go:456-): without `/sys/devices/system/cpu/online`
/// (no hotplug) every CPU is online, else the CPU must be in its list.
fn online_cpus(root: &Path) -> Option<Vec<(u64, u64)>> {
    let s = std::fs::read_to_string(at(root, "/sys/devices/system/cpu/online")).ok()?;
    let mut ranges = Vec::new();
    for part in s.trim().split(',').filter(|p| !p.is_empty()) {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        ranges.push((a.parse().ok()?, b.parse().ok()?));
    }
    Some(ranges)
}

/// `GetNodesInfo` / `getCPUTopology` / `getCoresInfo`: the number of online
/// logical CPUs with a `topology/core_id` and `topology/physical_package_id`.
/// Per NUMA node when the node directories exist, else over the CPU directory.
fn num_cores(root: &Path) -> Result<u64, String> {
    let online = online_cpus(root);
    let cpu_dirs = |dir: &Path| -> Vec<(u64, PathBuf)> {
        let mut v: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        let id = n.strip_prefix("cpu")?.parse::<u64>().ok()?;
                        Some((id, e.path()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    };
    let count = |dirs: Vec<(u64, PathBuf)>| -> u64 {
        dirs.into_iter()
            .filter(|(id, _)| {
                online
                    .as_ref()
                    .is_none_or(|r| r.iter().any(|(a, b)| a <= id && id <= b))
            })
            .filter(|(_, p)| {
                p.join("topology/core_id").exists()
                    && p.join("topology/physical_package_id").exists()
            })
            .count() as u64
    };
    let node_root = at(root, "/sys/devices/system/node");
    let nodes: Vec<PathBuf> = std::fs::read_dir(&node_root)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .strip_prefix("node")
                        .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    if nodes.is_empty() {
        let dirs = cpu_dirs(&at(root, "/sys/devices/system/cpu"));
        if dirs.is_empty() {
            return Err("Any CPU is not available, cpusPath: /sys/devices/system/cpu".into());
        }
        // Without a readable topology cadvisor still reports the CPU count.
        let n = count(dirs.clone());
        return Ok(if n == 0 { dirs.len() as u64 } else { n });
    }
    Ok(nodes.iter().map(|n| count(cpu_dirs(n))).sum())
}

/// `machine.Info` (info.go:57-160), the fields node status reads.
pub fn read_machine_info(root: &Path) -> Result<MachineInfo, String> {
    let meminfo = std::fs::read_to_string(at(root, "/proc/meminfo")).map_err(|e| e.to_string())?;
    Ok(MachineInfo {
        num_cores: num_cores(root)?,
        memory_capacity: parse_capacity(&meminfo, "MemTotal")?,
        swap_capacity: parse_capacity(&meminfo, "SwapTotal")?,
        huge_pages: huge_pages(root)?,
        machine_id: info_from_files(root, &["/etc/machine-id", "/var/lib/dbus/machine-id"]),
        system_uuid: system_uuid(root),
        boot_id: info_from_files(root, &["/proc/sys/kernel/random/boot_id"]),
    })
}

/// `machine.KernelVersion` (info.go:170-179: `uname` release).
fn kernel_version(root: &Path) -> String {
    std::fs::read_to_string(at(root, "/proc/sys/kernel/osrelease"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "Unknown".into())
}

/// `getOperatingSystem` (operatingsystem_unix.go): `PRETTY_NAME` of
/// `/etc/os-release`, else `/usr/lib/os-release`; "Linux" when it has none;
/// "Unknown" when neither file can be read (`ContainerOsVersion`).
fn container_os_version(root: &Path) -> String {
    let text = std::fs::read_to_string(at(root, "/etc/os-release"))
        .or_else(|_| std::fs::read_to_string(at(root, "/usr/lib/os-release")));
    let Ok(text) = text else {
        return "Unknown".into();
    };
    text.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "Linux".into())
}

/// The `VersionInfo` setter's source (`cadvisor.VersionInfo`).
pub fn read_version_info(root: &Path) -> VersionInfo {
    VersionInfo {
        kernel_version: kernel_version(root),
        container_os_version: container_os_version(root),
    }
}

/// `goruntime.GOARCH` for this build: Rust's `ARCH` names mapped to Go's.
pub fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "x86" => "386",
        "aarch64" => "arm64",
        "powerpc64" => "ppc64",
        "powerpc64le" => "ppc64le",
        other => other,
    }
}

/// `goruntime.GOOS`.
pub fn go_os() -> &'static str {
    std::env::consts::OS
}

/// `HugePageResourceName` (v1helper): `hugepages-<size quantity>`.
pub fn huge_page_resource_name(page_size_kb: u64) -> String {
    let q = Quantity::from_value((page_size_kb * 1024) as i64, Format::BinarySI);
    format!("hugepages-{}", q.canonical_string())
}

/// `CapacityFromMachineInfo` (cadvisor/util.go:41-60) plus the `pods` entry
/// of `MachineInfo` (setters.go:239-246): `podsPerCore > 0` caps pods at
/// `min(numCores * podsPerCore, maxPods)`.
pub fn capacity_from_machine_info(
    info: &MachineInfo,
    max_pods: i64,
    pods_per_core: i64,
) -> HashMap<String, String> {
    let mut c = HashMap::new();
    c.insert(
        "cpu".to_string(),
        Quantity::from_milli_value((info.num_cores * 1000) as i64, Format::DecimalSI)
            .canonical_string(),
    );
    c.insert(
        "memory".to_string(),
        Quantity::from_value(info.memory_capacity as i64, Format::BinarySI).canonical_string(),
    );
    for hp in &info.huge_pages {
        let bytes = (hp.page_size * 1024 * hp.num_pages) as i64;
        c.insert(
            huge_page_resource_name(hp.page_size),
            Quantity::from_value(bytes, Format::BinarySI).canonical_string(),
        );
    }
    let pods = if pods_per_core > 0 {
        (info.num_cores as i64 * pods_per_core).min(max_pods)
    } else {
        max_pods
    };
    c.insert(
        "pods".to_string(),
        Quantity::from_value(pods, Format::DecimalSI).canonical_string(),
    );
    c
}

/// The capacity when machine info cannot be read (setters.go:216-222): cpu 0,
/// memory 0Gi, pods `maxPods`.
pub fn capacity_without_machine_info(max_pods: i64) -> HashMap<String, String> {
    HashMap::from([
        ("cpu".to_string(), "0".to_string()),
        ("memory".to_string(), "0".to_string()),
        (
            "pods".to_string(),
            Quantity::from_value(max_pods, Format::DecimalSI).canonical_string(),
        ),
    ])
}

/// `EphemeralStorageCapacityFromFsInfo` for the capacity of `path`'s
/// filesystem, in bytes (`statfs`: blocks x block size).
pub fn ephemeral_storage_capacity(path: &Path) -> std::io::Result<String> {
    let st = rustix::fs::statvfs(path)?;
    let bytes = st.f_blocks.saturating_mul(st.f_frsize);
    Ok(Quantity::from_value(bytes as i64, Format::BinarySI).canonical_string())
}

/// The allocatable half of `MachineInfo` (setters.go:297-337): capacity minus
/// the node-allocatable reservation, never negative, and every huge page
/// reservation also removed from allocatable memory.
pub fn allocatable_from_capacity(
    capacity: &HashMap<String, String>,
    reservation: &HashMap<String, String>,
) -> HashMap<String, String> {
    let q =
        |s: &str| Quantity::parse(s).unwrap_or_else(|_| Quantity::from_value(0, Format::DecimalSI));
    let clamp = |v: Quantity| -> Quantity {
        if v.is_negative() {
            Quantity::from_value(0, v.format())
        } else {
            v
        }
    };
    let mut out: HashMap<String, String> = HashMap::new();
    for (k, v) in capacity {
        let mut value = q(v);
        if let Some(res) = reservation.get(k) {
            value = value.sub(&q(res)).unwrap_or(value);
        }
        out.insert(k.clone(), clamp(value).canonical_string());
    }
    for (k, v) in capacity {
        if k.starts_with("hugepages-") {
            let mem = q(out.get("memory").map_or("0", String::as_str));
            let left = clamp(mem.sub(&q(v)).unwrap_or(mem));
            out.insert("memory".to_string(), left.canonical_string());
        }
    }
    out
}
