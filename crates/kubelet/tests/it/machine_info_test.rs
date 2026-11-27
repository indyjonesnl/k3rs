//! Ported from `pkg/kubelet/nodestatus/setters_test.go` (`TestMachineInfo`,
//! `TestVersionInfo`, `TestGoRuntime`) and cadvisor's machine info readers,
//! over a fake `/proc` + `/sys` + `/etc` tree.

use kubernetes_rs_kubelet::machine_info::*;
use std::collections::HashMap;
use std::path::Path;

fn put(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn cpu(root: &Path, base: &str, id: u32) {
    put(
        root,
        &format!("{base}/cpu{id}/topology/core_id"),
        &format!("{id}\n"),
    );
    put(
        root,
        &format!("{base}/cpu{id}/topology/physical_package_id"),
        "0\n",
    );
}

fn fake_machine(root: &Path, cpus: u32) {
    put(
        root,
        "proc/meminfo",
        "MemTotal:        2048000 kB\nMemFree: 1 kB\nSwapTotal:       1024 kB\n",
    );
    put(root, "etc/machine-id", "mid\n");
    put(root, "proc/sys/kernel/random/boot_id", "boot\n");
    put(root, "sys/class/dmi/id/product_uuid", "uuid\n");
    for i in 0..cpus {
        cpu(root, "sys/devices/system/cpu", i);
    }
}

#[test]
fn machine_info_reads_identifiers_cpu_memory() {
    let d = tempfile::tempdir().unwrap();
    fake_machine(d.path(), 4);
    let m = read_machine_info(d.path()).unwrap();
    assert_eq!(m.num_cores, 4);
    assert_eq!(m.memory_capacity, 2048000 * 1024);
    assert_eq!(m.swap_capacity, 1024 * 1024);
    assert_eq!(
        (
            m.machine_id.as_str(),
            m.boot_id.as_str(),
            m.system_uuid.as_str()
        ),
        ("mid", "boot", "uuid")
    );
    assert!(m.huge_pages.is_empty());
}

#[test]
fn machine_info_machine_id_and_uuid_fallbacks() {
    let d = tempfile::tempdir().unwrap();
    fake_machine(d.path(), 1);
    std::fs::remove_file(d.path().join("etc/machine-id")).unwrap();
    std::fs::remove_file(d.path().join("sys/class/dmi/id/product_uuid")).unwrap();
    put(d.path(), "var/lib/dbus/machine-id", "dbus\n");
    put(d.path(), "proc/device-tree/system-id", "ppc-id\0");
    let m = read_machine_info(d.path()).unwrap();
    assert_eq!(m.machine_id, "dbus");
    assert_eq!(m.system_uuid, "ppc-id");
}

#[test]
fn machine_info_offline_cpus_and_missing_topology_are_not_counted() {
    let d = tempfile::tempdir().unwrap();
    fake_machine(d.path(), 4);
    put(d.path(), "sys/devices/system/cpu/online", "0-1,3\n");
    assert_eq!(read_machine_info(d.path()).unwrap().num_cores, 3);
    std::fs::remove_file(
        d.path()
            .join("sys/devices/system/cpu/cpu3/topology/core_id"),
    )
    .unwrap();
    assert_eq!(read_machine_info(d.path()).unwrap().num_cores, 2);
}

#[test]
fn machine_info_counts_cpus_per_numa_node() {
    let d = tempfile::tempdir().unwrap();
    fake_machine(d.path(), 0);
    for (node, ids) in [(0, [0, 1]), (1, [2, 3])] {
        for id in ids {
            cpu(d.path(), &format!("sys/devices/system/node/node{node}"), id);
        }
    }
    assert_eq!(read_machine_info(d.path()).unwrap().num_cores, 4);
}

#[test]
fn machine_info_errors_without_cpus_or_meminfo() {
    let d = tempfile::tempdir().unwrap();
    assert!(read_machine_info(d.path()).is_err());
    put(d.path(), "proc/meminfo", "garbage\n");
    assert!(read_machine_info(d.path()).is_err());
}

#[test]
fn machine_info_hugepages() {
    let d = tempfile::tempdir().unwrap();
    fake_machine(d.path(), 1);
    put(
        d.path(),
        "sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages",
        "4\n",
    );
    put(
        d.path(),
        "sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages",
        "1\n",
    );
    let m = read_machine_info(d.path()).unwrap();
    assert_eq!(m.huge_pages.len(), 2);
    let cap = capacity_from_machine_info(&m, 110, 0);
    assert_eq!(cap["hugepages-2Mi"], "8Mi");
    assert_eq!(cap["hugepages-1Gi"], "1Gi");
    put(
        d.path(),
        "sys/kernel/mm/hugepages/hugepages-64kB/nr_hugepages",
        "x\n",
    );
    assert!(read_machine_info(d.path()).is_err());
}

fn info(cores: u64, mem: u64) -> MachineInfo {
    MachineInfo {
        num_cores: cores,
        memory_capacity: mem,
        ..Default::default()
    }
}

/// `TestMachineInfo` "machine identifiers, basic capacity and allocatable".
#[test]
fn machine_info_capacity_and_allocatable_basic() {
    let cap = capacity_from_machine_info(&info(2, 1024), 110, 0);
    assert_eq!(cap["cpu"], "2");
    assert_eq!(cap["memory"], "1Ki");
    assert_eq!(cap["pods"], "110");
    assert_eq!(allocatable_from_capacity(&cap, &HashMap::new()), cap);
}

/// `TestMachineInfo` podsPerCore cases.
#[test]
fn machine_info_pods_per_core() {
    // podsPerCore greater than zero, but less than maxPods/cores
    assert_eq!(
        capacity_from_machine_info(&info(2, 1024), 10, 4)["pods"],
        "8"
    );
    // podsPerCore greater than maxPods/cores
    assert_eq!(
        capacity_from_machine_info(&info(2, 1024), 10, 6)["pods"],
        "10"
    );
}

/// `TestMachineInfo`: reservations are subtracted, never below zero, and
/// huge pages come out of allocatable memory.
#[test]
fn machine_info_allocatable_reservation_and_hugepages() {
    let mut m = info(2, 10 * 1024 * 1024);
    m.huge_pages = vec![HugePagesInfo {
        page_size: 2048,
        num_pages: 2,
    }];
    let cap = capacity_from_machine_info(&m, 110, 0);
    let res = HashMap::from([
        ("cpu".to_string(), "500m".to_string()),
        ("memory".to_string(), "1Mi".to_string()),
        ("pods".to_string(), "200".to_string()),
    ]);
    let a = allocatable_from_capacity(&cap, &res);
    assert_eq!(a["cpu"], "1500m");
    assert_eq!(a["memory"], "5Mi"); // 10Mi - 1Mi reserved - 4Mi hugepages
    assert_eq!(a["pods"], "0");
    assert_eq!(a["hugepages-2Mi"], "4Mi");
}

/// `TestMachineInfo` "machine info error".
#[test]
fn machine_info_error_capacity() {
    let c = capacity_without_machine_info(110);
    assert_eq!(
        (c["cpu"].as_str(), c["memory"].as_str(), c["pods"].as_str()),
        ("0", "0", "110")
    );
}

/// `TestVersionInfo`.
#[test]
fn machine_info_version_info() {
    let d = tempfile::tempdir().unwrap();
    put(d.path(), "proc/sys/kernel/osrelease", "6.1.0-test\n");
    put(
        d.path(),
        "etc/os-release",
        "NAME=\"X\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
    );
    let v = read_version_info(d.path());
    assert_eq!(v.kernel_version, "6.1.0-test");
    assert_eq!(v.container_os_version, "Debian GNU/Linux 12 (bookworm)");

    put(d.path(), "etc/os-release", "NAME=x\n");
    assert_eq!(read_version_info(d.path()).container_os_version, "Linux");
    std::fs::remove_file(d.path().join("etc/os-release")).unwrap();
    put(d.path(), "usr/lib/os-release", "PRETTY_NAME=Stateless\n");
    assert_eq!(
        read_version_info(d.path()).container_os_version,
        "Stateless"
    );
    std::fs::remove_file(d.path().join("usr/lib/os-release")).unwrap();
    assert_eq!(read_version_info(d.path()).container_os_version, "Unknown");
    std::fs::remove_file(d.path().join("proc/sys/kernel/osrelease")).unwrap();
    assert_eq!(read_version_info(d.path()).kernel_version, "Unknown");
}

/// `TestGoRuntime`: the Go names of this build.
#[test]
fn machine_info_go_runtime() {
    assert_eq!(go_os(), "linux");
    let arch = go_arch();
    #[cfg(target_arch = "x86_64")]
    assert_eq!(arch, "amd64");
    #[cfg(target_arch = "aarch64")]
    assert_eq!(arch, "arm64");
    assert!(!arch.is_empty());
}

#[test]
fn machine_info_ephemeral_storage_capacity() {
    let d = tempfile::tempdir().unwrap();
    let s = ephemeral_storage_capacity(d.path()).unwrap();
    assert_ne!(s, "0");
    assert!(ephemeral_storage_capacity(&d.path().join("nope")).is_err());
}
