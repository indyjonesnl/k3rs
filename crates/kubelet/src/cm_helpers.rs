//! `cm.ResourceConfigForPod` (`pkg/kubelet/cm/helpers_linux.go:126-223`) and
//! its helpers `MilliCPUToQuota` (:56), `MilliCPUToShares` (:90) and
//! `HugePageLimits` (:108). Requests and limits are summed by
//! `PodRequests` / `PodLimits`, which add `pod.spec.overhead`
//! (`component-helpers/resource/helpers.go:180-182`, `:366-373`), so the pod
//! cgroup limits include the RuntimeClass overhead. emptyDir's
//! `calculateEmptyDirMemorySize` (`pkg/volume/emptydir/empty_dir.go:122-129`)
//! reads `podResourceConfig.Memory`.

use kubernetes_rs_common::qos::{get_pod_qos, QoSClass};
use kubernetes_rs_common::quantity::Quantity;
use kubernetes_rs_common::quota::{
    is_hugepage_resource_name, parse_resource_list, pod_limits, pod_requests, ResourceList,
};
use kubernetes_rs_common::resources::Pod;
use std::collections::BTreeMap;

/// Kernel CFS limits (helpers_linux.go:35-36).
pub const MIN_SHARES: u64 = 2;
pub const MAX_SHARES: u64 = 262_144;
pub const SHARES_PER_CPU: i64 = 1024;
pub const MILLI_CPU_TO_CPU: i64 = 1000;
/// `QuotaPeriod` (100ms in microseconds) and `MinQuotaPeriod` (1ms).
pub const QUOTA_PERIOD: i64 = 100_000;
pub const MIN_QUOTA_PERIOD: i64 = 1000;
const HUGEPAGES_PREFIX: &str = "hugepages-";

/// `MilliCPUToQuota` (helpers_linux.go:56-79). `cpu_cfs_quota_period` is the
/// `CPUCFSQuotaPeriod` feature gate: when off the period is forced to
/// [`QUOTA_PERIOD`].
pub fn milli_cpu_to_quota(milli_cpu: i64, period: i64, cpu_cfs_quota_period: bool) -> i64 {
    if milli_cpu == 0 {
        return 0;
    }
    let period = if cpu_cfs_quota_period {
        period
    } else {
        QUOTA_PERIOD
    };
    let quota = (milli_cpu * period) / MILLI_CPU_TO_CPU;
    quota.max(MIN_QUOTA_PERIOD)
}

/// `MilliCPUToShares` (helpers_linux.go:82-104).
pub fn milli_cpu_to_shares(milli_cpu: i64) -> u64 {
    if milli_cpu == 0 {
        return MIN_SHARES;
    }
    let shares = (milli_cpu * SHARES_PER_CPU) / MILLI_CPU_TO_CPU;
    (shares.max(MIN_SHARES as i64) as u64).min(MAX_SHARES)
}

/// `HugePageLimits` (helpers_linux.go:108-123): page size (bytes) -> limit.
pub fn huge_page_limits(list: &ResourceList) -> BTreeMap<i64, i64> {
    let mut out = BTreeMap::new();
    for (k, v) in list {
        if !is_hugepage_resource_name(k) {
            continue;
        }
        // `HugePageSizeFromResourceName`; an unparseable size is skipped.
        let Some(size) = k
            .strip_prefix(HUGEPAGES_PREFIX)
            .and_then(|s| Quantity::parse(s).ok())
        else {
            continue;
        };
        let size = i64::try_from(size.value()).unwrap_or(i64::MAX);
        let v = i64::try_from(v.value()).unwrap_or(i64::MAX);
        *out.entry(size).or_insert(0) += v;
    }
    out
}

/// `ResourceConfig` (pkg/kubelet/cm/types.go), the fields
/// `ResourceConfigForPod` fills.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceConfig {
    pub memory: Option<i64>,
    pub cpu_shares: Option<u64>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<u64>,
    pub huge_page_limit: BTreeMap<i64, i64>,
    pub unified: BTreeMap<String, String>,
}

/// `Cgroup2MemoryMin` (pkg/kubelet/cm/types.go).
pub const CGROUP2_MEMORY_MIN: &str = "memory.min";

fn quantity_of(list: &ResourceList, name: &str) -> i128 {
    list.get(name).map(|q| q.value()).unwrap_or(0)
}

fn container_limit_nonzero(
    resources: Option<&kubernetes_rs_common::types::ResourceRequirements>,
    name: &str,
) -> bool {
    let list = resources
        .and_then(|r| r.limits.as_ref())
        .map(parse_resource_list)
        .unwrap_or_default();
    if name == "cpu" {
        list.get(name).map(|q| q.milli_value()).unwrap_or(0) != 0
    } else {
        quantity_of(&list, name) != 0
    }
}

/// Whether every container declares a non-zero limit for `name`: upstream's
/// `ContainerFn` clearing `cpuLimitsDeclared` / `memoryLimitsDeclared`
/// (`component-helpers/resource/helpers.go:396-445`) for every regular
/// container and for every init container's effective limits (own limits
/// plus the restartable init containers before it; a restartable init
/// container reports the running restartable total).
fn limits_declared(pod: &Pod, name: &str) -> bool {
    let Some(spec) = pod.spec.as_ref() else {
        return true;
    };
    let limit_of = |r: Option<&kubernetes_rs_common::types::ResourceRequirements>| -> i128 {
        let list = r
            .and_then(|r| r.limits.as_ref())
            .map(parse_resource_list)
            .unwrap_or_default();
        if name == "cpu" {
            list.get(name).map(|q| q.milli_value()).unwrap_or(0)
        } else {
            quantity_of(&list, name)
        }
    };
    let mut declared = true;
    for c in &spec.containers {
        if !container_limit_nonzero(c.resources.as_ref(), name) {
            declared = false;
        }
    }
    let mut restartable_total: i128 = 0;
    for c in spec.init_containers.iter().flatten() {
        let own = limit_of(c.resources.as_ref());
        let effective = if c.restart_policy.as_deref() == Some("Always") {
            restartable_total += own;
            restartable_total
        } else {
            own + restartable_total
        };
        if effective == 0 {
            declared = false;
        }
    }
    // Pod-level limits (PodLevelResources) can declare the limit for the pod.
    if kubernetes_rs_common::feature_gates::enabled(
        kubernetes_rs_common::feature_gates::Feature::PodLevelResources,
    ) {
        let pod_level = spec
            .resources
            .as_ref()
            .and_then(|r| r.limits.as_ref())
            .map(parse_resource_list)
            .unwrap_or_default();
        let nonzero = if name == "cpu" {
            pod_level.get(name).map(|q| q.milli_value()).unwrap_or(0) != 0
        } else {
            quantity_of(&pod_level, name) != 0
        };
        if nonzero {
            declared = true;
        }
    }
    declared
}

/// `ResourceConfigForPod` (helpers_linux.go:126-223).
pub fn resource_config_for_pod(
    pod: &Pod,
    enforce_cpu_limits: bool,
    cpu_period: u64,
    enforce_memory_qos: bool,
    cpu_cfs_quota_period: bool,
) -> ResourceConfig {
    let reqs = pod_requests(pod);
    let limits = pod_limits(pod);
    let memory_limits_declared = limits_declared(pod, "memory");
    let cpu_limits_declared = limits_declared(pod, "cpu");

    let huge_page_limits = huge_page_limits(&reqs);

    let cpu_requests = reqs
        .get("cpu")
        .map(|q| i64::try_from(q.milli_value()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let cpu_limit_milli = limits
        .get("cpu")
        .map(|q| i64::try_from(q.milli_value()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let memory_limits = i64::try_from(quantity_of(&limits, "memory")).unwrap_or(i64::MAX);

    // convert to CFS values
    let cpu_shares = milli_cpu_to_shares(cpu_requests);
    let mut cpu_quota =
        milli_cpu_to_quota(cpu_limit_milli, cpu_period as i64, cpu_cfs_quota_period);
    // quota is not capped when cfs quota is disabled
    if !enforce_cpu_limits {
        cpu_quota = -1;
    }

    let mut result = ResourceConfig::default();
    match get_pod_qos(pod) {
        QoSClass::Guaranteed => {
            result.cpu_shares = Some(cpu_shares);
            result.cpu_quota = Some(cpu_quota);
            result.cpu_period = Some(cpu_period);
            result.memory = Some(memory_limits);
        }
        QoSClass::Burstable => {
            result.cpu_shares = Some(cpu_shares);
            if cpu_limits_declared {
                result.cpu_quota = Some(cpu_quota);
                result.cpu_period = Some(cpu_period);
            }
            if memory_limits_declared {
                result.memory = Some(memory_limits);
            }
        }
        QoSClass::BestEffort => {
            result.cpu_shares = Some(MIN_SHARES);
        }
    }
    result.huge_page_limit = huge_page_limits;

    if enforce_memory_qos {
        let memory_min = i64::try_from(quantity_of(&reqs, "memory")).unwrap_or(i64::MAX);
        if memory_min > 0 {
            result
                .unified
                .insert(CGROUP2_MEMORY_MIN.to_string(), memory_min.to_string());
        }
    }
    result
}

/// `ResourceConfigForPod(pod, ..).Memory`: `None` when upstream leaves the
/// pointer nil (BestEffort, or Burstable with a container lacking a memory
/// limit), else the pod memory limit in bytes (0 when no limit is summed).
pub fn resource_config_for_pod_memory(pod: &Pod) -> Option<i64> {
    resource_config_for_pod(pod, true, QUOTA_PERIOD as u64, false, false).memory
}
