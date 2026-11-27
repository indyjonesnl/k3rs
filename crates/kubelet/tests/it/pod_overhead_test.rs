//! `cm.ResourceConfigForPod` incl. pod overhead
//! (`pkg/kubelet/cm/helpers_linux_test.go`: `TestResourceConfigForPod`,
//! `TestMilliCPUToQuota`, `TestHugePageLimits`; overhead is added by
//! `PodRequests`/`PodLimits`, component-helpers/resource/helpers.go:180,366).

use kubernetes_rs_common::quantity::Quantity;
use kubernetes_rs_common::quota::ResourceList;
use kubernetes_rs_common::resources::Pod;
use kubernetes_rs_kubelet::cm_helpers::*;
use std::collections::BTreeMap;

const MI: i64 = 1 << 20;
const PERIOD: u64 = 100_000;

fn pod(spec: serde_json::Value) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "p", "namespace": "default", "uid": "u"},
        "spec": spec,
    }))
    .unwrap()
}

fn ctr(req: (&str, &str), lim: (&str, &str)) -> serde_json::Value {
    let list = |(c, m): (&str, &str)| {
        let mut o = serde_json::Map::new();
        if !c.is_empty() {
            o.insert("cpu".into(), c.into());
        }
        if !m.is_empty() {
            o.insert("memory".into(), m.into());
        }
        serde_json::Value::Object(o)
    };
    serde_json::json!({"name": "c", "image": "i",
        "resources": {"requests": list(req), "limits": list(lim)}})
}

fn cfg(p: &Pod, enforce: bool, period: u64) -> ResourceConfig {
    resource_config_for_pod(p, enforce, period, false, period != PERIOD)
}

#[test]
fn pod_overhead_milli_cpu_to_quota() {
    for (input, quota) in [
        (0, 0),
        (5, 1000),
        (9, 1000),
        (10, 1000),
        (200, 20000),
        (500, 50000),
        (1000, 100000),
        (1500, 150000),
    ] {
        assert_eq!(milli_cpu_to_quota(input, 100_000, true), quota, "{input}");
    }
    // gate off: the period is forced to 100ms
    assert_eq!(milli_cpu_to_quota(100, 5000, false), 10_000);
    assert_eq!(milli_cpu_to_quota(100, 5000, true), 1000);
}

#[test]
fn pod_overhead_milli_cpu_to_shares() {
    assert_eq!(milli_cpu_to_shares(0), 2);
    assert_eq!(milli_cpu_to_shares(1), 2);
    assert_eq!(milli_cpu_to_shares(100), 102);
    assert_eq!(milli_cpu_to_shares(1000), 1024);
    assert_eq!(milli_cpu_to_shares(i64::from(u32::MAX)), 262_144);
}

#[test]
fn pod_overhead_resource_config_qos_table() {
    let shares100 = milli_cpu_to_shares(100);
    // besteffort
    let p = pod(serde_json::json!({"containers": [ctr(("", ""), ("", ""))]}));
    assert_eq!(
        cfg(&p, true, PERIOD),
        ResourceConfig {
            cpu_shares: Some(2),
            ..Default::default()
        }
    );
    // burstable-no-limits
    let p = pod(serde_json::json!({"containers": [ctr(("100m", "100Mi"), ("", ""))]}));
    assert_eq!(
        cfg(&p, true, PERIOD),
        ResourceConfig {
            cpu_shares: Some(shares100),
            ..Default::default()
        }
    );
    // burstable-with-limits
    let p = pod(serde_json::json!({"containers": [ctr(("100m", "100Mi"), ("200m", "200Mi"))]}));
    let want = ResourceConfig {
        cpu_shares: Some(shares100),
        cpu_quota: Some(20_000),
        cpu_period: Some(PERIOD),
        memory: Some(200 * MI),
        ..Default::default()
    };
    assert_eq!(cfg(&p, true, PERIOD), want);
    // ... without cpu enforcement the quota is -1
    let got = cfg(&p, false, PERIOD);
    assert_eq!(got.cpu_quota, Some(-1));
    // burstable-partial-limits: second container has no limits
    let p = pod(serde_json::json!({"containers": [
        ctr(("100m", "100Mi"), ("200m", "200Mi")), ctr(("100m", "100Mi"), ("", ""))]}));
    assert_eq!(
        cfg(&p, true, PERIOD),
        ResourceConfig {
            cpu_shares: Some(milli_cpu_to_shares(200)),
            ..Default::default()
        }
    );
    // guaranteed
    let p = pod(serde_json::json!({"containers": [ctr(("100m", "100Mi"), ("100m", "100Mi"))]}));
    assert_eq!(
        cfg(&p, true, PERIOD),
        ResourceConfig {
            cpu_shares: Some(shares100),
            cpu_quota: Some(10_000),
            cpu_period: Some(PERIOD),
            memory: Some(100 * MI),
            ..Default::default()
        }
    );
    // guaranteed with a tuned quota period (gate on)
    let got = cfg(&p, true, 5000);
    assert_eq!(got.cpu_quota, Some(milli_cpu_to_quota(100, 5000, true)));
    assert_eq!(got.cpu_period, Some(5000));
}

#[test]
fn pod_overhead_is_added_to_requests_and_limits() {
    // guaranteed 100m/100Mi plus overhead 50m/20Mi: the pod cgroup carries
    // both the shares and the limits of container + overhead.
    let p = pod(serde_json::json!({
        "containers": [ctr(("100m", "100Mi"), ("100m", "100Mi"))],
        "overhead": {"cpu": "50m", "memory": "20Mi"},
    }));
    let got = cfg(&p, true, PERIOD);
    assert_eq!(got.cpu_shares, Some(milli_cpu_to_shares(150)));
    assert_eq!(got.cpu_quota, Some(15_000));
    assert_eq!(got.memory, Some(120 * MI));
    // and the memory-only helper agrees (emptyDir sizing)
    assert_eq!(resource_config_for_pod_memory(&p), Some(120 * MI));
}

#[test]
fn pod_overhead_does_not_create_a_limit_for_an_unlimited_resource() {
    // burstable: CPU limit only; memory is not limited, so overhead memory
    // must not become a memory limit (helpers.go:366-373).
    let p = pod(serde_json::json!({
        "containers": [ctr(("100m", "100Mi"), ("200m", ""))],
        "overhead": {"cpu": "50m", "memory": "20Mi"},
    }));
    let got = cfg(&p, true, PERIOD);
    assert_eq!(got.memory, None);
    assert_eq!(got.cpu_quota, Some(25_000));
    assert_eq!(got.cpu_shares, Some(milli_cpu_to_shares(150)));
}

fn rl(items: &[(&str, &str)]) -> ResourceList {
    items
        .iter()
        .map(|(k, v)| (k.to_string(), Quantity::parse(v).unwrap()))
        .collect()
}

#[test]
fn pod_overhead_huge_page_limits() {
    let mi = i64::from(1u32 << 20);
    assert!(huge_page_limits(&rl(&[("2Mi", "128")])).is_empty());
    assert_eq!(
        huge_page_limits(&rl(&[("hugepages-2Mi", "128")])),
        BTreeMap::from([(2 * mi, 128)])
    );
    let l = rl(&[
        ("hugepages-2Mi", "128"),
        ("hugepages-2097152", "256"),
        ("hugepages-4Mi", "512"),
        ("4Mi", "1024"),
    ]);
    assert_eq!(
        huge_page_limits(&l),
        BTreeMap::from([(2 * mi, 384), (4 * mi, 512)])
    );
    // ResourceConfigForPod uses the REQUESTS (hugepages requests == limits)
    let p = pod(
        serde_json::json!({"containers": [{"name": "c", "image": "i",
        "resources": {"requests": {"hugepages-2Mi": "128"}}}]}),
    );
    assert_eq!(
        cfg(&p, false, 0).huge_page_limit,
        BTreeMap::from([(2 * mi, 128)])
    );
}

#[test]
fn pod_overhead_memory_qos_unified_memory_min() {
    let p = pod(
        serde_json::json!({"containers": [ctr(("100m", "100Mi"), ("", ""))],
        "overhead": {"memory": "28Mi"}}),
    );
    let got = resource_config_for_pod(&p, true, PERIOD, true, false);
    assert_eq!(
        got.unified.get(CGROUP2_MEMORY_MIN).map(String::as_str),
        Some((128 * MI).to_string().as_str())
    );
    let none = resource_config_for_pod(&p, true, PERIOD, false, false);
    assert!(none.unified.is_empty());
}
