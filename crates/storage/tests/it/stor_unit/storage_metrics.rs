//! Ports of `staging/src/k8s.io/apiserver/pkg/storage/etcd3/metrics/metrics_test.go`
//! (TestUpdateStoreStats, TestDeleteStoreStats, TestRecordEtcdRequest,
//! TestRecordDecodeError) over the default prometheus registry. Each test uses
//! its own group/resource so they can run in parallel.

use std::time::{Duration, Instant};

use kubernetes_rs_storage::metrics::*;

/// The value of the sample of `metric` whose labels are exactly `labels`.
fn sample(metric: &str, labels: &[(&str, &str)]) -> Option<f64> {
    use prometheus::proto::MetricType;
    for f in prometheus::gather().iter().filter(|f| f.name() == metric) {
        for m in f.get_metric() {
            let matches = m.get_label().len() == labels.len()
                && labels.iter().all(|(k, v)| {
                    m.get_label()
                        .iter()
                        .any(|l| l.name() == *k && l.value() == *v)
                });
            if matches {
                return Some(match f.get_field_type() {
                    MetricType::GAUGE => m.get_gauge().value(),
                    MetricType::COUNTER => m.get_counter().value(),
                    _ => m.get_histogram().get_sample_count() as f64,
                });
            }
        }
    }
    None
}

fn stats(group: &str, resource: &str) -> (Option<f64>, Option<f64>, Option<f64>) {
    (
        sample(
            "apiserver_resource_objects",
            &[("group", group), ("resource", resource)],
        ),
        sample(
            "apiserver_resource_size_estimate_bytes",
            &[("group", group), ("resource", resource)],
        ),
        sample(
            "apiserver_storage_objects",
            &[("resource", &format!("{resource}.{group}"))],
        ),
    )
}

#[test]
fn storage_metrics_update_store_stats() {
    let s = |c, b| Stats {
        object_count: c,
        estimated_average_object_size_bytes: b,
    };
    // successful object count (no size estimate yet: -1)
    update_store_stats("usg1", "bar", s(10, 0), false);
    assert_eq!(stats("usg1", "bar"), (Some(10.0), Some(-1.0), Some(10.0)));
    // successful object count and size
    update_store_stats("usg2", "bar", s(10, 10), false);
    assert_eq!(stats("usg2", "bar"), (Some(10.0), Some(100.0), Some(10.0)));
    // empty object count
    update_store_stats("usg3", "bar", s(0, 0), false);
    assert_eq!(stats("usg3", "bar"), (Some(0.0), Some(0.0), Some(0.0)));
    // failed fetch
    update_store_stats("usg4", "bar", Stats::default(), true);
    assert_eq!(stats("usg4", "bar"), (Some(-1.0), Some(-1.0), Some(-1.0)));
}

#[test]
fn storage_metrics_delete_store_stats() {
    update_store_stats(
        "dsg1",
        "bar1",
        Stats {
            object_count: 10,
            estimated_average_object_size_bytes: 0,
        },
        false,
    );
    update_store_stats(
        "dsg2",
        "bar2",
        Stats {
            object_count: 20,
            estimated_average_object_size_bytes: 10,
        },
        false,
    );
    assert_eq!(stats("dsg1", "bar1"), (Some(10.0), Some(-1.0), Some(10.0)));
    assert_eq!(stats("dsg2", "bar2"), (Some(20.0), Some(200.0), Some(20.0)));
    delete_store_stats("dsg1", "bar1");
    assert_eq!(stats("dsg1", "bar1"), (None, None, None));
    assert_eq!(stats("dsg2", "bar2"), (Some(20.0), Some(200.0), Some(20.0)));
    delete_store_stats("dsg2", "bar2");
    assert_eq!(stats("dsg2", "bar2"), (None, None, None));
}

#[test]
fn storage_metrics_record_etcd_request() {
    let l = |v: &'static str| [("operation", v), ("group", "rg"), ("resource", "rr")];
    record_etcd_request("get", "rg", "rr", false, Instant::now());
    record_etcd_request(
        "get",
        "rg",
        "rr",
        true,
        Instant::now() - Duration::from_secs(1),
    );
    record_etcd_request("create", "rg", "rr", true, Instant::now());
    assert_eq!(sample("etcd_requests_total", &l("get")), Some(2.0));
    assert_eq!(sample("etcd_request_errors_total", &l("get")), Some(1.0));
    assert_eq!(sample("etcd_request_errors_total", &l("create")), Some(1.0));
    assert_eq!(
        sample("etcd_request_duration_seconds", &l("get")),
        Some(2.0)
    );
}

#[test]
fn storage_metrics_decode_event_bookmark_list_and_lease() {
    record_decode_error("mg", "mr");
    record_decode_error("mg", "mr");
    assert_eq!(
        sample(
            "apiserver_storage_decode_errors_total",
            &[("group", "mg"), ("resource", "mr")]
        ),
        Some(2.0)
    );
    record_etcd_event("mg", "mr");
    record_etcd_bookmark("mg", "mr");
    let gr = [("group", "mg"), ("resource", "mr")];
    assert_eq!(
        sample("apiserver_storage_events_received_total", &gr),
        Some(1.0)
    );
    assert_eq!(sample("etcd_bookmark_counts", &gr), Some(1.0));
    record_storage_list_metrics("mg", "mr", 5, 4, 3);
    assert_eq!(sample("apiserver_storage_list_total", &gr), Some(1.0));
    assert_eq!(
        sample("apiserver_storage_list_fetched_objects_total", &gr),
        Some(5.0)
    );
    assert_eq!(
        sample("apiserver_storage_list_evaluated_objects_total", &gr),
        Some(4.0)
    );
    assert_eq!(
        sample("apiserver_storage_list_returned_objects_total", &gr),
        Some(3.0)
    );
    update_lease_object_count(10);
    assert!(sample("etcd_lease_object_counts", &[]).unwrap() >= 1.0);
}
