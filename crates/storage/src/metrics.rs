//! Storage metrics: port of
//! `staging/src/k8s.io/apiserver/pkg/storage/etcd3/metrics/metrics.go`
//! (release-1.35), with the backend-neutral recorders upstream's etcd3 store
//! calls. Names and labels are kept as upstream (`etcd_*`), like k3s/kine does
//! for non-etcd backends. This module only defines the collectors and the
//! `Record*`/`Update*` functions; the record sites are wired separately.
//!
//! Not ported: the `apiserver_storage_size_bytes` monitor collector
//! (`monitorCollector`, `SetStorageMonitorGetter`) and the deprecated
//! `apiserver_storage_db_total_size_in_bytes` (`UpdateEtcdDbSize`), which need
//! an etcd `Monitor`.

use std::sync::LazyLock;
use std::time::Instant;

use prometheus::{
    register, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts,
};

/// `SizeBasedListCostEstimate` (beta, on by default since 1.34).
fn size_based_list_cost_estimate() -> bool {
    kubernetes_rs_common::feature_gates::gate_enabled("SizeBasedListCostEstimate").unwrap_or(false)
}

fn counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(Opts::new(name, help), labels).expect("valid metric");
    let _ = register(Box::new(c.clone()));
    c
}

fn gauge_vec(name: &str, help: &str, labels: &[&str]) -> GaugeVec {
    let g = GaugeVec::new(Opts::new(name, help), labels).expect("valid metric");
    let _ = register(Box::new(g.clone()));
    g
}

/// `etcdRequestLatency`: buckets from metrics.go:45-50.
static ETCD_REQUEST_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "etcd_request_duration_seconds",
            "[ALPHA] Etcd request latency in seconds for each operation and object type.",
        )
        .buckets(vec![
            0.005, 0.025, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2.0, 3.0, 4.0, 5.0, 6.0,
            8.0, 10.0, 15.0, 20.0, 30.0, 45.0, 60.0,
        ]),
        &["operation", "group", "resource"],
    )
    .expect("valid metric");
    let _ = register(Box::new(h.clone()));
    h
});

static ETCD_REQUEST_COUNTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "etcd_requests_total",
        "[ALPHA] Etcd request counts for each operation and object type.",
        &["operation", "group", "resource"],
    )
});

static ETCD_REQUEST_ERROR_COUNTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "etcd_request_errors_total",
        "[ALPHA] Etcd failed request counts for each operation and object type.",
        &["operation", "group", "resource"],
    )
});

/// `objectCounts` (deprecated since 1.34.0, label `resource` is `group.resource`).
static OBJECT_COUNTS: LazyLock<GaugeVec> = LazyLock::new(|| {
    gauge_vec(
        "apiserver_storage_objects",
        "[STABLE] [DEPRECATED, consider using apiserver_resource_objects instead] Number of stored objects at the time of last check split by kind. In case of a fetching error, the value will be -1.",
        &["resource"],
    )
});

static RESOURCE_SIZE_ESTIMATE: LazyLock<GaugeVec> = LazyLock::new(|| {
    gauge_vec(
        "apiserver_resource_size_estimate_bytes",
        "[ALPHA] Estimated size of stored objects in database. Estimate is based on sum of last observed sizes of serialized objects. In case of a fetching error, the value will be -1.",
        &["group", "resource"],
    )
});

static NEW_OBJECT_COUNTS: LazyLock<GaugeVec> = LazyLock::new(|| {
    gauge_vec(
        "apiserver_resource_objects",
        "[ALPHA] Number of stored objects at the time of last check split by kind. In case of a fetching error, the value will be -1.",
        &["group", "resource"],
    )
});

static ETCD_EVENTS_RECEIVED_COUNTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "apiserver_storage_events_received_total",
        "[ALPHA] Number of etcd events received split by kind.",
        &["group", "resource"],
    )
});

static ETCD_BOOKMARK_COUNTS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "etcd_bookmark_counts",
            "[ALPHA] Number of etcd bookmarks (progress notify events) split by kind.",
        ),
        &["group", "resource"],
    )
    .expect("valid metric");
    let _ = register(Box::new(g.clone()));
    g
});

/// `etcdLeaseObjectCounts`: no labels.
static ETCD_LEASE_OBJECT_COUNTS: LazyLock<Histogram> = LazyLock::new(|| {
    let h = Histogram::with_opts(
        HistogramOpts::new(
            "etcd_lease_object_counts",
            "[ALPHA] Number of objects attached to a single etcd lease.",
        )
        .buckets(vec![10.0, 50.0, 100.0, 500.0, 1000.0, 2500.0, 5000.0]),
    )
    .expect("valid metric");
    let _ = register(Box::new(h.clone()));
    h
});

static LIST_STORAGE_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "apiserver_storage_list_total",
        "[ALPHA] Number of LIST requests served from storage",
        &["group", "resource"],
    )
});

static LIST_STORAGE_NUM_FETCHED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "apiserver_storage_list_fetched_objects_total",
        "[ALPHA] Number of objects read from storage in the course of serving a LIST request",
        &["group", "resource"],
    )
});

static LIST_STORAGE_NUM_SELECTOR_EVALS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "apiserver_storage_list_evaluated_objects_total",
        "[ALPHA] Number of objects tested in the course of serving a LIST request from storage",
        &["group", "resource"],
    )
});

static LIST_STORAGE_NUM_RETURNED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "apiserver_storage_list_returned_objects_total",
        "[ALPHA] Number of objects returned for a LIST request from storage",
        &["group", "resource"],
    )
});

static DECODE_ERROR_COUNTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec(
        "apiserver_storage_decode_errors_total",
        "[ALPHA] Number of stored object decode errors split by object type",
        &["group", "resource"],
    )
});

/// `storage.Stats`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub object_count: i64,
    pub estimated_average_object_size_bytes: i64,
}

/// `schema.GroupResource.String()`: `resource` or `resource.group`.
fn group_resource_string(group: &str, resource: &str) -> String {
    if group.is_empty() {
        resource.to_string()
    } else {
        format!("{resource}.{group}")
    }
}

/// `Register`: force-register every collector (they register on first use).
pub fn register_metrics() {
    LazyLock::force(&ETCD_REQUEST_LATENCY);
    LazyLock::force(&ETCD_REQUEST_COUNTS);
    LazyLock::force(&ETCD_REQUEST_ERROR_COUNTS);
    LazyLock::force(&OBJECT_COUNTS);
    LazyLock::force(&RESOURCE_SIZE_ESTIMATE);
    LazyLock::force(&NEW_OBJECT_COUNTS);
    LazyLock::force(&ETCD_EVENTS_RECEIVED_COUNTS);
    LazyLock::force(&ETCD_BOOKMARK_COUNTS);
    LazyLock::force(&ETCD_LEASE_OBJECT_COUNTS);
    LazyLock::force(&LIST_STORAGE_COUNT);
    LazyLock::force(&LIST_STORAGE_NUM_FETCHED);
    LazyLock::force(&LIST_STORAGE_NUM_SELECTOR_EVALS);
    LazyLock::force(&LIST_STORAGE_NUM_RETURNED);
    LazyLock::force(&DECODE_ERROR_COUNTS);
}

/// `UpdateStoreStats` (metrics.go:196). `err` is whether fetching the stats failed.
pub fn update_store_stats(group: &str, resource: &str, stats: Stats, err: bool) {
    let gr = group_resource_string(group, resource);
    let size_gate = size_based_list_cost_estimate();
    if err {
        OBJECT_COUNTS.with_label_values(&[&gr]).set(-1.0);
        NEW_OBJECT_COUNTS
            .with_label_values(&[group, resource])
            .set(-1.0);
        if size_gate {
            RESOURCE_SIZE_ESTIMATE
                .with_label_values(&[group, resource])
                .set(-1.0);
        }
        return;
    }
    OBJECT_COUNTS
        .with_label_values(&[&gr])
        .set(stats.object_count as f64);
    NEW_OBJECT_COUNTS
        .with_label_values(&[group, resource])
        .set(stats.object_count as f64);
    if size_gate {
        let v = if stats.object_count > 0 && stats.estimated_average_object_size_bytes == 0 {
            -1.0
        } else {
            (stats.estimated_average_object_size_bytes * stats.object_count) as f64
        };
        RESOURCE_SIZE_ESTIMATE
            .with_label_values(&[group, resource])
            .set(v);
    }
}

/// `DeleteStoreStats` (metrics.go:222).
pub fn delete_store_stats(group: &str, resource: &str) {
    let gr = group_resource_string(group, resource);
    let _ = OBJECT_COUNTS.remove_label_values(&[&gr]);
    let _ = NEW_OBJECT_COUNTS.remove_label_values(&[group, resource]);
    if size_based_list_cost_estimate() {
        let _ = RESOURCE_SIZE_ESTIMATE.remove_label_values(&[group, resource]);
    }
}

/// `RecordEtcdRequest` (metrics.go:233): latency, count and (on error) error count.
pub fn record_etcd_request(verb: &str, group: &str, resource: &str, err: bool, start: Instant) {
    ETCD_REQUEST_LATENCY
        .with_label_values(&[verb, group, resource])
        .observe(start.elapsed().as_secs_f64());
    ETCD_REQUEST_COUNTS
        .with_label_values(&[verb, group, resource])
        .inc();
    if err {
        ETCD_REQUEST_ERROR_COUNTS
            .with_label_values(&[verb, group, resource])
            .inc();
    }
}

/// `RecordEtcdEvent` (metrics.go:242).
pub fn record_etcd_event(group: &str, resource: &str) {
    ETCD_EVENTS_RECEIVED_COUNTS
        .with_label_values(&[group, resource])
        .inc();
}

/// `RecordEtcdBookmark` (metrics.go:247).
pub fn record_etcd_bookmark(group: &str, resource: &str) {
    ETCD_BOOKMARK_COUNTS
        .with_label_values(&[group, resource])
        .inc();
}

/// `RecordDecodeError` (metrics.go:252).
pub fn record_decode_error(group: &str, resource: &str) {
    DECODE_ERROR_COUNTS
        .with_label_values(&[group, resource])
        .inc();
}

/// `Reset` (metrics.go:257): resets `etcd_request_duration_seconds`.
pub fn reset() {
    ETCD_REQUEST_LATENCY.reset();
}

/// `UpdateLeaseObjectCount` (metrics.go:277).
pub fn update_lease_object_count(count: i64) {
    ETCD_LEASE_OBJECT_COUNTS.observe(count as f64);
}

/// `RecordStorageListMetrics` (metrics.go:285).
pub fn record_storage_list_metrics(
    group: &str,
    resource: &str,
    num_fetched: usize,
    num_evald: usize,
    num_returned: usize,
) {
    LIST_STORAGE_COUNT
        .with_label_values(&[group, resource])
        .inc();
    LIST_STORAGE_NUM_FETCHED
        .with_label_values(&[group, resource])
        .inc_by(num_fetched as u64);
    LIST_STORAGE_NUM_SELECTOR_EVALS
        .with_label_values(&[group, resource])
        .inc_by(num_evald as u64);
    LIST_STORAGE_NUM_RETURNED
        .with_label_values(&[group, resource])
        .inc_by(num_returned as u64);
}
