//! Ports of `pkg/scheduler/metrics/metric_recorder_test.go` (TestInc,
//! TestDec, TestClear, TestInFlightEventAsync) plus checks of the collector
//! names, labels and buckets from `metrics.go`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use kubernetes_rs_scheduler::metrics::*;
use prometheus::Registry;

fn fresh() -> (SchedulerMetrics, Registry) {
    let m = SchedulerMetrics::new();
    let r = Registry::new();
    m.register(&r, MetricFeatureGates::default()).unwrap();
    (m, r)
}

fn run_threads(rec: &Arc<PendingPodsRecorder>, incs: usize, decs: usize) {
    let mut hs = Vec::new();
    for _ in 0..incs {
        let r = rec.clone();
        hs.push(std::thread::spawn(move || r.inc()));
    }
    for _ in 0..decs {
        let r = rec.clone();
        hs.push(std::thread::spawn(move || r.dec()));
    }
    for h in hs {
        h.join().unwrap();
    }
}

#[test]
fn scheduler_metrics_inc_dec_clear() {
    let (m, _r) = fresh();
    let rec = Arc::new(PendingPodsRecorder::new_active_pods_recorder(&m));
    run_threads(&rec, 100, 80);
    assert_eq!(m.active_pods().get(), 20.0);
    // Other queues are separate series.
    assert_eq!(m.backoff_pods().get(), 0.0);
    rec.clear();
    assert_eq!(m.active_pods().get(), 0.0);
}

#[test]
fn scheduler_metrics_in_flight_event_async() {
    let (m, _r) = fresh();
    let mut r = MetricAsyncRecorder::new_manual(m.clone(), 100, Duration::from_secs(3600));

    r.observe_in_flight_events_async("Pod/Add", 10.0, false);
    r.observe_in_flight_events_async("Pod/Add", -1.0, false);
    r.observe_in_flight_events_async(POD_POPPED_IN_FLIGHT_EVENT, 1.0, false);
    let want: HashMap<String, i64> = [
        ("Pod/Add".to_string(), 9),
        (POD_POPPED_IN_FLIGHT_EVENT.to_string(), 1),
    ]
    .into();
    assert_eq!(r.aggregated_in_flight_events(), &want);

    // Interval elapsed: this adds -4 and flushes to the buffer.
    r.set_last_in_flight_flush_ago(Duration::from_secs(3600 * 2));
    r.observe_in_flight_events_async("Pod/Add", -4.0, false);
    assert!(r.aggregated_in_flight_events().is_empty());

    let mut got = r.drain_in_flight_buffer();
    got.sort_by(|a, b| a.label_values[0].cmp(&b.label_values[0]));
    assert_eq!(
        got,
        vec![
            GaugeVecMetric {
                label_values: vec!["Pod/Add".into()],
                value_to_add: 5.0
            },
            GaugeVecMetric {
                label_values: vec![POD_POPPED_IN_FLIGHT_EVENT.into()],
                value_to_add: 1.0
            },
        ]
    );

    // Force flush.
    r.observe_in_flight_events_async("Pod/Add", 1.0, true);
    assert!(r.aggregated_in_flight_events().is_empty());
}

#[test]
fn scheduler_metrics_async_flush_reaches_collectors() {
    let (m, _r) = fresh();
    let mut r = MetricAsyncRecorder::new_manual(m.clone(), 10, Duration::from_secs(3600));
    r.observe_plugin_duration_async(FILTER, "NodeName", "Success", 0.5);
    r.observe_queueing_hint_duration_async("NodeName", "Node/Add", QUEUEING_HINT_RESULT_QUEUE, 0.1);
    r.observe_in_flight_events_async("Pod/Add", 3.0, true);
    r.flush_metrics();
    let h = m
        .plugin_execution_duration
        .with_label_values(&["NodeName", FILTER, "Success"]);
    assert_eq!(h.get_sample_count(), 1);
    let q = m
        .queueing_hint_execution_duration
        .with_label_values(&["NodeName", "Node/Add", "Queue"]);
    assert_eq!(q.get_sample_count(), 1);
    assert_eq!(
        m.in_flight_events.with_label_values(&["Pod/Add"]).get(),
        3.0
    );
}

#[test]
fn scheduler_metrics_async_buffer_drops_when_full() {
    let (m, _r) = fresh();
    let r = MetricAsyncRecorder::new_manual(m.clone(), 2, Duration::from_secs(3600));
    for _ in 0..5 {
        r.observe_plugin_duration_async(FILTER, "P", "Success", 1.0);
    }
    r.flush_metrics();
    r.flush_metrics();
    let h = m
        .plugin_execution_duration
        .with_label_values(&["P", FILTER, "Success"]);
    assert_eq!(h.get_sample_count(), 2);
}

#[test]
fn scheduler_metrics_profile_result_helpers() {
    let (m, _r) = fresh();
    m.pod_scheduled("default-scheduler", 0.01);
    m.pod_unschedulable("default-scheduler", 0.02);
    m.pod_unschedulable("default-scheduler", 0.02);
    m.pod_schedule_error("p2", 0.03);
    let c = |res: &str, p: &str| m.schedule_attempts.with_label_values(&[res, p]).get();
    assert_eq!(c("scheduled", "default-scheduler"), 1.0);
    assert_eq!(c("unschedulable", "default-scheduler"), 2.0);
    assert_eq!(c("error", "p2"), 1.0);
    assert_eq!(
        m.scheduling_latency
            .with_label_values(&["unschedulable", "default-scheduler"])
            .get_sample_count(),
        2
    );
}

#[test]
fn scheduler_metrics_names_labels_and_buckets() {
    let (m, r) = fresh();
    m.pod_scheduled("p", 0.001);
    m.pending_pods.with_label_values(&["gated"]).inc();
    m.preemption_victims.observe(3.0);
    let fams = r.gather();
    let by: HashMap<_, _> = fams.iter().map(|f| (f.name().to_string(), f)).collect();

    let f = by["scheduler_schedule_attempts_total"];
    let labels: Vec<_> = f.get_metric()[0]
        .get_label()
        .iter()
        .map(|l| l.name().to_string())
        .collect();
    assert_eq!(labels, vec!["profile", "result"]);

    let f = by["scheduler_scheduling_attempt_duration_seconds"];
    let b: Vec<f64> = f.get_metric()[0]
        .get_histogram()
        .get_bucket()
        .iter()
        .map(|b| b.upper_bound())
        .collect();
    assert_eq!(b.len(), 15);
    assert!((b[0] - 0.001).abs() < 1e-12 && (b[14] - 16.384).abs() < 1e-9);

    // ExponentialBuckets(1, 2, 7): 1..64.
    let f = by["scheduler_preemption_victims"];
    let b: Vec<f64> = f.get_metric()[0]
        .get_histogram()
        .get_bucket()
        .iter()
        .map(|b| b.upper_bound())
        .collect();
    assert_eq!(b, vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0]);

    assert!(by.contains_key("scheduler_pending_pods"));
}

#[test]
fn scheduler_metrics_feature_gated_registration() {
    let m = SchedulerMetrics::new();
    let r = Registry::new();
    let gates = MetricFeatureGates {
        scheduler_queueing_hints: false,
        scheduler_async_preemption: false,
        scheduler_async_api_calls: false,
        dra_extended_resource: false,
    };
    m.register(&r, gates).unwrap();
    // Touch one child of each vec so it shows up in gather().
    m.in_flight_events.with_label_values(&["e"]).inc();
    m.async_api_pending_calls.with_label_values(&["c"]).inc();
    let names: Vec<String> = r.gather().iter().map(|f| f.name().to_string()).collect();
    assert!(!names.contains(&"scheduler_inflight_events".to_string()));
    assert!(!names.contains(&"scheduler_pending_async_api_calls".to_string()));

    // Defaults register queueing hints, async preemption and async API calls.
    let (m2, r2) = fresh();
    m2.in_flight_events.with_label_values(&["e"]).inc();
    m2.async_api_pending_calls.with_label_values(&["c"]).inc();
    m2.resource_claim_creates_total
        .with_label_values(&["ok"])
        .inc();
    let names: Vec<String> = r2.gather().iter().map(|f| f.name().to_string()).collect();
    assert!(names.contains(&"scheduler_inflight_events".to_string()));
    assert!(names.contains(&"scheduler_pending_async_api_calls".to_string()));
    assert!(!names.contains(&"scheduler_resourceclaim_creates_total".to_string()));
}

#[tokio::test]
async fn scheduler_metrics_run_loop_flushes_and_stops() {
    let (m, _r) = fresh();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (rec, mut stopped) =
        MetricAsyncRecorder::new(m.clone(), 10, Duration::from_millis(10), stop_rx);
    rec.observe_plugin_duration_async(SCORE, "P", "Success", 0.2);
    let h = m
        .plugin_execution_duration
        .with_label_values(&["P", SCORE, "Success"]);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while h.get_sample_count() == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(h.get_sample_count(), 1);
    stop_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), stopped.wait_for(|v| *v))
        .await
        .expect("recorder stopped in time")
        .unwrap();
}

struct CountingRecorder(std::sync::Arc<std::sync::atomic::AtomicI64>);

impl MetricRecorder for CountingRecorder {
    fn inc(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn dec(&self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn clear(&self) {
        self.0.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

/// `TestHeapWithRecorder` (`backend/heap/heap_test.go:275`).
#[test]
fn scheduler_metrics_heap_with_recorder() {
    use kubernetes_rs_scheduler::queue::heap::Heap;
    use std::sync::atomic::{AtomicI64, Ordering};
    let count = Arc::new(AtomicI64::new(0));
    let mut h: Heap<(String, i64)> = Heap::new_with_recorder(
        Box::new(|(k, _): &(String, i64)| k.clone()),
        Box::new(|a: &(String, i64), b: &(String, i64)| a.1 < b.1),
        Some(Box::new(CountingRecorder(count.clone()))),
    );
    for (k, v) in [("foo", 10), ("bar", 1), ("baz", 100), ("qux", 11)] {
        h.add_or_update((k.to_string(), v));
    }
    assert_eq!(count.load(Ordering::SeqCst), 4);
    // An update of an existing key does not count again.
    h.add_or_update(("foo".to_string(), 9));
    assert_eq!(count.load(Ordering::SeqCst), 4);
    h.delete(&("bar".to_string(), 1)).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 3);
    // A failed delete does not count.
    assert!(h.delete(&("nope".to_string(), 0)).is_err());
    assert_eq!(count.load(Ordering::SeqCst), 3);
    h.pop().unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
}
