//! Scheduler metrics with the upstream names, labels and buckets.
//!
//! Port of `pkg/scheduler/metrics/metrics.go` (collectors, label constants,
//! `InitMetrics`, `Register`), `metric_recorder.go` (`PendingPodsRecorder`,
//! `MetricAsyncRecorder`) and `profile_metrics.go` (`PodScheduled`,
//! `PodUnschedulable`, `PodScheduleError`), release-1.35.
//!
//! Nothing records into these collectors yet; wiring the scheduler is a
//! follow-up (see the backlog task `scheduler-P1-02b`).

use std::collections::HashMap;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use prometheus::{
    exponential_buckets, Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts,
    HistogramVec, Opts, Registry,
};

/// `SchedulerSubsystem` (metrics.go:34).
pub const SCHEDULER_SUBSYSTEM: &str = "scheduler";

// Work / operation label values (metrics.go:38-43).
pub const PRIORITIZING_EXTENDER: &str = "prioritizing_extender";
pub const BINDING: &str = "binding";

// metrics.go:45-48.
pub const GOROUTINE_RESULT_SUCCESS: &str = "success";
pub const GOROUTINE_RESULT_ERROR: &str = "error";

// Extension point label values (metrics.go:50-84).
pub const PRE_FILTER: &str = "PreFilter";
pub const FILTER: &str = "Filter";
pub const PRE_FILTER_EXTENSION_ADD_POD: &str = "PreFilterExtensionAddPod";
pub const PRE_FILTER_EXTENSION_REMOVE_POD: &str = "PreFilterExtensionRemovePod";
pub const POST_FILTER: &str = "PostFilter";
pub const PRE_SCORE: &str = "PreScore";
pub const SCORE: &str = "Score";
pub const SCORE_EXTENSION_NORMALIZE: &str = "ScoreExtensionNormalize";
pub const PRE_BIND: &str = "PreBind";
pub const PRE_BIND_PRE_FLIGHT: &str = "PreBindPreFlight";
pub const BIND: &str = "Bind";
pub const POST_BIND: &str = "PostBind";
pub const RESERVE: &str = "Reserve";
pub const UNRESERVE: &str = "Unreserve";
pub const PERMIT: &str = "Permit";
pub const SIGN: &str = "Sign";

/// `ExtensionPoints` (metrics.go:50-67).
pub const EXTENSION_POINTS: [&str; 16] = [
    PRE_FILTER,
    FILTER,
    PRE_FILTER_EXTENSION_ADD_POD,
    PRE_FILTER_EXTENSION_REMOVE_POD,
    POST_FILTER,
    PRE_SCORE,
    SCORE,
    SCORE_EXTENSION_NORMALIZE,
    PRE_BIND,
    PRE_BIND_PRE_FLIGHT,
    BIND,
    POST_BIND,
    RESERVE,
    UNRESERVE,
    PERMIT,
    SIGN,
];

// Queueing hint results (metrics.go:86-90).
pub const QUEUEING_HINT_RESULT_QUEUE: &str = "Queue";
pub const QUEUEING_HINT_RESULT_QUEUE_SKIP: &str = "QueueSkip";
pub const QUEUEING_HINT_RESULT_ERROR: &str = "Error";

/// `PodPoppedInFlightEvent` (metrics.go:92-94).
pub const POD_POPPED_IN_FLIGHT_EVENT: &str = "PodPopped";

// Batch attempt results (metrics.go:96-101).
pub const BATCH_ATTEMPT_NO_HINT: &str = "no_hint";
pub const BATCH_ATTEMPT_HINT_USED: &str = "hint_used";
pub const BATCH_ATTEMPT_HINT_NOT_USED: &str = "hint_not_used";

// Batch cache flush reasons (metrics.go:103-112).
pub const BATCH_FLUSH_POD_FAILED: &str = "pod_failed";
pub const BATCH_FLUSH_POD_SKIPPED: &str = "pod_skipped";
pub const BATCH_FLUSH_NODE_MISSING: &str = "node_missing";
pub const BATCH_FLUSH_NODE_NOT_FULL: &str = "node_not_full";
pub const BATCH_FLUSH_EMPTY_LIST: &str = "empty_list";
pub const BATCH_FLUSH_EXPIRED: &str = "expired";
pub const BATCH_FLUSH_POD_INCOMPATIBLE: &str = "pod_incompatible";
pub const BATCH_FLUSH_POD_NOT_BATCHABLE: &str = "pod_not_batchable";

// profile_metrics.go:21-25.
pub const SCHEDULED_RESULT: &str = "scheduled";
pub const UNSCHEDULABLE_RESULT: &str = "unschedulable";
pub const ERROR_RESULT: &str = "error";

/// The feature gates `Register` consults (metrics.go:Register). Defaults are
/// the release-1.35 defaults from `pkg/features/kube_features.go`.
#[derive(Debug, Clone, Copy)]
pub struct MetricFeatureGates {
    /// SchedulerQueueingHints (GA, locked to true).
    pub scheduler_queueing_hints: bool,
    /// SchedulerAsyncPreemption (Beta, default true).
    pub scheduler_async_preemption: bool,
    /// SchedulerAsyncAPICalls (Beta, default true).
    pub scheduler_async_api_calls: bool,
    /// DRAExtendedResource (Alpha, default false).
    pub dra_extended_resource: bool,
}

impl Default for MetricFeatureGates {
    fn default() -> Self {
        Self {
            scheduler_queueing_hints: true,
            scheduler_async_preemption: true,
            scheduler_async_api_calls: true,
            dra_extended_resource: false,
        }
    }
}

fn opts(name: &str, help: &str) -> Opts {
    Opts::new(name, help).subsystem(SCHEDULER_SUBSYSTEM)
}

fn hist(name: &str, help: &str, start: f64, factor: f64, count: usize) -> HistogramOpts {
    HistogramOpts::new(name, help)
        .subsystem(SCHEDULER_SUBSYSTEM)
        .buckets(exponential_buckets(start, factor, count).expect("valid buckets"))
}

fn counter_vec(name: &str, help: &str, labels: &[&str]) -> CounterVec {
    CounterVec::new(opts(name, help), labels).expect("valid counter")
}

fn gauge_vec(name: &str, help: &str, labels: &[&str]) -> GaugeVec {
    GaugeVec::new(opts(name, help), labels).expect("valid gauge")
}

fn hist_vec(o: HistogramOpts, labels: &[&str]) -> HistogramVec {
    HistogramVec::new(o, labels).expect("valid histogram")
}

/// All scheduler collectors (the `var (...)` block in metrics.go:114-150),
/// built by [`SchedulerMetrics::new`] (`InitMetrics`).
#[derive(Clone)]
pub struct SchedulerMetrics {
    pub schedule_attempts: CounterVec,
    pub event_handling_latency: HistogramVec,
    pub scheduling_latency: HistogramVec,
    pub scheduling_algorithm_latency: Histogram,
    pub preemption_victims: Histogram,
    pub preemption_attempts: Counter,
    pub pending_pods: GaugeVec,
    pub in_flight_events: GaugeVec,
    pub goroutines: GaugeVec,
    pub batch_attempt_stats: CounterVec,
    pub batch_cache_flushed: CounterVec,
    pub get_node_hint_duration: HistogramVec,
    pub store_schedule_results_duration: HistogramVec,
    pub pod_scheduling_sli_duration: HistogramVec,
    pub pod_scheduling_attempts: Histogram,
    pub framework_extension_point_duration: HistogramVec,
    pub plugin_execution_duration: HistogramVec,
    pub permit_wait_duration: HistogramVec,
    pub cache_size: GaugeVec,
    pub unschedulable_reasons: GaugeVec,
    pub plugin_evaluation_total: CounterVec,
    pub queueing_hint_execution_duration: HistogramVec,
    pub scheduler_queue_incoming_pods: CounterVec,
    pub preemption_goroutines_duration: HistogramVec,
    pub preemption_goroutines_execution_total: CounterVec,
    pub async_api_calls_total: CounterVec,
    pub async_api_call_duration: HistogramVec,
    pub async_api_pending_calls: GaugeVec,
    pub resource_claim_creates_total: CounterVec,
}

impl Default for SchedulerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerMetrics {
    /// `InitMetrics` (metrics.go:`InitMetrics`): names, help, labels and
    /// buckets copied verbatim.
    pub fn new() -> Self {
        Self {
            schedule_attempts: counter_vec(
                "schedule_attempts_total",
                "Number of attempts to schedule pods, by the result. 'unschedulable' means a pod could not be scheduled, while 'error' means an internal scheduler problem.",
                &["result", "profile"],
            ),
            event_handling_latency: hist_vec(
                hist(
                    "event_handling_duration_seconds",
                    "Event handling latency in seconds.",
                    0.0001,
                    2.0,
                    12,
                ),
                &["event"],
            ),
            scheduling_latency: hist_vec(
                hist(
                    "scheduling_attempt_duration_seconds",
                    "Scheduling attempt latency in seconds (scheduling algorithm + binding)",
                    0.001,
                    2.0,
                    15,
                ),
                &["result", "profile"],
            ),
            scheduling_algorithm_latency: Histogram::with_opts(hist(
                "scheduling_algorithm_duration_seconds",
                "Scheduling algorithm latency in seconds",
                0.001,
                2.0,
                15,
            ))
            .expect("valid histogram"),
            preemption_victims: Histogram::with_opts(hist(
                "preemption_victims",
                "Number of selected preemption victims",
                1.0,
                2.0,
                7,
            ))
            .expect("valid histogram"),
            preemption_attempts: Counter::with_opts(opts(
                "preemption_attempts_total",
                "Total preemption attempts in the cluster till now",
            ))
            .expect("valid counter"),
            pending_pods: gauge_vec(
                "pending_pods",
                "Number of pending pods, by the queue type. 'active' means number of pods in activeQ; 'backoff' means number of pods in backoffQ; 'unschedulable' means number of pods in unschedulablePods that the scheduler attempted to schedule and failed; 'gated' is the number of unschedulable pods that the scheduler never attempted to schedule because they are gated.",
                &["queue"],
            ),
            in_flight_events: gauge_vec(
                "inflight_events",
                "Number of events currently tracked in the scheduling queue.",
                &["event"],
            ),
            goroutines: gauge_vec(
                "goroutines",
                "Number of running goroutines split by the work they do such as binding.",
                &["operation"],
            ),
            batch_attempt_stats: counter_vec(
                "batch_attempts_total",
                "Counts of results when we attempt to use batching.",
                &["profile", "result"],
            ),
            batch_cache_flushed: counter_vec(
                "batch_cache_flushed_total",
                "Counts of cache flushes by reason.",
                &["profile", "reason"],
            ),
            get_node_hint_duration: hist_vec(
                hist(
                    "get_node_hint_duration_seconds",
                    "Latency for getting a node hint.",
                    0.00001,
                    2.0,
                    12,
                ),
                &["hinted", "profile"],
            ),
            store_schedule_results_duration: hist_vec(
                hist(
                    "store_schedule_results_duration_seconds",
                    "Latency for getting a no.",
                    0.00001,
                    2.0,
                    12,
                ),
                &["profile"],
            ),
            pod_scheduling_sli_duration: hist_vec(
                hist(
                    "pod_scheduling_sli_duration_seconds",
                    "E2e latency for a pod being scheduled, from the time the pod enters the scheduling queue and might involve multiple scheduling attempts.",
                    0.01,
                    2.0,
                    20,
                ),
                &["attempts"],
            ),
            pod_scheduling_attempts: Histogram::with_opts(hist(
                "pod_scheduling_attempts",
                "Number of attempts to successfully schedule a pod.",
                1.0,
                2.0,
                5,
            ))
            .expect("valid histogram"),
            framework_extension_point_duration: hist_vec(
                hist(
                    "framework_extension_point_duration_seconds",
                    "Latency for running all plugins of a specific extension point.",
                    0.0001,
                    2.0,
                    12,
                ),
                &["extension_point", "status", "profile"],
            ),
            plugin_execution_duration: hist_vec(
                hist(
                    "plugin_execution_duration_seconds",
                    "Duration for running a plugin at a specific extension point.",
                    0.00001,
                    1.5,
                    20,
                ),
                &["plugin", "extension_point", "status"],
            ),
            permit_wait_duration: hist_vec(
                hist(
                    "permit_wait_duration_seconds",
                    "Duration of waiting on permit.",
                    0.001,
                    2.0,
                    15,
                ),
                &["result"],
            ),
            cache_size: gauge_vec(
                "cache_size",
                "Number of nodes, pods, and assumed (bound) pods in the scheduler cache.",
                &["type"],
            ),
            unschedulable_reasons: gauge_vec(
                "unschedulable_pods",
                "The number of unschedulable pods broken down by plugin name. A pod will increment the gauge for all plugins that caused it to not schedule and so this metric have meaning only when broken down by plugin.",
                &["plugin", "profile"],
            ),
            plugin_evaluation_total: counter_vec(
                "plugin_evaluation_total",
                "Number of attempts to schedule pods by each plugin and the extension point (available only in PreFilter, Filter, PreScore, and Score).",
                &["plugin", "extension_point", "profile"],
            ),
            queueing_hint_execution_duration: hist_vec(
                hist(
                    "queueing_hint_execution_duration_seconds",
                    "Duration for running a queueing hint function of a plugin.",
                    0.00001,
                    1.5,
                    20,
                ),
                &["plugin", "event", "hint"],
            ),
            scheduler_queue_incoming_pods: counter_vec(
                "queue_incoming_pods_total",
                "Number of pods added to scheduling queues by event and queue type.",
                &["queue", "event"],
            ),
            preemption_goroutines_duration: hist_vec(
                hist(
                    "preemption_goroutines_duration_seconds",
                    "Duration in seconds for running goroutines for the preemption.",
                    0.01,
                    2.0,
                    20,
                ),
                &["result"],
            ),
            preemption_goroutines_execution_total: counter_vec(
                "preemption_goroutines_execution_total",
                "Number of preemption goroutines executed.",
                &["result"],
            ),
            async_api_calls_total: counter_vec(
                "async_api_call_execution_total",
                "Total number of API calls executed by the async dispatcher.",
                &["call_type", "result"],
            ),
            async_api_call_duration: hist_vec(
                hist(
                    "async_api_call_execution_duration_seconds",
                    "Duration in seconds for executing API call in the async dispatcher.",
                    0.001,
                    2.0,
                    15,
                ),
                &["call_type", "result"],
            ),
            async_api_pending_calls: gauge_vec(
                "pending_async_api_calls",
                "Number of API calls currently pending in the async queue.",
                &["call_type"],
            ),
            resource_claim_creates_total: counter_vec(
                "resourceclaim_creates_total",
                "Number of ResourceClaims creation requests within scheduler",
                &["status"],
            ),
        }
    }

    /// `Register` (metrics.go:`Register`): the always-registered list
    /// (`metricsList`) plus the feature-gated collectors.
    pub fn register(
        &self,
        registry: &Registry,
        gates: MetricFeatureGates,
    ) -> prometheus::Result<()> {
        macro_rules! reg {
            ($($f:ident),+ $(,)?) => {
                $( registry.register(Box::new(self.$f.clone()))?; )+
            };
        }
        // metricsList (metrics.go, end of InitMetrics).
        reg!(
            schedule_attempts,
            scheduling_latency,
            scheduling_algorithm_latency,
            event_handling_latency,
            preemption_victims,
            preemption_attempts,
            pending_pods,
            pod_scheduling_sli_duration,
            pod_scheduling_attempts,
            framework_extension_point_duration,
            plugin_execution_duration,
            scheduler_queue_incoming_pods,
            goroutines,
            permit_wait_duration,
            cache_size,
            unschedulable_reasons,
            plugin_evaluation_total,
            batch_attempt_stats,
            batch_cache_flushed,
            get_node_hint_duration,
            store_schedule_results_duration,
        );
        if gates.scheduler_queueing_hints {
            reg!(queueing_hint_execution_duration, in_flight_events);
        }
        if gates.scheduler_async_preemption {
            reg!(
                preemption_goroutines_duration,
                preemption_goroutines_execution_total
            );
        }
        if gates.scheduler_async_api_calls {
            reg!(
                async_api_calls_total,
                async_api_call_duration,
                async_api_pending_calls
            );
        }
        if gates.dra_extended_resource {
            reg!(resource_claim_creates_total);
        }
        Ok(())
    }

    /// `ActivePods` (metrics.go).
    pub fn active_pods(&self) -> Gauge {
        self.pending_pods.with_label_values(&["active"])
    }

    /// `BackoffPods` (metrics.go).
    pub fn backoff_pods(&self) -> Gauge {
        self.pending_pods.with_label_values(&["backoff"])
    }

    /// `UnschedulablePods` (metrics.go).
    pub fn unschedulable_pods(&self) -> Gauge {
        self.pending_pods.with_label_values(&["unschedulable"])
    }

    /// `GatedPods` (metrics.go).
    pub fn gated_pods(&self) -> Gauge {
        self.pending_pods.with_label_values(&["gated"])
    }

    /// `UnschedulableReason` (metrics.go).
    pub fn unschedulable_reason(&self, plugin: &str, profile: &str) -> Gauge {
        self.unschedulable_reasons
            .with_label_values(&[plugin, profile])
    }

    /// `PodScheduled` (profile_metrics.go).
    pub fn pod_scheduled(&self, profile: &str, duration: f64) {
        self.observe_schedule_attempt_and_latency(SCHEDULED_RESULT, profile, duration);
    }

    /// `PodUnschedulable` (profile_metrics.go).
    pub fn pod_unschedulable(&self, profile: &str, duration: f64) {
        self.observe_schedule_attempt_and_latency(UNSCHEDULABLE_RESULT, profile, duration);
    }

    /// `PodScheduleError` (profile_metrics.go).
    pub fn pod_schedule_error(&self, profile: &str, duration: f64) {
        self.observe_schedule_attempt_and_latency(ERROR_RESULT, profile, duration);
    }

    /// `observeScheduleAttemptAndLatency` (profile_metrics.go).
    fn observe_schedule_attempt_and_latency(&self, result: &str, profile: &str, duration: f64) {
        self.scheduling_latency
            .with_label_values(&[result, profile])
            .observe(duration);
        self.schedule_attempts
            .with_label_values(&[result, profile])
            .inc();
    }
}

static GLOBAL: LazyLock<SchedulerMetrics> = LazyLock::new(|| {
    let m = SchedulerMetrics::new();
    // `registerMetrics.Do(...)`: once, into the process-wide registry. An
    // AlreadyReg error means another component registered first; ignore it.
    let _ = m.register(
        prometheus::default_registry(),
        MetricFeatureGates::default(),
    );
    m
});

/// The process-wide collectors, registered once in the default registry
/// (`Register()` + the package-level variables upstream).
pub fn metrics() -> &'static SchedulerMetrics {
    &GLOBAL
}

/// `SinceInSeconds` (metrics.go).
pub fn since_in_seconds(start: Instant) -> f64 {
    start.elapsed().as_secs_f64()
}

/// `MetricRecorder` (metric_recorder.go).
pub trait MetricRecorder {
    fn inc(&self);
    fn dec(&self);
    fn clear(&self);
}

/// `PendingPodsRecorder` (metric_recorder.go).
pub struct PendingPodsRecorder {
    recorder: Gauge,
}

impl PendingPodsRecorder {
    pub fn new_active_pods_recorder(m: &SchedulerMetrics) -> Self {
        Self {
            recorder: m.active_pods(),
        }
    }

    pub fn new_unschedulable_pods_recorder(m: &SchedulerMetrics) -> Self {
        Self {
            recorder: m.unschedulable_pods(),
        }
    }

    pub fn new_backoff_pods_recorder(m: &SchedulerMetrics) -> Self {
        Self {
            recorder: m.backoff_pods(),
        }
    }

    pub fn new_gated_pods_recorder(m: &SchedulerMetrics) -> Self {
        Self {
            recorder: m.gated_pods(),
        }
    }
}

impl MetricRecorder for PendingPodsRecorder {
    fn inc(&self) {
        self.recorder.inc();
    }

    fn dec(&self) {
        self.recorder.dec();
    }

    fn clear(&self) {
        self.recorder.set(0.0);
    }
}

/// Which histogram a buffered observation belongs to.
#[derive(Clone, Copy)]
enum HistogramTarget {
    PluginExecution,
    QueueingHintExecution,
}

struct HistogramVecMetric {
    target: HistogramTarget,
    label_values: Vec<String>,
    value: f64,
}

/// `gaugeVecMetric` for the in-flight events gauge.
#[derive(Debug, Clone, PartialEq)]
pub struct GaugeVecMetric {
    pub label_values: Vec<String>,
    pub value_to_add: f64,
}

struct Buffers {
    histograms: Receiver<HistogramVecMetric>,
    inflight: Receiver<GaugeVecMetric>,
}

/// `MetricAsyncRecorder` (metric_recorder.go): buffers hot-path observations
/// in bounded channels (dropping when full, as the `select ... default`
/// upstream) and flushes them to the collectors on an interval.
pub struct MetricAsyncRecorder {
    metrics: SchedulerMetrics,
    histogram_tx: SyncSender<HistogramVecMetric>,
    inflight_tx: SyncSender<GaugeVecMetric>,
    buffers: Arc<Mutex<Buffers>>,
    buffer_size: usize,
    interval: Duration,
    aggregated_inflight_event_metric: HashMap<String, i64>,
    aggregated_inflight_event_metric_last_flush_time: Instant,
}

impl MetricAsyncRecorder {
    /// A recorder without the background flusher (callers invoke
    /// [`Self::flush_metrics`]); the struct literal upstream's test builds.
    pub fn new_manual(metrics: SchedulerMetrics, buffer_size: usize, interval: Duration) -> Self {
        let (htx, hrx) = sync_channel(buffer_size);
        let (itx, irx) = sync_channel(buffer_size);
        Self {
            metrics,
            histogram_tx: htx,
            inflight_tx: itx,
            buffers: Arc::new(Mutex::new(Buffers {
                histograms: hrx,
                inflight: irx,
            })),
            buffer_size,
            interval,
            aggregated_inflight_event_metric: HashMap::new(),
            aggregated_inflight_event_metric_last_flush_time: Instant::now(),
        }
    }

    /// `NewMetricsAsyncRecorder`: also starts the flush loop (`go
    /// recorder.run()`) on the current tokio runtime. The loop ends when
    /// `stop` becomes true; the returned receiver is `IsStoppedCh`.
    pub fn new(
        metrics: SchedulerMetrics,
        buffer_size: usize,
        interval: Duration,
        stop: tokio::sync::watch::Receiver<bool>,
    ) -> (Self, tokio::sync::watch::Receiver<bool>) {
        let recorder = Self::new_manual(metrics, buffer_size, interval);
        let (stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
        let flusher = recorder.flusher();
        tokio::spawn(async move {
            // run (metric_recorder.go): check stop, flush, sleep.
            loop {
                if *stop.borrow() {
                    let _ = stopped_tx.send(true);
                    return;
                }
                flusher.flush();
                tokio::time::sleep(interval).await;
            }
        });
        (recorder, stopped_rx)
    }

    fn flusher(&self) -> Flusher {
        Flusher {
            metrics: self.metrics.clone(),
            buffers: self.buffers.clone(),
            buffer_size: self.buffer_size,
        }
    }

    /// `ObservePluginDurationAsync`.
    pub fn observe_plugin_duration_async(
        &self,
        extension_point: &str,
        plugin_name: &str,
        status: &str,
        value: f64,
    ) {
        self.observe_metric_async(
            HistogramTarget::PluginExecution,
            value,
            [plugin_name, extension_point, status],
        );
    }

    /// `ObserveQueueingHintDurationAsync`.
    pub fn observe_queueing_hint_duration_async(
        &self,
        plugin_name: &str,
        event: &str,
        hint: &str,
        value: f64,
    ) {
        self.observe_metric_async(
            HistogramTarget::QueueingHintExecution,
            value,
            [plugin_name, event, hint],
        );
    }

    /// `ObserveInFlightEventsAsync`: aggregates locally and hands the totals
    /// to the buffer when `force_flush` or the interval elapsed.
    pub fn observe_in_flight_events_async(
        &mut self,
        event_label: &str,
        value_to_add: f64,
        force_flush: bool,
    ) {
        *self
            .aggregated_inflight_event_metric
            .entry(event_label.to_string())
            .or_insert(0) += value_to_add as i64;

        if force_flush
            || self
                .aggregated_inflight_event_metric_last_flush_time
                .elapsed()
                > self.interval
        {
            for (label, value) in self.aggregated_inflight_event_metric.drain() {
                let _ = self.inflight_tx.try_send(GaugeVecMetric {
                    label_values: vec![label],
                    value_to_add: value as f64,
                });
            }
            self.aggregated_inflight_event_metric_last_flush_time = Instant::now();
        }
    }

    /// The not yet flushed in-flight aggregation (white-box view for tests).
    pub fn aggregated_in_flight_events(&self) -> &HashMap<String, i64> {
        &self.aggregated_inflight_event_metric
    }

    /// Pretend the last in-flight flush happened `ago` ago (test hook for the
    /// interval-triggered flush).
    pub fn set_last_in_flight_flush_ago(&mut self, ago: Duration) {
        self.aggregated_inflight_event_metric_last_flush_time = Instant::now() - ago;
    }

    /// Drain what `observe_in_flight_events_async` sent to the buffer without
    /// applying it (white-box view for tests).
    pub fn drain_in_flight_buffer(&self) -> Vec<GaugeVecMetric> {
        let b = self.buffers.lock().expect("buffers lock");
        b.inflight.try_iter().collect()
    }

    fn observe_metric_async(&self, target: HistogramTarget, value: f64, labels: [&str; 3]) {
        // `select { case r.bufferCh <- m: default: }`
        let _ = self.histogram_tx.try_send(HistogramVecMetric {
            target,
            label_values: labels.iter().map(|s| s.to_string()).collect(),
            value,
        });
    }

    /// `FlushMetrics`.
    pub fn flush_metrics(&self) {
        self.flusher().flush();
    }
}

struct Flusher {
    metrics: SchedulerMetrics,
    buffers: Arc<Mutex<Buffers>>,
    buffer_size: usize,
}

impl Flusher {
    /// `FlushMetrics`: up to `buffer_size` entries of each buffer.
    fn flush(&self) {
        let b = self.buffers.lock().expect("buffers lock");
        for _ in 0..self.buffer_size {
            if let Ok(m) = b.histograms.try_recv() {
                let vec = match m.target {
                    HistogramTarget::PluginExecution => &self.metrics.plugin_execution_duration,
                    HistogramTarget::QueueingHintExecution => {
                        &self.metrics.queueing_hint_execution_duration
                    }
                };
                let labels: Vec<&str> = m.label_values.iter().map(String::as_str).collect();
                vec.with_label_values(&labels).observe(m.value);
            }
            if let Ok(m) = b.inflight.try_recv() {
                let labels: Vec<&str> = m.label_values.iter().map(String::as_str).collect();
                self.metrics
                    .in_flight_events
                    .with_label_values(&labels)
                    .add(m.value_to_add);
            }
        }
    }
}
