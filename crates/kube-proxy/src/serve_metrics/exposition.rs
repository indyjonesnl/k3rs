//! SLI routes and legacy-registry exposition from server.go:466,474.
use axum::{
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts,
    Registry,
};
use std::{collections::BTreeMap, sync::OnceLock};

struct Metrics {
    slis: Registry,
    healthcheck: GaugeVec,
    healthchecks_total: IntCounterVec,
    process_start: GaugeVec,
    healthz: IntCounterVec,
    livez: IntCounterVec,
    started: i64,
    scrapes: IntCounterVec,
    in_flight: IntGauge,
    _instrumentation: Registry,
}

fn metrics() -> &'static Metrics {
    static METRICS: OnceLock<Metrics> = OnceLock::new();
    METRICS.get_or_init(|| {
        // slis/metrics.go:33-58: these health checks have a separate registry.
        let slis = Registry::new();
        let healthcheck = GaugeVec::new(
            Opts::new(
                "kubernetes_healthcheck",
                "[STABLE] This metric records the result of a single healthcheck.",
            ),
            &["name", "type"],
        )
        .expect("static SLI gauge definition");
        let healthchecks_total = IntCounterVec::new(
            Opts::new(
                "kubernetes_healthchecks_total",
                "[STABLE] This metric records the results of all healthcheck.",
            ),
            &["name", "type", "status"],
        )
        .expect("static SLI counter definition");
        let process_start = GaugeVec::new(
            Opts::new(
                "process_start_time_seconds",
                "[ALPHA] Start time of the process since unix epoch in seconds.",
            ),
            &[],
        )
        .expect("static process gauge definition");
        for collector in [
            Box::new(healthcheck.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(healthchecks_total.clone()),
            Box::new(process_start.clone()),
        ] {
            slis.register(collector).expect("unique SLI metric names");
        }
        let started = chrono::Utc::now().timestamp();
        // processstarttime_others.go:29-40 and procfs/proc_stat.go:218-223:
        // use boot time plus process start ticks/100, falling back to now
        // only when procfs cannot be read (processstarttime.go:37-40).
        let process_started = process_start_time().unwrap_or(started as f64);
        process_start
            .with_label_values(&[] as &[&str])
            .set(process_started);
        // pkg/proxy/metrics/metrics.go:231-250,324-325: response counters live
        // in the legacy registry, not the SLI registry.
        let healthz = IntCounterVec::new(
            Opts::new(
                "kubeproxy_proxy_healthz_total",
                "[ALPHA] Cumulative proxy healthz HTTP status",
            ),
            &["code"],
        )
        .expect("static proxy health counter");
        let livez = IntCounterVec::new(
            Opts::new(
                "kubeproxy_proxy_livez_total",
                "[ALPHA] Cumulative proxy livez HTTP status",
            ),
            &["code"],
        )
        .expect("static proxy live counter");
        prometheus::default_registry()
            .register(Box::new(healthz.clone()))
            .expect("proxy health metrics registered once");
        prometheus::default_registry()
            .register(Box::new(livez.clone()))
            .expect("proxy live metrics registered once");
        // legacyregistry/registry.go:63-65 registers scrape instrumentation
        // with Prometheus.DefaultRegisterer, a distinct registry from the
        // legacy gatherer. These counters are not returned by /metrics.
        // promhttp/http.go:286-320 initializes 200/500/503 and in-flight.
        let instrumentation = Registry::new();
        let scrapes = IntCounterVec::new(
            Opts::new(
                "promhttp_metric_handler_requests_total",
                "Total number of scrapes by HTTP status code.",
            ),
            &["code"],
        )
        .expect("static scrape counter");
        for code in ["200", "500", "503"] {
            scrapes.with_label_values(&[code]);
        }
        let in_flight = IntGauge::new(
            "promhttp_metric_handler_requests_in_flight",
            "Current number of scrapes being served.",
        )
        .expect("static in-flight gauge");
        instrumentation
            .register(Box::new(scrapes.clone()))
            .expect("unique scrape counter");
        instrumentation
            .register(Box::new(in_flight.clone()))
            .expect("unique scrape gauge");
        Metrics {
            slis,
            healthcheck,
            healthchecks_total,
            process_start,
            healthz,
            livez,
            started,
            scrapes,
            in_flight,
            _instrumentation: instrumentation,
        }
    })
}

fn process_start_time() -> Option<f64> {
    let process = std::fs::read_to_string("/proc/self/stat").ok()?;
    let (_, fields) = process.rsplit_once(')')?;
    let ticks: f64 = fields.split_whitespace().nth(19)?.parse().ok()?;
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let boot: f64 = stat
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .parse()
        .ok()?;
    Some(boot + ticks / 100.0)
}

struct InFlight<'a>(Option<&'a IntGauge>);
impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if let Some(gauge) = self.0 {
            gauge.dec();
        }
    }
}

pub(super) fn initialize() {
    let _ = metrics();
}

/// The kube-proxy collectors of pkg/proxy/metrics/metrics.go:38-322
/// (subsystem `kubeproxy`). Recording hooks use these handles. The two
/// `*_nfacct` collectors (metrics.go:166,278) are not defined here.
pub struct KubeProxyMetrics {
    pub sync_proxy_rules_latency: HistogramVec,
    pub sync_full_proxy_rules_latency: HistogramVec,
    pub sync_partial_proxy_rules_latency: HistogramVec,
    pub sync_proxy_rules_last_timestamp: GaugeVec,
    pub network_programming_latency: HistogramVec,
    pub endpoint_changes_pending: IntGauge,
    pub endpoint_changes_total: IntCounter,
    pub service_changes_pending: IntGauge,
    pub service_changes_total: IntCounter,
    pub iptables_restore_failures_total: IntCounterVec,
    pub iptables_partial_restore_failures_total: IntCounterVec,
    pub iptables_rules_total: GaugeVec,
    pub iptables_rules_last_sync: GaugeVec,
    pub nftables_sync_failures_total: IntCounterVec,
    pub nftables_cleanup_failures_total: IntCounterVec,
    pub sync_proxy_rules_last_queued_timestamp: GaugeVec,
    pub sync_proxy_rules_no_local_endpoints_total: GaugeVec,
    pub reconcile_conntrack_flows_latency: HistogramVec,
    pub reconcile_conntrack_flows_deleted_entries_total: IntCounterVec,
}

const ALPHA: &str = "[ALPHA] ";

fn opts(name: &str, help: &str) -> Opts {
    Opts::new(name, format!("{ALPHA}{help}"))
}

fn histogram(name: &str, help: &str, buckets: Vec<f64>) -> HistogramVec {
    HistogramVec::new(
        HistogramOpts::new(name, format!("{ALPHA}{help}")).buckets(buckets),
        &["ip_family"],
    )
    .expect("static histogram definition")
}

fn counter_vec(name: &str, help: &str) -> IntCounterVec {
    IntCounterVec::new(opts(name, help), &["ip_family"]).expect("static counter definition")
}

fn gauge_vec(name: &str, help: &str, labels: &[&str]) -> GaugeVec {
    GaugeVec::new(opts(name, help), labels).expect("static gauge definition")
}

/// metrics.go:38-322 definitions.
pub fn kube_proxy_metrics() -> &'static KubeProxyMetrics {
    static M: OnceLock<KubeProxyMetrics> = OnceLock::new();
    M.get_or_init(|| {
        // metrics.ExponentialBuckets(0.001, 2, 15)
        let exp = || prometheus::exponential_buckets(0.001, 2.0, 15).expect("static buckets");
        // metrics.go:92-101 MergeBuckets of four LinearBuckets.
        let mut programming = Vec::new();
        for (start, width, count) in [
            (0.25, 0.25, 2),
            (1.0, 1.0, 59),
            (60.0, 5.0, 12),
            (120.0, 30.0, 7),
        ] {
            programming
                .extend(prometheus::linear_buckets(start, width, count).expect("static buckets"));
        }
        KubeProxyMetrics {
            sync_proxy_rules_latency: histogram(
                "kubeproxy_sync_proxy_rules_duration_seconds",
                "SyncProxyRules latency in seconds",
                exp(),
            ),
            sync_full_proxy_rules_latency: histogram(
                "kubeproxy_sync_full_proxy_rules_duration_seconds",
                "SyncProxyRules latency in seconds for full resyncs",
                exp(),
            ),
            sync_partial_proxy_rules_latency: histogram(
                "kubeproxy_sync_partial_proxy_rules_duration_seconds",
                "SyncProxyRules latency in seconds for partial resyncs",
                exp(),
            ),
            sync_proxy_rules_last_timestamp: gauge_vec(
                "kubeproxy_sync_proxy_rules_last_timestamp_seconds",
                "The last time proxy rules were successfully synced",
                &["ip_family"],
            ),
            network_programming_latency: histogram(
                "kubeproxy_network_programming_duration_seconds",
                "In Cluster Network Programming Latency in seconds",
                programming,
            ),
            endpoint_changes_pending: IntGauge::with_opts(opts(
                "kubeproxy_sync_proxy_rules_endpoint_changes_pending",
                "Pending proxy rules Endpoint changes",
            ))
            .expect("static gauge definition"),
            endpoint_changes_total: IntCounter::with_opts(opts(
                "kubeproxy_sync_proxy_rules_endpoint_changes_total",
                "Cumulative proxy rules Endpoint changes",
            ))
            .expect("static counter definition"),
            service_changes_pending: IntGauge::with_opts(opts(
                "kubeproxy_sync_proxy_rules_service_changes_pending",
                "Pending proxy rules Service changes",
            ))
            .expect("static gauge definition"),
            service_changes_total: IntCounter::with_opts(opts(
                "kubeproxy_sync_proxy_rules_service_changes_total",
                "Cumulative proxy rules Service changes",
            ))
            .expect("static counter definition"),
            iptables_restore_failures_total: counter_vec(
                "kubeproxy_sync_proxy_rules_iptables_restore_failures_total",
                "Cumulative proxy iptables restore failures",
            ),
            iptables_partial_restore_failures_total: counter_vec(
                "kubeproxy_sync_proxy_rules_iptables_partial_restore_failures_total",
                "Cumulative proxy iptables partial restore failures",
            ),
            iptables_rules_total: gauge_vec(
                "kubeproxy_sync_proxy_rules_iptables_total",
                "Total number of iptables rules owned by kube-proxy",
                &["table", "ip_family"],
            ),
            iptables_rules_last_sync: gauge_vec(
                "kubeproxy_sync_proxy_rules_iptables_last",
                "Number of iptables rules written by kube-proxy in last sync",
                &["table", "ip_family"],
            ),
            nftables_sync_failures_total: counter_vec(
                "kubeproxy_sync_proxy_rules_nftables_sync_failures_total",
                "Cumulative proxy nftables sync failures",
            ),
            nftables_cleanup_failures_total: counter_vec(
                "kubeproxy_sync_proxy_rules_nftables_cleanup_failures_total",
                "Cumulative proxy nftables cleanup failures",
            ),
            sync_proxy_rules_last_queued_timestamp: gauge_vec(
                "kubeproxy_sync_proxy_rules_last_queued_timestamp_seconds",
                "The last time a sync of proxy rules was queued",
                &["ip_family"],
            ),
            sync_proxy_rules_no_local_endpoints_total: gauge_vec(
                "kubeproxy_sync_proxy_rules_no_local_endpoints_total",
                "Number of services with a Local traffic policy and no endpoints",
                &["traffic_policy", "ip_family"],
            ),
            reconcile_conntrack_flows_latency: histogram(
                "kubeproxy_conntrack_reconciler_sync_duration_seconds",
                "ReconcileConntrackFlowsLatency latency in seconds",
                exp(),
            ),
            reconcile_conntrack_flows_deleted_entries_total: counter_vec(
                "kubeproxy_conntrack_reconciler_deleted_entries_total",
                "Cumulative conntrack flows deleted by conntrack reconciler",
            ),
        }
    })
}

/// metrics.go:309-358 `RegisterMetrics(mode)`: register the collectors for
/// `mode` in the legacy registry, once per process. The healthz/livez
/// counters (also registered there) are registered by [`metrics`].
pub fn register_metrics(mode: &str) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let m = kube_proxy_metrics();
        let reg = prometheus::default_registry();
        let add = |c: Box<dyn prometheus::core::Collector>| {
            reg.register(c).expect("kube-proxy metrics registered once");
        };
        // Core kube-proxy metrics for all backends (:314-325).
        add(Box::new(m.sync_proxy_rules_latency.clone()));
        add(Box::new(m.sync_proxy_rules_last_queued_timestamp.clone()));
        add(Box::new(m.sync_proxy_rules_last_timestamp.clone()));
        add(Box::new(m.endpoint_changes_pending.clone()));
        add(Box::new(m.endpoint_changes_total.clone()));
        add(Box::new(m.service_changes_pending.clone()));
        add(Box::new(m.service_changes_total.clone()));
        add(Box::new(m.network_programming_latency.clone()));
        add(Box::new(
            m.sync_proxy_rules_no_local_endpoints_total.clone(),
        ));
        let conntrack = |add: &dyn Fn(Box<dyn prometheus::core::Collector>)| {
            add(Box::new(m.reconcile_conntrack_flows_latency.clone()));
            add(Box::new(
                m.reconcile_conntrack_flows_deleted_entries_total.clone(),
            ));
        };
        match mode {
            "iptables" => {
                add(Box::new(m.sync_full_proxy_rules_latency.clone()));
                add(Box::new(m.sync_partial_proxy_rules_latency.clone()));
                add(Box::new(m.iptables_restore_failures_total.clone()));
                add(Box::new(m.iptables_partial_restore_failures_total.clone()));
                add(Box::new(m.iptables_rules_total.clone()));
                add(Box::new(m.iptables_rules_last_sync.clone()));
                conntrack(&add);
            }
            "ipvs" => {
                add(Box::new(m.iptables_restore_failures_total.clone()));
                conntrack(&add);
            }
            "nftables" => {
                add(Box::new(m.sync_full_proxy_rules_latency.clone()));
                add(Box::new(m.sync_partial_proxy_rules_latency.clone()));
                add(Box::new(m.nftables_sync_failures_total.clone()));
                add(Box::new(m.nftables_cleanup_failures_total.clone()));
                conntrack(&add);
            }
            // kernelspace: no winkernel-specific metrics.
            _ => {}
        }
    });
}

/// slis/metrics.go:66-73: successful root health checks record a gauge and count.
pub(super) fn observe_ping() {
    let metrics = metrics();
    metrics
        .healthcheck
        .with_label_values(&["ping", "healthz"])
        .set(1.0);
    metrics
        .healthchecks_total
        .with_label_values(&["ping", "healthz", "success"])
        .inc();
}

/// proxy_health.go:229-235,256-261: count each handler's returned HTTP code.
pub(super) fn observe_proxy_probe(healthz: bool, code: &str) {
    let metrics = metrics();
    let counter = if healthz {
        &metrics.healthz
    } else {
        &metrics.livez
    };
    counter.with_label_values(&[code]).inc();
}

// Port of vendor/github.com/munnerz/goautoneg/autoneg.go:98-165. Sort accept
// clauses by quality and specificity; expfmt falls back to text regardless of q.
fn accept_clauses(header: &str) -> Vec<(f32, String, BTreeMap<String, String>)> {
    let mut clauses = Vec::new();
    for clause in header.split(',') {
        let mut parts = clause.trim_matches(' ').split(';');
        let mime = parts.next().unwrap_or_default().trim_matches(' ');
        if mime != "*" && (mime.matches('/').count() != 1 || mime.ends_with('/')) {
            continue;
        }
        let mut params = BTreeMap::new();
        let mut quality: f32 = 1.0;
        for part in parts {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            if value.contains('=') {
                continue;
            }
            let key = key.trim_matches(' ');
            if key == "q" {
                quality = value.parse().unwrap_or(0.0);
            } else {
                params.insert(key.to_owned(), value.trim_matches(' ').to_owned());
            }
        }
        clauses.push((quality, mime.to_owned(), params));
    }
    // goautoneg/autoneg.go:62-74 compares quality and wildcard specificity.
    fn less(
        a: &(f32, String, BTreeMap<String, String>),
        b: &(f32, String, BTreeMap<String, String>),
    ) -> bool {
        if a.0 > b.0 {
            return true;
        }
        let (a_type, a_sub) = a.1.split_once('/').unwrap_or(("*", "*"));
        let (b_type, b_sub) = b.1.split_once('/').unwrap_or(("*", "*"));
        if a_type != "*" && b_type == "*" {
            return true;
        }
        a_sub != "*" && b_sub == "*"
    }
    // Insertion sort uses the upstream Less relation directly, including its
    // non-lexicographic wildcard behaviour (do not impose a stronger ordering).
    for i in 1..clauses.len() {
        let mut j = i;
        while j > 0 && less(&clauses[j], &clauses[j - 1]) {
            clauses.swap(j, j - 1);
            j -= 1;
        }
    }
    clauses
}

// vendor/github.com/prometheus/common/expfmt/encode.go:65-99: OpenMetrics is
// deliberately not negotiated by HandlerOpts{}; unsupported Accept => text.
fn format(header: &str) -> (String, String, String) {
    let mut escaping = "underscores".to_owned();
    for (_, mime, params) in accept_clauses(header) {
        if let Some(value) = params.get("escaping") {
            if ["allow-utf-8", "underscores", "dots", "values"].contains(&value.as_str()) {
                escaping.clone_from(value);
            }
        }
        if mime == "application/vnd.google.protobuf"
            && params
                .get("proto")
                .is_some_and(|v| v == "io.prometheus.client.MetricFamily")
        {
            if let Some(encoding) = params.get("encoding") {
                if ["delimited", "text", "compact-text"].contains(&encoding.as_str()) {
                    return (format!("application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding={encoding}; escaping={escaping}"), encoding.clone(), escaping);
                }
            }
        }
        if mime == "text/plain"
            && params
                .get("version")
                .is_none_or(|v| v.is_empty() || v == "0.0.4")
        {
            break;
        }
    }
    (
        format!("text/plain; version=0.0.4; charset=utf-8; escaping={escaping}"),
        "plain".to_owned(),
        escaping,
    )
}

// promhttp/http.go:465-490 and internal/github.com/golang/gddo/httputil/negotiate.go:19-39:
// identity wins equal qualities; unsupported/q=0 negotiation falls back to it.
fn encoding_specs(headers: &HeaderMap) -> Vec<(&str, f64)> {
    // Port header.ParseAccept, including stopping at an invalid parameter
    // within one header while continuing with other header values
    // (header/header.go:64-141).
    fn skip_space(value: &str) -> &str {
        value.trim_start_matches([' ', '\t', '\r', '\n'])
    }
    fn quality(value: &str) -> Option<(f64, &str)> {
        let first = *value.as_bytes().first()?;
        if first != b'0' && first != b'1' {
            return None;
        }
        let base = f64::from(first - b'0');
        let rest = &value[1..];
        let Some(rest) = rest.strip_prefix('.') else {
            return Some((base, rest));
        };
        let count = rest.bytes().take_while(u8::is_ascii_digit).count();
        let mut numerator: i64 = 0;
        let mut denominator: i64 = 1;
        for digit in rest.bytes().take(count) {
            numerator = numerator
                .wrapping_mul(10)
                .wrapping_add(i64::from(digit - b'0'));
            denominator = denominator.wrapping_mul(10);
        }
        Some((base + numerator as f64 / denominator as f64, &rest[count..]))
    }
    let mut specs = Vec::new();
    for header in headers.get_all("accept-encoding") {
        let Ok(mut rest) = header.to_str() else {
            continue;
        };
        loop {
            let count = rest
                .bytes()
                .take_while(|byte| {
                    *byte == b'/'
                        || (*byte > 32 && *byte < 127 && !b"\"(),/:;<=>?@[]\\{}".contains(byte))
                })
                .count();
            if count == 0 {
                break;
            }
            let token = &rest[..count];
            rest = skip_space(&rest[count..]);
            let mut q = 1.0;
            if let Some(parameters) = rest.strip_prefix(';') {
                let Some(value) = skip_space(parameters).strip_prefix("q=") else {
                    break;
                };
                let Some((parsed, remaining)) = quality(value) else {
                    break;
                };
                q = parsed;
                rest = remaining;
            }
            specs.push((token, q));
            let Some(remaining) = skip_space(rest).strip_prefix(',') else {
                break;
            };
            rest = skip_space(remaining);
        }
    }
    specs
}

fn wants_gzip(headers: &HeaderMap) -> bool {
    let specs = encoding_specs(headers);
    let mut best = -1.0;
    let mut selected = "identity";
    for offer in ["identity", "gzip"] {
        for (encoding, quality) in &specs {
            if *quality > best && (*encoding == offer || *encoding == "*") {
                best = *quality;
                selected = offer;
            }
        }
    }
    best > 0.0 && selected == "gzip"
}

fn gzip(body: &[u8]) -> Vec<u8> {
    // promhttp uses compress/gzip, whose gzip.go:147-158,246-248 writes a
    // header, DEFLATE, then CRC32/ISIZE. Use existing locked Rust codecs.
    let mut encoded = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    encoded.extend(miniz_oxide::deflate::compress_to_vec(body, 6));
    encoded.extend(
        crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC)
            .checksum(body)
            .to_le_bytes(),
    );
    encoded.extend((body.len() as u32).to_le_bytes());
    encoded
}

pub(super) fn render(headers: HeaderMap, slis: bool, method: Method) -> Response {
    let metrics = metrics();
    // component-base/metrics/http.go:77-85 and registry.go:396-401:
    // DELETE resets every resettable collector in the SLI registry only.
    if slis && method == Method::DELETE {
        metrics.healthcheck.reset();
        metrics.healthchecks_total.reset();
        metrics.process_start.reset();
        return (
            [("Content-Type", "text/plain; charset=utf-8")],
            "metrics reset\n",
        )
            .into_response();
    }
    // promhttp.InstrumentHandlerInFlight defers decrement even on panic.
    let _in_flight = if slis {
        InFlight(None)
    } else {
        metrics.in_flight.inc();
        InFlight(Some(&metrics.in_flight))
    };
    let families = if slis {
        metrics.slis.gather()
    } else {
        prometheus::default_registry().gather()
    };
    let accept = headers
        .get("accept")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let (content_type, encoding, escaping) = format(accept);
    // model/metric.go:353-359 preserves legacy-valid metric/label names,
    // which prometheus validates when these collectors are registered.
    let _ = escaping;
    let mut body = Vec::new();
    let result = match encoding.as_str() {
        "delimited" => prometheus::ProtobufEncoder::new().encode(&families, &mut body),
        "text" | "compact-text" => {
            for family in &families {
                let text = if encoding == "text" {
                    protobuf::text_format::print_to_string_pretty(family)
                } else {
                    protobuf::text_format::print_to_string(family)
                };
                body.extend(text.as_bytes());
                body.push(b'\n');
            }
            Ok(())
        }
        _ => prometheus::TextEncoder::new().encode(&families, &mut body),
    };
    // promhttp/http.go:157-158: process-start header is independent of format.
    let response = match result {
        Ok(()) => {
            let compressed = wants_gzip(&headers);
            if compressed {
                body = gzip(&body);
            }
            let mut response = (
                [
                    ("Content-Type", content_type),
                    ("Process-Start-Time-Unix", metrics.started.to_string()),
                ],
                body,
            )
                .into_response();
            if compressed {
                response.headers_mut().insert(
                    "Content-Encoding",
                    axum::http::HeaderValue::from_static("gzip"),
                );
            }
            response
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("An error has occurred while serving metrics:\n\n{error}\n"),
        )
            .into_response(),
    };
    // InstrumentHandlerCounter updates only after serving the response.
    if !slis {
        metrics
            .scrapes
            .with_label_values(&[response.status().as_str()])
            .inc();
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    // legacyregistry/registry.go:63-65 and promhttp/http.go:286-320:
    // count legacy scrapes, but don't instrument the separate SLI handler.
    #[test]
    #[serial_test::serial]
    fn legacy_scrapes_are_instrumented_separately() {
        let metrics = metrics();
        let before = metrics.scrapes.with_label_values(&["200"]).get();
        assert_eq!(render(HeaderMap::new(), false, Method::GET).status(), 200);
        assert_eq!(
            metrics.scrapes.with_label_values(&["200"]).get(),
            before + 1
        );
        assert_eq!(metrics.in_flight.get(), 0);
        assert_eq!(render(HeaderMap::new(), true, Method::GET).status(), 200);
        assert_eq!(
            metrics.scrapes.with_label_values(&["200"]).get(),
            before + 1
        );
        assert!(metrics
            ._instrumentation
            .gather()
            .iter()
            .any(|family| family.name() == "promhttp_metric_handler_requests_total"));
    }
}
