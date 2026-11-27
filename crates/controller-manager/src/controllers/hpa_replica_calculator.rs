//! Pure HPA replica math, ported from k8s
//! `pkg/controller/podautoscaler/replica_calculator.go`.
//!
//! All functions are side-effect-free and unit-testable.
//! `desired = ceil(current * usageRatio)` with the k8s tolerance band: if
//! `|ratio - 1| <= TOLERANCE`, keep current replicas (avoid thrashing).

use crate::controllers::hpa_metrics_client::PodMetricsInfo;

/// k8s default scale tolerance (10%): `--horizontal-pod-autoscaler-tolerance`
/// default (`defaultTestingTolerance` in replica_calculator.go).
pub const TOLERANCE: f64 = 0.1;

/// Metric usage ratio scale-up and scale-down tolerances. Port of
/// `Tolerances` (replica_calculator.go:46-60).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tolerances {
    pub scale_down: f64,
    pub scale_up: f64,
}

impl Default for Tolerances {
    fn default() -> Self {
        Self {
            scale_down: TOLERANCE,
            scale_up: TOLERANCE,
        }
    }
}

impl Tolerances {
    /// `isWithin`: `(1-down) <= ratio <= (1+up)`.
    pub fn is_within(&self, usage_ratio: f64) -> bool {
        (1.0 - self.scale_down) <= usage_ratio && usage_ratio <= (1.0 + self.scale_up)
    }
}

/// Whether `spec.behavior.{scaleUp,scaleDown}.tolerance` is honoured:
/// `HPAConfigurableTolerance` is Beta, on by default in 1.35.
const HPA_CONFIGURABLE_TOLERANCE: bool = true;

/// `Quantity.AsApproximateFloat64` for the decimal forms a tolerance takes
/// (`"0.05"`, `"50m"`, `"1"`). `None` when unparseable.
fn quantity_as_f64(q: &str) -> Option<f64> {
    let q = q.trim();
    let (num, mult) = match q.chars().last()? {
        'n' => (&q[..q.len() - 1], 1e-9),
        'u' => (&q[..q.len() - 1], 1e-6),
        'm' => (&q[..q.len() - 1], 1e-3),
        _ => (q, 1.0),
    };
    num.parse::<f64>().ok().map(|v| v * mult)
}

/// Port of `tolerancesForHpa` (horizontal.go:1456-1473): the controller-wide
/// tolerance, overridden per direction by `spec.behavior`.
pub fn tolerances_for_hpa(
    behavior: Option<&kubernetes_rs_common::resources::HorizontalPodAutoscalerBehavior>,
    default_tolerance: f64,
) -> Tolerances {
    let mut t = Tolerances {
        scale_down: default_tolerance,
        scale_up: default_tolerance,
    };
    let Some(behavior) = behavior else {
        return t;
    };
    if !HPA_CONFIGURABLE_TOLERANCE {
        return t;
    }
    if let Some(v) = behavior
        .scale_down
        .as_ref()
        .and_then(|r| r.tolerance.as_deref())
        .and_then(quantity_as_f64)
    {
        t.scale_down = v;
    }
    if let Some(v) = behavior
        .scale_up
        .as_ref()
        .and_then(|r| r.tolerance.as_deref())
        .and_then(quantity_as_f64)
    {
        t.scale_up = v;
    }
    t
}

fn scale(current_replicas: i32, usage_ratio: f64, tolerances: Tolerances) -> i32 {
    if tolerances.is_within(usage_ratio) {
        return current_replicas;
    }
    (current_replicas as f64 * usage_ratio).ceil() as i32
}

/// Average a per-pod metric and compute replicas vs a per-pod target
/// (Pods type, AverageValue). Errors if no pods reported.
pub fn get_metric_replicas(
    metrics: &PodMetricsInfo,
    current_replicas: i32,
    target_average_value: i64,
    tolerances: Tolerances,
) -> anyhow::Result<(i32, i64)> {
    if metrics.is_empty() {
        anyhow::bail!("no metrics returned for any pods");
    }
    let sum: i64 = metrics.values().map(|m| m.value).sum();
    let avg = sum / metrics.len() as i64;
    if target_average_value <= 0 {
        anyhow::bail!("target average value must be positive");
    }
    let ratio = avg as f64 / target_average_value as f64;
    Ok((scale(current_replicas, ratio, tolerances), avg))
}

/// Resource utilization (per-pod %). Errors if no pods reported.
pub fn get_resource_replicas(
    metrics: &PodMetricsInfo,
    current_replicas: i32,
    target_utilization: i32,
    tolerances: Tolerances,
) -> anyhow::Result<(i32, i32)> {
    if metrics.is_empty() {
        anyhow::bail!("no metrics returned for any pods");
    }
    let utils: Vec<i32> = metrics.values().filter_map(|m| m.utilization).collect();
    if utils.is_empty() {
        anyhow::bail!("no utilization data for any pods");
    }
    let avg = utils.iter().sum::<i32>() / utils.len() as i32;
    if target_utilization <= 0 {
        anyhow::bail!("target utilization must be positive");
    }
    let ratio = avg as f64 / target_utilization as f64;
    Ok((scale(current_replicas, ratio, tolerances), avg))
}

/// Object metric: single value vs target (Value) or per-pod average
/// (AverageValue).
pub fn get_object_metric_replicas(
    value: i64,
    current_replicas: i32,
    target_value: i64,
    tolerances: Tolerances,
) -> anyhow::Result<(i32, i64)> {
    if target_value <= 0 {
        anyhow::bail!("target value must be positive");
    }
    let ratio = value as f64 / target_value as f64;
    Ok((scale(current_replicas, ratio, tolerances), value))
}

/// External metric: sum of values vs a per-pod target
/// (`GetExternalPerPodMetricReplicas`, replica_calculator.go:382-420): the
/// current count is kept while `sum / (target * current)` is within the
/// tolerances, otherwise `ceil(sum / target)`.
pub fn get_external_metric_replicas(
    values: &[i64],
    current_replicas: i32,
    target_average_value: i64,
    tolerances: Tolerances,
) -> anyhow::Result<(i32, i64)> {
    if values.is_empty() {
        anyhow::bail!("no external metric values returned");
    }
    if target_average_value <= 0 {
        anyhow::bail!("target average value must be positive");
    }
    let sum: i64 = values.iter().sum();
    let ratio = sum as f64 / (target_average_value as f64 * current_replicas as f64);
    let desired = if tolerances.is_within(ratio) {
        current_replicas
    } else {
        (sum as f64 / target_average_value as f64).ceil() as i32
    };
    Ok((desired.max(1), sum))
}
