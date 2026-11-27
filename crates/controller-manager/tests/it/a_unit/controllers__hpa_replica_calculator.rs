//! Unit tests moved from `src/controllers/hpa_replica_calculator.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use kubernetes_rs_controller_manager::controllers::hpa_metrics_client::PodMetricsInfo;
}

mod tests {
    use super::__parent::*;
    use kubernetes_rs_controller_manager::controllers::hpa_metrics_client::FakeMetricsClient;
    use kubernetes_rs_controller_manager::controllers::hpa_replica_calculator::*;

    #[test]
    fn pods_metric_doubles_replicas() {
        // 2 pods @ 200 each, target 100/pod -> ratio 2.0 -> 2*2=4
        let info = FakeMetricsClient::pods_info(&[("p1", 200, None), ("p2", 200, None)]);
        let (replicas, avg) = get_metric_replicas(&info, 2, 100, Tolerances::default()).unwrap();
        assert_eq!(replicas, 4);
        assert_eq!(avg, 200);
    }

    #[test]
    fn within_tolerance_keeps_current() {
        // avg 105 vs target 100 -> ratio 1.05 (<=0.1 band) -> unchanged
        let info = FakeMetricsClient::pods_info(&[("p1", 105, None)]);
        let (replicas, _) = get_metric_replicas(&info, 3, 100, Tolerances::default()).unwrap();
        assert_eq!(replicas, 3);
    }

    #[test]
    fn empty_pods_errors() {
        let info = PodMetricsInfo::new();
        assert!(get_metric_replicas(&info, 2, 100, Tolerances::default()).is_err());
        assert!(get_resource_replicas(&info, 2, 80, Tolerances::default()).is_err());
    }

    #[test]
    fn external_sum_over_per_pod_target() {
        // queue depth 90 total, target 30/pod -> ceil(90/30)=3
        let (replicas, sum) =
            get_external_metric_replicas(&[90], 1, 30, Tolerances::default()).unwrap();
        assert_eq!(replicas, 3);
        assert_eq!(sum, 90);
    }

    #[test]
    fn object_ratio() {
        // value 200, target 100, current 2 -> 4
        let (replicas, _) = get_object_metric_replicas(200, 2, 100, Tolerances::default()).unwrap();
        assert_eq!(replicas, 4);
    }

    // Port of TestReplicaCalcConfigurableTolerance (replica_calculator_test.go:1336).
    fn resource_case(util: i32, tol: Tolerances) -> i32 {
        let info = FakeMetricsClient::pods_info(&[("p1", 1, Some(util))]);
        get_resource_replicas(&info, 3, 100, tol).unwrap().0
    }

    #[test]
    fn hpa_tolerance_configurable_resource() {
        let d = TOLERANCE;
        let t = |down, up| Tolerances {
            scale_down: down,
            scale_up: up,
        };
        assert_eq!(resource_case(101, t(0., 0.)), 4, "outside 0% tolerance");
        assert_eq!(resource_case(190, t(d, 2.)), 3, "within 200% scale-up");
        assert_eq!(resource_case(109, t(2., 0.08)), 4, "outside 8% scale-up");
        assert_eq!(resource_case(65, t(0.36, d)), 3, "within 36% scale-down");
        assert_eq!(resource_case(65, t(0.34, d)), 2, "outside 34% scale-down");
    }

    #[test]
    fn hpa_tolerance_external_per_pod() {
        // GetExternalPerPodMetricReplicas: ratio 90/(30*3) = 1.0 is within.
        let t = Tolerances::default();
        assert_eq!(get_external_metric_replicas(&[90], 3, 30, t).unwrap().0, 3);
        // ratio 1.5 outside the default band -> ceil(90/20) = 5.
        assert_eq!(get_external_metric_replicas(&[90], 3, 20, t).unwrap().0, 5);
        // ... but within a 60% scale-up tolerance.
        let wide = Tolerances {
            scale_down: 0.1,
            scale_up: 0.6,
        };
        assert_eq!(
            get_external_metric_replicas(&[90], 3, 20, wide).unwrap().0,
            3
        );
    }

    #[test]
    fn hpa_tolerance_for_hpa_behavior_overrides() {
        use kubernetes_rs_common::resources::{HPAScalingRules, HorizontalPodAutoscalerBehavior};
        let rules = |tol: &str| HPAScalingRules {
            stabilization_window_seconds: None,
            select_policy: None,
            policies: None,
            tolerance: Some(tol.to_string()),
        };
        // No behavior: controller-wide default both ways (horizontal.go:1460).
        assert_eq!(
            tolerances_for_hpa(None, 0.2),
            Tolerances {
                scale_down: 0.2,
                scale_up: 0.2
            }
        );
        let b = HorizontalPodAutoscalerBehavior {
            scale_up: Some(rules("0.9")),
            scale_down: Some(rules("10m")),
        };
        assert_eq!(
            tolerances_for_hpa(Some(&b), 0.1),
            Tolerances {
                scale_down: 0.01,
                scale_up: 0.9
            }
        );
        // Unset direction falls back to the default.
        let b = HorizontalPodAutoscalerBehavior {
            scale_up: Some(rules("0.05")),
            scale_down: None,
        };
        assert_eq!(
            tolerances_for_hpa(Some(&b), 0.1),
            Tolerances {
                scale_down: 0.1,
                scale_up: 0.05
            }
        );
    }
}
