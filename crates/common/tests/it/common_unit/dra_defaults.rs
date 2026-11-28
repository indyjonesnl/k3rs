//! Ports of `pkg/apis/resource/v1/defaults_test.go` (`TestSetDefaultAllocationMode`,
//! `TestSetDefaultAllocationModeWithSubRequests`).

use kubernetes_rs_common::defaults::default_resource_claim_spec;
use kubernetes_rs_common::resources::dra::*;

fn exactly(mode: Option<DeviceAllocationMode>, count: Option<i64>) -> ExactDeviceRequest {
    serde_json::from_value::<ExactDeviceRequest>(serde_json::json!({}))
        .map(|mut e| {
            e.allocation_mode = mode;
            e.count = count;
            e
        })
        .unwrap()
}

fn sub(name: &str, mode: Option<DeviceAllocationMode>, count: Option<i64>) -> DeviceSubRequest {
    let mut s: DeviceSubRequest =
        serde_json::from_value(serde_json::json!({ "name": name })).unwrap();
    s.allocation_mode = mode;
    s.count = count;
    s
}

fn spec(requests: Vec<DeviceRequest>) -> ResourceClaimSpec {
    ResourceClaimSpec {
        devices: DeviceClaim {
            requests,
            ..Default::default()
        },
    }
}

#[test]
fn dra_defaults_allocation_mode() {
    let mut s = spec(vec![DeviceRequest {
        name: String::new(),
        exactly: Some(exactly(None, None)),
        first_available: vec![],
    }]);
    default_resource_claim_spec(&mut s);
    let e = s.devices.requests[0].exactly.as_ref().unwrap();
    assert_eq!(e.allocation_mode, Some(DeviceAllocationMode::ExactCount));
    assert_eq!(e.count, Some(1));

    // Explicit values do not change.
    let mut s = spec(vec![DeviceRequest {
        name: String::new(),
        exactly: Some(exactly(Some(DeviceAllocationMode::ExactCount), Some(10))),
        first_available: vec![],
    }]);
    default_resource_claim_spec(&mut s);
    let e = s.devices.requests[0].exactly.as_ref().unwrap();
    assert_eq!(e.allocation_mode, Some(DeviceAllocationMode::ExactCount));
    assert_eq!(e.count, Some(10));
}

#[test]
fn dra_defaults_allocation_mode_all_keeps_count() {
    // count is only defaulted for ExactCount.
    let mut s = spec(vec![DeviceRequest {
        name: String::new(),
        exactly: Some(exactly(Some(DeviceAllocationMode::All), None)),
        first_available: vec![],
    }]);
    default_resource_claim_spec(&mut s);
    let e = s.devices.requests[0].exactly.as_ref().unwrap();
    assert_eq!(e.allocation_mode, Some(DeviceAllocationMode::All));
    assert_eq!(e.count, None);
}

#[test]
fn dra_defaults_allocation_mode_with_sub_requests() {
    let mut s = spec(vec![DeviceRequest {
        name: "req-1".into(),
        exactly: None,
        first_available: vec![sub("subReq-1", None, None), sub("subReq-2", None, Some(0))],
    }]);
    default_resource_claim_spec(&mut s);
    assert!(s.devices.requests[0].exactly.is_none());
    for r in &s.devices.requests[0].first_available {
        assert_eq!(r.allocation_mode, Some(DeviceAllocationMode::ExactCount));
        assert_eq!(r.count, Some(1));
    }

    let mut s = spec(vec![DeviceRequest {
        name: "req-1".into(),
        exactly: None,
        first_available: vec![
            sub("subReq-1", Some(DeviceAllocationMode::ExactCount), Some(10)),
            sub("subReq-2", Some(DeviceAllocationMode::ExactCount), Some(10)),
        ],
    }]);
    default_resource_claim_spec(&mut s);
    for r in &s.devices.requests[0].first_available {
        assert_eq!(r.count, Some(10));
    }
}

#[test]
fn dra_defaults_toleration_operator_and_device_taint_time_added() {
    use kubernetes_rs_common::defaults::{
        default_device_taint, default_resource_claim_spec, default_resource_slice,
    };
    // zz_generated.defaults.go:46-77: an empty operator is Equal.
    let mut e = exactly(None, None);
    e.tolerations = vec![serde_json::from_value(serde_json::json!({"key": "k"})).unwrap()];
    let mut s = spec(vec![DeviceRequest {
        name: "r".into(),
        exactly: Some(e),
        first_available: vec![],
    }]);
    default_resource_claim_spec(&mut s);
    let t = &s.devices.requests[0].exactly.as_ref().unwrap().tolerations[0];
    assert_eq!(t.operator, Some(TolerationOperator::Equal));

    // defaults.go:51-56: unset timeAdded -> now truncated to the second;
    // a set one is kept.
    let mut taint: DeviceTaint = serde_json::from_value(serde_json::json!({"key": "k"})).unwrap();
    default_device_taint(&mut taint);
    let t = taint.time_added.expect("defaulted");
    assert_eq!(t.timestamp_subsec_nanos(), 0);
    let kept = taint.time_added;
    default_device_taint(&mut taint);
    assert_eq!(taint.time_added, kept);

    let mut slice: kubernetes_rs_common::resources::ResourceSlice =
        serde_json::from_value(serde_json::json!({
            "metadata": {"name": "s"},
            "spec": {"devices": [{"name": "d", "taints": [{"key": "k", "effect": "None"}]}]}
        }))
        .unwrap();
    default_resource_slice(&mut slice);
    assert!(slice.spec.devices[0].taints[0].time_added.is_some());
}
