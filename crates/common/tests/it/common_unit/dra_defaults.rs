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
