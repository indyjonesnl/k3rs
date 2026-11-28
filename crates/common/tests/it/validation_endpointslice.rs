//! Tests for EndpointSlice field validation.
//!
//! Mirrors the core of upstream `ValidateEndpointSlice`
//! (`pkg/apis/discovery/validation/validation.go`, release-1.35).

use kubernetes_rs_common::resources::endpointslice::EndpointSlice;
use kubernetes_rs_common::validation::endpointslice::validate_endpoint_slice;
use kubernetes_rs_common::validation::field::{Error, ErrorType};
use serde_json::json;

fn es(v: serde_json::Value) -> EndpointSlice {
    let mut obj = json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {"name": "es", "namespace": "default"}
    });
    for (k, val) in v.as_object().unwrap() {
        obj[k] = val.clone();
    }
    serde_json::from_value(obj).unwrap()
}

fn has(errs: &[Error], field: &str, ty: ErrorType) -> bool {
    errs.iter().any(|e| e.field == field && e.error_type == ty)
}

#[test]
fn valid_ipv4_slice_passes() {
    let errs = validate_endpoint_slice(&es(json!({
        "addressType": "IPv4",
        "endpoints": [{"addresses": ["10.0.0.1"]}],
        "ports": [{"name": "http", "port": 80, "protocol": "TCP"}]
    })));
    assert!(errs.is_empty(), "unexpected errors: {errs:?}");
}

#[test]
fn unknown_address_type_rejected() {
    let errs = validate_endpoint_slice(&es(json!({
        "addressType": "Bogus",
        "endpoints": [],
        "ports": []
    })));
    assert!(
        has(&errs, "addressType", ErrorType::NotSupported),
        "got: {errs:?}"
    );
}

#[test]
fn empty_addresses_required() {
    let errs = validate_endpoint_slice(&es(json!({
        "addressType": "IPv4",
        "endpoints": [{"addresses": []}],
        "ports": []
    })));
    assert!(
        has(&errs, "endpoints[0].addresses", ErrorType::Required),
        "got: {errs:?}"
    );
}

#[test]
fn ipv6_address_in_ipv4_slice_rejected() {
    let errs = validate_endpoint_slice(&es(json!({
        "addressType": "IPv4",
        "endpoints": [{"addresses": ["2001:db8::1"]}],
        "ports": []
    })));
    assert!(
        has(&errs, "endpoints[0].addresses[0]", ErrorType::Invalid),
        "got: {errs:?}"
    );
}

#[test]
fn non_ip_in_ipv4_slice_rejected() {
    let errs = validate_endpoint_slice(&es(json!({
        "addressType": "IPv4",
        "endpoints": [{"addresses": ["not-an-ip"]}],
        "ports": []
    })));
    assert!(
        has(&errs, "endpoints[0].addresses[0]", ErrorType::Invalid),
        "got: {errs:?}"
    );
}

#[test]
fn valid_ipv6_slice_passes() {
    let errs = validate_endpoint_slice(&es(json!({
        "addressType": "IPv6",
        "endpoints": [{"addresses": ["2001:db8::1"]}],
        "ports": []
    })));
    assert!(errs.is_empty(), "unexpected errors: {errs:?}");
}

#[test]
fn bad_port_protocol_rejected() {
    let errs = validate_endpoint_slice(&es(json!({
        "addressType": "IPv4",
        "endpoints": [{"addresses": ["10.0.0.1"]}],
        "ports": [{"port": 80, "protocol": "ICMP"}]
    })));
    assert!(
        has(&errs, "ports[0].protocol", ErrorType::NotSupported),
        "got: {errs:?}"
    );
}

#[test]
fn out_of_range_port_rejected() {
    let errs = validate_endpoint_slice(&es(json!({
        "addressType": "IPv4",
        "endpoints": [{"addresses": ["10.0.0.1"]}],
        "ports": [{"port": 99999}]
    })));
    assert!(
        has(&errs, "ports[0].port", ErrorType::Invalid),
        "got: {errs:?}"
    );
}

// TestValidateEndpointSlice (discovery/validation/validation_test.go:34-): nodeName,
// hostname, deprecatedTopology and hints.
fn ep(v: serde_json::Value) -> EndpointSlice {
    es(json!({"addressType": "IPv4", "endpoints": [v]}))
}

#[test]
fn endpointslice_endpoints_node_name_and_hostname() {
    let errs = validate_endpoint_slice(&ep(json!({
        "addresses": ["10.1.2.3"], "nodeName": "Bad_Node", "hostname": "bad.host"
    })));
    assert!(
        has(&errs, "endpoints[0].nodeName", ErrorType::Invalid),
        "{errs:?}"
    );
    assert!(
        has(&errs, "endpoints[0].hostname", ErrorType::Invalid),
        "{errs:?}"
    );
    let ok = validate_endpoint_slice(&ep(json!({
        "addresses": ["10.1.2.3"], "nodeName": "node-1.example", "hostname": "pod-1"
    })));
    assert!(ok.is_empty(), "{ok:?}");
}

#[test]
fn endpointslice_endpoints_deprecated_topology() {
    let errs = validate_endpoint_slice(&ep(json!({
        "addresses": ["10.1.2.3"],
        "deprecatedTopology": {"topology.kubernetes.io/zone": "a", "bad key!": "v"}
    })));
    assert!(
        has(
            &errs,
            "endpoints[0].deprecatedTopology[topology.kubernetes.io/zone]",
            ErrorType::Internal
        ),
        "{errs:?}"
    );
    assert!(
        errs.iter()
            .any(|e| e.field == "endpoints[0].deprecatedTopology"
                && e.error_type == ErrorType::Invalid),
        "{errs:?}"
    );
    let many: serde_json::Map<String, serde_json::Value> =
        (0..17).map(|i| (format!("k{i}"), json!("v"))).collect();
    let errs = validate_endpoint_slice(&ep(json!({
        "addresses": ["10.1.2.3"], "deprecatedTopology": many
    })));
    assert!(
        has(&errs, "endpoints[0].deprecatedTopology", ErrorType::TooMany),
        "{errs:?}"
    );
}

#[test]
fn endpointslice_endpoints_hints() {
    let ok = validate_endpoint_slice(&ep(json!({
        "addresses": ["10.1.2.3"],
        "hints": {"forZones": [{"name": "zone-a"}], "forNodes": [{"name": "node-1"}]}
    })));
    assert!(ok.is_empty(), "{ok:?}");
    let errs = validate_endpoint_slice(&ep(json!({
        "addresses": ["10.1.2.3"],
        "hints": {"forZones": [{"name": "a"}, {"name": "a"}, {"name": "bad zone"}],
                  "forNodes": [{"name": "n"}, {"name": "n"}, {"name": "Bad_Node"}]}
    })));
    assert!(
        has(
            &errs,
            "endpoints[0].hints.forZones[1].name",
            ErrorType::Duplicate
        ),
        "{errs:?}"
    );
    assert!(
        has(
            &errs,
            "endpoints[0].hints.forZones[2].name",
            ErrorType::Invalid
        ),
        "{errs:?}"
    );
    assert!(
        has(
            &errs,
            "endpoints[0].hints.forNodes[1].name",
            ErrorType::Duplicate
        ),
        "{errs:?}"
    );
    assert!(
        has(
            &errs,
            "endpoints[0].hints.forNodes[2].name",
            ErrorType::Invalid
        ),
        "{errs:?}"
    );
    // A cap violation returns before forNodes is looked at.
    let zones: Vec<_> = (0..9).map(|i| json!({"name": format!("z{i}")})).collect();
    let errs = validate_endpoint_slice(&ep(json!({
        "addresses": ["10.1.2.3"],
        "hints": {"forZones": zones, "forNodes": [{"name": "Bad_Node"}]}
    })));
    assert!(
        has(&errs, "endpoints[0].hints.forZones", ErrorType::TooMany),
        "{errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.field.contains("forNodes")),
        "{errs:?}"
    );
    let nodes: Vec<_> = (0..9).map(|i| json!({"name": format!("n{i}")})).collect();
    let errs = validate_endpoint_slice(&ep(json!({
        "addresses": ["10.1.2.3"], "hints": {"forNodes": nodes}
    })));
    assert!(
        has(&errs, "endpoints[0].hints.forNodes", ErrorType::TooMany),
        "{errs:?}"
    );
}
