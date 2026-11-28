//! EndpointSlice validation — port of upstream Kubernetes
//! `pkg/apis/discovery/validation/validation.go::ValidateEndpointSlice`
//! (release-1.35).
//!
//! Scope: `addressType`, each endpoint's addresses (≥1, ≤100, valid for the
//! address type), each port (protocol/number/name), and the slice-level size
//! caps (≤1000 endpoints, ≤20000 ports), and each endpoint's nodeName,
//! deprecatedTopology, hostname and hints (`validateEndpoints` :94-176,
//! `validateHints` :219-265).

use std::net::IpAddr;
use std::str::FromStr;

use crate::resources::endpointslice::{
    EndpointHints, EndpointPort, EndpointSlice, ForNode, ForZone,
};
use crate::validation::field::{Error, ErrorList, Path};
use crate::validation::metav1::{
    is_dns1123_label, is_dns1123_subdomain, is_valid_label_value, validate_labels,
};
use crate::validation::pod_spec_extra::validate_node_name;

// Upstream `pkg/apis/discovery/validation` size limits.
pub const MAX_ENDPOINTS: usize = 1000;
pub const MAX_ADDRESSES: usize = 100;
pub const MAX_PORTS: usize = 20000;
pub const MAX_TOPOLOGY_LABELS: usize = 16;
pub const MAX_ZONE_HINTS: usize = 8;
pub const MAX_NODE_HINTS: usize = 8;
/// `corev1.LabelTopologyZone`.
const LABEL_TOPOLOGY_ZONE: &str = "topology.kubernetes.io/zone";

/// `validateHints` (validation.go:219-265): forZones then forNodes, each capped
/// (a cap violation returns immediately), names unique and valid.
fn validate_hints(hints: &EndpointHints, fld_path: &Path) -> ErrorList {
    let mut errs: ErrorList = Vec::new();
    let zones: &[ForZone] = hints.for_zones.as_deref().unwrap_or(&[]);
    let fz_path = fld_path.child("forZones");
    if zones.len() > MAX_ZONE_HINTS {
        errs.push(Error::too_many(&fz_path, zones.len(), MAX_ZONE_HINTS));
        return errs;
    }
    let mut seen: Vec<&str> = Vec::with_capacity(zones.len());
    for (i, z) in zones.iter().enumerate() {
        let p = fz_path.index(i).child("name");
        if seen.contains(&z.name.as_str()) {
            errs.push(Error::duplicate(&p, z.name.clone()));
        } else {
            seen.push(&z.name);
        }
        for msg in is_valid_label_value(&z.name) {
            errs.push(Error::invalid(&p, z.name.clone(), msg));
        }
    }
    let nodes: &[ForNode] = hints.for_nodes.as_deref().unwrap_or(&[]);
    let fn_path = fld_path.child("forNodes");
    if nodes.len() > MAX_NODE_HINTS {
        errs.push(Error::too_many(&fn_path, nodes.len(), MAX_NODE_HINTS));
        return errs;
    }
    let mut seen: Vec<&str> = Vec::with_capacity(nodes.len());
    for (i, n) in nodes.iter().enumerate() {
        let p = fn_path.index(i).child("name");
        if seen.contains(&n.name.as_str()) {
            errs.push(Error::duplicate(&p, n.name.clone()));
        } else {
            seen.push(&n.name);
        }
        errs.extend(validate_node_name(&n.name, &p));
    }
    errs
}

fn validate_port(port: &EndpointPort, fld_path: &Path) -> ErrorList {
    let mut errs: ErrorList = Vec::new();
    // name: when present it must be a DNS-1123 label. Upstream
    // `validateEndpointSlicePorts` (discovery validation.go:183-185) validates
    // the port name with `ValidateDNS1123Label` — NOT the 15-char
    // IANA_SVC_NAME `IsValidPortName` rule. (Duplicate-name detection is done
    // in the caller, where the port index is available — see line 187-191.)
    if let Some(name) = &port.name {
        if !name.is_empty() {
            for msg in is_dns1123_label(name) {
                errs.push(Error::invalid(&fld_path.child("name"), name.clone(), msg));
            }
        }
    }
    // protocol: required, then must be TCP/UDP/SCTP. Upstream
    // `validateEndpointSlicePorts` (discovery validation.go:193-197) emits
    // Required when protocol is nil, NotSupported otherwise.
    match port.protocol.as_str() {
        "" => {
            errs.push(Error::required(&fld_path.child("protocol"), ""));
        }
        "TCP" | "UDP" | "SCTP" => {}
        other => {
            errs.push(Error::not_supported(
                &fld_path.child("protocol"),
                other.to_string(),
                &["TCP", "UDP", "SCTP"],
            ));
        }
    }
    if let Some(p) = port.port {
        if !(1..=65535).contains(&p) {
            errs.push(Error::invalid(
                &fld_path.child("port"),
                p,
                "must be between 1 and 65535, inclusive",
            ));
        }
    }
    errs
}

/// Validate an `EndpointSlice`. Mirrors the core of upstream `ValidateEndpointSlice`.
pub fn validate_endpoint_slice(slice: &EndpointSlice) -> ErrorList {
    let mut errs: ErrorList = Vec::new();

    // addressType must be one of the supported values.
    if !matches!(slice.address_type.as_str(), "IPv4" | "IPv6" | "FQDN") {
        errs.push(Error::not_supported(
            &Path::new("addressType"),
            slice.address_type.clone(),
            &["IPv4", "IPv6", "FQDN"],
        ));
    }

    let eps_path = Path::new("endpoints");
    // Upstream caps the number of endpoints per slice (maxEndpoints).
    if slice.endpoints.len() > MAX_ENDPOINTS {
        errs.push(Error::too_many(
            &eps_path,
            slice.endpoints.len(),
            MAX_ENDPOINTS,
        ));
    }
    for (i, ep) in slice.endpoints.iter().enumerate() {
        let addr_path = eps_path.index(i).child("addresses");
        if ep.addresses.is_empty() {
            errs.push(Error::required(
                &addr_path,
                "must contain at least 1 address",
            ));
        } else if ep.addresses.len() > MAX_ADDRESSES {
            errs.push(Error::too_many(
                &addr_path,
                ep.addresses.len(),
                MAX_ADDRESSES,
            ));
        }
        for (j, addr) in ep.addresses.iter().enumerate() {
            let p = addr_path.index(j);
            match slice.address_type.as_str() {
                "IPv4" => match IpAddr::from_str(addr) {
                    Ok(IpAddr::V4(_)) => {}
                    _ => errs.push(Error::invalid(&p, addr.clone(), "must be an IPv4 address")),
                },
                "IPv6" => match IpAddr::from_str(addr) {
                    Ok(IpAddr::V6(_)) => {}
                    _ => errs.push(Error::invalid(&p, addr.clone(), "must be an IPv6 address")),
                },
                "FQDN" => {
                    for msg in is_dns1123_subdomain(addr) {
                        errs.push(Error::invalid(&p, addr.clone(), msg));
                    }
                }
                _ => {} // unknown type: addresses not validated (matches upstream)
            }
        }

        // nodeName (validation.go:139-145).
        if let Some(nn) = &ep.node_name {
            errs.extend(validate_node_name(nn, &eps_path.index(i).child("nodeName")));
        }

        // deprecatedTopology (validation.go:147-155).
        let topology_path = eps_path.index(i).child("deprecatedTopology");
        if let Some(topology) = &ep.deprecated_topology {
            if topology.len() > MAX_TOPOLOGY_LABELS {
                errs.push(Error::too_many(
                    &topology_path,
                    topology.len(),
                    MAX_TOPOLOGY_LABELS,
                ));
            }
            errs.extend(validate_labels(topology, &topology_path));
            if topology.contains_key(LABEL_TOPOLOGY_ZONE) {
                errs.push(Error::internal(
                    &topology_path.key(LABEL_TOPOLOGY_ZONE),
                    "reserved key was not removed in conversion",
                ));
            }
        }

        // hostname (validation.go:157-159): ValidateDNS1123Label.
        if let Some(h) = &ep.hostname {
            let hp = eps_path.index(i).child("hostname");
            for msg in is_dns1123_label(h) {
                errs.push(Error::invalid(&hp, h.clone(), msg));
            }
        }

        // hints (validation.go:161-163).
        if let Some(hints) = &ep.hints {
            errs.extend(validate_hints(hints, &eps_path.index(i).child("hints")));
        }
    }

    let ports_path = Path::new("ports");
    // Upstream caps the number of ports per slice (maxPorts).
    if slice.ports.len() > MAX_PORTS {
        errs.push(Error::too_many(&ports_path, slice.ports.len(), MAX_PORTS));
    }
    // Track port names for duplicate detection. Upstream
    // `validateEndpointSlicePorts` (discovery validation.go:187-191) dereferences
    // the (defaulted-to-empty) port name unconditionally, so two ports that both
    // omit a name — or share one — collide on the second occurrence.
    let mut seen_names: Vec<&str> = Vec::with_capacity(slice.ports.len());
    for (i, port) in slice.ports.iter().enumerate() {
        let idx = ports_path.index(i);
        errs.extend(validate_port(port, &idx));

        let name = port.name.as_deref().unwrap_or("");
        if seen_names.contains(&name) {
            errs.push(Error::duplicate(&idx.child("name"), name.to_string()));
        } else {
            seen_names.push(name);
        }
    }

    errs
}

/// Validate an `EndpointSlice` update — upstream `ValidateEndpointSliceUpdate`
/// (pkg/apis/discovery/validation): full field validation of the new slice,
/// plus `addressType` is immutable.
pub fn validate_endpoint_slice_update(
    new_slice: &EndpointSlice,
    old_slice: &EndpointSlice,
) -> ErrorList {
    let mut errs = validate_endpoint_slice(new_slice);
    // `ValidateEndpointSlice` ignores the endpoint errors of an update that
    // left `endpoints` unchanged: older versions considered that data valid
    // (validation.go:66-76).
    if new_slice.endpoints == old_slice.endpoints {
        errs.retain(|e| !e.field.starts_with("endpoints"));
    }
    if new_slice.address_type != old_slice.address_type {
        errs.push(Error::invalid(
            &Path::new("addressType"),
            new_slice.address_type.clone(),
            "field is immutable",
        ));
    }
    errs
}
