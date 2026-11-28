//! `CategorizeEndpoints`: which endpoints a service may use on this node.
//!
//! Ported from `pkg/proxy/topology.go` (release-1.35): `CategorizeEndpoints`
//! (:48), `topologyModeFromHints` (:178), `availableForTopology` (:237),
//! `filterEndpoints` (:254). Ready endpoints are used; with none, the
//! serving+terminating endpoints are used instead (independently for Cluster
//! and Local traffic policy), as `ProxyTerminatingEndpoints` (GA) requires.
//!
//! `PreferSameTrafficDistribution` is GA and locked on in 1.35
//! (`kube_features.go`, `LockToDefault: true`); upstream reads it from
//! `DefaultFeatureGate`, here it is the `prefer_same_traffic_distribution`
//! parameter so the pure function stays free of global state (the upstream
//! test also runs it disabled, under emulation version 1.34).

use crate::endpointslice_cache::EndpointInfo;
use crate::service_map::BaseServicePortInfo;
use std::collections::BTreeMap;

/// `v1.LabelTopologyZone`.
pub const LABEL_TOPOLOGY_ZONE: &str = "topology.kubernetes.io/zone";
/// `v1.ServiceTrafficDistributionPreferSameZone` / `...PreferSameNode`.
pub const PREFER_SAME_ZONE: &str = "PreferSameZone";
pub const PREFER_SAME_NODE: &str = "PreferSameNode";

/// What `CategorizeEndpoints` returns.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CategorizedEndpoints {
    /// Usable Cluster-policy endpoints (empty if the service never uses Cluster policy).
    pub cluster: Vec<EndpointInfo>,
    /// Usable Local-policy endpoints (empty if the service never uses Local policy).
    pub local: Vec<EndpointInfo>,
    /// Every endpoint reachable from this node (the union of the two above).
    pub all_reachable: Vec<EndpointInfo>,
    /// Whether the service has any endpoint reachable from anywhere in the
    /// cluster (true even if `all_reachable` is empty).
    pub has_any_endpoints: bool,
}

/// `CategorizeEndpoints` (topology.go:48-165).
pub fn categorize_endpoints(
    endpoints: &[EndpointInfo],
    svc: &BaseServicePortInfo,
    node_name: &str,
    topology_labels: &BTreeMap<String, String>,
    prefer_same_traffic_distribution: bool,
) -> CategorizedEndpoints {
    let mut out = CategorizedEndpoints::default();
    if endpoints.is_empty() {
        // If there are no endpoints, we have nothing to categorize.
        return out;
    }

    let mut topology_mode = "";
    let mut use_serving_terminating_endpoints = false;

    if svc.uses_cluster_endpoints() {
        let zone = topology_labels
            .get(LABEL_TOPOLOGY_ZONE)
            .map(String::as_str)
            .unwrap_or("");
        topology_mode =
            topology_mode_from_hints(endpoints, node_name, zone, prefer_same_traffic_distribution);
        out.cluster = filter_endpoints(endpoints, |ep| {
            ep.ready && available_for_topology(ep, topology_mode, node_name, zone)
        });

        // If we didn't get any endpoints, try again using terminating endpoints.
        // (We would already have chosen to ignore topology if there were no ready
        // endpoints for the given topology, so the problem must be that there are
        // no ready endpoints anywhere.)
        if out.cluster.is_empty() {
            out.cluster = filter_endpoints(endpoints, |ep| ep.serving && ep.terminating);
        }

        // If there are any Ready endpoints anywhere in the cluster, we are
        // guaranteed to get one in `cluster`.
        if !out.cluster.is_empty() {
            out.has_any_endpoints = true;
        }
    }

    if !svc.uses_local_endpoints() {
        out.all_reachable = out.cluster.clone();
        return out;
    }

    // Pre-scan the endpoints, to figure out which type of endpoint Local traffic
    // policy will use, and whether there are usable endpoints anywhere.
    let (mut has_local_ready, mut has_local_serving_terminating) = (false, false);
    for ep in endpoints {
        if ep.ready {
            out.has_any_endpoints = true;
            if ep.is_local {
                has_local_ready = true;
            }
        } else if ep.serving && ep.terminating {
            out.has_any_endpoints = true;
            if ep.is_local {
                has_local_serving_terminating = true;
            }
        }
    }

    if has_local_ready {
        out.local = filter_endpoints(endpoints, |ep| ep.is_local && ep.ready);
    } else if has_local_serving_terminating {
        use_serving_terminating_endpoints = true;
        out.local = filter_endpoints(endpoints, |ep| ep.is_local && ep.serving && ep.terminating);
    }

    if !svc.uses_cluster_endpoints() {
        out.all_reachable = out.local.clone();
        return out;
    }

    if topology_mode.is_empty() && !use_serving_terminating_endpoints {
        // `local` holds only Ready endpoints and `cluster` holds every Ready
        // endpoint, so `cluster` is a superset of `local`.
        out.all_reachable = out.cluster.clone();
        return out;
    }

    // `cluster` may contain remote endpoints that aren't in `local`, while `local`
    // may contain terminating or topologically-unavailable local endpoints that
    // aren't in `cluster`: merge the two lists (keyed by `String()`).
    let mut merged: BTreeMap<String, EndpointInfo> = BTreeMap::new();
    for ep in out.cluster.iter().chain(out.local.iter()) {
        merged.insert(ep.endpoint(), ep.clone());
    }
    out.all_reachable = merged.into_values().collect();
    out
}

/// `topologyModeFromHints` (topology.go:178-233): `""`, `PreferSameZone` or
/// `PreferSameNode`.
fn topology_mode_from_hints(
    endpoints: &[EndpointInfo],
    node_name: &str,
    zone: &str,
    prefer_same_traffic_distribution: bool,
) -> &'static str {
    if endpoints.is_empty() {
        // The logic below assumes at least 1 endpoint; with none there are no hints.
        return "";
    }
    let (mut has_endpoint_for_node, mut all_have_node_hints) = (false, true);
    let (mut has_endpoint_for_zone, mut all_have_zone_hints) = (false, true);
    for ep in endpoints {
        if !ep.ready {
            continue;
        }
        if ep.node_hints.is_empty() {
            all_have_node_hints = false;
        } else if ep.node_hints.contains(node_name) {
            has_endpoint_for_node = true;
        }
        if ep.zone_hints.is_empty() {
            all_have_zone_hints = false;
        } else if ep.zone_hints.contains(zone) {
            has_endpoint_for_zone = true;
        }
    }
    if prefer_same_traffic_distribution && all_have_node_hints && has_endpoint_for_node {
        return PREFER_SAME_NODE;
    }
    if all_have_zone_hints && has_endpoint_for_zone {
        return PREFER_SAME_ZONE;
    }
    ""
}

/// `availableForTopology` (topology.go:237-250). There is no fallback here: it
/// happens when deciding which mode to use, not when applying that decision.
fn available_for_topology(
    ep: &EndpointInfo,
    topology_mode: &str,
    node_name: &str,
    zone: &str,
) -> bool {
    match topology_mode {
        "" => true,
        PREFER_SAME_NODE => ep.node_hints.contains(node_name),
        PREFER_SAME_ZONE => ep.zone_hints.contains(zone),
        _ => false,
    }
}

/// `filterEndpoints` (topology.go:254-264).
fn filter_endpoints(
    endpoints: &[EndpointInfo],
    predicate: impl Fn(&EndpointInfo) -> bool,
) -> Vec<EndpointInfo> {
    endpoints
        .iter()
        .filter(|ep| predicate(ep))
        .cloned()
        .collect()
}
