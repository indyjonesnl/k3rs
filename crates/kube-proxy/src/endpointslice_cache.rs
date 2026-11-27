//! Port of `pkg/proxy/endpointslicecache.go` (`EndpointSliceCache`,
//! `updatePending`, `checkoutChanges`, `endpointInfoByServicePort`,
//! `addEndpoints`, `esDataChanged`, `endpointSliceCacheKeys`) and of
//! `pkg/proxy/endpoint.go` `BaseEndpointInfo` (ip/port, isLocal, ready,
//! serving, terminating, zone and node hints).
//!
//! Upstream locks the cache; here every mutation takes `&mut self`, so the
//! owner serialises access. `PreferSameTrafficDistribution` (node hints) is a
//! constructor flag, default on as in 1.35.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use kubernetes_rs_common::resources::{Endpoint, EndpointSlice};

/// `discovery.LabelServiceName`.
pub const LABEL_SERVICE_NAME: &str = "kubernetes.io/service-name";

/// `types.NamespacedName`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NamespacedName {
    pub namespace: String,
    pub name: String,
}

/// `proxy.ServicePortName` (types.go:44); `Display` is `ns/name[:port]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServicePortName {
    pub namespaced_name: NamespacedName,
    pub port: String,
    pub protocol: String,
}

impl std::fmt::Display for ServicePortName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}",
            self.namespaced_name.namespace, self.namespaced_name.name
        )?;
        if !self.port.is_empty() {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

/// `BaseEndpointInfo` (endpoint.go).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointInfo {
    pub ip: String,
    pub port: u16,
    pub is_local: bool,
    /// Ready and not terminating (`IsReady`).
    pub ready: bool,
    /// Ready regardless of terminating (`IsServing`).
    pub serving: bool,
    pub terminating: bool,
    pub zone_hints: BTreeSet<String>,
    pub node_hints: BTreeSet<String>,
}

impl EndpointInfo {
    /// `String()`: `net.JoinHostPort(ip, port)`.
    pub fn endpoint(&self) -> String {
        if self.ip.contains(':') {
            format!("[{}]:{}", self.ip, self.port)
        } else {
            format!("{}:{}", self.ip, self.port)
        }
    }
}

/// `EndpointsMap`.
pub type EndpointsMap = BTreeMap<ServicePortName, Vec<EndpointInfo>>;

/// `endpointsChange` (endpointschangetracker.go:168).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EndpointsChange {
    pub previous: EndpointsMap,
    pub current: EndpointsMap,
}

#[derive(Clone)]
struct SliceData {
    slice: EndpointSlice,
    remove: bool,
}

impl SliceData {
    /// `reflect.DeepEqual` of two `endpointSliceData`.
    fn same(&self, other: &SliceData) -> bool {
        self.remove == other.remove
            && serde_json::to_value(&self.slice).ok() == serde_json::to_value(&other.slice).ok()
    }
}

#[derive(Default)]
struct Tracker {
    applied: HashMap<String, SliceData>,
    pending: HashMap<String, SliceData>,
}

/// `EndpointSliceCache`.
pub struct EndpointSliceCache {
    tracker_by_service: HashMap<NamespacedName, Tracker>,
    node_name: String,
    prefer_same_traffic_distribution: bool,
}

/// `endpointSliceCacheKeys`: the service and slice name, or upstream's error.
fn cache_keys(es: &EndpointSlice) -> Result<(NamespacedName, String), String> {
    let service = es
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(LABEL_SERVICE_NAME))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            format!(
                "no {LABEL_SERVICE_NAME} label set on endpoint slice: {}",
                es.metadata.name
            )
        })?;
    let ns = es.metadata.namespace.clone().unwrap_or_default();
    if ns.is_empty() || es.metadata.name.is_empty() {
        return Err("expected EndpointSlice name and namespace to be set".to_string());
    }
    Ok((
        NamespacedName {
            namespace: ns,
            name: service.clone(),
        },
        es.metadata.name.clone(),
    ))
}

impl EndpointSliceCache {
    /// `NewEndpointSliceCache`.
    pub fn new(node_name: &str) -> Self {
        Self {
            tracker_by_service: HashMap::new(),
            node_name: node_name.to_string(),
            prefer_same_traffic_distribution: true,
        }
    }

    /// Toggle the `PreferSameTrafficDistribution` gate (node hints).
    pub fn with_prefer_same_traffic_distribution(mut self, on: bool) -> Self {
        self.prefer_same_traffic_distribution = on;
        self
    }

    /// `updatePending`: record a slice update or removal; true when it
    /// changes what is pending or applied.
    pub fn update_pending(&mut self, slice: &EndpointSlice, remove: bool) -> Result<bool, String> {
        let (service_key, slice_key) = cache_keys(slice)?;
        let data = SliceData {
            slice: slice.clone(),
            remove,
        };
        let tracker = self.tracker_by_service.entry(service_key).or_default();
        let changed = es_data_changed(tracker, &slice_key, &data);
        if changed {
            tracker.pending.insert(slice_key, data);
        }
        Ok(changed)
    }

    /// `checkoutChanges`: the endpoints change of every service with pending
    /// slices; the pending data becomes applied.
    pub fn checkout_changes(&mut self) -> BTreeMap<NamespacedName, EndpointsChange> {
        let mut changes = BTreeMap::new();
        let keys: Vec<NamespacedName> = self.tracker_by_service.keys().cloned().collect();
        for key in keys {
            let Some(tracker) = self.tracker_by_service.get_mut(&key) else {
                continue;
            };
            if tracker.pending.is_empty() {
                continue;
            }
            let previous = endpoints_map(
                &self.node_name,
                self.prefer_same_traffic_distribution,
                &key,
                &tracker.applied,
            );
            let pending: Vec<(String, SliceData)> = tracker.pending.drain().collect();
            for (name, data) in pending {
                if data.remove {
                    tracker.applied.remove(&name);
                } else {
                    tracker.applied.insert(name, data);
                }
            }
            let current = endpoints_map(
                &self.node_name,
                self.prefer_same_traffic_distribution,
                &key,
                &tracker.applied,
            );
            if tracker.applied.is_empty() {
                self.tracker_by_service.remove(&key);
            }
            changes.insert(key, EndpointsChange { previous, current });
        }
        changes
    }
}

/// `esDataChanged`.
fn es_data_changed(tracker: &Tracker, slice_key: &str, data: &SliceData) -> bool {
    if let Some(pending) = tracker.pending.get(slice_key) {
        return !data.same(pending);
    }
    if let Some(applied) = tracker.applied.get(slice_key) {
        return !data.same(applied);
    }
    // A removal of an unknown slice changes nothing; anything else is new.
    !data.remove
}

/// `getEndpointsMap` = `endpointsMapFromEndpointInfo(endpointInfoByServicePort)`.
fn endpoints_map(
    node_name: &str,
    prefer_same: bool,
    service: &NamespacedName,
    slices: &HashMap<String, SliceData>,
) -> EndpointsMap {
    let mut by_sp: BTreeMap<ServicePortName, BTreeMap<String, EndpointInfo>> = BTreeMap::new();
    // Deterministic slice order (Go ranges a map; the result is deduplicated
    // by endpoint string, with isLocal preferred, so order is immaterial).
    let mut names: Vec<&String> = slices.keys().collect();
    names.sort();
    for name in names {
        let data = &slices[name];
        for port in &data.slice.ports {
            let Some(port_name) = &port.name else {
                tracing::error!("Ignoring port with nil name");
                continue;
            };
            let Some(port_num) = port.port.filter(|p| *p != 0) else {
                tracing::error!("Ignoring invalid endpoint port {port_name}");
                continue;
            };
            let spn = ServicePortName {
                namespaced_name: service.clone(),
                port: port_name.clone(),
                protocol: port.protocol.clone(),
            };
            let set = by_sp.entry(spn).or_default();
            add_endpoints(
                node_name,
                prefer_same,
                port_num as u16,
                set,
                &data.slice.endpoints,
            );
        }
    }
    // endpointsMapFromEndpointInfo: non-empty sets only, sorted by String().
    by_sp
        .into_iter()
        .filter(|(_, set)| !set.is_empty())
        .map(|(spn, set)| (spn, set.into_values().collect()))
        .collect()
}

/// `addEndpoints`.
fn add_endpoints(
    node_name: &str,
    prefer_same: bool,
    port: u16,
    set: &mut BTreeMap<String, EndpointInfo>,
    endpoints: &[Endpoint],
) {
    for ep in endpoints {
        let Some(addr) = ep.addresses.first() else {
            tracing::error!("Ignoring invalid endpoint port with empty address");
            continue;
        };
        let is_local = ep
            .node_name
            .as_deref()
            .is_some_and(|n| !node_name.is_empty() && n == node_name);
        let cond = ep.conditions.as_ref();
        let ready = cond.and_then(|c| c.ready).unwrap_or(true);
        let serving = cond.and_then(|c| c.serving).unwrap_or(true);
        let terminating = cond.and_then(|c| c.terminating).unwrap_or(false);
        let mut zone_hints = BTreeSet::new();
        let mut node_hints = BTreeSet::new();
        if let Some(h) = &ep.hints {
            if let Some(z) = h.for_zones.as_ref().filter(|z| !z.is_empty()) {
                zone_hints = z.iter().map(|z| z.name.clone()).collect();
            }
            if prefer_same {
                if let Some(n) = h.for_nodes.as_ref().filter(|n| !n.is_empty()) {
                    node_hints = n.iter().map(|n| n.name.clone()).collect();
                }
            }
        }
        // utilnet.ParseIPSloppy(..).String(): "<nil>" for an unparseable address.
        let ip = addr
            .parse::<std::net::IpAddr>()
            .map(|i| i.to_string())
            .unwrap_or_else(|_| "<nil>".to_string());
        let info = EndpointInfo {
            ip,
            port,
            is_local,
            ready,
            serving,
            terminating,
            zone_hints,
            node_hints,
        };
        // Deduplicate overlapping endpoints; favour a local one.
        let key = info.endpoint();
        if !set.contains_key(&key) || is_local {
            set.insert(key, info);
        }
    }
}
