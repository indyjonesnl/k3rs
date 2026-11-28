//! Port of `pkg/proxy/endpointschangetracker.go` (release-1.35):
//! `EndpointsChangeTracker` (`NewEndpointsChangeTracker`, `EndpointSliceUpdate`
//! :81, `checkoutChanges`, `checkoutTriggerTimes`, `getLastChangeTriggerTime`),
//! `UpdateEndpointsMapResult`, `EndpointsMap.Update` :193, `merge`, `unmerge`,
//! `getLocalReadyEndpointIPs` and `LocalReadyEndpoints`.
//!
//! The [`EndpointsMap`] type and the slice cache are in
//! [`crate::endpointslice_cache`]. Upstream locks the tracker; here every
//! mutation takes `&mut self`, so the owner serialises access. Not ported:
//! the `EndpointChangesTotal` / `EndpointChangesPending` metrics, and the
//! `makeEndpointInfo` hook (proxier specific wrappers; callers read
//! [`EndpointInfo`] directly).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use kubernetes_rs_common::resources::EndpointSlice;

use crate::endpointslice_cache::{
    cache_keys, EndpointSliceCache, EndpointsChange, EndpointsMap, NamespacedName, ServicePortName,
};

/// `v1.EndpointsLastChangeTriggerTime`.
pub const ENDPOINTS_LAST_CHANGE_TRIGGER_TIME: &str =
    "endpoints.kubernetes.io/last-change-trigger-time";

/// `v1.IPFamily`: which `EndpointSlice` address type is tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    IPv4,
    IPv6,
}

/// `processEndpointsMapChangeFunc`: invoked on every change with the previous
/// and current map of the changed service; it must not modify the maps.
pub type ProcessEndpointsMapChange = Box<dyn FnMut(&EndpointsMap, &EndpointsMap) + Send>;

/// `EndpointsChangeTracker`: uncommitted changes to the `EndpointSlice`s of any
/// number of services.
pub struct EndpointsChangeTracker {
    process_endpoints_map_change: Option<ProcessEndpointsMapChange>,
    /// `discovery.AddressType` this proxy tracks.
    address_type: &'static str,
    endpoint_slice_cache: EndpointSliceCache,
    /// The times of the triggers that caused a service's slices to change
    /// (network-programming-latency).
    last_change_trigger_times: BTreeMap<NamespacedName, Vec<DateTime<Utc>>>,
    /// When the tracker was created: changes triggered before it are not
    /// measured.
    pub tracker_start_time: DateTime<Utc>,
}

/// `UpdateEndpointsMapResult`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UpdateEndpointsMapResult {
    /// Services with added/updated/deleted endpoints since the last update.
    pub updated_services: BTreeSet<NamespacedName>,
    /// True if any UDP service port changed endpoints (minimises conntrack
    /// cleanup calls).
    pub conntrack_cleanup_required: bool,
    /// Trigger times of every changed endpoints object.
    pub last_change_trigger_times: BTreeMap<NamespacedName, Vec<DateTime<Utc>>>,
}

impl EndpointsChangeTracker {
    /// `NewEndpointsChangeTracker`.
    pub fn new(
        ip_family: IpFamily,
        node_name: &str,
        process_endpoints_map_change: Option<ProcessEndpointsMapChange>,
    ) -> Self {
        Self {
            address_type: match ip_family {
                IpFamily::IPv4 => "IPv4",
                IpFamily::IPv6 => "IPv6",
            },
            last_change_trigger_times: BTreeMap::new(),
            tracker_start_time: Utc::now(),
            process_endpoints_map_change,
            endpoint_slice_cache: EndpointSliceCache::new(node_name),
        }
    }

    /// `EndpointSliceUpdate`: add/update or remove `slice`. True when the
    /// update contained a change that needs to be synced (not the same as
    /// `ServiceChangeTracker.Update`).
    pub fn endpoint_slice_update(&mut self, slice: &EndpointSlice, remove_slice: bool) -> bool {
        // "Ignoring unsupported EndpointSlice"
        if slice.address_type != self.address_type {
            return false;
        }
        let Ok((namespaced_name, _)) = cache_keys(slice) else {
            return false;
        };
        let change_needed = self
            .endpoint_slice_cache
            .update_pending(slice, remove_slice)
            .unwrap_or(false);
        if change_needed {
            // On deletion the annotation is the time of the last update, which
            // is not what is measured, so it is ignored.
            if remove_slice {
                self.last_change_trigger_times.remove(&namespaced_name);
            } else if let Some(t) =
                get_last_change_trigger_time(slice).filter(|t| *t > self.tracker_start_time)
            {
                self.last_change_trigger_times
                    .entry(namespaced_name)
                    .or_default()
                    .push(t);
            }
        }
        change_needed
    }

    /// `checkoutChanges`: apply and return the pending changes per service.
    pub fn checkout_changes(&mut self) -> BTreeMap<NamespacedName, EndpointsChange> {
        self.endpoint_slice_cache.checkout_changes()
    }

    /// `checkoutTriggerTimes`: move the cached trigger times into `out`.
    fn checkout_trigger_times(&mut self, out: &mut BTreeMap<NamespacedName, Vec<DateTime<Utc>>>) {
        for (k, v) in std::mem::take(&mut self.last_change_trigger_times) {
            out.entry(k).or_default().extend(v);
        }
    }
}

/// `getLastChangeTriggerTime`: the annotation as a time, `None` when absent or
/// not RFC 3339 (upstream's "zero" time, ignored by the caller).
fn get_last_change_trigger_time(slice: &EndpointSlice) -> Option<DateTime<Utc>> {
    let v = slice
        .metadata
        .annotations
        .as_ref()?
        .get(ENDPOINTS_LAST_CHANGE_TRIGGER_TIME)?;
    DateTime::parse_from_rfc3339(v)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// `EndpointsMap.Update`: apply the tracker's changes to `em`, report the diff
/// since the last update, call `processEndpointsMapChange` on every change and
/// clear the changes. A missing tracker is an empty result.
pub fn update_endpoints_map(
    em: &mut EndpointsMap,
    ect: Option<&mut EndpointsChangeTracker>,
) -> UpdateEndpointsMapResult {
    let mut result = UpdateEndpointsMapResult::default();
    let Some(ect) = ect else {
        return result;
    };
    let changes = ect.endpoint_slice_cache.checkout_changes();
    for (nn, change) in changes {
        if let Some(f) = ect.process_endpoints_map_change.as_mut() {
            f(&change.previous, &change.current);
        }
        result.updated_services.insert(nn.clone());

        unmerge(em, &change.previous);
        merge(em, &change.current);

        // Once any UDP service port of a changed service is seen, the value
        // stays true.
        if result.conntrack_cleanup_required {
            continue;
        }
        let has_udp = |m: &EndpointsMap| {
            m.keys()
                .any(|p| p.namespaced_name == nn && p.protocol == "UDP")
        };
        if has_udp(&change.previous) || has_udp(&change.current) {
            result.conntrack_cleanup_required = true;
        }
    }
    ect.checkout_trigger_times(&mut result.last_change_trigger_times);
    result
}

/// `EndpointsMap.merge`: `em` gains every `<service port, endpoints>` of `other`.
pub fn merge(em: &mut EndpointsMap, other: &EndpointsMap) {
    for (k, v) in other {
        em.insert(k.clone(), v.clone());
    }
}

/// `EndpointsMap.unmerge`: remove the service ports contained in `other`.
pub fn unmerge(em: &mut EndpointsMap, other: &EndpointsMap) {
    for k in other.keys() {
        em.remove(k);
    }
}

/// `getLocalReadyEndpointIPs`: local endpoint IPs by service. Only ready
/// endpoints count: a terminating endpoint may still serve traffic, but the
/// health check must fail when only terminating ones are left on the node.
pub fn get_local_ready_endpoint_ips(
    em: &EndpointsMap,
) -> BTreeMap<NamespacedName, BTreeSet<String>> {
    let mut local: BTreeMap<NamespacedName, BTreeSet<String>> = BTreeMap::new();
    for (spn, eps) in em {
        for ep in eps {
            if !ep.ready || !ep.is_local {
                continue;
            }
            local
                .entry(spn.namespaced_name.clone())
                .or_default()
                .insert(ep.ip.clone());
        }
    }
    local
}

/// `LocalReadyEndpoints`: the number of local ready endpoints by service,
/// counted by IP (an IP on two ports is one endpoint).
pub fn local_ready_endpoints(em: &EndpointsMap) -> BTreeMap<NamespacedName, usize> {
    get_local_ready_endpoint_ips(em)
        .into_iter()
        .map(|(nn, ips)| (nn, ips.len()))
        .collect()
}

/// A `ServicePortName` of a named service port (test and caller helper,
/// `makeServicePortName`).
pub fn service_port_name(ns: &str, name: &str, port: &str, protocol: &str) -> ServicePortName {
    ServicePortName {
        namespaced_name: NamespacedName {
            namespace: ns.to_string(),
            name: name.to_string(),
        },
        port: port.to_string(),
        protocol: protocol.to_string(),
    }
}
