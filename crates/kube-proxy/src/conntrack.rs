//! Stale UDP conntrack entry cleanup.
//!
//! Ported from upstream `pkg/proxy/conntrack` (release-1.35):
//! `cleanup.go` `CleanStaleEntries` (:46), `filterForIPPortNAT` (:175),
//! `filterForPortNAT` (:192), `filter.go` `conntrackFilter.MatchConntrackFlow`
//! and `fake.go` `FakeInterface`.
//!
//! Kubernetes UDP services can be affected by stale conntrack entries that
//! point to endpoints that no longer exist (e.g. DNS to a CoreDNS ClusterIP
//! after a restart keeps hitting the dead pod for the 30s UDP timeout).
//!
//! Deviations, stated explicitly:
//! - This crate has no `ServicePortMap` / `EndpointsMap` yet (see
//!   `svc_maps.rs`), so [`clean_stale_entries`] takes the already-flattened
//!   per-service-port view ([`ServiceConntrackInfo`]) holding exactly the
//!   fields `CleanStaleEntries` reads from `ServicePort` and `Endpoint`.
//! - Upstream records the `ReconcileConntrackFlows*` Prometheus metrics; this
//!   function returns the number of deleted entries so the caller can.
//! - The netlink-backed `Interface` is a separate task; only the trait and a
//!   recording fake exist here.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use tracing::{error, trace, warn};

/// `unix.IPPROTO_*` (IANA protocol numbers).
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_SCTP: u8 = 132;

/// `v1.IPFamily`, mapped to `unix.AF_INET` / `unix.AF_INET6` by `ipFamilyMap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    IPv4,
    IPv6,
}

impl IpFamily {
    pub fn af(self) -> u8 {
        match self {
            IpFamily::IPv4 => 2,
            IpFamily::IPv6 => 10,
        }
    }
}

/// `protocolMap`: `v1.Protocol` to the assigned protocol number (0 if unknown,
/// like a missing Go map key).
pub fn protocol_number(protocol: &str) -> u8 {
    match protocol {
        "TCP" => IPPROTO_TCP,
        "UDP" => IPPROTO_UDP,
        "SCTP" => IPPROTO_SCTP,
        _ => 0,
    }
}

/// One direction of a conntrack flow (`netlink.IPTuple`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpTuple {
    pub src_ip: Option<IpAddr>,
    pub src_port: u16,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: u16,
    pub protocol: u8,
}

/// `netlink.ConntrackFlow`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConntrackFlow {
    pub forward: IpTuple,
    pub reverse: IpTuple,
}

/// `connectionTuple` of filter.go: unset IP / zero port means "any".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionTuple {
    pub src_ip: Option<IpAddr>,
    pub src_port: u16,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: u16,
}

/// `conntrackFilter` (filter.go).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConntrackFilter {
    pub protocol: u8,
    pub original: Option<ConnectionTuple>,
    pub reply: Option<ConnectionTuple>,
}

impl ConntrackFilter {
    /// `MatchConntrackFlow` (filter.go:44).
    pub fn matches(&self, flow: &ConntrackFlow) -> bool {
        // return false in case of empty filter
        if self.protocol == 0 && self.original.is_none() && self.reply.is_none() {
            return false;
        }
        if self.protocol != 0 && self.protocol != flow.forward.protocol {
            return false;
        }
        if let Some(o) = &self.original {
            if o.src_ip.is_some() && o.src_ip != flow.forward.src_ip {
                return false;
            }
            if o.dst_ip.is_some() && o.dst_ip != flow.forward.dst_ip {
                return false;
            }
            if o.src_port != 0 && o.src_port != flow.forward.src_port {
                return false;
            }
            if o.dst_port != 0 && o.dst_port != flow.forward.dst_port {
                return false;
            }
        }
        if let Some(r) = &self.reply {
            if r.src_ip.is_some() && r.src_ip != flow.reverse.src_ip {
                return false;
            }
            if r.dst_ip.is_some() && r.dst_ip != flow.reverse.dst_ip {
                return false;
            }
            if r.src_port != 0 && r.src_port != flow.reverse.src_port {
                return false;
            }
            if r.dst_port != 0 && r.dst_port != flow.reverse.dst_port {
                return false;
            }
        }
        true
    }
}

/// `filterForIPPortNAT` (cleanup.go:175): match connections by original
/// destination IP and port plus reply source IP and port.
pub fn filter_for_ip_port_nat(
    orig_dst: IpAddr,
    orig_port_dst: u16,
    reply_src: IpAddr,
    reply_port_src: u16,
    protocol: &str,
) -> ConntrackFilter {
    trace!(%orig_dst, orig_port_dst, %reply_src, reply_port_src, protocol, "Adding conntrack filter for cleanup");
    ConntrackFilter {
        protocol: protocol_number(protocol),
        original: Some(ConnectionTuple {
            dst_ip: Some(orig_dst),
            dst_port: orig_port_dst,
            ..Default::default()
        }),
        reply: Some(ConnectionTuple {
            src_ip: Some(reply_src),
            src_port: reply_port_src,
            ..Default::default()
        }),
    }
}

/// `filterForPortNAT` (cleanup.go:192): match connections by original
/// destination port plus reply source IP and port.
pub fn filter_for_port_nat(
    orig_port_dst: u16,
    reply_src: IpAddr,
    reply_port_src: u16,
    protocol: &str,
) -> ConntrackFilter {
    trace!(orig_port_dst, %reply_src, reply_port_src, protocol, "Adding conntrack filter for cleanup");
    ConntrackFilter {
        protocol: protocol_number(protocol),
        original: Some(ConnectionTuple {
            dst_port: orig_port_dst,
            ..Default::default()
        }),
        reply: Some(ConnectionTuple {
            src_ip: Some(reply_src),
            src_port: reply_port_src,
            ..Default::default()
        }),
    }
}

/// Failure of `Interface.ListEntries` / `ClearEntries`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConntrackError {
    /// `unix.EINTR`: the dump was interrupted and the result is partial.
    Interrupted,
    Other(String),
}

/// `conntrack.Interface` (conntrack.go).
pub trait ConntrackInterface {
    /// Lists the entries of the family. A partial result may accompany
    /// [`ConntrackError::Interrupted`].
    fn list_entries(
        &mut self,
        family: IpFamily,
    ) -> (Vec<ConntrackFlow>, Result<(), ConntrackError>);
    /// Deletes every entry matching any filter; returns the number deleted.
    fn clear_entries(
        &mut self,
        family: IpFamily,
        filters: &[ConntrackFilter],
    ) -> Result<usize, ConntrackError>;
}

/// `FakeInterface` (fake.go): records entries that have been cleared.
#[derive(Debug, Default)]
pub struct FakeConntrack {
    pub entries: Vec<ConntrackFlow>,
}

impl ConntrackInterface for FakeConntrack {
    fn list_entries(
        &mut self,
        _family: IpFamily,
    ) -> (Vec<ConntrackFlow>, Result<(), ConntrackError>) {
        (self.entries.clone(), Ok(()))
    }

    fn clear_entries(
        &mut self,
        _family: IpFamily,
        filters: &[ConntrackFilter],
    ) -> Result<usize, ConntrackError> {
        let before = self.entries.len();
        self.entries
            .retain(|flow| !filters.iter().any(|f| f.matches(flow)));
        Ok(before - self.entries.len())
    }
}

/// A serving-relevant endpoint (`proxy.Endpoint`: `IsServing`, `IP`, `Port`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointInfo {
    pub ip: IpAddr,
    pub port: u16,
    pub serving: bool,
}

/// One Service port as `CleanStaleEntries` reads it from `ServicePortMap` and
/// `EndpointsMap[svcName]`.
#[derive(Debug, Clone)]
pub struct ServiceConntrackInfo {
    /// `svc.Protocol()`: "TCP", "UDP" or "SCTP".
    pub protocol: String,
    pub port: u16,
    pub cluster_ip: IpAddr,
    pub load_balancer_ips: Vec<IpAddr>,
    pub external_ips: Vec<IpAddr>,
    /// 0 when the port has no NodePort.
    pub node_port: u16,
    pub endpoints: Vec<EndpointInfo>,
}

/// `CleanStaleEntries` (cleanup.go:46): scans the conntrack table and removes
/// UDP entries for a service that do not correspond to a serving endpoint.
/// Returns the number of deleted entries (upstream feeds this to
/// `ReconcileConntrackFlowsDeletedEntriesTotal`).
pub fn clean_stale_entries<C: ConntrackInterface>(
    ct: &mut C,
    ip_family: IpFamily,
    services: &[ServiceConntrackInfo],
) -> usize {
    let (entries, list_result) = ct.list_entries(ip_family);
    match list_result {
        Ok(()) => {}
        Err(ConntrackError::Interrupted) => {
            warn!("received a partial result, continuing to clean with partial result");
        }
        Err(e) => {
            error!(error = ?e, "Failed to list conntrack entries");
            return 0;
        }
    }

    // service IPs (ClusterIP, LoadBalancerIPs, ExternalIPs) and Service Port ->
    // serving endpoints (IP and Port).
    let mut service_ip_endpoints: HashMap<(IpAddr, u16), HashSet<(IpAddr, u16)>> = HashMap::new();
    // service NodePort -> serving endpoints.
    let mut service_node_port_endpoints: HashMap<u16, HashSet<(IpAddr, u16)>> = HashMap::new();

    for svc in services {
        // we are only interested in UDP services
        if svc.protocol != "UDP" {
            continue;
        }
        // We map all the serving endpoints of the service and clear all the
        // conntrack entries destined for the service that are not DNATed to
        // these endpoints. Traffic policies, topology and terminating status
        // are deliberately not considered (cleanup.go:71-77).
        let endpoints: HashSet<(IpAddr, u16)> = svc
            .endpoints
            .iter()
            .filter(|e| e.serving)
            .map(|e| (e.ip, e.port))
            .collect();

        // a Service without endpoints does not require cleaning its entries.
        if endpoints.is_empty() {
            continue;
        }

        service_ip_endpoints.insert((svc.cluster_ip, svc.port), endpoints.clone());
        for ip in &svc.load_balancer_ips {
            service_ip_endpoints.insert((*ip, svc.port), endpoints.clone());
        }
        for ip in &svc.external_ips {
            service_ip_endpoints.insert((*ip, svc.port), endpoints.clone());
        }
        if svc.node_port != 0 {
            service_node_port_endpoints.insert(svc.node_port, endpoints);
        }
    }

    let mut filters = Vec::new();
    for entry in &entries {
        // we only deal with UDP protocol entries
        if entry.forward.protocol != IPPROTO_UDP {
            continue;
        }
        let orig_dst = entry.forward.dst_ip; // match Service IP
        let orig_port_dst = entry.forward.dst_port; // match Service Port
        let reply_src = entry.reverse.src_ip; // match Serving Endpoint IP
        let reply_port_src = entry.reverse.src_port; // match Serving Endpoint Port

        // A flow without a reply source IP cannot be attributed to a serving
        // endpoint. Upstream would build a filter with a nil reply IP (which
        // matches any); we skip it instead so that cannot over-delete.
        let Some(reply_src) = reply_src else {
            continue;
        };

        // original destination is a service IP:port and the reply source is not
        // a serving endpoint of the service: clear the entry. (A flow with no
        // original destination IP, as for *:NodePort, never matches here.)
        if let Some(endpoints) =
            orig_dst.and_then(|d| service_ip_endpoints.get(&(d, orig_port_dst)))
        {
            if !endpoints.contains(&(reply_src, reply_port_src)) {
                filters.push(filter_for_ip_port_nat(
                    orig_dst.expect("matched above"),
                    orig_port_dst,
                    reply_src,
                    reply_port_src,
                    "UDP",
                ));
            }
        }
        // original destination port is a NodePort and the reply source is not
        // a serving endpoint of the service: clear the entry.
        if let Some(endpoints) = service_node_port_endpoints.get(&orig_port_dst) {
            if !endpoints.contains(&(reply_src, reply_port_src)) {
                filters.push(filter_for_port_nat(
                    orig_port_dst,
                    reply_src,
                    reply_port_src,
                    "UDP",
                ));
            }
        }
    }

    match ct.clear_entries(ip_family, &filters) {
        Ok(n) => n,
        Err(e) => {
            error!(error = ?e, ?ip_family, "Failed to clear all conntrack entries");
            0
        }
    }
}
