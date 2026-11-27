//! Port of `pkg/proxy/servicechangetracker.go` (`ServiceChangeTracker`,
//! `ServicePortMap`, `serviceToServiceMap`, `merge`/`filter`/`unmerge`) and
//! `pkg/proxy/serviceport.go` (`BaseServicePortInfo`, `newBaseServiceInfo`).
//!
//! Upstream locks the tracker; here every mutation takes `&mut self`, so the
//! owner serialises access. Not ported: the `makeServiceInfo` hook (proxier
//! specific wrappers; callers read [`BaseServicePortInfo`] directly), metrics.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use kubernetes_rs_common::resources::service::{
    ServiceExternalTrafficPolicy, ServiceInternalTrafficPolicy,
};
use kubernetes_rs_common::resources::{Service, ServicePort, ServiceType};
use tracing::{debug, error};

use crate::endpointslice_cache::{NamespacedName, ServicePortName};
use crate::iptables::{cluster_ip_for_family, IpFamily};

/// `DefaultClientIPServiceAffinitySeconds` (pkg/apis/core/v1/defaults.go):
/// kube-apiserver always fills `sessionAffinityConfig` for ClientIP affinity,
/// so upstream dereferences it unchecked; this is the value it defaults to.
const DEFAULT_CLIENT_IP_AFFINITY_SECONDS: i32 = 10800;

/// A CIDR as `*net.IPNet` holds it: the network address (masked) and prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

/// `netutils.ParseIPSloppy`: like `IpAddr::from_str` but IPv4 octets may carry
/// leading zeros (read as decimal).
pub fn parse_ip_sloppy(s: &str) -> Option<IpAddr> {
    if !s.contains(':') {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut o = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            o[i] = p.parse::<u16>().ok().and_then(|v| u8::try_from(v).ok())?;
        }
        return Some(IpAddr::from(o));
    }
    s.parse().ok()
}

/// `netutils.ParseCIDRSloppy`: returns the masked network.
pub fn parse_cidr_sloppy(s: &str) -> Option<IpNet> {
    let (ip, len) = s.split_once('/')?;
    let addr = parse_ip_sloppy(ip)?;
    let prefix: u8 = len.parse().ok()?;
    let (bits, max) = match addr {
        IpAddr::V4(_) => (32u32, 32u8),
        IpAddr::V6(_) => (128, 128),
    };
    if prefix > max {
        return None;
    }
    let masked = match addr {
        IpAddr::V4(a) => {
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (bits - u32::from(prefix))
            };
            IpAddr::from((u32::from(a) & m).to_be_bytes())
        }
        IpAddr::V6(a) => {
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (bits - u32::from(prefix))
            };
            IpAddr::from((u128::from(a) & m).to_be_bytes())
        }
    };
    Some(IpNet {
        addr: masked,
        prefix,
    })
}

fn family_of(ip: &IpAddr) -> IpFamily {
    match ip {
        IpAddr::V4(_) => IpFamily::V4,
        IpAddr::V6(_) => IpFamily::V6,
    }
}

/// `BaseServicePortInfo` (serviceport.go:76).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseServicePortInfo {
    pub cluster_ip: IpAddr,
    pub port: i32,
    pub protocol: String,
    pub node_port: i32,
    pub load_balancer_vips: Vec<IpAddr>,
    pub session_affinity_type: String,
    pub sticky_max_age_seconds: i32,
    pub external_ips: Vec<IpAddr>,
    pub load_balancer_source_ranges: Vec<IpNet>,
    pub health_check_node_port: i32,
    pub external_policy_local: bool,
    pub internal_policy_local: bool,
}

impl BaseServicePortInfo {
    /// `String()`: `ip:port/protocol`.
    pub fn string(&self) -> String {
        format!("{}:{}/{}", self.cluster_ip, self.port, self.protocol)
    }

    /// `ExternallyAccessible`.
    pub fn externally_accessible(&self) -> bool {
        self.node_port != 0 || !self.load_balancer_vips.is_empty() || !self.external_ips.is_empty()
    }

    /// `UsesClusterEndpoints`: Cluster internal policy, or accepts external
    /// traffic at all (Local external policy still needs Cluster endpoints for
    /// short circuiting).
    pub fn uses_cluster_endpoints(&self) -> bool {
        !self.internal_policy_local || self.externally_accessible()
    }

    /// `UsesLocalEndpoints`.
    pub fn uses_local_endpoints(&self) -> bool {
        self.internal_policy_local || (self.external_policy_local && self.externally_accessible())
    }
}

/// `apiservice.ExternallyAccessible` (pkg/api/v1/service/util.go).
fn service_externally_accessible(svc: &Service) -> bool {
    match svc.spec.service_type {
        Some(ServiceType::LoadBalancer) | Some(ServiceType::NodePort) => true,
        None | Some(ServiceType::ClusterIP) => !svc
            .spec
            .external_ips
            .as_deref()
            .unwrap_or_default()
            .is_empty(),
        _ => false,
    }
}

/// `apiservice.ExternalPolicyLocal` (util.go:78).
fn external_policy_local(svc: &Service) -> bool {
    service_externally_accessible(svc)
        && svc.spec.external_traffic_policy == Some(ServiceExternalTrafficPolicy::Local)
}

/// `apiservice.InternalPolicyLocal` (util.go:86).
fn internal_policy_local(svc: &Service) -> bool {
    svc.spec.internal_traffic_policy == Some(ServiceInternalTrafficPolicy::Local)
}

/// `apiservice.NeedsHealthCheck` (util.go:94).
fn needs_health_check(svc: &Service) -> bool {
    svc.spec.service_type == Some(ServiceType::LoadBalancer) && external_policy_local(svc)
}

/// `proxyutil.ShouldSkipService` (pkg/proxy/util/utils.go:55).
fn should_skip_service(svc: &Service) -> bool {
    let ip = svc.spec.cluster_ip.as_deref().unwrap_or("");
    ip.is_empty() || ip == "None" || svc.spec.service_type == Some(ServiceType::ExternalName)
}

/// `newBaseServiceInfo` (serviceport.go:176). `None` when the Service has no
/// ClusterIP in `family` (callers have already applied `ShouldSkipService`).
fn new_base_service_info(
    svc: &Service,
    family: IpFamily,
    port: &ServicePort,
) -> Option<BaseServicePortInfo> {
    let sticky_max_age_seconds = if svc.spec.session_affinity.as_deref() == Some("ClientIP") {
        svc.spec
            .session_affinity_config
            .as_ref()
            .and_then(|c| c.client_ip.as_ref())
            .and_then(|c| c.timeout_seconds)
            .unwrap_or(DEFAULT_CLIENT_IP_AFFINITY_SECONDS)
    } else {
        0
    };

    let cluster_ip = parse_ip_sloppy(&cluster_ip_for_family(svc, family)?)?;

    // Filter ExternalIPs to the right family (`MapIPsByIPFamily`).
    let external_ips = svc
        .spec
        .external_ips
        .iter()
        .flatten()
        .filter_map(|s| parse_ip_sloppy(s))
        .filter(|ip| family_of(ip) == family)
        .collect();

    // Filter source ranges to the family; whitespace padding is accepted
    // (`MapCIDRsByIPFamily`). A zero-masked CIDR means "allow any", the same as
    // an empty list.
    let mut load_balancer_source_ranges: Vec<IpNet> = svc
        .spec
        .load_balancer_source_ranges
        .iter()
        .flatten()
        .filter_map(|s| parse_cidr_sloppy(s.trim()))
        .filter(|c| family_of(&c.addr) == family)
        .collect();
    if load_balancer_source_ranges.iter().any(|c| c.prefix == 0) {
        load_balancer_source_ranges.clear();
    }

    // Only VIP-mode ingress IPs of this family get rules (`IsVIPMode`).
    let load_balancer_vips = svc
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .into_iter()
        .flat_map(|lb| lb.ingress.iter())
        .filter(|ing| {
            ing.ip.as_deref().is_some_and(|i| !i.is_empty())
                && ing.ip_mode.as_deref().is_none_or(|m| m == "VIP")
        })
        .filter_map(|ing| parse_ip_sloppy(ing.ip.as_deref()?))
        .filter(|ip| family_of(ip) == family)
        .collect();

    let mut health_check_node_port = 0;
    if needs_health_check(svc) {
        match svc.spec.health_check_node_port.unwrap_or(0) {
            0 => error!(
                "Service {}/{} has no healthcheck nodeport",
                svc.metadata.namespace.as_deref().unwrap_or(""),
                svc.metadata.name
            ),
            p => health_check_node_port = p,
        }
    }

    Some(BaseServicePortInfo {
        cluster_ip,
        port: i32::from(port.port),
        protocol: port.protocol.clone(),
        node_port: i32::from(port.node_port.unwrap_or(0)),
        load_balancer_vips,
        session_affinity_type: svc.spec.session_affinity.clone().unwrap_or_default(),
        sticky_max_age_seconds,
        external_ips,
        load_balancer_source_ranges,
        health_check_node_port,
        external_policy_local: external_policy_local(svc),
        internal_policy_local: internal_policy_local(svc),
    })
}

/// `ServicePortMap`.
pub type ServicePortMap = BTreeMap<ServicePortName, BaseServicePortInfo>;

/// `UpdateServiceMapResult`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UpdateServiceMapResult {
    /// Services added/updated/deleted since the last update.
    pub updated_services: BTreeSet<NamespacedName>,
}

/// `ServicePortMap.HealthCheckNodePorts`.
pub fn health_check_node_ports(sm: &ServicePortMap) -> BTreeMap<NamespacedName, u16> {
    sm.iter()
        .filter(|(_, info)| info.health_check_node_port != 0)
        .map(|(name, info)| {
            (
                name.namespaced_name.clone(),
                info.health_check_node_port as u16,
            )
        })
        .collect()
}

/// `serviceChange`. `None` stands for upstream's nil map (a skipped or absent
/// Service), which `reflect.DeepEqual` distinguishes from an empty one.
#[derive(Debug, Clone, Default)]
struct ServiceChange {
    previous: Option<ServicePortMap>,
    current: Option<ServicePortMap>,
}

type ProcessServiceMapChange = Box<dyn FnMut(&ServicePortMap, &ServicePortMap) + Send>;

/// `ServiceChangeTracker`.
pub struct ServiceChangeTracker {
    items: BTreeMap<NamespacedName, ServiceChange>,
    process_service_map_change: Option<ProcessServiceMapChange>,
    ip_family: IpFamily,
}

impl ServiceChangeTracker {
    /// `NewServiceChangeTracker`.
    pub fn new(
        ip_family: IpFamily,
        process_service_map_change: Option<ProcessServiceMapChange>,
    ) -> Self {
        Self {
            items: BTreeMap::new(),
            process_service_map_change,
            ip_family,
        }
    }

    /// `Update`: record the `<previous, current>` pair (either, not both, may
    /// be `None`). Returns whether any changes are pending a sync.
    pub fn update(&mut self, previous: Option<&Service>, current: Option<&Service>) -> bool {
        let Some(svc) = current.or(previous) else {
            return false;
        };
        let name = NamespacedName {
            namespace: svc.metadata.namespace.clone().unwrap_or_default(),
            name: svc.metadata.name.clone(),
        };
        if !self.items.contains_key(&name) {
            let previous = self.service_to_service_map(previous);
            self.items.insert(
                name.clone(),
                ServiceChange {
                    previous,
                    current: None,
                },
            );
        }
        let current = self.service_to_service_map(current);
        let change = self.items.get_mut(&name).expect("inserted above");
        change.current = current;
        // Unchanged: previous equals current.
        if change.previous == change.current {
            self.items.remove(&name);
        } else {
            debug!(
                "Service {}/{} updated ports ({})",
                name.namespace,
                name.name,
                change.current.as_ref().map_or(0, |m| m.len())
            );
        }
        !self.items.is_empty()
    }

    /// `serviceToServiceMap`.
    fn service_to_service_map(&self, service: Option<&Service>) -> Option<ServicePortMap> {
        let service = service?;
        if should_skip_service(service) {
            return None;
        }
        cluster_ip_for_family(service, self.ip_family)?;
        let svc_name = NamespacedName {
            namespace: service.metadata.namespace.clone().unwrap_or_default(),
            name: service.metadata.name.clone(),
        };
        let mut map = ServicePortMap::new();
        for port in &service.spec.ports {
            let key = ServicePortName {
                namespaced_name: svc_name.clone(),
                port: port.name.clone().unwrap_or_default(),
                protocol: port.protocol.clone(),
            };
            if let Some(info) = new_base_service_info(service, self.ip_family, port) {
                map.insert(key, info);
            }
        }
        Some(map)
    }

    /// `ServicePortMap.Update(sct)`: apply and clear the pending changes.
    pub fn apply(&mut self, sm: &mut ServicePortMap) -> UpdateServiceMapResult {
        let mut result = UpdateServiceMapResult::default();
        for (nn, change) in std::mem::take(&mut self.items) {
            let previous = change.previous.unwrap_or_default();
            let current = change.current.unwrap_or_default();
            if let Some(f) = self.process_service_map_change.as_mut() {
                f(&previous, &current);
            }
            result.updated_services.insert(nn);

            // merge: other always wins.
            for (k, v) in &current {
                sm.insert(k.clone(), v.clone());
            }
            // filter: skip the delete for entries that were only updated.
            // unmerge: remove what is left of previous.
            for k in previous.keys().filter(|k| !current.contains_key(*k)) {
                if sm.remove(k).is_none() {
                    error!("Service port {k} does not exist");
                }
            }
        }
        result
    }

    /// Number of services with pending changes.
    pub fn pending(&self) -> usize {
        self.items.len()
    }
}
