//! Tests ported from `pkg/proxy/conntrack/cleanup_test.go` (release-1.35).

use kubernetes_rs_kube_proxy::conntrack::*;
use std::net::IpAddr;

const CLUSTER_IP: &str = "172.30.1.1";
const EXTERNAL_IP: &str = "192.168.99.100";
const LB_IP: &str = "1.2.3.4";
const SERVING_EP: &str = "10.240.0.4";
const NON_SERVING_EP: &str = "10.240.1.5";
const DELETED_EP: &str = "10.240.2.6";
const OLD_EP_PORT: u16 = 8080;
const EP_PORT: u16 = 9090;
const SVC_PORT: u16 = 8000;
const NODE_PORT: u16 = 32000;
const NON_SVC_PORT: u16 = 3000;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// `generateConntrackEntry`: an empty `orig_dst` means no original dst IP
/// (as for `*:NodePort`).
fn entry(
    orig_dst: &str,
    port_dst: u16,
    reply_src: &str,
    port_src: u16,
    proto: u8,
) -> ConntrackFlow {
    ConntrackFlow {
        forward: IpTuple {
            dst_ip: (!orig_dst.is_empty()).then(|| ip(orig_dst)),
            dst_port: port_dst,
            protocol: proto,
            ..Default::default()
        },
        reverse: IpTuple {
            src_ip: Some(ip(reply_src)),
            src_port: port_src,
            protocol: proto,
            ..Default::default()
        },
    }
}

fn svc_port(protocol: &str, endpoints: bool) -> ServiceConntrackInfo {
    let eps = if endpoints {
        vec![
            EndpointInfo {
                ip: ip(SERVING_EP),
                port: EP_PORT,
                serving: true,
            },
            EndpointInfo {
                ip: ip(NON_SERVING_EP),
                port: EP_PORT,
                serving: false,
            },
        ]
    } else {
        vec![]
    };
    ServiceConntrackInfo {
        protocol: protocol.to_string(),
        port: SVC_PORT,
        cluster_ip: ip(CLUSTER_IP),
        load_balancer_ips: vec![ip(LB_IP)],
        external_ips: vec![ip(EXTERNAL_IP)],
        node_port: if protocol == "TCP" { 0 } else { NODE_PORT },
        endpoints: eps,
    }
}

fn sorted(mut v: Vec<ConntrackFlow>) -> Vec<ConntrackFlow> {
    v.sort_by_key(|f| format!("{f:?}"));
    v
}

#[test]
fn conntrack_cleanup_stale_entries() {
    let services = vec![
        svc_port("TCP", true),
        svc_port("UDP", true),
        svc_port("SCTP", true),
    ];

    let mut before = Vec::new();
    let mut after = Vec::new();

    // Endpoints changing port without changing IP: cleared.
    for dst in [CLUSTER_IP, LB_IP, EXTERNAL_IP] {
        before.push(entry(dst, SVC_PORT, SERVING_EP, OLD_EP_PORT, IPPROTO_UDP));
    }
    for dnat in [SERVING_EP, NON_SERVING_EP, DELETED_EP] {
        for proto in [IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP] {
            for dst in [CLUSTER_IP, LB_IP, EXTERNAL_IP] {
                for port in [SVC_PORT, NON_SVC_PORT] {
                    let e = entry(dst, port, dnat, EP_PORT, proto);
                    before.push(e.clone());
                    if !(proto == IPPROTO_UDP && port == SVC_PORT && dnat != SERVING_EP) {
                        after.push(e);
                    }
                }
            }
            let e = entry("", NODE_PORT, dnat, EP_PORT, proto);
            before.push(e.clone());
            if !(proto == IPPROTO_UDP && dnat != SERVING_EP) {
                after.push(e);
            }
        }
    }
    // Non-DNATed entries (orig-dst == reply-src): service port ones are cleared.
    for dst in [CLUSTER_IP, LB_IP, EXTERNAL_IP] {
        for port in [SVC_PORT, NON_SVC_PORT] {
            let mut e = entry(dst, port, dst, 0, IPPROTO_UDP);
            e.reverse.src_port = 0;
            before.push(e.clone());
            if port != SVC_PORT {
                after.push(e);
            }
        }
    }

    let mut fake = FakeConntrack {
        entries: before.clone(),
    };
    let deleted = clean_stale_entries(&mut fake, IpFamily::IPv4, &services);
    assert_eq!(deleted, before.len() - after.len());
    assert_eq!(sorted(fake.entries), sorted(after));
}

#[test]
fn conntrack_cleanup_service_without_endpoints() {
    // TestServiceWithoutEndpoints: no endpoints for the service -> nothing cleared.
    let services = vec![svc_port("UDP", false)];
    let mut fake = FakeConntrack {
        entries: vec![
            entry(EXTERNAL_IP, SVC_PORT, SERVING_EP, EP_PORT, IPPROTO_UDP),
            entry(EXTERNAL_IP, SVC_PORT, DELETED_EP, EP_PORT, IPPROTO_UDP),
        ],
    };
    assert_eq!(clean_stale_entries(&mut fake, IpFamily::IPv4, &services), 0);
    assert_eq!(fake.entries.len(), 2);
}

#[test]
fn conntrack_cleanup_filter_for_ip_port_nat() {
    let f = filter_for_ip_port_nat(ip("10.96.0.10"), 80, ip("10.244.0.3"), 3000, "SCTP");
    assert_eq!(
        f,
        ConntrackFilter {
            protocol: 132,
            original: Some(ConnectionTuple {
                dst_ip: Some(ip("10.96.0.10")),
                dst_port: 80,
                ..Default::default()
            }),
            reply: Some(ConnectionTuple {
                src_ip: Some(ip("10.244.0.3")),
                src_port: 3000,
                ..Default::default()
            }),
        }
    );
    let f = filter_for_ip_port_nat(ip("2001:db8:1::2"), 443, ip("4001:ab8::2"), 5000, "UDP");
    assert_eq!(f.protocol, 17);
    assert_eq!(f.original.unwrap().dst_ip, Some(ip("2001:db8:1::2")));
}

#[test]
fn conntrack_cleanup_filter_for_port_nat() {
    let f = filter_for_port_nat(80, ip("10.96.0.10"), 3000, "TCP");
    assert_eq!(
        f,
        ConntrackFilter {
            protocol: 6,
            original: Some(ConnectionTuple {
                dst_port: 80,
                ..Default::default()
            }),
            reply: Some(ConnectionTuple {
                src_ip: Some(ip("10.96.0.10")),
                src_port: 3000,
                ..Default::default()
            }),
        }
    );
    let f = filter_for_port_nat(8000, ip("2001:db8:1::2"), 5000, "UDP");
    assert_eq!(f.protocol, 17);
}

#[test]
fn conntrack_cleanup_empty_filter_matches_nothing() {
    let e = entry(CLUSTER_IP, SVC_PORT, SERVING_EP, EP_PORT, IPPROTO_UDP);
    assert!(!ConntrackFilter::default().matches(&e));
}

struct ListFails(ConntrackError, Vec<ConntrackFlow>);
impl ConntrackInterface for ListFails {
    fn list_entries(&mut self, _: IpFamily) -> (Vec<ConntrackFlow>, Result<(), ConntrackError>) {
        (self.1.clone(), Err(self.0.clone()))
    }
    fn clear_entries(
        &mut self,
        _: IpFamily,
        filters: &[ConntrackFilter],
    ) -> Result<usize, ConntrackError> {
        Ok(filters.len())
    }
}

#[test]
fn conntrack_cleanup_list_errors() {
    let services = vec![svc_port("UDP", true)];
    let stale = entry(CLUSTER_IP, SVC_PORT, DELETED_EP, EP_PORT, IPPROTO_UDP);
    // EINTR: continue with the partial result.
    let mut ct = ListFails(ConntrackError::Interrupted, vec![stale.clone()]);
    assert_eq!(clean_stale_entries(&mut ct, IpFamily::IPv4, &services), 1);
    // Any other error: abort, delete nothing.
    let mut ct = ListFails(ConntrackError::Other("boom".into()), vec![stale]);
    assert_eq!(clean_stale_entries(&mut ct, IpFamily::IPv4, &services), 0);
}
