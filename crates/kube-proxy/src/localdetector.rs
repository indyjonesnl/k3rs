//! Port of `pkg/proxy/util/localdetector.go` (release-1.35): rule arguments
//! that match traffic from (or not from) local pods, by pod CIDR, bridge
//! interface or interface name prefix. `getLocalDetectors`
//! (`cmd/kube-proxy/app/server_linux.go`) chooses between them; replacing the
//! `detect_bridge_network` heuristic in iptables.rs is a separate wiring task.

use std::net::Ipv6Addr;

/// `LocalTrafficDetector`.
pub trait LocalTrafficDetector: Send + Sync {
    /// True if the implementation does something; the other methods must not
    /// be used otherwise.
    fn is_implemented(&self) -> bool;
    /// iptables arguments matching traffic from a local pod.
    fn if_local(&self) -> &[String];
    /// iptables arguments matching traffic that is not from a local pod.
    fn if_not_local(&self) -> &[String];
    /// nftables arguments matching traffic from a local pod.
    fn if_local_nft(&self) -> &[String];
    /// nftables arguments matching traffic that is not from a local pod.
    fn if_not_local_nft(&self) -> &[String];
}

/// `detectLocal`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectLocal {
    if_local: Vec<String>,
    if_not_local: Vec<String>,
    if_local_nft: Vec<String>,
    if_not_local_nft: Vec<String>,
}

fn v(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

impl LocalTrafficDetector for DetectLocal {
    fn is_implemented(&self) -> bool {
        !self.if_local.is_empty()
    }
    fn if_local(&self) -> &[String] {
        &self.if_local
    }
    fn if_not_local(&self) -> &[String] {
        &self.if_not_local
    }
    fn if_local_nft(&self) -> &[String] {
        &self.if_local_nft
    }
    fn if_not_local_nft(&self) -> &[String] {
        &self.if_not_local_nft
    }
}

/// `NewNoOpLocalDetector`.
pub fn new_no_op_local_detector() -> DetectLocal {
    DetectLocal::default()
}

/// `netutils.IsIPv6CIDRString`: a valid CIDR whose address is IPv6.
fn is_ipv6_cidr_string(cidr: &str) -> bool {
    match cidr.split_once('/') {
        Some((addr, bits)) => {
            addr.parse::<Ipv6Addr>().is_ok() && bits.parse::<u8>().is_ok_and(|b| b <= 128)
        }
        None => false,
    }
}

/// `NewDetectLocalByCIDR`: traffic from `cidr` is local, other traffic is not.
/// `cidr` is assumed to be valid.
pub fn new_detect_local_by_cidr(cidr: &str) -> DetectLocal {
    let nft_family = if is_ipv6_cidr_string(cidr) {
        "ip6"
    } else {
        "ip"
    };
    DetectLocal {
        if_local: v(&["-s", cidr]),
        if_not_local: v(&["!", "-s", cidr]),
        if_local_nft: v(&[nft_family, "saddr", cidr]),
        if_not_local_nft: v(&[nft_family, "saddr", "!=", cidr]),
    }
}

/// `NewDetectLocalByBridgeInterface`: traffic from `interface_name` is local.
pub fn new_detect_local_by_bridge_interface(interface_name: &str) -> DetectLocal {
    DetectLocal {
        if_local: v(&["-i", interface_name]),
        if_not_local: v(&["!", "-i", interface_name]),
        if_local_nft: v(&["iifname", interface_name]),
        if_not_local_nft: v(&["iifname", "!=", interface_name]),
    }
}

/// `NewDetectLocalByInterfaceNamePrefix`: traffic from interfaces starting
/// with `interface_prefix` is local.
pub fn new_detect_local_by_interface_name_prefix(interface_prefix: &str) -> DetectLocal {
    let plus = format!("{interface_prefix}+");
    let star = format!("{interface_prefix}*");
    DetectLocal {
        if_local: v(&["-i", &plus]),
        if_not_local: v(&["!", "-i", &plus]),
        if_local_nft: v(&["iifname", &star]),
        if_not_local_nft: v(&["iifname", "!=", &star]),
    }
}
