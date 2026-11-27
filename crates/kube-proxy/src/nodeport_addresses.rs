//! `--nodeport-addresses` handling.
//!
//! Port of `pkg/proxy/util/nodeport_addresses.go` (release-1.35):
//! `NewNodePortAddresses` (:44), `MatchAll` (:84), `GetNodeIPs` (:96),
//! `ContainsIPv4Loopback` (:132), with `IPv4ZeroCIDR` / `IPv6ZeroCIDR` /
//! `IsZeroCIDR` from `pkg/proxy/util/utils.go:34-52`. CIDRs are parsed with
//! std only; like `netutils.ParseCIDRSloppy` an IPv4 octet may carry leading
//! zeros. Unparsable CIDRs are skipped (upstream assumes the flag is already
//! validated).

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `IPv4ZeroCIDR` (utils.go:35).
pub const IPV4_ZERO_CIDR: &str = "0.0.0.0/0";
/// `IPv6ZeroCIDR` (utils.go:38).
pub const IPV6_ZERO_CIDR: &str = "::/0";

/// `v1.IPFamily`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    IPv4,
    IPv6,
}

/// A parsed CIDR (`*net.IPNet`): network address plus prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

fn parse_ipv4_sloppy(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        o[i] = p.parse::<u8>().ok()?;
    }
    Some(Ipv4Addr::from(o))
}

impl Cidr {
    /// `netutils.ParseCIDRSloppy`: the address is masked to the network.
    pub fn parse(s: &str) -> Option<Self> {
        let (ip, len) = s.split_once('/')?;
        let prefix: u8 = len.parse().ok()?;
        let addr = if ip.contains(':') {
            IpAddr::V6(ip.parse::<Ipv6Addr>().ok()?)
        } else {
            IpAddr::V4(parse_ipv4_sloppy(ip)?)
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return None;
        }
        Some(Self {
            addr: mask(addr, prefix),
            prefix,
        })
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// `IsZeroCIDR` (utils.go:46): prefix length 0.
    pub fn is_zero(&self) -> bool {
        self.prefix == 0
    }

    /// `(*net.IPNet).Contains`: an address of the other family never matches.
    pub fn contains(&self, ip: IpAddr) -> bool {
        if self.addr.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        mask(ip, self.prefix) == self.addr
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & m))
        }
        IpAddr::V6(v6) => {
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & m))
        }
    }
}

/// `NetworkInterfacer` (pkg/proxy/util/network.go): the host's interface
/// addresses, injected for tests.
pub trait NetworkInterfacer {
    fn interface_addrs(&self) -> Result<Vec<IpAddr>, String>;
}

/// `NodePortAddresses` for one IP family.
#[derive(Debug, Clone)]
pub struct NodePortAddresses {
    cidr_strings: Vec<String>,
    cidrs: Vec<Cidr>,
    contains_ipv4_loopback: bool,
    match_all: bool,
}

impl NodePortAddresses {
    /// `NewNodePortAddresses` (:44-81): keep the CIDRs of `family`; if none,
    /// use the zero CIDR; a zero CIDR makes everything else irrelevant.
    pub fn new(family: IpFamily, cidr_strings: &[String]) -> Self {
        let want_v4 = family == IpFamily::IPv4;
        let mut strs: Vec<String> = cidr_strings
            .iter()
            // IsIPv4CIDRString: no ':' in the string
            .filter(|s| want_v4 == !s.contains(':'))
            .cloned()
            .collect();
        if strs.is_empty() {
            strs = vec![if want_v4 {
                IPV4_ZERO_CIDR
            } else {
                IPV6_ZERO_CIDR
            }
            .to_string()];
        }

        let mut npa = Self {
            cidr_strings: strs.clone(),
            cidrs: Vec::new(),
            contains_ipv4_loopback: false,
            match_all: false,
        };
        let loopback_start = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0));
        for s in &strs {
            let Some(cidr) = Cidr::parse(s) else { continue };
            if cidr.is_ipv4() {
                let is_loopback = matches!(cidr.addr, IpAddr::V4(a) if a.is_loopback());
                if is_loopback || cidr.contains(loopback_start) {
                    npa.contains_ipv4_loopback = true;
                }
            }
            if cidr.is_zero() {
                // Ignore everything else
                npa.cidrs = vec![cidr];
                npa.match_all = true;
                break;
            }
            npa.cidrs.push(cidr);
        }
        npa
    }

    /// `MatchAll` (:84): matches all node IPs of the family.
    pub fn match_all(&self) -> bool {
        self.match_all
    }

    /// `ContainsIPv4Loopback` (:132).
    pub fn contains_ipv4_loopback(&self) -> bool {
        self.contains_ipv4_loopback
    }

    /// `GetNodeIPs` (:96-130): every interface address matched by a CIDR,
    /// de-duplicated.
    pub fn get_node_ips(&self, nw: &dyn NetworkInterfacer) -> Result<Vec<IpAddr>, String> {
        let addrs = nw
            .interface_addrs()
            .map_err(|e| format!("error listing all interfaceAddrs from host, error: {e}"))?;
        let mut found: BTreeSet<IpAddr> = BTreeSet::new();
        for cidr in &self.cidrs {
            for ip in &addrs {
                if cidr.contains(*ip) {
                    found.insert(*ip);
                }
            }
        }
        Ok(found.into_iter().collect())
    }
}

/// `String()` (:79): `fmt.Sprintf("%v", cidrStrings)`, i.e. `[a b]`.
impl fmt::Display for NodePortAddresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.cidr_strings.join(" "))
    }
}

/// `NetworkInterfacer` over procfs (no extra dependency): IPv4 local
/// addresses from `/proc/net/fib_trie` ("/32 host LOCAL" entries) and IPv6
/// addresses from `/proc/net/if_inet6`. The kernel's local-address view is
/// what `net.InterfaceAddrs()` reports for the host.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcNetworkInterfacer;

impl NetworkInterfacer for ProcNetworkInterfacer {
    fn interface_addrs(&self) -> Result<Vec<IpAddr>, String> {
        let mut out = Vec::new();
        let trie = std::fs::read_to_string("/proc/net/fib_trie").map_err(|e| e.to_string())?;
        out.extend(parse_fib_trie_local(&trie));
        // IPv6 may be disabled: a missing file is not an error.
        if let Ok(v6) = std::fs::read_to_string("/proc/net/if_inet6") {
            out.extend(parse_if_inet6(&v6));
        }
        Ok(out)
    }
}

/// Local IPv4 addresses of a `/proc/net/fib_trie` dump: a `|-- a.b.c.d` line
/// followed by `/32 host LOCAL`.
pub fn parse_fib_trie_local(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut last: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("|--") {
            last = rest.trim().parse().ok();
        } else if l.starts_with("/32 host LOCAL") {
            if let Some(a) = last {
                let ip = IpAddr::V4(a);
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

/// Addresses of a `/proc/net/if_inet6` dump (first column: 32 hex digits).
pub fn parse_if_inet6(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let hex = l.split_whitespace().next()?;
            u128::from_str_radix(hex, 16)
                .ok()
                .filter(|_| hex.len() == 32)
                .map(|v| IpAddr::V6(Ipv6Addr::from(v)))
        })
        .collect()
}

/// `localhostNodePorts` after `NewNodePortAddresses` is consulted
/// (iptables/proxier.go:236-238): it is forced off when the CIDRs cannot
/// contain an IPv4 loopback address.
pub fn effective_localhost_nodeports(npa: &NodePortAddresses, localhost_nodeports: bool) -> bool {
    localhost_nodeports && npa.contains_ipv4_loopback()
}

/// The destination matches of the tail-call into the NodePorts chain
/// (iptables/proxier.go:1389-1427), one rule per entry. With a match-all
/// CIDR it is a single `--dst-type LOCAL` rule that blocks localhost when
/// localhost NodePorts are unsupported; otherwise one `-d <ip>` rule per
/// matched node IP, skipping loopback addresses that cannot work. `errors`
/// receives what upstream logs.
pub fn nodeport_destinations(
    npa: &NodePortAddresses,
    family: IpFamily,
    localhost_nodeports: bool,
    nw: &dyn NetworkInterfacer,
    errors: &mut Vec<String>,
) -> Vec<Vec<String>> {
    let is_ipv6 = family == IpFamily::IPv6;
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    if npa.match_all() {
        let mut d = s(&["-m", "addrtype", "--dst-type", "LOCAL"]);
        // Block localhost nodePorts if they are not supported. (For IPv6 they
        // never work, and for IPv4 they only work with route_localnet.)
        if is_ipv6 {
            d.extend(s(&["!", "-d", "::1/128"]));
        } else if !localhost_nodeports {
            d.extend(s(&["!", "-d", "127.0.0.0/8"]));
        }
        return vec![d];
    }
    let ips = match npa.get_node_ips(nw) {
        Ok(ips) => ips,
        Err(e) => {
            errors.push(format!(
                "Failed to get node ip address matching nodeport cidrs, services with nodeport may not work as intended: {e}"
            ));
            Vec::new()
        }
    };
    let mut rules = Vec::new();
    for ip in ips {
        if ip.is_loopback() {
            if is_ipv6 {
                errors.push(format!("--nodeport-addresses includes localhost but localhost NodePorts are not supported on IPv6: {ip}"));
                continue;
            } else if !localhost_nodeports {
                errors.push(format!("--nodeport-addresses includes localhost but --iptables-localhost-nodeports=false was passed: {ip}"));
                continue;
            }
        }
        rules.push(vec!["-d".to_string(), ip.to_string()]);
    }
    rules
}
