//! Ports of pkg/proxy/util/nodeport_addresses_test.go `TestGetNodeIPs` and
//! `TestContainsIPv4Loopback`.

use kubernetes_rs_kube_proxy::nodeport_addresses::{
    IpFamily, NetworkInterfacer, NodePortAddresses,
};
use std::collections::BTreeSet;
use std::net::IpAddr;

struct Fake(Vec<IpAddr>);
impl NetworkInterfacer for Fake {
    fn interface_addrs(&self) -> Result<Vec<IpAddr>, String> {
        Ok(self.0.clone())
    }
}

fn ips(v: &[&str]) -> Vec<IpAddr> {
    v.iter().map(|s| s.parse().unwrap()).collect()
}
fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// (name, cidrs, interface addrs, v4 (match_all, ips), v6 (match_all, ips))
type Case = (
    &'static str,
    Vec<&'static str>,
    Vec<&'static str>,
    (bool, Vec<&'static str>),
    (bool, Vec<&'static str>),
);

#[test]
fn nodeport_addresses_get_node_ips() {
    let cases: Vec<Case> = vec![
        (
            "IPv4 single",
            vec!["10.20.30.0/24"],
            vec!["10.20.30.51", "100.200.201.1"],
            (false, vec!["10.20.30.51"]),
            (true, vec![]),
        ),
        (
            "IPv4 zero CIDR",
            vec!["0.0.0.0/0"],
            vec!["10.20.30.51", "127.0.0.1"],
            (true, vec!["10.20.30.51", "127.0.0.1"]),
            (true, vec![]),
        ),
        (
            "IPv6 multiple",
            vec!["2001:db8::/64", "::1/128"],
            vec!["2001:db8::1", "::1"],
            (true, vec![]),
            (false, vec!["2001:db8::1", "::1"]),
        ),
        (
            "IPv6 zero CIDR",
            vec!["::/0"],
            vec!["2001:db8::1", "::1"],
            (true, vec![]),
            (true, vec!["2001:db8::1", "::1"]),
        ),
        (
            "IPv4 localhost exact",
            vec!["127.0.0.1/32"],
            vec!["10.20.30.51", "127.0.0.1"],
            (false, vec!["127.0.0.1"]),
            (true, vec![]),
        ),
        (
            "IPv4 localhost subnet",
            vec!["127.0.0.0/8"],
            vec!["127.0.1.1"],
            (false, vec!["127.0.1.1"]),
            (true, vec![]),
        ),
        (
            "IPv4 multiple",
            vec!["10.20.30.0/24", "100.200.201.0/24"],
            vec!["10.20.30.51", "100.200.201.1"],
            (false, vec!["10.20.30.51", "100.200.201.1"]),
            (true, vec![]),
        ),
        (
            "IPv4 multiple, no match",
            vec!["10.20.30.0/24", "100.200.201.0/24"],
            vec!["192.168.1.2", "127.0.0.1"],
            (false, vec![]),
            (true, vec![]),
        ),
        (
            "empty list, IPv4 addrs",
            vec![],
            vec!["192.168.1.2", "127.0.0.1"],
            (true, vec!["192.168.1.2", "127.0.0.1"]),
            (true, vec![]),
        ),
        (
            "empty list, IPv6 addrs",
            vec![],
            vec!["2001:db8::1", "::1"],
            (true, vec![]),
            (true, vec!["2001:db8::1", "::1"]),
        ),
        (
            "IPv4 redundant CIDRs",
            vec!["1.2.3.0/24", "0.0.0.0/0"],
            vec!["1.2.3.4"],
            (true, vec!["1.2.3.4"]),
            (true, vec![]),
        ),
        (
            "Dual-stack, redundant IPv4",
            vec!["0.0.0.0/0", "1.2.3.0/24", "2001:db8::1/128"],
            vec!["1.2.3.4", "2001:db8::1", "127.0.0.1", "::1"],
            (true, vec!["1.2.3.4", "127.0.0.1"]),
            (false, vec!["2001:db8::1"]),
        ),
        (
            "Dual-stack, redundant IPv6",
            vec!["::/0", "1.2.3.0/24", "2001:db8::1/128"],
            vec!["1.2.3.4", "2001:db8::1", "127.0.0.1", "::1"],
            (false, vec!["1.2.3.4"]),
            (true, vec!["2001:db8::1", "::1"]),
        ),
    ];
    for (name, cidrs, addrs, v4, v6) in cases {
        let nw = Fake(ips(&addrs));
        for (family, (match_all, want)) in
            [(IpFamily::IPv4, v4.clone()), (IpFamily::IPv6, v6.clone())]
        {
            let npa = NodePortAddresses::new(family, &strs(&cidrs));
            assert_eq!(npa.match_all(), match_all, "{name} {family:?} match_all");
            let got: BTreeSet<IpAddr> = npa.get_node_ips(&nw).unwrap().into_iter().collect();
            let want: BTreeSet<IpAddr> = ips(&want).into_iter().collect();
            assert_eq!(got, want, "{name} {family:?}");
        }
    }
}

#[test]
fn nodeport_addresses_contains_ipv4_loopback() {
    let tail = ["224.0.0.0/24", "192.168.0.0/16", "fd00:1:d::/64"];
    let cases: Vec<(&str, Vec<&str>, bool)> = vec![
        ("empty", vec![], true),
        ("all zeros ipv4", [&tail[..], &["0.0.0.0/0"]].concat(), true),
        ("all zeros ipv6", [&tail[..], &["::/0"]].concat(), false),
        (
            "ipv4 loopback",
            [&tail[..], &["127.0.0.0/8"]].concat(),
            true,
        ),
        ("ipv6 loopback", [&tail[..], &["::1/128"]].concat(), false),
        (
            "ipv4 loopback smaller range",
            [&tail[..], &["127.0.2.0/28"]].concat(),
            true,
        ),
        (
            "ipv4 loopback within larger range",
            [&tail[..], &["64.0.0.0/2"]].concat(),
            true,
        ),
        (
            "non loop loopback",
            [&["128.0.2.0/28"][..], &tail[..]].concat(),
            false,
        ),
    ];
    for (name, cidrs, want) in cases {
        let v4 = NodePortAddresses::new(IpFamily::IPv4, &strs(&cidrs));
        assert_eq!(v4.contains_ipv4_loopback(), want, "{name}");
        // always false for family=IPv6
        let v6 = NodePortAddresses::new(IpFamily::IPv6, &strs(&cidrs));
        assert!(!v6.contains_ipv4_loopback(), "{name} v6");
    }
}

#[test]
fn nodeport_addresses_display_and_sloppy_parse() {
    let npa = NodePortAddresses::new(
        IpFamily::IPv4,
        &strs(&["10.0.0.0/8", "fd00::/8", "192.168.0.0/16"]),
    );
    assert_eq!(npa.to_string(), "[10.0.0.0/8 192.168.0.0/16]");
    // leading zeros accepted (ParseCIDRSloppy)
    let npa = NodePortAddresses::new(IpFamily::IPv4, &strs(&["010.001.0.0/16"]));
    let nw = Fake(ips(&["10.1.2.3"]));
    assert_eq!(npa.get_node_ips(&nw).unwrap(), ips(&["10.1.2.3"]));
}
