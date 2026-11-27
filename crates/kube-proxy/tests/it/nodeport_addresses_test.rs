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

mod iptables_wiring {
    use super::*;
    use kubernetes_rs_kube_proxy::iptables::IptablesManager;
    use kubernetes_rs_kube_proxy::nodeport_addresses::{
        effective_localhost_nodeports, nodeport_destinations, parse_fib_trie_local, parse_if_inet6,
    };
    use std::sync::Arc;

    fn dst(
        cidrs: &[&str],
        family: IpFamily,
        localhost: bool,
        addrs: &[&str],
    ) -> (Vec<Vec<String>>, Vec<String>) {
        let npa = NodePortAddresses::new(family, &strs(cidrs));
        let mut errs = vec![];
        let r = nodeport_destinations(&npa, family, localhost, &Fake(ips(addrs)), &mut errs);
        (r, errs)
    }

    fn v(x: &[&str]) -> Vec<String> {
        x.iter().map(|s| s.to_string()).collect()
    }

    /// proxier.go:1389-1402: match-all tail-calls on `--dst-type LOCAL`,
    /// excluding localhost when it is unsupported.
    #[test]
    fn nodeport_addresses_match_all_destinations() {
        let (r, _) = dst(&[], IpFamily::IPv4, true, &[]);
        assert_eq!(r, vec![v(&["-m", "addrtype", "--dst-type", "LOCAL"])]);
        let (r, _) = dst(&[], IpFamily::IPv4, false, &[]);
        assert_eq!(
            r,
            vec![v(&[
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "!",
                "-d",
                "127.0.0.0/8"
            ])]
        );
        let (r, _) = dst(&[], IpFamily::IPv6, true, &[]);
        assert_eq!(
            r,
            vec![v(&[
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "!",
                "-d",
                "::1/128"
            ])]
        );
    }

    /// proxier.go:1403-1427: one `-d ip` rule per node IP, loopback skipped
    /// (with an error) when localhost NodePorts are unsupported.
    #[test]
    fn nodeport_addresses_per_ip_destinations() {
        let (r, e) = dst(
            &["10.0.0.0/8", "127.0.0.0/8"],
            IpFamily::IPv4,
            true,
            &["10.1.1.1", "127.0.0.1", "192.168.0.5"],
        );
        let mut got: Vec<_> = r.iter().map(|x| x[1].clone()).collect();
        got.sort();
        assert_eq!(got, vec!["10.1.1.1", "127.0.0.1"]);
        assert!(e.is_empty());

        let (r, e) = dst(
            &["10.0.0.0/8", "127.0.0.0/8"],
            IpFamily::IPv4,
            false,
            &["10.1.1.1", "127.0.0.1"],
        );
        assert_eq!(r, vec![v(&["-d", "10.1.1.1"])]);
        assert_eq!(e.len(), 1);
        assert!(e[0].contains("--iptables-localhost-nodeports=false"));

        let (r, e) = dst(
            &["::1/128", "2001:db8::/64"],
            IpFamily::IPv6,
            true,
            &["::1", "2001:db8::1"],
        );
        assert_eq!(r, vec![v(&["-d", "2001:db8::1"])]);
        assert!(e[0].contains("not supported on IPv6"));
    }

    /// proxier.go:236-238: localhostNodePorts is forced off without a
    /// loopback CIDR.
    #[test]
    fn nodeport_addresses_localhost_nodeports_gating() {
        let all = NodePortAddresses::new(IpFamily::IPv4, &[]);
        assert!(effective_localhost_nodeports(&all, true));
        assert!(!effective_localhost_nodeports(&all, false));
        let narrow = NodePortAddresses::new(IpFamily::IPv4, &strs(&["10.0.0.0/8"]));
        assert!(!effective_localhost_nodeports(&narrow, true));

        let m = IptablesManager::for_testing(false)
            .with_nodeport_addresses(&strs(&["10.0.0.0/8"]), true)
            .with_network_interfacer(Arc::new(Fake(ips(&["10.1.2.3", "127.0.0.1"]))));
        assert!(!m.localhost_nodeports());
        assert_eq!(m.nodeport_jump_destinations(), vec![v(&["-d", "10.1.2.3"])]);
        let m = IptablesManager::for_testing(false);
        assert!(m.localhost_nodeports());
    }

    #[test]
    fn nodeport_addresses_proc_parsers() {
        let trie = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n     +-- 10.0.0.0/8 2 0 2\n        |-- 10.1.2.3\n           /32 host LOCAL\n        |-- 10.255.255.255\n           /32 link BROADCAST\n     +-- 127.0.0.0/8 2 0 2\n        |-- 127.0.0.1\n           /32 host LOCAL\n";
        assert_eq!(parse_fib_trie_local(trie), ips(&["10.1.2.3", "127.0.0.1"]));
        let v6 = "00000000000000000000000000000001 01 80 10 80       lo\n20010db8000000000000000000000001 02 40 00 00     eth0\n";
        assert_eq!(parse_if_inet6(v6), ips(&["::1", "2001:db8::1"]));
    }
}
