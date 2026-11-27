//! Ports of `pkg/proxy/util/localdetector_test.go`.

use kubernetes_rs_kube_proxy::localdetector::*;

fn eq(got: &[String], want: &[&str]) {
    assert_eq!(got, want);
}

#[test]
fn localdetector_no_op() {
    let d = new_no_op_local_detector();
    assert!(!d.is_implemented());
    assert!(d.if_local().is_empty() && d.if_not_local().is_empty());
    assert!(d.if_local_nft().is_empty() && d.if_not_local_nft().is_empty());
}

#[test]
fn localdetector_by_cidr() {
    for (cidr, fam) in [("10.0.0.0/14", "ip"), ("2002:0:0:1234::/64", "ip6")] {
        let d = new_detect_local_by_cidr(cidr);
        assert!(d.is_implemented());
        eq(d.if_local(), &["-s", cidr]);
        eq(d.if_not_local(), &["!", "-s", cidr]);
        eq(d.if_local_nft(), &[fam, "saddr", cidr]);
        eq(d.if_not_local_nft(), &[fam, "saddr", "!=", cidr]);
    }
}

#[test]
fn localdetector_by_bridge_interface() {
    for name in ["eth0", "cbr0", "br-dummy"] {
        let d = new_detect_local_by_bridge_interface(name);
        assert!(d.is_implemented());
        eq(d.if_local(), &["-i", name]);
        eq(d.if_not_local(), &["!", "-i", name]);
        eq(d.if_local_nft(), &["iifname", name]);
        eq(d.if_not_local_nft(), &["iifname", "!=", name]);
    }
}

#[test]
fn localdetector_by_interface_name_prefix() {
    for p in ["eth", "cbr", "br-dummy"] {
        let d = new_detect_local_by_interface_name_prefix(p);
        assert!(d.is_implemented());
        eq(d.if_local(), &["-i", &format!("{p}+")]);
        eq(d.if_not_local(), &["!", "-i", &format!("{p}+")]);
        eq(d.if_local_nft(), &["iifname", &format!("{p}*")]);
        eq(d.if_not_local_nft(), &["iifname", "!=", &format!("{p}*")]);
    }
}
