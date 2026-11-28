//! kube-proxy-P1-08: `filter`-table REJECT rules for Services without endpoints.
//!
//! Ported from `syncProxyRules` (pkg/proxy/iptables/proxier.go:996-1160) and
//! `TestNoEndpointsReject` (proxier_test.go): a service port with no endpoints
//! gets `-j REJECT` in `KUBE-SERVICES` (ClusterIP) and `KUBE-EXTERNAL-SERVICES`
//! (externalIPs, load-balancer ingress, NodePort); one with endpoints gets none.
use kubernetes_rs_common::resources::Service;
use kubernetes_rs_kube_proxy::iptables::IptablesManager;
use std::collections::HashMap;

fn svc(extra_spec: serde_json::Value, status: serde_json::Value) -> Service {
    let mut spec = serde_json::json!({
        "clusterIP": "172.30.0.41",
        "ports": [{"name": "p80", "port": 80, "protocol": "TCP", "nodePort": 3001}],
        "type": "NodePort"
    });
    for (k, v) in extra_spec.as_object().unwrap() {
        spec[k] = v.clone();
    }
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "svc1", "namespace": "ns1"},
        "spec": spec,
        "status": status
    }))
    .unwrap()
}

type Map = HashMap<String, Vec<(String, Option<String>, u16)>>;

#[test]
fn proxy_reject_no_endpoints_all_ips() {
    let s = svc(
        serde_json::json!({"externalIPs": ["192.168.99.11"]}),
        serde_json::json!({"loadBalancer": {"ingress": [{"ip": "1.2.3.4"}]}}),
    );
    let rules = IptablesManager::for_testing(true).build_filter_rules(&[s], &Map::new());
    let c = r#"-m comment --comment "ns1/svc1:p80 has no endpoints""#;
    assert!(rules.starts_with("*filter\n"), "{rules}");
    assert!(
        rules.contains(":KUBERNETES_RS-SERVICES - [0:0]\n"),
        "{rules}"
    );
    assert!(
        rules.contains(":KUBERNETES_RS-EXTERNAL-SERVICES - [0:0]\n"),
        "{rules}"
    );
    assert!(rules.ends_with("COMMIT\n"), "{rules}");
    for line in [
        format!("-A KUBERNETES_RS-SERVICES {c} -m tcp -p tcp -d 172.30.0.41 --dport 80 -j REJECT"),
        format!("-A KUBERNETES_RS-EXTERNAL-SERVICES {c} -m tcp -p tcp -d 192.168.99.11 --dport 80 -j REJECT"),
        format!("-A KUBERNETES_RS-EXTERNAL-SERVICES {c} -m tcp -p tcp -d 1.2.3.4 --dport 80 -j REJECT"),
        format!("-A KUBERNETES_RS-EXTERNAL-SERVICES {c} -m addrtype --dst-type LOCAL -m tcp -p tcp --dport 3001 -j REJECT"),
    ] {
        assert!(rules.contains(&format!("{line}\n")), "missing {line}\n{rules}");
    }
}

#[test]
fn proxy_reject_with_endpoints_has_no_reject_rules() {
    let s = svc(
        serde_json::json!({"externalIPs": ["192.168.99.11"]}),
        serde_json::json!({}),
    );
    let mut map = Map::new();
    map.insert(
        "ns1/svc1".into(),
        vec![("10.180.0.1".into(), Some("p80".into()), 80)],
    );
    let rules = IptablesManager::for_testing(true).build_filter_rules(&[s], &map);
    assert!(!rules.contains("REJECT"), "{rules}");
}

#[test]
fn proxy_reject_skips_other_family_and_unnamed_port_comment() {
    // An IPv6 external IP on an IPv4 proxier is not programmed; an unnamed
    // port's comment is `ns/name` (servicePortName.String()).
    let s: Service = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "svc1", "namespace": "ns1"},
        "spec": {"clusterIP": "172.30.0.41", "externalIPs": ["fd00::1", "192.168.99.11"],
                 "ports": [{"port": 80, "protocol": "UDP"}]}
    }))
    .unwrap();
    let rules = IptablesManager::for_testing(true).build_filter_rules(&[s], &Map::new());
    assert!(!rules.contains("fd00::1"), "{rules}");
    assert!(rules.contains("192.168.99.11"), "{rules}");
    assert!(
        rules.contains(r#"--comment "ns1/svc1 has no endpoints" -m udp -p udp"#),
        "{rules}"
    );
}
