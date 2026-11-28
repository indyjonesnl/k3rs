//! Ports of `pkg/proxy/apis/config/v1alpha1` defaults and
//! `pkg/proxy/apis/config/validation/validation_test.go` (release-1.35).

use kubernetes_rs_kube_proxy::config::*;

fn defaulted(mode: &str) -> KubeProxyConfiguration {
    let mut c = KubeProxyConfiguration {
        mode: mode.to_string(),
        ..Default::default()
    };
    set_defaults(&mut c);
    c
}

fn errs(c: &KubeProxyConfiguration) -> Vec<String> {
    validate(&convert_to_internal(c), false)
        .iter()
        .map(|e| format!("{}: {}", e.field, e.detail))
        .collect()
}

#[test]
fn kubeproxy_config_defaults_ipv4() {
    let c = defaulted("");
    assert_eq!(c.bind_address, "0.0.0.0");
    assert_eq!(c.healthz_bind_address, "0.0.0.0:10256");
    assert_eq!(c.metrics_bind_address, "127.0.0.1:10249");
    assert_eq!(c.oom_score_adj, Some(-999));
    assert_eq!(c.iptables.masquerade_bit, Some(14));
    assert_eq!(c.iptables.localhost_node_ports, Some(true));
    assert_eq!(c.iptables.sync_period, Duration::secs(30));
    assert_eq!(c.iptables.min_sync_period, Duration::secs(1));
    assert_eq!(c.conntrack.max_per_core, Some(32768));
    assert_eq!(c.conntrack.min, Some(131072));
    assert_eq!(
        c.conntrack.tcp_close_wait_timeout,
        Some(Duration::secs(3600))
    );
    assert_eq!(c.config_sync_period, Duration::secs(900));
    assert_eq!(c.client_connection.burst, 10);
    assert_eq!(c.client_connection.qps, 5.0);
}

#[test]
fn kubeproxy_config_defaults_ipv6_bind() {
    let mut c = KubeProxyConfiguration {
        bind_address: "::".into(),
        ..Default::default()
    };
    set_defaults(&mut c);
    assert_eq!(c.healthz_bind_address, "[::]:10256");
    assert_eq!(c.metrics_bind_address, "[::1]:10249");
}

#[test]
fn kubeproxy_config_defaults_append_port() {
    let mut c = KubeProxyConfiguration {
        healthz_bind_address: "1.2.3.4".into(),
        metrics_bind_address: "5.6.7.8".into(),
        ..Default::default()
    };
    set_defaults(&mut c);
    assert_eq!(c.healthz_bind_address, "1.2.3.4:10256");
    assert_eq!(c.metrics_bind_address, "5.6.7.8:10249");
}

#[test]
fn kubeproxy_config_default_validates() {
    assert_eq!(errs(&defaulted("")), Vec::<String>::new());
    assert_eq!(errs(&defaulted("nftables")), Vec::<String>::new());
    assert_eq!(errs(&defaulted("ipvs")), Vec::<String>::new());
}

#[test]
fn kubeproxy_config_duration_roundtrip() {
    let c = defaulted("");
    let y = serde_json::to_value(&c).unwrap();
    assert_eq!(y["iptables"]["syncPeriod"], "30s");
    assert_eq!(y["configSyncPeriod"], "15m0s");
    let back: KubeProxyConfiguration = serde_json::from_value(y).unwrap();
    assert_eq!(back, c);
}

#[test]
fn kubeproxy_config_sync_period_from_mode_section() {
    let mut c = defaulted("ipvs");
    c.ipvs.sync_period = Duration::secs(7);
    assert_eq!(convert_to_internal(&c).sync_period, Duration::secs(7));
    c.mode = "nftables".into();
    c.nftables.sync_period = Duration::secs(9);
    assert_eq!(convert_to_internal(&c).sync_period, Duration::secs(9));
}

#[test]
fn kubeproxy_config_cluster_cidr_split() {
    let mut c = defaulted("");
    c.cluster_cidr = "10.0.0.0/8,fd00::/8".into();
    assert_eq!(
        convert_to_internal(&c).detect_local.cluster_cidrs,
        vec!["10.0.0.0/8", "fd00::/8"]
    );
}

#[test]
fn kubeproxy_config_masquerade_bit_range() {
    let mut c = defaulted("");
    c.iptables.masquerade_bit = Some(32);
    assert_eq!(
        errs(&c),
        vec!["KubeProxyConfiguration.KubeProxyIPTablesConfiguration.MasqueradeBit: must be within the range [0, 31]"]
    );
}

#[test]
fn kubeproxy_config_bad_mode() {
    let c = defaulted("userspace");
    let e = errs(&c);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(
        e[0].contains("must be iptables, ipvs, nftables or blank"),
        "{e:?}"
    );
}

#[test]
fn kubeproxy_config_sync_periods() {
    let mut c = defaulted("");
    c.iptables.min_sync_period = Duration::secs(60);
    let e = errs(&c);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].starts_with("KubeProxyConfiguration.SyncPeriod: must be greater than or equal to KubeProxyConfiguration.MinSyncPeriod"));
    let mut c = defaulted("");
    c.config_sync_period = Duration(0);
    assert_eq!(
        errs(&c),
        vec!["KubeProxyConfiguration.ConfigSyncPeriod: must be greater than 0"]
    );
}

#[test]
fn kubeproxy_config_bind_addresses() {
    let mut c = defaulted("");
    c.bind_address = "bogus".into();
    c.healthz_bind_address = "1.2.3.4".into();
    c.metrics_bind_address = "1.2.3.4:0".into();
    let mut c2 = c.clone();
    // Validate sees the raw internal values (no defaulting applied here).
    let e = errs(&c);
    assert!(
        e.iter()
            .any(|m| m.starts_with("KubeProxyConfiguration.BindAddress")),
        "{e:?}"
    );
    assert!(
        e.iter().any(|m| m.contains("must be a valid port")),
        "{e:?}"
    );
    c2.healthz_bind_address = "1.2.3.4".into();
    assert!(errs(&c2)
        .iter()
        .any(|m| m.contains("HealthzBindAddress: must be IP:port")));
}

#[test]
fn kubeproxy_config_node_port_addresses() {
    let mut c = defaulted("");
    c.node_port_addresses = vec!["primary".into()];
    assert!(errs(&c).is_empty());
    c.node_port_addresses = vec!["10.0.0.0/8".into(), "primary".into()];
    assert_eq!(errs(&c).len(), 1);
    c.node_port_addresses = vec!["nope".into()];
    assert_eq!(
        errs(&c),
        vec!["KubeProxyConfiguration.NodePortAddresses[0]: must be a valid CIDR"]
    );
}

#[test]
fn kubeproxy_config_detect_local() {
    let mut c = defaulted("");
    c.detect_local_mode = "BridgeInterface".into();
    assert_eq!(errs(&c).len(), 1);
    c.detect_local.bridge_interface = "cbr0".into();
    assert!(errs(&c).is_empty());
    c.detect_local_mode = "ClusterCIDR".into();
    c.cluster_cidr = "10.0.0.0/8,11.0.0.0/8".into();
    assert_eq!(errs(&c).len(), 1);
    c.cluster_cidr = "10.0.0.0/8,fd00::/8".into();
    assert!(errs(&c).is_empty());
    c.detect_local_mode = "Bogus".into();
    assert_eq!(errs(&c).len(), 1);
}

#[test]
fn kubeproxy_config_oom_and_conntrack() {
    let mut c = defaulted("");
    c.oom_score_adj = Some(1001);
    c.conntrack.min = Some(-1);
    let e = errs(&c);
    assert_eq!(e.len(), 2, "{e:?}");
}

#[test]
fn kubeproxy_config_ipvs_exclude_cidrs() {
    let mut c = defaulted("ipvs");
    c.ipvs.exclude_cidrs = vec!["bad".into()];
    c.ipvs.tcp_timeout = Duration(-1);
    assert_eq!(errs(&c).len(), 2);
}

#[test]
fn kubeproxy_config_windows_mode() {
    let c = defaulted("kernelspace");
    assert!(validate(&convert_to_internal(&c), true).is_empty());
    assert_eq!(validate(&convert_to_internal(&c), false).len(), 1);
}

#[test]
fn kubeproxy_config_logging() {
    let mut c = defaulted("");
    c.logging.format = "xml".into();
    assert_eq!(
        errs(&c),
        vec!["KubeProxyConfiguration.logging.format: Unsupported log format"]
    );
}
