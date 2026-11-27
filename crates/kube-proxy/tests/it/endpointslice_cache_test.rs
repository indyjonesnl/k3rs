//! Ports of `pkg/proxy/endpointslicecache_test.go` (TestEndpointsMapFromESC,
//! TestEndpointInfoByServicePort, TestEsDataChanged, cache keys).

mod endpointslice_cache {
    use kubernetes_rs_common::resources::EndpointSlice;
    use kubernetes_rs_kube_proxy::endpointslice_cache::*;
    use serde_json::json;

    fn slice(
        name: &str,
        svc: Option<&str>,
        ports: serde_json::Value,
        eps: serde_json::Value,
    ) -> EndpointSlice {
        let mut labels = serde_json::Map::new();
        if let Some(s) = svc {
            labels.insert(LABEL_SERVICE_NAME.into(), s.into());
        }
        serde_json::from_value(json!({
            "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
            "metadata": {"name": name, "namespace": "ns", "labels": labels},
            "addressType": "IPv4", "ports": ports, "endpoints": eps,
        }))
        .unwrap()
    }

    fn ports() -> serde_json::Value {
        json!([{"name": "http", "port": 80, "protocol": "TCP"}])
    }

    fn spn(port: &str) -> ServicePortName {
        ServicePortName {
            namespaced_name: NamespacedName {
                namespace: "ns".into(),
                name: "svc".into(),
            },
            port: port.into(),
            protocol: "TCP".into(),
        }
    }

    #[test]
    fn endpointslice_cache_keys_errors() {
        let mut c = EndpointSliceCache::new("n1");
        let e = c
            .update_pending(&slice("s", None, ports(), json!([])), false)
            .unwrap_err();
        assert_eq!(
            e,
            "no kubernetes.io/service-name label set on endpoint slice: s"
        );
        assert!(c
            .update_pending(&slice("", Some("svc"), ports(), json!([])), false)
            .is_err());
    }

    #[test]
    fn endpointslice_cache_endpoint_info_conditions_hints_and_locality() {
        let mut c = EndpointSliceCache::new("n1");
        let s = slice(
            "s1",
            Some("svc"),
            ports(),
            json!([
                {"addresses": ["10.0.0.1"], "nodeName": "n1"},
                {"addresses": ["10.0.0.2"], "nodeName": "n2",
                 "conditions": {"ready": false, "serving": true, "terminating": true},
                 "hints": {"forZones": [{"name": "z1"}], "forNodes": [{"name": "n1"}]}},
                {"addresses": ["fd00::1"], "conditions": {"ready": false, "serving": false}},
                {"addresses": []},
            ]),
        );
        assert!(c.update_pending(&s, false).unwrap());
        let changes = c.checkout_changes();
        let ch = &changes[&NamespacedName {
            namespace: "ns".into(),
            name: "svc".into(),
        }];
        assert!(ch.previous.is_empty());
        let eps = &ch.current[&spn("http")];
        // sorted by endpoint string; the empty-address endpoint is ignored
        let strs: Vec<String> = eps.iter().map(|e| e.endpoint()).collect();
        assert_eq!(strs, ["10.0.0.1:80", "10.0.0.2:80", "[fd00::1]:80"]);
        let (a, b, v6) = (&eps[0], &eps[1], &eps[2]);
        assert!(a.is_local && a.ready && a.serving && !a.terminating);
        assert!(!b.is_local && !b.ready && b.serving && b.terminating);
        assert_eq!(b.zone_hints.iter().collect::<Vec<_>>(), ["z1"]);
        assert_eq!(b.node_hints.iter().collect::<Vec<_>>(), ["n1"]);
        assert!(!v6.ready && !v6.serving);
        // node hints are gated by PreferSameTrafficDistribution
        let mut off = EndpointSliceCache::new("n1").with_prefer_same_traffic_distribution(false);
        off.update_pending(&s, false).unwrap();
        let ch = off.checkout_changes();
        let eps = &ch.values().next().unwrap().current[&spn("http")];
        assert!(eps[1].node_hints.is_empty() && !eps[1].zone_hints.is_empty());
    }

    #[test]
    fn endpointslice_cache_ignores_invalid_ports_and_dedupes_preferring_local() {
        let mut c = EndpointSliceCache::new("n1");
        let s1 = slice(
            "s1",
            Some("svc"),
            json!([{"name": "http", "port": 80, "protocol": "TCP"}, {"name": "zero", "port": 0, "protocol": "TCP"}, {"port": 81, "protocol": "TCP"}]),
            json!([{"addresses": ["10.0.0.1"], "nodeName": "other"}]),
        );
        let s2 = slice(
            "s2",
            Some("svc"),
            ports(),
            json!([{"addresses": ["10.0.0.1"], "nodeName": "n1"}]),
        );
        c.update_pending(&s1, false).unwrap();
        c.update_pending(&s2, false).unwrap();
        let ch = c.checkout_changes();
        let cur = &ch.values().next().unwrap().current;
        assert_eq!(cur.len(), 1);
        let eps = &cur[&spn("http")];
        assert_eq!(eps.len(), 1);
        assert!(eps[0].is_local, "a local duplicate wins");
    }

    #[test]
    fn endpointslice_cache_es_data_changed_and_checkout_lifecycle() {
        let mut c = EndpointSliceCache::new("");
        let s = slice(
            "s1",
            Some("svc"),
            ports(),
            json!([{"addresses": ["10.0.0.1"]}]),
        );
        // removal of an unknown slice: no change
        assert!(!c.update_pending(&s, true).unwrap());
        assert!(c.update_pending(&s, false).unwrap());
        // same pending data: no change
        assert!(!c.update_pending(&s, false).unwrap());
        assert_eq!(c.checkout_changes().len(), 1);
        // same applied data: no change; nothing pending to check out
        assert!(!c.update_pending(&s, false).unwrap());
        assert!(c.checkout_changes().is_empty());
        // a changed slice is a change, with previous/current populated
        let s2 = slice(
            "s1",
            Some("svc"),
            ports(),
            json!([{"addresses": ["10.0.0.9"]}]),
        );
        assert!(c.update_pending(&s2, false).unwrap());
        let ch = c.checkout_changes();
        let ch = ch.values().next().unwrap();
        assert_eq!(ch.previous[&spn("http")][0].ip, "10.0.0.1");
        assert_eq!(ch.current[&spn("http")][0].ip, "10.0.0.9");
        // removing the last slice empties current and drops the service tracker
        assert!(c.update_pending(&s2, true).unwrap());
        let ch = c.checkout_changes();
        let ch = ch.values().next().unwrap();
        assert!(ch.current.is_empty() && !ch.previous.is_empty());
        assert!(c.checkout_changes().is_empty());
    }

    #[test]
    fn endpointslice_cache_service_port_name_display() {
        assert_eq!(spn("http").to_string(), "ns/svc:http");
        assert_eq!(spn("").to_string(), "ns/svc");
    }
}
