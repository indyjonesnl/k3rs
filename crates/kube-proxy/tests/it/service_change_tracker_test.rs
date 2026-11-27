//! Ports of `pkg/proxy/servicechangetracker_test.go`
//! (TestServiceToServiceMap, TestServiceMapUpdateHeadless,
//! TestUpdateServiceTypeExternalName, TestBuildServiceMapAddRemove,
//! TestBuildServiceMapServiceUpdate).

mod service_change_tracker {
    use kubernetes_rs_common::resources::Service;
    use kubernetes_rs_kube_proxy::endpointslice_cache::NamespacedName;
    use kubernetes_rs_kube_proxy::iptables::IpFamily;
    use kubernetes_rs_kube_proxy::service_map::*;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    fn nsn(ns: &str, name: &str) -> NamespacedName {
        NamespacedName {
            namespace: ns.into(),
            name: name.into(),
        }
    }

    fn svc(ns: &str, name: &str, spec: Value, status: Value) -> Service {
        serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": ns},
            "spec": spec, "status": status,
        }))
        .unwrap()
    }

    fn port(name: &str, proto: &str, port: u16, node_port: u16) -> Value {
        json!({"name": name, "protocol": proto, "port": port, "targetPort": 1, "nodePort": node_port})
    }

    fn tracker(f: IpFamily) -> ServiceChangeTracker {
        ServiceChangeTracker::new(f, None)
    }

    #[test]
    fn service_to_service_map_fields() {
        let s = svc(
            "ns",
            "s",
            json!({"type":"LoadBalancer","clusterIP":"172.16.55.4","clusterIPs":["172.16.55.4"],
                "ipFamilies":["IPv4"],
                "externalIPs":["1.2.3.4","fd00::1","bogus"],
                "loadBalancerSourceRanges":[" 10.1.2.0/28","fd00::/64"],
                "sessionAffinity":"ClientIP",
                "sessionAffinityConfig":{"clientIP":{"timeoutSeconds":99}},
                "externalTrafficPolicy":"Local","internalTrafficPolicy":"Local",
                "healthCheckNodePort":345,
                "ports":[port("p","UDP",1234,3001)]}),
            json!({"loadBalancer":{"ingress":[
                {"ip":"10.1.2.3"},{"ip":"10.1.2.4","ipMode":"Proxy"},{"ip":"fd00::2"}]}}),
        );
        let mut t = tracker(IpFamily::V4);
        assert!(t.update(None, Some(&s)));
        let mut m = ServicePortMap::new();
        t.apply(&mut m);
        assert_eq!(m.len(), 1);
        let i = m.values().next().unwrap();
        assert_eq!(i.string(), "172.16.55.4:1234/UDP");
        assert_eq!(i.node_port, 3001);
        assert_eq!(i.sticky_max_age_seconds, 99);
        assert_eq!(i.session_affinity_type, "ClientIP");
        assert_eq!(
            i.external_ips,
            vec!["1.2.3.4".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(
            i.load_balancer_vips,
            vec!["10.1.2.3".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(i.load_balancer_source_ranges.len(), 1);
        assert_eq!(i.load_balancer_source_ranges[0].prefix, 28);
        assert_eq!(i.health_check_node_port, 345);
        assert!(i.external_policy_local && i.internal_policy_local);
        assert!(
            i.externally_accessible() && i.uses_cluster_endpoints() && i.uses_local_endpoints()
        );
    }

    #[test]
    fn service_change_tracker_zero_cidr_means_allow_any() {
        let s = svc(
            "ns",
            "s",
            json!({"type":"LoadBalancer","clusterIP":"10.0.0.1",
                "loadBalancerSourceRanges":["10.0.0.0/8","0.0.0.0/0"],
                "ports":[port("p","TCP",80,30000)]}),
            json!({}),
        );
        let mut t = tracker(IpFamily::V4);
        t.update(None, Some(&s));
        let mut m = ServicePortMap::new();
        t.apply(&mut m);
        assert!(m
            .values()
            .next()
            .unwrap()
            .load_balancer_source_ranges
            .is_empty());
    }

    #[test]
    fn service_change_tracker_ipv6_family_selection() {
        let s = svc(
            "ns",
            "dual",
            json!({"type":"ClusterIP","clusterIP":"10.0.0.1","clusterIPs":["10.0.0.1","fd00::1"],
                "ipFamilies":["IPv4","IPv6"],"ports":[port("p","TCP",80,0)]}),
            json!({}),
        );
        let mut t4 = tracker(IpFamily::V4);
        let mut t6 = tracker(IpFamily::V6);
        t4.update(None, Some(&s));
        t6.update(None, Some(&s));
        let (mut m4, mut m6) = (ServicePortMap::new(), ServicePortMap::new());
        t4.apply(&mut m4);
        t6.apply(&mut m6);
        assert_eq!(
            m4.values().next().unwrap().cluster_ip.to_string(),
            "10.0.0.1"
        );
        assert_eq!(
            m6.values().next().unwrap().cluster_ip.to_string(),
            "fd00::1"
        );
    }

    #[test]
    fn service_change_tracker_headless_and_external_name_skipped() {
        let headless = svc(
            "ns",
            "h",
            json!({"type":"ClusterIP","clusterIP":"None","ports":[port("p","TCP",80,0)]}),
            json!({}),
        );
        let ext = svc(
            "ns",
            "e",
            json!({"type":"ExternalName","clusterIP":"1.2.3.4","externalName":"x.example.com",
                "ports":[port("p","TCP",80,0)]}),
            json!({}),
        );
        let mut t = tracker(IpFamily::V4);
        assert!(!t.update(None, Some(&headless)));
        assert!(!t.update(None, Some(&ext)));
        let mut m = ServicePortMap::new();
        assert!(t.apply(&mut m).updated_services.is_empty());
        assert!(m.is_empty());
    }

    fn svc_v1() -> Service {
        svc(
            "ns1",
            "svc1",
            json!({"type":"ClusterIP","clusterIP":"172.16.55.4",
                "ports":[port("p1","UDP",1234,0),port("p2","TCP",1235,0)]}),
            json!({}),
        )
    }

    fn svc_v2() -> Service {
        svc(
            "ns1",
            "svc1",
            json!({"type":"LoadBalancer","clusterIP":"172.16.55.4","loadBalancerIP":"5.6.7.8",
                "externalTrafficPolicy":"Local","healthCheckNodePort":345,
                "ports":[port("p1","UDP",1234,7002),port("p2","TCP",1235,7003)]}),
            json!({"loadBalancer":{"ingress":[{"ip":"10.1.2.3"}]}}),
        )
    }

    #[test]
    fn service_change_tracker_service_update_sequence() {
        let (v1, v2) = (svc_v1(), svc_v2());
        let mut t = tracker(IpFamily::V4);
        let mut m = ServicePortMap::new();

        t.update(None, Some(&v1));
        let r = t.apply(&mut m);
        assert_eq!((m.len(), r.updated_services.len()), (2, 1));
        assert!(health_check_node_ports(&m).is_empty());

        t.update(Some(&v1), Some(&v2));
        let r = t.apply(&mut m);
        assert_eq!((m.len(), r.updated_services.len()), (2, 1));
        assert_eq!(health_check_node_ports(&m).len(), 1);

        // No change: nothing pending.
        assert!(!t.update(Some(&v2), Some(&v2)));
        let r = t.apply(&mut m);
        assert_eq!((m.len(), r.updated_services.len()), (2, 0));
        assert_eq!(health_check_node_ports(&m).len(), 1);

        t.update(Some(&v2), Some(&v1));
        let r = t.apply(&mut m);
        assert_eq!((m.len(), r.updated_services.len()), (2, 1));
        assert!(health_check_node_ports(&m).is_empty());
    }

    #[test]
    fn service_change_tracker_add_remove() {
        let services = vec![
            svc(
                "ns2",
                "cluster-ip",
                json!({"type":"ClusterIP","clusterIP":"172.16.55.4",
                "ports":[port("port1","UDP",1234,0),port("port2","UDP",1235,0)]}),
                json!({}),
            ),
            svc(
                "ns2",
                "node-port",
                json!({"type":"NodePort","clusterIP":"172.16.55.10",
                "ports":[port("port1","UDP",345,0),port("port2","TCP",344,0)]}),
                json!({}),
            ),
            svc(
                "ns1",
                "load-balancer",
                json!({"type":"LoadBalancer","clusterIP":"172.16.55.11",
                "ports":[port("foobar","UDP",8675,7000),port("baz","UDP",8676,7001)]}),
                json!({"loadBalancer":{"ingress":[{"ip":"10.1.2.4"}]}}),
            ),
            svc(
                "ns1",
                "only-local-load-balancer",
                json!({"type":"LoadBalancer",
                "clusterIP":"172.16.55.12","externalTrafficPolicy":"Local","healthCheckNodePort":345,
                "ports":[port("foobar2","UDP",8677,7002),port("baz","UDP",8678,7003)]}),
                json!({"loadBalancer":{"ingress":[{"ip":"10.1.2.3"}]}}),
            ),
        ];
        let mut t = tracker(IpFamily::V4);
        let mut m = ServicePortMap::new();
        for s in &services {
            t.update(None, Some(s));
        }
        let r = t.apply(&mut m);
        assert_eq!(m.len(), 8);
        assert_eq!(r.updated_services.len(), 4);
        for s in &services {
            assert!(r.updated_services.contains(&nsn(
                s.metadata.namespace.as_deref().unwrap(),
                &s.metadata.name
            )));
        }
        let hc = health_check_node_ports(&m);
        assert_eq!(hc.len(), 1);
        assert_eq!(hc[&nsn("ns1", "only-local-load-balancer")], 345);

        // Drop port1 from services[0], delete the rest.
        let one = svc(
            "ns2",
            "cluster-ip",
            json!({"type":"ClusterIP","clusterIP":"172.16.55.4",
            "ports":[port("p2","UDP",1235,0)]}),
            json!({}),
        );
        t.update(Some(&services[0]), Some(&one));
        for s in &services[1..] {
            t.update(Some(s), None);
        }
        let r = t.apply(&mut m);
        assert_eq!(m.len(), 1);
        assert_eq!(r.updated_services.len(), 4);
        assert!(health_check_node_ports(&m).is_empty());
    }

    #[test]
    fn service_change_tracker_process_change_callback() {
        let seen: Arc<Mutex<Vec<(usize, usize)>>> = Default::default();
        let s2 = seen.clone();
        let mut t = ServiceChangeTracker::new(
            IpFamily::V4,
            Some(Box::new(move |p, c| {
                s2.lock().unwrap().push((p.len(), c.len()))
            })),
        );
        let mut m = ServicePortMap::new();
        t.update(None, Some(&svc_v1()));
        t.apply(&mut m);
        t.update(Some(&svc_v1()), None);
        t.apply(&mut m);
        assert_eq!(*seen.lock().unwrap(), vec![(0, 2), (2, 0)]);
        assert!(m.is_empty());
    }

    #[test]
    fn service_change_tracker_sloppy_parsing() {
        assert_eq!(
            parse_ip_sloppy("010.001.2.3").unwrap().to_string(),
            "10.1.2.3"
        );
        assert!(parse_ip_sloppy("1.2.3").is_none());
        assert!(parse_ip_sloppy("256.1.1.1").is_none());
        let c = parse_cidr_sloppy("10.1.2.3/24").unwrap();
        assert_eq!((c.addr.to_string(), c.prefix), ("10.1.2.0".to_string(), 24));
        assert!(parse_cidr_sloppy("10.0.0.0/33").is_none());
    }
}
