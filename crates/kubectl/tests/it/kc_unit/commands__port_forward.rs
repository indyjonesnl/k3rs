//! Unit tests moved from `src/commands/port_forward.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use anyhow::Result;
    pub use kubernetes_rs_client::http::ApiClient;
    pub use kubernetes_rs_kubectl::websocket;
}

mod tests {
    use super::__parent::*;
    use kubernetes_rs_kubectl::commands::port_forward::*;

    #[test]
    fn test_parse_port_mapping_local_remote() {
        let (local, remote) = parse_port_mapping("8080:80").unwrap();
        assert_eq!(local, 8080);
        assert_eq!(remote, 80);
    }

    #[test]
    fn test_parse_port_mapping_same_port() {
        let (local, remote) = parse_port_mapping("3000").unwrap();
        assert_eq!(local, 3000);
        assert_eq!(remote, 3000);
    }

    #[test]
    fn test_parse_port_mapping_invalid() {
        let result = parse_port_mapping("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_mapping_invalid_local() {
        let result = parse_port_mapping("abc:80");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_mapping_invalid_remote() {
        let result = parse_port_mapping("80:abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_mapping_high_port() {
        let (local, remote) = parse_port_mapping("65535:443").unwrap();
        assert_eq!(local, 65535);
        assert_eq!(remote, 443);
    }

    #[test]
    fn test_parse_port_mapping_overflow_fails() {
        // Port number exceeding u16 max should fail
        let result = parse_port_mapping("70000");
        assert!(result.is_err());
    }

    // ---- ported from portforward_test.go (release-1.35) ----

    use kubernetes_rs_common::resources::{Pod, Service};
    use serde_json::{json, Value};

    fn svc(cluster_ip: Option<&str>, ports: Value) -> Service {
        let mut spec = json!({ "ports": ports });
        if let Some(ip) = cluster_ip {
            spec["clusterIP"] = json!(ip);
        }
        serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "svc"}, "spec": spec
        }))
        .unwrap()
    }

    fn pod(ports: Value) -> Pod {
        serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod"},
            "spec": {"containers": [{"name": "c", "image": "i", "ports": ports}]}
        }))
        .unwrap()
    }

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn test_port_forward_translate_service_port_to_target_port() {
        let http_pod = pod(json!([{"name": "http", "containerPort": 8080}]));
        let named_pod = pod(json!([
            {"name": "http", "containerPort": 8080},
            {"name": "https", "containerPort": 8443}
        ]));
        let unnamed_pod = pod(json!([{"containerPort": 8080}, {"containerPort": 8443}]));
        let two = |named: bool, target_named: bool| {
            let t = |n: &str, i: i32| if target_named { json!(n) } else { json!(i) };
            let mk = |port: i32, name: &str, tp: Value| {
                let mut o = json!({"port": port, "targetPort": tp});
                if named {
                    o["name"] = json!(name);
                }
                o
            };
            json!([
                mk(80, "http", t("http", 8080)),
                mk(443, "https", t("https", 8443))
            ])
        };
        let http80_pod = pod(json!([{"name": "http", "containerPort": 80}]));
        let one = |tp: Value| json!([{"port": 80, "targetPort": tp}]);

        let ok: Vec<(Service, &Pod, Vec<&str>, Vec<&str>)> = vec![
            (
                svc(None, one(json!(8080))),
                &http_pod,
                vec!["80"],
                vec!["80:8080"],
            ),
            (
                svc(None, one(json!(8080))),
                &http_pod,
                vec![":80"],
                vec![":8080"],
            ),
            (
                svc(None, json!([{"port": 8080, "targetPort": 8080}])),
                &http_pod,
                vec!["8000:8080"],
                vec!["8000:8080"],
            ),
            (
                svc(Some("None"), one(json!(8080))),
                &http_pod,
                vec!["80"],
                vec!["80"],
            ),
            (
                svc(Some("None"), one(json!(8080))),
                &http_pod,
                vec![":80"],
                vec![":80"],
            ),
            (
                svc(None, two(false, true)),
                &named_pod,
                vec!["80", "443"],
                vec!["80:8080", "443:8443"],
            ),
            (
                svc(None, two(false, true)),
                &named_pod,
                vec![":80", ":443"],
                vec![":8080", ":8443"],
            ),
            (
                svc(None, two(true, false)),
                &unnamed_pod,
                vec!["http", "https"],
                vec!["80:8080", "443:8443"],
            ),
            (
                svc(None, two(true, false)),
                &unnamed_pod,
                vec![":http", ":https"],
                vec![":8080", ":8443"],
            ),
            (
                svc(
                    None,
                    json!([{"port": 80, "name": "http", "targetPort": "http"}]),
                ),
                &http80_pod,
                vec!["http"],
                vec!["80"],
            ),
            // targetPort omitted
            (
                svc(None, json!([{"port": 80}])),
                &http_pod,
                vec!["80"],
                vec!["80"],
            ),
            (
                svc(None, json!([{"port": 80}])),
                &http_pod,
                vec![":80"],
                vec![":80"],
            ),
        ];
        for (i, (s, p, ports, want)) in ok.iter().enumerate() {
            let got = translate_service_port_to_target_port(&v(ports), s, p).unwrap();
            assert_eq!(got, v(want), "case {i}");
        }

        // failures: unresolvable named target port, unknown service port name,
        // service port not declared.
        assert!(translate_service_port_to_target_port(
            &v(&["80"]),
            &svc(None, one(json!("http"))),
            &pod(json!([]))
        )
        .is_err());
        assert!(translate_service_port_to_target_port(
            &v(&["https"]),
            &svc(
                None,
                json!([{"port": 80, "name": "http", "targetPort": 8080}])
            ),
            &http_pod
        )
        .is_err());
        let e = translate_service_port_to_target_port(
            &v(&["443"]),
            &svc(None, one(json!(8080))),
            &http_pod,
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "Service svc does not have a service port 443"
        );
    }

    #[test]
    fn test_port_forward_convert_pod_named_port_to_number() {
        let p = pod(json!([{"name": "http", "containerPort": 80}]));
        for (ports, want) in [
            (vec!["80"], vec!["80"]),
            (vec!["8000:80"], vec!["8000:80"]),
            (vec![":80"], vec![":80"]),
            (vec!["http"], vec!["80"]),
            (vec!["8000:http"], vec!["8000:80"]),
            (vec![":http"], vec![":80"]),
        ] {
            assert_eq!(
                convert_pod_named_port_to_number(&v(&ports), &p).unwrap(),
                v(&want),
                "{ports:?}"
            );
        }
        let none = pod(json!([]));
        assert!(convert_pod_named_port_to_number(&v(&["http"]), &none).is_err());
        assert!(convert_pod_named_port_to_number(&v(&["https", "http"]), &p).is_err());
        let e = convert_pod_named_port_to_number(&v(&["28015:"]), &p).unwrap_err();
        assert_eq!(e.to_string(), "remote port cannot be empty");
    }

    #[test]
    fn test_port_forward_udp_ports_rejected() {
        let udp_pod = pod(json!([{"name": "dns", "containerPort": 53, "protocol": "UDP"}]));
        for ports in [vec!["53"], vec!["dns"]] {
            let e = check_udp_port_in_pod(&v(&ports), &udp_pod).unwrap_err();
            assert!(e
                .to_string()
                .starts_with("UDP protocol is not supported for"));
        }
        let both = pod(json!([
            {"containerPort": 53, "protocol": "UDP"},
            {"containerPort": 53, "protocol": "TCP"}
        ]));
        assert!(check_udp_port_in_pod(&v(&[":53"]), &both).is_ok());

        let udp_svc = svc(
            None,
            json!([{"name": "dns", "port": 53, "protocol": "UDP"}]),
        );
        assert!(check_udp_port_in_service(&v(&["53"]), &udp_svc).is_err());
        assert!(check_udp_port_in_service(&v(&["10053:dns"]), &udp_svc).is_err());
        let both_svc = svc(
            None,
            json!([{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]),
        );
        assert!(check_udp_port_in_service(&v(&["53"]), &both_svc).is_ok());
    }

    #[test]
    fn test_port_forward_parse_ports() {
        assert_eq!(
            parse_ports(&v(&["5000", "6000:80", ":5001"])).unwrap(),
            vec![(5000, 5000), (6000, 80), (0, 5001)]
        );
        for bad in ["1:2:3", "x:80", "80:x", "80:0", "70000", ":0", ""] {
            assert!(parse_ports(&v(&[bad])).is_err(), "{bad}");
        }
        assert_eq!(
            parse_ports(&v(&["80:0"])).unwrap_err().to_string(),
            "remote port must be > 0"
        );
        assert_eq!(split_port("a:b"), ("a".to_string(), "b".to_string()));
        assert_eq!(split_port("a"), ("a".to_string(), "a".to_string()));
    }
}
