//! Ports of `pkg/proxy/endpointschangetracker_test.go` (TestEndpointSliceUpdate)
//! and the `EndpointsMap` helpers.

mod tracker {
    use kubernetes_rs_common::resources::EndpointSlice;
    use kubernetes_rs_kube_proxy::endpoints_map::*;
    use kubernetes_rs_kube_proxy::endpointslice_cache::*;
    use serde_json::json;

    /// `generateEndpointSliceWithOffset`.
    #[allow(clippy::too_many_arguments)]
    fn gen(
        svc: &str,
        ns: &str,
        slice_num: i64,
        offset: i64,
        num: i64,
        unready_mod: i64,
        terminating_mod: i64,
        hosts: &[&str],
        ports: &[i64],
    ) -> EndpointSlice {
        let ports: Vec<_> = ports
            .iter()
            .enumerate()
            .map(|(i, p)| json!({"name": format!("port-{i}"), "port": p, "protocol": "TCP"}))
            .collect();
        let eps: Vec<_> = (1..=num)
            .map(|i| {
                let ready = i % unready_mod != 0;
                let term = i % terminating_mod == 0;
                let mut e = json!({
                    "addresses": [format!("10.0.{offset}.{i}")],
                    "conditions": {"ready": ready && !term, "serving": ready, "terminating": term},
                });
                if !hosts.is_empty() {
                    e["nodeName"] = hosts[(i as usize) % hosts.len()].into();
                }
                e
            })
            .collect();
        serde_json::from_value(json!({
            "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
            "metadata": {"name": format!("{svc}-{slice_num}"), "namespace": ns,
                         "labels": {LABEL_SERVICE_NAME: svc}},
            "addressType": "IPv4", "ports": ports, "endpoints": eps,
        }))
        .unwrap()
    }

    fn fqdn_slice() -> EndpointSlice {
        let mut s = gen("svc1", "ns1", 2, 2, 5, 999, 999, &["host1"], &[80, 443]);
        s.address_type = "FQDN".into();
        s
    }

    fn ep(
        ip: &str,
        port: u16,
        local: bool,
        ready: bool,
        serving: bool,
        term: bool,
    ) -> EndpointInfo {
        EndpointInfo {
            ip: ip.into(),
            port,
            is_local: local,
            ready,
            serving,
            terminating: term,
            zone_hints: Default::default(),
            node_hints: Default::default(),
        }
    }

    struct Case {
        name: &'static str,
        starting: Vec<EndpointSlice>,
        param: EndpointSlice,
        remove: bool,
        want_return: bool,
        want_current: Option<Vec<(&'static str, Vec<EndpointInfo>)>>,
    }

    #[test]
    fn endpoints_change_tracker_endpoint_slice_update() {
        let cases = vec![
            Case {
                name: "add a simple slice that doesn't already exist",
                starting: vec![],
                param: gen(
                    "svc1",
                    "ns1",
                    1,
                    1,
                    3,
                    999,
                    999,
                    &["host1", "host2"],
                    &[80, 443],
                ),
                remove: false,
                want_return: true,
                want_current: Some(vec![
                    (
                        "port-0",
                        vec![
                            ep("10.0.1.1", 80, false, true, true, false),
                            ep("10.0.1.2", 80, true, true, true, false),
                            ep("10.0.1.3", 80, false, true, true, false),
                        ],
                    ),
                    (
                        "port-1",
                        vec![
                            ep("10.0.1.1", 443, false, true, true, false),
                            ep("10.0.1.2", 443, true, true, true, false),
                            ep("10.0.1.3", 443, false, true, true, false),
                        ],
                    ),
                ]),
            },
            Case {
                name: "add the same slice that already exists",
                starting: vec![gen(
                    "svc1",
                    "ns1",
                    1,
                    1,
                    3,
                    999,
                    999,
                    &["host1", "host2"],
                    &[80, 443],
                )],
                param: gen(
                    "svc1",
                    "ns1",
                    1,
                    1,
                    3,
                    999,
                    999,
                    &["host1", "host2"],
                    &[80, 443],
                ),
                remove: false,
                want_return: false,
                want_current: None,
            },
            Case {
                name: "add an FQDN slice (invalid address type)",
                starting: vec![gen(
                    "svc1",
                    "ns1",
                    1,
                    1,
                    3,
                    999,
                    999,
                    &["host1", "host2"],
                    &[80, 443],
                )],
                param: fqdn_slice(),
                remove: false,
                want_return: false,
                want_current: None,
            },
            Case {
                name: "add a slice that overlaps with existing state",
                starting: vec![
                    gen(
                        "svc1",
                        "ns1",
                        1,
                        1,
                        3,
                        999,
                        999,
                        &["host1", "host2"],
                        &[80, 443],
                    ),
                    gen(
                        "svc1",
                        "ns1",
                        2,
                        2,
                        2,
                        999,
                        999,
                        &["host1", "host2"],
                        &[80, 443],
                    ),
                ],
                param: gen("svc1", "ns1", 1, 1, 5, 999, 999, &["host1"], &[80, 443]),
                remove: false,
                want_return: true,
                want_current: Some(vec![
                    (
                        "port-0",
                        vec![
                            ep("10.0.1.1", 80, true, true, true, false),
                            ep("10.0.1.2", 80, true, true, true, false),
                            ep("10.0.1.3", 80, true, true, true, false),
                            ep("10.0.1.4", 80, true, true, true, false),
                            ep("10.0.1.5", 80, true, true, true, false),
                            ep("10.0.2.1", 80, false, true, true, false),
                            ep("10.0.2.2", 80, true, true, true, false),
                        ],
                    ),
                    (
                        "port-1",
                        vec![
                            ep("10.0.1.1", 443, true, true, true, false),
                            ep("10.0.1.2", 443, true, true, true, false),
                            ep("10.0.1.3", 443, true, true, true, false),
                            ep("10.0.1.4", 443, true, true, true, false),
                            ep("10.0.1.5", 443, true, true, true, false),
                            ep("10.0.2.1", 443, false, true, true, false),
                            ep("10.0.2.2", 443, true, true, true, false),
                        ],
                    ),
                ]),
            },
            Case {
                name: "add a slice that overlaps with existing state and partial ports",
                starting: vec![
                    gen(
                        "svc1",
                        "ns1",
                        1,
                        1,
                        3,
                        999,
                        999,
                        &["host1", "host2"],
                        &[80, 443],
                    ),
                    gen(
                        "svc1",
                        "ns1",
                        2,
                        2,
                        2,
                        999,
                        999,
                        &["host1", "host2"],
                        &[80, 443],
                    ),
                ],
                param: gen("svc1", "ns1", 3, 1, 5, 999, 999, &["host1"], &[80]),
                remove: false,
                want_return: true,
                want_current: Some(vec![
                    (
                        "port-0",
                        vec![
                            ep("10.0.1.1", 80, true, true, true, false),
                            ep("10.0.1.2", 80, true, true, true, false),
                            ep("10.0.1.3", 80, true, true, true, false),
                            ep("10.0.1.4", 80, true, true, true, false),
                            ep("10.0.1.5", 80, true, true, true, false),
                            ep("10.0.2.1", 80, false, true, true, false),
                            ep("10.0.2.2", 80, true, true, true, false),
                        ],
                    ),
                    (
                        "port-1",
                        vec![
                            ep("10.0.1.1", 443, false, true, true, false),
                            ep("10.0.1.2", 443, true, true, true, false),
                            ep("10.0.1.3", 443, false, true, true, false),
                            ep("10.0.2.1", 443, false, true, true, false),
                            ep("10.0.2.2", 443, true, true, true, false),
                        ],
                    ),
                ]),
            },
            Case {
                name: "remove a slice that overlaps with existing state",
                starting: vec![
                    gen(
                        "svc1",
                        "ns1",
                        1,
                        1,
                        3,
                        999,
                        999,
                        &["host1", "host2"],
                        &[80, 443],
                    ),
                    gen(
                        "svc1",
                        "ns1",
                        2,
                        2,
                        2,
                        999,
                        999,
                        &["host1", "host2"],
                        &[80, 443],
                    ),
                ],
                param: gen("svc1", "ns1", 1, 1, 5, 999, 999, &["host1"], &[80, 443]),
                remove: true,
                want_return: true,
                want_current: Some(vec![
                    (
                        "port-0",
                        vec![
                            ep("10.0.2.1", 80, false, true, true, false),
                            ep("10.0.2.2", 80, true, true, true, false),
                        ],
                    ),
                    (
                        "port-1",
                        vec![
                            ep("10.0.2.1", 443, false, true, true, false),
                            ep("10.0.2.2", 443, true, true, true, false),
                        ],
                    ),
                ]),
            },
            Case {
                name: "remove a slice that doesn't even exist in current state",
                starting: vec![
                    gen("svc1", "ns1", 1, 1, 5, 999, 999, &["host1"], &[80, 443]),
                    gen("svc1", "ns1", 2, 2, 2, 999, 999, &["host1"], &[80, 443]),
                ],
                param: gen("svc1", "ns1", 3, 3, 5, 999, 999, &["host1"], &[80, 443]),
                remove: true,
                want_return: false,
                want_current: None,
            },
            Case {
                name: "transition all endpoints to unready state",
                starting: vec![gen(
                    "svc1",
                    "ns1",
                    1,
                    1,
                    3,
                    999,
                    999,
                    &["host1", "host2"],
                    &[80, 443],
                )],
                param: gen("svc1", "ns1", 1, 1, 3, 1, 999, &["host1"], &[80, 443]),
                remove: false,
                want_return: true,
                want_current: Some(vec![
                    (
                        "port-0",
                        vec![
                            ep("10.0.1.1", 80, true, false, false, false),
                            ep("10.0.1.2", 80, true, false, false, false),
                            ep("10.0.1.3", 80, true, false, false, false),
                        ],
                    ),
                    (
                        "port-1",
                        vec![
                            ep("10.0.1.1", 443, true, false, false, false),
                            ep("10.0.1.2", 443, true, false, false, false),
                            ep("10.0.1.3", 443, true, false, false, false),
                        ],
                    ),
                ]),
            },
            Case {
                name: "transition all endpoints to ready state",
                starting: vec![gen(
                    "svc1",
                    "ns1",
                    1,
                    1,
                    2,
                    1,
                    999,
                    &["host1", "host2"],
                    &[80, 443],
                )],
                param: gen("svc1", "ns1", 1, 1, 2, 999, 999, &["host1"], &[80, 443]),
                remove: false,
                want_return: true,
                want_current: Some(vec![
                    (
                        "port-0",
                        vec![
                            ep("10.0.1.1", 80, true, true, true, false),
                            ep("10.0.1.2", 80, true, true, true, false),
                        ],
                    ),
                    (
                        "port-1",
                        vec![
                            ep("10.0.1.1", 443, true, true, true, false),
                            ep("10.0.1.2", 443, true, true, true, false),
                        ],
                    ),
                ]),
            },
            Case {
                name: "transition some endpoints to ready state",
                starting: vec![
                    gen("svc1", "ns1", 1, 1, 3, 2, 999, &["host1"], &[80, 443]),
                    gen("svc1", "ns1", 2, 2, 2, 2, 999, &["host1"], &[80, 443]),
                ],
                param: gen("svc1", "ns1", 1, 1, 3, 3, 999, &["host1"], &[80, 443]),
                remove: false,
                want_return: true,
                want_current: Some(vec![
                    (
                        "port-0",
                        vec![
                            ep("10.0.1.1", 80, true, true, true, false),
                            ep("10.0.1.2", 80, true, true, true, false),
                            ep("10.0.1.3", 80, true, false, false, false),
                            ep("10.0.2.1", 80, true, true, true, false),
                            ep("10.0.2.2", 80, true, false, false, false),
                        ],
                    ),
                    (
                        "port-1",
                        vec![
                            ep("10.0.1.1", 443, true, true, true, false),
                            ep("10.0.1.2", 443, true, true, true, false),
                            ep("10.0.1.3", 443, true, false, false, false),
                            ep("10.0.2.1", 443, true, true, true, false),
                            ep("10.0.2.2", 443, true, false, false, false),
                        ],
                    ),
                ]),
            },
            Case {
                name: "transition some endpoints to terminating state",
                starting: vec![
                    gen("svc1", "ns1", 1, 1, 3, 2, 2, &["host1"], &[80, 443]),
                    gen("svc1", "ns1", 2, 2, 2, 2, 2, &["host1"], &[80, 443]),
                ],
                param: gen("svc1", "ns1", 1, 1, 3, 3, 2, &["host1"], &[80, 443]),
                remove: false,
                want_return: true,
                want_current: Some(vec![
                    (
                        "port-0",
                        vec![
                            ep("10.0.1.1", 80, true, true, true, false),
                            ep("10.0.1.2", 80, true, false, true, true),
                            ep("10.0.1.3", 80, true, false, false, false),
                            ep("10.0.2.1", 80, true, true, true, false),
                            ep("10.0.2.2", 80, true, false, false, true),
                        ],
                    ),
                    (
                        "port-1",
                        vec![
                            ep("10.0.1.1", 443, true, true, true, false),
                            ep("10.0.1.2", 443, true, false, true, true),
                            ep("10.0.1.3", 443, true, false, false, false),
                            ep("10.0.2.1", 443, true, true, true, false),
                            ep("10.0.2.2", 443, true, false, false, true),
                        ],
                    ),
                ]),
            },
        ];
        let key = NamespacedName {
            namespace: "ns1".into(),
            name: "svc1".into(),
        };
        for c in cases {
            let mut t = EndpointsChangeTracker::new(IpFamily::IPv4, "host1", None);
            for s in &c.starting {
                t.endpoint_slice_update(s, false);
            }
            t.checkout_changes();
            let got = t.endpoint_slice_update(&c.param, c.remove);
            assert_eq!(got, c.want_return, "{}: return value", c.name);
            let changes = t.checkout_changes();
            match c.want_current {
                None => assert!(changes.is_empty(), "{}: expected no changes", c.name),
                Some(want) => {
                    let ch = changes
                        .get(&key)
                        .unwrap_or_else(|| panic!("{}: expected changes", c.name));
                    assert_eq!(ch.current.len(), want.len(), "{}: port count", c.name);
                    for (port, eps) in want {
                        let spn = service_port_name("ns1", "svc1", port, "TCP");
                        let mut got: Vec<_> = ch.current[&spn].clone();
                        let mut eps = eps;
                        got.sort_by(|a, b| a.ip.cmp(&b.ip));
                        eps.sort_by(|a, b| a.ip.cmp(&b.ip));
                        assert_eq!(got, eps, "{}: {port}", c.name);
                    }
                }
            }
        }
    }
}
