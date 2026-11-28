//! Ports of `handlers/negotiation/negotiate_test.go` TestNegotiate and
//! `discovery/aggregated/wrapper_test.go` TestAggregationEnabled.

use kubernetes_rs_discovery::negotiation::*;

const JSON: &str = "application/json";
const PROTO: &str = "application/vnd.kubernetes.protobuf";
const BETA_SUFFIX: &str = ";g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList";
const SUFFIX: &str = ";g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList";

fn info(media: &'static str) -> SerializerInfo {
    let (t, st) = media.split_once('/').unwrap_or((media, ""));
    SerializerInfo {
        media_type: media,
        media_type_type: Box::leak(t.to_string().into_boxed_str()),
        media_type_sub_type: Box::leak(st.to_string().into_boxed_str()),
        streams: false,
        pretty: false,
    }
}

fn negotiate(
    accept: &str,
    query: &str,
    ua: &str,
    types: &[&'static str],
) -> Result<(String, bool), String> {
    let infos: Vec<_> = types.iter().map(|t| info(t)).collect();
    negotiate_output_media_type(accept, query, ua, &infos, &DefaultEndpointRestrictions)
        .map(|(_, i, _)| i.media_type.to_string())
        .map(|m| {
            let (o, ..) = negotiate_output_media_type(
                accept,
                query,
                ua,
                &infos,
                &DefaultEndpointRestrictions,
            )
            .unwrap();
            (m, o.pretty || is_pretty_print(query, ua))
        })
}

#[test]
fn discovery_negotiation_picks_media_type() {
    let both = [JSON, "application/protobuf"];
    let cases: &[(&str, &[&'static str], &str)] = &[
        ("", &[JSON], JSON),
        ("*/*", &[JSON], JSON),
        ("application/*", &[JSON], JSON),
        (JSON, &[JSON], JSON),
        (JSON, &both, JSON),
        ("application/protobuf", &both, "application/protobuf"),
        ("application/json; pretty=1", &[JSON], JSON),
        (
            "unrecognized/stuff,application/json; pretty=1",
            &[JSON],
            JSON,
        ),
        (
            "application/json;as=BOGUS;v=v1beta1;g=meta.k8s.io, application/json",
            &[JSON],
            JSON,
        ),
        ("application/BOGUS, application/json", &[JSON], JSON),
    ];
    for (accept, types, want) in cases {
        let (got, _) = negotiate(accept, "", "", types).unwrap_or_else(|e| panic!("{accept}: {e}"));
        assert_eq!(&got, want, "{accept}");
    }
}

#[test]
fn discovery_negotiation_pretty_from_param_query_and_user_agent() {
    assert!(
        negotiate("application/json; pretty=1", "", "", &[JSON])
            .unwrap()
            .1
    );
    assert!(negotiate(JSON, "pretty=1", "", &[JSON]).unwrap().1);
    for ua in ["curl", "Wget", "Mozilla/5.0"] {
        assert!(negotiate(JSON, "", ua, &[JSON]).unwrap().1, "{ua}");
    }
    assert!(!negotiate(JSON, "", "kubectl", &[JSON]).unwrap().1);
    // pretty=false in the query beats a curl user agent.
    assert!(!is_pretty_print("pretty=false", "curl"));
}

#[test]
fn discovery_negotiation_not_acceptable() {
    assert_eq!(
        negotiate("application", "", "", &["application"]).unwrap_err(),
        "only the following media types are accepted: application"
    );
    assert_eq!(
        negotiate("", "", "", &[]).unwrap_err(),
        "only the following media types are accepted: "
    );
    assert_eq!(
        negotiate("*/*", "", "", &[]).unwrap_err(),
        "only the following media types are accepted: "
    );
}

#[test]
fn discovery_negotiation_parameters_in_any_order() {
    let r = DiscoveryEndpointRestrictions::default();
    for accept in [
        "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList",
        "application/json; as=APIGroupDiscoveryList ; v=v2 ; g=apidiscovery.k8s.io",
        "application/json;v=v2;as=APIGroupDiscoveryList;g=apidiscovery.k8s.io;profile=nopeer",
    ] {
        let o = negotiate_media_type_options(accept, &SUPPORTED_MEDIA_TYPES, &r).unwrap();
        assert!(
            is_aggregated_discovery_gvk(o.convert.as_ref(), true),
            "{accept}"
        );
    }
    let o = negotiate_media_type_options(
        "application/json;profile=nopeer;v=v2;as=APIGroupDiscoveryList;g=apidiscovery.k8s.io",
        &SUPPORTED_MEDIA_TYPES,
        &r,
    )
    .unwrap();
    assert_eq!(o.profile, "nopeer");
}

#[test]
fn discovery_negotiation_stream_and_server_version_restrictions() {
    let r = DefaultEndpointRestrictions;
    // yaml has no stream serializer.
    assert!(negotiate_media_type_options(
        "application/yaml;stream=watch",
        &SUPPORTED_MEDIA_TYPES,
        &r
    )
    .is_none());
    assert!(negotiate_media_type_options(
        "application/json;stream=watch",
        &SUPPORTED_MEDIA_TYPES,
        &r
    )
    .is_some());
    assert!(negotiate_media_type_options(
        "application/json;stream=other",
        &SUPPORTED_MEDIA_TYPES,
        &r
    )
    .is_none());
    assert!(
        negotiate_media_type_options("application/json;sv=v1", &SUPPORTED_MEDIA_TYPES, &r)
            .is_none()
    );
    let o = negotiate_media_type_options("application/json;foo=bar", &SUPPORTED_MEDIA_TYPES, &r)
        .unwrap();
    assert_eq!(o.unrecognized, vec!["foo".to_string()]);
}

#[test]
fn discovery_negotiation_q_values_order_clauses() {
    let r = DefaultEndpointRestrictions;
    let o = negotiate_media_type_options(
        "application/json;q=0.5,application/yaml",
        &SUPPORTED_MEDIA_TYPES,
        &r,
    )
    .unwrap();
    assert_eq!(o.accepted.unwrap().media_type, "application/yaml");
}

#[test]
fn discovery_negotiation_aggregation_routing() {
    use DiscoveryRoute::*;
    let agg = |m: &str, s: &str| format!("{m}{s}");
    let nopeer = |m: &str| format!("{m}{SUFFIX};profile=nopeer");
    let r = DiscoveryEndpointRestrictions::default();
    let beta = DiscoveryEndpointRestrictions {
        remove_beta_type: false,
    };
    // (accept, restrictions, interop gate, peer handler present, want)
    let cases: Vec<(
        String,
        &DiscoveryEndpointRestrictions,
        bool,
        bool,
        DiscoveryRoute,
    )> = vec![
        (
            "application/json;foo=bar".into(),
            &r,
            false,
            false,
            Unaggregated,
        ),
        ("".into(), &r, false, false, Unaggregated),
        (agg(JSON, BETA_SUFFIX), &beta, false, false, Aggregated),
        (agg(PROTO, BETA_SUFFIX), &beta, false, false, Aggregated),
        // 1.35 locks the beta type off.
        (agg(JSON, BETA_SUFFIX), &r, false, false, Unaggregated),
        (agg(JSON, SUFFIX), &r, false, false, Aggregated),
        (agg(PROTO, SUFFIX), &r, false, false, Aggregated),
        (JSON.into(), &r, false, false, Unaggregated),
        (PROTO.into(), &r, false, false, Unaggregated),
        (
            format!("{}{SUFFIX},{JSON}", JSON),
            &r,
            false,
            false,
            Aggregated,
        ),
        (
            format!("{}{SUFFIX},{PROTO}", PROTO),
            &r,
            false,
            false,
            Aggregated,
        ),
        (agg(JSON, SUFFIX), &r, true, true, PeerAggregated),
        (agg(PROTO, SUFFIX), &r, true, true, PeerAggregated),
        (nopeer(JSON), &r, true, true, Aggregated),
        (nopeer(PROTO), &r, true, true, Aggregated),
        (
            format!("{}{SUFFIX};profile=foo", JSON),
            &r,
            true,
            true,
            PeerAggregated,
        ),
    ];
    for (accept, restrictions, gate, peer, want) in cases {
        assert_eq!(
            route_discovery(&accept, gate, peer, restrictions),
            want,
            "{accept}"
        );
    }
}
