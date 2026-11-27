//! Tests for `src/validation/pod_spec_extra.rs`, from `TestValidatePodSpec` /
//! `TestValidatePod` / hostAliases / preemption cases (release-1.35).

mod tests {
    use kubernetes_rs_common::resources::pod::{HostAlias, PodSpec};
    use kubernetes_rs_common::validation::field::{ErrorList, Path};
    use kubernetes_rs_common::validation::pod_spec_extra::*;
    use serde_json::json;

    fn spec(extra: serde_json::Value) -> PodSpec {
        let mut v = json!({"containers": [{"name": "c", "image": "i"}]});
        for (k, val) in extra.as_object().unwrap() {
            v[k] = val.clone();
        }
        serde_json::from_value(v).unwrap()
    }

    fn fields(errs: &ErrorList) -> Vec<String> {
        errs.iter()
            .map(|e| format!("{:?} {}", e.error_type, e.field))
            .collect()
    }

    #[test]
    fn pod_spec_extra_valid_spec_has_no_errors() {
        let s = spec(json!({
            "hostname": "h1", "subdomain": "sub", "nodeName": "node-1.example.com",
            "serviceAccountName": "default", "priorityClassName": "high",
            "runtimeClassName": "gvisor", "preemptionPolicy": "Never",
            "nodeSelector": {"kubernetes.io/os": "linux"},
            "hostAliases": [{"ip": "127.0.0.1", "hostnames": ["foo.local", "bar"]}],
        }));
        assert!(validate_pod_spec_extra(&s, &Path::new("spec")).is_empty());
    }

    #[test]
    fn pod_spec_extra_invalid_names_rejected() {
        let s = spec(json!({
            "hostname": "Bad_Host", "subdomain": "-x", "nodeName": "NODE",
            "serviceAccountName": "a_b", "priorityClassName": "UPPER",
            "runtimeClassName": "Bad Name",
            "nodeSelector": {"not a key!": "v"},
        }));
        let errs = validate_pod_spec_extra(&s, &Path::new("spec"));
        let got = fields(&errs);
        for f in [
            "spec.nodeSelector",
            "spec.serviceAccountName",
            "spec.nodeName",
            "spec.hostname",
            "spec.subdomain",
            "spec.priorityClassName",
            "spec.runtimeClassName",
        ] {
            assert!(
                got.iter()
                    .any(|g| g.starts_with("Invalid") && g.contains(f)),
                "missing {f}: {got:?}"
            );
        }
        let h = errs.iter().find(|e| e.field == "spec.hostname").unwrap();
        assert!(h
            .detail
            .starts_with("a lowercase RFC 1123 label must consist of"));
    }

    #[test]
    fn pod_spec_extra_host_aliases() {
        let ok = vec![HostAlias {
            ip: "::1".into(),
            hostnames: Some(vec!["a.b".into()]),
        }];
        assert!(validate_host_aliases(&ok, &Path::new("hostAliases")).is_empty());

        let bad = vec![
            HostAlias {
                ip: "999.1.1.1".into(),
                hostnames: Some(vec!["UPPER".into(), "ok".into()]),
            },
            HostAlias {
                ip: "".into(),
                hostnames: None,
            },
        ];
        let errs = validate_host_aliases(&bad, &Path::new("hostAliases"));
        assert_eq!(
            fields(&errs),
            [
                "Invalid hostAliases[0].ip",
                "Invalid hostAliases[0].hostnames[0]",
                "Invalid hostAliases[1].ip"
            ]
        );
        assert_eq!(
            errs[0].detail,
            "must be a valid IP address, (e.g. 10.9.8.7 or 2001:db8::ffff)"
        );
    }

    #[test]
    fn pod_spec_extra_preemption_policy() {
        let p = Path::new("spec").child("preemptionPolicy");
        assert!(validate_preemption_policy("PreemptLowerPriority", &p).is_empty());
        assert!(validate_preemption_policy("Never", &p).is_empty());
        let e = validate_preemption_policy("", &p);
        assert_eq!(fields(&e), ["Required spec.preemptionPolicy"]);
        let e = validate_preemption_policy("Sometimes", &p);
        assert_eq!(fields(&e), ["NotSupported spec.preemptionPolicy"]);
        assert_eq!(
            e[0].detail,
            "supported values: \"PreemptLowerPriority\", \"Never\""
        );
    }

    #[test]
    fn pod_spec_extra_empty_optional_names_are_skipped() {
        // Upstream only validates these when len > 0 (runtimeClassName and
        // preemptionPolicy when non-nil).
        let s = spec(json!({"hostname": "", "nodeName": "", "serviceAccountName": ""}));
        assert!(validate_pod_spec_extra(&s, &Path::new("spec")).is_empty());
        let s = spec(json!({"runtimeClassName": ""}));
        assert!(!validate_pod_spec_extra(&s, &Path::new("spec")).is_empty());
    }
}
