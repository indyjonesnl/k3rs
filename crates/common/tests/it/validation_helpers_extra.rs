//! `IsFullyQualifiedDomainName` (util/validation/validation_test.go
//! `TestIsFullyQualifiedDomainName`), selector label values, LimitRange types,
//! quota scopes and attachable volume names.

use kubernetes_rs_common::types::{LabelSelector, LabelSelectorRequirement};
use kubernetes_rs_common::validation::field::{ErrorType, Path};
use kubernetes_rs_common::validation::helpers_extra::*;

fn fqdn(name: &str) -> Vec<(ErrorType, String)> {
    is_fully_qualified_domain_name(&Path::new("f"), name)
        .into_iter()
        .map(|e| (e.error_type, e.detail))
        .collect()
}

#[test]
fn helpers_extra_fqdn_valid() {
    for n in [
        "a.b",
        "a.b.",
        "k8s.io",
        "kubernetes.io.",
        "a-b.c-d.example.com",
    ] {
        assert!(fqdn(n).is_empty(), "{n}: {:?}", fqdn(n));
    }
}

#[test]
fn helpers_extra_fqdn_invalid() {
    assert_eq!(fqdn("")[0].0, ErrorType::Required);
    // a single segment
    let e = fqdn("single");
    assert_eq!(e[0].0, ErrorType::Invalid);
    assert_eq!(
        e[0].1,
        "should be a domain with at least two segments separated by dots"
    );
    // not an RFC 1123 subdomain
    assert_eq!(fqdn("A.b")[0].0, ErrorType::Invalid);
    assert_eq!(fqdn("a..b")[0].0, ErrorType::Invalid);
    assert_eq!(fqdn("-a.b")[0].0, ErrorType::Invalid);
    // only one trailing dot is stripped
    assert_eq!(fqdn("a.b..")[0].0, ErrorType::Invalid);
    assert_eq!(fqdn(".")[0].0, ErrorType::Invalid);
}

fn sel(values: &[&str]) -> LabelSelector {
    LabelSelector {
        match_labels: None,
        match_expressions: Some(vec![LabelSelectorRequirement {
            key: "k".into(),
            operator: "In".into(),
            values: Some(values.iter().map(|s| s.to_string()).collect()),
        }]),
    }
}

#[test]
fn helpers_extra_label_selector_invalid_label_value() {
    assert!(!label_selector_has_invalid_label_value(None));
    assert!(!label_selector_has_invalid_label_value(Some(&sel(&[
        "a", "b-c", ""
    ]))));
    assert!(label_selector_has_invalid_label_value(Some(&sel(&[
        "ok",
        "not valid!"
    ]))));
    // matchLabels are not inspected
    let ml = LabelSelector {
        match_labels: Some([("k".to_string(), "not valid!".to_string())].into()),
        match_expressions: None,
    };
    assert!(!label_selector_has_invalid_label_value(Some(&ml)));
}

#[test]
fn helpers_extra_limit_range_types_and_attachable() {
    for t in ["Pod", "Container", "PersistentVolumeClaim"] {
        assert!(is_standard_limit_range_type(t));
    }
    assert!(!is_standard_limit_range_type("pod"));
    assert!(!is_standard_limit_range_type("Node"));
    assert!(is_attachable_volume_resource_name(
        "attachable-volumes-aws-ebs"
    ));
    assert!(!is_attachable_volume_resource_name("volumes-attachable"));
}

#[test]
fn helpers_extra_quota_scope_valid_for_resource() {
    for scope in [
        "Terminating",
        "NotTerminating",
        "NotBestEffort",
        "PriorityClass",
        "CrossNamespacePodAffinity",
    ] {
        assert!(
            is_resource_quota_scope_valid_for_resource(scope, "pods"),
            "{scope}"
        );
        assert!(
            is_resource_quota_scope_valid_for_resource(scope, "requests.cpu"),
            "{scope}"
        );
        assert!(
            !is_resource_quota_scope_valid_for_resource(scope, "services"),
            "{scope}"
        );
        assert!(
            !is_resource_quota_scope_valid_for_resource(scope, "requests.storage"),
            "{scope}"
        );
    }
    assert!(is_resource_quota_scope_valid_for_resource(
        "BestEffort",
        "pods"
    ));
    assert!(!is_resource_quota_scope_valid_for_resource(
        "BestEffort",
        "cpu"
    ));
    assert!(is_resource_quota_scope_valid_for_resource(
        "VolumeAttributesClass",
        "persistentvolumeclaims"
    ));
    assert!(is_resource_quota_scope_valid_for_resource(
        "VolumeAttributesClass",
        "requests.storage"
    ));
    assert!(!is_resource_quota_scope_valid_for_resource(
        "VolumeAttributesClass",
        "pods"
    ));
    // unknown scope: valid for everything
    assert!(is_resource_quota_scope_valid_for_resource(
        "Whatever", "services"
    ));
}
