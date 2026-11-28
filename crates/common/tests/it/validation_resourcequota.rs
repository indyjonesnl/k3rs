//! Tests for ResourceQuota field validation.
//!
//! Mirrors upstream `ValidateResourceQuotaSpec`
//! (`pkg/apis/core/validation/validation.go`, release-1.35).

use kubernetes_rs_common::resources::policy::ResourceQuota;
use kubernetes_rs_common::validation::field::{Error, ErrorType};
use kubernetes_rs_common::validation::resourcequota::validate_resource_quota;
use serde_json::json;

fn rq(spec: serde_json::Value) -> ResourceQuota {
    serde_json::from_value(json!({
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": {"name": "q", "namespace": "default"},
        "spec": spec
    }))
    .unwrap()
}

fn has(errs: &[Error], field: &str, ty: ErrorType) -> bool {
    errs.iter().any(|e| e.field == field && e.error_type == ty)
}

#[test]
fn valid_quota_passes() {
    let errs = validate_resource_quota(&rq(json!({
        // BestEffort covers only pod counts (helpers.go:157-158); the compute
        // resources need NotBestEffort.
        "hard": {"cpu": "10", "memory": "20Gi", "pods": "100"},
        "scopes": ["NotBestEffort"]
    })));
    assert!(errs.is_empty(), "unexpected errors: {errs:?}");
}

#[test]
fn negative_hard_quantity_rejected() {
    let errs = validate_resource_quota(&rq(json!({"hard": {"cpu": "-1"}})));
    // Upstream keys map entries with field.Key, rendering `spec.hard[cpu]`.
    assert!(
        has(&errs, "spec.hard[cpu]", ErrorType::Invalid),
        "got: {errs:?}"
    );
}

/// #1907 proposed switching every Quantity bad value to the "render unquoted"
/// form that #1903 introduced for `IntOrString`. That would have been wrong in
/// both directions, and this pins why.
///
/// `resource.Quantity` has a `MarshalJSON`, so upstream's `ErrorBody()` renders
/// it through the `default:` arm's `json.Marshal`
/// (`staging/src/k8s.io/apimachinery/pkg/util/validation/field/errors.go:92-97`)
/// and never reaches the `fmt.Stringer` fallback — which is only taken when
/// marshalling *errors*. Running upstream's own `ErrorBody()` on the pinned
/// checkout:
///
/// ```text
/// resource.MustParse("-1")  => Invalid value: "-1": some detail
/// resource.MustParse("2Gi") => Invalid value: "2Gi": some detail
/// ```
///
/// Quoted. Our quantity validators pass the raw string through
/// `BadValue::String`, which quotes, so they were already correct and #1907's
/// change would have broken them. The unquoted form the issue cites comes from
/// the kustomize fork of `field.Error`, not apimachinery.
#[test]
fn a_quantity_bad_value_renders_quoted_in_the_error_body() {
    let errs = validate_resource_quota(&rq(json!({"hard": {"cpu": "-1"}})));
    let e = errs
        .iter()
        .find(|e| e.field == "spec.hard[cpu]")
        .unwrap_or_else(|| panic!("expected a spec.hard[cpu] error, got: {errs:?}"));
    assert_eq!(
        e.error_body(),
        "Invalid value: \"-1\": must be greater than or equal to 0",
        "upstream: `resource.MustParse(\"-1\")` => `Invalid value: \"-1\"`"
    );
}

// Note: a syntactically-invalid hard quantity (e.g. "lots") is rejected at
// deserialization, before this validator runs — so the `Quantity::parse` Err
// arm is a backstop the API path can't reach (not unit-tested via `from_value`).

#[test]
fn unsupported_scope_rejected() {
    let errs = validate_resource_quota(&rq(json!({"hard": {"pods": "1"}, "scopes": ["Bogus"]})));
    assert!(
        has(&errs, "spec.scopes", ErrorType::Invalid),
        "got: {errs:?}"
    );
}

#[test]
fn conflicting_scopes_rejected() {
    let errs = validate_resource_quota(&rq(json!({
        "hard": {"pods": "1"},
        "scopes": ["BestEffort", "NotBestEffort"]
    })));
    assert!(
        errs.iter()
            .any(|e| e.field == "spec.scopes" && e.detail == "conflicting scopes"),
        "got: {errs:?}"
    );
}

#[test]
fn terminating_pair_conflict_rejected() {
    let errs = validate_resource_quota(&rq(json!({
        "scopes": ["Terminating", "NotTerminating"]
    })));
    assert!(
        errs.iter()
            .any(|e| e.field == "spec.scopes" && e.detail == "conflicting scopes"),
        "got: {errs:?}"
    );
}

#[test]
fn priority_class_scope_ok() {
    let errs = validate_resource_quota(&rq(json!({
        "hard": {"pods": "5"},
        "scopes": ["PriorityClass"]
    })));
    assert!(errs.is_empty(), "unexpected errors: {errs:?}");
}

// Ports of TestValidateResourceQuota (validation.go test :21576) scope cases,
// `validateResourceQuotaScopes` / `validateScopedResourceSelectorRequirement`
// (validation.go:7966-8055) and `IsResourceQuotaScopeValidForResource`
// (helpers.go:151-164).

fn details(errs: &[Error]) -> Vec<String> {
    errs.iter().map(|e| e.detail.clone()).collect()
}

#[test]
fn resourcequota_scopes_valid_combinations_pass() {
    for spec in [
        // terminatingSpec / nonTerminatingSpec / nonBestEffortSpec
        json!({"hard": {"cpu": "100", "limits.cpu": "200"}, "scopes": ["Terminating"]}),
        json!({"hard": {"cpu": "100"}, "scopes": ["NotTerminating"]}),
        json!({"hard": {"cpu": "100"}, "scopes": ["NotBestEffort"]}),
        // bestEffortSpec: only pods count
        json!({"hard": {"pods": "100"}, "scopes": ["BestEffort"]}),
        // crossNamespaceAffinitySpec
        json!({"hard": {"cpu": "100", "limits.cpu": "200"}, "scopes": ["CrossNamespacePodAffinity"]}),
        // scopeSelectorSpec (PriorityClass In)
        json!({"scopeSelector": {"matchExpressions": [
            {"scopeName": "PriorityClass", "operator": "In", "values": ["cluster-services"]}]}}),
        // VolumeAttributesClass applies to PVC count and storage only
        json!({"hard": {"persistentvolumeclaims": "1", "requests.storage": "1Gi"},
               "scopes": ["VolumeAttributesClass"]}),
        // unknown (non-standard) resource names are not checked against scopes
        json!({"hard": {"example.com/foo": "1"}, "scopes": ["BestEffort"]}),
    ] {
        let errs = validate_resource_quota(&rq(spec.clone()));
        assert!(errs.is_empty(), "{spec}: {errs:?}");
    }
}

#[test]
fn resourcequota_scopes_resource_not_valid_for_scope() {
    // BestEffort covers only pods; cpu is a pod compute resource.
    let errs =
        validate_resource_quota(&rq(json!({"hard": {"cpu": "1"}, "scopes": ["BestEffort"]})));
    assert!(
        errs.iter().any(|e| e.field == "spec.scopes"
            && e.error_type == ErrorType::Invalid
            && e.detail == "unsupported scope applied to resource"),
        "{errs:?}"
    );
    // VolumeAttributesClass does not cover pods.
    let errs = validate_resource_quota(&rq(
        json!({"hard": {"pods": "1"}, "scopes": ["VolumeAttributesClass"]}),
    ));
    assert!(
        details(&errs).contains(&"unsupported scope applied to resource".to_string()),
        "{errs:?}"
    );
    // Pod scopes do not cover services.
    let errs = validate_resource_quota(&rq(
        json!({"hard": {"services": "1"}, "scopes": ["Terminating"]}),
    ));
    assert!(
        details(&errs).contains(&"unsupported scope applied to resource".to_string()),
        "{errs:?}"
    );
}

#[test]
fn resourcequota_scopes_selector_resource_not_valid_for_scope() {
    let errs = validate_resource_quota(&rq(json!({
        "hard": {"services": "1"},
        "scopeSelector": {"matchExpressions": [{"scopeName": "NotBestEffort", "operator": "Exists"}]}
    })));
    assert!(
        errs.iter()
            .any(|e| e.field == "spec.scopeSelector.matchExpressions"
                && e.detail == "unsupported scope applied to resource"),
        "{errs:?}"
    );
}

#[test]
fn resourcequota_scopes_volume_attributes_class_is_a_standard_scope() {
    let errs = validate_resource_quota(&rq(json!({"scopes": ["VolumeAttributesClass"]})));
    assert!(errs.is_empty(), "{errs:?}");
    let errs = validate_resource_quota(&rq(json!({"scopes": ["Bogus"]})));
    assert!(
        errs.iter()
            .any(|e| e.field == "spec.scopes" && e.detail == "unsupported scope"),
        "{errs:?}"
    );
}

#[test]
fn resourcequota_scopes_selector_operator_rules() {
    let sel = |scope: &str, op: &str, values: serde_json::Value| {
        validate_resource_quota(&rq(json!({"scopeSelector": {"matchExpressions": [
            {"scopeName": scope, "operator": op, "values": values}]}})))
    };
    // invalid-cross-namespace-affinity
    let errs = sel("CrossNamespacePodAffinity", "In", json!(["a"]));
    assert!(
        errs.iter().any(
            |e| e.field == "spec.scopeSelector.matchExpressions.operator"
                && e.detail
                    .starts_with("must be 'Exists' when scope is any of")
        ),
        "{errs:?}"
    );
    // In/NotIn need values.
    let errs = sel("PriorityClass", "NotIn", json!([]));
    assert!(
        errs.iter().any(|e| e.error_type == ErrorType::Required
            && e.field == "spec.scopeSelector.matchExpressions.values"
            && e.detail
                == "must be at least one value when `operator` is 'In' or 'NotIn' for scope selector"),
        "{errs:?}"
    );
    // Exists/DoesNotExist take no values.
    let errs = sel("PriorityClass", "DoesNotExist", json!(["a"]));
    assert!(
        details(&errs).contains(
            &"must be no value when `operator` is 'Exist' or 'DoesNotExist' for scope selector"
                .to_string()
        ),
        "{errs:?}"
    );
    // Unknown operator.
    let errs = sel("PriorityClass", "Gt", json!(["1"]));
    assert!(
        errs.iter().any(
            |e| e.field == "spec.scopeSelector.matchExpressions.operator"
                && e.detail == "not a valid selector operator"
        ),
        "{errs:?}"
    );
}

#[test]
fn resourcequota_scopes_selector_conflicting_scopes() {
    let errs = validate_resource_quota(&rq(json!({"scopeSelector": {"matchExpressions": [
        {"scopeName": "Terminating", "operator": "Exists"},
        {"scopeName": "NotTerminating", "operator": "Exists"}]}})));
    assert!(
        errs.iter()
            .any(|e| e.field == "spec.scopeSelector.matchExpressions"
                && e.detail == "conflicting scopes"),
        "{errs:?}"
    );
}
