//! Ported from `authorization/cel/compile_test.go` (TestCompileCELExpression,
//! TestBuildRequestType): the typed `request` environment authorization
//! `matchConditions` compile against, on the cel-go checker port.
use kubernetes_rs_cel_checker::DType;
use kubernetes_rs_common::cel_authz::{
    build_non_resource_attributes_type, build_request_type, build_resource_attributes_type,
    check_authorization_compile, check_authorization_expression,
};
use kubernetes_rs_common::cel_versions::{self, EnvSet};

fn set() -> EnvSet {
    EnvSet::must_base_env_set(cel_versions::default_compatibility_version())
}

fn compile(expr: &str, selectors: bool) -> Result<(), String> {
    check_authorization_compile(&set(), selectors, expr)
}

#[test]
fn cel_typed_env_compile_cel_expression() {
    // (name, expression, expected error substring, AuthorizeWithSelectors)
    let cases: &[(&str, &str, &str, bool)] = &[
        ("SubjectAccessReviewSpec user comparison", "request.user == 'bob'", "", false),
        ("undefined fields", "request.time == 'now'", "undefined field", false),
        ("bad return type", "request.user", "must evaluate to bool", false),
        ("undeclared reference", "x.user", "undeclared reference", false),
        (
            "fieldSelector not enabled",
            "request.resourceAttributes.fieldSelector.rawSelector == 'foo'",
            "undefined field 'fieldSelector'",
            false,
        ),
        (
            "fieldSelector rawSelector",
            "request.resourceAttributes.fieldSelector.rawSelector == 'foo'",
            "",
            true,
        ),
        (
            "fieldSelector requirement",
            "request.resourceAttributes.fieldSelector.requirements.exists(r, r.key == 'foo' && r.operator == 'In' && ('bar' in r.values))",
            "",
            true,
        ),
        (
            "labelSelector not enabled",
            "request.resourceAttributes.labelSelector.rawSelector == 'foo'",
            "undefined field 'labelSelector'",
            false,
        ),
        (
            "labelSelector rawSelector",
            "request.resourceAttributes.labelSelector.rawSelector == 'foo'",
            "",
            true,
        ),
        (
            "labelSelector requirement",
            "request.resourceAttributes.labelSelector.requirements.exists(r, r.key == 'foo' && r.operator == 'In' && ('bar' in r.values))",
            "",
            true,
        ),
    ];
    for (name, expr, want, selectors) in cases {
        let got = compile(expr, *selectors);
        if want.is_empty() {
            assert!(got.is_ok(), "{name}: unexpected error {got:?}");
        } else {
            let e = got.expect_err(name);
            assert!(e.contains(want), "{name}: expected {want:?} in {e:?}");
        }
    }
    // Syntax errors are a compile failure, not a type error.
    assert!(compile("request++'", false)
        .unwrap_err()
        .contains("compilation failed"));
    assert!(check_authorization_expression(&set(), false, "request++'").is_none());
}

#[test]
fn cel_typed_env_request_type_matches_subject_access_review_spec() {
    assert_eq!(
        build_request_type(true).dtype(),
        DType::Struct("kubernetes.SubjectAccessReviewSpec".into())
    );
    assert_eq!(
        build_resource_attributes_type(false).dtype(),
        DType::Struct("kubernetes.ResourceAttributes".into())
    );
    assert_eq!(
        build_non_resource_attributes_type().dtype(),
        DType::Struct("kubernetes.NonResourceAttributes".into())
    );
    // Every json field of authorization/v1 SubjectAccessReviewSpec,
    // ResourceAttributes and NonResourceAttributes resolves, with its type.
    let ok = |e: &str| compile(e, true).unwrap_or_else(|m| panic!("{e}: {m}"));
    ok("request.user == '' && request.uid == ''");
    ok("request.groups.all(g, g.startsWith('system:'))");
    ok("request.extra['a'].exists(v, v == 'b')");
    ok("request.resourceAttributes.namespace == '' && request.resourceAttributes.verb == '' && request.resourceAttributes.group == '' && request.resourceAttributes.version == '' && request.resourceAttributes.resource == '' && request.resourceAttributes.subresource == '' && request.resourceAttributes.name == ''");
    ok("request.nonResourceAttributes.path == '' && request.nonResourceAttributes.verb == ''");
    // Field types are checked, not dyn.
    assert!(compile("request.user == 1", true).is_err());
    assert!(compile("request.groups == 'x'", true).is_err());
    assert!(compile("request.nonResourceAttributes.path.foo == 'x'", true).is_err());
    // The selector fields are gated.
    assert!(compile(
        "request.resourceAttributes.fieldSelector.rawSelector == ''",
        false
    )
    .is_err());
    assert!(compile(
        "request.resourceAttributes.fieldSelector.rawSelector == ''",
        true
    )
    .is_ok());
}

#[test]
fn cel_typed_env_only_request_is_declared() {
    for v in [
        "object",
        "oldObject",
        "params",
        "variables",
        "authorizer",
        "namespaceObject",
    ] {
        let e = compile(&format!("{v} == null"), false).unwrap_err();
        assert!(e.contains("undeclared reference"), "{v}: {e}");
    }
}

#[test]
fn cel_typed_env_field_counts_match_authorization_v1() {
    // TestBuildRequestType: one decl field per json field of the v1 types.
    let n = |t: kubernetes_rs_cel_checker::decl::DeclType| t.fields().unwrap().len();
    assert_eq!(n(build_request_type(true)), 6);
    assert_eq!(n(build_resource_attributes_type(true)), 9);
    assert_eq!(n(build_resource_attributes_type(false)), 7);
    assert_eq!(n(build_non_resource_attributes_type()), 2);
}

// Shadow comparison (`KUBERNETES_RS_CEL_CHECKER=shadow`): the divergence
// helper reports exactly the accept/reject disagreements.
#[test]
fn cel_typed_env_shadow_divergence_reports_only_disagreements() {
    use kubernetes_rs_common::cel_authz::{
        authorization_divergence, compile_authorization_expression,
    };
    let s = set();
    for expr in [
        "request.user == 'bob'",
        "request.time == 'now'",
        "request.user",
        "x.user",
    ] {
        let hand = compile_authorization_expression(expr);
        // Whatever the hand-rolled compile says must agree with the checker on
        // these upstream compile_test.go cases.
        assert_eq!(
            authorization_divergence(&s, false, expr, &hand),
            None,
            "{expr}"
        );
    }
    // A forged hand-rolled verdict is reported in both directions.
    let ok = compile_authorization_expression("request.user == 'bob'");
    assert!(authorization_divergence(&s, false, "request.time == 'now'", &ok).is_some());
    let err = Err("compilation failed: forged".to_string());
    let d = authorization_divergence(&s, false, "request.user == 'bob'", &err).unwrap();
    assert_eq!(d.0.as_deref(), Some("compilation failed: forged"));
    assert_eq!(d.1, None);
}
