//! `rules.Matcher`: does an admission request match a webhook
//! `RuleWithOperations`?
//!
//! Port of `staging/src/k8s.io/apiserver/pkg/admission/plugin/webhook/predicates/rules/rules.go`
//! (release-1.35): `Matcher.Matches` (:36), `scope` (:56), `group`, `version`,
//! `operation` (:85), `splitResource` + `resource` (:100) and
//! `IsExemptAdmissionConfigurationResource` (:122). The tests port
//! `rules_test.go` (TestGroup, TestVersion, TestOperation, TestResource,
//! TestScope). Unlike the hand-rolled matcher in `lib.rs`, the subresource is
//! its own attribute (not folded into the resource name) and the scope check
//! knows the `namespaces` resource is cluster-scoped.

use kubernetes_rs_common::admission::Operation;
use kubernetes_rs_common::resources::{OperationType, RuleWithOperations};

/// The slice of `admission.Attributes` the rule matcher reads.
#[derive(Debug, Clone)]
pub struct RuleAttributes {
    pub group: String,
    pub version: String,
    /// `GetResource().Resource`, without the subresource.
    pub resource: String,
    /// `GetSubresource()`.
    pub subresource: String,
    /// `GetNamespace()`; empty is `metav1.NamespaceNone`.
    pub namespace: String,
    pub operation: Operation,
}

/// `Matcher.Matches` (rules.go:36).
pub fn matches(rule: &RuleWithOperations, attr: &RuleAttributes) -> bool {
    scope(rule, attr)
        && operation(rule, attr)
        && group(rule, attr)
        && version(rule, attr)
        && resource(rule, attr)
}

/// `exactOrWildcard` (rules.go:44).
fn exact_or_wildcard(items: &[String], requested: &str) -> bool {
    items.iter().any(|i| i == "*" || i == requested)
}

/// `namespaceResource` (rules.go:55): Namespace objects are cluster-scoped
/// although their `attr.namespace` is the namespace's own name.
fn is_namespace_resource(attr: &RuleAttributes) -> bool {
    attr.group.is_empty() && attr.version == "v1" && attr.resource == "namespaces"
}

/// `Matcher.scope` (rules.go:56). An unknown scope matches nothing.
pub fn scope(rule: &RuleWithOperations, attr: &RuleAttributes) -> bool {
    match rule.rule.scope.as_deref() {
        None | Some("*") => true,
        Some("Namespaced") => !is_namespace_resource(attr) && !attr.namespace.is_empty(),
        Some("Cluster") => is_namespace_resource(attr) || attr.namespace.is_empty(),
        Some(_) => false,
    }
}

/// `Matcher.group` (rules.go:73).
pub fn group(rule: &RuleWithOperations, attr: &RuleAttributes) -> bool {
    exact_or_wildcard(&rule.rule.api_groups, &attr.group)
}

/// `Matcher.version` (rules.go:77).
pub fn version(rule: &RuleWithOperations, attr: &RuleAttributes) -> bool {
    exact_or_wildcard(&rule.rule.api_versions, &attr.version)
}

/// `Matcher.operation` (rules.go:85): `OperationAll` or the same operation.
pub fn operation(rule: &RuleWithOperations, attr: &RuleAttributes) -> bool {
    rule.operations.iter().any(|op| {
        matches!(
            (op, &attr.operation),
            (OperationType::All, _)
                | (OperationType::Create, Operation::Create)
                | (OperationType::Update, Operation::Update)
                | (OperationType::Delete, Operation::Delete)
                | (OperationType::Connect, Operation::Connect)
        )
    })
}

/// `splitResource` (rules.go:100): `strings.SplitN(resSub, "/", 2)`.
fn split_resource(res_sub: &str) -> (&str, &str) {
    res_sub.split_once('/').unwrap_or((res_sub, ""))
}

/// `Matcher.resource` (rules.go:108): `res`, `res/sub`, `res/*`, `*/sub`, `*/*`.
pub fn resource(rule: &RuleWithOperations, attr: &RuleAttributes) -> bool {
    rule.rule.resources.iter().any(|res_sub| {
        let (res, sub) = split_resource(res_sub);
        (res == "*" || res == attr.resource) && (sub == "*" || sub == attr.subresource)
    })
}

/// `IsExemptAdmissionConfigurationResource` (rules.go:122): webhook and policy
/// configuration kinds are never sent to webhooks.
pub fn is_exempt_admission_configuration_resource(group: &str, kind: &str) -> bool {
    group == "admissionregistration.k8s.io"
        && matches!(
            kind,
            "ValidatingWebhookConfiguration"
                | "MutatingWebhookConfiguration"
                | "ValidatingAdmissionPolicy"
                | "ValidatingAdmissionPolicyBinding"
                | "MutatingAdmissionPolicy"
                | "MutatingAdmissionPolicyBinding"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kubernetes_rs_common::resources::Rule;

    fn rule(
        ops: &[OperationType],
        groups: &[&str],
        versions: &[&str],
        resources: &[&str],
        scope: Option<&str>,
    ) -> RuleWithOperations {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        RuleWithOperations {
            operations: ops.to_vec(),
            rule: Rule {
                api_groups: s(groups),
                api_versions: s(versions),
                resources: s(resources),
                scope: scope.map(str::to_string),
            },
        }
    }

    fn a(g: &str, v: &str, r: &str, sub: &str, ns: &str, op: Operation) -> RuleAttributes {
        RuleAttributes {
            group: g.into(),
            version: v.into(),
            resource: r.into(),
            subresource: sub.into(),
            namespace: ns.into(),
            operation: op,
        }
    }
    fn ns_(g: &str, v: &str, r: &str, sub: &str) -> RuleAttributes {
        a(g, v, r, sub, "ns", Operation::Create)
    }
    fn cl(g: &str, v: &str, r: &str, sub: &str) -> RuleAttributes {
        a(g, v, r, sub, "", Operation::Create)
    }
    fn c(g: &str, v: &str, r: &str, sub: &str) -> RuleAttributes {
        ns_(g, v, r, sub)
    }

    /// rules_test.go TestGroup.
    #[test]
    fn rules_matcher_group() {
        let w = rule(&[], &["*"], &[], &[], None);
        assert!(group(&w, &c("g", "v", "r", "")));
        let e = rule(&[], &["g1", "g2"], &[], &[], None);
        assert!(group(&e, &c("g1", "v", "r", "")));
        assert!(group(&e, &c("g2", "v2", "r3", "")));
        assert!(!group(&e, &c("g3", "v", "r", "")));
        assert!(!group(&e, &c("g4", "v", "r", "")));
    }

    /// rules_test.go TestVersion.
    #[test]
    fn rules_matcher_version() {
        let w = rule(&[], &[], &["*"], &[], None);
        assert!(version(&w, &c("g", "v", "r", "")));
        let e = rule(&[], &[], &["v1", "v2"], &[], None);
        assert!(version(&e, &c("g", "v1", "r", "")));
        assert!(version(&e, &c("g2", "v2", "r3", "")));
        assert!(!version(&e, &c("g", "v3", "r", "")));
        // No versions listed matches nothing.
        assert!(!version(
            &rule(&[], &[], &[], &[], None),
            &c("g", "v", "r", "")
        ));
    }

    /// rules_test.go TestOperation.
    #[test]
    fn rules_matcher_operation() {
        use Operation::*;
        let all = [Create, Update, Delete, Connect];
        let cases: Vec<(Vec<OperationType>, Vec<Operation>)> = vec![
            (vec![OperationType::All], all.to_vec()),
            (vec![OperationType::Create], vec![Create]),
            (vec![OperationType::Update], vec![Update]),
            (vec![OperationType::Delete], vec![Delete]),
            (vec![OperationType::Connect], vec![Connect]),
            (
                vec![OperationType::Update, OperationType::Delete],
                vec![Update, Delete],
            ),
        ];
        for (ops, matching) in cases {
            let r = rule(&ops, &[], &[], &[], None);
            for o in all.clone() {
                let got = operation(&r, &a("g", "v", "r", "", "ns", o.clone()));
                assert_eq!(got, matching.contains(&o), "{ops:?} vs {o:?}");
            }
        }
    }

    /// rules_test.go TestResource.
    #[test]
    fn rules_matcher_resource() {
        let m =
            |res: &[&str], attr: RuleAttributes| resource(&rule(&[], &[], &[], res, None), &attr);
        // "no subresources": `*` matches the resource only, any resource.
        assert!(m(&["*"], c("g", "v", "r", "")));
        assert!(m(&["*"], c("2", "v", "r2", "")));
        assert!(!m(&["*"], c("g", "v", "r", "exec")));
        assert!(!m(&["*"], c("2", "v", "r2", "proxy")));
        // "r & subresources".
        assert!(m(&["r/*"], c("g", "v", "r", "")));
        assert!(m(&["r/*"], c("g", "v", "r", "exec")));
        assert!(!m(&["r/*"], c("2", "v", "r2", "")));
        assert!(!m(&["r/*"], c("2", "v", "r2", "proxy")));
        // "r & subresources or r2".
        assert!(m(&["r/*", "r2"], c("2", "v", "r2", "")));
        assert!(!m(&["r/*", "r2"], c("2", "v", "r2", "proxy")));
        // "proxy or exec".
        let pe = ["*/proxy", "*/exec"];
        assert!(m(&pe, c("g", "v", "r", "exec")));
        assert!(m(&pe, c("2", "v", "r3", "proxy")));
        assert!(!m(&pe, c("g", "v", "r", "")));
        assert!(!m(&pe, c("2", "v", "r4", "scale")));
        // `*/*` matches everything.
        assert!(m(&["*/*"], c("g", "v", "r", "scale")));
    }

    /// rules_test.go TestScope.
    #[test]
    fn rules_matcher_scope() {
        let cluster = rule(&[], &[], &[], &["*"], Some("Cluster"));
        assert!(scope(&cluster, &cl("g", "v", "r", "")));
        assert!(scope(&cluster, &cl("g", "v", "r", "exec")));
        assert!(scope(&cluster, &cl("", "v1", "namespaces", "")));
        assert!(scope(&cluster, &cl("", "v1", "namespaces", "finalize")));
        assert!(scope(&cluster, &ns_("", "v1", "namespaces", "")));
        assert!(scope(&cluster, &ns_("", "v1", "namespaces", "finalize")));
        assert!(!scope(&cluster, &ns_("g", "v", "r", "")));
        assert!(!scope(&cluster, &ns_("g", "v", "r", "exec")));

        let namespaced = rule(&[], &[], &[], &["*"], Some("Namespaced"));
        assert!(scope(&namespaced, &ns_("g", "v", "r", "")));
        assert!(scope(&namespaced, &ns_("g", "v", "r", "exec")));
        assert!(!scope(&namespaced, &cl("", "v1", "namespaces", "")));
        assert!(!scope(&namespaced, &cl("", "v1", "namespaces", "finalize")));
        assert!(!scope(&namespaced, &ns_("", "v1", "namespaces", "")));
        assert!(!scope(
            &namespaced,
            &ns_("", "v1", "namespaces", "finalize")
        ));
        assert!(!scope(&namespaced, &cl("g", "v", "r", "")));
        assert!(!scope(&namespaced, &cl("g", "v", "r", "exec")));

        for s in [Some("*"), None] {
            let all = rule(&[], &[], &[], &["*"], s);
            assert!(scope(&all, &ns_("g", "v", "r", "")));
            assert!(scope(&all, &cl("g", "v", "r", "exec")));
            assert!(scope(&all, &ns_("", "v1", "namespaces", "finalize")));
        }
        // rules.go:67 default: an unknown scope matches nothing.
        let bogus = rule(&[], &[], &[], &["*"], Some("Bogus"));
        assert!(!scope(&bogus, &ns_("g", "v", "r", "")));
    }

    #[test]
    fn rules_matcher_matches_requires_all_predicates() {
        use OperationType::*;
        let r = rule(
            &[Create],
            &["apps"],
            &["v1"],
            &["deployments/scale"],
            Some("Namespaced"),
        );
        assert!(matches(&r, &ns_("apps", "v1", "deployments", "scale")));
        assert!(!matches(&r, &ns_("apps", "v1", "deployments", "")));
        assert!(!matches(&r, &ns_("apps", "v2", "deployments", "scale")));
        assert!(!matches(
            &r,
            &a(
                "apps",
                "v1",
                "deployments",
                "scale",
                "ns",
                Operation::Update
            )
        ));
    }

    /// rules.go:122.
    #[test]
    fn rules_matcher_exempt_configuration_resources() {
        for k in [
            "ValidatingWebhookConfiguration",
            "MutatingWebhookConfiguration",
            "ValidatingAdmissionPolicy",
            "ValidatingAdmissionPolicyBinding",
            "MutatingAdmissionPolicy",
            "MutatingAdmissionPolicyBinding",
        ] {
            assert!(is_exempt_admission_configuration_resource(
                "admissionregistration.k8s.io",
                k
            ));
            assert!(!is_exempt_admission_configuration_resource(
                "example.com",
                k
            ));
        }
        assert!(!is_exempt_admission_configuration_resource(
            "admissionregistration.k8s.io",
            "Pod"
        ));
    }
}
