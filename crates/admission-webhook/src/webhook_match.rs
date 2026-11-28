//! Webhook `matchConditions` evaluation with upstream's metrics and
//! failurePolicy handling.
//!
//! Port of `Match` in
//! `staging/src/k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions/matcher.go:84-143`
//! (release-1.35), with its caller in
//! `.../plugin/webhook/generic/webhook.go:224-240` (`ShouldCallHook`):
//!
//! * every condition is evaluated in order; a condition error is counted
//!   (`ObserveMatchConditionEvalError`) and evaluation CONTINUES;
//! * the first `false` stops evaluation, observes the evaluation time and
//!   skips the webhook whatever the failurePolicy;
//! * otherwise, with errors collected: observe the time, then
//!   `failurePolicy: Fail` fails the request closed (`Forbidden`) and
//!   `Ignore` skips the webhook;
//! * a skipped webhook observes `ObserveMatchConditionExclusion`; the
//!   all-`true` path observes nothing.

use std::time::Instant;

use kubernetes_rs_common::admission::AdmissionRequest;
use kubernetes_rs_common::cel::CELEvaluator;
use kubernetes_rs_common::cel_cost::{
    charge_budget, CostOptions, RUNTIME_CEL_COST_BUDGET_MATCH_CONDITIONS,
};
use kubernetes_rs_common::resources::admission_webhook::MatchCondition;
use kubernetes_rs_common::resources::FailurePolicy;

use crate::admission_metrics::{
    observe_match_condition_eval_error, observe_match_condition_evaluation_time,
    observe_match_condition_exclusion, operation_label, KIND_WEBHOOK,
};
use crate::cel_evaluators::build_context;

/// `matching.Matcher.MatchObjectSelector`
/// (`staging/src/k8s.io/apiserver/pkg/admission/plugin/webhook/predicates/object/matcher.go:46-59`,
/// `matchObject` :61-72): an empty selector matches; otherwise the selector
/// is tried against the NEW object's labels and then the OLD object's
/// (`LabelSelectorAsSelector`, so `matchExpressions` count); a nil object
/// never matches. A selector that does not parse is an `InternalError` for
/// the request (`apierrors.NewInternalError`), never a silent skip.
pub fn match_object_selector(
    selector: Option<&serde_json::Value>,
    object: Option<&serde_json::Value>,
    old_object: Option<&serde_json::Value>,
) -> Result<bool, String> {
    let Some(sel) = selector else {
        return Ok(true);
    };
    // The webhook configuration and the shared types carry distinct
    // `LabelSelector` structs with the same wire form.
    let sel: kubernetes_rs_common::types::LabelSelector =
        serde_json::from_value(sel.clone()).map_err(|e| e.to_string())?;
    let sel = &sel;
    let parsed = kubernetes_rs_common::types::label_selector_as_selector(Some(sel))
        .map_err(|e| e.to_string())?;
    if parsed.is_everything() {
        return Ok(true);
    }
    let matches_object = |obj: Option<&serde_json::Value>| -> bool {
        let Some(obj) = obj else { return false };
        let labels: std::collections::HashMap<String, String> = obj
            .pointer("/metadata/labels")
            .and_then(|l| l.as_object())
            .map(|l| {
                l.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        parsed.matches(Some(&labels))
    };
    Ok(matches_object(object) || matches_object(old_object))
}

/// What `ShouldCallHook` does with the webhook after its match conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookMatch {
    /// Call the webhook.
    Matches,
    /// Skip the webhook (`return nil, nil`, webhook.go:235-238).
    Excluded,
    /// Fail the request closed with a `Forbidden` carrying this message
    /// (webhook.go:231-234).
    Forbidden(String),
}

/// `matcher.Match` + the `ShouldCallHook` branch on its result. `step_type`
/// is the accessor's `GetType()`: `"admit"` for mutating, `"validate"` for
/// validating webhooks (webhook/accessors.go:129, :296).
pub fn match_webhook_conditions(
    name: &str,
    step_type: &str,
    conditions: &[MatchCondition],
    failure_policy: Option<&FailurePolicy>,
    request: &AdmissionRequest,
) -> WebhookMatch {
    if conditions.is_empty() {
        return WebhookMatch::Matches;
    }
    // NewMatcher: a nil failurePolicy is Fail (matcher.go:65-69).
    let policy = failure_policy.unwrap_or(&FailurePolicy::Fail);
    let op = operation_label(&request.operation);
    let observe_time = |t: Instant| {
        observe_match_condition_evaluation_time(t.elapsed(), name, KIND_WEBHOOK, step_type, op)
    };
    let t = Instant::now();

    let result = match_inner(
        name,
        step_type,
        conditions,
        policy,
        request,
        &observe_time,
        t,
    );
    match result {
        Inner::Matches => WebhookMatch::Matches,
        Inner::Excluded => {
            observe_match_condition_exclusion(name, KIND_WEBHOOK, step_type, op);
            WebhookMatch::Excluded
        }
        Inner::Error(msg) => WebhookMatch::Forbidden(msg),
    }
}

/// `apierrors.NewForbidden(qualifiedResource, name, err)` message
/// (staging/src/k8s.io/apimachinery/pkg/api/errors/errors.go:209-217), as
/// `ShouldCallHook` builds it from `attr.GetResource().GroupResource()` and
/// `attr.GetName()` (webhook.go:231-234).
pub fn forbidden_message(group: &str, resource: &str, name: &str, err: &str) -> String {
    // GroupResource.String() (runtime/schema/group_version.go:62).
    let qualified = if group.is_empty() {
        resource.to_string()
    } else {
        format!("{resource}.{group}")
    };
    if qualified.is_empty() {
        format!("forbidden: {err}")
    } else if name.is_empty() {
        format!("{qualified} is forbidden: {err}")
    } else {
        format!("{qualified} \"{name}\" is forbidden: {err}")
    }
}

/// `utilerrors.NewAggregate(errs).Error()`
/// (apimachinery/pkg/util/errors/errors.go:70-96): one error is its message;
/// several are their distinct messages joined by ", " inside brackets.
fn aggregate(errors: &[String]) -> String {
    if let [one] = errors {
        return one.clone();
    }
    let mut seen: Vec<&str> = Vec::new();
    for e in errors {
        if !seen.contains(&e.as_str()) {
            seen.push(e);
        }
    }
    if seen.len() == 1 {
        seen[0].to_string()
    } else {
        format!("[{}]", seen.join(", "))
    }
}

enum Inner {
    Matches,
    Excluded,
    Error(String),
}

fn match_inner(
    name: &str,
    step_type: &str,
    conditions: &[MatchCondition],
    policy: &FailurePolicy,
    request: &AdmissionRequest,
    observe_time: &dyn Fn(Instant),
    t: Instant,
) -> Inner {
    let op = operation_label(&request.operation);
    let context = match build_context(request, None) {
        Ok(c) => c,
        Err(e) => {
            // matcher.go:88-103: the filter itself failing is not an
            // evaluation error, so no error metric.
            observe_time(t);
            return match policy {
                FailurePolicy::Fail => Inner::Error(e.to_string()),
                FailurePolicy::Ignore => Inner::Excluded,
                // No default branch upstream: falls through with no results.
                FailurePolicy::Unknown(_) => Inner::Matches,
            };
        }
    };

    // condition.go:90-111 `ForInput`: EVERY condition is evaluated first,
    // each charged against `RuntimeCELCostBudgetMatchConditions`; running out
    // returns `nil, -1, err` (no results), which `Match` treats as the filter
    // failing (matcher.go:86-103).
    let mut evaluator = CELEvaluator::new();
    let mut remaining = RUNTIME_CEL_COST_BUDGET_MATCH_CONDITIONS;
    let mut results: Vec<(&MatchCondition, Result<bool, String>)> = Vec::new();
    for cond in conditions {
        if cond.expression.trim().is_empty() {
            continue;
        }
        // Each expression runs under the per-call limit
        // (`environment/base.go:83`, `CostOptions::default`).
        let (value, cost) =
            evaluator.evaluate_with_cost(&cond.expression, &context, CostOptions::default());
        remaining = match charge_budget(None, cost, remaining) {
            Ok(r) => r,
            Err(e) => {
                observe_time(t);
                return match policy {
                    FailurePolicy::Fail => Inner::Error(e.detail),
                    FailurePolicy::Ignore => Inner::Excluded,
                    FailurePolicy::Unknown(_) => Inner::Matches,
                };
            }
        };
        results.push((
            cond,
            match value {
                Ok(cel::Value::Bool(b)) => Ok(b),
                Ok(other) => Err(format!(
                    "matchCondition '{}' (expression: {}) failed: expression resulted in non-bool value: {other:?}",
                    cond.name, cond.expression
                )),
                Err(e) => Err(format!(
                    "matchCondition '{}' (expression: {}) failed: {}",
                    cond.name, cond.expression, e
                )),
            },
        ));
    }

    let mut errors: Vec<String> = Vec::new();
    for (_, result) in results {
        match result {
            Err(e) => {
                errors.push(e);
                observe_match_condition_eval_error(name, KIND_WEBHOOK, step_type, op);
            }
            // matcher.go:111-117: any false skips the webhook always.
            Ok(false) => {
                observe_time(t);
                return Inner::Excluded;
            }
            Ok(true) => {}
        }
    }
    if !errors.is_empty() {
        // matcher.go:118-135: a mix of true and errors resorts to failurePolicy.
        observe_time(t);
        return match policy {
            FailurePolicy::Fail => Inner::Error(aggregate(&errors)),
            FailurePolicy::Ignore => Inner::Excluded,
            FailurePolicy::Unknown(_) => Inner::Matches,
        };
    }
    Inner::Matches
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ports of predicates/object/matcher_test.go TestMatcher: new object,
    // old object, matchExpressions, nil objects and an empty selector.
    fn sel(v: serde_json::Value) -> serde_json::Value {
        v
    }
    fn obj(labels: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"metadata": {"labels": labels}})
    }

    #[test]
    fn object_selector_empty_matches_everything_even_nil_objects() {
        assert_eq!(match_object_selector(None, None, None), Ok(true));
        assert_eq!(
            match_object_selector(Some(&sel(serde_json::json!({}))), None, None),
            Ok(true)
        );
    }

    #[test]
    fn object_selector_nil_objects_never_match_a_non_empty_selector() {
        let s = sel(serde_json::json!({"matchLabels": {"a": "b"}}));
        assert_eq!(match_object_selector(Some(&s), None, None), Ok(false));
    }

    #[test]
    fn object_selector_new_or_old_object_labels() {
        let s = sel(serde_json::json!({"matchLabels": {"a": "b"}}));
        let with = obj(serde_json::json!({"a": "b"}));
        let without = obj(serde_json::json!({"a": "other"}));
        assert_eq!(match_object_selector(Some(&s), Some(&with), None), Ok(true));
        // label removed by the update: the old object still selects it
        assert_eq!(
            match_object_selector(Some(&s), Some(&without), Some(&with)),
            Ok(true)
        );
        // DELETE: object nil, old object carries the labels
        assert_eq!(match_object_selector(Some(&s), None, Some(&with)), Ok(true));
        assert_eq!(
            match_object_selector(Some(&s), Some(&without), Some(&without)),
            Ok(false)
        );
    }

    #[test]
    fn object_selector_match_expressions_are_honoured() {
        let s = sel(serde_json::json!({"matchExpressions": [
            {"key": "tier", "operator": "In", "values": ["web", "api"]},
            {"key": "skip", "operator": "DoesNotExist"}
        ]}));
        assert_eq!(
            match_object_selector(
                Some(&s),
                Some(&obj(serde_json::json!({"tier": "web"}))),
                None
            ),
            Ok(true)
        );
        assert_eq!(
            match_object_selector(
                Some(&s),
                Some(&obj(serde_json::json!({"tier": "web", "skip": "1"}))),
                None
            ),
            Ok(false)
        );
        assert_eq!(
            match_object_selector(
                Some(&s),
                Some(&obj(serde_json::json!({"tier": "db"}))),
                None
            ),
            Ok(false)
        );
    }

    // Security: an unparsable selector is an error (InternalError upstream),
    // never a silent non-match.
    #[test]
    fn object_selector_invalid_selector_is_an_error() {
        let s = sel(serde_json::json!({"matchExpressions": [
            {"key": "k", "operator": "Bogus"}
        ]}));
        assert!(match_object_selector(Some(&s), Some(&obj(serde_json::json!({}))), None).is_err());
    }
    use kubernetes_rs_common::admission::{GroupVersionKind, UserInfo};

    #[test]
    fn forbidden_message_matches_new_forbidden() {
        // errors.go:216: `<group-resource> "<name>" is forbidden: <err>`,
        // GroupResource.String() being `resource.group` outside core.
        assert_eq!(
            forbidden_message("apps", "deployments", "d", "boom"),
            "deployments.apps \"d\" is forbidden: boom"
        );
        assert_eq!(
            forbidden_message("", "configmaps", "c", "boom"),
            "configmaps \"c\" is forbidden: boom"
        );
        // errors.go:213-214: no name, no quoted name.
        assert_eq!(
            forbidden_message("apps", "deployments", "", "boom"),
            "deployments.apps is forbidden: boom"
        );
    }

    fn request() -> AdmissionRequest {
        crate::build_admission_request_for_match(
            &kubernetes_rs_common::admission::Operation::Create,
            &GroupVersionKind {
                group: String::new(),
                version: "v1".into(),
                kind: "ConfigMap".into(),
            },
            Some("default"),
            "c",
            Some(&serde_json::json!({"metadata": {"name": "c"}})),
            None,
            Some(&UserInfo {
                username: "u".into(),
                uid: "1".into(),
                groups: vec![],
            }),
        )
    }

    fn cond(name: &str, expr: &str) -> MatchCondition {
        MatchCondition {
            name: name.into(),
            expression: expr.into(),
        }
    }

    /// `utilerrors.NewAggregate(...).Error()` (util/errors/errors.go:70-96):
    /// several distinct errors are `[a, b]`; a single one is bare.
    #[test]
    fn several_errors_are_an_aggregate_in_brackets() {
        let conds = [
            cond("a", "object.metadata.nosuch1 == 'x'"),
            cond("b", "object.metadata.nosuch2 == 'x'"),
        ];
        let r = match_webhook_conditions(
            "agg-test",
            "validate",
            &conds,
            Some(&FailurePolicy::Fail),
            &request(),
        );
        let WebhookMatch::Forbidden(msg) = r else {
            panic!("expected Forbidden, got {r:?}")
        };
        assert!(msg.starts_with('[') && msg.ends_with(']'), "got {msg}");
        let one = match_webhook_conditions(
            "agg-test-one",
            "validate",
            &conds[..1],
            Some(&FailurePolicy::Fail),
            &request(),
        );
        let WebhookMatch::Forbidden(msg) = one else {
            panic!("expected Forbidden")
        };
        assert!(!msg.starts_with('['), "got {msg}");
    }
}
