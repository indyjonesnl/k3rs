//! Ports of `internal/lastappliedmanager_test.go` TestApplyUsingLastAppliedAnnotation
//! (:48): applying to an object created by client-side apply only conflicts on
//! the fields the last-applied annotation does not excuse.

use kubernetes_rs_common::fieldmanager::lastapplied::LAST_APPLIED_CONFIG_ANNOTATION;
use kubernetes_rs_common::fieldmanager::versionconverter::UpdateFailure;
use kubernetes_rs_common::fieldmanager::{FieldManager, Managed, ResetFields};
use serde_json::{json, Value};

fn deployment(
    replicas: i64,
    label: &str,
    image: &str,
    extra_container: bool,
    sel_label: &str,
) -> Value {
    let mut containers = vec![json!({"name": "my-c", "image": image})];
    if extra_container {
        containers.push(json!({"name": "my-c2", "image": "my-image2"}));
    }
    json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "my-deployment", "labels": {"app": label}},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": sel_label}},
            "template": {"metadata": {"labels": {"app": label}},
                         "spec": {"containers": containers}}
        }
    })
}

fn fm() -> FieldManager {
    FieldManager::new("apps/v1", None, ResetFields::new())
}

/// `f.Update(originalObj, "test_client_side_apply")` with the annotation set.
fn live(original: &Value, last_applied: Option<&str>) -> Value {
    let mut obj = original.clone();
    let la = match last_applied {
        Some(s) => s.to_string(),
        None => serde_json::to_string(original).unwrap(),
    };
    obj["metadata"]["annotations"] = json!({ LAST_APPLIED_CONFIG_ANNOTATION: la });
    let managed = fm()
        .update_managed(
            &json!({}),
            &obj,
            Managed::default(),
            "test_client_side_apply",
            true,
        )
        .unwrap();
    obj["metadata"]["managedFields"] = serde_json::to_value(managed.encode().unwrap()).unwrap();
    obj
}

fn conflict_paths(err: UpdateFailure) -> Vec<String> {
    match err {
        UpdateFailure::Conflicts(c) => {
            assert!(c.iter().all(|c| c.manager == "test_client_side_apply"));
            let mut p: Vec<_> = c.into_iter().map(|c| c.path).collect();
            p.sort();
            p
        }
        other => panic!("{other:?}"),
    }
}

fn expect_conflicts(live: &Value, applied: &Value, manager: &str, want: &[&str]) {
    let err = fm()
        .apply_value(Some(live), applied, manager, false)
        .unwrap_err();
    let mut want: Vec<&str> = want.to_vec();
    want.sort();
    assert_eq!(conflict_paths(err), want);
    // Yet force resolves all conflicts.
    fm().apply_value(Some(live), applied, manager, true)
        .unwrap();
}

const LABEL: &str = ".metadata.labels.app";
const REPLICAS: &str = ".spec.replicas";
const IMAGE: &str = ".spec.template.spec.containers[name=\"my-c\"].image";

#[test]
fn last_applied_manager_case1_fields_not_allowed_by_last_applied() {
    let mut last = deployment(3, "my-app", "my-image-v1", true, "my-app");
    // The object's metadata.labels.app is "missing from last-applied".
    last["metadata"].as_object_mut().unwrap().remove("labels");
    let original = deployment(100, "my-app", "my-image-v2", false, "my-app");
    let l = live(&original, Some(&serde_json::to_string(&last).unwrap()));
    let mut applied = deployment(333, "my-new-label", "my-image-new", false, "my-new-label");
    applied["metadata"]["labels"] = json!({"app": "my-new-label"});
    expect_conflicts(&l, &applied, "kubectl", &[LABEL, REPLICAS, IMAGE]);
}

#[test]
fn last_applied_manager_case2_only_replicas_conflict() {
    let last = deployment(3, "my-app", "my-image", false, "my-app");
    let original = deployment(100, "my-app", "my-image", false, "my-app");
    let l = live(&original, Some(&serde_json::to_string(&last).unwrap()));
    let mut applied = deployment(3, "my-new-label", "my-image", false, "my-app");
    applied["spec"].as_object_mut().unwrap().remove("selector");
    applied["spec"]["template"]["metadata"]["labels"] = json!({"app": "my-app"});
    expect_conflicts(&l, &applied, "kubectl", &[REPLICAS]);
}

#[test]
fn last_applied_manager_applied_matches_original_no_conflict() {
    let original = deployment(100, "my-app", "my-image", false, "my-app");
    let l = live(&original, None);
    fm().apply_value(Some(&l), &original, "kubectl", false)
        .unwrap();
}

#[test]
fn last_applied_manager_updates_everything_last_applied_owns() {
    let original = deployment(3, "my-app", "my-image", false, "my-app");
    let l = live(&original, None);
    let mut applied = deployment(100, "my-new-label", "my-new-image", false, "my-new-label");
    applied["metadata"]["labels"] = json!({"app": "my-new-label"});
    let out = fm()
        .apply_value(Some(&l), &applied, "kubectl", false)
        .unwrap();
    assert_eq!(out["spec"]["replicas"], 100);
    assert_eq!(out["metadata"]["labels"]["app"], "my-new-label");
}

#[test]
fn last_applied_manager_not_kubectl_gets_all_conflicts() {
    let original = deployment(100, "my-app", "my-image", false, "my-app");
    let l = live(&original, None);
    let mut applied = deployment(3, "my-new-label", "my-new-image", false, "my-app");
    applied["metadata"]["labels"] = json!({"app": "my-new-label"});
    applied["spec"]["template"]["metadata"]["labels"] = json!({"app": "my-app"});
    expect_conflicts(&l, &applied, "not_kubectl", &[LABEL, REPLICAS, IMAGE]);
}

fn simple(api: &str, replicas: i64) -> Value {
    json!({"apiVersion": api, "kind": "Deployment",
           "metadata": {"name": "my-deployment"}, "spec": {"replicas": replicas}})
}

#[test]
fn last_applied_manager_unusable_annotation_keeps_conflicts() {
    let original = simple("apps/v1", 3);
    let applied = simple("apps/v1", 100);
    for last in [
        // apiVersion mismatch with the live object.
        r#"{"apiVersion":"extensions/v1beta1","kind":"Deployment","metadata":{"name":"my-deployment"},"spec":{"replicas":3}}"#,
        // Not a valid object (no apiVersion).
        r#"{"apiVerison":"foo","kind":"bar","spec":"expect conflict due to invalid object"}"#,
        // Not JSON.
        "not json",
        // Empty.
        "",
    ] {
        let l = live(&original, Some(last));
        expect_conflicts(&l, &applied, "kubectl", &[REPLICAS]);
    }
}
