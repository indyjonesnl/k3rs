//! Ports of `internal/lastappliedmanager_test.go` TestApplyUsingLastAppliedAnnotation
//! (:48): applying to an object created by client-side apply only conflicts on
//! the fields the last-applied annotation does not excuse.

use kubernetes_rs_common::fieldmanager::lastapplied::LAST_APPLIED_CONFIG_ANNOTATION;
use kubernetes_rs_common::fieldmanager::schema::Type;
use kubernetes_rs_common::fieldmanager::versionconverter::UpdateFailure;
use kubernetes_rs_common::fieldmanager::{FieldManager, Managed, ResetFields};
use serde_json::{json, Value};
use std::sync::Arc;

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

// ---- TestServiceApply (:568), TestReplicationControllerApply (:679),
// ---- TestPodApply (:742): core/v1 kinds through testConflicts (:920).

/// `testConflicts` for one case: `original` is Updated by
/// `test_client_side_apply` with itself as last-applied, then `applied` is
/// applied by `manager`. `want == None` expects no error.
fn core_case(original: Value, applied: Value, manager: &str, want: Option<&[&str]>) {
    let kind = original["kind"].as_str().unwrap().to_string();
    let f = FieldManager::new("v1", None, ResetFields::new()).with_schema(core_schema(&kind));
    let mut obj = original.clone();
    obj["metadata"]["annotations"] =
        json!({ LAST_APPLIED_CONFIG_ANNOTATION: serde_json::to_string(&original).unwrap() });
    let managed = f
        .update_managed(
            &json!({}),
            &obj,
            Managed::default(),
            "test_client_side_apply",
            true,
        )
        .unwrap();
    obj["metadata"]["managedFields"] = serde_json::to_value(managed.encode().unwrap()).unwrap();
    match want {
        None => {
            f.apply_value(Some(&obj), &applied, manager, false).unwrap();
        }
        Some(want) => {
            let err = f
                .apply_value(Some(&obj), &applied, manager, false)
                .unwrap_err();
            let mut want: Vec<&str> = want.to_vec();
            want.sort();
            assert_eq!(conflict_paths(err), want);
            f.apply_value(Some(&obj), &applied, manager, true).unwrap();
        }
    }
}

/// The typed schema the upstream fake type converter (testdata OpenAPI)
/// gives the kind: Service `ports` is a list map keyed by `port`+`protocol`
/// (protocol defaults to TCP) and `selector` is an atomic map; RC `selector`
/// is atomic; Pod `containers` is keyed by `name` and `nodeSelector` is an
/// atomic map (`x-kubernetes-map-type: atomic`).
fn core_schema(kind: &str) -> Option<Arc<Type>> {
    let spec = match kind {
        "Service" => json!({"type": "object", "properties": {
            "ports": {"type": "array", "items": {"type": "object", "properties": {
                "name": {"type": "string"}, "port": {"type": "integer"},
                "protocol": {"type": "string", "default": "TCP"},
                "targetPort": {"type": "integer"}}},
                "x-kubernetes-list-type": "map",
                "x-kubernetes-list-map-keys": ["port", "protocol"]},
            "selector": {"type": "object", "additionalProperties": {"type": "string"},
                         "x-kubernetes-map-type": "atomic"}}}),
        "ReplicationController" => json!({"type": "object", "properties": {
            "replicas": {"type": "integer"},
            "selector": {"type": "object", "additionalProperties": {"type": "string"},
                         "x-kubernetes-map-type": "atomic"}}}),
        _ => json!({"type": "object", "properties": {
            "containers": {"type": "array", "items": {"type": "object", "properties": {
                "name": {"type": "string"}, "image": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
                "command": {"type": "array", "items": {"type": "string"}}}},
                "x-kubernetes-list-type": "map",
                "x-kubernetes-list-map-keys": ["name"]},
            "nodeName": {"type": "string"},
            "nodeSelector": {"type": "object", "additionalProperties": {"type": "string"},
                             "x-kubernetes-map-type": "atomic"}}}),
    };
    let schemas = json!({"Root": {"type": "object", "properties": {
        "apiVersion": {"type": "string"}, "kind": {"type": "string"},
        "metadata": {"type": "object"}, "spec": spec}}});
    Type::from_openapi(schemas.as_object().unwrap(), "Root").map(Arc::new)
}

fn service(port_target: i64, selector: Value) -> Value {
    json!({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "test"},
           "spec": {"ports": [{"name": "https", "port": 443, "protocol": "TCP",
                               "targetPort": port_target}],
                    "selector": selector}})
}

#[test]
fn last_applied_manager_service_same_manager_accepts_all() {
    core_case(
        service(8443, json!({"old": "test"})),
        service(8444, json!({"new": "test"})),
        "kubectl",
        None,
    );
}

#[test]
fn last_applied_manager_service_same_manager_may_remove_selector() {
    core_case(
        service(8443, json!({"old": "test"})),
        service(8444, json!({})),
        "kubectl",
        None,
    );
}

#[test]
fn last_applied_manager_service_other_manager_conflicts() {
    core_case(
        service(8443, json!({"old": "test"})),
        service(8444, json!({"new": "test"})),
        "not_kubectl",
        Some(&[
            ".spec.selector",
            ".spec.ports[port=443,protocol=\"TCP\"].targetPort",
        ]),
    );
}

fn rc(replicas: i64, selector: &str) -> Value {
    json!({"apiVersion": "v1", "kind": "ReplicationController",
           "metadata": {"name": "test"},
           "spec": {"replicas": replicas, "selector": {selector: "test"}}})
}

#[test]
fn last_applied_manager_replication_controller_same_manager_accepts_all() {
    core_case(rc(0, "old"), rc(3, "new"), "kubectl", None);
}

#[test]
fn last_applied_manager_replication_controller_other_manager_conflicts() {
    core_case(
        rc(0, "old"),
        rc(3, "new"),
        "not_kubectl",
        Some(&[".spec.selector", ".spec.replicas"]),
    );
}

fn pod(node_name: Option<&str>, selector: Value) -> Value {
    let mut spec = json!({"containers": [{"args": ["-v=2"], "command": ["controller"],
                                         "image": "some.registry/app:latest", "name": "doJob"}],
                          "nodeSelector": selector});
    if let Some(n) = node_name {
        spec["nodeName"] = json!(n);
    }
    json!({"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "test", "namespace": "test"}, "spec": spec})
}

const MASTER: &str = "node-role.kubernetes.io/master";

#[test]
fn last_applied_manager_pod_same_manager_accepts_all() {
    core_case(
        pod(Some("definetlyControlPlane"), json!({MASTER: ""})),
        pod(None, json!({"node-role.kubernetes.io/worker": ""})),
        "kubectl",
        None,
    );
}

#[test]
fn last_applied_manager_pod_other_manager_selector_conflicts() {
    core_case(
        pod(Some("definetlyControlPlane"), json!({MASTER: ""})),
        pod(
            Some("definetlyControlPlane"),
            json!({MASTER: "", "otherNodeType": ""}),
        ),
        "not_kubectl",
        Some(&[".spec.nodeSelector"]),
    );
}

#[test]
fn last_applied_manager_pod_other_manager_cannot_purge_selector() {
    core_case(
        pod(Some("definetlyControlPlane"), json!({MASTER: ""})),
        pod(Some("another"), json!({})),
        "not_kubectl",
        Some(&[".spec.nodeSelector", ".spec.nodeName"]),
    );
}

#[test]
fn last_applied_manager_pod_same_manager_may_purge_selector() {
    core_case(
        pod(Some("definetlyControlPlane"), json!({MASTER: ""})),
        pod(Some("another"), json!({})),
        "kubectl",
        None,
    );
}
