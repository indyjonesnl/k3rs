//! Ported from `kubectl/pkg/explain/v2/templates/plaintext_test.go`
//! (TestPlaintext) plus `funcs_test.go` wrap/resolveRef behaviour. Fixtures are
//! upstream's `apiextensions.k8s.io_v1.json` and `batch.k8s.io_v1.json`.
use kubernetes_rs_kubectl::commands::explain::openapi::*;
use serde_json::{json, Value};

fn apiext() -> Value {
    serde_json::from_str(include_str!("../testdata/apiextensions.k8s.io_v1.json")).unwrap()
}
fn batch() -> Value {
    serde_json::from_str(include_str!("../testdata/batch.k8s.io_v1.json")).unwrap()
}
fn gvr(g: &str, v: &str, r: &str) -> Gvr {
    Gvr {
        group: g.into(),
        version: v.into(),
        resource: r.into(),
    }
}
fn crd() -> Gvr {
    gvr("apiextensions.k8s.io", "v1", "customresourcedefinitions")
}
fn fp(p: &[&str]) -> Vec<String> {
    p.iter().map(|s| s.to_string()).collect()
}

#[test]
fn explain_openapi_resource_not_found() {
    let e = render_plaintext(&apiext(), &Gvr::default(), &[], false).unwrap_err();
    assert!(
        e.contains("error: GVR (/, Resource=) not found in OpenAPI schema"),
        "{e}"
    );
}

#[test]
fn explain_openapi_schema_found() {
    let o = render_plaintext(&apiext(), &crd(), &[], false).unwrap();
    assert!(o.starts_with("GROUP:      apiextensions.k8s.io\nKIND:       CustomResourceDefinition\nVERSION:    v1\n\nDESCRIPTION:\n    "), "{o}");
    assert!(o.contains("CustomResourceDefinition represents a resource that should be exposed"));
    assert!(o.contains("FIELDS:\n"));
    assert!(o.ends_with('\n'));
}

#[test]
fn explain_openapi_schema_found_namespaced_and_without_list_verb() {
    let o = render_plaintext(&batch(), &gvr("batch", "v1", "jobs"), &[], false).unwrap();
    assert!(o.contains("Job represents the configuration of a single job"));

    let mut d = batch();
    let paths = d["paths"].as_object_mut().unwrap();
    paths.remove("/apis/batch/v1/jobs");
    paths.remove("/apis/batch/v1/namespaces/{namespace}/jobs");
    paths.remove("/apis/batch/v1/cronjobs");
    paths.remove("/apis/batch/v1/namespaces/{namespace}/cronjobs/{name}");
    let o = render_plaintext(&d, &gvr("batch", "v1", "jobs"), &[], false).unwrap();
    assert!(o.contains("Job represents the configuration of a single job"));
    let o = render_plaintext(&d, &gvr("batch", "v1", "cronjobs"), &[], false).unwrap();
    assert!(o.contains("CronJob represents the configuration of a single cron job"));

    let mut d = apiext();
    d["paths"]
        .as_object_mut()
        .unwrap()
        .remove("/apis/apiextensions.k8s.io/v1/customresourcedefinitions");
    let o = render_plaintext(&d, &crd(), &[], false).unwrap();
    assert!(o.contains("CustomResourceDefinition represents a resource that should be exposed"));
}

#[test]
fn explain_openapi_field_path() {
    let e = render_plaintext(&apiext(), &crd(), &fp(&["does", "not", "exist"]), false).unwrap_err();
    assert!(e.contains("error: field \"exist\" does not exist"), "{e}");

    let o = render_plaintext(&apiext(), &crd(), &fp(&["kind"]), false).unwrap();
    assert!(o.contains("FIELD: kind <string>"), "{o}");
    let o = render_plaintext(
        &apiext(),
        &crd(),
        &fp(&["spec", "names", "singular"]),
        false,
    )
    .unwrap();
    assert!(o.contains("FIELD: singular <string>"));
    // through a list
    let o = render_plaintext(&apiext(), &crd(), &fp(&["spec", "versions", "name"]), false).unwrap();
    assert!(o.contains("FIELD: name <string>"));
    // through a map[string]T
    let o = render_plaintext(
        &apiext(),
        &crd(),
        &fp(&[
            "spec",
            "versions",
            "schema",
            "openAPIV3Schema",
            "properties",
            "default",
        ]),
        false,
    )
    .unwrap();
    assert!(o.contains("default is a default value for undefined object fields"));
    // recursive schema
    let o = render_plaintext(
        &apiext(),
        &crd(),
        &fp(&[
            "spec",
            "versions",
            "schema",
            "openAPIV3Schema",
            "properties",
            "properties",
            "properties",
            "properties",
            "properties",
            "default",
        ]),
        false,
    )
    .unwrap();
    assert!(o.contains("default is a default value for undefined object fields"));
}

#[test]
fn explain_openapi_all_fields_and_recursive() {
    let d = apiext();
    let props = d["components"]["schemas"]
        ["io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.CustomResourceValidation"]
        ["properties"]
        .as_object()
        .unwrap()
        .clone();
    let path = fp(&["spec", "versions", "schema"]);
    let o = render_plaintext(&d, &crd(), &path, false).unwrap();
    for (k, v) in &props {
        assert!(o.contains(k.as_str()));
        assert!(o.contains(v["description"].as_str().unwrap_or("")));
    }
    let o = render_plaintext(&d, &crd(), &path, true).unwrap();
    for k in props.keys() {
        assert!(o.contains(k.as_str()));
    }
}

fn tg(schema: Value, doc: Value) -> String {
    type_guess(&schema, &doc).unwrap()
}

#[test]
fn explain_openapi_type_guess() {
    let empty = json!({});
    assert_eq!(tg(json!({"type": "string"}), empty.clone()), "string");
    assert_eq!(
        tg(
            json!({"type": "string", "additionalProperties": true}),
            empty.clone()
        ),
        "string"
    );
    let doc =
        json!({"components": {"schemas": {"v1.Time": {"type": "string", "format": "date-time"}}}});
    assert_eq!(
        tg(json!({"$ref": "#/components/schemas/v1.Time"}), doc),
        "string"
    );
    assert_eq!(tg(json!({"type": "array"}), empty.clone()), "array");
    assert_eq!(tg(json!({"type": "object"}), empty.clone()), "Object");
    assert_eq!(
        tg(
            json!({"type": "array", "items": {"type": "number"}}),
            empty.clone()
        ),
        "[]number"
    );
    let r = "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.CustomResourceValidation";
    assert_eq!(
        tg(
            json!({"type": "array", "items": {"type": "object", "allOf": [{"$ref": r}]}}),
            empty.clone()
        ),
        "[]CustomResourceValidation"
    );
    assert_eq!(
        tg(
            json!({"type": "array", "items": {"type": "object", "$ref": r}}),
            empty.clone()
        ),
        "[]CustomResourceValidation"
    );
    assert_eq!(
        tg(
            json!({"type": "array", "items": {"type": "object", "additionalProperties": {"type": "string"}}}),
            empty.clone()
        ),
        "[]map[string]string"
    );
    assert_eq!(
        tg(
            json!({"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}}),
            empty.clone()
        ),
        "map[string][]string"
    );
    assert_eq!(
        tg(
            json!({"type": "object", "additionalProperties": {"type": "string", "allOf": [{"$ref": r}]}}),
            empty.clone()
        ),
        "map[string]CustomResourceValidation"
    );
    assert_eq!(tg(json!({"description": "a cool field"}), empty), "Object");
}

#[test]
fn explain_openapi_enum() {
    let s = |e: Value| json!({"type": "string", "enum": e});
    assert_eq!(extract_enum(&s(json!([])), false, -1, 0), "");
    assert_eq!(
        extract_enum(&s(json!([0, 1, 2, 3])), true, -1, 0),
        "ENUM:\n    0\n    1\n    2\n    3"
    );
    assert_eq!(
        extract_enum(&s(json!([0, 1, 2, 3])), false, 0, 2),
        "\n  enum: 0, 1, 2, 3"
    );
    assert_eq!(
        extract_enum(&s(json!([0, 1, 2, 3])), false, 2, 2),
        "\n  enum: 0, 1, ...."
    );
    assert_eq!(
        extract_enum(&s(json!([0, 1, 2, 3])), true, 2, 2),
        "ENUM:\n    0\n    1, ...."
    );
    assert_eq!(
        extract_enum(&s(json!(["Block", "File", ""])), true, -1, 0),
        "ENUM:\n    Block\n    File\n    \"\""
    );
}

#[test]
fn explain_openapi_resolve_ref_and_wrap() {
    let doc = json!({"components": {"schemas": {"a": {"type": "string"}}}});
    assert_eq!(
        resolve_ref(Some(&json!("#/components/schemas/a")), &doc),
        Some(&json!({"type": "string"}))
    );
    assert_eq!(
        resolve_ref(Some(&json!("#/components/schemas/b")), &doc),
        None
    );
    assert_eq!(resolve_ref(Some(&json!("other.json#/x")), &doc), None);
    assert_eq!(resolve_ref(None, &doc), None);
    assert_eq!(wrap(10, "aaaa bbbb cccc"), "aaaa bbbb\ncccc");
    assert_eq!(wrap(0, "aaaa bbbb cccc"), "aaaa bbbb cccc");
    assert_eq!(wrap(5, "a\nb"), "a\nb");
}
