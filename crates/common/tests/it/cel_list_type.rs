//! `x-kubernetes-list-type` set / map list values.
//!
//! Upstream: `apiextensions-apiserver/pkg/apiserver/schema/cel/values_test.go`
//! (`TestEquality` set and map-list cases, `TestLister` Size/Get/Contains/Add)
//! over `apiserver/pkg/cel/common/valuesunstructured.go`.

use kubernetes_rs_common::cel_list_types::json_to_val_with_schema;
use kubernetes_rs_common::cel_struct;
use kubernetes_rs_common::resources::crd::JSONSchemaProps;
use serde_json::{json, Value};

fn schema(v: Value) -> JSONSchemaProps {
    serde_json::from_value(v).unwrap()
}

fn set_schema() -> Value {
    json!({"type": "array", "x-kubernetes-list-type": "set", "items": {"type": "string"}})
}

fn atomic_schema() -> Value {
    json!({"type": "array", "items": {"type": "string"}})
}

fn map_schema(keys: &[&str]) -> Value {
    json!({
        "type": "array",
        "x-kubernetes-list-type": "map",
        "x-kubernetes-list-map-keys": keys,
        "items": {"type": "object", "properties": {
            "key": {"type": "string"}, "key1": {"type": "string"}, "key2": {"type": "string"},
            "val": {"type": "integer"}}},
    })
}

/// Evaluate `rule` with `a` and `b` bound to the values converted with their schemas.
fn eval(rule: &str, a: (Value, Value), b: (Value, Value)) -> bool {
    let program = cel_struct::compile(rule).unwrap();
    let mut ctx = cel_struct::new_context_for(&program);
    ctx.add_variable_as_val("a", json_to_val_with_schema(&a.0, &schema(a.1)).unwrap());
    ctx.add_variable_as_val("b", json_to_val_with_schema(&b.0, &schema(b.1)).unwrap());
    match cel_struct::execute(&program, &ctx).unwrap() {
        cel::Value::Bool(v) => v,
        other => panic!("{rule}: not a bool: {other:?}"),
    }
}

fn pair(a: Value, b: Value, s: Value) -> bool {
    eval("a == b && b == a", (a, s.clone()), (b, s))
}

#[test]
fn cel_list_type_set_equality() {
    // "set lists are equal regardless of order"
    assert!(pair(json!(["a", "b"]), json!(["b", "a"]), set_schema()));
    // "... not equal if contents differ"
    assert!(!pair(json!(["a", "b"]), json!(["a", "c"]), set_schema()));
    // "... not equal if lengths differ"
    assert!(!pair(
        json!(["a", "b"]),
        json!(["a", "b", "c"]),
        set_schema()
    ));
    // an atomic list (the default) is order sensitive
    assert!(pair(json!(["a", "b"]), json!(["a", "b"]), atomic_schema()));
    assert!(!pair(json!(["a", "b"]), json!(["b", "a"]), atomic_schema()));
    assert!(!pair(json!(["a", "b"]), json!(["a", "c"]), atomic_schema()));
    // explicit atomic
    let mut s = atomic_schema();
    s["x-kubernetes-list-type"] = json!("atomic");
    assert!(!pair(json!(["a", "b"]), json!(["b", "a"]), s));
}

#[test]
fn cel_list_type_map_list_equality() {
    let one = |k: &str, v: i64| json!({"key": k, "val": v});
    let s = || map_schema(&["key"]);
    // "map lists are equal regardless of order"
    assert!(pair(
        json!([one("a", 1), one("b", 2)]),
        json!([one("b", 2), one("a", 1)]),
        s()
    ));
    // "... not equal if contents differs"
    assert!(!pair(
        json!([one("a", 1), one("b", 2)]),
        json!([one("a", 1), one("b", 3)]),
        s()
    ));
    // "... not equal if length differs"
    assert!(!pair(
        json!([one("a", 1), one("b", 2)]),
        json!([one("a", 1), one("b", 2), one("c", 3)]),
        s()
    ));
    // multi-key
    let m = |k1: &str, k2: &str, v: i64| json!({"key1": k1, "key2": k2, "val": v});
    let s2 = || map_schema(&["key1", "key2"]);
    assert!(pair(
        json!([m("a1", "a2", 1), m("b1", "b2", 2)]),
        json!([m("b1", "b2", 2), m("a1", "a2", 1)]),
        s2()
    ));
    assert!(!pair(
        json!([m("a1", "a2", 1), m("b1", "b2", 2)]),
        json!([m("a1", "a2", 1), m("c1", "c2", 3)]),
        s2()
    ));
    assert!(!pair(
        json!([m("a1", "a2", 1)]),
        json!([m("a1", "a2", 1), m("b1", "b2", 3)]),
        s2()
    ));
}

#[test]
fn cel_list_type_set_equals_a_list_literal_in_any_order() {
    assert!(eval(
        "a == ['b', 'a']",
        (json!(["a", "b"]), set_schema()),
        (json!([]), atomic_schema())
    ));
    assert!(!eval(
        "a == ['b', 'c']",
        (json!(["a", "b"]), set_schema()),
        (json!([]), atomic_schema())
    ));
}

#[test]
fn cel_list_type_lister_size_get_contains() {
    let one = |k: &str, v: i64| json!({"key": k, "val": v});
    let a = (json!([one("a", 1), one("b", 2)]), map_schema(&["key"]));
    let none = (json!([]), atomic_schema());
    assert!(eval(
        "size(a) == 2 && a[0].key == 'a' && a[1].val == 2",
        a.clone(),
        none.clone()
    ));
    // Contains: the whole element is compared.
    assert!(eval("{'key': 'b', 'val': 2} in a", a.clone(), none.clone()));
    assert!(!eval(
        "{'key': 'a', 'val': 2} in a",
        a.clone(),
        none.clone()
    ));
    assert!(!eval(
        "{'key': 'c', 'val': 1} in a",
        a.clone(),
        none.clone()
    ));
    // Iteration and comprehensions.
    assert!(eval(
        "a.all(e, e.val > 0) && a.exists(e, e.key == 'b')",
        a,
        none.clone()
    ));
    let s = (json!(["a", "b"]), set_schema());
    assert!(eval(
        "size(a) == 2 && 'a' in a && !('c' in a) && a[1] == 'b'",
        s,
        none
    ));
}

#[test]
fn cel_list_type_set_add_is_a_union() {
    // TestLister "set list": [a b] + [b c] = [a b c].
    let a = (json!(["a", "b"]), set_schema());
    let b = (json!(["b", "c"]), set_schema());
    assert!(eval(
        "size(a + b) == 3 && (a + b)[0] == 'a' && (a + b)[1] == 'b' && (a + b)[2] == 'c'",
        a,
        b
    ));
    // "atomic list": plain concatenation [a b b c].
    let a = (json!(["a", "b"]), atomic_schema());
    let b = (json!(["b", "c"]), atomic_schema());
    assert!(eval("size(a + b) == 4 && (a + b)[2] == 'b'", a, b));
}

#[test]
fn cel_list_type_map_list_add_merges_by_key() {
    // TestLister "map list": [a:1 b:2] + [b:3 c:4] = [a:1 b:3 c:4].
    let one = |k: &str, v: i64| json!({"key": k, "val": v});
    let a = (json!([one("a", 1), one("b", 2)]), map_schema(&["key"]));
    let b = (json!([one("b", 3), one("c", 4)]), map_schema(&["key"]));
    assert!(eval(
        "size(a + b) == 3 && (a + b)[0].val == 1 && (a + b)[1].val == 3 && (a + b)[2].key == 'c' && (a + b)[2].val == 4",
        a.clone(),
        b.clone()
    ));
    // The result is still a map list: order-insensitive equality.
    assert!(eval(
        "(a + b) == [{'key': 'c', 'val': 4}, {'key': 'b', 'val': 3}, {'key': 'a', 'val': 1}]",
        a,
        b
    ));
}

#[test]
fn cel_list_type_nested_in_an_object() {
    let s = schema(json!({"type": "object", "properties": {
        "tags": {"type": "array", "x-kubernetes-list-type": "set", "items": {"type": "string"}}}}));
    let program = cel_struct::compile("self.tags == oldSelf.tags").unwrap();
    let mut ctx = cel_struct::new_context_for(&program);
    ctx.add_variable_as_val(
        "self",
        json_to_val_with_schema(&json!({"tags": ["x", "y"]}), &s).unwrap(),
    );
    ctx.add_variable_as_val(
        "oldSelf",
        json_to_val_with_schema(&json!({"tags": ["y", "x"]}), &s).unwrap(),
    );
    assert!(matches!(
        cel_struct::execute(&program, &ctx).unwrap(),
        cel::Value::Bool(true)
    ));
}

#[test]
fn cel_list_type_unknown_list_type_is_rejected() {
    let mut s = atomic_schema();
    s["x-kubernetes-list-type"] = json!("bogus");
    let e = json_to_val_with_schema(&json!(["a"]), &schema(s))
        .err()
        .unwrap();
    assert_eq!(
        e.to_string(),
        "invalid x-kubernetes-list-type, expected 'map', 'set' or 'atomic' but got bogus"
    );
}
