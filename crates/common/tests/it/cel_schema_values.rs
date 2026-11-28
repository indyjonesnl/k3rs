//! `UnstructuredToVal` (`apiserver/pkg/cel/common/valuesunstructured.go`):
//! schema-aware conversion of CR values for CRD validation rules.

use kubernetes_rs_common::resources::crd::JSONSchemaProps;
use kubernetes_rs_common::{CELContext, CELEvaluator};
use serde_json::{json, Value};

fn schema(v: Value) -> JSONSchemaProps {
    serde_json::from_value(v).unwrap()
}

fn eval(rule: &str, value: Value, s: Value) -> anyhow::Result<bool> {
    let mut ctx = CELContext::new();
    ctx.add_json_variable_with_schema("self", &value, &schema(s))?;
    CELEvaluator::new().evaluate(rule, &ctx)
}

fn obj(props: Value) -> Value {
    json!({"type": "object", "properties": props})
}

#[test]
fn cel_schema_values_date_time_is_a_timestamp() {
    let s = obj(json!({"t": {"type": "string", "format": "date-time"}}));
    let v = json!({"t": "2024-03-05T10:20:30Z"});
    assert!(eval("self.t.getFullYear() == 2024", v.clone(), s.clone()).unwrap());
    assert!(eval("self.t < timestamp('2025-01-01T00:00:00Z')", v, s).unwrap());
}

#[test]
fn cel_schema_values_date_is_a_timestamp() {
    let s = obj(json!({"d": {"type": "string", "format": "date"}}));
    let v = json!({"d": "2024-03-05"});
    assert!(eval("self.d.getMonth() == 2 && self.d.getDate() == 5", v, s).unwrap());
}

#[test]
fn cel_schema_values_duration() {
    let s = obj(json!({"d": {"type": "string", "format": "duration"}}));
    let v = json!({"d": "1h30m"});
    assert!(eval("self.d.getSeconds() == 5400", v.clone(), s.clone()).unwrap());
    assert!(eval("self.d > duration('1h')", v, s).unwrap());
}

#[test]
fn cel_schema_values_byte_is_bytes() {
    let s = obj(json!({"b": {"type": "string", "format": "byte"}}));
    let v = json!({"b": "aGVsbG8="});
    assert!(eval("self.b == b'hello' && size(self.b) == 5", v, s).unwrap());
}

#[test]
fn cel_schema_values_int_or_string_and_numbers() {
    let s = obj(json!({
        "x": {"x-kubernetes-int-or-string": true},
        "n": {"type": "number"},
        "i": {"type": "integer"},
        "b": {"type": "boolean"},
    }));
    let v = json!({"x": 3, "n": 2, "i": 7, "b": true});
    assert!(eval(
        "self.x == 3 && self.n == 2.0 && self.i == 7 && self.b",
        v,
        s.clone()
    )
    .unwrap());
    let v = json!({"x": "3", "n": 1.5, "i": 7, "b": false});
    assert!(eval("self.x == '3' && self.n == 1.5", v, s).unwrap());
}

#[test]
fn cel_schema_values_nested_maps_and_lists() {
    let s = obj(json!({
        "m": {"type": "object", "additionalProperties": {"type": "string", "format": "date-time"}},
        "l": {"type": "array", "items": {"type": "string", "format": "duration"}},
    }));
    let v = json!({"m": {"a": "2024-01-01T00:00:00Z"}, "l": ["1s", "2m"]});
    assert!(eval(
        "self.m['a'].getFullYear() == 2024 && self.l[1].getMinutes() == 2",
        v,
        s
    )
    .unwrap());
}

#[test]
fn cel_schema_values_absent_key_is_no_such_key() {
    let s = obj(json!({"a": {"type": "string"}}));
    let v = json!({});
    assert!(eval("self.a == 'x'", v.clone(), s.clone()).is_err());
    assert!(!eval("has(self.a)", v, s).unwrap());
}

#[test]
fn cel_schema_values_invalid_values_are_errors() {
    let dt = obj(json!({"t": {"type": "string", "format": "date-time"}}));
    for (s, v) in [
        (dt.clone(), json!({"t": "not a time"})),
        (dt, json!({"t": 5})),
        (
            obj(json!({"d": {"type": "string", "format": "duration"}})),
            json!({"d": "soon"}),
        ),
        (
            obj(json!({"b": {"type": "string", "format": "byte"}})),
            json!({"b": "***"}),
        ),
        (
            obj(json!({"x": {"x-kubernetes-int-or-string": true}})),
            json!({"x": true}),
        ),
        (obj(json!({"i": {"type": "integer"}})), json!({"i": "1"})),
        (obj(json!({"b": {"type": "boolean"}})), json!({"b": 1})),
        (obj(json!({"o": {"type": "object"}})), json!({"o": []})),
        (
            obj(json!({"l": {"type": "array", "items": {"type": "string"}}})),
            json!({"l": {}}),
        ),
    ] {
        let mut ctx = CELContext::new();
        assert!(
            ctx.add_json_variable_with_schema("self", &v, &schema(s))
                .is_err(),
            "{v}"
        );
    }
}

/// `strfmt.ParseDuration` (kube-openapi `strfmt/duration.go`): the scala-style
/// units on top of `time.ParseDuration`.
#[test]
fn cel_schema_values_strfmt_duration_units() {
    let s = obj(json!({"d": {"type": "string", "format": "duration"}}));
    for (v, secs) in [
        ("1d", 86_400),
        ("2w", 14 * 86_400),
        ("1d 2h", 86_400 + 7_200),
        ("3 days", 3 * 86_400),
        ("5min", 300),
        ("1hour30min", 5_400),
        ("1h30m", 5_400),
    ] {
        let rule = format!("self.d.getSeconds() == {secs}");
        assert!(eval(&rule, json!({"d": v}), s.clone()).unwrap(), "{v}");
    }
}

/// `strfmt.ParseDateTime`: zone-less `2006-01-02T15:04:05` is accepted, the
/// empty string is the epoch.
#[test]
fn cel_schema_values_strfmt_date_time_layouts() {
    let s = obj(json!({"t": {"type": "string", "format": "date-time"}}));
    assert!(eval(
        "self.t.getFullYear() == 2024",
        json!({"t": "2024-03-05T10:20:30"}),
        s.clone()
    )
    .unwrap());
    assert!(eval("self.t.getFullYear() == 1970", json!({"t": ""}), s).unwrap());
}
