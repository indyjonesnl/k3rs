//! Port of the EXECUTOR half of `k8s.io/client-go/util/jsonpath`
//! (`staging/src/k8s.io/client-go/util/jsonpath/jsonpath.go`, release-1.35)
//! over `serde_json::Value`, driving the parser already ported in
//! `kubernetes_rs_common::jsonpath` (`parser.go`, `node.go`).
//!
//! Covers `range`/`end` (including nested and empty ranges), field and map-key
//! access, array index/slice/step, unions, wildcards, recursive descent `..`,
//! filters (`?(@.x=="y")`, `?(@.x)`), `AllowMissingKeys` and the JSON output
//! mode. Comparison semantics are the forked text/template funcs
//! (`client-go/third_party/forked/golang/template/funcs.go`).
//!
//! Deviations (Rust value model, no reflection): there are no Go structs, so
//! `findFieldInValue` has no counterpart; map keys iterate in sorted order
//! (Go's `MapKeys` order is unspecified; `json.Marshal` sorts too).

use kubernetes_rs_common::jsonpath::{parse, ListNode, Node, ParamsEntry};
use serde_json::{Map, Value};

/// `JSONPath` (jsonpath.go:34-45).
pub struct JsonPath {
    name: String,
    root: Option<ListNode>,
    allow_missing_keys: bool,
    output_json: bool,
}

#[derive(Default)]
struct Exec {
    begin_range: usize,
    in_range: usize,
    end_range: usize,
    /// `lastEndNode`, as an absolute index into the root node list.
    last_end: Option<usize>,
    allow_missing_keys: bool,
}

type Res<T> = Result<T, String>;

impl JsonPath {
    /// `New`.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            root: None,
            allow_missing_keys: false,
            output_json: false,
        }
    }

    /// `AllowMissingKeys`.
    pub fn allow_missing_keys(mut self, allow: bool) -> Self {
        self.allow_missing_keys = allow;
        self
    }

    /// `EnableJSONOutput`.
    pub fn enable_json_output(mut self, v: bool) -> Self {
        self.output_json = v;
        self
    }

    /// `Parse`: the error text is the parser's `err.Error()`.
    pub fn parse(&mut self, text: &str) -> Res<()> {
        let p = parse(&self.name, text).map_err(|e| e.to_string())?;
        self.root = Some(p.root);
        Ok(())
    }

    /// `Execute`: bind `data` into the template and return the output.
    pub fn execute(&self, data: &Value) -> Res<String> {
        let full = self.find_results(data)?;
        let mut out = String::new();
        for results in &full {
            out.push_str(&self.print_results(results)?);
        }
        Ok(out)
    }

    /// `FindResults`.
    pub fn find_results(&self, data: &Value) -> Res<Vec<Vec<Value>>> {
        let Some(root) = &self.root else {
            return Err(format!("{} is an incomplete jsonpath template", self.name));
        };
        let mut ex = Exec {
            allow_missing_keys: self.allow_missing_keys,
            ..Exec::default()
        };
        find_results(&mut ex, &root.nodes, 0, data.clone())
    }

    /// `PrintResults`.
    pub fn print_results(&self, results: &[Value]) -> Res<String> {
        let wrapped;
        let results: &[Value] = if self.output_json {
            wrapped = [Value::Array(results.to_vec())];
            &wrapped
        } else {
            results
        };
        let mut out = String::new();
        for (i, r) in results.iter().enumerate() {
            let is_container = matches!(r, Value::Object(_) | Value::Array(_));
            let mut text = if is_container || self.output_json {
                if self.output_json {
                    let mut t = go_marshal(r, Some("    "));
                    t.push('\n');
                    t
                } else {
                    go_marshal(r, None)
                }
            } else {
                eval_to_text(r)
            };
            if i != results.len() - 1 {
                text.push(' ');
            }
            out.push_str(&text);
        }
        Ok(out)
    }
}

fn find_results(ex: &mut Exec, nodes: &[Node], offset: usize, data: Value) -> Res<Vec<Vec<Value>>> {
    let cur = vec![data];
    let mut full: Vec<Vec<Value>> = Vec::new();
    let mut i = 0;
    while i < nodes.len() {
        let results = walk(ex, &cur, &nodes[i])?;
        // encounter an end node, break the current block
        if ex.end_range > 0 && ex.end_range <= ex.in_range {
            ex.end_range -= 1;
            ex.last_end = Some(offset + i);
            break;
        }
        // encounter a range node, start a range loop
        if ex.begin_range > 0 {
            ex.begin_range -= 1;
            ex.in_range += 1;
            if !results.is_empty() {
                for value in results {
                    let next = find_results(ex, &nodes[i + 1..], offset + i + 1, value)?;
                    full.extend(next);
                }
            } else {
                // No results: the nodes within the range are still processed so
                // the position advances to the end node.
                find_results(ex, &nodes[i + 1..], offset + i + 1, Value::Null)?;
            }
            ex.in_range -= 1;

            // Fast forward to resume after the most recent end node.
            for k in i + 1..nodes.len() {
                if ex.last_end == Some(offset + k) {
                    i = k;
                    break;
                }
            }
            i += 1;
            continue;
        }
        full.push(results);
        i += 1;
    }
    Ok(full)
}

fn walk(ex: &mut Exec, value: &[Value], node: &Node) -> Res<Vec<Value>> {
    match node {
        Node::List(l) => eval_list(ex, value, l),
        Node::Text(t) => Ok(vec![Value::String(t.clone())]),
        Node::Field(f) => eval_field(ex, value, f),
        Node::Array(p) => eval_array(value, p),
        Node::Filter {
            left,
            right,
            operator,
        } => eval_filter(ex, value, left, right, operator),
        Node::Int(i) => Ok(value.iter().map(|_| Value::from(*i)).collect()),
        Node::Bool(b) => Ok(value.iter().map(|_| Value::Bool(*b)).collect()),
        Node::Float(f) => Ok(value.iter().map(|_| Value::from(*f)).collect()),
        Node::Wildcard => Ok(eval_wildcard(value)),
        Node::Recursive => Ok(eval_recursive(value)),
        Node::Union(nodes) => {
            let mut result = Vec::new();
            for l in nodes {
                result.extend(eval_list(ex, value, l)?);
            }
            Ok(result)
        }
        Node::Identifier(name) => eval_identifier(ex, value, name),
    }
}

fn eval_list(ex: &mut Exec, value: &[Value], node: &ListNode) -> Res<Vec<Value>> {
    let mut cur = value.to_vec();
    for n in &node.nodes {
        cur = walk(ex, &cur, n)?;
    }
    Ok(cur)
}

fn eval_identifier(ex: &mut Exec, input: &[Value], name: &str) -> Res<Vec<Value>> {
    match name {
        "range" => {
            ex.begin_range += 1;
            Ok(input.to_vec())
        }
        "end" => {
            if ex.in_range > 0 {
                ex.end_range += 1;
                Ok(Vec::new())
            } else {
                Err("not in range, nothing to end".to_string())
            }
        }
        other => Err(format!("unrecognized identifier {other}")),
    }
}

fn eval_array(input: &[Value], node: &[ParamsEntry; 3]) -> Res<Vec<Value>> {
    let mut result = Vec::new();
    for value in input {
        if value.is_null() {
            continue; // template.Indirect isNil
        }
        let Value::Array(items) = value else {
            return Err(format!("{} is not array or slice", go_type_name(value)));
        };
        let len = items.len() as i64;
        let mut p = *node;
        if !p[0].known {
            p[0].value = 0;
        }
        if p[0].value < 0 {
            p[0].value += len;
        }
        if !p[1].known {
            p[1].value = len;
        }
        if p[1].value < 0 || (p[1].value == 0 && p[1].derived) {
            p[1].value += len;
        }
        if p[1].value != p[0].value {
            if p[0].value >= len || p[0].value < 0 {
                return Err(format!(
                    "array index out of bounds: index {}, length {}",
                    p[0].value, len
                ));
            }
            if p[1].value > len || p[1].value < 0 {
                return Err(format!(
                    "array index out of bounds: index {}, length {}",
                    p[1].value - 1,
                    len
                ));
            }
            if p[0].value > p[1].value {
                return Err(format!(
                    "starting index {} is greater than ending index {}",
                    p[0].value, p[1].value
                ));
            }
        } else {
            // requesting zero elements is allowed through
            return Ok(result);
        }
        let mut step = 1;
        if p[2].known {
            if p[2].value <= 0 {
                return Err("step must be > 0".to_string());
            }
            step = p[2].value as usize;
        }
        let sub = &items[p[0].value as usize..p[1].value as usize];
        let mut i = 0;
        while i < sub.len() {
            result.push(sub[i].clone());
            i += step;
        }
    }
    Ok(result)
}

fn eval_field(ex: &Exec, input: &[Value], name: &str) -> Res<Vec<Value>> {
    let mut results = Vec::new();
    if input.is_empty() {
        return Ok(results);
    }
    for value in input {
        if let Value::Object(m) = value {
            if let Some(v) = m.get(name) {
                results.push(v.clone());
            }
        }
    }
    if results.is_empty() {
        if ex.allow_missing_keys {
            return Ok(results);
        }
        return Err(format!("{name} is not found"));
    }
    Ok(results)
}

/// The children `evalWildcard`/`evalRecursive` visit: struct fields and map
/// values, slice elements, or the bytes of a string (Go indexes a string).
fn children(value: &Value) -> Vec<Value> {
    match value {
        Value::Object(m) => sorted_entries(m)
            .into_iter()
            .map(|(_, v)| v.clone())
            .collect(),
        Value::Array(a) => a.clone(),
        Value::String(s) => s.bytes().map(Value::from).collect(),
        _ => Vec::new(),
    }
}

fn sorted_entries(m: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut e: Vec<_> = m.iter().collect();
    e.sort_by(|a, b| a.0.cmp(b.0));
    e
}

fn eval_wildcard(input: &[Value]) -> Vec<Value> {
    input
        .iter()
        .filter(|v| !v.is_null())
        .flat_map(children)
        .collect()
}

fn eval_recursive(input: &[Value]) -> Vec<Value> {
    let mut result = Vec::new();
    for value in input {
        if value.is_null() {
            continue;
        }
        let kids = children(value);
        if !kids.is_empty() {
            result.push(value.clone());
            result.extend(eval_recursive(&kids));
        }
    }
    result
}

fn eval_filter(
    ex: &mut Exec,
    input: &[Value],
    left: &ListNode,
    right: &ListNode,
    operator: &str,
) -> Res<Vec<Value>> {
    let mut results = Vec::new();
    for value in input {
        let Value::Array(items) = value else {
            return Err(format!(
                "{} is not array or slice and cannot be filtered",
                go_v(value)
            ));
        };
        for item in items {
            let temp = vec![item.clone()];
            let lefts = eval_list(ex, &temp, left);
            // case exists
            if operator == "exists" {
                if lefts.map(|l| !l.is_empty()).unwrap_or(false) {
                    results.push(item.clone());
                }
                continue;
            }
            let lefts = lefts?;
            if lefts.is_empty() {
                continue;
            }
            if lefts.len() > 1 {
                return Err("can only compare one element at a time".to_string());
            }
            let rights = eval_list(ex, &temp, right)?;
            if rights.is_empty() {
                continue;
            }
            if rights.len() > 1 {
                return Err("can only compare one element at a time".to_string());
            }
            let (l, r) = (&lefts[0], &rights[0]);
            let pass = match operator {
                "<" => less(l, r)?,
                ">" => greater(l, r)?,
                "==" => equal(l, r)?,
                "!=" => !equal(l, r)?,
                "<=" => less_equal(l, r)?,
                ">=" => !less(l, r)?,
                other => return Err(format!("unrecognized filter operator {other}")),
            };
            if pass {
                results.push(item.clone());
            }
        }
    }
    Ok(results)
}

// ---- forked text/template comparison funcs (funcs.go) ----

#[derive(PartialEq, Clone, Copy)]
enum Kind {
    Bool,
    Int,
    Float,
    String,
    Uint,
}

const ERR_BAD_COMPARISON_TYPE: &str = "invalid type for comparison";
const ERR_BAD_COMPARISON: &str = "incompatible types for comparison";

fn basic_kind(v: &Value) -> Res<Kind> {
    match v {
        Value::Bool(_) => Ok(Kind::Bool),
        Value::String(_) => Ok(Kind::String),
        Value::Number(n) if n.is_i64() => Ok(Kind::Int),
        Value::Number(n) if n.is_u64() => Ok(Kind::Uint),
        Value::Number(_) => Ok(Kind::Float),
        _ => Err(ERR_BAD_COMPARISON_TYPE.to_string()),
    }
}

fn equal(a: &Value, b: &Value) -> Res<bool> {
    let (k1, k2) = (basic_kind(a)?, basic_kind(b)?);
    if k1 != k2 {
        return match (k1, k2) {
            (Kind::Int, Kind::Uint) => {
                let i = a.as_i64().unwrap();
                Ok(i >= 0 && i as u64 == b.as_u64().unwrap())
            }
            (Kind::Uint, Kind::Int) => {
                let i = b.as_i64().unwrap();
                Ok(i >= 0 && a.as_u64().unwrap() == i as u64)
            }
            _ => Err(ERR_BAD_COMPARISON.to_string()),
        };
    }
    Ok(match k1 {
        Kind::Bool => a.as_bool() == b.as_bool(),
        Kind::Float => a.as_f64() == b.as_f64(),
        Kind::Int => a.as_i64() == b.as_i64(),
        Kind::Uint => a.as_u64() == b.as_u64(),
        Kind::String => a.as_str() == b.as_str(),
    })
}

fn less(a: &Value, b: &Value) -> Res<bool> {
    let (k1, k2) = (basic_kind(a)?, basic_kind(b)?);
    if k1 != k2 {
        return match (k1, k2) {
            (Kind::Int, Kind::Uint) => {
                let i = a.as_i64().unwrap();
                Ok(i < 0 || (i as u64) < b.as_u64().unwrap())
            }
            (Kind::Uint, Kind::Int) => {
                let i = b.as_i64().unwrap();
                Ok(i >= 0 && a.as_u64().unwrap() < i as u64)
            }
            _ => Err(ERR_BAD_COMPARISON.to_string()),
        };
    }
    Ok(match k1 {
        Kind::Bool => return Err(ERR_BAD_COMPARISON_TYPE.to_string()),
        Kind::Float => a.as_f64() < b.as_f64(),
        Kind::Int => a.as_i64() < b.as_i64(),
        Kind::Uint => a.as_u64() < b.as_u64(),
        Kind::String => a.as_str() < b.as_str(),
    })
}

fn less_equal(a: &Value, b: &Value) -> Res<bool> {
    let lt = less(a, b)?;
    if lt {
        return Ok(true);
    }
    equal(a, b)
}

fn greater(a: &Value, b: &Value) -> Res<bool> {
    Ok(!less_equal(a, b)?)
}

// ---- Go formatting ----

/// `reflect.Type.String()` for a decoded JSON value.
fn go_type_name(v: &Value) -> &'static str {
    match v {
        Value::Object(_) => "map[string]interface {}",
        Value::String(_) => "string",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_i64() => "int64",
        Value::Number(n) if n.is_u64() => "uint64",
        Value::Number(_) => "float64",
        Value::Array(_) => "[]interface {}",
        Value::Null => "<nil>",
    }
}

/// `%v` of a decoded JSON value (best effort for error messages).
fn go_v(v: &Value) -> String {
    match v {
        Value::Null => "<nil>".to_string(),
        other => eval_to_text(other),
    }
}

/// `evalToText` (`fmt.Fprint`): strings raw, numbers as `%v`.
fn eval_to_text(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => i.to_string(),
            (_, Some(u)) => u.to_string(),
            _ => fmt_float_v(n.as_f64().unwrap_or(0.0)),
        },
        // containers are marshalled to JSON by the caller
        other => go_marshal(other, None),
    }
}

/// Shortest decimal digits and exponent: `d.ddd * 10^exp`.
fn shortest(f: f64) -> (String, i32) {
    let s = format!("{:e}", f.abs());
    let (mant, exp) = s.split_once('e').unwrap();
    (mant.replace('.', ""), exp.parse().unwrap())
}

fn fmt_exp(digits: &str, exp: i32, pad: bool) -> String {
    let mut s = digits[..1].to_string();
    if digits.len() > 1 {
        s.push('.');
        s.push_str(&digits[1..]);
    }
    let sign = if exp < 0 { '-' } else { '+' };
    let e = exp.abs();
    if pad && e < 10 {
        format!("{s}e{sign}0{e}")
    } else {
        format!("{s}e{sign}{e}")
    }
}

fn fmt_fixed(digits: &str, exp: i32) -> String {
    let dp = exp + 1;
    if dp <= 0 {
        format!("0.{}{}", "0".repeat((-dp) as usize), digits)
    } else if digits.len() as i32 <= dp {
        format!(
            "{}{}",
            digits,
            "0".repeat((dp - digits.len() as i32) as usize)
        )
    } else {
        format!("{}.{}", &digits[..dp as usize], &digits[dp as usize..])
    }
}

/// `fmt` `%v` of a float64: strconv `'g'` with the shortest digits, `%e` when
/// the exponent is < -4 or >= 6 (`ftoa.go`: `if shortest { eprec = 6 }`).
fn fmt_float_v(f: f64) -> String {
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.to_string();
    }
    let (digits, exp) = shortest(f);
    let sign = if f < 0.0 { "-" } else { "" };
    if !(-4..6).contains(&exp) {
        format!("{sign}{}", fmt_exp(&digits, exp, true))
    } else {
        format!("{sign}{}", fmt_fixed(&digits, exp))
    }
}

/// `encoding/json` float64 encoding: `'f'` unless the exponent is < -6 or
/// >= 21, then `'e'` with a single-digit exponent unpadded.
fn json_float(f: f64) -> String {
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.to_string();
    }
    let (digits, exp) = shortest(f);
    let sign = if f < 0.0 { "-" } else { "" };
    if !(-6..21).contains(&exp) {
        format!("{sign}{}", fmt_exp(&digits, exp, false))
    } else {
        format!("{sign}{}", fmt_fixed(&digits, exp))
    }
}

fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `json.Marshal` (`indent == None`) / `json.MarshalIndent("", indent)`:
/// sorted keys, HTML-escaped strings, Go float formatting.
fn go_marshal(v: &Value, indent: Option<&str>) -> String {
    let mut out = String::new();
    marshal_into(v, indent, 0, &mut out);
    out
}

fn marshal_into(v: &Value, indent: Option<&str>, depth: usize, out: &mut String) {
    let nl = |out: &mut String, d: usize| {
        if let Some(ind) = indent {
            out.push('\n');
            out.push_str(&ind.repeat(d));
        }
    };
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(&b.to_string()),
        Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => out.push_str(&i.to_string()),
            (_, Some(u)) => out.push_str(&u.to_string()),
            _ => out.push_str(&json_float(n.as_f64().unwrap_or(0.0))),
        },
        Value::String(s) => json_string(s, out),
        Value::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                nl(out, depth + 1);
                marshal_into(item, indent, depth + 1, out);
            }
            nl(out, depth);
            out.push(']');
        }
        Value::Object(m) => {
            if m.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, item)) in sorted_entries(m).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                nl(out, depth + 1);
                json_string(k, out);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                marshal_into(item, indent, depth + 1, out);
            }
            nl(out, depth);
            out.push('}');
        }
    }
}
