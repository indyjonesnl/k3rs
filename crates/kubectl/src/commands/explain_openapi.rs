//! `kubectl explain` rendered from the server's `/openapi/v3` documents.
//!
//! Port of `staging/src/k8s.io/kubectl/pkg/explain/v2` (release-1.35):
//! `explain.go` `PrintModelDescription` (:33-97), `generator.go` `Render`, the
//! builtin template functions in `funcs.go` (`resolveRef`, `wrap`, `indent`,
//! `contains`, ...) and `templates/plaintext.tmpl` (templates "schema",
//! "output", "fieldList", "fieldDetail", "description", "typeGuess",
//! "extractEnum"). Upstream renders with a Go `text/template`; each template
//! is ported as a function with the same data flow and the same whitespace.
//!
//! Not in this slice (backlog kubectl-P2-29b): resource/field-path parsing
//! through the RESTMapper (`explain.SplitAndParseResourceRequest*`), the
//! `--output`/`--api-version` flags and the openapi v2 fallback, and wiring
//! into `main.rs`.

use kubernetes_rs_client::http::ApiClient;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// `schema.GroupVersionResource`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gvr {
    pub group: String,
    pub version: String,
    pub resource: String,
}

impl Gvr {
    /// `GroupVersionResource.String()`.
    pub fn go_string(&self) -> String {
        format!(
            "{}/{}, Resource={}",
            self.group, self.version, self.resource
        )
    }
}

/// Go template truthiness (`text/template` `isTrue`).
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_object().and_then(|o| o.get(key))
}

/// `and .additionalProperties (not (eq "bool" (printf "%T" ...)))`.
fn map_additional(schema: &Value) -> Option<&Value> {
    let ap = get(schema, "additionalProperties");
    if truthy(ap) && !matches!(ap, Some(Value::Bool(_))) {
        ap
    } else {
        None
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    get(v, key).and_then(Value::as_str).unwrap_or("")
}

/// `%v` of a decoded JSON scalar (float64 numbers print without exponent for
/// whole values below 1e21).
fn go_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                let f = n.as_f64().unwrap_or(0.0);
                if f.fract() == 0.0 && f.abs() < 1e21 {
                    format!("{}", f as i128)
                } else {
                    f.to_string()
                }
            }
        }
        Value::Bool(b) => b.to_string(),
        Value::Null => "<nil>".into(),
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(go_display).collect::<Vec<_>>().join(" ")
        ),
        Value::Object(o) => go_map_display(o),
    }
}

/// `%v` of a `map[string]any`: `map[k:v k2:v2]` with sorted keys.
fn go_map_display(o: &Map<String, Value>) -> String {
    let keys: BTreeSet<&String> = o.keys().collect();
    format!(
        "map[{}]",
        keys.iter()
            .map(|k| format!("{k}:{}", go_display(&o[*k])))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

/// `net/url` fragment decoding (`%XX`).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(h) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(h);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// funcs.go `resolveRef`: fragment-only refs, walked through nested maps.
/// Anything else (nil, remote ref, missing component) is `nil`.
pub fn resolve_ref<'a>(ref_any: Option<&Value>, document: &'a Value) -> Option<&'a Value> {
    let r = ref_any?.as_str()?;
    let fragment = r.strip_prefix('#')?;
    let fragment = percent_decode(fragment);
    let mut cur = document;
    for k in fragment.split('/') {
        if k.is_empty() {
            continue;
        }
        cur = get(cur, k).filter(|v| v.is_object())?;
    }
    Some(cur)
}

/// `or (resolveRef ref doc) schema`.
fn resolved<'a>(schema: &'a Value, document: &'a Value) -> &'a Value {
    match resolve_ref(get(schema, "$ref"), document) {
        Some(r) if truthy(Some(r)) => r,
        _ => schema,
    }
}

/// funcs.go `indent`.
fn indent(amount: usize, s: &str) -> String {
    let pad = " ".repeat(amount);
    format!("{pad}{}", s.replace('\n', &format!("\n{pad}")))
}

/// `github.com/mitchellh/go-wordwrap` `WrapString`, as used by `wrap`
/// (`term.NewWordWrapWriter`: limit 0 writes through).
pub fn wrap(lim: usize, s: &str) -> String {
    if lim == 0 {
        return s.to_string();
    }
    let nbsp = '\u{a0}';
    let mut buf = String::with_capacity(s.len());
    let mut current = 0usize;
    let mut word = String::new();
    let mut space = String::new();
    let (mut word_len, mut space_len) = (0usize, 0usize);
    for ch in s.chars() {
        if ch == '\n' {
            if word.is_empty() {
                // (upstream also updates `current` here; it is reset below)
                if current + space_len <= lim {
                    buf.push_str(&space);
                }
                space.clear();
                space_len = 0;
            } else {
                buf.push_str(&space);
                buf.push_str(&word);
                space.clear();
                word.clear();
                space_len = 0;
                word_len = 0;
            }
            buf.push(ch);
            current = 0;
        } else if ch.is_whitespace() && ch != nbsp {
            if space.is_empty() || !word.is_empty() {
                current += space_len + word_len;
                buf.push_str(&space);
                space.clear();
                space_len = 0;
                buf.push_str(&word);
                word.clear();
                word_len = 0;
            }
            space.push(ch);
            space_len += 1;
        } else {
            word.push(ch);
            word_len += 1;
            if current + word_len + space_len > lim && word_len < lim {
                buf.push('\n');
                current = 0;
                space.clear();
                space_len = 0;
            }
        }
    }
    if word.is_empty() {
        if current + space_len <= lim {
            buf.push_str(&space);
        }
    } else {
        buf.push_str(&space);
        buf.push_str(&word);
    }
    buf
}

/// Guard standing in for Go's stack overflow on pathological ref cycles.
const MAX_DEPTH: usize = 256;

/// Template "typeGuess".
pub fn type_guess(schema: &Value, document: &Value) -> Result<String, String> {
    type_guess_depth(schema, document, 0)
}

fn type_guess_depth(schema: &Value, document: &Value, depth: usize) -> Result<String, String> {
    if !truthy(Some(schema)) || depth > MAX_DEPTH {
        return Err("expected schema argument to subtemplate 'typeguess'".into());
    }
    if truthy(get(schema, "items")) {
        let items = get(schema, "items").unwrap();
        return Ok(format!(
            "[]{}",
            type_guess_depth(items, document, depth + 1)?
        ));
    }
    if let Some(ap) = map_additional(schema) {
        return Ok(format!(
            "map[string]{}",
            type_guess_depth(ap, document, depth + 1)?
        ));
    }
    if truthy(get(schema, "allOf"))
        && !truthy(get(schema, "properties"))
        && get(schema, "allOf").and_then(Value::as_array).map(Vec::len) == Some(1)
    {
        let first = &get(schema, "allOf").unwrap()[0];
        return type_guess_depth(first, document, depth + 1);
    }
    if truthy(get(schema, "$ref")) {
        let r = str_of(schema, "$ref");
        let ref_schema = resolve_ref(get(schema, "$ref"), document).filter(|v| truthy(Some(v)));
        let is_object = match ref_schema {
            None => true,
            Some(rs) => !truthy(get(rs, "type")) || str_of(rs, "type") == "object",
        };
        if is_object {
            let name = r.rsplit('/').next().unwrap_or("");
            let name = name.rsplit('.').next().unwrap_or("");
            return Ok(if name.is_empty() { "Object" } else { name }.to_string());
        }
        // `else if $refSchema.type` (always true here): the referred type.
        return Ok(str_of(ref_schema.unwrap(), "type").to_string());
    }
    let t = str_of(schema, "type");
    Ok(if t == "object" || t.is_empty() {
        "Object".to_string()
    } else {
        t.to_string()
    })
}

/// Template "extractEnum". `limit` is the template's `$.limit` (`or` turns 0
/// and absent into -1); `indent_amount` only matters in the short view.
pub fn extract_enum(
    schema: &Value,
    is_long_view: bool,
    limit: i64,
    indent_amount: usize,
) -> String {
    let mut out = String::new();
    if !truthy(Some(schema)) || !truthy(get(schema, "enum")) {
        return out;
    }
    let enums = get(schema, "enum")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let limit = if limit == 0 { -1 } else { limit };
    if !is_long_view {
        out.push('\n');
        out.push_str(&" ".repeat(indent_amount));
        out.push_str("enum: ");
    } else {
        out.push_str("ENUM:");
    }
    for (i, el) in enums.iter().enumerate() {
        if limit > -1 && (i as i64) >= limit {
            out.push_str(", ....");
            break;
        }
        if i > 0 && !is_long_view {
            out.push_str(", ");
        } else if is_long_view {
            out.push_str("\n    ");
        }
        match el {
            Value::String(s) if s.is_empty() => out.push_str("\"\""),
            other => out.push_str(&go_display(other)),
        }
    }
    out
}

/// Template "fieldDetail".
fn field_detail(
    name: &str,
    schema: &Value,
    short: bool,
    level: usize,
    document: &Value,
) -> Result<String, String> {
    let indent_amount = level * 2;
    let field_schema = get(schema, "properties")
        .and_then(|p| get(p, name))
        .cloned()
        .unwrap_or(Value::Null);
    let mut out = indent(indent_amount, name);
    out.push_str("\t<");
    out.push_str(&type_guess(&field_schema, document)?);
    out.push('>');
    let required = get(schema, "required")
        .and_then(Value::as_array)
        .is_some_and(|r| r.iter().any(|v| v.as_str() == Some(name)));
    if required {
        out.push_str(" -required-");
    }
    out.push_str(&extract_enum(&field_schema, false, 4, indent_amount));
    out.push('\n');
    if !short {
        let desc = match get(&field_schema, "description") {
            v if truthy(v) => v.and_then(Value::as_str).unwrap_or("").to_string(),
            _ => "<no description>".to_string(),
        };
        let width = 78usize.saturating_sub(indent_amount);
        out.push_str(&indent(indent_amount + 2, &wrap(width, &desc)));
        out.push_str("\n\n");
    }
    Ok(out)
}

/// `set $ "history" (set $.history ref 1)`.
fn with_history(history: &BTreeSet<String>, r: &str) -> BTreeSet<String> {
    let mut h = history.clone();
    h.insert(r.to_string());
    h
}

/// Template "fieldList".
fn field_list(
    schema: &Value,
    level: usize,
    history: &BTreeSet<String>,
    document: &Value,
    recursive: bool,
    depth: usize,
) -> Result<String, String> {
    if depth > MAX_DEPTH {
        return Ok(String::new());
    }
    let ref_string = str_of(schema, "$ref");
    if !ref_string.is_empty() && history.contains(ref_string) {
        return Ok(String::new());
    }
    let next = with_history(history, ref_string);
    let res = resolved(schema, document);
    let mut out = String::new();
    if let Some(props) = get(res, "properties").and_then(Value::as_object) {
        let mut keys: Vec<&String> = props.keys().collect();
        keys.sort();
        for k in keys {
            out.push_str(&field_detail(k, res, recursive, level, document)?);
            if recursive {
                out.push_str(&field_list(
                    &props[k],
                    level + 1,
                    &next,
                    document,
                    recursive,
                    depth + 1,
                )?);
            }
        }
    }
    if let Some(all_of) = get(res, "allOf").and_then(Value::as_array) {
        for sub in all_of {
            out.push_str(&field_list(
                sub,
                level,
                &next,
                document,
                recursive,
                depth + 1,
            )?);
        }
    }
    if truthy(get(res, "items")) {
        out.push_str(&field_list(
            get(res, "items").unwrap(),
            level,
            &next,
            document,
            recursive,
            depth + 1,
        )?);
    }
    if let Some(ap) = map_additional(res) {
        out.push_str(&field_list(
            ap,
            level,
            &next,
            document,
            recursive,
            depth + 1,
        )?);
    }
    Ok(out)
}

/// Template "description".
fn description(schema: &Value, document: &Value, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return String::new();
    }
    let cur = resolved(schema, document);
    if !truthy(Some(cur)) {
        return String::new();
    }
    let mut out = String::new();
    if truthy(get(cur, "description")) {
        out.push_str(str_of(cur, "description"));
        out.push('\n');
    }
    if let Some(all_of) = get(cur, "allOf").and_then(Value::as_array) {
        for sub in all_of {
            out.push_str(&description(sub, document, depth + 1));
        }
    }
    if truthy(get(cur, "items")) {
        out.push_str(&description(
            get(cur, "items").unwrap(),
            document,
            depth + 1,
        ));
    }
    if let Some(ap) = map_additional(cur) {
        out.push_str(&description(ap, document, depth + 1));
    }
    out
}

/// Template "output".
fn output(
    schema: &Value,
    history: &BTreeSet<String>,
    field_path: &[String],
    document: &Value,
    recursive: bool,
    depth: usize,
) -> Result<String, String> {
    if depth > MAX_DEPTH {
        return Ok(String::new());
    }
    let ref_string = str_of(schema, "$ref");
    let next = with_history(history, ref_string);
    let res = resolved(schema, document);
    if field_path.is_empty() {
        let d = description(res, document, 0);
        let d = if d.is_empty() {
            "<empty>".to_string()
        } else {
            d
        };
        let mut out = String::from("DESCRIPTION:\n");
        out.push_str(&indent(4, &wrap(76, &d)));
        out.push('\n');
        let list = field_list(res, 1, &BTreeSet::new(), document, recursive, 0)?;
        if !list.is_empty() {
            out.push_str("FIELDS:\n");
            out.push_str(&list);
        }
        return Ok(out);
    }
    if !ref_string.is_empty() && history.contains(ref_string) {
        // Hit a cycle: stop and do nothing.
        return Ok(String::new());
    }
    let first = &field_path[0];
    if let Some(sub) = get(res, "properties")
        .and_then(|p| get(p, first))
        .filter(|s| truthy(Some(s)))
    {
        let mut out = String::new();
        if field_path.len() == 1 {
            out.push_str(&format!(
                "FIELD: {first} <{}>\n",
                type_guess(sub, document)?
            ));
            out.push_str(&extract_enum(sub, true, -1, 0));
            out.push_str("\n\n");
        }
        out.push_str(&output(
            sub,
            &BTreeSet::new(),
            &field_path[1..],
            document,
            recursive,
            depth + 1,
        )?);
        return Ok(out);
    }
    if truthy(get(res, "items")) {
        return output(
            get(res, "items").unwrap(),
            &next,
            field_path,
            document,
            recursive,
            depth + 1,
        );
    }
    if let Some(ap) = map_additional(res) {
        return output(ap, &next, field_path, document, recursive, depth + 1);
    }
    if let Some(all_of) = get(res, "allOf").and_then(Value::as_array) {
        for sub in all_of {
            let o = output(sub, &next, field_path, document, recursive, depth + 1)?;
            if !o.is_empty() {
                return Ok(o);
            }
        }
    }
    Ok(String::new())
}

/// `plaintext.tmpl` main template + generator.go `Render`: the `error: ...`
/// strings are the `explainError`s `PrintModelDescription` returns as is.
pub fn render_plaintext(
    document: &Value,
    gvr: &Gvr,
    field_path: &[String],
    recursive: bool,
) -> Result<String, String> {
    let prefix = if gvr.group.is_empty() {
        "/api".to_string()
    } else {
        format!("/apis/{}", gvr.group)
    };
    let search = [
        format!("{prefix}/{}/{}", gvr.version, gvr.resource),
        format!("{prefix}/{}/{}/{{name}}", gvr.version, gvr.resource),
        format!(
            "{prefix}/{}/namespaces/{{namespace}}/{}",
            gvr.version, gvr.resource
        ),
        format!(
            "{prefix}/{}/namespaces/{{namespace}}/{}/{{name}}",
            gvr.version, gvr.resource
        ),
    ];
    // Pull the GVK from an operation. `with $gvk = index ...` assigns on every
    // method that has an operation object, and `break` only leaves the method
    // loop, so the last path that has any operation decides.
    let mut gvk: Option<Value> = None;
    for path in &search {
        let elem = get(document, "paths").and_then(|p| get(p, path));
        if !truthy(elem) {
            continue;
        }
        for method in ["get", "post", "put", "patch", "delete"] {
            let op = get(elem.unwrap(), method);
            if !truthy(op) {
                continue;
            }
            gvk = get(op.unwrap(), "x-kubernetes-group-version-kind").cloned();
            if truthy(gvk.as_ref()) {
                break;
            }
        }
    }
    let Some(gvk) = gvk.filter(|g| truthy(Some(g))) else {
        return Err(format!(
            "error: GVR ({}) not found in OpenAPI schema",
            gvr.go_string()
        ));
    };
    let mut out = String::new();
    if truthy(get(&gvk, "group")) {
        out.push_str(&format!(
            "GROUP:      {}\n",
            go_display(get(&gvk, "group").unwrap())
        ));
    }
    out.push_str(&format!(
        "KIND:       {}\nVERSION:    {}\n\n",
        get(&gvk, "kind").map(go_display).unwrap_or_default(),
        get(&gvk, "version").map(go_display).unwrap_or_default(),
    ));

    // Template "schema".
    let mut body = String::new();
    if let Some(schemas) = get(document, "components")
        .and_then(|c| get(c, "schemas"))
        .and_then(Value::as_object)
    {
        let mut names: Vec<&String> = schemas.keys().collect();
        names.sort();
        for name in names {
            let s = &schemas[name];
            let matches = get(s, "x-kubernetes-group-version-kind")
                .and_then(Value::as_array)
                .is_some_and(|l| l.iter().any(|g| g == &gvk));
            if !matches {
                continue;
            }
            let o = output(s, &BTreeSet::new(), field_path, document, recursive, 0)?;
            if o.is_empty() {
                let last = field_path.last().map(String::as_str).unwrap_or("");
                return Err(format!("error: field \"{last}\" does not exist"));
            }
            body = o;
            break;
        }
    }
    if body.is_empty() {
        return Err(format!(
            "error: GVK {} not found in OpenAPI schema",
            go_display(&gvk)
        ));
    }
    out.push_str(&body);
    out.push('\n');
    Ok(out)
}

/// `PrintModelDescription` (explain/v2/explain.go:55): fetch the group-version
/// document from `/openapi/v3` and render it.
pub async fn print_model_description(
    client: &ApiClient,
    field_path: &[String],
    gvr: &Gvr,
    recursive: bool,
) -> Result<String, String> {
    let index: Value = client
        .get("/openapi/v3")
        .await
        .map_err(|e| format!("failed to fetch list of groupVersions: {e}"))?;
    let resource_path = if gvr.group.is_empty() {
        format!("api/{}", gvr.version)
    } else {
        format!("apis/{}/{}", gvr.group, gvr.version)
    };
    let url = get(&index, "paths")
        .and_then(|p| get(p, &resource_path))
        .map(|gv| str_of(gv, "serverRelativeURL").to_string())
        .ok_or_else(|| format!("couldn't find resource for \"{}\"", gvr.go_string()))?;
    let document: Value = client
        .get(&url)
        .await
        .map_err(|e| format!("failed to fetch openapi schema for {resource_path}: {e}"))?;
    render_plaintext(&document, gvr, field_path, recursive)
}
