//! Generic describer and Events section of `kubectl describe`.
//!
//! Ports, from `staging/src/k8s.io/kubectl/pkg/describe/describe.go`:
//! `PrefixWriter`/`tabbedString` (tabwriter `0, 8, 2, ' ', 0`),
//! `DescribeEvents` (:4117), `searchEvents` (:5363), `genericDescriber.Describe`
//! (:281), `printUnstructuredContent` (:307), `smartLabelFor` (:350),
//! `printLabelsMultiline` (:4915), `printAnnotationsMultiline` (:5150) and
//! `translateTimestampSince`; plus `duration.HumanDuration`
//! (`apimachinery/pkg/util/duration/duration.go`) and `SortableEvents`
//! (`kubectl/pkg/util/event/sorted_event_list.go`).

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use kubernetes_rs_client::http::ApiClient;
use kubernetes_rs_common::resources::Event;
use serde_json::Value;
use std::collections::BTreeMap;

/// `maxAnnotationLen` (describe.go:5146).
const MAX_ANNOTATION_LEN: usize = 140;
/// `corev1.LastAppliedConfigAnnotation`, the one entry in `skipAnnotations`.
const LAST_APPLIED_CONFIG_ANNOTATION: &str = "kubectl.kubernetes.io/last-applied-configuration";

pub const LEVEL_0: usize = 0;
pub const LEVEL_1: usize = 1;

/// `duration.HumanDuration`.
pub fn human_duration(d: Duration) -> String {
    let seconds = d.num_seconds();
    if seconds < -1 {
        return "<invalid>".into();
    } else if seconds < 0 {
        return "0s".into();
    } else if seconds < 60 * 2 {
        return format!("{seconds}s");
    }
    let minutes = d.num_minutes();
    if minutes < 10 {
        let s = seconds % 60;
        return if s == 0 {
            format!("{minutes}m")
        } else {
            format!("{minutes}m{s}s")
        };
    } else if minutes < 60 * 3 {
        return format!("{minutes}m");
    }
    let hours = d.num_hours();
    if hours < 8 {
        let m = minutes % 60;
        return if m == 0 {
            format!("{hours}h")
        } else {
            format!("{hours}h{m}m")
        };
    } else if hours < 48 {
        return format!("{hours}h");
    } else if hours < 24 * 8 {
        let h = hours % 24;
        return if h == 0 {
            format!("{}d", hours / 24)
        } else {
            format!("{}d{h}h", hours / 24)
        };
    } else if hours < 24 * 365 * 2 {
        return format!("{}d", hours / 24);
    } else if hours < 24 * 365 * 8 {
        let dy = (hours / 24) % 365;
        return if dy == 0 {
            format!("{}y", hours / 24 / 365)
        } else {
            format!("{}y{dy}d", hours / 24 / 365)
        };
    }
    format!("{}y", hours / 24 / 365)
}

/// `translateTimestampSince` / `translateMicroTimestampSince`.
pub fn translate_timestamp_since(t: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    match t {
        None => "<unknown>".into(),
        Some(t) => human_duration(now - t),
    }
}

/// `tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)` over one flushed block of text:
/// consecutive lines sharing a tab-terminated cell at column `c` align it to
/// the widest cell plus padding 2; the unterminated tail of a line is left as is.
pub fn tabbed_string(text: &str) -> String {
    const PADDING: usize = 2;
    let lines: Vec<Vec<&str>> = text.split('\n').map(|l| l.split('\t').collect()).collect();
    // widths[i][c] = width of line i's terminated cell c.
    let mut widths: Vec<Vec<usize>> = lines.iter().map(|l| vec![0; l.len() - 1]).collect();
    let max_cols = lines.iter().map(|l| l.len() - 1).max().unwrap_or(0);
    for c in 0..max_cols {
        let mut i = 0;
        while i < lines.len() {
            if lines[i].len() - 1 <= c {
                i += 1;
                continue;
            }
            let start = i;
            let mut w = 0;
            while i < lines.len() && lines[i].len() - 1 > c {
                w = w.max(lines[i][c].chars().count());
                i += 1;
            }
            for row in widths.iter_mut().take(i).skip(start) {
                row[c] = w + PADDING;
            }
        }
    }
    let mut out = String::new();
    for (i, cells) in lines.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        for (c, cell) in cells.iter().enumerate() {
            out.push_str(cell);
            if c < cells.len() - 1 {
                for _ in cell.chars().count()..widths[i][c] {
                    out.push(' ');
                }
            }
        }
    }
    out
}

/// `PrefixWriter` over a tabwriter. `flush` ends the current alignment block,
/// as `w.Flush()` does in `DescribeEvents`.
#[derive(Default)]
pub struct PrefixWriter {
    done: String,
    buf: String,
}

impl PrefixWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// `Write(level, ...)`: two spaces of indent per level.
    pub fn write(&mut self, level: usize, text: &str) {
        for _ in 0..level {
            self.buf.push_str("  ");
        }
        self.buf.push_str(text);
    }

    /// `WriteLine`.
    pub fn write_line(&mut self, text: &str) {
        self.write(LEVEL_0, &format!("{text}\n"));
    }

    pub fn flush(&mut self) {
        self.done.push_str(&tabbed_string(&self.buf));
        self.buf.clear();
    }

    /// `tabbedString`'s result.
    pub fn finish(mut self) -> String {
        self.flush();
        self.done
    }
}

/// `smartLabelFor` with `camelcase.Split`.
pub fn smart_label_for(field: &str) -> String {
    if field.chars().any(|r| !r.is_alphabetic() && r != '-') {
        return field.to_string();
    }
    let class = |r: char| {
        if r.is_lowercase() {
            1
        } else if r.is_uppercase() {
            2
        } else if r.is_numeric() {
            3
        } else {
            4
        }
    };
    let mut runs: Vec<Vec<char>> = Vec::new();
    let mut last = 0;
    for r in field.chars() {
        let c = class(r);
        if c == last {
            runs.last_mut().expect("run exists").push(r);
        } else {
            runs.push(vec![r]);
        }
        last = c;
    }
    // "PDFL", "oader" -> "PDF", "Loader"
    for i in 0..runs.len().saturating_sub(1) {
        if runs[i][0].is_uppercase() && runs[i + 1][0].is_lowercase() {
            if let Some(moved) = runs[i].pop() {
                runs[i + 1].insert(0, moved);
            }
        }
    }
    const ACRONYMS: [&str; 5] = ["API", "URL", "UID", "OSB", "GUID"];
    runs.into_iter()
        .filter(|p| !p.is_empty())
        .map(|p| p.into_iter().collect::<String>())
        .filter(|p| p != "_")
        .map(|p| {
            if ACRONYMS.contains(&p.to_uppercase().as_str()) {
                p.to_uppercase()
            } else {
                let mut cs = p.chars();
                match cs.next() {
                    Some(f) => f.to_uppercase().collect::<String>() + &cs.as_str().to_lowercase(),
                    None => p,
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Go `%v` of a decoded JSON scalar.
fn go_value(v: &Value) -> String {
    match v {
        Value::Null => "<nil>".into(),
        Value::String(s) => s.clone(),
        Value::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() && f.fract() == 0.0 && f.abs() < 1e21 => format!("{}", f as i64),
            _ => n.to_string(),
        },
        other => other.to_string(),
    }
}

/// `printUnstructuredContent` (describe.go:307).
pub fn print_unstructured_content(
    w: &mut PrefixWriter,
    level: usize,
    content: &serde_json::Map<String, Value>,
    skip_prefix: &str,
    skip: &[&str],
) {
    let mut fields: Vec<&String> = content.keys().collect();
    fields.sort();
    for field in fields {
        let value = &content[field];
        let skip_expr = format!("{skip_prefix}.{field}");
        if skip.contains(&skip_expr.as_str()) {
            continue;
        }
        match value {
            Value::Object(m) => {
                w.write(level, &format!("{}:\n", smart_label_for(field)));
                print_unstructured_content(w, level + 1, m, &skip_expr, skip);
            }
            Value::Array(items) => {
                w.write(level, &format!("{}:\n", smart_label_for(field)));
                for child in items {
                    match child {
                        Value::Object(m) => {
                            print_unstructured_content(w, level + 1, m, &skip_expr, skip)
                        }
                        other => w.write(level + 1, &format!("{}\n", go_value(other))),
                    }
                }
            }
            other => w.write(
                level,
                &format!("{}:\t{}\n", smart_label_for(field), go_value(other)),
            ),
        }
    }
}

/// `printLabelsMultiline`.
pub fn print_labels_multiline(
    w: &mut PrefixWriter,
    title: &str,
    labels: &BTreeMap<String, String>,
) {
    w.write(LEVEL_0, &format!("{title}:\t"));
    if labels.is_empty() {
        w.write_line("<none>");
        return;
    }
    for (i, (k, v)) in labels.iter().enumerate() {
        if i != 0 {
            w.write(LEVEL_0, "\t");
        }
        w.write(LEVEL_0, &format!("{k}={v}\n"));
    }
}

/// `shorten`.
fn shorten(s: &str, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    } else {
        s.to_string()
    }
}

/// `printAnnotationsMultiline`.
pub fn print_annotations_multiline(
    w: &mut PrefixWriter,
    title: &str,
    annotations: &BTreeMap<String, String>,
) {
    w.write(LEVEL_0, &format!("{title}:\t"));
    let keys: Vec<&String> = annotations
        .keys()
        .filter(|k| k.as_str() != LAST_APPLIED_CONFIG_ANNOTATION)
        .collect();
    if keys.is_empty() {
        w.write_line("<none>");
        return;
    }
    for (i, key) in keys.iter().enumerate() {
        if i != 0 {
            w.write(LEVEL_0, "\t");
        }
        let value = annotations[*key]
            .strip_suffix('\n')
            .unwrap_or(&annotations[*key]);
        if value.len() + key.len() + 2 > MAX_ANNOTATION_LEN || value.contains('\n') {
            w.write(LEVEL_0, &format!("{key}:\n"));
            for s in value.split('\n') {
                w.write(
                    LEVEL_0,
                    &format!("\t  {}\n", shorten(s, MAX_ANNOTATION_LEN - 2)),
                );
            }
        } else {
            w.write(LEVEL_0, &format!("{key}: {value}\n"));
        }
    }
}

/// `DescribeEvents` (describe.go:4117), with `now` injected for tests.
pub fn describe_events_at(events: &[Event], w: &mut PrefixWriter, now: DateTime<Utc>) {
    if events.is_empty() {
        w.write(LEVEL_0, "Events:\t<none>\n");
        return;
    }
    w.flush();
    // `SortableEvents`: by LastTimestamp.
    let mut sorted: Vec<&Event> = events.iter().collect();
    sorted.sort_by_key(|e| e.last_timestamp);
    w.write(LEVEL_0, "Events:\n  Type\tReason\tAge\tFrom\tMessage\n");
    w.write(LEVEL_1, "----\t------\t----\t----\t-------\n");
    for e in sorted {
        let first_since = if e.event_time.is_some() {
            translate_timestamp_since(e.event_time, now)
        } else {
            translate_timestamp_since(e.first_timestamp, now)
        };
        let interval = if let Some(series) = &e.series {
            format!(
                "{} (x{} over {})",
                translate_timestamp_since(Some(series.last_observed_time), now),
                series.count,
                first_since
            )
        } else if e.count > 1 {
            format!(
                "{} (x{} over {})",
                translate_timestamp_since(e.last_timestamp, now),
                e.count,
                first_since
            )
        } else {
            first_since
        };
        let source = if e.source.component.is_empty() {
            e.reporting_component.clone().unwrap_or_default()
        } else {
            e.source.component.clone()
        };
        let mut message = e.message.trim().to_string();
        if let Some(fp) = e
            .involved_object
            .field_path
            .as_deref()
            .filter(|f| !f.is_empty())
        {
            message = format!("{fp}: {message}");
        }
        w.write(
            LEVEL_1,
            &format!(
                "{:?}\t{}\t{}\t{}\t{}\n",
                e.event_type, e.reason, interval, source, message
            ),
        );
    }
}

/// `DescribeEvents` at the current time.
pub fn describe_events(events: &[Event], w: &mut PrefixWriter) {
    describe_events_at(events, w, Utc::now())
}

/// Percent-encode a query value.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `searchEvents` (describe.go:5363): events whose involvedObject is `obj`,
/// following `continue` tokens in pages of `limit` (`FollowContinue`).
pub async fn search_events(client: &ApiClient, obj: &Value, limit: i64) -> Result<Vec<Event>> {
    let meta = |k: &str| {
        obj.pointer(&format!("/metadata/{k}"))
            .and_then(Value::as_str)
            .unwrap_or("")
    };
    let kind = obj.get("kind").and_then(Value::as_str).unwrap_or("");
    let namespace = meta("namespace");
    // `fields.Set.AsSelector()` joins `key=value` terms sorted by key; kind and
    // uid are only included when non-empty.
    let mut terms = Vec::new();
    if !kind.is_empty() {
        terms.push(format!("involvedObject.kind={kind}"));
    }
    terms.push(format!("involvedObject.name={}", meta("name")));
    terms.push(format!("involvedObject.namespace={namespace}"));
    if !meta("uid").is_empty() {
        terms.push(format!("involvedObject.uid={}", meta("uid")));
    }
    let selector = encode(&terms.join(","));
    let base = if namespace.is_empty() {
        "/api/v1/events".to_string()
    } else {
        format!("/api/v1/namespaces/{namespace}/events")
    };
    let mut events = Vec::new();
    let mut token = String::new();
    loop {
        let mut path = format!("{base}?fieldSelector={selector}");
        if limit > 0 {
            path.push_str(&format!("&limit={limit}"));
        }
        if !token.is_empty() {
            path.push_str(&format!("&continue={}", encode(&token)));
        }
        let page: Value = client
            .get(&path)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        for item in page
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            events.push(serde_json::from_value(item.clone())?);
        }
        token = page
            .pointer("/metadata/continue")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if token.is_empty() {
            return Ok(events);
        }
    }
}

fn string_map(obj: &Value, pointer: &str) -> BTreeMap<String, String> {
    obj.pointer(pointer)
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// `genericDescriber.Describe` (describe.go:281) over an already-fetched
/// object. `events` is `None` when events were not requested.
pub fn describe_generic(obj: &Value, events: Option<&[Event]>, now: DateTime<Utc>) -> String {
    let mut w = PrefixWriter::new();
    let name = obj
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let ns = obj
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("");
    w.write(LEVEL_0, &format!("Name:\t{name}\n"));
    w.write(LEVEL_0, &format!("Namespace:\t{ns}\n"));
    print_labels_multiline(&mut w, "Labels", &string_map(obj, "/metadata/labels"));
    print_annotations_multiline(
        &mut w,
        "Annotations",
        &string_map(obj, "/metadata/annotations"),
    );
    if let Some(content) = obj.as_object() {
        print_unstructured_content(
            &mut w,
            LEVEL_0,
            content,
            "",
            &[
                ".metadata.managedFields",
                ".metadata.name",
                ".metadata.namespace",
                ".metadata.labels",
                ".metadata.annotations",
            ],
        );
    }
    if let Some(events) = events {
        describe_events_at(events, &mut w, now);
    }
    w.finish()
}
