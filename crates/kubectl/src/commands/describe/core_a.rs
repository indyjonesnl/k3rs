//! `kubectl describe` for ConfigMap, Secret, ServiceAccount, ResourceQuota,
//! LimitRange and PriorityClass.
//!
//! Ported from `staging/src/k8s.io/kubectl/pkg/describe/describe.go`:
//! `ConfigMapDescriber.Describe` (:4285), `describeSecret` (:2590),
//! `describeServiceAccount` (:3252), `describeQuota` (:681),
//! `helpTextForResourceQuotaScope` (:662), `describeLimitRange` (:644) with
//! `describeLimitRangeSpec` (:508), `describePriorityClass` (:4728).
//! Each takes the already-fetched object; `events` is `None` when events were
//! not requested (`DescriberSettings.ShowEvents`). Registration in `execute`
//! is the wiring task (kubectl-P1-16).

use super::events::{
    describe_events_at, print_annotations_multiline, print_labels_multiline, PrefixWriter, LEVEL_0,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use kubernetes_rs_common::quantity::{Format, Quantity};
use kubernetes_rs_common::resources::Event;
use serde_json::Value;
use std::collections::BTreeMap;

fn str_at<'a>(obj: &'a Value, ptr: &str) -> &'a str {
    obj.pointer(ptr).and_then(Value::as_str).unwrap_or("")
}

fn string_map(obj: &Value, ptr: &str) -> BTreeMap<String, String> {
    obj.pointer(ptr)
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Decoded length of a `[]byte` field (JSON base64).
fn decoded(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap_or(""))
        .unwrap_or_default()
}

/// `Name`, `Namespace`, `Labels`, `Annotations` (the common header).
fn header(w: &mut PrefixWriter, obj: &Value) {
    w.write(
        LEVEL_0,
        &format!("Name:\t{}\n", str_at(obj, "/metadata/name")),
    );
    w.write(
        LEVEL_0,
        &format!("Namespace:\t{}\n", str_at(obj, "/metadata/namespace")),
    );
    print_labels_multiline(w, "Labels", &string_map(obj, "/metadata/labels"));
    print_annotations_multiline(w, "Annotations", &string_map(obj, "/metadata/annotations"));
}

/// `ConfigMapDescriber.Describe` (describe.go:4296-4325).
pub fn describe_config_map(obj: &Value, events: Option<&[Event]>, now: DateTime<Utc>) -> String {
    let mut w = PrefixWriter::new();
    header(&mut w, obj);
    w.write(LEVEL_0, "\nData\n====\n");
    let data = string_map(obj, "/data"); // BTreeMap iterates sorted, `slices.Sorted(maps.Keys)`.
    for (k, v) in &data {
        w.write(LEVEL_0, &format!("{k}:\n----\n"));
        w.write(LEVEL_0, &format!("{v}\n"));
        w.write(LEVEL_0, "\n");
    }
    w.write(LEVEL_0, "\nBinaryData\n====\n");
    let binary: BTreeMap<&String, usize> = obj
        .pointer("/binaryData")
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k, decoded(v).len())).collect())
        .unwrap_or_default();
    for (k, n) in &binary {
        w.write(LEVEL_0, &format!("{k}: {n} bytes\n"));
    }
    w.write(LEVEL_0, "\n");
    if let Some(events) = events {
        describe_events_at(events, &mut w, now);
    }
    w.finish()
}

/// `describeSecret` (describe.go:2590-2614). Values are never printed, except
/// the `token` key of a `kubernetes.io/service-account-token` Secret.
pub fn describe_secret(obj: &Value) -> String {
    let mut w = PrefixWriter::new();
    header(&mut w, obj);
    let ty = str_at(obj, "/type");
    w.write(LEVEL_0, &format!("\nType:\t{ty}\n"));
    w.write(LEVEL_0, "\nData\n====\n");
    let data: BTreeMap<&String, Vec<u8>> = obj
        .pointer("/data")
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k, decoded(v))).collect())
        .unwrap_or_default();
    for (k, v) in &data {
        if k.as_str() == "token" && ty == "kubernetes.io/service-account-token" {
            w.write(LEVEL_0, &format!("{k}:\t{}\n", String::from_utf8_lossy(v)));
        } else {
            w.write(LEVEL_0, &format!("{k}:\t{} bytes\n", v.len()));
        }
    }
    w.finish()
}

/// `describeServiceAccount` (describe.go:3252-3293).
pub fn describe_service_account(
    obj: &Value,
    events: Option<&[Event]>,
    now: DateTime<Utc>,
) -> String {
    let mut w = PrefixWriter::new();
    header(&mut w, obj);
    const EMPTY_HEADER: &str = "                   ";
    const PULL_HEADER: &str = "Image pull secrets:";
    let names: Vec<&str> = obj
        .pointer("/imagePullSecrets")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|s| s.get("name").and_then(Value::as_str).unwrap_or(""))
                .collect()
        })
        .unwrap_or_default();
    if names.is_empty() {
        w.write(LEVEL_0, &format!("{PULL_HEADER}\t<none>\n"));
    } else {
        let mut prefix = PULL_HEADER;
        for name in names {
            w.write(LEVEL_0, &format!("{prefix}\t{name}\n"));
            prefix = EMPTY_HEADER;
        }
    }
    if let Some(events) = events {
        describe_events_at(events, &mut w, now);
    }
    w.finish()
}

/// `helpTextForResourceQuotaScope` (describe.go:662-676).
fn help_text_for_resource_quota_scope(scope: &str) -> &'static str {
    match scope {
        "Terminating" => "Matches all pods that have an active deadline. These pods have a limited lifespan on a node before being actively terminated by the system.",
        "NotTerminating" => "Matches all pods that do not have an active deadline. These pods usually include long running pods whose container command is not expected to terminate.",
        "BestEffort" => "Matches all pods that do not have resource requirements set. These pods have a best effort quality of service.",
        "NotBestEffort" => "Matches all pods that have at least one resource requirement set. These pods have a burstable or guaranteed quality of service.",
        _ => "",
    }
}

/// `resource.Quantity.String()` of a JSON quantity (canonical form).
fn quantity_string(v: &Value) -> String {
    let raw = v
        .as_str()
        .map(str::to_string)
        .or_else(|| v.as_i64().map(|n| n.to_string()))
        .unwrap_or_default();
    Quantity::parse(&raw)
        .map(|q| q.canonical_string())
        .unwrap_or(raw)
}

/// `describeQuota` (describe.go:681-720).
pub fn describe_resource_quota(obj: &Value) -> String {
    let mut w = PrefixWriter::new();
    w.write(
        LEVEL_0,
        &format!("Name:\t{}\n", str_at(obj, "/metadata/name")),
    );
    w.write(
        LEVEL_0,
        &format!("Namespace:\t{}\n", str_at(obj, "/metadata/namespace")),
    );
    let mut scopes: Vec<&str> = obj
        .pointer("/spec/scopes")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !scopes.is_empty() {
        scopes.sort();
        w.write(LEVEL_0, &format!("Scopes:\t{}\n", scopes.join(", ")));
        for scope in &scopes {
            let help = help_text_for_resource_quota_scope(scope);
            if !help.is_empty() {
                w.write(LEVEL_0, &format!(" * {help}\n"));
            }
        }
    }
    w.write(LEVEL_0, "Resource\tUsed\tHard\n");
    w.write(LEVEL_0, "--------\t----\t----\n");
    let hard = obj.pointer("/status/hard").and_then(Value::as_object);
    let used = obj.pointer("/status/used").and_then(Value::as_object);
    let mut names: Vec<&String> = hard.map(|m| m.keys().collect()).unwrap_or_default();
    names.sort(); // SortableResourceNames
    for name in names {
        let hard_q = hard.and_then(|m| m.get(name)).and_then(quantity_string_q);
        let used_q = match used.and_then(|m| m.get(name)) {
            Some(v) => quantity_string_q(v),
            None => Some(Quantity::from_value(0, Format::DecimalSI)),
        };
        let hard_str = hard
            .and_then(|m| m.get(name))
            .map(quantity_string)
            .unwrap_or_default();
        // `if hardQuantity.Format != usedQuantity.Format { usedQuantity =
        // *resource.NewQuantity(usedQuantity.Value(), hardQuantity.Format) }`.
        let used_str = match (&hard_q, used_q) {
            (Some(h), Some(u)) if h.format() != u.format() => {
                Quantity::from_value(u.value() as i64, h.format()).canonical_string()
            }
            (_, Some(u)) => u.canonical_string(),
            _ => String::new(),
        };
        w.write(LEVEL_0, &format!("{name}\t{used_str}\t{hard_str}\n"));
    }
    w.finish()
}

fn quantity_string_q(v: &Value) -> Option<Quantity> {
    let raw = v
        .as_str()
        .map(str::to_string)
        .or_else(|| v.as_i64().map(|n| n.to_string()))?;
    Quantity::parse(&raw).ok()
}

/// `describeLimitRangeSpec` (describe.go:508-566). Go ranges over a map, so the
/// resource order is unspecified; resources are sorted by name here.
fn describe_limit_range_spec(spec: &Value, prefix: &str, w: &mut PrefixWriter) {
    let Some(limits) = spec.pointer("/limits").and_then(Value::as_array) else {
        return;
    };
    for item in limits {
        let ty = item.get("type").and_then(Value::as_str).unwrap_or("");
        let field = |name: &str| item.get(name).and_then(Value::as_object);
        let (max, min, def, def_req, ratio) = (
            field("max"),
            field("min"),
            field("default"),
            field("defaultRequest"),
            field("maxLimitRequestRatio"),
        );
        let mut set: Vec<&String> = [max, min, def, def_req, ratio]
            .iter()
            .flatten()
            .flat_map(|m| m.keys())
            .collect();
        set.sort();
        set.dedup();
        for k in set {
            let val = |m: Option<&serde_json::Map<String, Value>>| {
                m.and_then(|m| m.get(k))
                    .map(quantity_string)
                    .unwrap_or_else(|| "-".to_string())
            };
            w.write(
                LEVEL_0,
                &format!(
                    "{prefix}{ty}\t{k}\t{}\t{}\t{}\t{}\t{}\n",
                    val(min),
                    val(max),
                    val(def_req),
                    val(def),
                    val(ratio)
                ),
            );
        }
    }
}

/// `describeLimitRange` (describe.go:644-657).
pub fn describe_limit_range(obj: &Value) -> String {
    let mut w = PrefixWriter::new();
    w.write(
        LEVEL_0,
        &format!("Name:\t{}\n", str_at(obj, "/metadata/name")),
    );
    w.write(
        LEVEL_0,
        &format!("Namespace:\t{}\n", str_at(obj, "/metadata/namespace")),
    );
    w.write(
        LEVEL_0,
        "Type\tResource\tMin\tMax\tDefault Request\tDefault Limit\tMax Limit/Request Ratio\n",
    );
    w.write(
        LEVEL_0,
        "----\t--------\t---\t---\t---------------\t-------------\t-----------------------\n",
    );
    if let Some(spec) = obj.get("spec") {
        describe_limit_range_spec(spec, "", &mut w);
    }
    w.finish()
}

/// `labels.FormatLabels` (apimachinery/pkg/labels/labels.go): `k=v,k=v` sorted,
/// `<none>` when empty.
fn format_labels(m: &BTreeMap<String, String>) -> String {
    if m.is_empty() {
        return "<none>".to_string();
    }
    m.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// `describePriorityClass` (describe.go:4728-4745). `preemptionPolicy` is
/// dereferenced unconditionally upstream (the API server defaults it); an absent
/// value prints the default, `PreemptLowerPriority`.
pub fn describe_priority_class(
    obj: &Value,
    events: Option<&[Event]>,
    now: DateTime<Utc>,
) -> String {
    let mut w = PrefixWriter::new();
    w.write(
        LEVEL_0,
        &format!("Name:\t{}\n", str_at(obj, "/metadata/name")),
    );
    let value = obj.get("value").and_then(Value::as_i64).unwrap_or(0);
    w.write(LEVEL_0, &format!("Value:\t{value}\n"));
    let global_default = obj
        .get("globalDefault")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    w.write(LEVEL_0, &format!("GlobalDefault:\t{global_default}\n"));
    let policy = obj
        .get("preemptionPolicy")
        .and_then(Value::as_str)
        .unwrap_or("PreemptLowerPriority");
    w.write(LEVEL_0, &format!("PreemptionPolicy:\t{policy}\n"));
    w.write(
        LEVEL_0,
        &format!("Description:\t{}\n", str_at(obj, "/description")),
    );
    w.write(
        LEVEL_0,
        &format!(
            "Annotations:\t{}\n",
            format_labels(&string_map(obj, "/metadata/annotations"))
        ),
    );
    if let Some(events) = events {
        describe_events_at(events, &mut w, now);
    }
    w.finish()
}
