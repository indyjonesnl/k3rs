//! `kubectl describe` for PersistentVolume, PersistentVolumeClaim,
//! StorageClass and CSINode.
//!
//! Ported from `staging/src/k8s.io/kubectl/pkg/describe/describe.go`:
//! `describePersistentVolume` (:1571), `printVolumeNodeAffinity` (:1529),
//! `describePersistentVolumeClaim` (:1731) with `printPersistentVolumeClaim`
//! (:1769), `printPodsMultiline` (:4983), `describeStorageClass` (:4510),
//! `printAllowedTopologies`, `describeCSINode` (:4596); helpers from
//! `staging/src/k8s.io/kubectl/pkg/util/storage/storage.go`.
//!
//! CSIDriver and VolumeAttachment have no describer upstream
//! (`DescriberFor` falls back to the generic describer), so none is added.
//! PersistentVolume sources other than HostPath, NFS, Local and CSI are not
//! ported yet (backlog kubectl-P1-14b); they print `<unknown>`.
//! Each takes the already-fetched object; `events` is `None` when events were
//! not requested. Registration in `execute` is the wiring task (kubectl-P1-16).

use super::events::{
    describe_events_at, print_annotations_multiline, print_labels_multiline,
    translate_timestamp_since, PrefixWriter, LEVEL_0, LEVEL_1,
};
use chrono::{DateTime, Utc};
use kubernetes_rs_common::quantity::Quantity;
use kubernetes_rs_common::resources::Event;
use serde_json::Value;
use std::collections::BTreeMap;

const LEVEL_2: usize = 2;
const LEVEL_3: usize = 3;
const LEVEL_4: usize = 4;

/// `maxAnnotationLen` (describe.go).
const MAX_ANNOTATION_LEN: usize = 140;

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

fn string_list(obj: &Value, ptr: &str) -> Vec<String> {
    obj.pointer(ptr)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|v| v.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Go's `%v` of a `[]string`: `[a b]`.
fn go_slice(items: &[String]) -> String {
    format!("[{}]", items.join(" "))
}

/// Go's `%v` of a `bool`.
fn go_bool(obj: &Value, ptr: &str) -> &'static str {
    if obj.pointer(ptr).and_then(Value::as_bool).unwrap_or(false) {
        "true"
    } else {
        "false"
    }
}

/// `labels.FormatLabels`: `k=v,k=v` sorted, `<none>` when empty.
fn format_labels(m: &BTreeMap<String, String>) -> String {
    if m.is_empty() {
        return "<none>".to_string();
    }
    m.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// `resource.Quantity.String()`; the zero Quantity prints `0`.
fn quantity_string(v: Option<&Value>) -> String {
    let raw = v
        .and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.as_i64().map(|n| n.to_string()))
        })
        .unwrap_or_default();
    if raw.is_empty() {
        return "0".into();
    }
    Quantity::parse(&raw)
        .map(|q| q.canonical_string())
        .unwrap_or(raw)
}

fn parse_time(obj: &Value, ptr: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(obj.pointer(ptr)?.as_str()?)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// `Time.Format(time.RFC1123Z)` of a `metav1.Time` (which decodes to local
/// time).
fn rfc1123z(t: DateTime<Utc>) -> String {
    t.with_timezone(&chrono::Local)
        .format("%a, %d %b %Y %H:%M:%S %z")
        .to_string()
}

/// `Terminating (lasts <age>)` when deleting, else the phase.
fn status_line(obj: &Value, now: DateTime<Utc>) -> String {
    match parse_time(obj, "/metadata/deletionTimestamp") {
        Some(t) => format!(
            "Terminating (lasts {})",
            translate_timestamp_since(Some(t), now)
        ),
        None => str_at(obj, "/status/phase").to_string(),
    }
}

/// `GetAccessModesAsString` (kubectl/pkg/util/storage/storage.go:49-65):
/// always in the order RWO,ROX,RWX,RWOP, without duplicates.
pub fn access_modes_as_string(modes: &[String]) -> String {
    [
        ("ReadWriteOnce", "RWO"),
        ("ReadOnlyMany", "ROX"),
        ("ReadWriteMany", "RWX"),
        ("ReadWriteOncePod", "RWOP"),
    ]
    .iter()
    .filter(|(full, _)| modes.iter().any(|m| m == full))
    .map(|(_, short)| *short)
    .collect::<Vec<_>>()
    .join(",")
}

const BETA_STORAGE_CLASS_ANNOTATION: &str = "volume.beta.kubernetes.io/storage-class";

/// `GetPersistentVolumeClass` (storage.go:88-97): the beta annotation first.
fn persistent_volume_class(pv: &Value) -> String {
    match pv
        .pointer("/metadata/annotations")
        .and_then(|a| a.get(BETA_STORAGE_CLASS_ANNOTATION))
    {
        Some(c) => c.as_str().unwrap_or("").to_string(),
        None => str_at(pv, "/spec/storageClassName").to_string(),
    }
}

/// `GetPersistentVolumeClaimClass` (storage.go:99-111).
fn persistent_volume_claim_class(pvc: &Value) -> String {
    persistent_volume_class(pvc)
}

/// `IsDefaultAnnotationText` (storage.go:36-47).
fn is_default_annotation_text(obj: &Value) -> &'static str {
    let ann = string_map(obj, "/metadata/annotations");
    let is = |k: &str| ann.get(k).map(String::as_str) == Some("true");
    if is("storageclass.kubernetes.io/is-default-class")
        || is("storageclass.beta.kubernetes.io/is-default-class")
    {
        "Yes"
    } else {
        "No"
    }
}

/// `printNodeSelectorTermsMultilineWithIndent` (describe.go:1551-1569).
fn print_selector_terms(
    w: &mut PrefixWriter,
    level: usize,
    title: &str,
    reqs: &[Value],
    topology: bool,
) {
    w.write(level, &format!("{title}:\t"));
    if reqs.is_empty() {
        w.write_line("<none>");
        return;
    }
    for (i, req) in reqs.iter().enumerate() {
        if i != 0 {
            w.write(level, "\t");
        }
        let op = if topology {
            "in".to_string()
        } else {
            str_at(req, "/operator").to_lowercase()
        };
        let mut expr = format!("{} {}", str_at(req, "/key"), op);
        let values = string_list(req, "/values");
        if !values.is_empty() {
            expr = format!("{expr} [{}]", values.join(", "));
        }
        w.write(LEVEL_0, &format!("{expr}\n"));
    }
}

/// `printVolumeNodeAffinity` (describe.go:1529-1548).
fn print_volume_node_affinity(w: &mut PrefixWriter, affinity: Option<&Value>) {
    w.write(LEVEL_0, "Node Affinity:\t");
    let Some(required) = affinity
        .and_then(|a| a.get("required"))
        .filter(|r| !r.is_null())
    else {
        w.write_line("<none>");
        return;
    };
    w.write_line("");
    w.write(LEVEL_1, "Required Terms:\t");
    let terms = required
        .get("nodeSelectorTerms")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if terms.is_empty() {
        w.write_line("<none>");
        return;
    }
    w.write_line("");
    for (i, term) in terms.iter().enumerate() {
        let reqs = term
            .get("matchExpressions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        print_selector_terms(w, LEVEL_2, &format!("Term {i}"), &reqs, false);
    }
}

/// `printCSIPersistentVolumeAttributesMultilineIndent` (describe.go:1466-1500).
fn print_csi_attributes(w: &mut PrefixWriter, title: &str, attrs: &BTreeMap<String, String>) {
    w.write(LEVEL_2, &format!("{title}:\t"));
    if attrs.is_empty() {
        w.write_line("<none>");
        return;
    }
    for (i, (k, v)) in attrs.iter().enumerate() {
        if i != 0 {
            w.write(LEVEL_2, "\t");
        }
        let line = format!("{k}={v}");
        if line.len() > MAX_ANNOTATION_LEN {
            let mut end = MAX_ANNOTATION_LEN;
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            w.write(LEVEL_2, &format!("{}...\n", &line[..end]));
        } else {
            w.write(LEVEL_2, &format!("{line}\n"));
        }
    }
}

/// `describePersistentVolume` (describe.go:1571-1659).
pub fn describe_persistent_volume(
    pv: &Value,
    events: Option<&[Event]>,
    now: DateTime<Utc>,
) -> String {
    let mut w = PrefixWriter::new();
    w.write(
        LEVEL_0,
        &format!("Name:\t{}\n", str_at(pv, "/metadata/name")),
    );
    print_labels_multiline(&mut w, "Labels", &string_map(pv, "/metadata/labels"));
    print_annotations_multiline(
        &mut w,
        "Annotations",
        &string_map(pv, "/metadata/annotations"),
    );
    w.write(
        LEVEL_0,
        &format!(
            "Finalizers:\t{}\n",
            go_slice(&string_list(pv, "/metadata/finalizers"))
        ),
    );
    w.write(
        LEVEL_0,
        &format!("StorageClass:\t{}\n", persistent_volume_class(pv)),
    );
    w.write(LEVEL_0, &format!("Status:\t{}\n", status_line(pv, now)));
    match pv.pointer("/spec/claimRef").filter(|c| !c.is_null()) {
        Some(c) => w.write(
            LEVEL_0,
            &format!(
                "Claim:\t{}/{}\n",
                str_at(c, "/namespace"),
                str_at(c, "/name")
            ),
        ),
        None => w.write(LEVEL_0, "Claim:\t\n"),
    }
    w.write(
        LEVEL_0,
        &format!(
            "Reclaim Policy:\t{}\n",
            str_at(pv, "/spec/persistentVolumeReclaimPolicy")
        ),
    );
    w.write(
        LEVEL_0,
        &format!(
            "Access Modes:\t{}\n",
            access_modes_as_string(&string_list(pv, "/spec/accessModes"))
        ),
    );
    if let Some(m) = pv.pointer("/spec/volumeMode").and_then(Value::as_str) {
        w.write(LEVEL_0, &format!("VolumeMode:\t{m}\n"));
    }
    w.write(
        LEVEL_0,
        &format!(
            "Capacity:\t{}\n",
            quantity_string(pv.pointer("/spec/capacity/storage"))
        ),
    );
    print_volume_node_affinity(&mut w, pv.pointer("/spec/nodeAffinity"));
    w.write(
        LEVEL_0,
        &format!("Message:\t{}\n", str_at(pv, "/status/message")),
    );
    w.write(LEVEL_0, "Source:\n");
    let src = |k: &str| pv.pointer(&format!("/spec/{k}")).filter(|v| !v.is_null());
    if let Some(hp) = src("hostPath") {
        let ty = hp.get("type").and_then(Value::as_str).unwrap_or("<none>");
        w.write(
            LEVEL_2,
            &format!(
                "Type:\tHostPath (bare host directory volume)\n    Path:\t{}\n    HostPathType:\t{}\n",
                str_at(hp, "/path"),
                ty
            ),
        );
    } else if let Some(nfs) = src("nfs") {
        w.write(
            LEVEL_2,
            &format!(
                "Type:\tNFS (an NFS mount that lasts the lifetime of a pod)\n    Server:\t{}\n    Path:\t{}\n    ReadOnly:\t{}\n",
                str_at(nfs, "/server"),
                str_at(nfs, "/path"),
                go_bool(nfs, "/readOnly")
            ),
        );
    } else if let Some(local) = src("local") {
        w.write(
            LEVEL_2,
            &format!(
                "Type:\tLocalVolume (a persistent volume backed by local storage on a node)\n    Path:\t{}\n",
                str_at(local, "/path")
            ),
        );
    } else if let Some(csi) = src("csi") {
        w.write(
            LEVEL_2,
            &format!(
                "Type:\tCSI (a Container Storage Interface (CSI) volume source)\n    Driver:\t{}\n    FSType:\t{}\n    VolumeHandle:\t{}\n    ReadOnly:\t{}\n",
                str_at(csi, "/driver"),
                str_at(csi, "/fsType"),
                str_at(csi, "/volumeHandle"),
                go_bool(csi, "/readOnly")
            ),
        );
        print_csi_attributes(
            &mut w,
            "VolumeAttributes",
            &string_map(csi, "/volumeAttributes"),
        );
    } else {
        w.write(LEVEL_1, "<unknown>\n");
    }
    if let Some(events) = events {
        describe_events_at(events, &mut w, now);
    }
    w.finish()
}

/// `printPersistentVolumeClaim` (describe.go:1769-1815) with `isFullPVC`.
fn print_persistent_volume_claim(w: &mut PrefixWriter, pvc: &Value, now: DateTime<Utc>) {
    w.write(
        LEVEL_0,
        &format!("Name:\t{}\n", str_at(pvc, "/metadata/name")),
    );
    w.write(
        LEVEL_0,
        &format!("Namespace:\t{}\n", str_at(pvc, "/metadata/namespace")),
    );
    w.write(
        LEVEL_0,
        &format!("StorageClass:\t{}\n", persistent_volume_claim_class(pvc)),
    );
    w.write(LEVEL_0, &format!("Status:\t{}\n", status_line(pvc, now)));
    let volume_name = str_at(pvc, "/spec/volumeName");
    w.write(LEVEL_0, &format!("Volume:\t{volume_name}\n"));
    print_labels_multiline(w, "Labels", &string_map(pvc, "/metadata/labels"));
    print_annotations_multiline(w, "Annotations", &string_map(pvc, "/metadata/annotations"));
    w.write(
        LEVEL_0,
        &format!(
            "Finalizers:\t{}\n",
            go_slice(&string_list(pvc, "/metadata/finalizers"))
        ),
    );
    let (capacity, access_modes) = if volume_name.is_empty() {
        (String::new(), String::new())
    } else {
        (
            quantity_string(pvc.pointer("/status/capacity/storage")),
            access_modes_as_string(&string_list(pvc, "/status/accessModes")),
        )
    };
    w.write(LEVEL_0, &format!("Capacity:\t{capacity}\n"));
    w.write(LEVEL_0, &format!("Access Modes:\t{access_modes}\n"));
    if let Some(m) = pvc.pointer("/spec/volumeMode").and_then(Value::as_str) {
        w.write(LEVEL_0, &format!("VolumeMode:\t{m}\n"));
    }
    if let Some(ds) = pvc.pointer("/spec/dataSource").filter(|d| !d.is_null()) {
        w.write(LEVEL_0, "DataSource:\n");
        if let Some(g) = ds.get("apiGroup").and_then(Value::as_str) {
            w.write(LEVEL_1, &format!("APIGroup:\t{g}\n"));
        }
        w.write(LEVEL_1, &format!("Kind:\t{}\n", str_at(ds, "/kind")));
        w.write(LEVEL_1, &format!("Name:\t{}\n", str_at(ds, "/name")));
    }
}

/// `describePersistentVolumeClaim` (describe.go:1731-1759). `pods` are the
/// pods in the claim's namespace that mount it (`Used By`).
pub fn describe_persistent_volume_claim(
    pvc: &Value,
    pods: &[Value],
    events: Option<&[Event]>,
    now: DateTime<Utc>,
) -> String {
    let mut w = PrefixWriter::new();
    print_persistent_volume_claim(&mut w, pvc, now);
    // printPodsMultiline: sorted by name.
    w.write(LEVEL_0, "Used By:\t");
    let mut names: Vec<&str> = pods.iter().map(|p| str_at(p, "/metadata/name")).collect();
    names.sort_unstable();
    if names.is_empty() {
        w.write_line("<none>");
    } else {
        for (i, n) in names.iter().enumerate() {
            if i != 0 {
                w.write(LEVEL_0, "\t");
            }
            w.write(LEVEL_0, &format!("{n}\n"));
        }
    }
    let conditions = pvc
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !conditions.is_empty() {
        w.write(LEVEL_0, "Conditions:\n");
        w.write(
            LEVEL_1,
            "Type\tStatus\tLastProbeTime\tLastTransitionTime\tReason\tMessage\n",
        );
        w.write(
            LEVEL_1,
            "----\t------\t-----------------\t------------------\t------\t-------\n",
        );
        for c in &conditions {
            // The zero `metav1.Time` formats as year 1.
            let time = |k: &str| {
                parse_time(c, &format!("/{k}"))
                    .map(rfc1123z)
                    .unwrap_or_else(|| "Mon, 01 Jan 0001 00:00:00 +0000".to_string())
            };
            w.write(
                LEVEL_1,
                &format!(
                    "{} \t{} \t{} \t{} \t{} \t{}\n",
                    str_at(c, "/type"),
                    str_at(c, "/status"),
                    time("lastProbeTime"),
                    time("lastTransitionTime"),
                    str_at(c, "/reason"),
                    str_at(c, "/message")
                ),
            );
        }
    }
    if let Some(events) = events {
        describe_events_at(events, &mut w, now);
    }
    w.finish()
}

/// `describeStorageClass` (describe.go:4510-4546).
pub fn describe_storage_class(sc: &Value, events: Option<&[Event]>, now: DateTime<Utc>) -> String {
    let mut w = PrefixWriter::new();
    w.write(
        LEVEL_0,
        &format!("Name:\t{}\n", str_at(sc, "/metadata/name")),
    );
    w.write(
        LEVEL_0,
        &format!("IsDefaultClass:\t{}\n", is_default_annotation_text(sc)),
    );
    w.write(
        LEVEL_0,
        &format!(
            "Annotations:\t{}\n",
            format_labels(&string_map(sc, "/metadata/annotations"))
        ),
    );
    w.write(
        LEVEL_0,
        &format!("Provisioner:\t{}\n", str_at(sc, "/provisioner")),
    );
    w.write(
        LEVEL_0,
        &format!(
            "Parameters:\t{}\n",
            format_labels(&string_map(sc, "/parameters"))
        ),
    );
    let expansion = match sc.pointer("/allowVolumeExpansion").and_then(Value::as_bool) {
        Some(true) => "True",
        Some(false) => "False",
        None => "<unset>",
    };
    w.write(LEVEL_0, &format!("AllowVolumeExpansion:\t{expansion}\n"));
    let options = string_list(sc, "/mountOptions");
    if options.is_empty() {
        w.write(LEVEL_0, "MountOptions:\t<none>\n");
    } else {
        w.write(LEVEL_0, "MountOptions:\n");
        for o in &options {
            w.write(LEVEL_1, &format!("{o}\n"));
        }
    }
    if let Some(p) = sc.pointer("/reclaimPolicy").and_then(Value::as_str) {
        w.write(LEVEL_0, &format!("ReclaimPolicy:\t{p}\n"));
    }
    if let Some(m) = sc.pointer("/volumeBindingMode").and_then(Value::as_str) {
        w.write(LEVEL_0, &format!("VolumeBindingMode:\t{m}\n"));
    }
    if let Some(topologies) = sc.pointer("/allowedTopologies").and_then(Value::as_array) {
        // printAllowedTopologies
        w.write(LEVEL_0, "AllowedTopologies:\t");
        if topologies.is_empty() {
            w.write_line("<none>");
        } else {
            w.write_line("");
            for (i, term) in topologies.iter().enumerate() {
                let reqs = term
                    .get("matchLabelExpressions")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                print_selector_terms(&mut w, LEVEL_1, &format!("Term {i}"), &reqs, true);
            }
        }
    }
    if let Some(events) = events {
        describe_events_at(events, &mut w, now);
    }
    w.finish()
}

/// `describeCSINode` (describe.go:4596-4626).
pub fn describe_csi_node(csi: &Value, events: Option<&[Event]>, now: DateTime<Utc>) -> String {
    let mut w = PrefixWriter::new();
    w.write(
        LEVEL_0,
        &format!("Name:\t{}\n", str_at(csi, "/metadata/name")),
    );
    print_labels_multiline(&mut w, "Labels", &string_map(csi, "/metadata/labels"));
    print_annotations_multiline(
        &mut w,
        "Annotations",
        &string_map(csi, "/metadata/annotations"),
    );
    let created = parse_time(csi, "/metadata/creationTimestamp")
        .map(rfc1123z)
        .unwrap_or_else(|| "Mon, 01 Jan 0001 00:00:00 +0000".to_string());
    w.write(LEVEL_0, &format!("CreationTimestamp:\t{created}\n"));
    w.write(LEVEL_0, "Spec:\n");
    if let Some(drivers) = csi.pointer("/spec/drivers").and_then(Value::as_array) {
        w.write(LEVEL_1, "Drivers:\n");
        for d in drivers {
            w.write(LEVEL_2, &format!("{}:\n", str_at(d, "/name")));
            w.write(LEVEL_3, &format!("Node ID:\t{}\n", str_at(d, "/nodeID")));
            if let Some(count) = d.pointer("/allocatable/count").and_then(Value::as_i64) {
                w.write(LEVEL_3, "Allocatables:\n");
                w.write(LEVEL_4, &format!("Count:\t{count}\n"));
            }
            if let Some(keys) = d.get("topologyKeys").filter(|k| !k.is_null()) {
                let keys: Vec<String> = keys
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|v| v.as_str().unwrap_or("").to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                w.write(LEVEL_3, &format!("Topology Keys:\t{}\n", go_slice(&keys)));
            }
        }
    }
    if let Some(events) = events {
        describe_events_at(events, &mut w, now);
    }
    w.finish()
}
