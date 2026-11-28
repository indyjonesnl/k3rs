//! Ports of `TestPersistentVolumeDescriber`, `TestPersistentVolumeClaimDescriber`,
//! `TestDescribeStorageClass` and `TestDescribeCSINode`
//! (`kubectl/pkg/describe/describe_test.go:1965, 2349, 3966, 4066`).
use chrono::{DateTime, Duration, Utc};
use kubernetes_rs_kubectl::commands::describe::storage::*;
use serde_json::{json, Value};

fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Keep each line's indent, collapse the tabwriter's column padding.
fn norm(s: &str) -> String {
    s.split('\n')
        .map(|l| {
            let body = l.trim_start_matches(' ');
            let indent = &l[..l.len() - body.len()];
            let mut out = String::from(indent);
            let mut prev_space = false;
            for c in body.chars() {
                if c == ' ' {
                    if !prev_space {
                        out.push(c);
                    }
                    prev_space = true;
                } else {
                    out.push(c);
                    prev_space = false;
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn check(out: &str, expected: &[&str], unexpected: &[&str]) {
    let n = norm(out);
    for e in expected {
        assert!(n.contains(&norm(e)), "expected {e:?} in output:\n{out}");
    }
    for u in unexpected {
        assert!(!n.contains(&norm(u)), "unexpected {u:?} in output:\n{out}");
    }
}

fn pv(spec: Value) -> Value {
    json!({"metadata": {"name": "bar"}, "spec": spec})
}

#[test]
fn describe_storage_pv_sources_and_volume_mode() {
    // test0 hostpath: no VolumeMode line without spec.volumeMode.
    let out = describe_persistent_volume(&pv(json!({"hostPath": {"type": ""}})), None, now());
    check(
        &out,
        &["HostPath (bare host directory volume)", "HostPathType:"],
        &["VolumeMode", "Filesystem"],
    );
    // test3 nfs
    let out = describe_persistent_volume(&pv(json!({"nfs": {}})), None, now());
    check(
        &out,
        &["NFS (an NFS mount that lasts the lifetime of a pod)"],
        &["VolumeMode"],
    );
    // block / filesystem
    let out =
        describe_persistent_volume(&pv(json!({"nfs": {}, "volumeMode": "Block"})), None, now());
    check(&out, &["VolumeMode", "Block"], &[]);
    let out = describe_persistent_volume(
        &pv(json!({"local": {"path": "/mnt/d"}, "volumeMode": "Filesystem"})),
        None,
        now(),
    );
    check(
        &out,
        &[
            "VolumeMode",
            "Filesystem",
            "LocalVolume (a persistent volume backed by local storage on a node)",
            "Path:",
            "/mnt/d",
        ],
        &[],
    );
    // no source known
    let out = describe_persistent_volume(&pv(json!({})), None, now());
    check(&out, &["Source:\n  <unknown>\n"], &[]);
}

#[test]
fn describe_storage_pv_csi_source_and_attributes() {
    let out = describe_persistent_volume(
        &pv(
            json!({"csi": {"driver": "d.example", "volumeHandle": "vh-1", "fsType": "ext4",
            "volumeAttributes": {"b": "2", "a": "1"}}}),
        ),
        None,
        now(),
    );
    check(
        &out,
        &[
            "CSI (a Container Storage Interface (CSI) volume source)",
            "Driver:",
            "d.example",
            "VolumeHandle:",
            "vh-1",
            "FSType:",
            "ext4",
            "ReadOnly:",
            "false",
            "VolumeAttributes:",
            "a=1",
            "b=2",
        ],
        &[],
    );
    let a = out.find("a=1").unwrap();
    let b = out.find("b=2").unwrap();
    assert!(a < b, "attributes sorted");
}

#[test]
fn describe_storage_pv_header_claim_status_and_node_affinity() {
    let v = json!({
        "metadata": {"name": "pv1", "finalizers": ["kubernetes.io/pv-protection"],
                     "annotations": {"volume.beta.kubernetes.io/storage-class": "beta"}},
        "spec": {
            "storageClassName": "ignored", "accessModes": ["ReadWriteMany", "ReadWriteOnce", "ReadWriteOnce"],
            "capacity": {"storage": "10Gi"}, "persistentVolumeReclaimPolicy": "Retain",
            "claimRef": {"namespace": "ns", "name": "c1"},
            "nodeAffinity": {"required": {"nodeSelectorTerms": [
                {"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": ["n1", "n2"]}]}]}},
            "local": {"path": "/x"}
        },
        "status": {"phase": "Bound", "message": "hi"}
    });
    let out = describe_persistent_volume(&v, None, now());
    check(
        &out,
        &[
            "Finalizers:    [kubernetes.io/pv-protection]",
            "StorageClass:  beta",
            "Status:        Bound",
            "Claim:         ns/c1",
            "Reclaim Policy:  Retain",
            "Access Modes:    RWO,RWX",
            "Capacity:        10Gi",
            "Node Affinity:",
            "Required Terms:",
            "Term 0:  kubernetes.io/hostname in [n1, n2]",
            "Message:         hi",
        ],
        &[],
    );
}

#[test]
fn describe_storage_pv_terminating_and_events() {
    let mut v = pv(json!({"nfs": {}}));
    v["metadata"]["deletionTimestamp"] = json!((now() - Duration::days(3650 + 3)).to_rfc3339());
    let out = describe_persistent_volume(&v, Some(&[]), now());
    check(&out, &["Terminating (lasts 10y)", "Events:  <none>"], &[]);
    let out = describe_persistent_volume(&v, None, now());
    check(&out, &[], &["Events"]);
}

fn pvc(spec: Value, status: Value) -> Value {
    json!({"metadata": {"namespace": "foo", "name": "bar"}, "spec": spec, "status": status})
}

#[test]
fn describe_storage_pvc_default_and_volume_mode() {
    let spec = json!({"volumeName": "volume1", "storageClassName": "gold"});
    let st = json!({"phase": "Bound"});
    let out =
        describe_persistent_volume_claim(&pvc(spec.clone(), st.clone()), &[], Some(&[]), now());
    check(
        &out,
        &["Events", "StorageClass:  gold", "Volume:         volume1"],
        &["VolumeMode", "Filesystem"],
    );
    let mut s = spec.clone();
    s["volumeMode"] = json!("Filesystem");
    check(
        &describe_persistent_volume_claim(&pvc(s, st.clone()), &[], Some(&[]), now()),
        &["VolumeMode", "Filesystem"],
        &[],
    );
    let mut s = spec;
    s["volumeMode"] = json!("Block");
    check(
        &describe_persistent_volume_claim(&pvc(s, st.clone()), &[], Some(&[]), now()),
        &["VolumeMode", "Block"],
        &[],
    );
    // no-show-events
    let out = describe_persistent_volume_claim(
        &pvc(
            json!({"volumeName": "volume1", "storageClassName": "gold"}),
            st,
        ),
        &[],
        None,
        now(),
    );
    check(&out, &[], &["Events"]);
}

#[test]
fn describe_storage_pvc_capacity_and_modes_come_from_status_once_bound() {
    let out = describe_persistent_volume_claim(
        &pvc(
            json!({"volumeName": "pv1", "resources": {"requests": {"storage": "1Gi"}}}),
            json!({"capacity": {"storage": "2Gi"}, "accessModes": ["ReadOnlyMany", "ReadWriteOnce"]}),
        ),
        &[],
        None,
        now(),
    );
    check(
        &out,
        &["Capacity:       2Gi", "Access Modes:   RWO,ROX"],
        &[],
    );
    let out = describe_persistent_volume_claim(
        &pvc(
            json!({"resources": {"requests": {"storage": "1Gi"}}}),
            json!({}),
        ),
        &[],
        None,
        now(),
    );
    check(&out, &[], &["1Gi"]);
    for key in ["Capacity:", "Access Modes:"] {
        let line = out.lines().find(|l| l.starts_with(key)).unwrap();
        assert_eq!(line.trim_end(), key, "empty until the claim is bound");
    }
}

#[test]
fn describe_storage_pvc_conditions() {
    let t = now();
    let spec = json!({"volumeName": "volume4", "storageClassName": "gold"});
    for (cond, expected) in [
        (
            json!({"type": "Resizing"}),
            vec!["Conditions", "Type", "Resizing"],
        ),
        (
            json!({"status": "True"}),
            vec!["Conditions", "Status", "True"],
        ),
        (
            json!({"reason": "OfflineResize"}),
            vec!["Conditions", "Reason", "OfflineResize"],
        ),
        (
            json!({"message": "User request resize"}),
            vec!["Conditions", "Message", "User request resize"],
        ),
    ] {
        let out = describe_persistent_volume_claim(
            &pvc(spec.clone(), json!({"conditions": [cond]})),
            &[],
            None,
            t,
        );
        check(&out, &expected, &[]);
    }
    let want = t
        .with_timezone(&chrono::Local)
        .format("%a, %d %b %Y %H:%M:%S %z")
        .to_string();
    for key in ["lastProbeTime", "lastTransitionTime"] {
        let mut c = json!({});
        c[key] = json!(t.to_rfc3339());
        let out = describe_persistent_volume_claim(
            &pvc(spec.clone(), json!({"conditions": [c]})),
            &[],
            None,
            t,
        );
        check(&out, &["Conditions", &want], &[]);
    }
}

#[test]
fn describe_storage_pvc_terminating_datasource_and_used_by() {
    let mut v = pvc(
        json!({"volumeName": "volume10", "storageClassName": "gold"}),
        json!({}),
    );
    v["metadata"]["deletionTimestamp"] = json!((now() - Duration::days(3650 + 3)).to_rfc3339());
    check(
        &describe_persistent_volume_claim(&v, &[], None, now()),
        &["Terminating (lasts 10y)"],
        &[],
    );

    let v = pvc(
        json!({"volumeName": "v", "storageClassName": "gold",
               "dataSource": {"name": "srcpvc", "kind": "PersistentVolumeClaim"}}),
        json!({}),
    );
    check(
        &describe_persistent_volume_claim(&v, &[], None, now()),
        &["\nDataSource:\n  Kind:   PersistentVolumeClaim\n  Name:   srcpvc"],
        &[],
    );
    let v = pvc(
        json!({"volumeName": "v", "storageClassName": "gold",
               "dataSource": {"name": "src-snapshot", "kind": "VolumeSnapshot", "apiGroup": "snapshot.storage.k8s.io"}}),
        json!({}),
    );
    check(&describe_persistent_volume_claim(&v, &[], None, now()), &["DataSource:\n  APIGroup:  snapshot.storage.k8s.io\n  Kind:      VolumeSnapshot\n  Name:      src-snapshot\n"], &[]);

    let pods = [
        json!({"metadata": {"name": "b"}}),
        json!({"metadata": {"name": "a"}}),
    ];
    let out = describe_persistent_volume_claim(&pvc(json!({}), json!({})), &pods, None, now());
    check(&out, &["Used By: a\n"], &[]);
    let lines: Vec<&str> = out.lines().collect();
    let i = lines
        .iter()
        .position(|l| l.starts_with("Used By:"))
        .unwrap();
    assert_eq!(
        lines[i + 1].trim(),
        "b",
        "second pod on its own aligned line"
    );
    let out = describe_persistent_volume_claim(&pvc(json!({}), json!({})), &[], None, now());
    check(&out, &["Used By:    <none>"], &[]);
}

#[test]
fn describe_storage_class_all_fields() {
    let sc = json!({
        "metadata": {"name": "foo", "annotations": {"name": "foo", "storageclass.kubernetes.io/is-default-class": "true"}},
        "provisioner": "my-provisioner",
        "parameters": {"param1": "value1", "param2": "value2"},
        "reclaimPolicy": "Retain", "volumeBindingMode": "bindingmode",
        "mountOptions": ["debug"],
        "allowVolumeExpansion": true,
        "allowedTopologies": [
            {"matchLabelExpressions": [
                {"key": "failure-domain.beta.kubernetes.io/zone", "values": ["zone1"]},
                {"key": "kubernetes.io/hostname", "values": ["node1"]}]},
            {"matchLabelExpressions": [
                {"key": "failure-domain.beta.kubernetes.io/zone", "values": ["zone2"]},
                {"key": "kubernetes.io/hostname", "values": ["node2"]}]}]
    });
    let out = describe_storage_class(&sc, Some(&[]), now());
    check(
        &out,
        &[
            "foo",
            "my-provisioner",
            "param1=value1,param2=value2",
            "Retain",
            "bindingmode",
            "IsDefaultClass:",
            "Yes",
            "AllowVolumeExpansion:",
            "True",
            "MountOptions:\n  debug\n",
            "AllowedTopologies:",
            "Term 0:",
            "failure-domain.beta.kubernetes.io/zone in [zone1]",
            "kubernetes.io/hostname in [node1]",
            "Term 1:",
            "zone2",
            "node2",
            "Events:",
        ],
        &[],
    );
}

#[test]
fn describe_storage_class_defaults() {
    let out = describe_storage_class(
        &json!({"metadata": {"name": "s"}, "provisioner": "p"}),
        None,
        now(),
    );
    check(
        &out,
        &[
            "IsDefaultClass:       No",
            "Annotations:          <none>",
            "Parameters:           <none>",
            "AllowVolumeExpansion:  <unset>",
            "MountOptions:          <none>",
        ],
        &[
            "ReclaimPolicy",
            "VolumeBindingMode",
            "AllowedTopologies",
            "Events",
        ],
    );
}

#[test]
fn describe_storage_csi_node() {
    let csi = json!({
        "metadata": {"name": "foo", "creationTimestamp": "2024-05-01T10:00:00Z"},
        "spec": {"drivers": [
            {"name": "driver1", "nodeID": "node1"},
            {"name": "driver2", "nodeID": "node2", "allocatable": {"count": 2}, "topologyKeys": ["k1", "k2"]}]}
    });
    let out = describe_csi_node(&csi, Some(&[]), now());
    check(
        &out,
        &[
            "foo",
            "CreationTimestamp:",
            "Spec:",
            "  Drivers:\n",
            "    driver1:\n",
            "Node ID:  node1",
            "    driver2:\n",
            "Node ID:  node2",
            "      Allocatables:\n",
            "        Count:  2",
            "Topology Keys:  [k1 k2]",
            "Events:",
        ],
        &["Topology Keys:  []"],
    );
}

#[test]
fn describe_storage_access_modes_string_order() {
    let m = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        access_modes_as_string(&m(&[
            "ReadWriteOncePod",
            "ReadWriteMany",
            "ReadOnlyMany",
            "ReadWriteOnce"
        ])),
        "RWO,ROX,RWX,RWOP"
    );
    assert_eq!(access_modes_as_string(&[]), "");
}
