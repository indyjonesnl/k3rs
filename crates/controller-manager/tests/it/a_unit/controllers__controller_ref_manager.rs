//! Ports of `TestClaimPods` / `TestClaimReplicaSets` /
//! `TestClaimControllerRevisions` (`pkg/controller/controller_ref_manager_test.go`)
//! and the patch generators.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kubernetes_rs_common::types::{
    label_selector_as_selector, LabelSelector, ObjectMeta, OwnerReference,
};
use kubernetes_rs_common::{Error, Result};
use kubernetes_rs_controller_manager::controllers::controller_ref_manager::*;
use serde_json::{json, Value};

#[derive(Default)]
struct Rec {
    patches: Mutex<Vec<(String, String, Value)>>,
    fail: Mutex<Option<fn() -> Error>>,
}
#[async_trait]
impl PatchControl for Rec {
    async fn patch(&self, ns: &str, name: &str, patch: &Value) -> Result<()> {
        self.patches
            .lock()
            .unwrap()
            .push((ns.into(), name.into(), patch.clone()));
        match *self.fail.lock().unwrap() {
            Some(f) => Err(f()),
            None => Ok(()),
        }
    }
}

fn kind() -> ControllerKind {
    ControllerKind {
        api_version: "v1".into(),
        kind: "ReplicationController".into(),
    }
}
fn controller(deleting: bool) -> ObjectMeta {
    let mut m = ObjectMeta::new("rc").with_namespace("default");
    m.uid = "rc-uid".into();
    if deleting {
        m.deletion_timestamp = Some(chrono::Utc::now());
    }
    m
}
fn labels(v: &str) -> Option<HashMap<String, String>> {
    Some(HashMap::from([("foo".to_string(), v.to_string())]))
}
fn obj(name: &str, label: &str, owner_uid: Option<&str>) -> ObjectMeta {
    let mut m = ObjectMeta::new(name).with_namespace("default");
    m.uid = format!("{name}-uid");
    m.labels = labels(label);
    if let Some(u) = owner_uid {
        m.owner_references = Some(vec![OwnerReference {
            api_version: "v1".into(),
            kind: "ReplicationController".into(),
            name: "rc".into(),
            uid: u.into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }]);
    }
    m
}
fn mgr(
    rec: &Arc<Rec>,
    deleting: bool,
    can_adopt: Option<CanAdoptFn>,
    fin: &[&str],
) -> ControllerRefManager {
    let sel = label_selector_as_selector(Some(&LabelSelector {
        match_labels: Some(HashMap::from([("foo".to_string(), "bar".to_string())])),
        ..Default::default()
    }))
    .unwrap();
    ControllerRefManager::new(
        rec.clone(),
        controller(deleting),
        sel,
        kind(),
        can_adopt,
        fin.iter().map(|s| s.to_string()).collect(),
    )
}

#[tokio::test]
async fn controller_ref_manager_claim_orphan_matching_adopts() {
    let rec = Arc::new(Rec::default());
    let objs = [obj("a", "bar", None), obj("b", "other", None)];
    let (claimed, err) = mgr(&rec, false, None, &[]).claim_objects(&objs, &[]).await;
    assert!(err.is_none());
    assert_eq!(claimed.len(), 1);
    let p = rec.patches.lock().unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(
        p[0].2,
        json!({"metadata": {"uid": "a-uid", "ownerReferences": [{
            "apiVersion": "v1", "kind": "ReplicationController", "name": "rc",
            "uid": "rc-uid", "controller": true, "blockOwnerDeletion": true}]}})
    );
}

#[tokio::test]
async fn controller_ref_manager_claim_ignores_foreign_and_owned_matching() {
    let rec = Arc::new(Rec::default());
    let objs = [
        obj("a", "bar", Some("rc-uid")),
        obj("b", "bar", Some("someone-else")),
    ];
    let (claimed, err) = mgr(&rec, false, None, &[]).claim_objects(&objs, &[]).await;
    assert!(err.is_none());
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].name, "a");
    assert!(rec.patches.lock().unwrap().is_empty());
}

#[tokio::test]
async fn controller_ref_manager_claim_owned_mismatch_releases() {
    let rec = Arc::new(Rec::default());
    let objs = [obj("a", "other", Some("rc-uid"))];
    let (claimed, err) = mgr(&rec, false, None, &["fin"])
        .claim_objects(&objs, &[])
        .await;
    assert!(err.is_none() && claimed.is_empty());
    assert_eq!(
        rec.patches.lock().unwrap()[0].2,
        json!({"metadata": {"uid": "a-uid",
            "ownerReferences": [{"$patch": "delete", "uid": "rc-uid"}],
            "$deleteFromPrimitiveList/finalizers": ["fin"]}})
    );
}

#[tokio::test]
async fn controller_ref_manager_deleting_controller_neither_adopts_nor_releases() {
    let rec = Arc::new(Rec::default());
    let objs = [
        obj("orphan", "bar", None),
        obj("owned-mismatch", "other", Some("rc-uid")),
        obj("owned-match", "bar", Some("rc-uid")),
    ];
    let (claimed, err) = mgr(&rec, true, None, &[]).claim_objects(&objs, &[]).await;
    assert!(err.is_none());
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].name, "owned-match");
    assert!(rec.patches.lock().unwrap().is_empty());
}

#[tokio::test]
async fn controller_ref_manager_deleting_object_and_other_namespace_not_adopted() {
    let rec = Arc::new(Rec::default());
    let mut deleting = obj("d", "bar", None);
    deleting.deletion_timestamp = Some(chrono::Utc::now());
    let mut other_ns = obj("n", "bar", None);
    other_ns.namespace = Some("other".into());
    let objs = [deleting, other_ns];
    let (claimed, err) = mgr(&rec, false, None, &[]).claim_objects(&objs, &[]).await;
    assert!(err.is_none() && claimed.is_empty());
    assert!(rec.patches.lock().unwrap().is_empty());
}

#[tokio::test]
async fn controller_ref_manager_filters_run_after_selector() {
    let rec = Arc::new(Rec::default());
    let objs = [obj("a", "bar", None), obj("b", "bar", None)];
    let only_b = |o: &ObjectMeta| o.name == "b";
    let (claimed, _) = mgr(&rec, false, None, &[])
        .claim_objects(&objs, &[&only_b])
        .await;
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].name, "b");
}

#[tokio::test]
async fn controller_ref_manager_can_adopt_runs_once_and_blocks_adoption() {
    let rec = Arc::new(Rec::default());
    let calls = Arc::new(Mutex::new(0));
    let c = calls.clone();
    let can_adopt: CanAdoptFn = Box::new(move || {
        *c.lock().unwrap() += 1;
        Box::pin(async { Err(Error::Internal("nope".into())) })
    });
    let objs = [obj("a", "bar", None), obj("b", "bar", None)];
    let m = mgr(&rec, false, Some(can_adopt), &[]).with_controllee_kind("ReplicaSet");
    let (claimed, err) = m.claim_objects(&objs, &[]).await;
    assert!(claimed.is_empty());
    assert_eq!(*calls.lock().unwrap(), 1);
    let msg = err.unwrap().to_string();
    assert!(
        msg.contains("can't adopt ReplicaSet default/a (a-uid): nope"),
        "{msg}"
    );
    assert!(
        msg.contains("[can't adopt") && msg.contains("nope, can't adopt"),
        "{msg}"
    );
    assert!(rec.patches.lock().unwrap().is_empty());
}

#[tokio::test]
async fn controller_ref_manager_release_ignores_not_found_and_invalid() {
    for f in [(|| Error::NotFound("x".into())) as fn() -> Error, || {
        Error::InvalidResource("x".into())
    }] {
        let rec = Arc::new(Rec::default());
        *rec.fail.lock().unwrap() = Some(f);
        let objs = [obj("a", "other", Some("rc-uid"))];
        let (claimed, err) = mgr(&rec, false, None, &[]).claim_objects(&objs, &[]).await;
        assert!(err.is_none() && claimed.is_empty());
    }
    let rec = Arc::new(Rec::default());
    *rec.fail.lock().unwrap() = Some(|| Error::Conflict("c".into()));
    let objs = [obj("a", "other", Some("rc-uid"))];
    let (_, err) = mgr(&rec, false, None, &[]).claim_objects(&objs, &[]).await;
    assert!(err.is_some());
}

#[tokio::test]
async fn controller_ref_manager_adopt_not_found_is_not_an_error() {
    let rec = Arc::new(Rec::default());
    *rec.fail.lock().unwrap() = Some(|| Error::NotFound("gone".into()));
    let objs = [obj("a", "bar", None)];
    let (claimed, err) = mgr(&rec, false, None, &[]).claim_objects(&objs, &[]).await;
    assert!(err.is_none() && claimed.is_empty());
}

#[tokio::test]
async fn controller_ref_manager_recheck_deletion_timestamp() {
    let alive = recheck_deletion_timestamp(|| async { Ok(controller(false)) });
    assert!(alive().await.is_ok());
    let dying = recheck_deletion_timestamp(|| async { Ok(controller(true)) });
    let e = dying().await.unwrap_err().to_string();
    assert!(e.contains("default/rc has just been deleted at"), "{e}");
    let broken = recheck_deletion_timestamp(|| async { Err(Error::NotFound("x".into())) });
    assert!(broken()
        .await
        .unwrap_err()
        .to_string()
        .contains("can't recheck DeletionTimestamp"));
}
