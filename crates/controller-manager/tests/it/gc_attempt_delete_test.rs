//! GC workers over the graph.
//!
//! Upstream: `garbagecollector_test.go` (`TestAttemptToDeleteItem`,
//! `TestDeleteOwnerRefPatch`, `TestUnblockOwnerReference`,
//! `TestOrphanDependentsFailure`).

use async_trait::async_trait;
use kubernetes_rs_common::types::{ObjectMeta, OwnerReference};
use kubernetes_rs_controller_manager::controllers::gc_graph::*;
use kubernetes_rs_controller_manager::controllers::gc_workers::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

fn id(kind: &str, ns: &str, name: &str, uid: &str) -> ObjectReference {
    ObjectReference {
        api_version: "v1".into(),
        kind: kind.into(),
        name: name.into(),
        uid: uid.into(),
        namespace: ns.into(),
    }
}

fn owner(r: &ObjectReference, block: bool) -> OwnerReference {
    OwnerReference {
        api_version: r.api_version.clone(),
        kind: r.kind.clone(),
        name: r.name.clone(),
        uid: r.uid.clone(),
        block_owner_deletion: block.then_some(true),
        controller: None,
    }
}

fn meta(
    r: &ObjectReference,
    owners: Vec<OwnerReference>,
    fin: &[&str],
    deleting: bool,
) -> ObjectMeta {
    ObjectMeta {
        name: r.name.clone(),
        namespace: (!r.namespace.is_empty()).then(|| r.namespace.clone()),
        uid: r.uid.clone(),
        resource_version: Some("1".into()),
        owner_references: (!owners.is_empty()).then_some(owners),
        finalizers: (!fin.is_empty()).then(|| fin.iter().map(|s| s.to_string()).collect()),
        deletion_timestamp: deleting.then(chrono::Utc::now),
        ..Default::default()
    }
}

fn add(g: &mut Graph, r: &ObjectReference, m: ObjectMeta) {
    g.process_graph_change(&GraphChange {
        virtual_event: false,
        event_type: EventType::Add,
        api_version: r.api_version.clone(),
        kind: r.kind.clone(),
        meta: m,
        old_meta: None,
    });
}

type DeleteCall = (String, Option<Propagation>, Option<String>);

#[derive(Default)]
struct Fake {
    objects: Mutex<HashMap<String, ObjectMeta>>,
    patches: Mutex<Vec<(String, PatchType, Value)>>,
    deletes: Mutex<Vec<DeleteCall>>,
    patch_err: Mutex<Option<ApiError>>,
    /// Delete fails with Conflict this many times first.
    delete_conflicts: Mutex<u32>,
}

impl Fake {
    fn put(&self, r: &ObjectReference, m: ObjectMeta) {
        self.objects.lock().unwrap().insert(r.uid.clone(), m);
    }
    fn find(&self, kind: &str, ns: &str, name: &str) -> Option<ObjectMeta> {
        self.objects
            .lock()
            .unwrap()
            .values()
            .find(|m| {
                m.name == name && m.namespace.as_deref().unwrap_or("") == ns && !kind.is_empty()
            })
            .cloned()
    }
}

#[async_trait]
impl GcApi for Fake {
    async fn is_namespaced(&self, _a: &str, kind: &str) -> Result<bool, GcError> {
        match kind {
            "Pod" | "ReplicaSet" => Ok(true),
            "Node" => Ok(false),
            _ => Err(GcError::RestMapping {
                kind: kind.into(),
                version: "v1".into(),
            }),
        }
    }
    async fn get(
        &self,
        _a: &str,
        kind: &str,
        ns: &str,
        name: &str,
    ) -> Result<ObjectMeta, ApiError> {
        self.find(kind, ns, name)
            .ok_or_else(|| ApiError::NotFound(format!("{name} not found")))
    }
    async fn delete(
        &self,
        id: &ObjectReference,
        _ns: &str,
        pre: Preconditions,
        policy: Option<Propagation>,
    ) -> Result<(), ApiError> {
        {
            let mut c = self.delete_conflicts.lock().unwrap();
            if *c > 0 {
                *c -= 1;
                // Simulate an unrelated update bumping the resourceVersion.
                if let Some(m) = self.objects.lock().unwrap().get_mut(&id.uid) {
                    m.resource_version = Some("2".into());
                }
                return Err(ApiError::Conflict("conflict".into()));
            }
        }
        self.deletes
            .lock()
            .unwrap()
            .push((id.name.clone(), policy, pre.resource_version));
        Ok(())
    }
    async fn patch(
        &self,
        id: &ObjectReference,
        _ns: &str,
        patch: Value,
        t: PatchType,
    ) -> Result<ObjectMeta, ApiError> {
        if let Some(e) = self.patch_err.lock().unwrap().clone() {
            return Err(e);
        }
        self.patches
            .lock()
            .unwrap()
            .push((id.name.clone(), t, patch));
        Ok(ObjectMeta::default())
    }
}

fn workers(fake: Fake, setup: impl FnOnce(&mut Graph, &Fake)) -> GcWorkers<Fake> {
    let mut g = Graph::new();
    setup(&mut g, &fake);
    GcWorkers::new(g, fake)
}

#[tokio::test]
async fn gc_attempt_delete_item_cases() {
    // (name, owner exists in API, owner uid matches, expect delete policy)
    for (name, owner_present, uid_matches, want_delete) in [
        ("owner exists, no delete", true, true, false),
        ("owner gone, background delete", false, true, true),
        ("owner uid changed, background delete", true, false, true),
    ] {
        let o = id("ReplicaSet", "ns", "rs", "rs-uid");
        let p = id("Pod", "ns", "pod", "pod-uid");
        let w = workers(Fake::default(), |g, f| {
            add(g, &o, meta(&o, vec![], &[], false));
            add(g, &p, meta(&p, vec![owner(&o, false)], &[], false));
            f.put(&p, meta(&p, vec![owner(&o, false)], &[], false));
            if owner_present {
                let mut m = meta(&o, vec![], &[], false);
                if !uid_matches {
                    m.uid = "other".into();
                }
                f.put(&o, m);
            }
        });
        w.attempt_to_delete_item("pod-uid")
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let deletes = w.api().deletes.lock().unwrap().clone();
        assert_eq!(!deletes.is_empty(), want_delete, "{name}");
        if want_delete {
            assert_eq!(deletes[0].1, Some(Propagation::Background), "{name}");
            assert_eq!(deletes[0].2.as_deref(), Some("1"), "{name}");
        }
    }
}

#[tokio::test]
async fn gc_attempt_delete_item_virtual_owner_enqueues_delete_event() {
    let o = id("ReplicaSet", "ns", "rs", "rs-uid");
    let w = workers(Fake::default(), |g, _| {
        add(g, &o, meta(&o, vec![], &[], false))
    });
    let e = w.attempt_to_delete_item("rs-uid").await.unwrap_err();
    assert_eq!(e, GcError::EnqueuedVirtualDeleteEvent);
    assert_eq!(w.graph_changes.lock().unwrap().len(), 1);
    assert_eq!(
        w.attempt_to_delete_worker("rs-uid").await,
        WorkQueueItemAction::Forget
    );
}

#[tokio::test]
async fn gc_attempt_delete_item_solid_owner_removes_dangling_refs() {
    let live = id("ReplicaSet", "ns", "rs", "rs-uid");
    let gone = id("ReplicaSet", "ns", "gone", "gone-uid");
    let p = id("Pod", "ns", "pod", "pod-uid");
    let refs = vec![owner(&live, false), owner(&gone, false)];
    let w = workers(Fake::default(), |g, f| {
        add(g, &p, meta(&p, refs.clone(), &[], false));
        f.put(&p, meta(&p, refs.clone(), &[], false));
        f.put(&live, meta(&live, vec![], &[], false));
    });
    w.attempt_to_delete_item("pod-uid").await.unwrap();
    assert!(w.api().deletes.lock().unwrap().is_empty());
    let patches = w.api().patches.lock().unwrap().clone();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0].1, PatchType::StrategicMerge);
    assert_eq!(
        patches[0].2,
        json!({"metadata": {"uid": "pod-uid", "ownerReferences": [{"$patch": "delete", "uid": "gone-uid"}]}})
    );
}

#[tokio::test]
async fn gc_attempt_delete_item_orphan_finalizer_picks_orphan_policy() {
    let o = id("ReplicaSet", "ns", "rs", "rs-uid");
    let p = id("Pod", "ns", "pod", "pod-uid");
    let w = workers(Fake::default(), |g, f| {
        add(g, &p, meta(&p, vec![owner(&o, false)], &["orphan"], false));
        f.put(&p, meta(&p, vec![owner(&o, false)], &["orphan"], false));
    });
    w.attempt_to_delete_item("pod-uid").await.unwrap();
    assert_eq!(
        w.api().deletes.lock().unwrap()[0].1,
        Some(Propagation::Orphan)
    );
}

#[tokio::test]
async fn gc_attempt_delete_item_delete_conflict_retries_without_precondition() {
    let o = id("ReplicaSet", "ns", "rs", "rs-uid");
    let p = id("Pod", "ns", "pod", "pod-uid");
    let w = workers(Fake::default(), |g, f| {
        add(g, &p, meta(&p, vec![owner(&o, false)], &[], false));
        f.put(&p, meta(&p, vec![owner(&o, false)], &[], false));
        *f.delete_conflicts.lock().unwrap() = 1;
    });
    w.attempt_to_delete_item("pod-uid").await.unwrap();
    let d = w.api().deletes.lock().unwrap().clone();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].2, None, "retry drops the resourceVersion precondition");
}

#[tokio::test]
async fn gc_attempt_delete_item_cluster_scoped_item_with_namespaced_owner() {
    let o = id("ReplicaSet", "", "rs", "rs-uid");
    let n = id("Node", "", "node", "node-uid");
    let w = workers(Fake::default(), |g, f| {
        add(g, &n, meta(&n, vec![owner(&o, false)], &[], false));
        f.put(&n, meta(&n, vec![owner(&o, false)], &[], false));
    });
    let e = w.attempt_to_delete_item("node-uid").await.unwrap_err();
    assert_eq!(e, GcError::NamespacedOwnerOfClusterScopedObject);
    assert_eq!(
        w.attempt_to_delete_worker("node-uid").await,
        WorkQueueItemAction::Forget
    );
}

#[tokio::test]
async fn gc_attempt_delete_item_rest_mapping_error_message() {
    let e = GcError::RestMapping {
        kind: "Foo".into(),
        version: "v1".into(),
    };
    assert!(e
        .to_string()
        .starts_with("unable to get REST mapping for v1/Foo."));
}

#[test]
fn gc_attempt_delete_owner_ref_patch_shape() {
    // TestDeleteOwnerRefPatch: patch is built from UIDs only.
    let p = generate_delete_owner_ref_strategic_merge("dep", &["1".into(), "2".into()]);
    assert_eq!(
        p,
        json!({"metadata": {"uid": "dep", "ownerReferences": [
            {"$patch": "delete", "uid": "1"}, {"$patch": "delete", "uid": "2"}]}})
    );
}

#[tokio::test]
async fn gc_attempt_delete_unblock_owner_references_patch() {
    // TestUnblockOwnerReference: only blocking references are patched, to false.
    let a = id("ReplicaSet", "ns", "a", "a-uid");
    let b = id("ReplicaSet", "ns", "b", "b-uid");
    let p = id("Pod", "ns", "pod", "pod-uid");
    let w = workers(Fake::default(), |g, _| {
        add(
            g,
            &p,
            meta(&p, vec![owner(&a, true), owner(&b, false)], &[], false),
        );
    });
    let n = w.graph.lock().unwrap().node("pod-uid").unwrap().clone();
    let patch = unblock_owner_references_strategic_merge_patch(&n);
    let refs = patch["metadata"]["ownerReferences"].as_array().unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0]["uid"], "a-uid");
    assert_eq!(refs[0]["blockOwnerDeletion"], false);
}

#[tokio::test]
async fn gc_attempt_delete_orphan_dependents_failure() {
    // TestOrphanDependentsFailure: a conflict on the patch surfaces in the error.
    let o = id("ReplicaSet", "ns", "rs", "rs-uid");
    let p = id("Pod", "ns", "pod", "pod-uid");
    let w = workers(Fake::default(), |g, f| {
        add(g, &o, meta(&o, vec![], &["orphan"], true));
        add(g, &p, meta(&p, vec![owner(&o, false)], &[], false));
        *f.patch_err.lock().unwrap() =
            Some(ApiError::Conflict("the server reported a conflict".into()));
    });
    let dep = w.graph.lock().unwrap().node("pod-uid").unwrap().clone();
    let e = w.orphan_dependents(&o, &[dep]).await.unwrap_err();
    assert!(
        e.to_string().contains("the server reported a conflict"),
        "{e}"
    );
    assert_eq!(
        w.attempt_to_orphan_worker("rs-uid").await,
        WorkQueueItemAction::Requeue
    );
}

#[tokio::test]
async fn gc_attempt_delete_deleting_dependents_removes_finalizer_when_unblocked() {
    let o = id("ReplicaSet", "ns", "rs", "rs-uid");
    let w = workers(Fake::default(), |g, f| {
        add(g, &o, meta(&o, vec![], &["foregroundDeletion"], true));
        f.put(&o, meta(&o, vec![], &["foregroundDeletion"], true));
    });
    w.attempt_to_delete_item("rs-uid").await.unwrap();
    let p = w.api().patches.lock().unwrap().clone();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].1, PatchType::Merge);
    assert_eq!(p[0].2["metadata"]["finalizers"], json!([]));
}
