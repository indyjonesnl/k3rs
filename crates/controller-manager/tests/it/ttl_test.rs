//! Ported from `pkg/controller/ttl/ttl_controller_test.go` (release-1.35):
//! `TestPatchNode`, `TestUpdateNodeIfNeeded` and `TestDesiredTTL`, plus a
//! `run()` test that drives the real list+watch -> store -> queue -> patch path
//! against `MemoryStorage`.
use kubernetes_rs_client::reflector::StoreEvent;
use kubernetes_rs_common::resources::Node;
use kubernetes_rs_controller_manager::controllers::ttl::*;
use kubernetes_rs_storage::memory::MemoryStorage;
use kubernetes_rs_storage::{build_key, Storage};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

type C = TtlController<MemoryStorage>;

/// (existing annotations, desired TTL, expected annotation after the sync)
type UpdateCase<'a> = (Vec<(&'a str, &'a str)>, i64, Option<&'a str>);

fn node(name: &str, annotations: &[(&str, &str)]) -> Node {
    let annotations: HashMap<String, String> = annotations
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Node",
        "metadata": {"name": name, "uid": format!("uid-{name}"), "annotations": annotations},
    }))
    .unwrap()
}

async fn ttl_of(storage: &MemoryStorage, name: &str) -> Option<String> {
    let n: Node = storage.get(&build_key("nodes", None, name)).await.unwrap();
    n.metadata
        .annotations
        .and_then(|a| a.get(OBJECT_TTL_ANNOTATION_KEY).cloned())
}

/// `TestUpdateNodeIfNeeded`: patch when the annotation is absent or differs,
/// do nothing when it already matches.
#[tokio::test]
async fn test_update_node_if_needed() {
    let cases: Vec<UpdateCase> = vec![
        (vec![], 0, Some("0")),
        (vec![], 15, Some("15")),
        (vec![], 30, Some("30")),
        (vec![(OBJECT_TTL_ANNOTATION_KEY, "0")], 60, Some("60")),
        // Already matching: untouched.
        (vec![(OBJECT_TTL_ANNOTATION_KEY, "60")], 60, Some("60")),
        (vec![(OBJECT_TTL_ANNOTATION_KEY, "60")], 30, Some("30")),
        // An annotation that is not an integer counts as absent.
        (vec![(OBJECT_TTL_ANNOTATION_KEY, "soon")], 15, Some("15")),
        // Other annotations are preserved.
        (vec![("a", "b")], 15, Some("15")),
    ];
    for (i, (annotations, desired, want)) in cases.into_iter().enumerate() {
        let storage = Arc::new(MemoryStorage::new());
        storage
            .create(
                &build_key("nodes", None, "name"),
                &node("name", &annotations),
            )
            .await
            .unwrap();
        let c = C::new(storage.clone()).with_sizing(0, desired, 0);
        // The lister reads the informer store.
        let r = Arc::new(c);
        r.start_informer();
        tokio::time::sleep(Duration::from_millis(200)).await;
        r.update_node_if_needed("name").await.unwrap();
        assert_eq!(
            ttl_of(&storage, "name").await.as_deref(),
            want,
            "{i}: unexpected ttl"
        );
        let n: Node = storage
            .get(&build_key("nodes", None, "name"))
            .await
            .unwrap();
        if let Some((_, v)) = annotations.iter().find(|(k, _)| *k == "a") {
            assert_eq!(n.metadata.annotations.unwrap().get("a").unwrap(), v);
        }
    }
}

/// A Node that is not in the lister is not an error.
#[tokio::test]
async fn test_update_node_if_needed_missing_node_is_ok() {
    let storage = Arc::new(MemoryStorage::new());
    let c = C::new(storage);
    c.update_node_if_needed("nope").await.unwrap();
}

/// `TestDesiredTTL`.
#[tokio::test]
async fn test_desired_ttl() {
    struct Case {
        add: bool,
        delete: bool,
        node_count: i64,
        desired_ttl: i64,
        boundary_step: usize,
        expected_ttl: i64,
    }
    let c = |add, delete, node_count, desired_ttl, boundary_step, expected_ttl| Case {
        add,
        delete,
        node_count,
        desired_ttl,
        boundary_step,
        expected_ttl,
    };
    let cases = vec![
        c(true, false, 0, 0, 0, 0),
        c(true, false, 99, 0, 0, 0),
        c(true, false, 100, 0, 0, 15),
        c(false, true, 101, 15, 1, 15),
        c(false, true, 91, 15, 1, 15),
        c(true, false, 91, 15, 1, 15),
        c(false, true, 90, 15, 1, 0),
        c(false, true, 1800, 300, 4, 60),
        c(false, true, 10000, 300, 4, 300),
    ];
    for (i, tc) in cases.into_iter().enumerate() {
        let storage = Arc::new(MemoryStorage::new());
        let ctl = C::new(storage).with_sizing(tc.node_count, tc.desired_ttl, tc.boundary_step);
        if tc.add {
            ctl.on_node_event(&StoreEvent::Added(node("n", &[]))).await;
        }
        if tc.delete {
            ctl.on_node_event(&StoreEvent::Deleted(node("n", &[])))
                .await;
        }
        assert_eq!(
            ctl.desired_ttl_seconds(),
            tc.expected_ttl,
            "{i}: unexpected ttl"
        );
    }
}

/// An update only enqueues; it never changes the count.
#[tokio::test]
async fn test_update_event_enqueues_without_counting() {
    let storage = Arc::new(MemoryStorage::new());
    let ctl = C::new(storage);
    ctl.on_node_event(&StoreEvent::Modified(node("n", &[])))
        .await;
    assert_eq!(ctl.sizing(), (0, 0));
    assert_eq!(ctl.queue().get().await.as_deref(), Some("n"));
}

/// `Run`: every Node, existing and new, ends up annotated with the desired TTL.
#[tokio::test]
async fn test_run_annotates_existing_and_new_nodes() {
    let storage = Arc::new(MemoryStorage::new());
    storage
        .create(&build_key("nodes", None, "a"), &node("a", &[]))
        .await
        .unwrap();
    let ctl = Arc::new(C::new(storage.clone()));
    let h = tokio::spawn(ctl.clone().run());
    storage
        .create(&build_key("nodes", None, "b"), &node("b", &[]))
        .await
        .unwrap();
    for name in ["a", "b"] {
        let mut got = None;
        for _ in 0..100 {
            got = ttl_of(&storage, name).await;
            if got.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(got.as_deref(), Some("0"), "node {name} annotated");
    }
    assert_eq!(ctl.sizing().0, 2);
    h.abort();
}
