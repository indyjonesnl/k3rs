//! The garbage collector dependency graph.
//!
//! Upstream: `pkg/controller/garbagecollector/graph_builder_test.go`
//! (`TestGetAlternateOwnerIdentity`) and the `processGraphChanges` behaviour
//! of `graph_builder.go` / `garbagecollector_test.go`.

use chrono::Utc;
use kubernetes_rs_common::types::{ObjectMeta, OwnerReference};
use kubernetes_rs_controller_manager::controllers::gc_graph::*;

fn id(api: &str, kind: &str, ns: &str, name: &str, uid: &str) -> ObjectReference {
    ObjectReference {
        api_version: api.into(),
        kind: kind.into(),
        name: name.into(),
        uid: uid.into(),
        namespace: ns.into(),
    }
}

fn owner(r: &ObjectReference) -> OwnerReference {
    OwnerReference {
        api_version: r.api_version.clone(),
        kind: r.kind.clone(),
        name: r.name.clone(),
        uid: r.uid.clone(),
        block_owner_deletion: None,
        controller: None,
    }
}

fn blocking(r: &ObjectReference) -> OwnerReference {
    OwnerReference {
        block_owner_deletion: Some(true),
        ..owner(r)
    }
}

fn change(
    t: EventType,
    r: &ObjectReference,
    owners: Vec<OwnerReference>,
    finalizers: &[&str],
    deleting: bool,
    old: Option<ObjectMeta>,
) -> GraphChange {
    GraphChange {
        virtual_event: false,
        event_type: t,
        api_version: r.api_version.clone(),
        kind: r.kind.clone(),
        meta: meta(r, owners, finalizers, deleting),
        old_meta: old,
    }
}

fn meta(
    r: &ObjectReference,
    owners: Vec<OwnerReference>,
    f: &[&str],
    deleting: bool,
) -> ObjectMeta {
    ObjectMeta {
        name: r.name.clone(),
        namespace: (!r.namespace.is_empty()).then(|| r.namespace.clone()),
        uid: r.uid.clone(),
        owner_references: (!owners.is_empty()).then_some(owners),
        finalizers: (!f.is_empty()).then(|| f.iter().map(|s| s.to_string()).collect()),
        deletion_timestamp: deleting.then(Utc::now),
        ..Default::default()
    }
}

fn add(g: &mut Graph, r: &ObjectReference, owners: Vec<OwnerReference>) {
    g.process_graph_change(&change(EventType::Add, r, owners, &[], false, None));
}

#[test]
fn gc_graph_add_creates_virtual_owner_and_enqueues_it() {
    let mut g = Graph::new();
    let parent = id("v1", "Parent", "ns", "p", "puid");
    let child = id("v1", "Child", "ns", "c", "cuid");
    add(&mut g, &child, vec![owner(&parent)]);
    let p = g.node("puid").unwrap();
    assert!(!p.is_observed());
    assert_eq!(p.identity, parent);
    assert_eq!(p.dependents().collect::<Vec<_>>(), ["cuid"]);
    assert!(g.attempt_to_delete.contains("puid"));
    assert!(!g.attempt_to_delete.contains("cuid"));
}

#[test]
fn gc_graph_observing_virtual_owner_marks_observed() {
    let mut g = Graph::new();
    let parent = id("v1", "Parent", "ns", "p", "puid");
    add(
        &mut g,
        &id("v1", "Child", "ns", "c", "cuid"),
        vec![owner(&parent)],
    );
    g.attempt_to_delete.drain();
    add(&mut g, &parent, vec![]);
    assert!(g.node("puid").unwrap().is_observed());
    assert!(g.attempt_to_delete.is_empty());
}

#[test]
fn gc_graph_observed_identity_mismatch_enqueues_dependents() {
    let mut g = Graph::new();
    let wrong = id("v1", "Parent", "ns", "p", "puid");
    let child = id("v1", "Child", "ns", "c", "cuid");
    add(&mut g, &child, vec![owner(&wrong)]);
    g.attempt_to_delete.drain();
    // The owner is observed with another kind: the child is rechecked.
    add(&mut g, &id("v1", "Other", "ns", "p", "puid"), vec![]);
    assert_eq!(g.node("puid").unwrap().identity.kind, "Other");
    assert!(g.attempt_to_delete.contains("cuid"));
}

#[test]
fn gc_graph_namespace_mismatch_reports_event() {
    let mut g = Graph::new();
    let parent = id("v1", "Parent", "ns1", "p", "puid");
    add(&mut g, &parent, vec![]);
    let child = id("v1", "Child", "ns2", "c", "cuid");
    add(&mut g, &child, vec![owner(&parent)]);
    assert!(g.attempt_to_delete.contains("cuid"));
    let ev = g.take_events();
    assert_eq!(ev.len(), 1);
    assert_eq!(
        ev[0].message,
        "ownerRef [v1/Parent, namespace: ns2, name: p, uid: puid] does not exist in namespace \"ns2\""
    );
    assert_eq!(ev[0].involved, child);
}

#[test]
fn gc_graph_cluster_scoped_owner_is_valid_from_any_namespace() {
    let mut g = Graph::new();
    let parent = id("v1", "ClusterParent", "", "p", "puid");
    add(&mut g, &parent, vec![]);
    add(
        &mut g,
        &id("v1", "Child", "ns", "c", "cuid"),
        vec![owner(&parent)],
    );
    assert!(g.attempt_to_delete.is_empty());
    assert!(g.take_events().is_empty());
}

#[test]
fn gc_graph_owner_coordinate_mismatch_enqueues_dependent() {
    let mut g = Graph::new();
    add(&mut g, &id("v1", "Parent", "ns", "p", "puid"), vec![]);
    let mut o = owner(&id("v1", "Parent", "ns", "renamed", "puid"));
    o.kind = "Parent".into();
    add(&mut g, &id("v1", "Child", "ns", "c", "cuid"), vec![o]);
    assert!(g.attempt_to_delete.contains("cuid"));
}

#[test]
fn gc_graph_update_diffs_owner_references() {
    let mut g = Graph::new();
    let a = id("v1", "P", "ns", "a", "auid");
    let b = id("v1", "P", "ns", "b", "buid");
    let child = id("v1", "Child", "ns", "c", "cuid");
    add(&mut g, &a, vec![]);
    add(&mut g, &b, vec![]);
    add(&mut g, &child, vec![blocking(&a)]);
    g.attempt_to_delete.drain();
    g.process_graph_change(&change(
        EventType::Update,
        &child,
        vec![owner(&b)],
        &[],
        false,
        None,
    ));
    assert_eq!(g.node("auid").unwrap().dependents_length(), 0);
    assert_eq!(
        g.node("buid").unwrap().dependents().collect::<Vec<_>>(),
        ["cuid"]
    );
    // The removed blocking reference unblocks its owner.
    assert!(g.attempt_to_delete.contains("auid"));
    assert!(!g.attempt_to_delete.contains("buid"));
}

#[test]
fn gc_graph_changed_block_owner_deletion_unblocks_owner() {
    let mut g = Graph::new();
    let a = id("v1", "P", "ns", "a", "auid");
    let child = id("v1", "Child", "ns", "c", "cuid");
    add(&mut g, &a, vec![]);
    add(&mut g, &child, vec![blocking(&a)]);
    assert_eq!(g.blocking_dependents("auid").len(), 1);
    g.attempt_to_delete.drain();
    g.process_graph_change(&change(
        EventType::Update,
        &child,
        vec![owner(&a)],
        &[],
        false,
        None,
    ));
    assert!(g.blocking_dependents("auid").is_empty());
    assert!(g.attempt_to_delete.contains("auid"));
}

#[test]
fn gc_graph_foreground_deletion_enqueues_owner_and_dependents() {
    let mut g = Graph::new();
    let p = id("v1", "P", "ns", "p", "puid");
    let c = id("v1", "Child", "ns", "c", "cuid");
    add(&mut g, &p, vec![]);
    add(&mut g, &c, vec![owner(&p)]);
    g.attempt_to_delete.drain();
    let old = meta(&p, vec![], &[], false);
    g.process_graph_change(&change(
        EventType::Update,
        &p,
        vec![],
        &[FINALIZER_DELETE_DEPENDENTS],
        true,
        Some(old),
    ));
    let n = g.node("puid").unwrap();
    assert!(n.is_deleting_dependents() && n.is_being_deleted());
    assert!(g.attempt_to_delete.contains("cuid") && g.attempt_to_delete.contains("puid"));
    assert!(g.attempt_to_orphan.is_empty());
}

#[test]
fn gc_graph_orphan_deletion_enqueues_orphan() {
    let mut g = Graph::new();
    let p = id("v1", "P", "ns", "p", "puid");
    add(&mut g, &p, vec![]);
    g.process_graph_change(&change(
        EventType::Update,
        &p,
        vec![],
        &[FINALIZER_ORPHAN_DEPENDENTS],
        true,
        Some(meta(&p, vec![], &[], false)),
    ));
    assert!(g.attempt_to_orphan.contains("puid"));
    assert!(g.attempt_to_delete.is_empty());
}

#[test]
fn gc_graph_creation_with_deletion_in_one_event_processes_transition() {
    let mut g = Graph::new();
    let p = id("v1", "P", "ns", "p", "puid");
    g.process_graph_change(&change(
        EventType::Add,
        &p,
        vec![],
        &[FINALIZER_DELETE_DEPENDENTS],
        true,
        None,
    ));
    let n = g.node("puid").unwrap();
    assert!(n.is_deleting_dependents() && n.is_being_deleted());
    assert!(g.attempt_to_delete.contains("puid"));
}

#[test]
fn gc_graph_delete_removes_node_and_enqueues_dependents() {
    let mut g = Graph::new();
    let p = id("v1", "P", "ns", "p", "puid");
    let c = id("v1", "Child", "ns", "c", "cuid");
    add(&mut g, &p, vec![]);
    add(&mut g, &c, vec![owner(&p)]);
    g.attempt_to_delete.drain();
    g.process_graph_change(&change(EventType::Delete, &p, vec![], &[], false, None));
    assert!(g.node("puid").is_none());
    assert!(g.absent_owner_cache.contains(&p));
    assert!(g.attempt_to_delete.contains("cuid"));
}

#[test]
fn gc_graph_delete_of_last_dependent_rechecks_foreground_owner() {
    let mut g = Graph::new();
    let p = id("v1", "P", "ns", "p", "puid");
    let c = id("v1", "Child", "ns", "c", "cuid");
    add(&mut g, &p, vec![]);
    add(&mut g, &c, vec![blocking(&p)]);
    g.process_graph_change(&change(
        EventType::Update,
        &p,
        vec![],
        &[FINALIZER_DELETE_DEPENDENTS],
        true,
        Some(meta(&p, vec![], &[], false)),
    ));
    g.attempt_to_delete.drain();
    g.process_graph_change(&change(
        EventType::Delete,
        &c,
        vec![blocking(&p)],
        &[],
        false,
        None,
    ));
    assert!(g.node("cuid").is_none());
    assert_eq!(g.node("puid").unwrap().dependents_length(), 0);
    assert!(g.attempt_to_delete.contains("puid"));
}

#[test]
fn gc_graph_delete_of_unknown_item_is_ignored() {
    let mut g = Graph::new();
    g.process_graph_change(&change(
        EventType::Delete,
        &id("v1", "P", "ns", "p", "puid"),
        vec![],
        &[],
        false,
        None,
    ));
    assert!(g.is_empty());
}

#[test]
fn gc_graph_virtual_delete_removes_virtual_owner() {
    let mut g = Graph::new();
    let p = id("v1", "P", "ns", "p", "puid");
    add(
        &mut g,
        &id("v1", "Child", "ns", "c", "cuid"),
        vec![owner(&p)],
    );
    g.attempt_to_delete.drain();
    g.process_graph_change(&GraphChange::virtual_delete(&p));
    assert!(g.node("puid").is_none());
    assert!(g.absent_owner_cache.contains(&p));
    assert!(g.attempt_to_delete.contains("cuid"));
}

#[test]
fn gc_graph_virtual_delete_with_other_coordinates_keeps_node() {
    let mut g = Graph::new();
    let ns1 = id("v1", "NSParent", "ns1", "p", "puid");
    let alt = id("xx", "NSParent", "ns1", "p", "puid");
    add(
        &mut g,
        &id("v1", "Child", "ns1", "c1", "c1uid"),
        vec![owner(&ns1)],
    );
    add(
        &mut g,
        &id("v1", "Child", "ns1", "c2", "c2uid"),
        vec![owner(&alt)],
    );
    g.attempt_to_delete.drain();
    g.process_graph_change(&GraphChange::virtual_delete(&ns1));
    // The node stays, now under the alternate identity, and is retried.
    assert_eq!(g.node("puid").unwrap().identity, alt);
    assert!(g.absent_owner_cache.contains(&ns1));
    assert!(g.attempt_to_delete.contains("c1uid"));
    assert!(g.attempt_to_delete.was_rate_limited("puid"));
}

#[test]
fn gc_graph_virtual_delete_does_not_remove_observed_node_with_other_identity() {
    let mut g = Graph::new();
    let real = id("v1", "P", "ns", "p", "puid");
    add(&mut g, &real, vec![]);
    let stale = id("xx", "P", "ns", "p", "puid");
    add(
        &mut g,
        &id("v1", "Child", "ns", "c", "cuid"),
        vec![owner(&stale)],
    );
    g.attempt_to_delete.drain();
    g.process_graph_change(&GraphChange::virtual_delete(&stale));
    assert_eq!(g.node("puid").unwrap().identity, real);
    assert!(g.absent_owner_cache.contains(&stale));
    assert!(g.attempt_to_delete.contains("cuid"));
}

#[test]
fn gc_graph_references_diffs() {
    let a = owner(&id("v1", "P", "ns", "a", "a"));
    let b = owner(&id("v1", "P", "ns", "b", "b"));
    let c = owner(&id("v1", "P", "ns", "c", "c"));
    let mut a2 = a.clone();
    a2.controller = Some(true);
    let (added, removed, changed) =
        references_diffs(&[a.clone(), b.clone()], &[a2.clone(), c.clone()]);
    assert_eq!(added, vec![c]);
    assert_eq!(removed, vec![b]);
    assert_eq!(
        changed,
        vec![OwnerRefPair {
            old_ref: a,
            new_ref: a2
        }]
    );
}

/// `TestGetAlternateOwnerIdentity`, observed through a virtual delete event:
/// the node is re-identified as the alternate the remaining dependents use.
#[test]
fn gc_graph_alternate_owner_identity() {
    let cases: Vec<(
        &str,
        ObjectReference,
        Vec<ObjectReference>,
        Option<ObjectReference>,
    )> = vec![
        (
            "namespaced alternate version",
            id("v1", "NSParent", "ns1", "parentname", "parentuid"),
            vec![id("xx", "NSParent", "ns1", "parentname", "parentuid")],
            Some(id("xx", "NSParent", "ns1", "parentname", "parentuid")),
        ),
        (
            "namespaced alternate kind",
            id("v1", "NSParent", "ns1", "parentname", "parentuid"),
            vec![id("v1", "xxxxxxxx", "ns1", "parentname", "parentuid")],
            Some(id("v1", "xxxxxxxx", "ns1", "parentname", "parentuid")),
        ),
        (
            "namespaced alternate name",
            id("v1", "NSParent", "ns1", "parentname", "parentuid"),
            vec![id("v1", "NSParent", "ns1", "xxxxxxxxxx", "parentuid")],
            Some(id("v1", "NSParent", "ns1", "xxxxxxxxxx", "parentuid")),
        ),
        (
            "cluster alternate version",
            id("v1", "ClusterParent", "", "parentname", "parentuid"),
            vec![id("xx", "ClusterParent", "", "parentname", "parentuid")],
            // Only an identical apiVersion and kind clears the namespace
            // (clusterabsentparent_ns1_version upstream).
            Some(id("xx", "ClusterParent", "ns1", "parentname", "parentuid")),
        ),
        (
            "first following the absent identity wins",
            id("v2", "kind", "ns1", "name", "uid"),
            vec![
                id("v1", "kind", "ns1", "name", "uid"),
                id("v3", "kind", "ns1", "name", "uid"),
                id("v5", "kind", "ns1", "name", "uid"),
            ],
            Some(id("v3", "kind", "ns1", "name", "uid")),
        ),
        (
            "wraps to the first when none follow",
            id("v5", "kind", "ns1", "name", "uid"),
            vec![
                id("v3", "kind", "ns1", "name", "uid"),
                id("v1", "kind", "ns1", "name", "uid"),
            ],
            Some(id("v1", "kind", "ns1", "name", "uid")),
        ),
    ];
    for (name, absent, alternates, expected) in cases {
        let mut g = Graph::new();
        // One dependent still references the absent identity, the others use
        // the alternates.
        add(
            &mut g,
            &id("v1", "Child", &absent.namespace, "c0", "c0uid"),
            vec![owner(&absent)],
        );
        for (i, alt) in alternates.iter().enumerate() {
            let ns = if absent.namespace.is_empty() {
                "ns1".to_string()
            } else {
                absent.namespace.clone()
            };
            add(
                &mut g,
                &id(
                    "v1",
                    "Child",
                    &ns,
                    &format!("c{}", i + 1),
                    &format!("c{}uid", i + 1),
                ),
                vec![owner(alt)],
            );
        }
        g.process_graph_change(&GraphChange::virtual_delete(&absent));
        let got = g
            .node("parentuid")
            .or_else(|| g.node("uid"))
            .map(|n| n.identity.clone());
        assert_eq!(got, expected, "{name}");
    }
}
