//! Ports of the monitor behaviour of `pkg/controller/garbagecollector`
//! (`graph_builder.go` `syncMonitors`, `startMonitors`, `IsSynced`,
//! `DefaultIgnoredResources`; `metaonly` decoding).

mod gc_monitors {
    use kubernetes_rs_controller_manager::controllers::gc_monitors::*;
    use kubernetes_rs_storage::{build_key, memory::MemoryStorage, Storage};
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

    fn gvr(group: &str, resource: &str) -> GroupVersionResource {
        GroupVersionResource::new(group, "v1", resource)
    }

    fn kind_for(r: &GroupVersionResource) -> Result<GroupVersionKind, String> {
        if r.resource == "broken" {
            return Err("no kind".into());
        }
        Ok(GroupVersionKind {
            group: r.group.clone(),
            version: r.version.clone(),
            kind: r.resource.trim_end_matches('s').to_string(),
        })
    }

    fn set(rs: &[GroupVersionResource]) -> BTreeSet<GroupVersionResource> {
        rs.iter().cloned().collect()
    }

    fn monitors() -> (
        Monitors<MemoryStorage>,
        Arc<MemoryStorage>,
        UnboundedReceiver<GraphEvent>,
    ) {
        let storage = Arc::new(MemoryStorage::new());
        let (tx, rx) = unbounded_channel();
        (
            Monitors::new(storage.clone(), default_ignored_resources(), tx),
            storage,
            rx,
        )
    }

    async fn next(rx: &mut UnboundedReceiver<GraphEvent>) -> GraphEvent {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("event within 5s")
            .expect("channel open")
    }

    fn cm(name: &str, uid: &str, data: &str) -> serde_json::Value {
        json!({"apiVersion":"v1","kind":"ConfigMap",
            "metadata":{"name":name,"namespace":"ns","uid":uid,
                "ownerReferences":[{"apiVersion":"v1","kind":"Pod","name":"o","uid":"owner-1"}]},
            "data":{"k":data}})
    }

    #[test]
    fn gc_monitors_default_ignored_resources() {
        let d = default_ignored_resources();
        assert_eq!(d.len(), 2);
        assert!(d.contains(&GroupResource::new("", "events")));
        assert!(d.contains(&GroupResource::new("events.k8s.io", "events")));
    }

    #[test]
    fn gc_monitors_metadata_only_decoding_drops_the_rest() {
        let obj: MetadataOnlyObject =
            serde_json::from_value(cm("a", "u1", "secret-payload")).unwrap();
        assert_eq!(obj.type_meta.kind, "ConfigMap");
        assert_eq!(obj.metadata.uid, "u1");
        assert!(!serde_json::to_string(&obj)
            .unwrap()
            .contains("secret-payload"));
    }

    #[tokio::test]
    async fn gc_monitors_sync_adds_keeps_removes_and_skips_ignored() {
        let (mut m, _s, _rx) = monitors();
        let (r, errs) = m.sync_monitors(
            &set(&[
                gvr("", "pods"),
                gvr("", "events"),
                gvr("events.k8s.io", "events"),
            ]),
            kind_for,
        );
        assert!(errs.is_empty());
        assert_eq!(
            r,
            SyncMonitorsResult {
                added: 1,
                kept: 0,
                removed: 0
            }
        );

        let (r, _) = m.sync_monitors(
            &set(&[gvr("", "pods"), gvr("apps", "deployments")]),
            kind_for,
        );
        assert_eq!(
            r,
            SyncMonitorsResult {
                added: 1,
                kept: 1,
                removed: 0
            }
        );

        let (r, _) = m.sync_monitors(&set(&[gvr("apps", "deployments")]), kind_for);
        assert_eq!(
            r,
            SyncMonitorsResult {
                added: 0,
                kept: 1,
                removed: 1
            }
        );
        assert_eq!(m.len(), 1);
    }

    #[tokio::test]
    async fn gc_monitors_sync_aggregates_errors_but_creates_the_rest() {
        let (mut m, _s, _rx) = monitors();
        let (r, errs) = m.sync_monitors(&set(&[gvr("", "broken"), gvr("", "pods")]), kind_for);
        assert_eq!(r.added, 1);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("couldn't look up resource"), "{errs:?}");
    }

    #[tokio::test]
    async fn gc_monitors_start_does_nothing_before_run() {
        let (mut m, _s, _rx) = monitors();
        m.sync_monitors(&set(&[gvr("", "configmaps")]), kind_for);
        assert_eq!(m.start_monitors(), 0);
        assert!(!m.is_synced());
        m.set_running(true);
        assert_eq!(m.start_monitors(), 1);
        // Already started: not started twice.
        assert_eq!(m.start_monitors(), 0);
    }

    #[tokio::test]
    async fn gc_monitors_is_synced_needs_monitors() {
        let (m, _s, _rx) = monitors();
        assert!(!m.is_synced());
        assert!(!m.is_resource_synced(&gvr("", "configmaps")));
    }

    #[tokio::test]
    async fn gc_monitors_emit_add_update_delete_with_metadata_only() {
        let (mut m, storage, mut rx) = monitors();
        storage
            .create(
                &build_key("configmaps", Some("ns"), "a"),
                &cm("a", "u1", "v1"),
            )
            .await
            .unwrap();
        let r = gvr("", "configmaps");
        m.sync_monitors(&set(std::slice::from_ref(&r)), kind_for);
        m.set_running(true);
        m.start_monitors();

        let ev = next(&mut rx).await;
        assert_eq!(ev.event_type, GraphEventType::Add);
        assert!(!ev.virtual_event);
        assert_eq!(ev.obj.metadata.uid, "u1");
        assert_eq!(ev.gvk.kind, "configmap");
        assert_eq!(
            ev.obj.metadata.owner_references.as_ref().unwrap()[0].uid,
            "owner-1"
        );
        for _ in 0..50 {
            if m.is_resource_synced(&r) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(m.is_resource_synced(&r) && m.is_synced());

        storage
            .update(
                &build_key("configmaps", Some("ns"), "a"),
                &cm("a", "u1", "v2"),
            )
            .await
            .unwrap();
        let ev = next(&mut rx).await;
        assert_eq!(ev.event_type, GraphEventType::Update);
        assert_eq!(ev.old_obj.unwrap().metadata.uid, "u1");

        storage
            .delete(&build_key("configmaps", Some("ns"), "a"))
            .await
            .unwrap();
        let ev = next(&mut rx).await;
        assert_eq!(ev.event_type, GraphEventType::Delete);
        assert_eq!(ev.obj.metadata.uid, "u1");
        m.stop_monitors();
    }

    #[tokio::test]
    async fn gc_monitors_stop_ends_events() {
        let (mut m, storage, mut rx) = monitors();
        m.sync_monitors(&set(&[gvr("", "configmaps")]), kind_for);
        m.set_running(true);
        m.start_monitors();
        tokio::time::sleep(Duration::from_millis(100)).await;
        m.stop_monitors();
        assert!(m.is_empty());
        storage
            .create(
                &build_key("configmaps", Some("ns"), "b"),
                &cm("b", "u2", "v"),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(rx.try_recv().is_err());
    }
}
