//! Ports of pkg/kubelet/allocation/state/state_checkpoint_test.go
//! (`Test_stateCheckpoint_storeState`, `Test_stateCheckpoint_formatUpgraded`)
//! plus the checkpointmanager corruption / not-found cases.

use std::collections::HashSet;

use kubernetes_rs_kubelet::allocation::state::*;

const NAME: &str = "pod_state_checkpoint";

fn rr(v: &str) -> ResourceRequirements {
    ResourceRequirements::new([("cpu", v), ("memory", v)], [])
}

fn info(v: &str) -> PodResourceInfo {
    PodResourceInfo {
        container_resources: [("container1".to_string(), rr(v))].into(),
        pod_level_resources: Some(rr(v)),
    }
}

#[test]
fn allocation_state_golden_checksum() {
    // From Test_stateCheckpoint_formatUpgraded.
    let data = r#"{"entries":{"pod1":{"ContainerResources":{"container1":{"requests":{"cpu":"1Ki","memory":"1Ki"}}}}}}"#;
    assert_eq!(checksum_of(data), 1178570812);
}

#[test]
fn allocation_state_store_and_restore() {
    let suffixes = [
        "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "n", "u", "m", "k", "M", "G", "T", "P", "E", "",
    ];
    // A subset of the upstream factors (fsync per write makes the full matrix slow).
    let factors = ["1", "0.1", "1024"];
    for fact in factors {
        for suf in suffixes {
            if (suf == "E" || suf == "Ei") && (fact == "1000" || fact == "10000") {
                continue; // overflows, see the upstream test
            }
            let q = format!("{fact}{suf}");
            let dir = tempfile::tempdir().unwrap();
            let sc = StateCheckpoint::new(dir.path(), NAME).unwrap();
            sc.set_pod_resource_info("pod1", info(&q)).unwrap();
            assert_eq!(sc.get_pod_resource_info("pod1"), Some(info(&q)), "{q}");

            let restored = StateCheckpoint::new(dir.path(), NAME).unwrap();
            assert_eq!(
                restored.get_pod_resource_info_map(),
                sc.get_pod_resource_info_map(),
                "{q}"
            );

            let path = dir.path().join(NAME);
            assert!(path.exists());
            std::fs::remove_file(&path).unwrap();
            // The same values must not re-write the checkpoint.
            sc.set_pod_resource_info("pod1", info(&q)).unwrap();
            assert!(!path.exists(), "{q}: checkpoint should not be re-written");
            // A new value does.
            sc.set_pod_resource_info(
                "foo-bar",
                PodResourceInfo {
                    container_resources: [(
                        "container1".to_string(),
                        ResourceRequirements::new([("cpu", "1")], []),
                    )]
                    .into(),
                    pod_level_resources: Some(ResourceRequirements::new([("cpu", "1")], [])),
                },
            )
            .unwrap();
            assert!(path.exists(), "{q}: checkpoint should be re-written");
        }
    }
}

#[test]
fn allocation_state_format_upgraded_checkpoint_loads() {
    let dir = tempfile::tempdir().unwrap();
    let content = r#"{"data":"{\"entries\":{\"pod1\":{\"ContainerResources\":{\"container1\":{\"requests\":{\"cpu\":\"1Ki\",\"memory\":\"1Ki\"}}}}}}","checksum":1178570812}"#;
    std::fs::write(dir.path().join(NAME), content).unwrap();
    let sc = StateCheckpoint::new(dir.path(), NAME).unwrap();
    let want: PodResourceInfoMap = [(
        "pod1".to_string(),
        PodResourceInfo {
            container_resources: [("container1".to_string(), rr("1Ki"))].into(),
            pod_level_resources: None,
        },
    )]
    .into();
    assert_eq!(sc.get_pod_resource_info_map(), want);
}

#[test]
fn allocation_state_corrupt_checkpoint_is_an_error_with_advice() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(NAME),
        r#"{"data":"{\"entries\":{}}","checksum":1}"#,
    )
    .unwrap();
    let err = StateCheckpoint::new(dir.path(), NAME).err().unwrap();
    assert!(err.starts_with("could not restore state from checkpoint: checkpoint is corrupted, please drain this node and delete pod resource information checkpoint file \""));
    assert!(err.ends_with("before restarting Kubelet"));
}

#[test]
fn allocation_state_memory_semantics() {
    let m = StateMemory::new(None);
    assert_eq!(m.get_container_resources("p", "c"), None);
    m.set_container_resources("p", "c", rr("1")).unwrap();
    m.set_pod_level_resources("p", Some(rr("2"))).unwrap();
    assert_eq!(m.get_container_resources("p", "c"), Some(rr("1")));
    assert_eq!(m.get_pod_level_resources("p"), Some(Some(rr("2"))));
    assert_eq!(m.get_pod_level_resources("zz"), None);
    m.set_pod_resource_info("q", PodResourceInfo::default())
        .unwrap();
    // RemoveOrphanedPods keeps only the remaining pods.
    m.remove_orphaned_pods(&HashSet::from(["q".to_string()]));
    assert_eq!(m.get_pod_resource_info("p"), None);
    assert!(m.get_pod_resource_info("q").is_some());
    m.remove_pod("q").unwrap();
    assert!(m.get_pod_resource_info_map().is_empty());
}

#[test]
fn allocation_state_remove_pod_is_not_persisted_until_next_write() {
    let dir = tempfile::tempdir().unwrap();
    let sc = StateCheckpoint::new(dir.path(), NAME).unwrap();
    sc.set_pod_resource_info("a", info("1")).unwrap();
    sc.set_pod_resource_info("b", info("1")).unwrap();
    sc.remove_pod("a").unwrap();
    // RemovePod does not write: a restart still sees both.
    assert_eq!(
        StateCheckpoint::new(dir.path(), NAME)
            .unwrap()
            .get_pod_resource_info_map()
            .len(),
        2
    );
    // The deletion is stored by the next real update.
    sc.set_pod_resource_info("c", info("1")).unwrap();
    let keys: Vec<String> = StateCheckpoint::new(dir.path(), NAME)
        .unwrap()
        .get_pod_resource_info_map()
        .into_keys()
        .collect();
    assert_eq!(keys, vec!["b", "c"]);
}

#[test]
fn allocation_state_noop_holds_nothing_and_invalid_key_rejected() {
    let n = NoopStateCheckpoint;
    n.set_pod_resource_info("p", info("1")).unwrap();
    assert!(n.get_pod_resource_info_map().is_empty());
    assert_eq!(n.get_container_resources("p", "container1"), None);
    // A directory-escaping name is not a valid checkpoint key.
    let dir = tempfile::tempdir().unwrap();
    let err = StateCheckpoint::new(dir.path(), "../x").err().unwrap();
    assert!(err.starts_with("could not restore state from checkpoint: invalid key: \"../x\""));
}
