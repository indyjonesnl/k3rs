//! Ports of `pkg/kubelet/userns/userns_manager_test.go` (release-1.35):
//! TestUserNsManagerAllocate, TestMakeUserNsManager,
//! TestUserNsManagerParseUserNsFile, TestGetOrCreateUserNamespaceMappings,
//! TestCleanupOrphanedPodUsernsAllocations, TestMakeUserNsManagerFailsListPod,
//! TestRecordBounds, plus `parseGetSubIdsOutput` cases.

use kubernetes_rs_cri::v1;
use kubernetes_rs_kubelet::userns::{
    default_kubelet_mappings, parse_get_sub_ids_output, UserNsPodsManager, UsernsManager,
};
use std::path::PathBuf;
use std::sync::Arc;

const TEST_USER_NS_LENGTH: u32 = 65536;
const MINIMUM_MAPPING_UID: u32 = TEST_USER_NS_LENGTH;
const MAPPING_LEN: u32 = TEST_USER_NS_LENGTH * 2000;
const TEST_MAX_PODS: usize = 110;

#[derive(Default)]
struct TestPods {
    pod_dir: Option<PathBuf>,
    pod_list: Vec<String>,
    userns: bool,
    max_pods: usize,
    mapping_first_id: u32,
    mapping_len: u32,
    fail_list: bool,
}

impl UserNsPodsManager for TestPods {
    fn handler_supports_user_namespaces(&self, h: &str) -> Result<bool, String> {
        if h == "error" {
            return Err("unknown runtime".into());
        }
        Ok(self.userns)
    }
    fn get_pod_dir(&self, _uid: &str) -> PathBuf {
        self.pod_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/tmp/non-existent-dir.This-is-not-used-in-tests"))
    }
    fn list_pods_from_disk(&self) -> std::io::Result<Vec<String>> {
        if self.fail_list {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        Ok(self.pod_list.clone())
    }
    fn get_kubelet_mappings(&self, _ids: u32) -> Result<(u32, u32), String> {
        if self.mapping_first_id != 0 {
            return Ok((self.mapping_first_id, self.mapping_len));
        }
        Ok((MINIMUM_MAPPING_UID, MAPPING_LEN))
    }
    fn get_max_pods(&self) -> usize {
        if self.max_pods != 0 {
            self.max_pods
        } else {
            TEST_MAX_PODS
        }
    }
}

fn make(t: TestPods, ids: Option<i64>) -> Result<UsernsManager, String> {
    UsernsManager::make(Arc::new(t), ids, true).map(|m| m.unwrap())
}

#[test]
fn userns_manager_allocate() {
    let custom = 1048576u32;
    for (len, first, mlen) in [
        (TEST_USER_NS_LENGTH, MINIMUM_MAPPING_UID, MAPPING_LEN),
        (custom, custom, custom * 2000),
    ] {
        let m = make(
            TestPods {
                mapping_first_id: first,
                mapping_len: mlen,
                ..Default::default()
            },
            Some(len as i64),
        )
        .unwrap();
        let (a, l) = m.allocate_one("one").unwrap();
        assert_eq!(l, len);
        assert!(m.is_set(a));
        let (a2, l2) = m.allocate_one("two").unwrap();
        assert_ne!(a, a2);
        assert_eq!(l, l2);
        // re-adding the same pod with the same settings won't fail, anything else does
        m.record("two", a2, l2).unwrap();
        assert!(m.record("two", a2 + 1, l2).is_err());
        m.release("one");
        m.release("two");
        assert!(!m.is_set(a));
        assert!(!m.is_set(a2));

        let mut allocs = vec![];
        for i in 0..1000 {
            let (a, l) = m.allocate_one(&i.to_string()).unwrap();
            assert_eq!(l, len);
            assert!(a >= first);
            assert!(a <= first + mlen - len);
            allocs.push(a);
        }
        for (i, v) in allocs.into_iter().enumerate() {
            assert!(m.is_set(v));
            m.release(&i.to_string());
            assert!(!m.is_set(v));
            m.record(&i.to_string(), v, len).unwrap();
            m.release(&i.to_string());
            assert!(!m.is_set(v));
        }
    }
}

#[test]
fn userns_manager_make() {
    // (name, first, len, max_pods, success)
    let cases = [
        ("default", 0, 0, 0, true),
        ("firstID not multiple", 65536 + 1, 0, 0, false),
        ("firstID is less than 65535", 1, 0, 0, false),
        ("mappingLen not multiple", 65536, 65536 + 1, 0, false),
        ("range can't fit maxPods", 65536, 65536, 2, false),
    ];
    for (name, first, len, max_pods, ok) in cases {
        let dir = tempfile::tempdir().unwrap();
        let r = make(
            TestPods {
                pod_dir: Some(dir.path().into()),
                mapping_first_id: first,
                mapping_len: len,
                max_pods,
                ..Default::default()
            },
            None,
        );
        assert_eq!(r.is_ok(), ok, "{name}");
    }
    // feature gate off: no manager at all
    assert!(
        UsernsManager::make(Arc::new(TestPods::default()), None, false)
            .unwrap()
            .is_none()
    );
}

#[test]
fn userns_manager_parse_user_ns_file() {
    let f = |u: &str, g: &str| format!(r#"{{"uidMappings":[{u}],"gidMappings":[{g}]}}"#);
    let one = r#"{"hostId":131072,"containerId":0,"length":65536}"#;
    let cases = [
        ("basic", f(one, one), true),
        (
            "invalid length",
            f(
                r#"{"hostId":131072,"containerId":0,"length":0}"#,
                r#"{"hostId":131072,"containerId":0,"length":0}"#,
            ),
            false,
        ),
        (
            "wrong offset",
            f(one, r#"{"hostId":1,"containerId":0,"length":65536}"#),
            false,
        ),
        (
            "two GID mappings",
            f(
                one,
                &format!(r#"{one},{{"hostId":196608,"containerId":0,"length":65536}}"#),
            ),
            false,
        ),
        (
            "two UID mappings",
            f(
                &format!(r#"{one},{{"hostId":196608,"containerId":0,"length":65536}}"#),
                one,
            ),
            false,
        ),
        (
            "no root UID",
            f(r#"{"hostId":131072,"containerId":1,"length":65536}"#, one),
            false,
        ),
        (
            "no root GID",
            f(one, r#"{"hostId":131072,"containerId":1,"length":65536}"#),
            false,
        ),
    ];
    let m = make(TestPods::default(), None).unwrap_or_else(|e| panic!("{e}"));
    for (name, file, ok) in cases {
        let r = m.parse_user_ns_file_and_record(name, file.as_bytes());
        assert_eq!(r.is_ok(), ok, "{name}: {r:?}");
    }
}

#[test]
#[allow(clippy::type_complexity)]
fn userns_manager_get_or_create_mappings() {
    // (name, pod hostUsers (None = no pod fields), nil pod, runtime userns, handler, success, mode)
    let node = v1::NamespaceMode::Node as i32;
    let podm = v1::NamespaceMode::Pod as i32;
    let cases: Vec<(&str, Option<Option<bool>>, bool, &str, bool, i32)> = vec![
        ("no user namespace", Some(None), false, "", true, node),
        ("nil pod", None, false, "", true, node),
        (
            "opt-in to host user namespace",
            Some(Some(true)),
            false,
            "",
            true,
            node,
        ),
        ("user namespace", Some(Some(false)), true, "", true, podm),
        ("no runtime support", Some(Some(false)), false, "", false, 0),
        (
            "runtime returns error",
            Some(Some(false)),
            false,
            "error",
            false,
            0,
        ),
    ];
    for (name, pod, rt, handler, ok, mode) in cases {
        let dir = tempfile::tempdir().unwrap();
        let m = make(
            TestPods {
                pod_dir: Some(dir.path().into()),
                userns: rt,
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let r = m.get_or_create_user_namespace_mappings(pod.map(|h| ("uid", h)), handler);
        assert_eq!(r.is_ok(), ok, "{name}: {r:?}");
        if ok {
            assert_eq!(r.unwrap().unwrap().mode, mode, "{name}");
            if mode == podm {
                // persisted, and a second call reads it back instead of allocating
                assert!(dir.path().join("userns").exists());
                let again = m
                    .get_or_create_user_namespace_mappings(Some(("uid", Some(false))), "")
                    .unwrap()
                    .unwrap();
                assert_eq!(again.uids.len(), 1);
                assert_eq!(again.uids, again.gids);
            }
        }
    }
    // gate disabled but hostUsers set: error; unset: no namespace at all
    let off = UsernsManager::make(Arc::new(TestPods::default()), None, false).unwrap();
    assert!(off.is_none());
}

#[test]
#[allow(clippy::type_complexity)]
fn userns_manager_cleanup_orphaned() {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    // (name, list, set_before, running, pods, set_after, unset_after)
    let cases: Vec<(
        &str,
        Vec<String>,
        Vec<String>,
        Vec<String>,
        Vec<String>,
        Vec<String>,
        Vec<String>,
    )> = vec![
        (
            "no stale pods",
            s(&["pod-1", "pod-2"]),
            s(&[]),
            s(&[]),
            s(&[]),
            s(&[]),
            s(&[]),
        ),
        (
            "no stale pods set",
            s(&["pod-1", "pod-2"]),
            s(&["pod-1", "pod-2"]),
            s(&[]),
            s(&[]),
            s(&[]),
            s(&["pod-1", "pod-2"]),
        ),
        (
            "one running pod",
            s(&["pod-1", "pod-2"]),
            s(&["pod-1", "pod-2"]),
            s(&["pod-1"]),
            s(&[]),
            s(&["pod-1"]),
            s(&["pod-2"]),
        ),
        (
            "set but not listed",
            s(&[]),
            s(&["pod-1", "pod-2"]),
            s(&["pod-1"]),
            s(&[]),
            s(&[]),
            s(&["pod-1", "pod-2"]),
        ),
        (
            "one pod",
            s(&["pod-1", "pod-2"]),
            s(&["pod-1", "pod-2"]),
            s(&[]),
            s(&["pod-1"]),
            s(&["pod-1"]),
            s(&["pod-2"]),
        ),
        (
            "no listed pods",
            s(&[]),
            s(&["pod-1", "pod-2"]),
            s(&[]),
            s(&[]),
            s(&[]),
            s(&["pod-1", "pod-2"]),
        ),
    ];
    for (name, list, before, running, pods, after, unset) in cases {
        let dir = tempfile::tempdir().unwrap();
        let m = make(
            TestPods {
                pod_dir: Some(dir.path().into()),
                pod_list: list,
                ..Default::default()
            },
            None,
        )
        .unwrap();
        for (i, p) in before.iter().enumerate() {
            m.record(p, ((i + 1) * 65536) as u32, 65536).unwrap();
        }
        m.cleanup_orphaned_pod_userns_allocations(&pods, &running)
            .unwrap();
        for p in after {
            assert!(m.pod_allocated(&p), "{name}: {p} should be allocated");
        }
        for p in unset {
            assert!(!m.pod_allocated(&p), "{name}: {p} should not be allocated");
        }
    }
}

#[test]
fn userns_manager_fails_list_pod() {
    let e = make(
        TestPods {
            fail_list: true,
            ..Default::default()
        },
        None,
    )
    .err()
    .unwrap();
    assert!(e.contains("read pods from disk"), "{e}");
}

#[test]
fn userns_manager_record_bounds() {
    // Allow exactly for 1 pod
    let m = make(
        TestPods {
            mapping_first_id: 65536,
            mapping_len: 65536,
            max_pods: 1,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    m.record("0", 65536, 65536).unwrap();
    let e = m.record("2", 2 * 65536, 65536).unwrap_err();
    assert!(e.contains("out of range"), "{e}");
}

#[test]
fn userns_manager_get_sub_ids_output() {
    assert_eq!(
        parse_get_sub_ids_output("0: kubelet 65536 2147483648\n").unwrap(),
        (65536, 2147483648)
    );
    assert!(parse_get_sub_ids_output("a\nb").is_err());
    assert!(parse_get_sub_ids_output("0: kubelet 65536").is_err());
    assert!(parse_get_sub_ids_output("0: kubelet x 1").is_err());
    assert!(parse_get_sub_ids_output("0: kubelet 65536 4294967296").is_err());
    assert_eq!(
        default_kubelet_mappings(65536),
        (65536, 4294967296u64.wrapping_sub(65536) as u32)
    );
}
