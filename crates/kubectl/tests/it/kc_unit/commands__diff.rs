//! Unit tests moved from `src/commands/diff.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use anyhow::{Context, Result};
    pub use kubernetes_rs_client::http::{ApiClient, GetError};
    pub use kubernetes_rs_kubectl::discovery::RestMapper;
    pub use kubernetes_rs_kubectl::ops::build_path;
    pub use serde_json::Value;
}

mod tests {
    use kubernetes_rs_kubectl::commands::diff::strip_server_managed;
    use kubernetes_rs_kubectl::discovery::{ResourceMapping, RestMapper};
    use kubernetes_rs_kubectl::ops::build_path;
    use serde_json::json;

    fn mapping(
        group: &str,
        version: &str,
        kind: &str,
        plural: &str,
        namespaced: bool,
    ) -> ResourceMapping {
        ResourceMapping {
            group: group.into(),
            version: version.into(),
            kind: kind.into(),
            plural: plural.into(),
            singular: kind.to_lowercase(),
            namespaced,
            verbs: vec![],
            short_names: vec![],
        }
    }

    fn mapper_with(mappings: Vec<ResourceMapping>) -> RestMapper {
        RestMapper::new(mappings)
    }

    // ---------------------------------------------------------------------------
    // Path-building tests: verify that build_path (used by diff_resource) produces
    // the correct API paths for a variety of resource kinds via the mapper.
    // ---------------------------------------------------------------------------

    #[test]
    fn strip_server_managed_removes_managed_fields_keeps_real_data() {
        let mut v = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "f2-cm",
                "namespace": "default",
                "labels": { "app": "demo" },
                "uid": "abc-123",
                "resourceVersion": "4711",
                "generation": 3,
                "creationTimestamp": "2026-05-29T00:00:00Z",
                "managedFields": [{ "manager": "kubectl" }],
                "selfLink": "/api/v1/namespaces/default/configmaps/f2-cm",
                "ownerReferences": [{ "name": "owner" }],
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": "{}"
                }
            },
            "data": { "a": "1", "b": "2" },
            "status": { "phase": "Active" }
        });

        strip_server_managed(&mut v);

        let meta = v.get("metadata").unwrap().as_object().unwrap();
        for k in [
            "uid",
            "resourceVersion",
            "generation",
            "creationTimestamp",
            "managedFields",
            "selfLink",
            "ownerReferences",
        ] {
            assert!(!meta.contains_key(k), "expected {k} to be stripped");
        }
        // last-applied-configuration was the only annotation → annotations map dropped
        assert!(!meta.contains_key("annotations"));
        // status is server-populated → stripped
        assert!(v.get("status").is_none());

        // user-meaningful fields survive
        assert_eq!(meta.get("name").unwrap(), "f2-cm");
        assert_eq!(meta.get("namespace").unwrap(), "default");
        assert_eq!(meta.get("labels").unwrap(), &json!({ "app": "demo" }));
        assert_eq!(v.get("data").unwrap(), &json!({ "a": "1", "b": "2" }));
        assert_eq!(v.get("kind").unwrap(), "ConfigMap");
    }

    #[test]
    fn strip_server_managed_keeps_other_annotations() {
        let mut v = json!({
            "metadata": {
                "name": "x",
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": "{}",
                    "team": "infra"
                }
            }
        });
        strip_server_managed(&mut v);
        let ann = v
            .get("metadata")
            .unwrap()
            .get("annotations")
            .unwrap()
            .as_object()
            .unwrap();
        assert!(!ann.contains_key("kubectl.kubernetes.io/last-applied-configuration"));
        assert_eq!(ann.get("team").unwrap(), "infra");
    }

    #[test]
    fn pod_path_via_mapper() {
        let m = mapper_with(vec![mapping("", "v1", "Pod", "pods", true)]);
        let pod = m.resolve("Pod").unwrap();
        assert_eq!(
            build_path(pod, Some("default"), Some("nginx")),
            "/api/v1/namespaces/default/pods/nginx"
        );
    }

    #[test]
    fn deployment_path_via_mapper() {
        let m = mapper_with(vec![mapping(
            "apps",
            "v1",
            "Deployment",
            "deployments",
            true,
        )]);
        let dep = m.resolve("Deployment").unwrap();
        assert_eq!(
            build_path(dep, Some("prod"), Some("web")),
            "/apis/apps/v1/namespaces/prod/deployments/web"
        );
    }

    #[test]
    fn persistent_volume_cluster_scoped() {
        let m = mapper_with(vec![mapping(
            "",
            "v1",
            "PersistentVolume",
            "persistentvolumes",
            false,
        )]);
        let pv = m.resolve("PersistentVolume").unwrap();
        // namespace argument is ignored for cluster-scoped resources
        assert_eq!(
            build_path(pv, Some("ignored"), Some("pv-1")),
            "/api/v1/persistentvolumes/pv-1"
        );
    }

    #[test]
    fn crd_path_via_mapper() {
        let m = mapper_with(vec![mapping(
            "apiextensions.k8s.io",
            "v1",
            "CustomResourceDefinition",
            "customresourcedefinitions",
            false,
        )]);
        let crd = m.resolve("CustomResourceDefinition").unwrap();
        assert_eq!(
            build_path(crd, Some("ignored"), Some("foos.example.com")),
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/foos.example.com"
        );
    }

    #[test]
    fn unknown_kind_resolves_to_none() {
        let m = mapper_with(vec![mapping("", "v1", "Pod", "pods", true)]);
        assert!(m.resolve("Unknown").is_none());
    }

    #[test]
    fn service_path_via_mapper() {
        let m = mapper_with(vec![mapping("", "v1", "Service", "services", true)]);
        let svc = m.resolve("Service").unwrap();
        assert_eq!(
            build_path(svc, Some("prod"), Some("my-svc")),
            "/api/v1/namespaces/prod/services/my-svc"
        );
    }

    #[test]
    fn configmap_path_via_mapper() {
        let m = mapper_with(vec![mapping("", "v1", "ConfigMap", "configmaps", true)]);
        let cm = m.resolve("ConfigMap").unwrap();
        assert_eq!(
            build_path(cm, Some("default"), Some("cfg")),
            "/api/v1/namespaces/default/configmaps/cfg"
        );
    }

    #[test]
    fn namespace_cluster_scoped_via_mapper() {
        let m = mapper_with(vec![mapping("", "v1", "Namespace", "namespaces", false)]);
        let ns = m.resolve("Namespace").unwrap();
        assert_eq!(
            build_path(ns, Some("ignored"), Some("kube-system")),
            "/api/v1/namespaces/kube-system"
        );
    }

    #[test]
    fn statefulset_path_via_mapper() {
        let m = mapper_with(vec![mapping(
            "apps",
            "v1",
            "StatefulSet",
            "statefulsets",
            true,
        )]);
        let ss = m.resolve("StatefulSet").unwrap();
        assert_eq!(
            build_path(ss, Some("staging"), Some("mysql")),
            "/apis/apps/v1/namespaces/staging/statefulsets/mysql"
        );
    }

    #[test]
    fn node_cluster_scoped_via_mapper() {
        let m = mapper_with(vec![mapping("", "v1", "Node", "nodes", false)]);
        let node = m.resolve("Node").unwrap();
        assert_eq!(
            build_path(node, Some("ignored"), Some("worker-1")),
            "/api/v1/nodes/worker-1"
        );
    }

    #[test]
    fn rbac_resources_via_mapper() {
        let mappings = vec![
            mapping(
                "rbac.authorization.k8s.io",
                "v1",
                "ClusterRole",
                "clusterroles",
                false,
            ),
            mapping(
                "rbac.authorization.k8s.io",
                "v1",
                "ClusterRoleBinding",
                "clusterrolebindings",
                false,
            ),
            mapping("rbac.authorization.k8s.io", "v1", "Role", "roles", true),
        ];
        let m = mapper_with(mappings);

        let cr = m.resolve("ClusterRole").unwrap();
        assert_eq!(
            build_path(cr, Some("ignored"), Some("admin")),
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/admin"
        );

        let crb = m.resolve("ClusterRoleBinding").unwrap();
        assert_eq!(
            build_path(crb, Some("ignored"), Some("admin-binding")),
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/admin-binding"
        );

        let role = m.resolve("Role").unwrap();
        assert_eq!(
            build_path(role, Some("default"), Some("pod-reader")),
            "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles/pod-reader"
        );
    }
}

/// Ports of `diff_test.go` `TestMasker` and `TestDiffProgram` (diff.go
/// `Masker`, `DiffProgram`, `diffError`).
mod diff_masker_program {
    use kubernetes_rs_kubectl::commands::diff::*;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    fn mask(from: Option<Value>, to: Option<Value>) -> (Option<Value>, Option<Value>) {
        let m = Masker::new(from, to).unwrap();
        (m.from().cloned(), m.to().cloned())
    }

    fn d(v: Value) -> Option<Value> {
        Some(json!({ "data": v }))
    }

    #[test]
    fn diff_masker_no_changes() {
        let both = json!({"username": "abc", "password": "123"});
        let (f, t) = mask(d(both.clone()), d(both));
        let want = json!({"username": "***", "password": "***"});
        assert_eq!(f, d(want.clone()));
        assert_eq!(t, d(want));
    }

    #[test]
    fn diff_masker_object_created_and_removed() {
        let v = json!({"username": "abc", "password": "123"});
        let want = d(json!({"username": "***", "password": "***"}));
        let (f, t) = mask(None, d(v.clone()));
        assert_eq!((f, t), (None, want.clone()));
        let (f, t) = mask(d(v), None);
        assert_eq!((f, t), (want, None));
    }

    #[test]
    fn diff_masker_data_key_added_changed_removed() {
        let (f, t) = mask(
            d(json!({"username": "abc"})),
            d(json!({"username": "abc", "password": "123"})),
        );
        assert_eq!(f, d(json!({"username": "***"})));
        assert_eq!(t, d(json!({"username": "***", "password": "***"})));

        let (f, t) = mask(
            d(json!({"username": "abc", "password": "123"})),
            d(json!({"username": "abc", "password": "456"})),
        );
        assert_eq!(f, d(json!({"username": "***", "password": "*** (before)"})));
        assert_eq!(t, d(json!({"username": "***", "password": "*** (after)"})));

        let (f, t) = mask(
            d(json!({"username": "abc", "password": "123"})),
            d(json!({"username": "abc"})),
        );
        assert_eq!(f, d(json!({"username": "***", "password": "***"})));
        assert_eq!(t, d(json!({"username": "***"})));
    }

    #[test]
    fn diff_masker_empty_secret_and_invalid_data_key() {
        let v = json!({"username": "abc", "password": "123"});
        let want = d(json!({"username": "***", "password": "***"}));
        let (f, t) = mask(Some(json!({})), d(v.clone()));
        assert_eq!((f, t), (Some(json!({})), want.clone()));
        let (f, t) = mask(d(v.clone()), Some(json!({})));
        assert_eq!((f, t), (want, Some(json!({}))));
        // Not under `data`: skipped.
        let other = Some(json!({"some_other_key": v}));
        let (f, t) = mask(other.clone(), other.clone());
        assert_eq!((f, t), (other.clone(), other));
        // A `data` that is not a map is an error (unstructured.NestedMap).
        assert!(Masker::new(Some(json!({"data": "x"})), None).is_err());
    }

    #[test]
    fn diff_omit_managed_fields_and_secret_check() {
        let mut o = json!({"metadata": {"name": "a", "managedFields": [{}]}});
        omit_managed_fields(&mut o);
        assert_eq!(o, json!({"metadata": {"name": "a"}}));
        assert!(is_v1_secret(&json!({"apiVersion": "v1", "kind": "Secret"})));
        assert!(!is_v1_secret(
            &json!({"apiVersion": "v1", "kind": "ConfigMap"})
        ));
    }

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // One test mutates the process environment, so keep all env cases together.
    #[test]
    fn diff_program_external_diff_and_exit_codes() {
        // TestDiffProgram: "diff", "diff -ruN", "diff --report-identical-files".
        for (i, c) in ["diff", "diff -ruN", "diff --report-identical-files"]
            .iter()
            .enumerate()
        {
            std::env::set_var("KUBECTL_EXTERNAL_DIFF", c);
            std::env::set_var("LANG", "C");
            std::env::set_var("LANGUAGE", "en_US");
            let out = Buf::default();
            let mut p = DiffProgram {
                out: Box::new(out.clone()),
                err_out: Box::new(Buf::default()),
            };
            p.run("/dev/zero", "/dev/zero").unwrap();
            if i == 2 {
                let got = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
                assert_eq!(got, "Files /dev/zero and /dev/zero are identical\n");
            }
        }

        // getCommand: valid extra words are appended after the paths, invalid dropped.
        std::env::set_var("KUBECTL_EXTERNAL_DIFF", "colordiff -N --x=1 ;rm $(x)");
        let p = DiffProgram {
            out: Box::new(Buf::default()),
            err_out: Box::new(Buf::default()),
        };
        let (prog, args) = p.get_command("a", "b");
        assert_eq!(prog, "colordiff");
        assert_eq!(args, ["a", "b", "-N", "--x=1"]);
        std::env::remove_var("KUBECTL_EXTERNAL_DIFF");
        let (prog, args) = p.get_command("a", "b");
        assert_eq!(
            (prog.as_str(), args),
            (
                "diff",
                vec!["-u".into(), "-N".into(), "a".into(), "b".into()]
            )
        );

        // Exit status 1 is a diffError; a missing program is not.
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, "x\n").unwrap();
        std::fs::write(&b, "y\n").unwrap();
        let mut p = DiffProgram {
            out: Box::new(Buf::default()),
            err_out: Box::new(Buf::default()),
        };
        let err = p.run(a.to_str().unwrap(), b.to_str().unwrap()).unwrap_err();
        assert_eq!(diff_error(&err), Some(&DiffExitError { status: 1 }));
        std::env::set_var("KUBECTL_EXTERNAL_DIFF", "/nonexistent-diff-program");
        let err = p.run("a", "b").unwrap_err();
        assert!(diff_error(&err).is_none());
        assert!(err
            .to_string()
            .starts_with("failed to run \"/nonexistent-diff-program\""));
        std::env::remove_var("KUBECTL_EXTERNAL_DIFF");
    }
}

/// `Differ`, `InfoObject.Name`, `Complete` flag checks and the exit-status
/// contract of `kubectl diff` (diff.go:376, 545-610, 631-651; diff_test.go
/// TestDiffer).
mod diff_differ {
    use kubernetes_rs_kubectl::commands::diff::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn program(out: &Buf) -> DiffProgram {
        DiffProgram {
            out: Box::new(out.clone()),
            err_out: Box::new(Buf::default()),
        }
    }

    fn text(out: &Buf) -> String {
        String::from_utf8(out.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn diff_object_name_and_field_manager() {
        assert_eq!(
            object_name("apps", "v1", "Deployment", "ns", "web"),
            "apps.v1.Deployment.ns.web"
        );
        assert_eq!(object_name("", "v1", "Pod", "ns", "p"), "v1.Pod.ns.p");
        assert_eq!(
            apply_field_manager(None, false),
            "kubectl-client-side-apply"
        );
        assert_eq!(apply_field_manager(None, true), "kubectl");
        assert_eq!(apply_field_manager(Some("me"), true), "me");
    }

    #[test]
    fn diff_validate_options() {
        let ok = DiffOptions {
            files: vec!["a.yaml".into()],
            ..Default::default()
        };
        assert!(validate_options(&ok).is_ok());
        assert_eq!(
            validate_options(&DiffOptions::default())
                .unwrap_err()
                .to_string(),
            "must specify one of -f and -k"
        );
        let bad = DiffOptions {
            force_conflicts: true,
            ..ok
        };
        assert_eq!(
            validate_options(&bad).unwrap_err().to_string(),
            "--force-conflicts only works with --server-side"
        );
    }

    // Env-mutating, so kept as one test (nextest runs each test in its own process).
    #[test]
    fn diff_differ_masks_secret_omits_managed_fields_and_reports_status() {
        std::env::remove_var("KUBECTL_EXTERNAL_DIFF");
        let differ = Differ::new("LIVE", "MERGED").unwrap();
        let live = json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "s", "managedFields": [{"manager": "x"}]},
            "data": {"password": "MTIz", "same": "eA=="}
        });
        let mut merged = live.clone();
        merged["data"]["password"] = json!("NDU2");
        differ
            .diff("v1.Secret.ns.s", Some(live.clone()), Some(merged), false)
            .unwrap();

        let out = Buf::default();
        let err = differ.run(&mut program(&out)).unwrap_err();
        // Differences were found: exit status 1, not a failure.
        assert_eq!(diff_error(&err), Some(&DiffExitError { status: 1 }));
        let t = text(&out);
        assert!(
            t.contains("*** (before)") && t.contains("*** (after)"),
            "{t}"
        );
        assert!(
            !t.contains("MTIz") && !t.contains("NDU2"),
            "secret leaked: {t}"
        );
        assert!(!t.contains("managedFields"), "{t}");

        // No differences: exit status 0.
        let same = Differ::new("LIVE", "MERGED").unwrap();
        same.diff("n", Some(live.clone()), Some(live), true)
            .unwrap();
        assert!(same.run(&mut program(&Buf::default())).is_ok());

        // A created object shows as all added.
        let created = Differ::new("LIVE", "MERGED").unwrap();
        created
            .diff("n", None, Some(json!({"kind": "ConfigMap"})), true)
            .unwrap();
        let out = Buf::default();
        assert!(created.run(&mut program(&out)).is_err());
        assert!(text(&out).contains("+kind: ConfigMap"), "{}", text(&out));
    }
}
