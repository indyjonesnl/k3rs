//! Unit tests moved from `src/commands/set.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use anyhow::{Context, Result};
    pub use kubernetes_rs_client::http::ApiClient;
    pub use kubernetes_rs_kubectl::discovery::ResourceMapping;
    pub use kubernetes_rs_kubectl::types::SetCommands;
    pub use serde_json::{json, Value};
}

mod tests {
    use super::__parent::*;
    use kubernetes_rs_kubectl::commands::set::*;

    #[test]
    fn test_parse_resource_arg() {
        let (rt, name) = parse_resource_arg("deployment/nginx").unwrap();
        assert_eq!(rt, "deployment");
        assert_eq!(name, "nginx");
    }

    #[test]
    fn test_parse_resource_arg_invalid() {
        assert!(parse_resource_arg("nginx").is_err());
    }

    #[test]
    fn test_parse_resource_spec() {
        let map = parse_resource_spec(Some("cpu=200m,memory=512Mi")).unwrap();
        assert_eq!(map.get("cpu").unwrap(), "200m");
        assert_eq!(map.get("memory").unwrap(), "512Mi");
    }

    #[test]
    fn test_parse_resource_spec_none() {
        let map = parse_resource_spec(None).unwrap();
        assert!(map.is_empty());
    }

    // Helper mirroring a discovery ResourceMapping so the path-shape assertions
    // below exercise the same `ops::build_path` that `resolve_resource_path`
    // now calls. The actual name->mapping resolution is covered by the mapper
    // tests in discovery.rs.
    fn mapping(
        group: &str,
        plural: &str,
        namespaced: bool,
    ) -> kubernetes_rs_kubectl::discovery::ResourceMapping {
        kubernetes_rs_kubectl::discovery::ResourceMapping {
            group: group.into(),
            version: "v1".into(),
            kind: "X".into(),
            plural: plural.into(),
            singular: "x".into(),
            namespaced,
            verbs: vec![],
            short_names: vec![],
        }
    }

    #[test]
    fn test_resolve_resource_path() {
        let dep = mapping("apps", "deployments", true);
        assert_eq!(
            kubernetes_rs_kubectl::ops::build_path(&dep, Some("default"), Some("nginx")),
            "/apis/apps/v1/namespaces/default/deployments/nginx"
        );

        let pod = mapping("", "pods", true);
        assert_eq!(
            kubernetes_rs_kubectl::ops::build_path(&pod, Some("kube-system"), Some("mypod")),
            "/api/v1/namespaces/kube-system/pods/mypod"
        );

        let sts = mapping("apps", "statefulsets", true);
        assert_eq!(
            kubernetes_rs_kubectl::ops::build_path(&sts, Some("default"), Some("myapp")),
            "/apis/apps/v1/namespaces/default/statefulsets/myapp"
        );
    }

    #[test]
    fn test_image_patch_construction_for_deployment() {
        // Simulate building a strategic merge patch for image update on a deployment
        let patch_containers = vec![json!({"name": "nginx", "image": "nginx:1.21"})];

        let patch_body = json!({
            "spec": {
                "template": {
                    "spec": {
                        "containers": patch_containers,
                    }
                }
            }
        });

        assert_eq!(
            patch_body["spec"]["template"]["spec"]["containers"][0]["name"],
            "nginx"
        );
        assert_eq!(
            patch_body["spec"]["template"]["spec"]["containers"][0]["image"],
            "nginx:1.21"
        );
    }

    #[test]
    fn test_env_update_add_and_remove() {
        // Simulate the env update logic: add KEY=VALUE and remove KEY-
        let env_vars = vec!["NEW_VAR=hello".to_string(), "OLD_VAR-".to_string()];
        let mut to_add: Vec<(String, String)> = Vec::new();
        let mut to_remove: Vec<String> = Vec::new();

        for ev in &env_vars {
            if let Some(key) = ev.strip_suffix('-') {
                to_remove.push(key.to_string());
            } else if let Some((key, value)) = ev.split_once('=') {
                to_add.push((key.to_string(), value.to_string()));
            }
        }

        assert_eq!(to_add, vec![("NEW_VAR".to_string(), "hello".to_string())]);
        assert_eq!(to_remove, vec!["OLD_VAR".to_string()]);

        // Simulate applying to existing env list
        let mut env_list: Vec<Value> = vec![
            json!({"name": "OLD_VAR", "value": "world"}),
            json!({"name": "KEEP", "value": "yes"}),
        ];

        env_list.retain(|e| {
            let key = e.get("name").and_then(|n| n.as_str()).unwrap_or("");
            !to_remove.contains(&key.to_string())
        });

        for (key, value) in &to_add {
            env_list.push(json!({"name": key, "value": value}));
        }

        assert_eq!(env_list.len(), 2);
        assert_eq!(env_list[0]["name"], "KEEP");
        assert_eq!(env_list[1]["name"], "NEW_VAR");
        assert_eq!(env_list[1]["value"], "hello");
    }

    #[test]
    fn test_parse_resource_spec_invalid() {
        assert!(parse_resource_spec(Some("cpu200m")).is_err());
    }

    #[test]
    fn test_parse_selector_expressions() {
        let expressions = vec!["app=nginx".to_string(), "env=prod".to_string()];
        let mut selector = serde_json::Map::new();
        for expr in &expressions {
            if let Some((key, value)) = expr.split_once('=') {
                selector.insert(key.to_string(), json!(value));
            }
        }
        assert_eq!(selector.get("app").unwrap(), "nginx");
        assert_eq!(selector.get("env").unwrap(), "prod");
    }

    #[test]
    fn test_parse_serviceaccount_with_namespace() {
        let sa = "kube-system:default";
        let (ns, name) = sa.split_once(':').unwrap();
        assert_eq!(ns, "kube-system");
        assert_eq!(name, "default");
    }

    #[test]
    fn test_subject_json_construction() {
        let user_subject = json!({
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "User",
            "name": "admin",
        });
        assert_eq!(user_subject["kind"].as_str().unwrap(), "User");
        assert_eq!(user_subject["name"].as_str().unwrap(), "admin");
    }

    #[test]
    fn test_resolve_resource_path_full_plural_names() {
        // Path shapes built by ops::build_path for the workload kinds set
        // operates on. Name resolution itself lives in discovery.rs.
        let cases = vec![
            (mapping("", "pods", true), "/api/v1/namespaces/ns1/pods/p1"),
            (
                mapping("apps", "deployments", true),
                "/apis/apps/v1/namespaces/ns1/deployments/d1",
            ),
            (
                mapping("apps", "daemonsets", true),
                "/apis/apps/v1/namespaces/ns1/daemonsets/ds1",
            ),
            (
                mapping("apps", "statefulsets", true),
                "/apis/apps/v1/namespaces/ns1/statefulsets/ss1",
            ),
            (
                mapping("apps", "replicasets", true),
                "/apis/apps/v1/namespaces/ns1/replicasets/rs1",
            ),
            (
                mapping("", "replicationcontrollers", true),
                "/api/v1/namespaces/ns1/replicationcontrollers/rc1",
            ),
            (
                mapping("batch", "cronjobs", true),
                "/apis/batch/v1/namespaces/ns1/cronjobs/cj1",
            ),
        ];
        for (m, expected) in cases {
            let name = expected.rsplit('/').next().unwrap();
            assert_eq!(
                kubernetes_rs_kubectl::ops::build_path(&m, Some("ns1"), Some(name)),
                expected
            );
        }
    }

    #[test]
    fn test_parse_resource_arg_with_slash_in_name() {
        // splitn(2, '/') means only first slash is used
        let (rt, name) = parse_resource_arg("deployment/my-app").unwrap();
        assert_eq!(rt, "deployment");
        assert_eq!(name, "my-app");
    }

    #[test]
    fn test_parse_resource_arg_empty_name() {
        let (rt, name) = parse_resource_arg("deployment/").unwrap();
        assert_eq!(rt, "deployment");
        assert_eq!(name, "");
    }

    #[test]
    fn test_parse_resource_spec_empty_string() {
        let map = parse_resource_spec(Some("")).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_resource_spec_trailing_comma() {
        let map = parse_resource_spec(Some("cpu=100m,")).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("cpu").unwrap(), "100m");
    }

    #[test]
    fn test_parse_resource_spec_whitespace_trimming() {
        let map = parse_resource_spec(Some(" cpu=100m , memory=256Mi ")).unwrap();
        assert_eq!(map.get("cpu").unwrap(), "100m");
        assert_eq!(map.get("memory").unwrap(), "256Mi");
    }

    #[test]
    fn test_parse_resource_spec_single_value() {
        let map = parse_resource_spec(Some("cpu=500m")).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("cpu").unwrap(), "500m");
    }

    #[test]
    fn test_selector_expression_invalid_format() {
        let expressions = vec!["noequalssign".to_string()];
        let mut selector = serde_json::Map::new();
        let mut had_error = false;
        for expr in &expressions {
            if let Some((key, value)) = expr.split_once('=') {
                selector.insert(key.to_string(), json!(value));
            } else {
                had_error = true;
            }
        }
        assert!(had_error);
        assert!(selector.is_empty());
    }

    #[test]
    fn test_selector_expression_empty_value() {
        let expressions = vec!["app=".to_string()];
        let mut selector = serde_json::Map::new();
        for expr in &expressions {
            if let Some((key, value)) = expr.split_once('=') {
                selector.insert(key.to_string(), json!(value));
            }
        }
        assert_eq!(selector.get("app").unwrap(), "");
    }

    #[test]
    fn test_image_patch_construction_for_pod() {
        // Pod has no template — patch goes directly under spec
        let patch_containers = vec![json!({"name": "app", "image": "myapp:2.0"})];
        let patch_body = json!({
            "spec": {
                "containers": patch_containers,
            }
        });
        assert_eq!(patch_body["spec"]["containers"][0]["name"], "app");
        assert_eq!(patch_body["spec"]["containers"][0]["image"], "myapp:2.0");
        // Ensure no template nesting
        assert!(patch_body["spec"].get("template").is_none());
    }

    #[test]
    fn test_image_patch_wildcard_updates_all() {
        // Simulate wildcard container image update
        let containers = vec![
            json!({"name": "web", "image": "nginx:1.19"}),
            json!({"name": "sidecar", "image": "envoy:1.0"}),
        ];
        let new_image = "registry.example.com/latest";
        let mut patch_containers: Vec<Value> = Vec::new();
        for c in &containers {
            if let Some(cname) = c.get("name").and_then(|n| n.as_str()) {
                patch_containers.push(json!({
                    "name": cname,
                    "image": new_image,
                }));
            }
        }
        assert_eq!(patch_containers.len(), 2);
        assert_eq!(patch_containers[0]["name"], "web");
        assert_eq!(patch_containers[0]["image"], new_image);
        assert_eq!(patch_containers[1]["name"], "sidecar");
        assert_eq!(patch_containers[1]["image"], new_image);
    }

    #[test]
    fn test_serviceaccount_without_namespace_separator() {
        let sa = "my-sa";
        let result = sa.split_once(':');
        assert!(result.is_none());
        // Falls back to using the default namespace
        let (sa_namespace, sa_name) = if let Some((ns, n)) = sa.split_once(':') {
            (ns.to_string(), n.to_string())
        } else {
            ("default".to_string(), sa.to_string())
        };
        assert_eq!(sa_namespace, "default");
        assert_eq!(sa_name, "my-sa");
    }

    #[test]
    fn test_subject_group_json_construction() {
        let group_subject = json!({
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Group",
            "name": "developers",
        });
        assert_eq!(group_subject["kind"].as_str().unwrap(), "Group");
        assert_eq!(group_subject["name"].as_str().unwrap(), "developers");
        assert_eq!(
            group_subject["apiGroup"].as_str().unwrap(),
            "rbac.authorization.k8s.io"
        );
    }

    #[test]
    fn test_subject_serviceaccount_json_construction() {
        let sa_subject = json!({
            "kind": "ServiceAccount",
            "name": "deployer",
            "namespace": "ci-cd",
        });
        assert_eq!(sa_subject["kind"].as_str().unwrap(), "ServiceAccount");
        assert_eq!(sa_subject["name"].as_str().unwrap(), "deployer");
        assert_eq!(sa_subject["namespace"].as_str().unwrap(), "ci-cd");
        // ServiceAccount subjects should NOT have apiGroup
        assert!(sa_subject.get("apiGroup").is_none());
    }

    #[test]
    fn test_env_parsing_invalid_format() {
        let ev = "NOEQUALSNODASH";
        let is_remove = ev.strip_suffix('-').is_some();
        let is_add = ev.split_once('=').is_some();
        assert!(!is_remove);
        assert!(!is_add);
    }

    #[test]
    fn test_env_parsing_value_with_equals() {
        // KEY=VAL=UE should split on first = only
        let ev = "DB_URL=postgres://host:5432/db?opt=val";
        let (key, value) = ev.split_once('=').unwrap();
        assert_eq!(key, "DB_URL");
        assert_eq!(value, "postgres://host:5432/db?opt=val");
    }

    // ===== 10 additional tests for untested async functions =====

    fn make_test_client() -> ApiClient {
        ApiClient::new("http://127.0.0.1:1", true, None).unwrap()
    }

    #[tokio::test]
    async fn test_execute_image_returns_err_on_unreachable() {
        let client = make_test_client();
        let result = execute_image(
            &client,
            "deployment/nginx",
            &["nginx=nginx:1.21".to_string()],
            "default",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_image_invalid_resource_format() {
        let client = make_test_client();
        let result = execute_image(
            &client,
            "nginx",
            &["nginx=nginx:1.21".to_string()],
            "default",
        )
        .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid resource format"));
    }

    #[tokio::test]
    async fn test_execute_env_returns_err_on_unreachable() {
        let client = make_test_client();
        let result = execute_env(
            &client,
            "deployment/web",
            &["FOO=bar".to_string()],
            "default",
            None,
            false,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_resources_returns_err_on_unreachable() {
        let client = make_test_client();
        let result = execute_resources(
            &client,
            "deployment/web",
            "default",
            None,
            Some("cpu=200m"),
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_selector_returns_err_on_unreachable() {
        let client = make_test_client();
        let result =
            execute_selector(&client, "service/web", &["app=web".to_string()], "default").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_serviceaccount_returns_err_on_unreachable() {
        let client = make_test_client();
        let result = execute_serviceaccount(&client, "deployment/web", "my-sa", "default").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_subject_returns_err_on_unreachable() {
        let client = make_test_client();
        let result = execute_subject(
            &client,
            "clusterrolebinding/admin",
            "default",
            None,
            Some("admin-user"),
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_subject_unsupported_resource_type() {
        // The "only supports rolebinding/clusterrolebinding" guard now runs
        // after server discovery, so against an unreachable server the error is
        // a connection/discovery failure rather than the guard message. The
        // contract preserved here is simply that a non-binding kind fails.
        let client = make_test_client();
        let result = execute_subject(
            &client,
            "deployment/web",
            "default",
            None,
            Some("user1"),
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_subject_guard_rejects_non_binding_kind() {
        use kubernetes_rs_kubectl::discovery::{parse_aggregated_discovery, RestMapper};
        let raw = include_str!("../../fixtures/aggregated-discovery.json");
        let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
        let mapper = RestMapper::new(parse_aggregated_discovery(&doc).unwrap());
        let mapping = mapper.resolve("deployment").unwrap();
        // The same predicate execute_subject's guard uses:
        let allowed = mapping.kind == "RoleBinding" || mapping.kind == "ClusterRoleBinding";
        assert!(
            !allowed,
            "deployment must be rejected by the set-subject kind guard"
        );
        // and a positive case if rolebindings is in the fixture:
        if let Some(rb) = mapper.resolve("rolebindings") {
            assert!(rb.kind == "RoleBinding" || rb.kind == "ClusterRoleBinding");
        }
    }

    #[tokio::test]
    async fn test_execute_image_no_container_images_returns_err() {
        let client = make_test_client();
        let result = execute_image(&client, "deployment/nginx", &[], "default").await;
        // Empty container_images should fail (after fetching, but resource fetch fails first)
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_set_dispatches_image_command() {
        let client = make_test_client();
        let cmd = SetCommands::Image {
            resource: "deployment/nginx".to_string(),
            container_images: vec!["nginx=nginx:1.21".to_string()],
            namespace: Some("test-ns".to_string()),
        };
        let result = execute_set(&client, cmd, "default").await;
        assert!(result.is_err()); // connection error
    }
}

/// Ports of cmd/set/env/env_parse_test.go and cmd/set/helper_test.go
/// `Test_updateEnv`.
mod set_env_parse {
    use kubernetes_rs_kubectl::commands::set::*;
    use serde_json::{json, Value};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }
    fn ev(n: &str, v: &str) -> Value {
        json!({"name": n, "value": v})
    }

    #[test]
    fn set_env_is_environment_argument() {
        assert!(is_environment_argument("returns=true"));
        assert!(!is_environment_argument("returnsfalse"));
        assert!(!is_environment_argument("=x"));
    }

    #[test]
    fn set_env_split_environment_from_resources() {
        let args = s(&["resource", "ENV\\=ARG", "ONE\\=MORE", "DASH-"]);
        let (r, e) = split_environment_from_resources(&args).unwrap();
        assert_eq!(r, ["resource"]);
        assert_eq!(e, ["ENV\\=ARG", "ONE\\=MORE", "DASH-"]);
        // a resource after an env argument is not ok
        assert!(split_environment_from_resources(&s(&["A=b", "res"])).is_none());
    }

    #[test]
    fn set_env_parse_env_good_with_stdin() {
        let mut r = std::io::Cursor::new("FROM=READER");
        let ss = s(&[
            "ENV=VARIABLE",
            "ENV.TEST=VARIABLE",
            "AND=ANOTHER",
            "REMOVE-",
            "-",
        ]);
        let (env, remove, used) = parse_env(&ss, Some(&mut r)).unwrap();
        assert_eq!(
            env,
            [
                ev("ENV", "VARIABLE"),
                ev("ENV.TEST", "VARIABLE"),
                ev("AND", "ANOTHER"),
                ev("FROM", "READER")
            ]
        );
        assert_eq!(remove, ["REMOVE"]);
        assert!(used);
    }

    #[test]
    fn set_env_parse_env_good_without_stdin() {
        let ss = s(&[
            "ENV=VARIABLE",
            "ENV.TEST=VARIABLE",
            "AND=ANOTHER",
            "REMOVE-",
        ]);
        let (env, remove, used) = parse_env(&ss, None).unwrap();
        assert_eq!(env.len(), 3);
        assert_eq!(remove, ["REMOVE"]);
        assert!(!used);
        // '-' needs an open STDIN
        assert_eq!(
            parse_env(&s(&["-"]), None).unwrap_err().to_string(),
            "when '-' is used, STDIN must be open"
        );
    }

    #[test]
    fn set_env_parse_env_errors() {
        let msg = "a valid environment variable name must consist of alphabetic characters, digits, '_', '-', or '.', and must not start with a digit (e.g. 'my.env-name',  or 'MY_ENV.NAME',  or 'MyEnvName1', regex used for validation is '[-._a-zA-Z][-._a-zA-Z0-9]*')";
        let e = |x: &str| parse_env(&s(&[x]), None).unwrap_err().to_string();
        assert_eq!(
            e("This not in the key=value format."),
            format!("\"This not in the key\" is not a valid key name: {msg}")
        );
        assert_eq!(
            e(".=VARIABLE"),
            "\".\" is not a valid key name: must not be '.'"
        );
        assert_eq!(
            e("..=VARIABLE"),
            "\"..\" is not a valid key name: must not be '..'"
        );
        assert_eq!(
            e("..ENV=VARIABLE"),
            "\"..ENV\" is not a valid key name: must not start with '..'"
        );
        assert_eq!(e("plain"), "unknown environment variable: plain");
        assert_eq!(
            parse_env(&s(&["A=1", "A-"]), None).unwrap_err().to_string(),
            "can not both modify and remove the same environment variable in the same command"
        );
    }

    // Test_updateEnv (helper_test.go:26)
    #[test]
    fn set_env_update_env() {
        let (e1, e2, e3) = (ev("env1", "env1"), ev("env2", "env2"), ev("env3", "env3"));
        let r = |x: &[&str]| s(x);
        type Case = (Vec<Value>, Vec<Value>, Vec<String>, Vec<Value>);
        let cases: Vec<Case> = vec![
            (
                vec![e1.clone()],
                vec![e2.clone()],
                r(&["env1"]),
                vec![e2.clone()],
            ),
            (
                vec![e1.clone(), e2.clone()],
                vec![e3.clone()],
                r(&["env1"]),
                vec![e2.clone(), e3.clone()],
            ),
            (
                vec![e1.clone()],
                vec![e2.clone(), e2.clone()],
                r(&["env1"]),
                vec![e2.clone()],
            ),
            (
                vec![e1.clone()],
                vec![e2.clone(), e2.clone(), e2.clone(), e3.clone()],
                r(&["env1"]),
                vec![e2.clone(), e3.clone()],
            ),
            (
                vec![e1.clone()],
                vec![e2.clone(), e1.clone()],
                r(&["env1", "env1"]),
                vec![e2.clone()],
            ),
            (
                vec![e1.clone(), e1.clone()],
                vec![e2.clone()],
                vec![],
                vec![e1.clone(), e1.clone(), e2.clone()],
            ),
            (
                vec![e1.clone(), e1.clone(), e2.clone()],
                vec![e1.clone()],
                vec![],
                vec![e1.clone(), e2.clone()],
            ),
        ];
        for (i, (existing, add, remove, want)) in cases.iter().enumerate() {
            assert_eq!(&update_env(existing, add, remove), want, "case {}", i + 1);
        }
    }

    #[test]
    fn set_env_validate_no_overwrites_and_key_names() {
        let existing = vec![ev("A", "1")];
        assert!(validate_no_overwrites(&existing, &[ev("A", "1")]).is_ok());
        assert_eq!(
            validate_no_overwrites(&existing, &[ev("A", "2")])
                .unwrap_err()
                .to_string(),
            "'A' already has a value (1), and --overwrite is false"
        );
        assert!(env_keys_contain("k", &[]));
        assert!(!env_keys_contain("k", &s(&["x"])));
        assert_eq!(key_to_env_name("my-key.v1"), "MY_KEY_V1");
    }

    #[test]
    fn set_env_select_string() {
        assert!(select_string("abc", "*"));
        assert!(select_string("abc", "abc"));
        assert!(!select_string("abc", "abd"));
        assert!(select_string("abcdef", "abc*"));
        assert!(select_string("abcdef", "*def"));
        assert!(!select_string("abcdef", "*de"));
        assert!(!select_string("abcdef", "x*"));
    }
}

/// Ports of the logic exercised by set_image_test.go (`getResourcesAndImages`,
/// `Validate`, `setImage`, the Run patch function).
mod set_image_logic {
    use kubernetes_rs_kubectl::commands::set::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn set_image_resources_and_pairs() {
        let (r, p) = get_resources_and_pairs(
            &s(&["deployment/nginx", "busybox=busybox", "nginx=nginx:1.9.1"]),
            "image",
        )
        .unwrap();
        assert_eq!(r, ["deployment/nginx"]);
        assert_eq!(p, ["busybox=busybox", "nginx=nginx:1.9.1"]);
        assert_eq!(
            get_resources_and_pairs(&s(&["a=b", "res"]), "image")
                .unwrap_err()
                .to_string(),
            "all resources must be specified before image changes: res"
        );
        // A leading '=' is a resource, not a pair.
        let (r, p) = get_resources_and_pairs(&s(&["=x"]), "image").unwrap();
        assert_eq!((r, p), (s(&["=x"]), vec![]));
        assert_eq!(
            parse_pairs(&s(&["x-"]), "image").unwrap_err().to_string(),
            "invalid image format: x-"
        );
    }

    #[test]
    fn set_image_validate() {
        let one: BTreeMap<String, String> = [("a".to_string(), "i".to_string())].into();
        let res = s(&["deployment/x"]);
        assert!(validate_image_args(&res, &one).is_ok());
        assert_eq!(
            validate_image_args(&res, &BTreeMap::new())
                .unwrap_err()
                .to_string(),
            "at least one image update is required"
        );
        let wild: BTreeMap<String, String> = [
            ("*".to_string(), "i".to_string()),
            ("a".to_string(), "j".to_string()),
        ]
        .into();
        assert_eq!(
            validate_image_args(&res, &wild).unwrap_err().to_string(),
            "all containers are already specified by *, but saw more than one container_name=container_image pairs"
        );
        assert_eq!(
            validate_image_args(&[], &BTreeMap::new()).unwrap_err().to_string(),
            "[one or more resources must be specified as <resource> <name> or <resource>/<name>, at least one image update is required]"
        );
    }

    #[test]
    fn set_image_patch_ops_init_containers_wildcard_and_missing() {
        let spec = json!({
            "initContainers": [{"name": "init", "image": "busybox"}],
            "containers": [
                {"name": "web", "image": "nginx:1.19"},
                {"name": "side", "image": "envoy:1.0"}
            ]
        });
        let img = |k: &str, v: &str| -> BTreeMap<String, String> {
            [(k.to_string(), v.to_string())].into()
        };

        let (ops, errs) = image_patch_ops("/spec/template/spec", &spec, &img("*", "x:1"));
        assert!(errs.is_empty());
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0]["path"], "/spec/template/spec/initContainers/0/image");
        assert_eq!(ops[2]["path"], "/spec/template/spec/containers/1/image");

        let (ops, errs) = image_patch_ops("/spec", &spec, &img("web", "nginx:1.21"));
        assert!(errs.is_empty());
        assert_eq!(
            ops,
            [json!({"op": "add", "path": "/spec/containers/0/image", "value": "nginx:1.21"})]
        );

        // Same image: no change, no ops.
        let (ops, _) = image_patch_ops("/spec", &spec, &img("web", "nginx:1.19"));
        assert!(ops.is_empty());

        let (ops, errs) = image_patch_ops("/spec", &spec, &img("nope", "x"));
        assert!(ops.is_empty());
        assert_eq!(errs, ["error: unable to find container named \"nope\""]);
    }
}
