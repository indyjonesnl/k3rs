//! Unit tests moved from `src/commands/run.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use anyhow::{Context, Result};
    pub use kubernetes_rs_client::http::ApiClient;
    pub use serde_json::json;
    pub use std::collections::HashMap;
}

mod tests {
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn test_pod_json_structure() {
        let name = "nginx";
        let image = "nginx:latest";
        let namespace = "default";

        let mut label_map: HashMap<String, String> = HashMap::new();
        label_map.insert("run".to_string(), name.to_string());

        let container = json!({
            "name": name,
            "image": image,
        });

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": label_map,
            },
            "spec": {
                "containers": [container],
                "restartPolicy": "Always",
            }
        });

        assert_eq!(pod["kind"], "Pod");
        assert_eq!(pod["apiVersion"], "v1");
        assert_eq!(pod["metadata"]["name"], "nginx");
        assert_eq!(pod["metadata"]["namespace"], "default");
        assert_eq!(pod["metadata"]["labels"]["run"], "nginx");
        assert_eq!(pod["spec"]["containers"][0]["name"], "nginx");
        assert_eq!(pod["spec"]["containers"][0]["image"], "nginx:latest");
        assert_eq!(pod["spec"]["restartPolicy"], "Always");
    }

    #[test]
    fn test_pod_with_port() {
        let mut container = json!({
            "name": "nginx",
            "image": "nginx",
        });
        container["ports"] = json!([{"containerPort": 80}]);

        assert_eq!(container["ports"][0]["containerPort"], 80);
    }

    #[test]
    fn test_pod_with_env() {
        let env_vars = vec!["FOO=bar".to_string(), "BAZ=qux".to_string()];
        let mut env_list = Vec::new();
        for env in &env_vars {
            if let Some((k, v)) = env.split_once('=') {
                env_list.push(json!({"name": k, "value": v}));
            }
        }

        assert_eq!(env_list.len(), 2);
        assert_eq!(env_list[0]["name"], "FOO");
        assert_eq!(env_list[0]["value"], "bar");
        assert_eq!(env_list[1]["name"], "BAZ");
        assert_eq!(env_list[1]["value"], "qux");
    }

    #[test]
    fn test_pod_with_labels() {
        let labels_str = "app=nginx,env=prod";
        let mut label_map: HashMap<String, String> = HashMap::new();
        label_map.insert("run".to_string(), "nginx".to_string());

        for pair in labels_str.split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                label_map.insert(k.to_string(), v.to_string());
            }
        }

        assert_eq!(label_map.get("run"), Some(&"nginx".to_string()));
        assert_eq!(label_map.get("app"), Some(&"nginx".to_string()));
        assert_eq!(label_map.get("env"), Some(&"prod".to_string()));
    }

    #[test]
    fn test_pod_with_command() {
        let command = vec!["sh".to_string(), "-c".to_string(), "echo hello".to_string()];
        let mut container = json!({
            "name": "test",
            "image": "busybox",
        });
        container["command"] = json!(command);

        assert_eq!(container["command"][0], "sh");
        assert_eq!(container["command"][1], "-c");
        assert_eq!(container["command"][2], "echo hello");
    }

    #[test]
    fn test_restart_policy_values() {
        for policy in &["Always", "OnFailure", "Never"] {
            let pod = json!({
                "spec": {
                    "restartPolicy": policy,
                }
            });
            assert_eq!(pod["spec"]["restartPolicy"], *policy);
        }
    }

    #[test]
    fn test_dry_run_client_path() {
        let namespace = "default";
        let path = format!("/api/v1/namespaces/{}/pods", namespace);
        let dry_run = Some("server");
        let query = if let Some(dr) = dry_run {
            if dr == "server" {
                format!("{}?dryRun=All", path)
            } else {
                path.clone()
            }
        } else {
            path.clone()
        };
        assert_eq!(query, "/api/v1/namespaces/default/pods?dryRun=All");
    }
}

/// Ports of `pkg/generate/versioned/run_test.go` / `pkg/cmd/run/run_test.go`
/// behaviours for the pod generator.
mod run_generator {
    use kubernetes_rs_kubectl::commands::run::*;
    use serde_json::json;

    fn base() -> RunPodParams {
        RunPodParams {
            name: "foo".into(),
            image: "nginx".into(),
            ..Default::default()
        }
    }

    #[test]
    fn run_generate_pod_defaults() {
        let pod = generate_pod(&base()).unwrap();
        assert_eq!(pod["metadata"]["labels"], json!({"run": "foo"}));
        assert_eq!(pod["spec"]["restartPolicy"], "Always");
        assert_eq!(pod["spec"]["dnsPolicy"], "ClusterFirst");
        assert_eq!(pod["spec"]["containers"][0]["name"], "foo");
    }

    // getLabels: explicit labels REPLACE the default run=<name>.
    #[test]
    fn run_labels_replace_default() {
        let mut p = base();
        p.labels = Some("a=b,c=d".into());
        let pod = generate_pod(&p).unwrap();
        assert_eq!(pod["metadata"]["labels"], json!({"a": "b", "c": "d"}));
        p.labels = Some("a".into());
        assert_eq!(
            generate_pod(&p).unwrap_err().to_string(),
            "unexpected label spec: a"
        );
        p.labels = Some("=b".into());
        assert_eq!(
            generate_pod(&p).unwrap_err().to_string(),
            "unexpected empty label key"
        );
    }

    #[test]
    fn run_env_validation_and_value_with_equals() {
        let mut p = base();
        p.env = vec!["A=b=c".into()];
        let pod = generate_pod(&p).unwrap();
        assert_eq!(
            pod["spec"]["containers"][0]["env"],
            json!([{"name":"A","value":"b=c"}])
        );
        for bad in ["noequals", "=v", "1A=v"] {
            p.env = vec![bad.into()];
            assert_eq!(
                generate_pod(&p).unwrap_err().to_string(),
                format!("invalid env: {bad}")
            );
        }
    }

    #[test]
    fn run_annotations_pairs() {
        let mut p = base();
        p.annotations = vec!["k=v".into()];
        assert_eq!(
            generate_pod(&p).unwrap()["metadata"]["annotations"],
            json!({"k":"v"})
        );
        p.annotations = vec!["k".into(), "=x".into()];
        assert_eq!(
            generate_pod(&p).unwrap_err().to_string(),
            "invalid annotations format: k, =x"
        );
    }

    #[test]
    fn run_restart_policy_and_pull_policy_validation() {
        assert_eq!(get_restart_policy("", false).unwrap(), "Always");
        assert_eq!(get_restart_policy("", true).unwrap(), "OnFailure");
        assert_eq!(get_restart_policy("Never", false).unwrap(), "Never");
        assert_eq!(
            get_restart_policy("bogus", false).unwrap_err().to_string(),
            "invalid restart policy: bogus"
        );
        assert!(verify_image_pull_policy("IfNotPresent").is_ok());
        assert_eq!(
            verify_image_pull_policy("x").unwrap_err().to_string(),
            "invalid image pull policy: x"
        );
    }

    #[test]
    fn run_validate_requires_image_and_stdin_for_tty() {
        let mut p = base();
        p.image = String::new();
        assert_eq!(
            validate_run(&p).unwrap_err().to_string(),
            "--image is required"
        );
        p.image = "nginx".into();
        p.tty = true;
        assert_eq!(
            validate_run(&p).unwrap_err().to_string(),
            "-i/--stdin is required for containers with -t/--tty=true"
        );
    }

    #[test]
    fn run_privileged_pullpolicy_port_command() {
        let mut p = base();
        p.privileged = true;
        p.image_pull_policy = "Never".into();
        p.port = Some(80);
        p.command = true;
        p.args = vec!["sleep".into(), "1".into()];
        let c = &generate_pod(&p).unwrap()["spec"]["containers"][0];
        assert_eq!(c["securityContext"], json!({"privileged": true}));
        assert_eq!(c["imagePullPolicy"], "Never");
        assert_eq!(c["ports"], json!([{"containerPort": 80}]));
        assert_eq!(c["command"], json!(["sleep", "1"]));
        assert!(c.get("args").is_none());
    }

    #[test]
    fn run_resource_requirements() {
        let mut p = base();
        p.limits = "cpu=1,memory=1Gi".into();
        p.requests = "cpu=500m".into();
        let r = &generate_pod(&p).unwrap()["spec"]["containers"][0]["resources"];
        assert_eq!(r["limits"]["memory"], "1Gi");
        assert_eq!(r["requests"]["cpu"], "500m");
        p.limits = "cpu".into();
        assert_eq!(
            generate_pod(&p).unwrap_err().to_string(),
            "Invalid argument syntax cpu, expected <resource>=<value>"
        );
    }
}
