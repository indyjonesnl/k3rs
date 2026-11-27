//! Unit tests for `src/commands/create_common.rs`, ported from kubectl
//! `create.go` / `pkg/cmd/util/helpers.go` / cli-runtime name printer
//! (release-1.35).

mod tests {
    use kubernetes_rs_kubectl::commands::apply::LAST_APPLIED_ANNOTATION;
    use kubernetes_rs_kubectl::commands::create::build_deployment;
    use kubernetes_rs_kubectl::commands::create_common::*;
    use serde_json::json;

    #[test]
    fn create_common_dry_run_strategy() {
        for (flag, want) in [
            ("none", DryRunStrategy::None),
            ("client", DryRunStrategy::Client),
            ("server", DryRunStrategy::Server),
            (DRY_RUN_NO_OPT_DEF_VAL, DryRunStrategy::Client),
            ("true", DryRunStrategy::Client),
            ("1", DryRunStrategy::Client),
            ("false", DryRunStrategy::None),
            ("F", DryRunStrategy::None),
        ] {
            assert_eq!(get_dry_run_strategy(flag).unwrap(), want, "{flag}");
        }
        let e = get_dry_run_strategy("bogus").unwrap_err();
        assert_eq!(
            e.to_string(),
            "Invalid dry-run value (bogus). Must be \"none\", \"server\", or \"client\"."
        );
    }

    #[test]
    fn create_common_validation_directive() {
        for (flag, want) in [
            ("strict", "Strict"),
            ("true", "Strict"),
            ("warn", "Warn"),
            ("ignore", "Ignore"),
            ("false", "Ignore"),
        ] {
            assert_eq!(get_validation_directive(flag).unwrap(), want, "{flag}");
        }
        let e = get_validation_directive("loose").unwrap_err();
        assert!(e
            .to_string()
            .starts_with("invalid - validate option \"loose\""));
    }

    #[test]
    fn create_common_query() {
        assert_eq!(create_query("", "", DryRunStrategy::None), "");
        assert_eq!(
            create_query("kubectl-create", "Strict", DryRunStrategy::Server),
            "?fieldManager=kubectl-create&fieldValidation=Strict&dryRun=All"
        );
        // client dry-run never reaches the server, so it adds no dryRun
        assert_eq!(
            create_query("a b", "Warn", DryRunStrategy::Client),
            "?fieldManager=a%20b&fieldValidation=Warn"
        );
    }

    #[test]
    fn create_common_save_config_annotation() {
        let mut o = build_deployment("web", "default", "nginx", 1, None);
        create_or_update_annotation(false, &mut o);
        assert!(o.pointer("/metadata/annotations").is_none());

        create_or_update_annotation(true, &mut o);
        let ann = o["metadata"]["annotations"][LAST_APPLIED_ANNOTATION]
            .as_str()
            .unwrap()
            .to_string();
        let saved: serde_json::Value = serde_json::from_str(&ann).unwrap();
        assert_eq!(saved["metadata"]["name"], "web");
        assert!(saved.pointer("/metadata/annotations").is_none());

        // updateApplyAnnotation: an existing annotation is refreshed
        o["spec"]["replicas"] = json!(3);
        create_or_update_annotation(false, &mut o);
        let ann = o["metadata"]["annotations"][LAST_APPLIED_ANNOTATION]
            .as_str()
            .unwrap();
        let saved: serde_json::Value = serde_json::from_str(ann).unwrap();
        assert_eq!(saved["spec"]["replicas"], 3);
    }

    #[test]
    fn create_common_print_name_and_default() {
        let dep = build_deployment("web", "default", "nginx", 1, None);
        assert_eq!(
            print_obj(&dep, "", DryRunStrategy::None).unwrap(),
            "deployment.apps/web created\n"
        );
        assert_eq!(
            print_obj(&dep, "", DryRunStrategy::Client).unwrap(),
            "deployment.apps/web created (dry run)\n"
        );
        assert_eq!(
            print_obj(&dep, "", DryRunStrategy::Server).unwrap(),
            "deployment.apps/web created (server dry run)\n"
        );
        // -o name is short output: no operation text
        assert_eq!(
            print_obj(&dep, "name", DryRunStrategy::Client).unwrap(),
            "deployment.apps/web\n"
        );
        // core group has no ".group"
        let ns = json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "n"}});
        assert_eq!(
            print_obj(&ns, "", DryRunStrategy::None).unwrap(),
            "namespace/n created\n"
        );
    }

    #[test]
    fn create_common_print_json_yaml_omits_managed_fields() {
        let mut dep = build_deployment("web", "default", "nginx", 2, Some(80));
        dep["metadata"]["managedFields"] = json!([{"manager": "x"}]);
        let y = print_obj(&dep, "yaml", DryRunStrategy::Client).unwrap();
        assert!(
            y.starts_with("apiVersion: apps/v1\nkind: Deployment\n"),
            "{y}"
        );
        assert!(!y.contains("managedFields"));
        let j = print_obj(&dep, "JSON", DryRunStrategy::Client).unwrap();
        assert!(j.ends_with("}\n"));
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["spec"]["replicas"], 2);
        assert!(v["metadata"].get("managedFields").is_none());
    }

    #[test]
    fn create_common_print_rejects_bad_input() {
        let dep = build_deployment("web", "default", "nginx", 1, None);
        assert!(print_obj(&dep, "jsonpath", DryRunStrategy::None).is_err());
        let e = print_obj(
            &json!({"metadata": {"name": "x"}}),
            "",
            DryRunStrategy::None,
        )
        .unwrap_err();
        assert!(e.to_string().starts_with("missing apiVersion or kind"));
        let e = print_obj(&json!({"apiVersion": "v1"}), "", DryRunStrategy::None).unwrap_err();
        assert_eq!(
            e.to_string(),
            "missing kind for resource with name <unknown>"
        );
    }
}
