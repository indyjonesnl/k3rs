//! Unit tests moved from `src/registry/core/podtemplate.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use kubernetes_rs_api_server::registry::generic::Store;
    pub use kubernetes_rs_api_server::registry::rest::{
        GroupResource, NamespaceScopedStrategy, RequestContext, RestCreateStrategy,
        RestDeleteStrategy, RestUpdateStrategy,
    };
    pub use kubernetes_rs_common::equality::semantic_equal;
    pub use kubernetes_rs_common::resources::PodTemplate;
    pub use kubernetes_rs_common::validation::field::ErrorList;
    pub use kubernetes_rs_common::validation::podtemplate::{
        validate_pod_template, validate_pod_template_update,
    };
    pub use kubernetes_rs_storage::StorageBackend;
    pub use std::sync::Arc;
}

mod tests {
    use super::__parent::*;
    use kubernetes_rs_api_server::registry::core::podtemplate::*;
    use std::collections::HashMap;

    fn pod_template() -> PodTemplate {
        let mut pt: PodTemplate = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "PodTemplate",
            "metadata": {"name": "t", "namespace": "default", "generation": 3,
                         "resourceVersion": "1"},
            "template": {
                "metadata": {"labels": {"app": "t"}},
                "spec": {"containers": [{"name": "c", "image": "i"}]}
            }
        }))
        .unwrap();
        convert_to_internal(&mut pt);
        pt
    }

    fn ctx() -> RequestContext {
        RequestContext::new(Some("default"))
    }

    #[test]
    fn strategy_flags_match_upstream() {
        assert!(Strategy.namespace_scoped());
        assert!(!Strategy.allow_create_on_update());
        assert!(Strategy.allow_unconditional_update());
        assert!(Strategy.default_garbage_collection_policy(&ctx()).is_none());
    }

    #[test]
    fn prepare_for_create_starts_the_generation_at_one() {
        let mut pt = pod_template();
        Strategy.prepare_for_create(&ctx(), &mut pt);
        assert_eq!(pt.metadata.generation, Some(1));
        let errs = Strategy.validate(&ctx(), &pt);
        assert!(errs.is_empty(), "{errs:?}");
    }

    /// `TestStrategy` (strategy_test.go): only a template change bumps.
    #[test]
    fn prepare_for_update_bumps_generation_on_template_change() {
        let old = pod_template();
        let mut labelled = old.clone();
        labelled.metadata.labels = Some([("l".to_string(), "v".to_string())].into());
        Strategy.prepare_for_update(&ctx(), &mut labelled, &old);
        assert_eq!(labelled.metadata.generation, Some(3));

        let mut reimaged = old.clone();
        reimaged.template.spec.containers[0].image = "j".into();
        Strategy.prepare_for_update(&ctx(), &mut reimaged, &old);
        assert_eq!(reimaged.metadata.generation, Some(4));
        let errs = Strategy.validate_update(&ctx(), &reimaged, &old);
        assert!(errs.is_empty(), "{errs:?}");
    }

    fn with_template_node_selector(o: &mut PodTemplate) {
        o.template.spec.node_selector = Some(HashMap::from([(
            "beta.kubernetes.io/os".to_string(),
            "linux".to_string(),
        )]));
    }

    /// `GetWarningsForPodTemplate` on create, rooted at `template`.
    #[test]
    fn create_warns_about_the_pod_template() {
        let mut o = pod_template();
        assert!(Strategy
            .warnings_on_create(&ctx(), &o)
            .iter()
            .all(|w| !w.contains("nodeSelector")));
        with_template_node_selector(&mut o);
        let warnings = Strategy.warnings_on_create(&ctx(), &o);
        assert!(warnings.contains(&r#"template.spec.nodeSelector[beta.kubernetes.io/os]: deprecated since v1.14; use "kubernetes.io/os" instead"#.to_string()), "{warnings:?}");
    }

    /// Only a changed generation re-evaluates the template.
    #[test]
    fn update_warns_only_when_the_generation_changed() {
        let old = pod_template();
        let mut new = old.clone();

        with_template_node_selector(&mut new);
        assert!(Strategy.warnings_on_update(&ctx(), &new, &old).is_empty());
        new.metadata.generation = Some(old.metadata.generation.unwrap() + 1);
        let warnings = Strategy.warnings_on_update(&ctx(), &new, &old);
        assert_eq!(warnings, vec![r#"template.spec.nodeSelector[beta.kubernetes.io/os]: deprecated since v1.14; use "kubernetes.io/os" instead"#.to_string()]);
    }
}
