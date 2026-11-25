//! Unit tests moved from `src/registry/apps/daemonset.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use kubernetes_rs_api_server::registry::generic::Store;
    pub use kubernetes_rs_api_server::registry::rest::{
        GarbageCollectionPolicy, GroupResource, NamespaceScopedStrategy, RequestContext,
        RestCreateStrategy, RestDeleteStrategy, RestUpdateStrategy,
    };
    pub use kubernetes_rs_api_server::ssa::ResetFields;
    pub use kubernetes_rs_common::equality::semantic_equal;
    pub use kubernetes_rs_common::resources::{DaemonSet, DaemonSetStatus};
    pub use kubernetes_rs_common::validation::apps::{
        validate_daemonset, validate_daemonset_status_update, validate_daemonset_update,
    };
    pub use kubernetes_rs_common::validation::field::ErrorList;
    pub use kubernetes_rs_storage::StorageBackend;
    pub use std::sync::Arc;
}

mod tests {
    use super::__parent::*;
    use kubernetes_rs_api_server::registry::apps::daemonset::*;
    use std::collections::HashMap;

    fn daemon_set() -> DaemonSet {
        let mut ds: DaemonSet = serde_json::from_value(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "DaemonSet",
            "metadata": {"name": "d", "namespace": "default", "generation": 4, "resourceVersion": "1"},
            "spec": {
                "selector": {"matchLabels": {"app": "d"}},
                "template": {
                    "metadata": {"labels": {"app": "d"}},
                    "spec": {"containers": [{"name": "c", "image": "i"}]}
                }
            },
            "status": {"desiredNumberScheduled": 2, "currentNumberScheduled": 2,
                       "numberReady": 1, "numberMisscheduled": 0}
        }))
        .unwrap();
        convert_to_internal(&mut ds);
        ds.set_template_generation(3);
        ds
    }

    fn ctx() -> RequestContext {
        RequestContext::new(Some("default"))
    }

    #[test]
    fn strategy_flags_match_upstream() {
        assert!(Strategy.namespace_scoped());
        assert!(!Strategy.allow_create_on_update());
        assert!(Strategy.allow_unconditional_update());
        assert_eq!(
            Strategy.default_garbage_collection_policy(&ctx()),
            Some(GarbageCollectionPolicy::DeleteDependents)
        );
        assert!(!StatusStrategy.allow_create_on_update());
        assert!(StatusStrategy.allow_unconditional_update());
    }

    #[test]
    fn prepare_for_create_resets_status_and_seeds_generations() {
        let mut ds = daemon_set();
        ds.metadata.annotations = None;
        Strategy.prepare_for_create(&ctx(), &mut ds);
        assert_eq!(ds.status, Some(DaemonSetStatus::default()));
        assert_eq!(ds.metadata.generation, Some(1));
        assert_eq!(ds.template_generation(), 1);

        // A template generation the client supplied above 1 is kept.
        let mut ds = daemon_set();
        Strategy.prepare_for_create(&ctx(), &mut ds);
        assert_eq!(ds.template_generation(), 3);
    }

    #[test]
    fn prepare_for_update_bumps_generations_by_what_changed() {
        let old = daemon_set();

        // Metadata only: nothing moves, and status and the template generation
        // the client dropped are restored.
        let mut annotated = old.clone();
        annotated.status = None;
        annotated.metadata.annotations = Some(HashMap::from([("a".into(), "1".into())]));
        Strategy.prepare_for_update(&ctx(), &mut annotated, &old);
        assert_eq!(annotated.status, old.status);
        assert_eq!(annotated.metadata.generation, Some(4));
        assert_eq!(annotated.template_generation(), 3);

        // A client cannot set the template generation itself.
        let mut forged = old.clone();
        forged.set_template_generation(9);
        Strategy.prepare_for_update(&ctx(), &mut forged, &old);
        assert_eq!(forged.template_generation(), 3);
        assert_eq!(forged.metadata.generation, Some(4));

        // A non-template spec change: the generation only.
        let mut slower = old.clone();
        slower.spec.min_ready_seconds = Some(5);
        Strategy.prepare_for_update(&ctx(), &mut slower, &old);
        assert_eq!(slower.metadata.generation, Some(5));
        assert_eq!(slower.template_generation(), 3);

        // A template change: both.
        let mut reimaged = old.clone();
        reimaged.spec.template.spec.containers[0].image = "j".into();
        Strategy.prepare_for_update(&ctx(), &mut reimaged, &old);
        assert_eq!(reimaged.metadata.generation, Some(5));
        assert_eq!(reimaged.template_generation(), 4);
        let errs = Strategy.validate_update(&ctx(), &reimaged, &old);
        assert!(errs.is_empty(), "{errs:?}");
    }

    #[test]
    fn status_prepare_for_update_keeps_spec_and_template_generation() {
        let old = daemon_set();
        let mut new = old.clone();
        new.spec.min_ready_seconds = Some(9);
        new.metadata.annotations = None;
        new.metadata.labels = Some(HashMap::from([("l".into(), "new".into())]));
        new.status = Some(DaemonSetStatus {
            number_ready: 2,
            ..DaemonSetStatus::default()
        });
        StatusStrategy.prepare_for_update(&ctx(), &mut new, &old);
        assert_eq!(new.spec.min_ready_seconds, old.spec.min_ready_seconds);
        assert_eq!(new.template_generation(), 3);
        assert_eq!(new.metadata.labels.unwrap()["l"], "new");
        assert_eq!(new.status.unwrap().number_ready, 2);
    }

    fn with_template_node_selector(o: &mut DaemonSet) {
        o.spec.template.spec.node_selector = Some(HashMap::from([(
            "beta.kubernetes.io/os".to_string(),
            "linux".to_string(),
        )]));
    }

    /// `GetWarningsForPodTemplate` on create, rooted at `spec.template`.
    #[test]
    fn create_warns_about_the_pod_template() {
        let mut o = daemon_set();
        assert!(Strategy
            .warnings_on_create(&ctx(), &o)
            .iter()
            .all(|w| !w.contains("nodeSelector")));
        with_template_node_selector(&mut o);
        let warnings = Strategy.warnings_on_create(&ctx(), &o);
        assert!(warnings.contains(&r#"spec.template.spec.nodeSelector[beta.kubernetes.io/os]: deprecated since v1.14; use "kubernetes.io/os" instead"#.to_string()), "{warnings:?}");
    }

    /// Only a changed generation re-evaluates the template. Here that is `spec.templateGeneration` (strategy.go:155).
    #[test]
    fn update_warns_only_when_the_generation_changed() {
        let old = daemon_set();
        let mut new = old.clone();

        with_template_node_selector(&mut new);
        assert!(Strategy.warnings_on_update(&ctx(), &new, &old).is_empty());
        new.set_template_generation(old.template_generation() + 1);
        let warnings = Strategy.warnings_on_update(&ctx(), &new, &old);
        assert_eq!(warnings, vec![r#"spec.template.spec.nodeSelector[beta.kubernetes.io/os]: deprecated since v1.14; use "kubernetes.io/os" instead"#.to_string()]);
    }
}
