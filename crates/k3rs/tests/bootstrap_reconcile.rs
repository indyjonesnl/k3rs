//! `k3rs server`'s own RBAC objects (`system:k3rs-dns`, `system:k3rs-event-gc`)
//! are reconciled on every start, like upstream's bootstrap policy
//! (`ensureRBACPolicy`, pkg/registry/rbac/rest/storage_rbac.go:183-331, over
//! component-helpers/auth/rbac/reconciliation): missing rules and subjects are
//! added, admin-added ones kept, `autoupdate: "false"` opts out, and a binding
//! whose roleRef changed is recreated.
//!
//! Run with `cargo nextest run -p k3rs --test bootstrap_reconcile`.

mod common;

use common::{apply_bootstrap, boot};
use k3rs::bootstrap::{DNS_CLUSTER_ROLE, EVENT_GC_CLUSTER_ROLE};
use serde_json::{json, Value};

const ROLES: &str = "/apis/rbac.authorization.k8s.io/v1/clusterroles";
const BINDINGS: &str = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings";
const AUTOUPDATE: &str = "rbac.authorization.kubernetes.io/autoupdate";

fn grants(role: &Value, group: &str, resource: &str, verb: &str) -> bool {
    role["rules"].as_array().unwrap().iter().any(|r| {
        let has = |f: &str, v: &str| {
            r[f].as_array()
                .is_some_and(|a| a.iter().any(|x| x == v || x == "*"))
        };
        has("apiGroups", group) && has("resources", resource) && has("verbs", verb)
    })
}

/// resourceVersion of each k3rs-managed role and binding.
async fn resource_versions(admin: &k3rs_client::http::ApiClient) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for coll in [ROLES, BINDINGS] {
        for name in [DNS_CLUSTER_ROLE, EVENT_GC_CLUSTER_ROLE] {
            let o: Value = admin.get(&format!("{coll}/{name}")).await.unwrap();
            out.push((
                format!("{coll}/{name}"),
                o["metadata"]["resourceVersion"].clone(),
            ));
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_k3rs_rbac_is_reconciled_like_bootstrap_policy() {
    let e = boot().await;
    let creds = e.pki.ensure_component_creds("n1", "127.0.0.1").unwrap();
    let admin =
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig("admin"), Some(&e.base)).unwrap();

    // A cluster from an older k3rs: the DNS role lacks rules the current
    // release needs, and an admin added a rule of their own.
    let _: Value = admin
        .post(
            ROLES,
            &json!({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": {"name": DNS_CLUSTER_ROLE},
            "rules": [
                {"apiGroups": [""], "resources": ["services"], "verbs": ["list", "watch"]},
                {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}
            ]}),
        )
        .await
        .unwrap();
    // The DNS binding points at another role (roleRef is immutable) and has
    // an extra subject.
    let old_binding: Value = admin
        .post(
            BINDINGS,
            &json!({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                    "metadata": {"name": DNS_CLUSTER_ROLE},
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                                "kind": "ClusterRole", "name": "view"},
                    "subjects": [{"apiGroup": "rbac.authorization.k8s.io",
                                  "kind": "User", "name": "someone-else"}]}),
        )
        .await
        .unwrap();
    // The event-gc role was opted out of reconciliation.
    let _: Value = admin
        .post(
            ROLES,
            &json!({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                    "metadata": {"name": EVENT_GC_CLUSTER_ROLE,
                                 "annotations": {AUTOUPDATE: "false"}},
                    "rules": [{"apiGroups": [""], "resources": ["events"], "verbs": ["get"]}]}),
        )
        .await
        .unwrap();

    apply_bootstrap(&e, &creds).await;
    let versions = resource_versions(&admin).await;
    // A second start is a no-op: every object keeps its resourceVersion
    // (`ReconcileNone` writes nothing).
    apply_bootstrap(&e, &creds).await;
    assert_eq!(resource_versions(&admin).await, versions);

    let dns: Value = admin
        .get(&format!("{ROLES}/{DNS_CLUSTER_ROLE}"))
        .await
        .unwrap();
    assert!(
        grants(&dns, "", "pods", "watch"),
        "missing rule added: {dns}"
    );
    assert!(
        grants(&dns, "discovery.k8s.io", "endpointslices", "list"),
        "{dns}"
    );
    assert!(
        grants(&dns, "", "configmaps", "get"),
        "admin-added rule kept: {dns}"
    );
    assert_eq!(dns["metadata"]["annotations"][AUTOUPDATE], "true");
    assert_eq!(
        dns["metadata"]["labels"]["kubernetes.io/bootstrapping"],
        "rbac-defaults"
    );

    let binding: Value = admin
        .get(&format!("{BINDINGS}/{DNS_CLUSTER_ROLE}"))
        .await
        .unwrap();
    assert_eq!(binding["roleRef"]["name"], DNS_CLUSTER_ROLE, "{binding}");
    assert_eq!(
        binding["subjects"],
        json!([{"apiGroup": "rbac.authorization.k8s.io", "kind": "User",
                "name": k3rs::bootstrap::DNS_USER}])
    );
    assert_ne!(
        binding["metadata"]["uid"], old_binding["metadata"]["uid"],
        "roleRef change recreates the binding"
    );

    let ev: Value = admin
        .get(&format!("{ROLES}/{EVENT_GC_CLUSTER_ROLE}"))
        .await
        .unwrap();
    assert_eq!(
        ev["rules"],
        json!([{"apiGroups": [""], "resources": ["events"], "verbs": ["get"]}]),
        "autoupdate=false is left alone"
    );
    assert_eq!(ev["metadata"]["annotations"][AUTOUPDATE], "false");

    // Absent objects are still created.
    let ev_binding: Value = admin
        .get(&format!("{BINDINGS}/{EVENT_GC_CLUSTER_ROLE}"))
        .await
        .unwrap();
    assert_eq!(ev_binding["roleRef"]["name"], EVENT_GC_CLUSTER_ROLE);
}

/// A binding opted out with `autoupdate: "false"` is protected even when its
/// roleRef differs: it is neither recreated nor changed
/// (`result.Protected` short-circuits before `ReconcileRecreate`,
/// component-helpers/auth/rbac/reconciliation/reconcile_rolebindings.go:116-119).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_binding_with_other_role_ref_is_not_recreated() {
    let e = boot().await;
    let creds = e.pki.ensure_component_creds("n1", "127.0.0.1").unwrap();
    let admin =
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig("admin"), Some(&e.base)).unwrap();
    let old: Value = admin
        .post(
            BINDINGS,
            &json!({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                    "metadata": {"name": DNS_CLUSTER_ROLE,
                                 "annotations": {AUTOUPDATE: "false"}},
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                                "kind": "ClusterRole", "name": "view"},
                    "subjects": [{"apiGroup": "rbac.authorization.k8s.io",
                                  "kind": "User", "name": "someone-else"}]}),
        )
        .await
        .unwrap();

    apply_bootstrap(&e, &creds).await;

    let got: Value = admin
        .get(&format!("{BINDINGS}/{DNS_CLUSTER_ROLE}"))
        .await
        .unwrap();
    assert_eq!(
        got["metadata"]["uid"], old["metadata"]["uid"],
        "not recreated"
    );
    assert_eq!(
        got["metadata"]["resourceVersion"], old["metadata"]["resourceVersion"],
        "not updated"
    );
    assert_eq!(got["roleRef"]["name"], "view");
    assert_eq!(got["subjects"], old["subjects"]);
}
