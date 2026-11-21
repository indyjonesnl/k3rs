//! Objects `k3rs server` applies once the control plane is up.
//!
//! Source: the all-in-one branch of `scripts/bootstrap-cluster.sh` (Step 5:
//! kube-dns EndpointSlice `kube-dns-k3rs`) and the kube-dns Service of
//! `bootstrap-cluster.yaml`. k3rs-dns runs in-process on the server
//! (`run_all_in_one` DNS task), so the Service has no selector and the slice
//! points at the node IP.
//!
//! Deliberately NOT created here because the api-server already seeds them
//! (`crates/api-server/src/startup.rs::register_post_start_hooks`): the
//! `kubernetes` Service + Endpoints (`bootstrap::bootstrap_kubernetes_service`),
//! the system Namespaces `kube-system`/`default`/`kube-public`/
//! `kube-node-lease` (`bootstrap_system_namespaces`, upstream
//! systemnamespaces controller) and the `system-node-critical` /
//! `system-cluster-critical` PriorityClasses
//! (`bootstrap_system_priority_classes`, upstream storage_scheduling.go).
//! `default` ServiceAccounts come from the serviceaccount controller.
//!
//! RBAC for the in-process DNS: a `system:k3rs-dns` ClusterRole + binding
//! to the DNS client identity (User `system:k3rs-dns`, `pki::COMPONENT_IDENTITIES`),
//! see [`DNS_CLUSTER_ROLE`].
//!
//! k3s comparison: manifests/coredns.yaml ships the same kube-dns Service
//! (ports dns/53 UDP, dns-tcp/53 TCP, labels `k8s-app`,
//! `kubernetes.io/cluster-service`) but with a `k8s-app: kube-dns` selector
//! backed by a CoreDNS Deployment; k3rs has no such pod.

use std::time::Duration;

use anyhow::{anyhow, Result};
use k3rs_api_server::registry::rbac::reconciliation::{
    compute_reconciled_role, compute_reconciled_role_binding, ReconcileOperation,
    AUTOUPDATE_ANNOTATION,
};
use k3rs_client::api_status;
use k3rs_client::http::{ApiClient, GetError};
use serde_json::{json, Value};

/// ClusterIP of `kube-dns` (bootstrap-cluster.yaml; `--cluster-dns`).
pub const KUBE_DNS_CLUSTER_IP: &str = "10.96.0.10";

/// Name of the ClusterRole (and its ClusterRoleBinding) for the embedded DNS.
pub const DNS_CLUSTER_ROLE: &str = "system:k3rs-dns";
/// The DNS client cert's CN (`pki::COMPONENT_IDENTITIES`, name `dns`).
pub const DNS_USER: &str = "system:k3rs-dns";

/// RBAC for the in-process DNS identity.
///
/// Deviation, cited: k3s grants CoreDNS the `system:coredns` ClusterRole
/// (list/watch `endpoints`, `services`, `pods`, `namespaces`, and
/// `discovery.k8s.io` `endpointslices`) bound to the ServiceAccount
/// `kube-system/coredns` (../k3s manifests/coredns.yaml:8-47). k3rs runs its DNS
/// in-process under a client cert (User `system:k3rs-dns`), so the binding
/// names that User, and the rules are narrowed to exactly what
/// `k3rs_dns::run_with_api` lists and watches (crates/dns/src/watcher.rs
/// `api_paths`: services, pods, endpointslices; no endpoints/namespaces).
/// The seeded upstream `system:kube-dns` role (list/watch endpoints and
/// services only, plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go)
/// does not cover pods or endpointslices, so it is not reused.
fn dns_rbac() -> Vec<BootstrapObject> {
    let labels = json!({"kubernetes.io/bootstrapping": "rbac-defaults"});
    let annotations = autoupdate();
    let role = json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": DNS_CLUSTER_ROLE, "labels": labels, "annotations": annotations},
        "rules": [
            {"apiGroups": [""], "resources": ["services", "pods"], "verbs": ["list", "watch"]},
            {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["list", "watch"]}
        ]
    });
    let binding = json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": DNS_CLUSTER_ROLE, "labels": labels, "annotations": annotations},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": DNS_CLUSTER_ROLE},
        "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": DNS_USER}]
    });
    vec![
        BootstrapObject {
            path: "/apis/rbac.authorization.k8s.io/v1/clusterroles".into(),
            name: DNS_CLUSTER_ROLE.into(),
            body: role,
        },
        BootstrapObject {
            path: "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings".into(),
            name: DNS_CLUSTER_ROLE.into(),
            body: binding,
        },
    ]
}

/// The annotations every bootstrap RBAC object carries
/// (`addClusterRoleLabel` / `addClusterRoleBindingLabel`,
/// plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go:157-175):
/// `rbac.authorization.kubernetes.io/autoupdate: "true"`. An admin opts an
/// object out of reconciliation by setting it to `"false"`.
fn autoupdate() -> Value {
    json!({AUTOUPDATE_ANNOTATION: "true"})
}

/// ClusterRole (and binding) for the controller-manager's k3rs-only Events
/// controller.
pub const EVENT_GC_CLUSTER_ROLE: &str = "system:k3rs-event-gc";

/// RBAC for the k3rs-only Events controller
/// (`crates/controller-manager/src/controllers/events.rs`).
///
/// Deviation, cited: upstream has no such controller, so there is no seeded
/// `system:controller:*` role to reuse. It runs under its own
/// ServiceAccount-style identity (`kube-system/event-gc-controller`,
/// `identities::EVENT_GC_SERVICE_ACCOUNT`), bound like the seeded controller
/// roles (`addControllerRole`, bootstrappolicy/controller_policy.go:34-51),
/// and the rules are exactly the core `events` verbs it uses: get (dedup /
/// `EventRecorder` lookup), create and update (`EventRecorder`
/// `create_with_ttl` / `update_with_ttl`), delete (the 1 h cleanup), list
/// and watch (its event watch and cleanup listing). No other resource; its
/// Pod listing goes through the controller-manager's root informer client.
fn event_gc_rbac() -> Vec<BootstrapObject> {
    let labels = json!({"kubernetes.io/bootstrapping": "rbac-defaults"});
    let annotations = autoupdate();
    let sa = k3rs_controller_manager::identities::EVENT_GC_SERVICE_ACCOUNT;
    let role = json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": EVENT_GC_CLUSTER_ROLE, "labels": labels, "annotations": annotations},
        "rules": [
            {"apiGroups": [""], "resources": ["events"],
             "verbs": ["create", "delete", "get", "list", "update", "watch"]}
        ]
    });
    let binding = json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": EVENT_GC_CLUSTER_ROLE, "labels": labels, "annotations": annotations},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": EVENT_GC_CLUSTER_ROLE},
        "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": "kube-system"}]
    });
    vec![
        BootstrapObject {
            path: "/apis/rbac.authorization.k8s.io/v1/clusterroles".into(),
            name: EVENT_GC_CLUSTER_ROLE.into(),
            body: role,
        },
        BootstrapObject {
            path: "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings".into(),
            name: EVENT_GC_CLUSTER_ROLE.into(),
            body: binding,
        },
    ]
}

/// How long `apply_all` keeps retrying while the api-server is not answering.
const APPLY_DEADLINE: Duration = Duration::from_secs(120);

/// One object to create: `POST {path}` with `body`, existence via
/// `GET {path}/{name}`.
#[derive(Debug, Clone, PartialEq)]
pub struct BootstrapObject {
    /// Collection path, e.g. `/api/v1/namespaces/kube-system/services`.
    pub path: String,
    pub name: String,
    pub body: Value,
}

/// The objects for a server whose node IP is `node_ip` (first address when a
/// dual-stack list is given).
pub fn objects(node_ip: &str) -> Vec<BootstrapObject> {
    let ip = node_ip.split(',').next().unwrap_or(node_ip).trim();
    let address_type = if ip.contains(':') { "IPv6" } else { "IPv4" };
    let service = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "kube-dns",
            "namespace": "kube-system",
            "labels": {
                "k8s-app": "kube-dns",
                "kubernetes.io/cluster-service": "true",
                "kubernetes.io/name": "k3rs-dns"
            }
        },
        "spec": {
            "clusterIP": KUBE_DNS_CLUSTER_IP,
            "ports": [
                {"name": "dns", "port": 53, "protocol": "UDP"},
                {"name": "dns-tcp", "port": 53, "protocol": "TCP"}
            ]
        }
    });
    let slice = json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": "kube-dns-k3rs",
            "namespace": "kube-system",
            "labels": {
                "kubernetes.io/service-name": "kube-dns",
                "endpointslice.kubernetes.io/managed-by": "k3rs"
            }
        },
        "addressType": address_type,
        "ports": [
            {"name": "dns", "port": 53, "protocol": "UDP"},
            {"name": "dns-tcp", "port": 53, "protocol": "TCP"}
        ],
        "endpoints": [{
            "addresses": [ip],
            "conditions": {"ready": true, "serving": true, "terminating": false}
        }]
    });
    let mut objs = dns_rbac();
    objs.extend(event_gc_rbac());
    objs.extend([
        BootstrapObject {
            path: "/api/v1/namespaces/kube-system/services".into(),
            name: "kube-dns".into(),
            body: service,
        },
        BootstrapObject {
            path: "/apis/discovery.k8s.io/v1/namespaces/kube-system/endpointslices".into(),
            name: "kube-dns-k3rs".into(),
            body: slice,
        },
    ]);
    objs
}

async fn apply_one(client: &ApiClient, o: &BootstrapObject) -> Result<()> {
    match o.body["kind"].as_str() {
        Some("ClusterRole" | "Role") => return reconcile_rbac(client, o, RbacKind::Role, 0).await,
        Some("ClusterRoleBinding" | "RoleBinding") => {
            return reconcile_rbac(client, o, RbacKind::Binding, 0).await
        }
        _ => {}
    }
    if client
        .resource_exists(&format!("{}/{}", o.path, o.name))
        .await?
    {
        return Ok(());
    }
    match client.post::<_, Value>(&o.path, &o.body).await {
        Ok(_) => Ok(()),
        // Lost a race with another creator: the object exists, never overwrite.
        Err(e) if api_status::is_already_exists(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RbacKind {
    Role,
    Binding,
}

/// `ReconcileRoleOptions.run` / `ReconcileRoleBindingOptions.run`
/// (staging/src/k8s.io/component-helpers/auth/rbac/reconciliation/
/// reconcile_role.go:101-176, reconcile_rolebindings.go:89-177) with
/// `Confirm: true` and no `RemoveExtra*`, as `ensureRBACPolicy` runs them for
/// the bootstrap policy (pkg/registry/rbac/rest/storage_rbac.go:207-260),
/// through the API like upstream's loopback clientset. The diff is the
/// api-server's own port (`registry::rbac::reconciliation`), shared with its
/// bootstrap-policy seeding:
///
/// - absent: create; AlreadyExists re-runs.
/// - present: add the missing rules / aggregation selectors / subjects and
///   the expected labels and annotations; rules or subjects an admin added
///   are kept (`computeReconciledRole`, `removeExtraPermissions == false`).
/// - `autoupdate: "false"`: left alone, with upstream's warning when it
///   lacks something (`result.Protected`, storage_rbac.go:221-222).
/// - binding with a different roleRef: delete (UID precondition) and
///   recreate; a precondition conflict re-runs.
/// - update hitting NotFound or Conflict re-runs from a fresh GET (upstream
///   re-runs on NotFound and wraps the whole run in `RetryOnConflict`).
///
/// Attempts are bounded like upstream (`attempts > 2` roles, `> 3` bindings).
fn reconcile_rbac<'a>(
    client: &'a ApiClient,
    o: &'a BootstrapObject,
    kind: RbacKind,
    attempts: u32,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let max = if kind == RbacKind::Role { 2 } else { 3 };
        if attempts > max {
            return Err(anyhow!("exceeded maximum attempts"));
        }
        let item = format!("{}/{}", o.path, o.name);
        let existing: Value = match client.get(&item).await {
            Ok(v) => v,
            Err(GetError::NotFound(_)) => {
                return match client.post::<_, Value>(&o.path, &o.body).await {
                    Ok(_) => {
                        tracing::info!("created {item}");
                        Ok(())
                    }
                    Err(e) if api_status::is_already_exists(&e) => {
                        reconcile_rbac(client, o, kind, attempts + 1).await
                    }
                    Err(e) => Err(e),
                };
            }
            Err(GetError::Other(e)) => return Err(e),
        };
        let result = match kind {
            RbacKind::Role => compute_reconciled_role(&existing, &o.body),
            RbacKind::Binding => compute_reconciled_role_binding(&existing, &o.body),
        };
        if result.protected {
            if result.operation != ReconcileOperation::None {
                tracing::warn!("skipped reconcile-protected {item} with missing permissions");
            }
            return Ok(());
        }
        match result.operation {
            ReconcileOperation::None => Ok(()),
            ReconcileOperation::Update => {
                match client.put::<_, Value>(&item, &result.object).await {
                    Ok(_) => {
                        tracing::info!("reconciled {item} with additional permissions");
                        Ok(())
                    }
                    Err(e) if api_status::is_not_found(&e) || api_status::is_conflict(&e) => {
                        reconcile_rbac(client, o, kind, attempts + 1).await
                    }
                    Err(e) => Err(e),
                }
            }
            ReconcileOperation::Recreate => {
                let uid = existing["metadata"]["uid"].as_str().unwrap_or_default();
                let opts = json!({"apiVersion": "v1", "kind": "DeleteOptions",
                                  "preconditions": {"uid": uid}});
                // `case err == nil, errors.IsNotFound(err)`: gone is what we
                // want (reconcile_rolebindings.go:128-131). `delete_with_options`
                // already maps a 404 to Ok; the arm keeps that explicit.
                match client.delete_with_options(&item, &[], Some(&opts)).await {
                    Ok(_) => {}
                    Err(e) if api_status::is_not_found(&e) => {}
                    Err(e) if api_status::is_conflict(&e) => {
                        return reconcile_rbac(client, o, kind, attempts + 1).await;
                    }
                    Err(e) => return Err(e),
                }
                match client.post::<_, Value>(&o.path, &result.object).await {
                    Ok(_) => {
                        tracing::info!("recreated {item} with a new roleRef");
                        Ok(())
                    }
                    Err(e) if api_status::is_already_exists(&e) => {
                        reconcile_rbac(client, o, kind, attempts + 1).await
                    }
                    Err(e) => Err(e),
                }
            }
        }
    })
}

/// Create each object that is absent; RBAC objects that exist are reconciled
/// (see [`reconcile_rbac`]), everything else is never overwritten. Retries
/// with backoff (250ms doubling to 5s) until the api-server answers, for at
/// most two minutes.
pub async fn apply_all(client: &ApiClient, objs: &[BootstrapObject]) -> Result<()> {
    apply_all_within(client, objs, APPLY_DEADLINE).await
}

async fn apply_all_within(
    client: &ApiClient,
    objs: &[BootstrapObject],
    deadline: Duration,
) -> Result<()> {
    let start = tokio::time::Instant::now();
    let mut delay = Duration::from_millis(250);
    for o in objs {
        loop {
            match apply_one(client, o).await {
                Ok(()) => break,
                Err(e) if start.elapsed() + delay >= deadline => {
                    return Err(anyhow!("bootstrap {}/{}: {e:#}", o.path, o.name));
                }
                Err(e) => {
                    tracing::debug!("bootstrap {}/{} not ready: {e:#}", o.path, o.name);
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{StatusCode, Uri},
        routing::any,
        Json, Router,
    };
    use std::sync::{Arc, Mutex};

    fn find<'a>(objs: &'a [BootstrapObject], name: &str) -> &'a BootstrapObject {
        objs.iter().find(|o| o.name == name).unwrap()
    }

    #[test]
    fn objects_contain_kube_dns_service_with_pinned_cluster_ip() {
        let objs = objects("192.0.2.10");
        let svc = find(&objs, "kube-dns");
        assert_eq!(svc.path, "/api/v1/namespaces/kube-system/services");
        assert_eq!(svc.body["spec"]["clusterIP"], "10.96.0.10");
        assert!(svc.body["spec"].get("selector").is_none());
        assert_eq!(svc.body["spec"]["ports"][0]["protocol"], "UDP");
        assert_eq!(svc.body["spec"]["ports"][1]["name"], "dns-tcp");
    }

    #[test]
    fn endpointslice_points_at_node_ip_port_53_both_protocols() {
        let objs = objects("192.0.2.10");
        let s = find(&objs, "kube-dns-k3rs");
        assert_eq!(
            s.body["metadata"]["labels"]["kubernetes.io/service-name"],
            "kube-dns"
        );
        assert_eq!(
            s.body["metadata"]["labels"]["endpointslice.kubernetes.io/managed-by"],
            "k3rs"
        );
        assert_eq!(s.body["endpoints"][0]["addresses"][0], "192.0.2.10");
        let ports = s.body["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 2);
        assert!(ports.iter().all(|p| p["port"] == 53));
        assert_eq!(ports[0]["protocol"], "UDP");
        assert_eq!(ports[1]["protocol"], "TCP");
    }

    type Posts = Arc<Mutex<Vec<String>>>;

    async fn serve(existing: Vec<String>) -> (String, Posts) {
        let posts: Posts = Arc::default();
        let st = (posts.clone(), Arc::new(existing));
        async fn h(
            State((posts, existing)): State<(Posts, Arc<Vec<String>>)>,
            method: axum::http::Method,
            uri: Uri,
        ) -> (StatusCode, Json<Value>) {
            if method == axum::http::Method::POST {
                posts.lock().unwrap().push(uri.path().to_string());
                (StatusCode::CREATED, Json(json!({})))
            } else if existing.iter().any(|e| e == uri.path()) {
                (StatusCode::OK, Json(json!({})))
            } else {
                (StatusCode::NOT_FOUND, Json(json!({})))
            }
        }
        let app = Router::new().fallback(any(h)).with_state(st);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, posts)
    }

    /// The binding names the DNS client cert's CN, and the rules are exactly
    /// the collections `k3rs_dns::run_with_api` lists and watches.
    #[test]
    fn dns_rbac_binds_the_dns_identity_to_what_it_reads() {
        assert!(crate::pki::COMPONENT_IDENTITIES
            .iter()
            .any(|i| i.name == "dns" && i.cn == DNS_USER && i.orgs.is_empty()));
        let objs = objects("192.0.2.10");
        let role = objs
            .iter()
            .find(|o| o.path.ends_with("/clusterroles"))
            .unwrap();
        assert_eq!(role.name, DNS_CLUSTER_ROLE);
        let rules = role.body["rules"].as_array().unwrap();
        let mut granted = Vec::new();
        for r in rules {
            assert_eq!(r["verbs"], json!(["list", "watch"]));
            for g in r["apiGroups"].as_array().unwrap() {
                for res in r["resources"].as_array().unwrap() {
                    granted.push(format!("{}/{}", g.as_str().unwrap(), res.as_str().unwrap()));
                }
            }
        }
        granted.sort();
        assert_eq!(
            granted,
            ["/pods", "/services", "discovery.k8s.io/endpointslices"]
        );
        for p in [
            k3rs_dns::watcher::api_paths::SERVICES,
            k3rs_dns::watcher::api_paths::PODS,
            k3rs_dns::watcher::api_paths::ENDPOINTSLICES,
        ] {
            let res = p.rsplit('/').next().unwrap();
            assert!(
                granted.iter().any(|g| g.ends_with(&format!("/{res}"))),
                "{p}"
            );
        }
        let binding = objs
            .iter()
            .find(|o| o.path.ends_with("/clusterrolebindings"))
            .unwrap();
        assert_eq!(binding.body["roleRef"]["name"], DNS_CLUSTER_ROLE);
        assert_eq!(
            binding.body["subjects"],
            json!([{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": DNS_USER}])
        );
    }

    /// The Events controller's k3rs-only role covers exactly core `events`
    /// with the verbs events.rs / EventRecorder use, bound to its
    /// ServiceAccount identity.
    #[test]
    fn event_gc_rbac_is_events_only_and_binds_the_controller_identity() {
        let objs = objects("192.0.2.10");
        let role = objs
            .iter()
            .find(|o| o.path.ends_with("/clusterroles") && o.name == EVENT_GC_CLUSTER_ROLE)
            .unwrap();
        assert_eq!(
            role.body["rules"],
            json!([{"apiGroups": [""], "resources": ["events"],
                "verbs": ["create", "delete", "get", "list", "update", "watch"]}])
        );
        let binding = objs
            .iter()
            .find(|o| o.path.ends_with("/clusterrolebindings") && o.name == EVENT_GC_CLUSTER_ROLE)
            .unwrap();
        assert_eq!(binding.body["roleRef"]["name"], EVENT_GC_CLUSTER_ROLE);
        assert_eq!(
            binding.body["subjects"],
            json!([{"kind": "ServiceAccount",
                "name": k3rs_controller_manager::identities::EVENT_GC_SERVICE_ACCOUNT,
                "namespace": "kube-system"}])
        );
    }

    #[tokio::test]
    async fn apply_all_skips_existing() {
        let objs = objects("192.0.2.10");
        let svc = find(&objs, "kube-dns");
        let (url, posts) = serve(vec![format!("{}/{}", svc.path, svc.name)]).await;
        let client = ApiClient::new(&url, false, None).unwrap();
        apply_all(&client, &objs).await.unwrap();
        let got = posts.lock().unwrap().clone();
        assert_eq!(
            got,
            vec![
                // DNS role + binding, Events-controller role + binding.
                "/apis/rbac.authorization.k8s.io/v1/clusterroles".to_string(),
                "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings".to_string(),
                "/apis/rbac.authorization.k8s.io/v1/clusterroles".to_string(),
                "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings".to_string(),
                "/apis/discovery.k8s.io/v1/namespaces/kube-system/endpointslices".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn apply_all_gives_up_when_api_never_answers() {
        let client = ApiClient::new("http://127.0.0.1:1", false, None).unwrap();
        let r = apply_all_within(&client, &objects("192.0.2.10"), Duration::from_millis(600)).await;
        assert!(r.is_err());
    }

    /// The binding was deleted by someone else between our GET and DELETE:
    /// a NotFound from the delete counts as success and the binding is
    /// recreated (`case err == nil, errors.IsNotFound(err)`,
    /// component-helpers/auth/rbac/reconciliation/reconcile_rolebindings.go:128-131).
    #[tokio::test]
    async fn recreate_treats_delete_not_found_as_deleted() {
        let calls: Posts = Arc::default();
        async fn h(
            State(calls): State<Posts>,
            method: axum::http::Method,
            uri: Uri,
        ) -> (StatusCode, Json<Value>) {
            calls
                .lock()
                .unwrap()
                .push(format!("{method} {}", uri.path()));
            match method.as_str() {
                "GET" => (
                    StatusCode::OK,
                    Json(json!({
                        "apiVersion": "rbac.authorization.k8s.io/v1",
                        "kind": "ClusterRoleBinding",
                        "metadata": {"name": DNS_CLUSTER_ROLE, "uid": "old-uid",
                                     "resourceVersion": "5"},
                        "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                                    "kind": "ClusterRole", "name": "view"},
                        "subjects": []
                    })),
                ),
                "DELETE" => (
                    StatusCode::NOT_FOUND,
                    Json(
                        json!({"apiVersion": "v1", "kind": "Status", "status": "Failure",
                                "reason": "NotFound", "code": 404}),
                    ),
                ),
                _ => (StatusCode::CREATED, Json(json!({}))),
            }
        }
        let app = Router::new().fallback(any(h)).with_state(calls.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let client = ApiClient::new(&url, false, None).unwrap();

        let binding = objects("192.0.2.10")
            .into_iter()
            .find(|o| o.path.ends_with("/clusterrolebindings") && o.name == DNS_CLUSTER_ROLE)
            .unwrap();
        reconcile_rbac(&client, &binding, RbacKind::Binding, 0)
            .await
            .unwrap();
        let path = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings";
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                format!("GET {path}/{DNS_CLUSTER_ROLE}"),
                format!("DELETE {path}/{DNS_CLUSTER_ROLE}"),
                format!("POST {path}"),
            ]
        );
    }
}
