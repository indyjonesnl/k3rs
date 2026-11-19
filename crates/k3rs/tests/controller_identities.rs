//! Task 6b: the controller-manager's per-controller identities
//! (`--use-service-account-credentials`, k3s `pkg/daemons/control/server.go:124`)
//! against a real in-process api-server with Node,RBAC and the seeded
//! bootstrap policy.
//!
//! Each controller presents the client cert `Pki::ensure_component_creds`
//! minted for its upstream ServiceAccount (CN
//! `system:serviceaccount:kube-system:<sa>`, O `system:serviceaccounts`,
//! `system:serviceaccounts:kube-system`), so the seeded
//! `system:controller:<sa>` ClusterRoleBinding, whose subject is the
//! ServiceAccount `kube-system/<sa>`, applies: RBAC matches a ServiceAccount
//! subject by user name (`appliesToUser`,
//! plugin/pkg/auth/authorizer/rbac/rbac.go, `serviceaccount.MatchesUsername`).
//!
//! One process per test under nextest (the api-server keeps process-global
//! state): `cargo nextest run -p k3rs --test controller_identities`.

mod common;

use common::{apply_bootstrap, boot_with, client_from_files, send, status, Env};
use k3rs::pki::{controller_cred_name, ComponentCreds};
use k3rs_controller_manager::identities::{
    controller_identity, controller_service_accounts, ControllerIdentity, CONTROLLER_IDENTITIES,
};
use reqwest::Method;
use serde_json::json;

fn sa_client(e: &Env, creds: &ComponentCreds, sa: &str) -> reqwest::Client {
    let n = controller_cred_name(sa);
    client_from_files(&e.pki, &creds.cert(&n), &creds.key(&n))
}

async fn setup() -> (Env, ComponentCreds) {
    let e = boot_with(false).await;
    let creds = e.pki.ensure_component_creds("n2", "192.0.2.2").unwrap();
    (e, creds)
}

/// Upstream's feature-gated controller roles
/// (`crates/api-server/src/bootstrap.rs` `apply_feature_gated_policy`): absent
/// when their gate is off, as the controllers themselves are then not spawned.
const GATED: &[&str] = &[
    "device-taint-eviction-controller",
    "kube-apiserver-serving-clustertrustbundle-publisher",
    "podcertificaterequestcleaner",
    "storage-version-garbage-collector",
];

/// Every ServiceAccount the table maps a controller to has a seeded binding
/// whose subject is exactly that ServiceAccount (`addControllerRole`,
/// bootstrappolicy/controller_policy.go:34-51; the bootstrap-signer and
/// token-cleaner Roles are namespaced, namespace_policy.go).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_controller_service_account_has_a_seeded_binding() {
    let (e, creds) = setup().await;
    let admin = client_from_files(&e.pki, &creds.cert("admin"), &creds.key("admin"));
    for sa in controller_service_accounts() {
        let url = match sa {
            "bootstrap-signer" => format!(
                "{}/apis/rbac.authorization.k8s.io/v1/namespaces/kube-public/rolebindings/system:controller:{sa}",
                e.base
            ),
            "token-cleaner" => format!(
                "{}/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/rolebindings/system:controller:{sa}",
                e.base
            ),
            // k3rs-only (no upstream role): bound by k3rs bootstrap, below.
            k3rs_controller_manager::identities::EVENT_GC_SERVICE_ACCOUNT => continue,
            _ => format!(
                "{}/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system:controller:{sa}",
                e.base
            ),
        };
        let r = admin.get(&url).send().await.unwrap();
        if r.status() == 404 && GATED.contains(&sa) {
            continue;
        }
        assert_eq!(r.status(), 200, "{sa}: {url}");
        let b: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            b["roleRef"]["name"],
            format!("system:controller:{sa}"),
            "{sa}"
        );
        assert_eq!(
            b["subjects"],
            json!([{"kind": "ServiceAccount", "name": sa, "namespace": "kube-system"}]),
            "{sa}"
        );
    }
}

/// replicaset-controller creates pods (system:controller:replicaset-controller:
/// `create` pods) but cannot read Secrets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replicaset_controller_creates_pods_but_not_secrets() {
    let (e, creds) = setup().await;
    assert_eq!(
        controller_identity("ReplicaSet"),
        Some(ControllerIdentity::ServiceAccount("replicaset-controller"))
    );
    let admin = client_from_files(&e.pki, &creds.cert("admin"), &creds.key("admin"));
    let sa = json!({"apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"name": "default", "namespace": "default"}});
    let s = send(
        &admin,
        Method::POST,
        format!("{}/api/v1/namespaces/default/serviceaccounts", e.base),
        Some(sa),
    )
    .await;
    assert!(s == 201 || s == 409, "default SA -> {s}");
    let rs = sa_client(&e, &creds, "replicaset-controller");
    let pod = json!({"apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "p", "namespace": "default"},
        "spec": {"automountServiceAccountToken": false,
                 "containers": [{"name": "c", "image": "busybox"}]}});
    assert_eq!(
        send(
            &rs,
            Method::POST,
            format!("{}/api/v1/namespaces/default/pods", e.base),
            Some(pod)
        )
        .await,
        201
    );
    for p in [
        "/api/v1/namespaces/kube-system/secrets",
        "/api/v1/namespaces/kube-system/secrets/x",
    ] {
        assert_eq!(status(&rs, format!("{}{p}", e.base)).await, 403, "{p}");
    }
}

/// The api-server sees a controller cert exactly as upstream sees the
/// ServiceAccount: user `system:serviceaccount:kube-system:<sa>`, groups
/// `system:serviceaccounts`, `system:serviceaccounts:kube-system`,
/// `system:authenticated` (SelfSubjectReview, authentication.k8s.io/v1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_cert_authenticates_as_the_service_account() {
    let (e, creds) = setup().await;
    let c = sa_client(&e, &creds, "replicaset-controller");
    let r = c
        .post(format!(
            "{}/apis/authentication.k8s.io/v1/selfsubjectreviews",
            e.base
        ))
        .json(&json!({"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let b: serde_json::Value = r.json().await.unwrap();
    let ui = &b["status"]["userInfo"];
    assert_eq!(
        ui["username"],
        "system:serviceaccount:kube-system:replicaset-controller"
    );
    let mut groups: Vec<&str> = ui["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap())
        .collect();
    groups.sort();
    assert_eq!(
        groups,
        [
            "system:authenticated",
            "system:serviceaccounts",
            "system:serviceaccounts:kube-system"
        ]
    );
}

/// endpointslice-controller creates EndpointSlices.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn endpointslice_controller_creates_endpointslices() {
    let (e, creds) = setup().await;
    let c = sa_client(&e, &creds, "endpointslice-controller");
    let slice = json!({"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
        "metadata": {"name": "s1", "namespace": "default",
                     "labels": {"kubernetes.io/service-name": "x",
                                "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"}},
        "addressType": "IPv4", "endpoints": [], "ports": []});
    assert_eq!(
        send(
            &c,
            Method::POST,
            format!(
                "{}/apis/discovery.k8s.io/v1/namespaces/default/endpointslices",
                e.base
            ),
            Some(slice)
        )
        .await,
        201
    );
    assert_eq!(status(&c, format!("{}/api/v1/secrets", e.base)).await, 403);
}

/// namespace-controller finalizes and deletes namespaces
/// (`update` namespaces/finalize, `delete` on everything).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn namespace_controller_finalizes_and_deletes_namespaces() {
    let (e, creds) = setup().await;
    let admin = client_from_files(&e.pki, &creds.cert("admin"), &creds.key("admin"));
    let ns = json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "doomed"}});
    assert_eq!(
        send(
            &admin,
            Method::POST,
            format!("{}/api/v1/namespaces", e.base),
            Some(ns)
        )
        .await,
        201
    );
    let c = sa_client(&e, &creds, "namespace-controller");
    let r = c
        .get(format!("{}/api/v1/namespaces/doomed", e.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let mut ns: serde_json::Value = r.json().await.unwrap();
    ns["spec"]["finalizers"] = json!([]);
    assert_eq!(
        send(
            &c,
            Method::PUT,
            format!("{}/api/v1/namespaces/doomed/finalize", e.base),
            Some(ns)
        )
        .await,
        200
    );
    let s = send(
        &c,
        Method::DELETE,
        format!("{}/api/v1/namespaces/doomed", e.base),
        None,
    )
    .await;
    assert!(s == 200 || s == 202, "delete namespace -> {s}");
    // Not a namespace creator.
    let ns = json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "other"}});
    assert_eq!(
        send(
            &c,
            Method::POST,
            format!("{}/api/v1/namespaces", e.base),
            Some(ns)
        )
        .await,
        403
    );
}

/// node-controller (node IPAM and lifecycle share it upstream, core.go:156,
/// :190, :232) patches a Node and its status, the writes
/// `node_ipam.rs` (`patch_strategic_merge`) and the lifecycle controller make.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_controller_patches_nodes_and_status() {
    let (e, creds) = setup().await;
    let c = sa_client(&e, &creds, "node-controller");
    let patch = |url: String, body: serde_json::Value| {
        let c = c.clone();
        async move {
            c.patch(url)
                .header("Content-Type", "application/strategic-merge-patch+json")
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(
        patch(
            format!("{}/api/v1/nodes/n2", e.base),
            json!({"spec": {"podCIDR": "10.42.0.0/24", "podCIDRs": ["10.42.0.0/24"]}})
        )
        .await,
        200
    );
    assert_eq!(
        patch(
            format!("{}/api/v1/nodes/n2/status", e.base),
            json!({"status": {"conditions": [{"type": "Ready", "status": "Unknown"}]}})
        )
        .await,
        200
    );
    assert_eq!(
        status(
            &c,
            format!("{}/api/v1/namespaces/kube-system/secrets", e.base)
        )
        .await,
        403
    );
}

/// The informer reads (`ApiStorage` list/watch/discovery) run as the
/// controller-manager's own identity, which may list/watch everything
/// (`system:kube-controller-manager`, "Needed for all shared informers") but
/// not write Pods; a controller ServiceAccount whose role lacks `list` on a
/// resource still gets its informer data that way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_manager_identity_is_the_informer_reader() {
    let (e, creds) = setup().await;
    let cm = client_from_files(
        &e.pki,
        &creds.cert("controller-manager"),
        &creds.key("controller-manager"),
    );
    for p in [
        "/api/v1/secrets",
        "/apis/apps/v1/replicasets",
        "/api/v1/nodes",
        "/api",
        "/apis",
        "/api/v1",
    ] {
        assert_eq!(status(&cm, format!("{}{p}", e.base)).await, 200, "{p}");
    }
    let pod = json!({"apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "p", "namespace": "default"},
        "spec": {"containers": [{"name": "c", "image": "busybox"}]}});
    assert_eq!(
        send(
            &cm,
            Method::POST,
            format!("{}/api/v1/namespaces/default/pods", e.base),
            Some(pod)
        )
        .await,
        403
    );
    // The ServiceAccount table never names the root identity's user.
    assert!(CONTROLLER_IDENTITIES
        .iter()
        .all(|(_, id)| *id != ControllerIdentity::ServiceAccount("kube-controller-manager")));
}

// ---- End to end: the real controllers under their identities ---------------

struct Capture(std::sync::Mutex<Vec<k3rs_common::audit::AuditEvent>>);

#[async_trait::async_trait]
impl k3rs_common::audit::AuditBackend for Capture {
    async fn log(&self, e: k3rs_common::audit::AuditEvent) -> Result<(), String> {
        self.0.lock().unwrap().push(e);
        Ok(())
    }
    async fn flush(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Spawn every controller under its own identity (the k3rs server wiring).
fn spawn_identity_controllers(e: &Env, creds: &ComponentCreds) -> Vec<tokio::task::JoinHandle<()>> {
    let kc = |name: &str| {
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig(name), Some(&e.base)).unwrap()
    };
    let root = std::sync::Arc::new(kc("controller-manager").with_rate_limit(100.0, 200.0));
    let mut identities = k3rs_controller_manager::ControllerCredentials::new();
    for sa in controller_service_accounts() {
        identities.insert(sa, kc(&controller_cred_name(sa)));
    }
    let storage_for = k3rs_controller_manager::identity_storage_for(root, identities).unwrap();
    k3rs_controller_manager::spawn_controllers(
        storage_for,
        k3rs_controller_manager::ControllerManagerConfig {
            sync_interval: 2,
            pv_recycler: Default::default(),
            metrics_config: None,
            ca_cert_pem: Some(e.pki.server_ca_pem().to_string()),
            node_ipam: None,
            legacy_sa_token_clean_up_period:
                k3rs_controller_manager::controllers::legacy_serviceaccount_token_cleaner::DEFAULT_CLEAN_UP_PERIOD,
            csi_attachers: Vec::new(),
            attach_detach_controller: false,
            bootstrap_signer_controller: false,
            selinux_warning_controller: false,
            terminated_pod_gc_threshold:
                k3rs_controller_manager::controllers::podgc::DEFAULT_TERMINATED_POD_GC_THRESHOLD,
            token_cleaner_controller: false,
            service_cluster_ip_range: String::new(),
        },
    )
}

/// The job-controller's role grants pods `create, delete, list, patch, watch`
/// and no `get`/`update` (bootstrappolicy/controller_policy.go
/// `job-controller`). Upstream releases the job-tracking finalizer with
/// `PatchPod(removeTrackingFinalizerPatch(pod))` and treats only NotFound as
/// "pod gone" (job_controller.go:1470-1510, :1954-1965). A succeeded pod must
/// be counted once, released, and the Job left with no failures.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn job_controller_counts_and_releases_a_succeeded_pod() {
    let (e, creds) = setup().await;
    let handles = spawn_identity_controllers(&e, &creds);
    let admin = client_from_files(&e.pki, &creds.cert("admin"), &creds.key("admin"));
    assert_eq!(
        send(
            &admin,
            Method::POST,
            format!("{}/apis/batch/v1/namespaces/default/jobs", e.base),
            Some(json!({"apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": "once", "namespace": "default"},
                "spec": {"backoffLimit": 0, "template": {"spec": {"restartPolicy": "Never",
                    "containers": [{"name": "c", "image": "busybox"}]}}}})),
        )
        .await,
        201
    );
    let get = |path: String| {
        let (admin, url) = (admin.clone(), format!("{}{path}", e.base));
        async move {
            admin
                .get(url)
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap_or_default()
        }
    };
    let held = |pod: &serde_json::Value| {
        pod["metadata"]["finalizers"]
            .to_string()
            .contains("batch.kubernetes.io/job-tracking")
    };
    let mut pod = serde_json::Value::Null;
    for _ in 0..60 {
        let pods =
            get("/api/v1/namespaces/default/pods?labelSelector=job-name%3Donce".into()).await;
        if let Some(p) = pods["items"].as_array().and_then(|a| a.first()) {
            pod = p.clone();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let name = pod["metadata"]["name"]
        .as_str()
        .expect("job pod created")
        .to_string();
    assert!(held(&pod), "{pod}");
    let r = admin
        .patch(format!(
            "{}/api/v1/namespaces/default/pods/{name}/status",
            e.base
        ))
        .header("content-type", "application/merge-patch+json")
        .body(json!({"status": {"phase": "Succeeded"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let mut job = serde_json::Value::Null;
    for _ in 0..120 {
        job = get("/apis/batch/v1/namespaces/default/jobs/once".into()).await;
        pod = get(format!("/api/v1/namespaces/default/pods/{name}")).await;
        if job["status"]["succeeded"] == 1 && !held(&pod) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    for h in &handles {
        h.abort();
    }
    assert_eq!(job["status"]["succeeded"], 1, "job: {job}");
    assert_eq!(
        job["status"]["failed"].as_i64().unwrap_or(0),
        0,
        "job: {job}"
    );
    assert!(!held(&pod), "pod still held: {pod}");
}

/// Run every controller the way `k3rs server` does
/// (`run_with_api_identities`'s storage, real minted certs) against the
/// authenticated api-server, drive a Deployment + Service + Job and a
/// namespace deletion, and check the work gets done under the controllers'
/// own identities. Every 403 the api-server answered is printed (user,
/// verb, resource) for the gap report; run with `--no-capture` to see it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controllers_reconcile_under_their_own_identities() {
    let cap = std::sync::Arc::new(Capture(Default::default()));
    k3rs_api_server::audit::install_audit(k3rs_api_server::audit::AuditConfig {
        policy: k3rs_api_server::audit::Policy::from_yaml(
            "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: Metadata\n",
        )
        .unwrap(),
        sink: cap.clone(),
    });
    let (e, creds) = setup().await;
    let kc = |name: &str| {
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig(name), Some(&e.base)).unwrap()
    };
    let root = std::sync::Arc::new(kc("controller-manager").with_rate_limit(100.0, 200.0));
    let mut identities = k3rs_controller_manager::ControllerCredentials::new();
    for sa in controller_service_accounts() {
        identities.insert(sa, kc(&controller_cred_name(sa)));
    }
    let storage_for = k3rs_controller_manager::identity_storage_for(root, identities).unwrap();
    let handles = k3rs_controller_manager::spawn_controllers(
        storage_for,
        k3rs_controller_manager::ControllerManagerConfig {
            sync_interval: 2,
            pv_recycler: Default::default(),
            metrics_config: None,
            ca_cert_pem: Some(e.pki.server_ca_pem().to_string()),
            node_ipam: None,
            legacy_sa_token_clean_up_period:
                k3rs_controller_manager::controllers::legacy_serviceaccount_token_cleaner::DEFAULT_CLEAN_UP_PERIOD,
            csi_attachers: Vec::new(),
            attach_detach_controller: false,
            bootstrap_signer_controller: false,
            selinux_warning_controller: false,
            terminated_pod_gc_threshold:
                k3rs_controller_manager::controllers::podgc::DEFAULT_TERMINATED_POD_GC_THRESHOLD,
            token_cleaner_controller: false,
            service_cluster_ip_range: String::new(),
        },
    );

    let admin = client_from_files(&e.pki, &creds.cert("admin"), &creds.key("admin"));
    let post = |path: &str, body: serde_json::Value| {
        let (admin, url) = (admin.clone(), format!("{}{path}", e.base));
        async move { send(&admin, Method::POST, url, Some(body)).await }
    };
    let labels = json!({"app": "web"});
    assert_eq!(
        post(
            "/apis/apps/v1/namespaces/default/deployments",
            json!({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": "web", "namespace": "default"},
                "spec": {"replicas": 2, "selector": {"matchLabels": labels},
                    "template": {"metadata": {"labels": labels},
                        "spec": {"containers": [{"name": "c", "image": "busybox"}]}}}})
        )
        .await,
        201
    );
    assert_eq!(
        post(
            "/api/v1/namespaces/default/services",
            json!({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": "web", "namespace": "default"},
                "spec": {"selector": labels, "ports": [{"port": 80}]}})
        )
        .await,
        201
    );
    assert_eq!(
        post(
            "/apis/batch/v1/namespaces/default/jobs",
            json!({"apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": "once", "namespace": "default"},
                "spec": {"template": {"spec": {"restartPolicy": "Never",
                    "containers": [{"name": "c", "image": "busybox"}]}}}})
        )
        .await,
        201
    );
    assert_eq!(
        post(
            "/api/v1/namespaces",
            json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "doomed"}})
        )
        .await,
        201
    );
    assert_eq!(
        post(
            "/api/v1/namespaces/doomed/configmaps",
            json!({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "cm"}})
        )
        .await,
        201
    );
    let s = send(
        &admin,
        Method::DELETE,
        format!("{}/api/v1/namespaces/doomed", e.base),
        None,
    )
    .await;
    assert!(s == 200 || s == 202, "delete ns -> {s}");

    let get = |path: &str| {
        let (admin, url) = (admin.clone(), format!("{}{path}", e.base));
        async move {
            let r = admin.get(url).send().await.unwrap();
            (
                r.status().as_u16(),
                r.json::<serde_json::Value>().await.unwrap_or_default(),
            )
        }
    };
    let mut outcome = std::collections::BTreeMap::new();
    for _ in 0..120 {
        let (_, rs) = get("/apis/apps/v1/namespaces/default/replicasets").await;
        let (_, pods) = get("/api/v1/namespaces/default/pods?labelSelector=app%3Dweb").await;
        let (_, job_pods) =
            get("/api/v1/namespaces/default/pods?labelSelector=job-name%3Donce").await;
        let (_, slices) = get(
            "/apis/discovery.k8s.io/v1/namespaces/default/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3Dweb",
        )
        .await;
        let (ns, _) = get("/api/v1/namespaces/doomed").await;
        let (_, cm) = get("/api/v1/namespaces/default/configmaps/kube-root-ca.crt").await;
        let n = |v: &serde_json::Value| v["items"].as_array().map_or(0, |a| a.len());
        outcome.insert("deployment-controller: replicaset", n(&rs) >= 1);
        outcome.insert("replicaset-controller: 2 pods", n(&pods) >= 2);
        outcome.insert("job-controller: pod", n(&job_pods) >= 1);
        outcome.insert("endpointslice-controller: slice", n(&slices) >= 1);
        outcome.insert("namespace-controller: ns gone", ns == 404);
        outcome.insert(
            "root-ca-cert-publisher: kube-root-ca.crt",
            cm["kind"] == "ConfigMap",
        );
        if outcome.values().all(|v| *v) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    for h in &handles {
        h.abort();
    }

    let mut denied = std::collections::BTreeSet::new();
    for ev in cap.0.lock().unwrap().iter() {
        if ev.response_status.as_ref().map(|s| s.code) == Some(403) {
            let o = ev.object_ref.clone().unwrap_or_default();
            let res = format!(
                "{}{}{}",
                o.api_group
                    .as_deref()
                    .map(|g| format!("{g}/"))
                    .unwrap_or_default(),
                o.resource.as_deref().unwrap_or("?"),
                o.subresource
                    .as_deref()
                    .map(|s| format!("/{s}"))
                    .unwrap_or_default()
            );
            denied.insert(format!("{} {} {}", ev.user.username, ev.verb, res));
        }
    }
    eprintln!("=== outcome ===");
    for (k, v) in &outcome {
        eprintln!("{v:5} {k}");
    }
    eprintln!("=== 403s (user verb resource) ===");
    for d in &denied {
        eprintln!("{d}");
    }
    for (k, v) in &outcome {
        assert!(v, "not reconciled: {k}; 403s: {denied:#?}");
    }
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap()
}

/// Rough RSS cost of the per-controller identities (not a gate; run with
/// `--run-ignored only --no-capture`): one cert-bearing client per controller
/// ServiceAccount, each making one authenticated request (so each holds its
/// own TLS connection pool), against the same number of `for_controller`
/// clones of one client (shared pool), as before this change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn rss_of_controller_identities() {
    let (e, creds) = setup().await;
    let kc = |name: &str| {
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig(name), Some(&e.base)).unwrap()
    };
    let sas = controller_service_accounts();
    let root = kc("controller-manager");
    root.get_text("/api/v1/namespaces").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let before = rss_kib();
    let clones: Vec<_> = sas.iter().map(|sa| root.for_controller(sa)).collect();
    for c in &clones {
        c.get_text("/api/v1/namespaces").await.unwrap();
    }
    let after_shared = rss_kib();

    let ids: Vec<_> = sas.iter().map(|sa| kc(&controller_cred_name(sa))).collect();
    for (sa, c) in sas.iter().zip(&ids) {
        // `get` namespaces is not in every role; any authenticated answer
        // (200 or 403) means the TLS connection is up.
        let _ = c
            .get_text(&format!(
                "/api/v1/namespaces/kube-system/serviceaccounts/{sa}"
            ))
            .await;
    }
    let after_ids = rss_kib();
    eprintln!(
        "RSS: {} identities; shared-client clones +{} KiB; per-identity clients +{} KiB ({} KiB each)",
        sas.len(),
        after_shared.saturating_sub(before),
        after_ids.saturating_sub(after_shared),
        after_ids.saturating_sub(after_shared) / sas.len() as u64
    );
    drop((clones, ids));
}

// ---- Reads that feed destructive actions go through the informer path ------

/// `storage_for` exactly as `run_with_api_identities` builds it.
fn identity_storage(
    e: &Env,
    creds: &ComponentCreds,
) -> impl Fn(&'static str) -> std::sync::Arc<k3rs_storage::api_storage::ApiStorage> {
    let kc = |name: &str| {
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig(name), Some(&e.base)).unwrap()
    };
    let root = std::sync::Arc::new(kc("controller-manager"));
    let mut ids = k3rs_controller_manager::ControllerCredentials::new();
    for sa in controller_service_accounts() {
        ids.insert(sa, kc(&controller_cred_name(sa)));
    }
    k3rs_controller_manager::identity_storage_for(root, ids).unwrap()
}

async fn admin_json(
    e: &Env,
    creds: &ComponentCreds,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value) {
    let admin = client_from_files(&e.pki, &creds.cert("admin"), &creds.key("admin"));
    let mut r = admin.request(method, format!("{}{path}", e.base));
    if let Some(b) = body {
        r = r.json(&b);
    }
    let r = r.send().await.unwrap();
    let code = r.status().as_u16();
    (code, r.json().await.unwrap_or_default())
}

/// A node whose status heartbeat is old but whose Lease keeps renewing stays
/// Ready (`tryUpdateNodeHealth`, node_lifecycle_controller.go:921-935: the
/// lease renewal refreshes the probe timestamp). The node-controller
/// ServiceAccount has no `get` on leases, so the Lease must be read through
/// the informer path; a live GET would 403, the renewal would be missed and
/// the node marked Unknown (then tainted and its pods evicted).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_with_renewing_lease_stays_ready_under_node_controller_identity() {
    let (e, creds) = setup().await;
    let t0 = chrono::Utc::now() - chrono::Duration::hours(1);
    let hb = t0.to_rfc3339();
    let node = json!({"apiVersion": "v1", "kind": "Node",
        "metadata": {"name": "n9"},
        "status": {"conditions": [{"type": "Ready", "status": "True",
            "lastHeartbeatTime": hb, "lastTransitionTime": hb}]}});
    let (s, _) = admin_json(&e, &creds, Method::POST, "/api/v1/nodes", Some(node)).await;
    assert_eq!(s, 201);
    // The api-server may drop status on create: write it via /status too.
    let (_, mut n) = admin_json(&e, &creds, Method::GET, "/api/v1/nodes/n9", None).await;
    n["status"] = json!({"conditions": [{"type": "Ready", "status": "True",
        "lastHeartbeatTime": hb, "lastTransitionTime": hb}]});
    let (s, _) = admin_json(&e, &creds, Method::PUT, "/api/v1/nodes/n9/status", Some(n)).await;
    assert_eq!(s, 200);
    let lease = |renew: chrono::DateTime<chrono::Utc>, rv: Option<&str>| {
        let mut l = json!({"apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
            "metadata": {"name": "n9", "namespace": "kube-node-lease"},
            "spec": {"holderIdentity": "n9", "leaseDurationSeconds": 40,
                "renewTime": renew.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)}});
        if let Some(rv) = rv {
            l["metadata"]["resourceVersion"] = json!(rv);
        }
        l
    };
    let leases = "/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases";
    let (s, _) = admin_json(&e, &creds, Method::POST, leases, Some(lease(t0, None))).await;
    assert_eq!(s, 201);

    let storage_for = identity_storage(&e, &creds);
    let c = k3rs_controller_manager::controllers::node::NodeController::new(storage_for("Node"));
    c.monitor_node_health().await.unwrap();
    c.advance_clock_for_test(chrono::Duration::seconds(30));
    let (_, cur) = admin_json(&e, &creds, Method::GET, &format!("{leases}/n9"), None).await;
    let rv = cur["metadata"]["resourceVersion"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, _) = admin_json(
        &e,
        &creds,
        Method::PUT,
        &format!("{leases}/n9"),
        Some(lease(t0 + chrono::Duration::seconds(10), Some(&rv))),
    )
    .await;
    assert_eq!(s, 200);
    c.monitor_node_health().await.unwrap();
    c.advance_clock_for_test(chrono::Duration::seconds(30));
    c.monitor_node_health().await.unwrap();
    let (_, n) = admin_json(&e, &creds, Method::GET, "/api/v1/nodes/n9", None).await;
    let ready = n["status"]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == "Ready")
        .unwrap()["status"]
        .clone();
    assert_eq!(ready, "True", "{n}");
}

/// The endpointslice-controller ServiceAccount has no `get` on endpoints.
/// Mirrored EndpointSlices are deleted only when the source Endpoints is
/// gone; reading it with a live GET (403) made every mirrored slice look
/// orphaned. Through the informer path the slice survives while its
/// Endpoints exists, and is still cleaned up once it is deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirrored_endpointslice_survives_under_endpointslice_identity() {
    let (e, creds) = setup().await;
    let svc = json!({"apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "ext", "namespace": "default"},
        "spec": {"ports": [{"port": 80}]}});
    let ep = json!({"apiVersion": "v1", "kind": "Endpoints",
        "metadata": {"name": "ext", "namespace": "default"},
        "subsets": [{"addresses": [{"ip": "192.0.2.50"}], "ports": [{"port": 80}]}]});
    let slice = json!({"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
        "metadata": {"name": "ext", "namespace": "default",
            "labels": {"kubernetes.io/service-name": "ext",
                "endpointslice.kubernetes.io/managed-by": "endpointslice-mirroring-controller.k8s.io"}},
        "addressType": "IPv4",
        "endpoints": [{"addresses": ["192.0.2.50"]}],
        "ports": [{"port": 80}]});
    for (path, body) in [
        ("/api/v1/namespaces/default/services", svc),
        ("/api/v1/namespaces/default/endpoints", ep),
        (
            "/apis/discovery.k8s.io/v1/namespaces/default/endpointslices",
            slice,
        ),
    ] {
        let (s, b) = admin_json(&e, &creds, Method::POST, path, Some(body)).await;
        assert_eq!(s, 201, "{path}: {b}");
    }
    let storage_for = identity_storage(&e, &creds);
    let c = k3rs_controller_manager::controllers::endpointslice::EndpointSliceController::new(
        storage_for("EndpointSlice"),
    );
    let slice_path = "/apis/discovery.k8s.io/v1/namespaces/default/endpointslices/ext";
    c.cleanup_orphans().await.unwrap();
    assert_eq!(
        admin_json(&e, &creds, Method::GET, slice_path, None)
            .await
            .0,
        200,
        "mirrored slice deleted while its Endpoints exists"
    );
    let (s, _) = admin_json(
        &e,
        &creds,
        Method::DELETE,
        "/api/v1/namespaces/default/endpoints/ext",
        None,
    )
    .await;
    assert_eq!(s, 200);
    c.cleanup_orphans().await.unwrap();
    assert_eq!(
        admin_json(&e, &creds, Method::GET, slice_path, None)
            .await
            .0,
        404,
        "mirrored slice kept after its Endpoints was deleted"
    );
}

// ---- k3rs-only Events controller identity (`system:k3rs-event-gc`) --------

const EVENT_GC: &str = k3rs_controller_manager::identities::EVENT_GC_SERVICE_ACCOUNT;

/// An Event in `default` whose lastTimestamp is two hours old.
async fn post_old_event(e: &Env, admin: &reqwest::Client, name: &str) {
    let old = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
    assert_eq!(
        send(
            admin,
            Method::POST,
            format!("{}/api/v1/namespaces/default/events", e.base),
            Some(json!({"apiVersion": "v1", "kind": "Event",
                "metadata": {"name": name, "namespace": "default"},
                "involvedObject": {"kind": "Pod", "namespace": "default", "name": "gone"},
                "reason": "Old", "message": "old", "type": "Normal",
                "firstTimestamp": old, "lastTimestamp": old, "count": 1})),
        )
        .await,
        201
    );
}

/// The bootstrap ClusterRole binds the Events controller's identity to
/// list/get/delete Events, and to nothing else: no Pod delete, no Secrets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn event_gc_identity_deletes_events_but_not_pods_or_secrets() {
    let (e, creds) = setup().await;
    apply_bootstrap(&e, &creds).await;
    let admin = client_from_files(&e.pki, &creds.cert("admin"), &creds.key("admin"));
    post_old_event(&e, &admin, "old-1").await;
    let gc = sa_client(&e, &creds, EVENT_GC);
    let ev = format!("{}/api/v1/namespaces/default/events", e.base);
    assert_eq!(status(&gc, ev.clone()).await, 200, "list events");
    assert_eq!(status(&gc, format!("{ev}/old-1")).await, 200, "get event");
    assert_eq!(
        send(&gc, Method::DELETE, format!("{ev}/old-1"), None).await,
        200,
        "delete event"
    );
    assert_eq!(
        send(
            &gc,
            Method::DELETE,
            format!("{}/api/v1/namespaces/default/pods/p", e.base),
            None
        )
        .await,
        403,
        // Authorization runs before the lookup: an allowed DELETE of this
        // absent pod would be 404.
        "delete pod"
    );
    assert_eq!(
        status(
            &gc,
            format!("{}/api/v1/namespaces/kube-system/secrets", e.base)
        )
        .await,
        403,
        "list secrets"
    );
}

/// The Events controller's janitor pass, built exactly as `k3rs server`
/// builds it (`identity_storage_for("Events")`), removes an Event older than
/// 1 h and is never denied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn event_gc_janitor_pass_deletes_old_events_without_denials() {
    let cap = std::sync::Arc::new(Capture(Default::default()));
    k3rs_api_server::audit::install_audit(k3rs_api_server::audit::AuditConfig {
        policy: k3rs_api_server::audit::Policy::from_yaml(
            "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: Metadata\n",
        )
        .unwrap(),
        sink: cap.clone(),
    });
    let (e, creds) = setup().await;
    apply_bootstrap(&e, &creds).await;
    let admin = client_from_files(&e.pki, &creds.cert("admin"), &creds.key("admin"));
    post_old_event(&e, &admin, "old-2").await;

    let kc = |name: &str| {
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig(name), Some(&e.base)).unwrap()
    };
    let root = std::sync::Arc::new(kc("controller-manager"));
    let mut identities = k3rs_controller_manager::ControllerCredentials::new();
    for sa in controller_service_accounts() {
        identities.insert(sa, kc(&controller_cred_name(sa)));
    }
    let storage_for = k3rs_controller_manager::identity_storage_for(root, identities).unwrap();
    let ctrl = k3rs_controller_manager::controllers::events::EventsController::new(
        storage_for("Events"),
        2,
    );
    ctrl.reconcile_all()
        .await
        .map_err(|e| e.to_string())
        .unwrap();

    assert_eq!(
        status(
            &admin,
            format!("{}/api/v1/namespaces/default/events/old-2", e.base)
        )
        .await,
        404,
        "old event deleted"
    );
    let gc_user = k3rs_controller_manager::identities::service_account_username(EVENT_GC);
    let denied: Vec<String> = cap
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|ev| ev.response_status.as_ref().map(|s| s.code) == Some(403))
        .map(|ev| format!("{} {} {:?}", ev.user.username, ev.verb, ev.object_ref))
        .collect();
    assert!(
        denied.is_empty(),
        "denied requests during the janitor pass ({gc_user}): {denied:#?}"
    );
}

/// Install an audit sink capturing every request, as the other end-to-end
/// tests here do, and return it.
fn capture_audit() -> std::sync::Arc<Capture> {
    let cap = std::sync::Arc::new(Capture(Default::default()));
    k3rs_api_server::audit::install_audit(k3rs_api_server::audit::AuditConfig {
        policy: k3rs_api_server::audit::Policy::from_yaml(
            "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: Metadata\n",
        )
        .unwrap(),
        sink: cap.clone(),
    });
    cap
}

/// The `default` ServiceAccount in `default` (no ServiceAccount controller
/// runs here; ServiceAccount admission refuses a pod without it).
async fn default_service_account(e: &Env, creds: &ComponentCreds) {
    let (s, b) = admin_json(
        e,
        creds,
        Method::POST,
        "/api/v1/namespaces/default/serviceaccounts",
        Some(json!({"apiVersion": "v1", "kind": "ServiceAccount",
            "metadata": {"name": "default", "namespace": "default"}})),
    )
    .await;
    assert!(s == 201 || s == 409, "{s}: {b}");
}

/// Every request answered 403 so far, as `user verb objectRef`.
fn denials(cap: &Capture) -> Vec<String> {
    cap.0
        .lock()
        .unwrap()
        .iter()
        .filter(|ev| ev.response_status.as_ref().map(|s| s.code) == Some(403))
        .map(|ev| format!("{} {} {:?}", ev.user.username, ev.verb, ev.object_ref))
        .collect()
}

/// `system:controller:resourcequota-controller` has list/watch on `*/*` and
/// update on `resourcequotas/status`, and no `get`. Upstream
/// `syncResourceQuotaFromKey` reads the quota from its lister
/// (pkg/controller/resourcequota/resource_quota_controller.go:340-364) and
/// writes `UpdateStatus`. A live GET 403'd, was taken for "deleted", and the
/// status was never written, so quota admission refused every create in the
/// namespace ("status unknown for quota"). Under its own identity the
/// controller must populate status.hard/used, and a pod create must then be
/// admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resourcequota_controller_populates_status_under_its_identity() {
    let cap = capture_audit();
    let (e, creds) = setup().await;
    default_service_account(&e, &creds).await;
    let quotas = "/api/v1/namespaces/default/resourcequotas";
    let (s, b) = admin_json(
        &e,
        &creds,
        Method::POST,
        quotas,
        Some(json!({"apiVersion": "v1", "kind": "ResourceQuota",
            "metadata": {"name": "q", "namespace": "default"},
            "spec": {"hard": {"pods": "5"}}})),
    )
    .await;
    assert_eq!(s, 201, "{b}");

    let storage_for = identity_storage(&e, &creds);
    let c = k3rs_controller_manager::controllers::resource_quota::ResourceQuotaController::new(
        storage_for("ResourceQuota"),
    );
    c.reconcile_one("default", "q")
        .await
        .map_err(|e| e.to_string())
        .unwrap();
    // A quota that is gone is "deleted", not an error (lister NotFound).
    c.reconcile_one("default", "absent")
        .await
        .map_err(|e| e.to_string())
        .unwrap();

    let (_, q) = admin_json(&e, &creds, Method::GET, &format!("{quotas}/q"), None).await;
    assert_eq!(q["status"]["hard"]["pods"], "5", "{q}");
    assert_eq!(q["status"]["used"]["pods"], "0", "{q}");
    let (s, b) = admin_json(
        &e,
        &creds,
        Method::POST,
        "/api/v1/namespaces/default/pods",
        Some(json!({"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "under-quota", "namespace": "default"},
            "spec": {"containers": [{"name": "c", "image": "busybox"}]}})),
    )
    .await;
    assert_eq!(s, 201, "pod create under a synced quota: {b}");
    let denied = denials(&cap);
    assert!(denied.is_empty(), "denied requests: {denied:#?}");
}
