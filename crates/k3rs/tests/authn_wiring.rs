//! Task 1 of the RBAC plan: prove the existing api-server wiring behaves as
//! the k3rs server will assume. An in-process api-server runs with
//! `client_ca_file` = the Pki client CA, `Node,RBAC`, `skip_auth=false`, and
//! the Pki serving cert; clients present certs minted by `Pki::sign_csr`.
//!
//! Upstream behaviour relied on:
//! - x509 authn CN->user / O->groups: `k8s.io/apiserver/pkg/authentication/request/x509`.
//! - Node authorizer + NodeRestriction: `plugin/pkg/auth/authorizer/node/node_authorizer.go`.
//! - Bootstrap RBAC policy (system:masters, system:kube-scheduler, system:nodes):
//!   `plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go`.
//!
//! Each test runs in its own process under nextest (the api-server keeps
//! process-global state), so run with `cargo nextest run -p k3rs authn_wiring`.

use std::net::TcpListener;

use k3rs::pki::{CaKind, Pki, Usage};
use k3rs_api_server::{run, ApiServerConfig};
use k3rs_storage::{build_key, Storage, StorageBackend};
use std::sync::Arc;
use tokio::task::JoinHandle;

/// Start an authenticated api-server on an ephemeral loopback port.
/// Returns `(base_url, join_handle)`; the handle keeps the server alive.
pub async fn start_authn_api(
    pki: &Pki,
    storage: Arc<StorageBackend>,
) -> (String, JoinHandle<anyhow::Result<()>>) {
    start_authn_api_with(pki, storage, true).await
}

/// As [`start_authn_api`], with `--anonymous-auth` set to `anonymous_auth`
/// (`k3rs server` passes `false`, like k3s `apiServer` :222).
pub async fn start_authn_api_with(
    pki: &Pki,
    storage: Arc<StorageBackend>,
    anonymous_auth: bool,
) -> (String, JoinHandle<anyhow::Result<()>>) {
    k3rs::agent::ensure_crypto_provider();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let ca_path = pki.dir.join("client-ca.crt");
    let cfg = ApiServerConfig {
        bind_address: format!("127.0.0.1:{port}"),
        tls: true,
        tls_cert_file: Some(pki.dir.join("serving.crt").to_string_lossy().into()),
        tls_key_file: Some(pki.dir.join("serving.key").to_string_lossy().into()),
        skip_auth: false,
        authorization_mode: vec!["Node".into(), "RBAC".into()],
        client_ca_file: Some(ca_path.to_string_lossy().into()),
        anonymous_auth,
        ..Default::default()
    };
    let h = tokio::spawn(run(storage, cfg));
    (format!("https://127.0.0.1:{port}"), h)
}

fn client_for(pki: &Pki, cn: &str, orgs: &[&str]) -> reqwest::Client {
    let kp = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::default();
    p.distinguished_name = rcgen::DistinguishedName::new();
    let csr = p.serialize_request(&kp).unwrap().der().to_vec();
    let cert = pki
        .sign_csr(CaKind::Client, &csr, cn, orgs, Usage::ClientAuth, &[])
        .unwrap();
    let id =
        reqwest::Identity::from_pem(format!("{cert}{}", kp.serialize_pem()).as_bytes()).unwrap();
    base_builder(pki).identity(id).build().unwrap()
}

fn base_builder(pki: &Pki) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(pki.server_ca_pem().as_bytes()).unwrap(),
        )
}

struct Env {
    _dir: tempfile::TempDir,
    pki: Pki,
    base: String,
    _h: JoinHandle<anyhow::Result<()>>,
}

async fn boot() -> Env {
    boot_with(true).await
}

async fn boot_with(anonymous_auth: bool) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::load_or_create(dir.path(), &["localhost".to_string()]).unwrap();
    let storage = Arc::new(StorageBackend::new_memory());
    // Seed node n2 so the Node authorizer has an object to read.
    for n in ["n2", "n3"] {
        storage
            .create(
                &build_key("nodes", None, n),
                &serde_json::json!({
                    "apiVersion": "v1", "kind": "Node",
                    "metadata": {"name": n, "uid": format!("uid-{n}")}
                }),
            )
            .await
            .unwrap();
    }
    let (base, h) = start_authn_api_with(&pki, storage, anonymous_auth).await;
    // Wait until the bootstrap RBAC policy is served: admin listing succeeds
    // (system:masters is also allowed by the authorizer before policy lands,
    // so additionally wait for the scheduler ClusterRole to exist).
    let admin = client_for(&pki, "system:admin", &["system:masters"]);
    let url =
        format!("{base}/apis/rbac.authorization.k8s.io/v1/clusterroles/system:kube-scheduler");
    let mut ok = false;
    for _ in 0..200 {
        if let Ok(r) = admin.get(&url).send().await {
            if r.status().is_success() {
                ok = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(ok, "bootstrap RBAC policy never became available");
    Env {
        _dir: dir,
        pki,
        base,
        _h: h,
    }
}

async fn status(c: &reqwest::Client, url: String) -> u16 {
    c.get(url).send().await.unwrap().status().as_u16()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_api_is_rejected() {
    let e = boot().await;
    let c = base_builder(&e.pki).build().unwrap();
    let s = status(&c, format!("{}/api", e.base)).await;
    assert!(s == 401 || s == 403, "anonymous /api -> {s}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_cert_lists_namespaces() {
    let e = boot().await;
    let c = client_for(&e.pki, "system:admin", &["system:masters"]);
    assert_eq!(
        status(&c, format!("{}/api/v1/namespaces", e.base)).await,
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_cert_reads_own_node() {
    let e = boot().await;
    let c = client_for(&e.pki, "system:node:n2", &["system:nodes"]);
    assert_eq!(status(&c, format!("{}/api/v1/nodes/n2", e.base)).await, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_cert_cannot_read_kube_system_secrets() {
    let e = boot().await;
    let c = client_for(&e.pki, "system:node:n2", &["system:nodes"]);
    assert_eq!(
        status(
            &c,
            format!("{}/api/v1/namespaces/kube-system/secrets", e.base)
        )
        .await,
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_cert_cannot_read_other_nodes_password_secret() {
    let e = boot().await;
    let c = client_for(&e.pki, "system:node:n2", &["system:nodes"]);
    assert_eq!(
        status(
            &c,
            format!(
                "{}/api/v1/namespaces/kube-system/secrets/n3.node-password.k3rs",
                e.base
            )
        )
        .await,
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scheduler_cert_can_list_pods() {
    let e = boot().await;
    let c = client_for(&e.pki, "system:kube-scheduler", &[]);
    assert_eq!(status(&c, format!("{}/api/v1/pods", e.base)).await, 200);
}

/// Task 3: the clients `k3rs server` hands its embedded components. Each
/// minted kubeconfig (server overridden to the loopback port) verifies the
/// serving cert against the server CA (SAN 127.0.0.1) and authenticates as
/// its own identity; the readiness wait passes with the admin cert; a client
/// without a cert is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_clients_authenticate_over_loopback() {
    let e = boot().await;
    let creds = e.pki.ensure_component_creds("n2", "192.0.2.2").unwrap();
    let client = |name: &str| {
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig(name), Some(&e.base))
            .unwrap_or_else(|err| panic!("{name}: {err:#}"))
    };
    let admin = client("admin");
    k3rs::util::wait_for_readyz(
        &admin,
        std::time::Duration::from_secs(10),
        std::time::Duration::from_millis(100),
    )
    .await
    .unwrap();
    admin.get_text("/api/v1/namespaces").await.unwrap();
    // system:node:n2 reads its own Node (Node authorizer).
    client("kubelet")
        .get_text("/api/v1/nodes/n2")
        .await
        .unwrap();
    // system:kube-scheduler and system:kube-proxy (system:node-proxier).
    client("scheduler").get_text("/api/v1/pods").await.unwrap();
    client("kube-proxy")
        .get_text("/api/v1/services")
        .await
        .unwrap();
    // system:kube-controller-manager: `*/*` list.
    client("controller-manager")
        .get_text("/api/v1/pods")
        .await
        .unwrap();

    let anon = k3rs_client::http::ApiClient::with_tls(
        &e.base,
        false,
        Some(e.pki.server_ca_pem().as_bytes().to_vec()),
        None,
        None,
        None,
    )
    .unwrap();
    let err = anon
        .get_text("/api/v1/namespaces")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("403") || err.contains("401"), "{err}");
}

/// The unauthenticated-reachable paths `k3rs server` must close: discovery,
/// the health probes, metrics, version and the OIDC discovery documents.
const ANON_PATHS: &[&str] = &[
    "/api",
    "/healthz",
    "/livez",
    "/readyz",
    "/metrics",
    "/version",
    "/.well-known/openid-configuration",
    "/openid/v1/jwks",
];

/// GET `url` until it is not 503 (readyz reports not-ready while post-start
/// hooks finish), at most ~20 s.
async fn status_ready(c: &reqwest::Client, url: String) -> u16 {
    for _ in 0..200 {
        let s = status(c, url.clone()).await;
        if s != 503 {
            return s;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    status(c, url).await
}

/// Task 3b: `--anonymous-auth=false` (k3s `apiServer`, pkg/daemons/control/
/// server.go:222). With no anonymous authenticator in the union
/// (pkg/kubeapiserver/authenticator/config.go:242-246) a request that no
/// authenticator accepts hits `WithAuthentication`'s `Unauthorized` handler
/// (staging/src/k8s.io/apiserver/pkg/endpoints/filters/authentication.go):
/// 401 with a `Status` body, on every path, health probes included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_disabled_rejects_unauthenticated_with_401() {
    let e = boot_with(false).await;
    let c = base_builder(&e.pki).build().unwrap();
    for p in ANON_PATHS {
        let r = c.get(format!("{}{p}", e.base)).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 401, "anonymous {p}");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["kind"], "Status", "{p}: {body}");
        assert_eq!(body["reason"], "Unauthorized", "{p}: {body}");
        assert_eq!(body["code"], 401, "{p}: {body}");
    }
}

/// Authenticated callers are unchanged: the admin cert (system:masters) is
/// authorized on every one of those paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_disabled_admin_cert_still_served() {
    let e = boot_with(false).await;
    let c = client_for(&e.pki, "system:admin", &["system:masters"]);
    for p in ANON_PATHS {
        let s = status_ready(&c, format!("{}{p}", e.base)).await;
        if *p == "/openid/v1/jwks" {
            // No --service-account-key-file in this harness: the handler's
            // own answer (200 or 404), never an authn/authz refusal.
            assert!(s != 401 && s != 403, "admin {p} -> {s}");
        } else {
            assert_eq!(s, 200, "admin {p}");
        }
    }
}

/// A node identity still reads discovery and the public-info paths
/// (`system:discovery` / `system:public-info-viewer` are bound to
/// `system:authenticated`, bootstrappolicy/policy.go).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_disabled_node_cert_reads_api() {
    let e = boot_with(false).await;
    let c = client_for(&e.pki, "system:node:n2", &["system:nodes"]);
    assert_eq!(status(&c, format!("{}/api", e.base)).await, 200);
    assert_eq!(status(&c, format!("{}/version", e.base)).await, 200);
    assert_eq!(status_ready(&c, format!("{}/healthz", e.base)).await, 200);
    assert_eq!(status(&c, format!("{}/api/v1/nodes/n2", e.base)).await, 200);
}

/// `anonymous_auth` defaults to true (`WithAnonymous`, authentication.go:
/// 186-191), which is exactly the behaviour before Task 3b: anonymous health
/// probes and `/version` are served, anonymous API calls are `system:anonymous`
/// and RBAC answers 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_enabled_by_default_is_unchanged() {
    assert!(ApiServerConfig::default().anonymous_auth);
    let e = boot().await;
    let c = base_builder(&e.pki).build().unwrap();
    for p in ["/healthz", "/livez", "/version", "/metrics"] {
        assert_eq!(status(&c, format!("{}{p}", e.base)).await, 200, "{p}");
    }
    assert_eq!(status_ready(&c, format!("{}/readyz", e.base)).await, 200);
    assert_eq!(status(&c, format!("{}/api", e.base)).await, 403);
}

// ---- Task 5: the authenticated kubelet API against this api-server ---------

/// The kubelet's own identity must be able to create the reviews its API's
/// webhook authn/authz posts. Upstream grants `create` on `tokenreviews` and
/// `subjectaccessreviews` in `NodeRules()` (plugin/pkg/auth/authorizer/rbac/
/// bootstrappolicy/policy.go:194-198), which the Node authorizer applies to
/// every `system:nodes` member (plugin/pkg/auth/authorizer/node/
/// node_authorizer.go:165 `rbac.RulesAllow(attrs, r.nodeRules...)`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_identity_can_create_token_and_access_reviews() {
    let e = boot_with(false).await;
    let creds = e.pki.ensure_component_creds("n2", "192.0.2.2").unwrap();
    let kubelet =
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig("kubelet"), Some(&e.base)).unwrap();
    let sar = serde_json::json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {
            "user": "system:admin",
            "groups": ["system:masters", "system:authenticated"],
            "resourceAttributes": {"verb": "get", "resource": "nodes", "subresource": "proxy", "name": "n2"}
        }
    });
    let (code, r) = kubelet
        .post_with_status::<_, serde_json::Value>(
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            &sar,
        )
        .await;
    let r = r.unwrap_or_else(|err| panic!("SAR as system:node:n2 -> {code}: {err:#}"));
    assert_eq!(r["status"]["allowed"], true, "{r}");
    let tr = serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": {"token": "not-a-token"}
    });
    let (code, r) = kubelet
        .post_with_status::<_, serde_json::Value>(
            "/apis/authentication.k8s.io/v1/tokenreviews",
            &tr,
        )
        .await;
    let r = r.unwrap_or_else(|err| panic!("TokenReview as system:node:n2 -> {code}: {err:#}"));
    assert_ne!(r["status"]["authenticated"], true, "{r}");
}

/// End to end: node n2's kubelet API served with `kubelet_api_serving` from
/// the server's real credentials (client CA, `serving-kubelet` pair, the
/// `system:node:n2` client posting SubjectAccessReviews to this api-server).
/// Anonymous is 401; `system:apiserver` and `system:admin` (system:masters)
/// are allowed by RBAC; another node is denied (the Node authorizer grants no
/// `nodes/proxy`, and `system:node` RBAC has no subjects).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kubelet_api_authenticates_against_the_api_server() {
    let e = boot_with(false).await;
    let creds = e.pki.ensure_component_creds("n2", "192.0.2.2").unwrap();
    let kubelet = Arc::new(
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig("kubelet"), Some(&e.base)).unwrap(),
    );
    let auth = k3rs_kubelet::KubeletApiAuth {
        client_ca_file: creds.client_ca().to_string_lossy().into_owned(),
        api_client: kubelet,
        serving_cert_file: creds.serving_cert(),
        serving_key_file: creds.serving_key(),
    };
    let serving = k3rs_kubelet::kubelet_api_serving("n2", Some(&auth)).unwrap();
    let app = k3rs_kubelet::api_router(
        k3rs_kubelet::server::ServerState {
            node_name: "n2".into(),
            storage: Arc::new(StorageBackend::new_memory()),
            kubelet: None,
        },
        Arc::new(
            k3rs_common::observability::MetricsRegistry::new()
                .with_kubelet_metrics()
                .unwrap(),
        ),
        Arc::new(k3rs_kubelet::config::KubeletConfiguration::default()),
        std::env::temp_dir(),
        serving.auth.clone(),
    );
    let listener = k3rs_kubelet::bind_kubelet_api("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(k3rs_kubelet::serve_kubelet_api(listener, app, serving));
    // The serving cert is signed by the server CA with SAN 127.0.0.1, so the
    // clients below (trusting only the server CA) verify it.
    let url = format!("https://127.0.0.1:{port}/pods");

    let anon = base_builder(&e.pki).build().unwrap();
    assert_eq!(status(&anon, url.clone()).await, 401, "anonymous");
    let apiserver = client_for(&e.pki, "system:apiserver", &["system:masters"]);
    assert_eq!(
        status(&apiserver, url.clone()).await,
        200,
        "system:apiserver"
    );
    let admin = client_for(&e.pki, "system:admin", &["system:masters"]);
    assert_eq!(status(&admin, url.clone()).await, 200, "system:admin");
    let n3 = client_for(&e.pki, "system:node:n3", &["system:nodes"]);
    assert_eq!(status(&n3, url.clone()).await, 403, "system:node:n3");
}

/// A SubjectAccessReview keeps its `subresource` (`ResourceAttributesFrom`,
/// pkg/registry/authorization/util/helpers.go:35-46): another node may `get`
/// the Node object n2 (Node authorizer `NodeRules`), but not `nodes/proxy`
/// or `nodes/pods` on it, the subresources a kubelet's webhook authz asks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subject_access_review_keeps_the_subresource() {
    let e = boot_with(false).await;
    let creds = e.pki.ensure_component_creds("n2", "192.0.2.2").unwrap();
    let admin =
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig("admin"), Some(&e.base)).unwrap();
    let review = |verb: &str, sub: Option<&str>| {
        let mut ra = serde_json::json!({"verb": verb, "resource": "nodes", "name": "n2"});
        if let Some(sub) = sub {
            ra["subresource"] = sub.into();
        }
        serde_json::json!({
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SubjectAccessReview",
            "spec": {
                "user": "system:node:n3",
                "groups": ["system:nodes", "system:authenticated"],
                "resourceAttributes": ra
            }
        })
    };
    for (verb, sub, want) in [
        ("get", None, true),
        ("get", Some("proxy"), false),
        ("create", Some("proxy"), false),
        ("get", Some("pods"), false),
    ] {
        let (code, r) = admin
            .post_with_status::<_, serde_json::Value>(
                "/apis/authorization.k8s.io/v1/subjectaccessreviews",
                &review(verb, sub),
            )
            .await;
        let r = r.unwrap_or_else(|err| panic!("SAR -> {code}: {err:#}"));
        assert_eq!(r["status"]["allowed"], want, "{verb} nodes/{sub:?}: {r}");
    }
}
