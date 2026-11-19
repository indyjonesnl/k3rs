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
    let (base, h) = start_authn_api(&pki, storage).await;
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
