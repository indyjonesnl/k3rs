//! Shared in-process authn harness for the k3rs integration tests: an
//! api-server with the Pki client CA, `Node,RBAC` and the Pki serving cert,
//! plus clients that present certs minted by `Pki::sign_csr`.
//!
//! Import with `mod common;` from a test binary. Not every binary uses every
//! helper, hence the `dead_code` allowance.
#![allow(dead_code)]

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use k3rs::pki::{CaKind, Pki, Usage};
use k3rs_api_server::{run, ApiServerConfig};
use k3rs_storage::{build_key, Storage, StorageBackend};
use tokio::task::JoinHandle;

/// Start an authenticated api-server on an ephemeral loopback port.
/// Returns `(base_url, join_handle)`; the handle keeps the server alive.
pub async fn start_authn_api(
    pki: &Pki,
    storage: Arc<StorageBackend>,
) -> (String, JoinHandle<anyhow::Result<()>>) {
    start_authn_api_with(pki, storage, true).await
}

/// Attempts at finding a free port (see [`start_authn_api_with`]).
const PORT_ATTEMPTS: usize = 5;

/// As [`start_authn_api`], with `--anonymous-auth` set to `anonymous_auth`
/// (`k3rs server` passes `false`, like k3s `apiServer` :222).
///
/// `run` binds its own listener from `bind_address`, so the port is found by
/// binding `:0` and releasing it, which races with other processes. The race
/// is closed by retrying: the server counts as up only once it answers TLS
/// with the Pki serving cert (so a foreign listener that grabbed the port is
/// never mistaken for it), and a server task that ended (bind failed) is
/// retried on a new port.
pub async fn start_authn_api_with(
    pki: &Pki,
    storage: Arc<StorageBackend>,
    anonymous_auth: bool,
) -> (String, JoinHandle<anyhow::Result<()>>) {
    k3rs::agent::ensure_crypto_provider();
    let probe = base_builder(pki)
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let mut last_err = String::new();
    for _ in 0..PORT_ATTEMPTS {
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
        let base = format!("https://127.0.0.1:{port}");
        let h = tokio::spawn(run(storage.clone(), cfg));
        for _ in 0..300 {
            if h.is_finished() {
                break;
            }
            // Any HTTP answer over TLS verified against the Pki server CA
            // proves the listener is ours.
            if probe.get(format!("{base}/version")).send().await.is_ok() {
                return (base, h);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if h.is_finished() {
            last_err = match h.await {
                Ok(Ok(())) => "api-server exited".into(),
                Ok(Err(e)) => format!("{e:#}"),
                Err(e) => e.to_string(),
            };
        } else {
            h.abort();
            last_err = "api-server did not answer within 15s".into();
        }
    }
    panic!("api-server did not start after {PORT_ATTEMPTS} ports: {last_err}");
}

/// A reqwest client presenting a fresh client cert `cn`/`orgs` signed by the
/// Pki client CA.
pub fn client_for(pki: &Pki, cn: &str, orgs: &[&str]) -> reqwest::Client {
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

/// A rustls client builder trusting only the Pki server CA (no client cert).
pub fn base_builder(pki: &Pki) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(pki.server_ca_pem().as_bytes()).unwrap(),
        )
}

pub struct Env {
    pub _dir: tempfile::TempDir,
    pub pki: Pki,
    pub base: String,
    pub _h: JoinHandle<anyhow::Result<()>>,
}

pub async fn boot() -> Env {
    boot_with(true).await
}

pub async fn boot_with(anonymous_auth: bool) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::load_or_create(dir.path(), &["localhost".to_string()]).unwrap();
    let storage = Arc::new(StorageBackend::new_memory());
    // Seed nodes n2/n3 so the Node authorizer has objects to read.
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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "bootstrap RBAC policy never became available");
    Env {
        _dir: dir,
        pki,
        base,
        _h: h,
    }
}

pub async fn status(c: &reqwest::Client, url: String) -> u16 {
    c.get(url).send().await.unwrap().status().as_u16()
}

/// GET `url` until it is not 503 (readyz reports not-ready while post-start
/// hooks finish), at most ~20 s.
pub async fn status_ready(c: &reqwest::Client, url: String) -> u16 {
    for _ in 0..200 {
        let s = status(c, url.clone()).await;
        if s != 503 {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    status(c, url).await
}

/// A reqwest client presenting the cert/key pair at `crt`/`key` (e.g. the
/// minted `ComponentCreds`), trusting only the Pki server CA.
pub fn client_from_files(
    pki: &Pki,
    crt: &std::path::Path,
    key: &std::path::Path,
) -> reqwest::Client {
    let mut pem = std::fs::read(crt).unwrap();
    pem.extend(std::fs::read(key).unwrap());
    base_builder(pki)
        .identity(reqwest::Identity::from_pem(&pem).unwrap())
        .build()
        .unwrap()
}

/// Send `method url` with an optional JSON body; the status code.
pub async fn send(
    c: &reqwest::Client,
    method: reqwest::Method,
    url: String,
    body: Option<serde_json::Value>,
) -> u16 {
    let mut r = c.request(method, url);
    if let Some(b) = body {
        r = r.json(&b);
    }
    r.send().await.unwrap().status().as_u16()
}

/// Apply `k3rs::bootstrap::objects` with the admin identity, as `k3rs
/// server`'s post-start step does.
pub async fn apply_bootstrap(e: &Env, creds: &k3rs::pki::ComponentCreds) {
    let admin =
        k3rs::util::client_from_kubeconfig(&creds.kubeconfig("admin"), Some(&e.base)).unwrap();
    k3rs::bootstrap::apply_all(&admin, &k3rs::bootstrap::objects("192.0.2.2"))
        .await
        .unwrap();
}
