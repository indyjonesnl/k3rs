//! The authenticated kubelet API (`run_with_auth` / `kubelet_api_serving`):
//! the k3s kubelet posture (pkg/daemons/agent/agent.go:199-236) wired through
//! `server_auth` (cmd/kubelet/app/auth.go `BuildAuth`) and the file-backed
//! serving cert (cmd/kubelet/app/server.go `InitializeTLS`).

use axum::routing::post;
use axum::{Json, Router};
use k3rs_client::http::ApiClient;
use k3rs_kubelet::{
    api_router, kubelet_api_serving, run_with_auth, serve_kubelet_api, KubeletApiAuth,
    KubeletConfig,
};
use k3rs_storage::StorageBackend;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Pki {
    ca_pem: String,
    ca: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

fn pki() -> Pki {
    // installs the process-wide rustls crypto provider
    k3rs_common::tls::TlsConfig::generate_self_signed("x", vec!["x".into()]).ok();
    let mut p = rcgen::CertificateParams::default();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    p.distinguished_name
        .push(rcgen::DnType::CommonName, "test-ca");
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = p.self_signed(&ca_key).unwrap();
    Pki {
        ca_pem: ca.pem(),
        ca,
        ca_key,
    }
}

/// (cert PEM, key PEM) of a leaf for `cn`/`orgs`, client or server.
fn leaf(pki: &Pki, cn: &str, orgs: &[&str], server: bool) -> (String, String) {
    let mut p = rcgen::CertificateParams::default();
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    for o in orgs {
        p.distinguished_name
            .push(rcgen::DnType::OrganizationName, *o);
    }
    if server {
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        p.subject_alt_names = vec![
            rcgen::SanType::DnsName("localhost".try_into().unwrap()),
            rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
        ];
    } else {
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    }
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &pki.ca, &pki.ca_key).unwrap();
    (cert.pem(), key.serialize_pem())
}

/// Client CA, serving cert and serving key on disk.
struct Files {
    _dir: tempfile::TempDir,
    client_ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

fn files(client: &Pki, server: &Pki) -> Files {
    let dir = tempfile::tempdir().unwrap();
    let client_ca = dir.path().join("client-ca.crt");
    std::fs::write(&client_ca, &client.ca_pem).unwrap();
    let (c, k) = leaf(server, "node-1", &[], true);
    let cert = dir.path().join("serving-kubelet.crt");
    let key = dir.path().join("serving-kubelet.key");
    std::fs::write(&cert, c).unwrap();
    std::fs::write(&key, k).unwrap();
    Files {
        _dir: dir,
        client_ca,
        cert,
        key,
    }
}

fn auth_for(f: &Files, client: Arc<ApiClient>) -> KubeletApiAuth {
    KubeletApiAuth {
        client_ca_file: f.client_ca.to_string_lossy().into_owned(),
        api_client: client,
        serving_cert_file: f.cert.clone(),
        serving_key_file: f.key.clone(),
    }
}

/// An API client that is never reached (the failures happen first).
fn unused_client() -> Arc<ApiClient> {
    Arc::new(ApiClient::new("http://127.0.0.1:1", false, None).unwrap())
}

/// `run_with_auth` must fail before the kubelet starts; a bounded wait keeps
/// a regression (a kubelet that starts anyway) from hanging the suite.
async fn run_err(auth: KubeletApiAuth) -> String {
    let storage = Arc::new(StorageBackend::new_memory());
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        run_with_auth(storage, KubeletConfig::default(), Some(auth)),
    )
    .await
    .expect("run_with_auth must fail fast, not start the kubelet");
    format!("{:#}", res.expect_err("run_with_auth must fail"))
}

#[tokio::test]
async fn empty_client_ca_path_is_an_error() {
    let (c, s) = (pki(), pki());
    let f = files(&c, &s);
    let mut a = auth_for(&f, unused_client());
    a.client_ca_file = String::new();
    let e = run_err(a).await;
    assert!(e.contains("client CA file path is empty"), "{e}");
}

#[tokio::test]
async fn missing_client_ca_file_is_an_error() {
    let (c, s) = (pki(), pki());
    let f = files(&c, &s);
    let mut a = auth_for(&f, unused_client());
    a.client_ca_file = f
        .client_ca
        .with_extension("missing")
        .to_string_lossy()
        .into();
    let e = run_err(a).await;
    assert!(e.contains("kubelet API authentication"), "{e}");
}

#[tokio::test]
async fn empty_client_ca_file_is_an_error() {
    let (c, s) = (pki(), pki());
    let f = files(&c, &s);
    std::fs::write(&f.client_ca, "").unwrap();
    let e = run_err(auth_for(&f, unused_client())).await;
    assert!(e.contains("missing content for CA bundle"), "{e}");
}

#[tokio::test]
async fn invalid_client_ca_pem_is_an_error() {
    let (c, s) = (pki(), pki());
    let f = files(&c, &s);
    std::fs::write(&f.client_ca, "not a certificate\n").unwrap();
    let e = run_err(auth_for(&f, unused_client())).await;
    assert!(e.contains("kubelet API authentication"), "{e}");
}

#[tokio::test]
async fn missing_serving_cert_is_an_error() {
    let (c, s) = (pki(), pki());
    let f = files(&c, &s);
    std::fs::remove_file(&f.cert).unwrap();
    let e = run_err(auth_for(&f, unused_client())).await;
    assert!(e.contains("read kubelet serving cert"), "{e}");
}

#[tokio::test]
async fn missing_serving_key_is_an_error() {
    let (c, s) = (pki(), pki());
    let f = files(&c, &s);
    std::fs::remove_file(&f.key).unwrap();
    let e = run_err(auth_for(&f, unused_client())).await;
    assert!(e.contains("read kubelet serving key"), "{e}");
}

#[tokio::test]
async fn invalid_serving_cert_pem_is_an_error() {
    let (c, s) = (pki(), pki());
    let f = files(&c, &s);
    std::fs::write(&f.cert, "-----BEGIN CERTIFICATE-----\ngarbage\n").unwrap();
    let e = run_err(auth_for(&f, unused_client())).await;
    assert!(e.contains("kubelet serving cert"), "{e}");
}

#[tokio::test]
async fn mismatched_serving_key_is_an_error() {
    let (c, s) = (pki(), pki());
    let f = files(&c, &s);
    let (_, other_key) = leaf(&s, "other", &[], true);
    std::fs::write(&f.key, other_key).unwrap();
    let e = run_err(auth_for(&f, unused_client())).await;
    assert!(e.contains("kubelet serving cert"), "{e}");
}

// ---- end to end over TLS with a stub review backend ------------------------

/// A stub api-server for the kubelet's reviews: SubjectAccessReview allows
/// any user in `system:masters` and denies everyone else; TokenReview
/// authenticates nothing. Counts the SARs it answered.
async fn stub_review_api(sars: Arc<AtomicUsize>) -> String {
    let app = Router::new()
        .route(
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            post(move |Json(mut v): Json<serde_json::Value>| {
                let sars = sars.clone();
                async move {
                    sars.fetch_add(1, Ordering::SeqCst);
                    let admin = v["spec"]["groups"]
                        .as_array()
                        .map(|g| g.iter().any(|g| g == "system:masters"))
                        .unwrap_or(false);
                    v["status"] = if admin {
                        serde_json::json!({"allowed": true, "reason": "stub: admin"})
                    } else {
                        serde_json::json!({"allowed": false, "denied": true, "reason": "stub: no"})
                    };
                    (axum::http::StatusCode::CREATED, Json(v))
                }
            }),
        )
        .route(
            "/apis/authentication.k8s.io/v1/tokenreviews",
            post(|Json(mut v): Json<serde_json::Value>| async move {
                v["status"] = serde_json::json!({"authenticated": false});
                (axum::http::StatusCode::CREATED, Json(v))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// Serve the real kubelet API router (no kubelet attached) with
/// `kubelet_api_serving(Some(..))` on an ephemeral port.
async fn serve(auth: &KubeletApiAuth) -> u16 {
    let serving = kubelet_api_serving("node-1", Some(auth)).unwrap();
    let state = k3rs_kubelet::server::ServerState {
        node_name: "node-1".into(),
        storage: Arc::new(StorageBackend::new_memory()),
        kubelet: None,
    };
    let metrics = Arc::new(
        k3rs_common::observability::MetricsRegistry::new()
            .with_kubelet_metrics()
            .unwrap(),
    );
    let app = api_router(
        state,
        metrics,
        Arc::new(k3rs_kubelet::config::KubeletConfiguration::default()),
        std::env::temp_dir(),
        serving.auth.clone(),
    );
    let listener = k3rs_kubelet::bind_kubelet_api("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_kubelet_api(listener, app, serving));
    port
}

/// A client that trusts only `server_ca` (so the handshake proves which
/// serving cert was presented), with an optional client identity.
fn client(server_ca: &Pki, id: Option<(String, String)>) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(server_ca.ca_pem.as_bytes()).unwrap());
    if let Some((c, k)) = id {
        b = b.identity(reqwest::Identity::from_pem(format!("{c}{k}").as_bytes()).unwrap());
    }
    b.build().unwrap()
}

async fn status(c: &reqwest::Client, port: u16, path: &str) -> u16 {
    c.get(format!("https://localhost:{port}{path}"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_kubelet_api_end_to_end() {
    let (client_pki, server_pki) = (pki(), pki());
    let f = files(&client_pki, &server_pki);
    let sars = Arc::new(AtomicUsize::new(0));
    let base = stub_review_api(sars.clone()).await;
    let api = Arc::new(ApiClient::new(&base, false, None).unwrap());
    let port = serve(&auth_for(&f, api)).await;

    // The handshake succeeds only against the server CA that signed the
    // file-backed serving cert (not a self-signed one).
    let anon = client(&server_pki, None);
    assert_eq!(status(&anon, port, "/pods").await, 401);
    assert_eq!(status(&anon, port, "/healthz").await, 401);
    assert_eq!(sars.load(Ordering::SeqCst), 0, "401 before authorization");

    // An admin-group cert: the SAR allows it.
    let admin = client(
        &server_pki,
        Some(leaf(
            &client_pki,
            "system:apiserver",
            &["system:masters"],
            false,
        )),
    );
    assert_eq!(status(&admin, port, "/pods").await, 200);
    assert!(sars.load(Ordering::SeqCst) >= 1);

    // Another node's identity: authenticated, the SAR denies it.
    let other_node = client(
        &server_pki,
        Some(leaf(
            &client_pki,
            "system:node:node-2",
            &["system:nodes"],
            false,
        )),
    );
    assert_eq!(status(&other_node, port, "/pods").await, 403);

    // A cert from a CA the kubelet does not trust: 401, never anonymous.
    let rogue = pki();
    let bad = client(
        &server_pki,
        Some(leaf(&rogue, "system:apiserver", &["system:masters"], false)),
    );
    assert_eq!(status(&bad, port, "/pods").await, 401);
}

// The serving cert presented is the one from the files: a client trusting
// only that CA completes the handshake; one trusting another CA does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serving_cert_comes_from_files() {
    let (client_pki, server_pki) = (pki(), pki());
    let f = files(&client_pki, &server_pki);
    let port = serve(&auth_for(&f, unused_client())).await;
    let ok = client(&server_pki, None);
    assert_eq!(status(&ok, port, "/pods").await, 401);
    let wrong = client(&pki(), None);
    assert!(wrong
        .get(format!("https://localhost:{port}/pods"))
        .send()
        .await
        .is_err());
}

#[test]
fn bare_kubelet_api_serving_is_anonymous_always_allow() {
    // `None` keeps the bare all-in-one posture: it builds without any files.
    let s = kubelet_api_serving("node-1", None).unwrap();
    assert!(s.client_ca.is_none());
}
