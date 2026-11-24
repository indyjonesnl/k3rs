//! Agent join flow against a real supervisor router served over TLS
//! (port of k3s `pkg/agent/config/config.go` `get` against `pkg/server/handlers`).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use k3rs::agent::{join, JoinParams};
use k3rs::pki::Pki;
use k3rs::supervisor::{router, ClusterInfo, LocalNode, SupervisorState};
use k3rs::token::format_token;
use k3rs_storage::{Storage, StorageBackend};

struct Server {
    _pki_dir: tempfile::TempDir,
    pki: Arc<Pki>,
    storage: Arc<StorageBackend>,
    url: String,
}

async fn boot(password: &str) -> Server {
    boot_with(password, None).await
}

async fn boot_with(password: &str, local_node: Option<LocalNode>) -> Server {
    k3rs::agent::ensure_crypto_provider();
    let d = tempfile::tempdir().unwrap();
    let pki = Arc::new(Pki::load_or_create(d.path(), &["localhost".to_string()]).unwrap());
    let storage = Arc::new(StorageBackend::new_memory());
    let st = SupervisorState {
        pki: pki.clone(),
        token_password: password.into(),
        storage: storage.clone(),
        cluster_info: ClusterInfo {
            cluster_cidr: "10.42.0.0/16".into(),
            service_cidr: "10.43.0.0/16".into(),
            cluster_dns: "10.43.0.10".into(),
        },
        local_node,
    };
    let cfg = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        pki.dir.join("serving.crt"),
        pki.dir.join("serving.key"),
    )
    .await
    .unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(l, cfg)
            .serve(router(st).into_make_service())
            .await
            .unwrap();
    });
    Server {
        _pki_dir: d,
        pki,
        storage,
        url: format!("https://127.0.0.1:{port}"),
    }
}

fn params(s: &Server, token: String, name: &str, dir: &Path) -> JoinParams {
    JoinParams {
        server: s.url.clone(),
        token,
        node_name: name.into(),
        node_ip: Some("10.0.0.5".into()),
        data_dir: dir.to_path_buf(),
    }
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn join_writes_creds_and_kubeconfigs() {
    let s = boot("pw1").await;
    let d = tempfile::tempdir().unwrap();
    let tok = format_token(&s.pki.ca_hash(), "pw1");
    let c = join(&params(&s, tok, "node-a", d.path())).await.unwrap();
    let a = d.path().join("agent");
    for f in [
        "client-kubelet.crt",
        "client-kubelet.key",
        "serving-kubelet.crt",
        "serving-kubelet.key",
        "client-kube-proxy.crt",
        "client-kube-proxy.key",
        "kubelet.kubeconfig",
        "kube-proxy.kubeconfig",
        "node-password",
        "client-ca.crt",
    ] {
        assert!(a.join(f).exists(), "{f} missing");
    }
    // `getHostFile` (k3s pkg/agent/config/config.go:275-284): the server's
    // client CA, written 0600, is the kubelet API's x509 client CA.
    assert_eq!(
        std::fs::read_to_string(a.join("client-ca.crt")).unwrap(),
        s.pki.client_ca_pem()
    );
    assert_eq!(c.client_ca, a.join("client-ca.crt"));
    for f in [
        "client-ca.crt",
        "client-kubelet.key",
        "serving-kubelet.key",
        "client-kube-proxy.key",
        "node-password",
    ] {
        assert_eq!(mode(&a.join(f)), 0o600, "{f}");
    }
    let pw = std::fs::read_to_string(a.join("node-password")).unwrap();
    assert_eq!(pw.trim().len(), 32);
    assert!(pw.trim().chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(
        ::pem::parse(&c.ca_pem).unwrap().contents(),
        ::pem::parse(s.pki.server_ca_pem()).unwrap().contents()
    );
    assert_eq!(c.cluster.cluster_dns, "10.43.0.10");
    assert_eq!(c.kubelet_kubeconfig, a.join("kubelet.kubeconfig"));
    assert_eq!(c.kube_proxy_kubeconfig, a.join("kube-proxy.kubeconfig"));

    let kc = k3rs_client::kubeconfig::KubeConfig::load_from_file(&c.kubelet_kubeconfig).unwrap();
    assert_eq!(kc.clusters[0].cluster.server, s.url);
    assert!(kc.clusters[0].cluster.certificate_authority_data.is_some());
    assert!(kc.users[0].user.client_certificate.is_some());
    k3rs_client::kubeconfig::KubeConfig::load_from_file(&c.kube_proxy_kubeconfig).unwrap();

    // Client cert chains to the client CA and has the node identity.
    use x509_parser::prelude::*;
    let leaf = ::pem::parse_many(std::fs::read_to_string(a.join("client-kubelet.crt")).unwrap())
        .unwrap()
        .remove(0);
    let (_, cert) = X509Certificate::from_der(leaf.contents()).unwrap();
    let ca = ::pem::parse(s.pki.client_ca_pem()).unwrap();
    let (_, ca_cert) = X509Certificate::from_der(ca.contents()).unwrap();
    cert.verify_signature(Some(ca_cert.public_key())).unwrap();
    assert!(cert.subject().to_string().contains("system:node:node-a"));
}

#[tokio::test]
async fn wrong_ca_hash_refused() {
    let s = boot("pw1").await;
    let d = tempfile::tempdir().unwrap();
    let tok = format_token(&"ab".repeat(32), "pw1");
    let e = join(&params(&s, tok, "node-a", d.path()))
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("CA hash mismatch"), "{e:#}");
    assert!(!d.path().join("agent/client-kubelet.crt").exists());
}

#[tokio::test]
async fn bare_secret_token_warns_and_joins() {
    let s = boot("bare-secret").await;
    let d = tempfile::tempdir().unwrap();
    let c = join(&params(&s, "bare-secret".into(), "node-a", d.path()))
        .await
        .unwrap();
    assert!(c.kubelet_kubeconfig.exists());
}

#[tokio::test]
async fn rejoin_same_data_dir_ok() {
    let s = boot("pw1").await;
    let d = tempfile::tempdir().unwrap();
    let tok = format_token(&s.pki.ca_hash(), "pw1");
    join(&params(&s, tok.clone(), "node-a", d.path()))
        .await
        .unwrap();
    let pw1 = std::fs::read_to_string(d.path().join("agent/node-password")).unwrap();
    join(&params(&s, tok, "node-a", d.path())).await.unwrap();
    let pw2 = std::fs::read_to_string(d.path().join("agent/node-password")).unwrap();
    assert_eq!(pw1, pw2);
}

#[tokio::test]
async fn rejoin_wiped_dir_same_name_403_names_the_conflict() {
    let s = boot("pw1").await;
    let tok = format_token(&s.pki.ca_hash(), "pw1");
    let d1 = tempfile::tempdir().unwrap();
    join(&params(&s, tok.clone(), "node-a", d1.path()))
        .await
        .unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let e = join(&params(&s, tok, "node-a", d2.path()))
        .await
        .unwrap_err();
    let m = format!("{e:#}");
    assert!(
        m.contains("node password rejected for node \"node-a\""),
        "{m}"
    );
    assert!(m.contains("duplicate hostname"), "{m}");
}

#[tokio::test]
async fn wrong_token_fails_401() {
    let s = boot("pw1").await;
    let d = tempfile::tempdir().unwrap();
    let tok = format_token(&s.pki.ca_hash(), "WRONG");
    let e = join(&params(&s, tok, "node-a", d.path()))
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("401"), "{e:#}");
}

#[tokio::test]
async fn multi_cert_cacerts_bundle_refused_before_any_authed_request() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    k3rs::agent::ensure_crypto_provider();
    let d = tempfile::tempdir().unwrap();
    let pki = Pki::load_or_create(d.path(), &["localhost".to_string()]).unwrap();
    let real = pki.server_ca_pem().to_string();
    let other = pki.client_ca_pem().to_string();
    let bundle = format!("{real}{other}");
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let app = axum::Router::new()
        .route(
            "/cacerts",
            axum::routing::get(move || async move { bundle }),
        )
        .fallback(move || {
            let h = h.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                "x"
            }
        });
    let cfg = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        pki.dir.join("serving.crt"),
        pki.dir.join("serving.key"),
    )
    .await
    .unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(l, cfg)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    let out = tempfile::tempdir().unwrap();
    let p = JoinParams {
        server: format!("https://127.0.0.1:{port}"),
        // hash of the FIRST cert matches: the old code would have joined
        token: format_token(&pki.ca_hash(), "pw"),
        node_name: "n".into(),
        node_ip: None,
        data_dir: out.path().to_path_buf(),
    };
    let e = join(&p).await.unwrap_err();
    assert!(format!("{e:#}").contains("exactly one"), "{e:#}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "authed request was sent");
}

#[tokio::test]
async fn http_scheme_refused() {
    let s = boot("pw1").await;
    let d = tempfile::tempdir().unwrap();
    let mut p = params(&s, "pw1".into(), "node-a", d.path());
    p.server = s.url.replacen("https://", "http://", 1);
    let e = join(&p).await.unwrap_err();
    assert!(format!("{e:#}").contains("insecure"), "{e:#}");
}

#[tokio::test]
async fn bare_host_port_defaults_to_https() {
    let s = boot("pw1").await;
    let d = tempfile::tempdir().unwrap();
    let mut p = params(
        &s,
        format_token(&s.pki.ca_hash(), "pw1"),
        "node-a",
        d.path(),
    );
    p.server = s.url.trim_start_matches("https://").to_string();
    join(&p).await.unwrap();
}

// --- The server's own node name (k3s pkg/nodepassword/validate.go:62-64,
// `verifyLocalPassword` :127-166). A join token holder must not be able to
// claim the server's node identity by being first to present a password.

const SERVER_NODE: &str = "server-a";
const SERVER_NODE_PW: &str = "0123456789abcdef0123456789abcdef";

/// A supervisor whose own node is `server-a`, with that node's password file
/// written like `k3rs server` does (agent `ensure_node_password`).
async fn boot_server_node() -> (Server, tempfile::TempDir) {
    let nd = tempfile::tempdir().unwrap();
    let password_file = nd.path().join("node-password");
    std::fs::write(&password_file, format!("{SERVER_NODE_PW}\n")).unwrap();
    let s = boot_with("pw1", Some(LocalNode::new(SERVER_NODE, password_file))).await;
    (s, nd)
}

/// Raw `POST /v1-k3rs/<which>.crt` with a fresh CSR, as an agent sends it
/// (k3s pkg/agent/config/config.go `getNodeNamedCrt`).
async fn post_node_cert(s: &Server, which: &str, node: &str, pass: &str) -> reqwest::StatusCode {
    let kp = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::default();
    p.distinguished_name = rcgen::DistinguishedName::new();
    let csr = p.serialize_request(&kp).unwrap().der().to_vec();
    let ca = reqwest::Certificate::from_pem(s.pki.server_ca_pem().as_bytes()).unwrap();
    let http = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .build()
        .unwrap();
    http.post(format!("{}/v1-k3rs/{which}.crt", s.url))
        .basic_auth("server", Some("pw1"))
        .header("k3rs-Node-Name", node)
        .header("k3rs-Node-Password", pass)
        .body(csr)
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn server_node_name_with_unknown_password_403() {
    let (s, _nd) = boot_server_node().await;
    for which in ["client-kubelet", "serving-kubelet"] {
        assert_eq!(
            post_node_cert(&s, which, SERVER_NODE, "attacker-password").await,
            403,
            "{which}: first caller must not win the server's node name"
        );
        // Header names are lowercased by `getNodeInfo` (validate.go:119).
        assert_eq!(
            post_node_cert(&s, which, "SERVER-A", "attacker-password").await,
            403,
            "{which} (uppercase name)"
        );
    }
    // A rejected request must not have planted a node-password Secret.
    let key = "/registry/secrets/kube-system/server-a.node-password.k3rs";
    assert!(s
        .storage
        .get::<k3rs_common::resources::Secret>(key)
        .await
        .is_err());
}

#[tokio::test]
async fn server_node_name_with_local_password_ok_and_attacker_still_403() {
    let (s, _nd) = boot_server_node().await;
    // Attacker first, then the real node password, then the attacker again:
    // trust-on-first-use never applies to the server's own node name.
    assert_eq!(
        post_node_cert(&s, "client-kubelet", SERVER_NODE, "attacker").await,
        403
    );
    for which in ["client-kubelet", "serving-kubelet"] {
        assert_eq!(
            post_node_cert(&s, which, SERVER_NODE, SERVER_NODE_PW).await,
            200,
            "{which}"
        );
    }
    assert_eq!(
        post_node_cert(&s, "serving-kubelet", SERVER_NODE, "attacker").await,
        403
    );
    // A full agent join holding the server's node-password file also works
    // (validate.go:152 compares with the file's trimmed contents).
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("agent")).unwrap();
    std::fs::write(
        d.path().join("agent/node-password"),
        format!("{SERVER_NODE_PW}\n"),
    )
    .unwrap();
    let tok = format_token(&s.pki.ca_hash(), "pw1");
    join(&params(&s, tok, SERVER_NODE, d.path())).await.unwrap();
    // `go ensureSecret` (validate.go:161): the Secret follows the local file.
    let key = "/registry/secrets/kube-system/server-a.node-password.k3rs";
    let mut found = false;
    for _ in 0..50 {
        if s.storage
            .get::<k3rs_common::resources::Secret>(key)
            .await
            .is_ok()
        {
            found = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        found,
        "node-password Secret for the server node not ensured"
    );
}

#[tokio::test]
async fn server_node_name_join_with_other_password_file_403() {
    let (s, _nd) = boot_server_node().await;
    let d = tempfile::tempdir().unwrap();
    let tok = format_token(&s.pki.ca_hash(), "pw1");
    let e = join(&params(&s, tok, SERVER_NODE, d.path()))
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("403"), "{e:#}");
    assert!(!d.path().join("agent/client-kubelet.crt").exists());
}

#[tokio::test]
async fn other_node_name_still_joins_next_to_server_node() {
    let (s, _nd) = boot_server_node().await;
    let d = tempfile::tempdir().unwrap();
    let tok = format_token(&s.pki.ca_hash(), "pw1");
    join(&params(&s, tok.clone(), "node-b", d.path()))
        .await
        .unwrap();
    // ...and keeps trust-on-first-use semantics (nodepassword.go `ensure`).
    let d2 = tempfile::tempdir().unwrap();
    let e = join(&params(&s, tok, "node-b", d2.path()))
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("duplicate hostname"), "{e:#}");
}
