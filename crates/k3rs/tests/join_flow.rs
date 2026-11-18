//! Agent join flow against a real supervisor router served over TLS
//! (port of k3s `pkg/agent/config/config.go` `get` against `pkg/server/handlers`).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use k3rs::agent::{join, JoinParams};
use k3rs::pki::Pki;
use k3rs::supervisor::{router, ClusterInfo, SupervisorState};
use k3rs::token::format_token;
use k3rs_storage::StorageBackend;

struct Server {
    _pki_dir: tempfile::TempDir,
    pki: Arc<Pki>,
    url: String,
}

async fn boot(password: &str) -> Server {
    k3rs::agent::ensure_crypto_provider();
    let d = tempfile::tempdir().unwrap();
    let pki = Arc::new(Pki::load_or_create(d.path(), &["localhost".to_string()]).unwrap());
    let st = SupervisorState {
        pki: pki.clone(),
        token_password: password.into(),
        storage: Arc::new(StorageBackend::new_memory()),
        cluster_info: ClusterInfo {
            cluster_cidr: "10.42.0.0/16".into(),
            service_cidr: "10.43.0.0/16".into(),
            cluster_dns: "10.43.0.10".into(),
        },
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
    ] {
        assert!(a.join(f).exists(), "{f} missing");
    }
    for f in [
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
    assert_eq!(c.ca_pem, s.pki.server_ca_pem());
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
