//! api-server -> kubelet serving-cert verification on the log path
//! (`--kubelet-certificate-authority`).
//!
//! Upstream: `KubeletClientConfig.transportConfig` verifies against the CA when
//! set (pkg/kubelet/client/kubelet_client.go:114-128) and `LogLocation` uses
//! `InsecureSkipTLSVerifyTransport` only for `insecureSkipTLSVerifyBackend`
//! (pkg/registry/core/pod/strategy.go:667-670).

use std::sync::Arc;

use futures::StreamExt;
use k3rs_api_server::handlers::pod_subresources::{
    fetch_kubelet_log_stream, insecure_skip_tls_verify_backend,
};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Minted {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

fn mint(cn: &str, sans: &[&str]) -> Minted {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
    Minted {
        ca_pem: ca.pem(),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// An HTTPS "kubelet" answering every request with one log line.
async fn kubelet(m: &Minted) -> std::net::SocketAddr {
    let certs: Vec<_> = rustls_pemfile::certs(&mut m.cert_pem.as_bytes())
        .map(Result::unwrap)
        .collect();
    let key = rustls_pemfile::private_key(&mut m.key_pem.as_bytes())
        .unwrap()
        .unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nline1\n",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

async fn fetch(addr: std::net::SocketAddr, insecure: bool) -> Result<Vec<u8>, String> {
    let target: axum::http::Uri = format!("https://{addr}/containerLogs/ns/p/c")
        .parse()
        .unwrap();
    match fetch_kubelet_log_stream(&target, "p", None, insecure).await {
        Err(e) => Err(e.to_string()),
        Ok(Err(resp)) => Err(format!("kubelet refused: {}", resp.status())),
        Ok(Ok(mut s)) => {
            let mut got = Vec::new();
            while let Some(c) = s.next().await {
                got.extend_from_slice(&c.unwrap());
            }
            Ok(got)
        }
    }
}

#[tokio::test]
#[serial]
async fn log_fetch_verifies_kubelet_serving_cert_against_configured_ca() {
    let good = mint("server-ca", &["node1", "127.0.0.1"]);
    let rogue = mint("rogue-ca", &["node1", "127.0.0.1"]);
    let ca = std::env::temp_dir().join(format!(
        "k3rs-kubelet-ca-{}-{}.crt",
        std::process::id(),
        line!()
    ));
    std::fs::write(&ca, &good.ca_pem).unwrap();
    std::env::set_var(k3rs_streamproxy::KUBELET_CERTIFICATE_AUTHORITY_ENV, &ca);

    let ok = fetch(kubelet(&good).await, false).await;
    let refused = fetch(kubelet(&rogue).await, false).await;
    let skipped = fetch(kubelet(&rogue).await, true).await;
    std::env::remove_var(k3rs_streamproxy::KUBELET_CERTIFICATE_AUTHORITY_ENV);

    assert_eq!(ok.unwrap(), b"line1\n");
    let e = refused.expect_err("a kubelet cert from another CA is refused");
    assert!(e.contains("InvalidCertificate"), "{e}");
    // insecureSkipTLSVerifyBackend=true selects the insecure transport.
    assert_eq!(skipped.unwrap(), b"line1\n");
}

#[tokio::test]
#[serial]
async fn log_fetch_without_ca_keeps_unverified_default() {
    std::env::remove_var(k3rs_streamproxy::KUBELET_CERTIFICATE_AUTHORITY_ENV);
    let any = mint("whatever", &["elsewhere"]);
    assert_eq!(fetch(kubelet(&any).await, false).await.unwrap(), b"line1\n");
}

#[test]
fn insecure_skip_tls_verify_backend_follows_query_bool_conversion() {
    assert!(!insecure_skip_tls_verify_backend(""));
    assert!(!insecure_skip_tls_verify_backend("container=c"));
    assert!(insecure_skip_tls_verify_backend(
        "container=c&insecureSkipTLSVerifyBackend=true"
    ));
    assert!(insecure_skip_tls_verify_backend(
        "insecureSkipTLSVerifyBackend=1"
    ));
    assert!(insecure_skip_tls_verify_backend(
        "insecureSkipTLSVerifyBackend"
    ));
    assert!(!insecure_skip_tls_verify_backend(
        "insecureSkipTLSVerifyBackend=false"
    ));
    assert!(!insecure_skip_tls_verify_backend(
        "insecureSkipTLSVerifyBackend=0"
    ));
    // First value wins (`(*in)[0]`).
    assert!(!insecure_skip_tls_verify_backend(
        "insecureSkipTLSVerifyBackend=0&insecureSkipTLSVerifyBackend=1"
    ));
}

fn node(name: &str, kubelet_port: u16) -> k3rs_common::resources::Node {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1", "kind": "Node",
        "metadata": {"name": name},
        "status": {
            "addresses": [{"type": "InternalIP", "address": "127.0.0.1"}],
            "daemonEndpoints": {"kubeletEndpoint": {"Port": kubelet_port}}
        }
    }))
    .unwrap()
}

/// `nodes/proxy` to the kubelet port rides the kubelet client transport
/// (`ResourceLocation`, pkg/registry/core/node/strategy.go:260-274), so the
/// serving cert is verified; any other port uses the unverified
/// `ProxyTransport`.
#[tokio::test]
#[serial]
async fn node_proxy_to_kubelet_port_verifies_serving_cert() {
    use k3rs_storage::{build_key, Storage};
    let good = mint("server-ca", &["n", "127.0.0.1"]);
    let rogue = mint("rogue-ca", &["n", "127.0.0.1"]);
    let ca = std::env::temp_dir().join(format!(
        "k3rs-kubelet-ca-{}-{}.crt",
        std::process::id(),
        line!()
    ));
    std::fs::write(&ca, &good.ca_pem).unwrap();
    std::env::set_var(k3rs_streamproxy::KUBELET_CERTIFICATE_AUTHORITY_ENV, &ca);

    let good_port = kubelet(&good).await.port();
    let rogue_port = kubelet(&rogue).await.port();
    let api = k3rs_test_support::harness::TestApiServer::new();
    for (n, p) in [("good", good_port), ("rogue", rogue_port)] {
        api.storage
            .create(&build_key("nodes", None, n), &node(n, p))
            .await
            .unwrap();
    }
    let get = |uri: String| {
        let api = &api;
        async move {
            let (s, _, b, _) = api.send_full("GET", &uri, None, None, None).await;
            (s.as_u16(), String::from_utf8_lossy(&b).to_string())
        }
    };
    let ok = get("/api/v1/nodes/good/proxy/pods".into()).await;
    let refused = get("/api/v1/nodes/rogue/proxy/pods".into()).await;
    let refused_explicit = get(format!("/api/v1/nodes/rogue:{rogue_port}/proxy/pods")).await;
    // A non-kubelet port: `proxyTransport`, not verified.
    let other_port = get(format!("/api/v1/nodes/good:{rogue_port}/proxy/pods")).await;
    std::env::remove_var(k3rs_streamproxy::KUBELET_CERTIFICATE_AUTHORITY_ENV);

    assert_eq!(ok.0, 200, "{}", ok.1);
    assert_eq!(ok.1, "line1\n");
    assert_ne!(
        refused.0, 200,
        "rogue kubelet cert must be refused: {}",
        refused.1
    );
    assert_ne!(refused_explicit.0, 200, "{}", refused_explicit.1);
    assert_eq!(other_port.0, 200, "{}", other_port.1);
}
