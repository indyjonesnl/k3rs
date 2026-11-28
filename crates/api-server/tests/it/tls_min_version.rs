//! `--tls-min-version` / `--tls-cipher-suites` enforced on the serving
//! listener (apiserver/pkg/server/options/serving.go:186-193; test shape from
//! server/secure_serving_test.go `TestNewSecureServingMinVersion`-style
//! handshakes): a client that only speaks TLS 1.2 must be refused when the
//! minimum is VersionTLS13, and the default policy must keep accepting it.
use std::sync::Arc;

use kubernetes_rs_common::tls::{TlsConfig, TlsPolicy};
use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// The generated serving cert is a CA (`is_ca`), which webpki refuses as an
/// end entity (`CaUsedAsEndEntity`); the test is about protocol versions and
/// suites, so the client accepts any certificate and still checks signatures.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn handshake(
    server_policy: TlsPolicy,
    client_versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<(), String> {
    let tls = TlsConfig::generate_self_signed("tls-min-version", vec!["localhost".into()]).unwrap();
    let server_cfg = tls.into_server_config_with_policy(&server_policy).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        match acceptor.accept(sock).await {
            Ok(mut s) => {
                let _ = s.shutdown().await;
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    });

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(client_versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let sock = TcpStream::connect(addr).await.unwrap();
    let client = connector
        .connect(ServerName::try_from("localhost").unwrap(), sock)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    let server = server.await.unwrap();
    // Either side failing is a failed handshake.
    client.and(server)
}

#[tokio::test]
async fn tls_min_version_default_accepts_tls12_client() {
    handshake(TlsPolicy::default(), &[&rustls::version::TLS12])
        .await
        .expect("TLS 1.2 client under the default minimum");
}

#[tokio::test]
async fn tls_min_version_tls13_refuses_tls12_client() {
    let policy = TlsPolicy {
        tls13_only: true,
        cipher_suites: vec![],
    };
    let err = handshake(policy, &[&rustls::version::TLS12])
        .await
        .expect_err("a TLS 1.2 client must be refused when the minimum is VersionTLS13");
    assert!(!err.is_empty());
}

#[tokio::test]
async fn tls_min_version_tls13_accepts_tls13_client() {
    let policy = TlsPolicy {
        tls13_only: true,
        cipher_suites: vec![],
    };
    handshake(policy, &[&rustls::version::TLS13]).await.unwrap();
}

#[tokio::test]
async fn tls_min_version_cipher_suites_restrict_tls12() {
    use rustls::crypto::aws_lc_rs::cipher_suite::{
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    };
    // The self-signed key is ECDSA; a policy of only an RSA-keyed suite leaves
    // no usable TLS 1.2 suite, so a TLS 1.2 client is refused ...
    let only_rsa = TlsPolicy {
        tls13_only: false,
        cipher_suites: vec![TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
    };
    assert!(handshake(only_rsa, &[&rustls::version::TLS12])
        .await
        .is_err());
    // ... and an ECDSA suite in the list is accepted.
    let ecdsa = TlsPolicy {
        tls13_only: false,
        cipher_suites: vec![TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384],
    };
    handshake(ecdsa, &[&rustls::version::TLS12]).await.unwrap();
}
