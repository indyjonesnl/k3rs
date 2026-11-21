//! TLS connector for proxying to the kubelet.
//!
//! The kubelet serves its `:10250` API (logs/exec/attach/metrics) over HTTPS.
//! The api-server proxies to `https://<nodeIP>:10250`, so this crate's
//! reverse-proxy client must speak TLS. Whether it verifies the kubelet's
//! serving certificate follows upstream's kubelet client transport
//! (`pkg/kubelet/client/kubelet_client.go` `transportConfig`, :114-128): with
//! `--kubelet-certificate-authority` the serving cert must chain to that CA
//! and match the dialed host (Go's `tls.Config` `ServerName` = the URL host,
//! so an IP is checked against the cert's IP SANs); without it the transport
//! is `Insecure` (no verification), which keeps compose/conformance stacks
//! whose kubelets present self-signed certs working. The connector still
//! handles plain `http://` targets (`.https_or_http()`).

use std::sync::Arc;

use hyper_util::client::legacy::connect::HttpConnector;

/// A hyper connector that dials both `http://` and `https://`, skipping
/// verification of the (self-signed) kubelet serving certificate.
pub type KubeletProxyConnector = hyper_rustls::HttpsConnector<HttpConnector>;

/// Standard kubeadm location of the api-server's kubelet client credential.
/// Upstream's `--kubelet-client-certificate` / `--kubelet-client-key`
/// (`pkg/kubeapiserver/options/kubeletclient`, `pkg/kubelet/client/kubelet_client.go`).
/// The kubelet authenticates incoming api-server requests (logs/exec/attach)
/// via this x509 client cert; without it the request is anonymous and a
/// vanilla kubelet (`--anonymous-auth=false`) rejects it with 401 (#1670).
const KUBELET_CLIENT_CERT: &str = "/etc/kubernetes/pki/apiserver-kubelet-client.crt";
const KUBELET_CLIENT_KEY: &str = "/etc/kubernetes/pki/apiserver-kubelet-client.key";

/// Env override for the cert path (k3rs's `--kubelet-client-certificate`;
/// k3s passes it in pkg/daemons/control/server.go).
pub const KUBELET_CLIENT_CERT_ENV: &str = "K3RS_KUBELET_CLIENT_CERT";
/// Env override for the key path (`--kubelet-client-key`).
pub const KUBELET_CLIENT_KEY_ENV: &str = "K3RS_KUBELET_CLIENT_KEY";
/// In-process `--kubelet-certificate-authority`
/// (cmd/kube-apiserver/app/options/options.go:149; k3s sets it to the server
/// CA, pkg/daemons/control/server.go:248), set once by `k3rs server` or the
/// api-server flag.
static CONFIGURED_CA: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

tokio::task_local! {
    /// A task-scoped CA that replaces [`CONFIGURED_CA`] for one future, so a
    /// test (or an embedder) can choose the CA per call without mutating
    /// process state shared with other tests.
    static SCOPED_CA: Option<std::path::PathBuf>;
}

/// Configure the kubelet serving CA in-process. May be called once.
pub fn set_kubelet_certificate_authority(path: std::path::PathBuf) -> Result<(), String> {
    CONFIGURED_CA
        .set(path)
        .map_err(|_| "kubelet certificate authority already configured".to_string())
}

/// Run `f` with `ca` as the kubelet serving CA (`None`: no CA) instead of the
/// process-wide setting. Applies to everything `f` builds on this task.
pub async fn with_kubelet_certificate_authority<F: std::future::Future>(
    ca: Option<std::path::PathBuf>,
    f: F,
) -> F::Output {
    SCOPED_CA.scope(ca, f).await
}

/// Synchronous [`with_kubelet_certificate_authority`].
pub fn with_kubelet_certificate_authority_sync<R>(
    ca: Option<std::path::PathBuf>,
    f: impl FnOnce() -> R,
) -> R {
    SCOPED_CA.sync_scope(ca, f)
}

/// The kubelet serving CA file in effect: the task-scoped one inside
/// [`with_kubelet_certificate_authority`], else the configured one. `None`
/// keeps upstream's "no CA => Insecure" default.
pub fn kubelet_certificate_authority() -> Option<std::path::PathBuf> {
    if let Ok(scoped) = SCOPED_CA.try_with(Clone::clone) {
        return scoped;
    }
    CONFIGURED_CA.get().cloned()
}

/// Load the kubelet serving CA bundle as a root store: `Ok(None)` when no CA
/// is configured, `Err` when one is configured but cannot be read or holds no
/// certificate. Upstream fails the same way (`transport.New` ->
/// `loadTLSFiles`/`rootCertPool` error, kubelet_client.go:89-111, which makes
/// `NewNodeConnectionInfoGetter` fail): a bad CA is never a silent fallback to
/// no verification. With a CA the pool is that CA alone (Go's
/// `rootCertPool(caData)`), not the system roots.
pub fn kubelet_ca_roots() -> Result<Option<rustls::RootCertStore>, String> {
    let Some(path) = kubelet_certificate_authority() else {
        return Ok(None);
    };
    let pem = std::fs::read(&path)
        .map_err(|e| format!("read kubelet certificate authority {}: {e}", path.display()))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| {
            format!(
                "parse kubelet certificate authority {}: {e}",
                path.display()
            )
        })?;
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(format!(
            "kubelet certificate authority {}: no valid certificates found",
            path.display()
        ));
    }
    Ok(Some(roots))
}

/// Where the api-server's kubelet client identity lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeletClientPaths {
    pub cert: std::path::PathBuf,
    pub key: std::path::PathBuf,
    /// True when set via the env vars: an unreadable file is then an error,
    /// not "no identity" (an explicitly configured identity must not silently
    /// degrade to anonymous).
    pub explicit: bool,
}

/// In-process configuration (the `--kubelet-client-certificate/--kubelet-client-key`
/// flag equivalent). Set once by `k3rs server`; race-free, unlike mutating the
/// process environment from inside a running multi-threaded runtime. Takes
/// precedence over the env vars and the kubeadm default.
static CONFIGURED: std::sync::OnceLock<KubeletClientPaths> = std::sync::OnceLock::new();

/// Configure the kubelet client identity in-process. May be called once; the
/// paths are treated as explicit (unreadable files are errors).
pub fn set_kubelet_client_paths(
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
) -> Result<(), String> {
    CONFIGURED
        .set(KubeletClientPaths {
            cert,
            key,
            explicit: true,
        })
        .map_err(|_| "kubelet client identity already configured".to_string())
}

/// Single resolver for the kubelet client identity paths. Both env vars set
/// selects them; neither set selects the kubeadm default; exactly one set is
/// a configuration error (like kube-apiserver's validation that the two
/// flags go together).
pub fn kubelet_client_paths() -> Result<KubeletClientPaths, String> {
    if let Some(p) = CONFIGURED.get() {
        return Ok(p.clone());
    }
    let cert = std::env::var_os(KUBELET_CLIENT_CERT_ENV).filter(|v| !v.is_empty());
    let key = std::env::var_os(KUBELET_CLIENT_KEY_ENV).filter(|v| !v.is_empty());
    match (cert, key) {
        (Some(c), Some(k)) => Ok(KubeletClientPaths {
            cert: c.into(),
            key: k.into(),
            explicit: true,
        }),
        (None, None) => Ok(KubeletClientPaths {
            cert: KUBELET_CLIENT_CERT.into(),
            key: KUBELET_CLIENT_KEY.into(),
            explicit: false,
        }),
        _ => Err(format!(
            "{KUBELET_CLIENT_CERT_ENV} and {KUBELET_CLIENT_KEY_ENV} must be set together"
        )),
    }
}

/// Read a file of the identity. Missing default-path files are `Ok(None)`;
/// missing/unreadable explicit ones are errors.
fn read_identity_file(path: &std::path::Path, explicit: bool) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(_) if !explicit => Ok(None),
        Err(e) => Err(format!(
            "read kubelet client credential {}: {e}",
            path.display()
        )),
    }
}

/// Load the api-server's kubelet client identity (cert chain + key). `Ok(None)`
/// when the default kubeadm files are absent (the connector then uses
/// `.with_no_client_auth()`); `Err` for a half-set/unreadable/invalid explicit
/// configuration.
fn load_kubelet_client_identity() -> Result<
    Option<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )>,
    String,
> {
    let p = kubelet_client_paths()?;
    let Some(cert_pem) = read_identity_file(&p.cert, p.explicit)? else {
        return Ok(None);
    };
    let Some(key_pem) = read_identity_file(&p.key, p.explicit)? else {
        return Ok(None);
    };
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .filter_map(Result::ok)
        .collect();
    if certs.is_empty() {
        let msg = format!(
            "kubelet client cert {} contained no certificates",
            p.cert.display()
        );
        if p.explicit {
            return Err(msg);
        }
        tracing::warn!("{msg}");
        return Ok(None);
    }
    match rustls_pemfile::private_key(&mut key_pem.as_slice()) {
        Ok(Some(k)) => Ok(Some((certs, k))),
        _ => {
            let msg = format!(
                "kubelet client key {} contained no private key",
                p.key.display()
            );
            if p.explicit {
                return Err(msg);
            }
            tracing::warn!("{msg}");
            Ok(None)
        }
    }
}

/// The api-server's kubelet client identity (certificate chain then key, PEM),
/// for a caller that builds its own TLS config. `Ok(None)` when the default
/// files are absent; `Err` on a misconfigured explicit identity.
pub fn kubelet_client_identity_pem() -> Result<Option<Vec<u8>>, String> {
    let p = kubelet_client_paths()?;
    let Some(mut pem) = read_identity_file(&p.cert, p.explicit)? else {
        return Ok(None);
    };
    pem.push(b'\n');
    let Some(key) = read_identity_file(&p.key, p.explicit)? else {
        return Ok(None);
    };
    pem.extend_from_slice(&key);
    Ok(Some(pem))
}

/// The api-server's kubelet client TLS config (`KubeletClientConfig.transportConfig`
/// and `makeTransport`, kubelet_client.go:89-128): the serving cert is verified
/// against `--kubelet-certificate-authority` when one is configured and
/// `insecure_skip_tls_verify` is false (the `InsecureSkipTLSVerifyTransport`
/// clears the CA and sets `Insecure`, :93-96); otherwise it is not verified.
/// Presents the api-server's kubelet client identity when there is one.
pub fn kubelet_tls_config(insecure_skip_tls_verify: bool) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default TLS protocol versions");
    // Load the CA even for the insecure transport: upstream builds both
    // transports at startup, so a bad CA fails either way.
    let roots = kubelet_ca_roots().map_err(|e| format!("kubelet certificate authority: {e}"))?;
    let builder = match roots {
        Some(roots) if !insecure_skip_tls_verify => {
            let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .map_err(|e| format!("kubelet certificate authority: {e}"))?;
            builder.with_webpki_verifier(verifier)
        }
        _ => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify)),
    };

    // A misconfigured explicit identity (half-set env, unreadable or invalid
    // files) is an error rather than silently proxying anonymously: the
    // kubelet would 401 every exec/logs call with no hint why. Callers map it
    // to a 500 with this message.
    match load_kubelet_client_identity() {
        Ok(Some((certs, key))) => {
            tracing::info!("kubelet proxy: presenting kubelet client cert");
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("invalid kubelet client cert/key: {e}"))
        }
        Ok(None) => Ok(builder.with_no_client_auth()),
        Err(e) => Err(format!("kubelet client identity misconfigured: {e}")),
    }
}

fn connector_from(tls: rustls::ClientConfig) -> KubeletProxyConnector {
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build()
}

/// Build the shared kubelet-proxy connector (`ConnectionInfo.Transport`):
/// verifies the kubelet serving cert when `--kubelet-certificate-authority`
/// is configured, and presents the api-server's kubelet client cert when it
/// exists so a vanilla kubelet authenticates the api-server.
pub fn kubelet_proxy_connector() -> Result<KubeletProxyConnector, String> {
    kubelet_tls_config(false).map(connector_from)
}

/// `ConnectionInfo.InsecureSkipTLSVerifyTransport`: used only for pod logs
/// with `insecureSkipTLSVerifyBackend=true` (pkg/registry/core/pod/strategy.go:667-669).
pub fn kubelet_proxy_connector_insecure() -> Result<KubeletProxyConnector, String> {
    kubelet_tls_config(true).map(connector_from)
}

/// Accept any server certificate. The kubelet presents a self-signed serving
/// cert; the api-server→kubelet trust model does not verify it (matches the
/// reqwest `danger_accept_invalid_certs` log client and upstream defaults).
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn clear() {
        std::env::remove_var(KUBELET_CLIENT_CERT_ENV);
        std::env::remove_var(KUBELET_CLIENT_KEY_ENV);
    }

    /// A CA and a kubelet serving cert it signed for `sans` (like the
    /// supervisor's `serving-kubelet.crt`: node name + node IP SANs).
    struct Pki {
        ca_pem: String,
        cert_pem: String,
        key_pem: String,
    }

    fn mint(sans: &[&str]) -> Pki {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-server-ca");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        Pki {
            ca_pem: ca.pem(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    /// A one-shot HTTPS "kubelet" on 127.0.0.1 presenting `pki`'s cert.
    async fn serve(pki: &Pki) -> std::net::SocketAddr {
        let certs: Vec<_> = rustls_pemfile::certs(&mut pki.cert_pem.as_bytes())
            .map(Result::unwrap)
            .collect();
        let key = rustls_pemfile::private_key(&mut pki.key_pem.as_bytes())
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
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = [0u8; 4096];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        addr
    }

    async fn get(connector: KubeletProxyConnector, url: String) -> Result<u16, String> {
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build::<_, http_body_util::Empty<axum::body::Bytes>>(connector);
        client
            .get(url.parse().unwrap())
            .await
            .map(|r| r.status().as_u16())
            .map_err(|e| format!("{e:?}"))
    }

    fn write_ca(dir: &tempfile::TempDir, pem: &str) -> std::path::PathBuf {
        let p = dir.path().join("server-ca.crt");
        std::fs::write(&p, pem).unwrap();
        p
    }

    /// `--kubelet-certificate-authority` set: a kubelet presenting a cert
    /// signed by that CA for the dialed IP is reached.
    #[tokio::test]
    #[serial]
    async fn ca_verifies_kubelet_serving_cert_for_dialed_ip() {
        clear();
        let pki = mint(&["node1", "127.0.0.1"]);
        let addr = serve(&pki).await;
        let dir = tempfile::tempdir().unwrap();
        let r = with_kubelet_certificate_authority(Some(write_ca(&dir, &pki.ca_pem)), async {
            get(
                kubelet_proxy_connector().unwrap(),
                format!("https://{addr}/"),
            )
            .await
        })
        .await;
        assert_eq!(r, Ok(200));
    }

    /// A kubelet whose cert comes from another CA is refused.
    #[tokio::test]
    #[serial]
    async fn ca_refuses_kubelet_cert_from_another_ca() {
        clear();
        let kubelet = mint(&["node1", "127.0.0.1"]);
        let other = mint(&["node1", "127.0.0.1"]);
        let addr = serve(&kubelet).await;
        let dir = tempfile::tempdir().unwrap();
        let r = with_kubelet_certificate_authority(Some(write_ca(&dir, &other.ca_pem)), async {
            get(
                kubelet_proxy_connector().unwrap(),
                format!("https://{addr}/"),
            )
            .await
        })
        .await;
        let e = r.expect_err("a cert from another CA must be refused");
        assert!(e.contains("InvalidCertificate"), "{e}");
    }

    /// The cert must match the address dialed (Go `ServerName` = URL host):
    /// right CA, but the cert names a different IP.
    #[tokio::test]
    #[serial]
    async fn ca_refuses_kubelet_cert_for_another_address() {
        clear();
        let pki = mint(&["node2", "10.9.9.9"]);
        let addr = serve(&pki).await;
        let dir = tempfile::tempdir().unwrap();
        let r = with_kubelet_certificate_authority(Some(write_ca(&dir, &pki.ca_pem)), async {
            get(
                kubelet_proxy_connector().unwrap(),
                format!("https://{addr}/"),
            )
            .await
        })
        .await;
        let e = r.expect_err("a cert for another address must be refused");
        assert!(e.contains("NotValidForName"), "{e}");
    }

    /// No CA configured: upstream's `Insecure` transport, unchanged default.
    #[tokio::test]
    #[serial]
    async fn no_ca_does_not_verify() {
        clear();
        let pki = mint(&["somewhere-else"]);
        let addr = serve(&pki).await;
        let r = get(
            kubelet_proxy_connector().unwrap(),
            format!("https://{addr}/"),
        )
        .await;
        assert_eq!(r, Ok(200));
    }

    /// `insecureSkipTLSVerifyBackend`: the insecure transport skips the CA.
    #[tokio::test]
    #[serial]
    async fn insecure_transport_skips_ca() {
        clear();
        let kubelet = mint(&["node1", "127.0.0.1"]);
        let other = mint(&["node1"]);
        let addr = serve(&kubelet).await;
        let dir = tempfile::tempdir().unwrap();
        let r = with_kubelet_certificate_authority(Some(write_ca(&dir, &other.ca_pem)), async {
            get(
                kubelet_proxy_connector_insecure().unwrap(),
                format!("https://{addr}/"),
            )
            .await
        })
        .await;
        assert_eq!(r, Ok(200));
    }

    /// A configured CA that cannot be read, or holds no certificate, is a
    /// hard error for both transports, never a fallback to no verification.
    #[test]
    #[serial]
    fn bad_ca_is_an_error() {
        clear();
        with_kubelet_certificate_authority_sync(Some("/nonexistent/ca.crt".into()), || {
            assert!(kubelet_proxy_connector().is_err());
            assert!(kubelet_proxy_connector_insecure().is_err());
        });
        let dir = tempfile::tempdir().unwrap();
        with_kubelet_certificate_authority_sync(Some(write_ca(&dir, "not a pem")), || {
            let e = kubelet_ca_roots().expect_err("garbage CA");
            assert!(e.contains("no valid certificates"), "{e}");
            assert!(kubelet_proxy_connector().is_err());
        });
    }

    /// The scope replaces the process-wide CA only inside it.
    #[test]
    fn scoped_ca_applies_only_inside_the_scope() {
        let p = std::path::PathBuf::from("/scoped/ca.crt");
        let inside =
            with_kubelet_certificate_authority_sync(Some(p.clone()), kubelet_certificate_authority);
        assert_eq!(inside, Some(p));
        assert_eq!(
            with_kubelet_certificate_authority_sync(None, kubelet_certificate_authority),
            None
        );
        assert_eq!(
            kubelet_certificate_authority(),
            CONFIGURED_CA.get().cloned()
        );
    }

    // Regression for #1644: the kubelet-proxy connector must build (TLS wiring
    // intact) so the api-server can proxy logs/exec/attach to the HTTPS kubelet.
    #[test]
    #[serial]
    fn connector_builds() {
        clear();
        assert!(kubelet_proxy_connector().is_ok());
    }

    #[test]
    #[serial]
    fn unset_uses_kubeadm_default_path() {
        clear();
        let p = kubelet_client_paths().unwrap();
        assert_eq!(p.cert, std::path::Path::new(KUBELET_CLIENT_CERT));
        assert_eq!(p.key, std::path::Path::new(KUBELET_CLIENT_KEY));
        assert!(!p.explicit);
    }

    #[test]
    #[serial]
    fn env_set_loads_identity_from_those_paths() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("c.crt");
        let key = dir.path().join("c.key");
        std::fs::write(&cert, "CERTPEM").unwrap();
        std::fs::write(&key, "KEYPEM").unwrap();
        std::env::set_var(KUBELET_CLIENT_CERT_ENV, &cert);
        std::env::set_var(KUBELET_CLIENT_KEY_ENV, &key);
        let p = kubelet_client_paths().unwrap();
        assert_eq!(
            (p.cert.clone(), p.key.clone(), p.explicit),
            (cert, key, true)
        );
        assert_eq!(
            kubelet_client_identity_pem().unwrap().unwrap(),
            b"CERTPEM\nKEYPEM".to_vec()
        );
        clear();
    }

    #[test]
    #[serial]
    fn half_set_is_an_error() {
        clear();
        std::env::set_var(KUBELET_CLIENT_CERT_ENV, "/x.crt");
        assert!(kubelet_client_paths().is_err());
        assert!(kubelet_client_identity_pem().is_err());
        assert!(load_kubelet_client_identity().is_err());
        assert!(kubelet_proxy_connector().is_err());
        clear();
        std::env::set_var(KUBELET_CLIENT_KEY_ENV, "/x.key");
        assert!(kubelet_client_paths().is_err());
        clear();
    }

    #[test]
    #[serial]
    fn explicit_but_missing_file_is_an_error() {
        clear();
        std::env::set_var(KUBELET_CLIENT_CERT_ENV, "/nonexistent/c.crt");
        std::env::set_var(KUBELET_CLIENT_KEY_ENV, "/nonexistent/c.key");
        assert!(kubelet_client_identity_pem().is_err());
        assert!(load_kubelet_client_identity().is_err());
        clear();
    }
}
