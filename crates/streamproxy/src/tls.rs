//! TLS connector for proxying to the kubelet.
//!
//! The kubelet serves its `:10250` API (logs/exec/attach/metrics) over HTTPS
//! with a self-signed serving certificate (#1644). The api-server proxies to
//! `https://<nodeIP>:10250`, so this crate's reverse-proxy client must speak
//! TLS — and must NOT verify the kubelet's self-signed cert (upstream's default
//! posture; no `--kubelet-certificate-authority`). The connector still handles
//! plain `http://` targets (`.https_or_http()`), so existing callers are
//! unaffected.

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

/// Single resolver for the kubelet client identity paths. Both env vars set
/// selects them; neither set selects the kubeadm default; exactly one set is
/// a configuration error (like kube-apiserver's validation that the two
/// flags go together).
pub fn kubelet_client_paths() -> Result<KubeletClientPaths, String> {
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

/// Build the shared kubelet-proxy connector. Presents the kubeadm
/// `apiserver-kubelet-client` cert when it exists so a vanilla kubelet
/// authenticates the api-server; otherwise no client auth (k3rs' own
/// kubelet does not require it).
pub fn kubelet_proxy_connector() -> KubeletProxyConnector {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("aws-lc-rs supports the default TLS protocol versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerify));

    // A misconfigured explicit identity (half-set env, unreadable or invalid
    // files) panics here rather than silently proxying anonymously: the
    // kubelet would 401 every exec/logs call with no hint why.
    let tls = match load_kubelet_client_identity() {
        Ok(Some((certs, key))) => {
            tracing::info!("kubelet proxy: presenting kubelet client cert");
            builder
                .with_client_auth_cert(certs, key)
                .expect("valid kubelet client cert/key")
        }
        Ok(None) => builder.with_no_client_auth(),
        Err(e) => panic!("kubelet client identity misconfigured: {e}"),
    };

    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build()
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

    // Regression for #1644: the kubelet-proxy connector must build (TLS wiring
    // intact) so the api-server can proxy logs/exec/attach to the HTTPS kubelet.
    #[test]
    #[serial]
    fn connector_builds() {
        clear();
        let _ = kubelet_proxy_connector();
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
