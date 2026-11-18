//! Server PKI generation and CSR signing for `k3rs server` / `k3rs agent` join.
//!
//! File set and SANs mirror `scripts/generate-certs.sh`. CN/O/EKU of issued
//! certificates are ported from k3s `pkg/server/handlers/handlers.go`
//! (`signAndSend`, `ClientKubeletCert`, `ServingKubeletCert`,
//! `ClientKubeProxyCert`): the CSR contributes only the public key (k3s agents
//! send an empty-subject CSR, `getCSRBytes`); the subject comes from the server.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use base64::Engine;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// notBefore backdating, absorbs clock skew between server and agents.
const BACKDATE: Duration = Duration::minutes(5);
const CA_VALIDITY: Duration = Duration::days(3650);
const LEAF_VALIDITY: Duration = Duration::days(365);
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("invalid CSR: {0}")]
    BadCsr(String),
    #[error("unsupported key type (only ECDSA P-256 is accepted)")]
    UnsupportedKey,
    #[error("signing failed: {0}")]
    Sign(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaKind {
    Server,
    Client,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    ClientAuth,
    ServerAuth,
}

struct Ca {
    cert: Certificate,
    key: KeyPair,
    pem: String,
}

pub struct Pki {
    pub dir: PathBuf,
    pub client_ca_pem: String,
    server: Ca,
    client: Ca,
}

fn write_file(path: &Path, data: &str, mode: u32) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    f.write_all(data.as_bytes())?;
    Ok(())
}

fn write_key(path: &Path, kp: &KeyPair) -> Result<()> {
    write_file(path, &kp.serialize_pem(), 0o600)
}

fn dn(cn: &str, orgs: &[&str]) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    for o in orgs {
        d.push(DnType::OrganizationName, *o);
    }
    d
}

fn base_params(cn: &str, orgs: &[&str], validity: Duration) -> CertificateParams {
    let mut p = CertificateParams::default();
    let now = OffsetDateTime::now_utc();
    p.not_before = now - BACKDATE;
    p.not_after = now + validity;
    p.distinguished_name = dn(cn, orgs);
    p
}

fn new_ca(cn: &str) -> Result<Ca> {
    let key = KeyPair::generate()?;
    let mut p = base_params(cn, &[], CA_VALIDITY);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let cert = p.self_signed(&key)?;
    let pem = cert.pem();
    Ok(Ca { cert, key, pem })
}

/// Rebuild a signing handle from the persisted PEMs. The original certificate
/// PEM is kept for distribution (the re-signed handle is only used as issuer).
fn load_ca(crt: &Path, key: &Path) -> Result<Ca> {
    let pem = std::fs::read_to_string(crt)?;
    let key = KeyPair::from_pem(&std::fs::read_to_string(key)?)?;
    let params = CertificateParams::from_ca_cert_pem(&pem)?;
    let cert = params.self_signed(&key)?;
    Ok(Ca { cert, key, pem })
}

fn ensure_ca(tls: &Path, name: &str, cn: &str) -> Result<(Ca, bool)> {
    let crt = tls.join(format!("{name}.crt"));
    let key = tls.join(format!("{name}.key"));
    if crt.exists() && key.exists() {
        return Ok((load_ca(&crt, &key)?, false));
    }
    let ca = new_ca(cn)?;
    write_key(&key, &ca.key)?;
    write_file(&crt, &ca.pem, 0o644)?;
    Ok((ca, true))
}

fn san_type(s: &str) -> Result<SanType> {
    Ok(match IpAddr::from_str(s) {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => SanType::DnsName(Ia5String::try_from(s.to_string())?),
    })
}

fn local_ips() -> Vec<IpAddr> {
    let mut out = Vec::new();
    // SAFETY: getifaddrs allocates a list we walk read-only and free once.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let a = (*cur).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(a as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            sin.sin_addr.s_addr,
                        ))));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(a as *const libc::sockaddr_in6);
                        out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// The first non-loopback, non-link-local IPv4 address of this host, used as
/// the server's default `--node-ip`. Simplification of k3s
/// `util.GetHostnameAndIPs` -> `apinet.ChooseHostInterface` (pkg/util/net.go:
/// 138-152), which prefers the default-route interface; this walks
/// `getifaddrs` order instead.
pub fn primary_ipv4() -> Option<Ipv4Addr> {
    local_ips().into_iter().find_map(|ip| match ip {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified() => {
            Some(v4)
        }
        _ => None,
    })
}

fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return None;
    }
    let n = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let h = String::from_utf8_lossy(&buf[..n]).to_string();
    (!h.is_empty()).then_some(h)
}

fn issue_leaf(
    ca: &Ca,
    cn: &str,
    orgs: &[&str],
    usage: Usage,
    sans: &[String],
    key: &KeyPair,
) -> Result<String> {
    let mut p = base_params(cn, orgs, LEAF_VALIDITY);
    apply_usage(&mut p, usage, sans)?;
    Ok(p.signed_by(key, &ca.cert, &ca.key)?.pem())
}

fn apply_usage(p: &mut CertificateParams, usage: Usage, sans: &[String]) -> Result<()> {
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    p.extended_key_usages = vec![match usage {
        Usage::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
        Usage::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
    }];
    p.subject_alt_names = sans.iter().map(|s| san_type(s)).collect::<Result<_>>()?;
    Ok(())
}

impl Pki {
    /// Create the PKI under `<data_dir>/tls`, or load it if present. Existing
    /// files are never rewritten, except that a regenerated CA also regenerates
    /// the leaves it signs: server CA -> `serving.{crt,key}`, request-header CA
    /// -> `front-proxy-client.{crt,key}`, client CA -> `admin.kubeconfig`.
    pub fn load_or_create(data_dir: &Path, sans: &[String]) -> Result<Pki> {
        let tls = data_dir.join("tls");
        std::fs::create_dir_all(&tls)?;
        let (server, s_new) = ensure_ca(&tls, "server-ca", "k3rs-server-ca")?;
        let (client, client_new) = ensure_ca(&tls, "client-ca", "k3rs-client-ca")?;
        let (rh, rh_new) = ensure_ca(&tls, "request-header-ca", "k3rs-request-header-ca")?;

        // Front-proxy client cert: CN front-proxy-client, clientAuth, signed by
        // the request-header CA (generate-certs.sh generate_front_proxy_certs).
        let fp_crt = tls.join("front-proxy-client.crt");
        let fp_key = tls.join("front-proxy-client.key");
        if rh_new || !fp_crt.exists() || !fp_key.exists() {
            let k = KeyPair::generate()?;
            let pem = issue_leaf(&rh, "front-proxy-client", &[], Usage::ClientAuth, &[], &k)?;
            write_key(&fp_key, &k)?;
            write_file(&fp_crt, &pem, 0o644)?;
        }

        // API serving cert, SANs per generate-certs.sh plus every local IP.
        let sv_crt = tls.join("serving.crt");
        let sv_key = tls.join("serving.key");
        if s_new || !sv_crt.exists() || !sv_key.exists() {
            let mut names: Vec<String> = Vec::new();
            names.extend(hostname());
            for n in [
                "localhost",
                "kubernetes",
                "kubernetes.default",
                "kubernetes.default.svc",
                "kubernetes.default.svc.cluster.local",
                "127.0.0.1",
                "10.96.0.1",
            ] {
                names.push(n.to_string());
            }
            names.extend(local_ips().iter().map(|i| i.to_string()));
            names.extend(sans.iter().cloned());
            let mut seen = std::collections::HashSet::new();
            names.retain(|n| seen.insert(n.clone()));
            let k = KeyPair::generate()?;
            let pem = issue_leaf(
                &server,
                "kube-apiserver",
                &[],
                Usage::ServerAuth,
                &names,
                &k,
            )?;
            write_key(&sv_key, &k)?;
            write_file(&sv_crt, &pem, 0o644)?;
        }

        // ServiceAccount signing key pair (ES256; accepted by
        // k3rs_common::sa_keys alongside RSA).
        let sa_key = tls.join("sa.key");
        let sa_pub = tls.join("sa.pub");
        if !sa_key.exists() || !sa_pub.exists() {
            let k = KeyPair::generate()?;
            write_key(&sa_key, &k)?;
            write_file(&sa_pub, &k.public_key_pem(), 0o644)?;
        }

        // Admin kubeconfig: CN system:admin, O system:masters, client CA.
        let adm = tls.join("admin.kubeconfig");
        if client_new || !adm.exists() {
            let k = KeyPair::generate()?;
            let pem = issue_leaf(
                &client,
                "system:admin",
                &["system:masters"],
                Usage::ClientAuth,
                &[],
                &k,
            )?;
            let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
            let kc = format!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: default\n  cluster:\n    server: https://127.0.0.1:6443\n    certificate-authority-data: {}\nusers:\n- name: default\n  user:\n    client-certificate-data: {}\n    client-key-data: {}\ncontexts:\n- name: default\n  context:\n    cluster: default\n    user: default\ncurrent-context: default\n",
                b64(&server.pem),
                b64(&pem),
                b64(&k.serialize_pem()),
            );
            write_file(&adm, &kc, 0o600)?;
        }

        Ok(Pki {
            dir: tls,
            client_ca_pem: client.pem.clone(),
            server,
            client,
        })
    }

    pub fn server_ca_pem(&self) -> &str {
        &self.server.pem
    }

    pub fn client_ca_pem(&self) -> &str {
        &self.client_ca_pem
    }

    /// Lowercase hex sha256 of the DER of the server CA certificate.
    pub fn ca_hash(&self) -> String {
        let der = pem::parse(&self.server.pem)
            .map(|p| p.into_contents())
            .unwrap_or_default();
        hex::encode(Sha256::digest(der))
    }

    /// Sign a CSR with the chosen CA (k3s `signAndSend`): only the CSR's public
    /// key is used; subject, EKU and SANs come from the caller.
    pub fn sign_csr(
        &self,
        ca: CaKind,
        csr_der: &[u8],
        cn: &str,
        orgs: &[&str],
        usage: Usage,
        sans: &[String],
    ) -> Result<String, PkiError> {
        check_p256(csr_der)?;
        let der = rustls_pki_der(csr_der);
        let mut csr = CertificateSigningRequestParams::from_der(&der)
            .map_err(|e| PkiError::BadCsr(e.to_string()))?;
        let now = OffsetDateTime::now_utc();
        csr.params.not_before = now - BACKDATE;
        csr.params.not_after = now + LEAF_VALIDITY;
        csr.params.distinguished_name = dn(cn, orgs);
        apply_usage(&mut csr.params, usage, sans).map_err(|e| PkiError::Sign(e.to_string()))?;
        let issuer = match ca {
            CaKind::Server => &self.server,
            CaKind::Client => &self.client,
        };
        csr.signed_by(&issuer.cert, &issuer.key)
            .map(|c| c.pem())
            .map_err(|e| PkiError::Sign(e.to_string()))
    }
}

fn rustls_pki_der(b: &[u8]) -> rustls::pki_types::CertificateSigningRequestDer<'static> {
    rustls::pki_types::CertificateSigningRequestDer::from(b.to_vec())
}

/// Parse the CSR and require an ECDSA P-256 subject key.
fn check_p256(csr_der: &[u8]) -> Result<(), PkiError> {
    use x509_parser::certification_request::X509CertificationRequest;
    use x509_parser::prelude::FromDer;
    let (rest, req) =
        X509CertificationRequest::from_der(csr_der).map_err(|e| PkiError::BadCsr(e.to_string()))?;
    if !rest.is_empty() {
        return Err(PkiError::BadCsr("trailing data".into()));
    }
    let spki = &req.certification_request_info.subject_pki;
    let alg = &spki.algorithm;
    let curve = alg
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|o| o.to_id_string());
    if alg.algorithm.to_id_string() == OID_EC_PUBLIC_KEY && curve.as_deref() == Some(OID_P256) {
        Ok(())
    } else {
        Err(PkiError::UnsupportedKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use x509_parser::prelude::*;

    const FILES: &[&str] = &[
        "server-ca.crt",
        "server-ca.key",
        "client-ca.crt",
        "client-ca.key",
        "request-header-ca.crt",
        "request-header-ca.key",
        "front-proxy-client.crt",
        "front-proxy-client.key",
        "serving.crt",
        "serving.key",
        "sa.key",
        "sa.pub",
        "admin.kubeconfig",
    ];

    fn pem_der(pem: &str) -> Vec<u8> {
        ::pem::parse(pem).unwrap().into_contents()
    }

    fn csr_for(kp: &rcgen::KeyPair) -> Vec<u8> {
        let mut p = rcgen::CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.serialize_request(kp).unwrap().der().to_vec()
    }

    fn mk() -> (tempfile::TempDir, Pki) {
        let d = tempfile::tempdir().unwrap();
        let pki = Pki::load_or_create(d.path(), &["my.example.org".to_string()]).unwrap();
        (d, pki)
    }

    #[test]
    fn load_or_create_is_idempotent() {
        let (d, a) = mk();
        let tls = d.path().join("tls");
        let before: Vec<_> = FILES
            .iter()
            .map(|f| std::fs::read(tls.join(f)).unwrap())
            .collect();
        let b = Pki::load_or_create(d.path(), &["my.example.org".to_string()]).unwrap();
        let after: Vec<_> = FILES
            .iter()
            .map(|f| std::fs::read(tls.join(f)).unwrap())
            .collect();
        assert_eq!(before, after);
        assert_eq!(a.ca_hash(), b.ca_hash());
        assert_eq!(a.ca_hash().len(), 64);
        assert_eq!(a.server_ca_pem(), b.server_ca_pem());
    }

    #[test]
    fn admin_kubeconfig_is_reissued_when_client_ca_is_regenerated() {
        use base64::Engine;
        let (d, _) = mk();
        let tls = d.path().join("tls");
        std::fs::remove_file(tls.join("client-ca.key")).unwrap();
        std::fs::remove_file(tls.join("client-ca.crt")).unwrap();
        let pki = Pki::load_or_create(d.path(), &[]).unwrap();
        let kc = std::fs::read_to_string(tls.join("admin.kubeconfig")).unwrap();
        let line = kc
            .lines()
            .find_map(|l| l.trim().strip_prefix("client-certificate-data: "))
            .unwrap();
        let pem = base64::engine::general_purpose::STANDARD
            .decode(line)
            .unwrap();
        let der = pem_der(std::str::from_utf8(&pem).unwrap());
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let ca_der = pem_der(pki.client_ca_pem());
        let (_, ca) = X509Certificate::from_der(&ca_der).unwrap();
        cert.verify_signature(Some(ca.public_key())).unwrap();
        let cn = cert.subject().iter_common_name().next().unwrap();
        assert_eq!(cn.as_str().unwrap(), "system:admin");
        let o = cert.subject().iter_organization().next().unwrap();
        assert_eq!(o.as_str().unwrap(), "system:masters");
    }

    #[test]
    fn keys_are_0600() {
        let (d, _) = mk();
        for f in FILES.iter().filter(|f| f.ends_with(".key")) {
            let m = std::fs::metadata(d.path().join("tls").join(f)).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600, "{f}");
        }
    }

    #[test]
    fn serving_cert_chains_to_server_ca_and_has_sans() {
        let (d, pki) = mk();
        let pem = std::fs::read_to_string(d.path().join("tls/serving.crt")).unwrap();
        let der = pem_der(&pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let ca_der = pem_der(pki.server_ca_pem());
        let (_, ca) = X509Certificate::from_der(&ca_der).unwrap();
        cert.verify_signature(Some(ca.public_key())).unwrap();
        assert_eq!(cert.issuer(), ca.subject());
        let san = cert.subject_alternative_name().unwrap().unwrap();
        let names = &san.value.general_names;
        let has_dns = |n: &str| {
            names
                .iter()
                .any(|g| matches!(g, GeneralName::DNSName(x) if *x == n))
        };
        assert!(has_dns("localhost"));
        assert!(has_dns("kubernetes.default.svc.cluster.local"));
        assert!(has_dns("my.example.org"));
        assert!(names
            .iter()
            .any(|g| matches!(g, GeneralName::IPAddress(b) if *b == [10, 96, 0, 1])));
        assert!(names
            .iter()
            .any(|g| matches!(g, GeneralName::IPAddress(b) if *b == [127, 0, 0, 1])));
    }

    #[test]
    fn sign_csr_client_cert() {
        let (_d, pki) = mk();
        let kp = rcgen::KeyPair::generate().unwrap();
        let pem = pki
            .sign_csr(
                CaKind::Client,
                &csr_for(&kp),
                "system:node:n1",
                &["system:nodes"],
                Usage::ClientAuth,
                &[],
            )
            .unwrap();
        let der = pem_der(&pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let cn = cert.subject().iter_common_name().next().unwrap();
        assert_eq!(cn.as_str().unwrap(), "system:node:n1");
        let o = cert.subject().iter_organization().next().unwrap();
        assert_eq!(o.as_str().unwrap(), "system:nodes");
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && !eku.server_auth);
        let ca_der = pem_der(&pki.client_ca_pem);
        let (_, ca) = X509Certificate::from_der(&ca_der).unwrap();
        assert_eq!(cert.issuer(), ca.subject());
        cert.verify_signature(Some(ca.public_key())).unwrap();
        assert_eq!(
            cert.public_key().subject_public_key.data.as_ref(),
            kp.public_key_raw()
        );
    }

    #[test]
    fn sign_csr_server_cert_has_sans() {
        let (_d, pki) = mk();
        let kp = rcgen::KeyPair::generate().unwrap();
        let pem = pki
            .sign_csr(
                CaKind::Server,
                &csr_for(&kp),
                "n1",
                &[],
                Usage::ServerAuth,
                &["n1".to_string(), "10.1.2.3".to_string()],
            )
            .unwrap();
        let der = pem_der(&pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth);
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert_eq!(san.value.general_names.len(), 2);
    }

    #[test]
    fn signed_certs_are_backdated() {
        let (_d, pki) = mk();
        let kp = rcgen::KeyPair::generate().unwrap();
        let pem = pki
            .sign_csr(
                CaKind::Client,
                &csr_for(&kp),
                "x",
                &[],
                Usage::ClientAuth,
                &[],
            )
            .unwrap();
        let der = pem_der(&pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let nb = cert.validity().not_before.timestamp();
        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(nb <= now - 4 * 60, "notBefore {nb} now {now}");
    }

    #[test]
    fn garbage_csr_is_bad_csr() {
        let (_d, pki) = mk();
        let e = pki
            .sign_csr(CaKind::Client, b"garbage", "x", &[], Usage::ClientAuth, &[])
            .unwrap_err();
        assert!(matches!(e, PkiError::BadCsr(_)), "{e:?}");
    }

    #[test]
    fn rsa_csr_is_unsupported() {
        use rsa::pkcs8::EncodePrivateKey;
        let (_d, pki) = mk();
        let rsa_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let pem = rsa_key.to_pkcs8_pem(Default::default()).unwrap();
        let kp = rcgen::KeyPair::from_pem_and_sign_algo(&pem, &rcgen::PKCS_RSA_SHA256).unwrap();
        let e = pki
            .sign_csr(
                CaKind::Client,
                &csr_for(&kp),
                "x",
                &[],
                Usage::ClientAuth,
                &[],
            )
            .unwrap_err();
        assert!(matches!(e, PkiError::UnsupportedKey), "{e:?}");
    }
}
