//! Server PKI generation and CSR signing for `k3rs server` / `k3rs agent` join.
//!
//! File set and SANs mirror `scripts/generate-certs.sh`. CN/O/EKU of issued
//! certificates are ported from k3s `pkg/server/handlers/handlers.go`
//! (`signAndSend`, `ClientKubeletCert`, `ServingKubeletCert`,
//! `ClientKubeProxyCert`): the CSR contributes only the public key (k3s agents
//! send an empty-subject CSR, `getCSRBytes`); the subject comes from the server.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Result;
use base64::Engine;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// notBefore backdating, absorbs clock skew between server and agents.
/// kubernetes `pkg/controller/certificates/signer/signer.go:209`
/// (`Backdate: 5 * time.Minute`).
const BACKDATE: Duration = Duration::minutes(5);
/// 10 years: client-go `util/cert/cert.go:79` (`duration365d * 10`, CA).
const CA_VALIDITY: Duration = Duration::days(3650);
/// 1 year: client-go `util/cert/cert.go:40` (`duration365d`), the leaf TTL.
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

use crate::util::write_file_mode as write_file;

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

/// Exactly one of the CA cert/key exists: a broken `tls/` that forces a new CA.
fn ca_half_present(crt: &Path, key: &Path) -> bool {
    crt.exists() != key.exists()
}

fn ensure_ca(tls: &Path, name: &str, cn: &str) -> Result<(Ca, bool)> {
    let crt = tls.join(format!("{name}.crt"));
    let key = tls.join(format!("{name}.key"));
    if crt.exists() && key.exists() {
        return Ok((load_ca(&crt, &key)?, false));
    }
    if ca_half_present(&crt, &key) {
        let msg = format!(
            "regenerating CA {name} (only one of {} / {} exists); all issued tokens and agent pins are invalidated",
            crt.display(),
            key.display()
        );
        eprintln!("WARNING: {msg}");
        tracing::warn!("{msg}");
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

/// A static per-component client identity. Ported from k3s
/// `pkg/daemons/control/deps/deps.go:330-420` (`genClientCerts`: admin,
/// controller-manager, scheduler, kube-proxy, apiserver, plus the node's
/// kubelet cert which is minted separately because its CN carries the node name).
pub struct Identity {
    pub name: &'static str,
    pub cn: &'static str,
    pub orgs: &'static [&'static str],
}

/// Identities minted for every server; the node identity is added by
/// [`Pki::ensure_component_creds`]. k3s: `system:admin`/`system:masters`
/// (deps.go:339), `system:kube-controller-manager` (:351),
/// `system:kube-scheduler` (:365), `system:kube-proxy` (:381),
/// `system:apiserver`/`system:masters` (:373, the apiserver->kubelet client).
/// `system:k3rs-dns` is k3rs-specific (k3s runs CoreDNS as a pod).
pub const COMPONENT_IDENTITIES: &[Identity] = &[
    Identity {
        name: "admin",
        cn: "system:admin",
        orgs: &["system:masters"],
    },
    Identity {
        name: "controller-manager",
        cn: "system:kube-controller-manager",
        orgs: &[],
    },
    Identity {
        name: "scheduler",
        cn: "system:kube-scheduler",
        orgs: &[],
    },
    Identity {
        name: "kube-proxy",
        cn: "system:kube-proxy",
        orgs: &[],
    },
    Identity {
        name: "dns",
        cn: "system:k3rs-dns",
        orgs: &[],
    },
    Identity {
        name: "apiserver",
        cn: "system:apiserver",
        orgs: &["system:masters"],
    },
];

/// Reuse a leaf only while it has at least this long left.
const REUSE_MARGIN: i64 = 30 * 24 * 3600;
const LOOPBACK_SERVER: &str = "https://127.0.0.1:6443";

/// Locations of the minted component credentials under `<data-dir>`.
#[derive(Clone, Debug)]
pub struct ComponentCreds {
    pub dir: PathBuf,
}

impl ComponentCreds {
    pub fn cert(&self, name: &str) -> PathBuf {
        self.dir.join("tls").join(format!("client-{name}.crt"))
    }
    pub fn key(&self, name: &str) -> PathBuf {
        self.dir.join("tls").join(format!("client-{name}.key"))
    }
    pub fn kubeconfig(&self, name: &str) -> PathBuf {
        self.dir.join("cred").join(format!("{name}.kubeconfig"))
    }
    pub fn serving_cert(&self) -> PathBuf {
        self.dir.join("tls").join("serving-kubelet.crt")
    }
    pub fn serving_key(&self) -> PathBuf {
        self.dir.join("tls").join("serving-kubelet.key")
    }
}

fn leaf_pem_der(pem_str: &str) -> Option<Vec<u8>> {
    ::pem::parse(pem_str).ok().map(|p| p.into_contents())
}

/// Whether the leaf at `crt`/`key` can be kept: it parses, has the expected
/// subject (and SANs when `sans` is given), is unexpired with margin, was
/// signed by `ca_pem`, and matches the private key on disk.
fn leaf_is_current(
    crt: &Path,
    key: &Path,
    ca_pem: &str,
    cn: &str,
    orgs: &[&str],
    sans: Option<&[String]>,
) -> bool {
    use x509_parser::prelude::*;
    let (Ok(crt_pem), Ok(key_pem)) = (std::fs::read_to_string(crt), std::fs::read_to_string(key))
    else {
        return false;
    };
    let (Some(der), Some(ca_der), Ok(kp)) = (
        leaf_pem_der(&crt_pem),
        leaf_pem_der(ca_pem),
        KeyPair::from_pem(&key_pem),
    ) else {
        return false;
    };
    let (Ok((_, cert)), Ok((_, ca))) = (
        X509Certificate::from_der(&der),
        X509Certificate::from_der(&ca_der),
    ) else {
        return false;
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if cert.validity().not_after.timestamp() < now + REUSE_MARGIN
        || cert.validity().not_before.timestamp() > now
    {
        return false;
    }
    if cert.verify_signature(Some(ca.public_key())).is_err() {
        return false;
    }
    if cert.public_key().subject_public_key.data.as_ref() != kp.public_key_raw() {
        return false;
    }
    let got_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|c| c.as_str().ok());
    let got_orgs: Vec<&str> = cert
        .subject()
        .iter_organization()
        .filter_map(|o| o.as_str().ok())
        .collect();
    if got_cn != Some(cn) || got_orgs != orgs {
        return false;
    }
    if let Some(want) = sans {
        let mut have: Vec<String> = match cert.subject_alternative_name() {
            Ok(Some(e)) => e
                .value
                .general_names
                .iter()
                .filter_map(|g| match g {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    GeneralName::IPAddress(b) => match b.len() {
                        4 => Some(IpAddr::from(<[u8; 4]>::try_from(*b).ok()?).to_string()),
                        16 => Some(IpAddr::from(<[u8; 16]>::try_from(*b).ok()?).to_string()),
                        _ => None,
                    },
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        let mut want: Vec<String> = want.iter().map(|w| canonical_san(w)).collect();
        have.sort();
        want.sort();
        if have != want {
            return false;
        }
    }
    true
}

fn canonical_san(s: &str) -> String {
    IpAddr::from_str(s).map_or_else(|_| s.to_string(), |ip| ip.to_string())
}

fn component_kubeconfig(ca_pem: &str, crt: &Path, key: &Path) -> String {
    let ca = base64::engine::general_purpose::STANDARD.encode(ca_pem);
    format!(
        "apiVersion: v1\nkind: Config\nclusters:\n- name: local\n  cluster:\n    server: {LOOPBACK_SERVER}\n    certificate-authority-data: {ca}\ncontexts:\n- name: Default\n  context:\n    cluster: local\n    user: default\ncurrent-context: Default\nusers:\n- name: default\n  user:\n    client-certificate: {}\n    client-key: {}\n",
        crt.display(),
        key.display(),
    )
}

impl Pki {
    /// Mint (or reuse) the per-component client identities, the node's kubelet
    /// client cert (`system:node:<node_name>` / `system:nodes`, name
    /// `kubelet`), its serving cert, and one kubeconfig per identity under
    /// `<data-dir>/cred/`. Mirrors k3s `deps.go:330-420`.
    ///
    /// A leaf is reused only if it parses, has margin left, matches its key
    /// and verifies against the CURRENT CA; otherwise it is re-minted, so a
    /// regenerated CA never leaves stale leaves behind.
    pub fn ensure_component_creds(
        &self,
        node_name: &str,
        node_ip: &str,
    ) -> Result<ComponentCreds, PkiError> {
        self.ensure_component_creds_inner(node_name, node_ip)
            .map_err(|e| PkiError::Sign(format!("{e:#}")))
    }

    fn ensure_component_creds_inner(
        &self,
        node_name: &str,
        node_ip: &str,
    ) -> Result<ComponentCreds> {
        let data_dir = self.dir.parent().unwrap_or(&self.dir).to_path_buf();
        let creds = ComponentCreds { dir: data_dir };
        std::fs::create_dir_all(creds.dir.join("tls"))?;
        std::fs::create_dir_all(creds.dir.join("cred"))?;

        let node_cn = format!("system:node:{node_name}");
        let mut all: Vec<(&str, &str, &[&str])> = COMPONENT_IDENTITIES
            .iter()
            .map(|i| (i.name, i.cn, i.orgs))
            .collect();
        all.push(("kubelet", node_cn.as_str(), &["system:nodes"]));

        for (name, cn, orgs) in all {
            let (crt, key) = (creds.cert(name), creds.key(name));
            if !leaf_is_current(&crt, &key, &self.client.pem, cn, orgs, Some(&[])) {
                let k = KeyPair::generate()?;
                let pem = issue_leaf(&self.client, cn, orgs, Usage::ClientAuth, &[], &k)?;
                write_key(&key, &k)?;
                write_file(&crt, &pem, 0o644)?;
            }
            let kc = creds.kubeconfig(name);
            let want = component_kubeconfig(&self.server.pem, &crt, &key);
            if std::fs::read_to_string(&kc).ok().as_deref() != Some(want.as_str()) {
                write_file(&kc, &want, 0o600)?;
            }
        }

        // Kubelet serving cert (k3s `ServingKubeletCert`, handlers.go): SANs
        // node name, node IP, plus loopback.
        let mut sans: Vec<String> = vec![node_name.into(), node_ip.into()];
        sans.extend(["localhost", "127.0.0.1", "::1"].map(String::from));
        let mut seen = std::collections::HashSet::new();
        sans.retain(|s| !s.is_empty() && seen.insert(canonical_san(s)));
        let (crt, key) = (creds.serving_cert(), creds.serving_key());
        if !leaf_is_current(&crt, &key, &self.server.pem, node_name, &[], Some(&sans)) {
            let k = KeyPair::generate()?;
            let pem = issue_leaf(&self.server, node_name, &[], Usage::ServerAuth, &sans, &k)?;
            write_key(&key, &k)?;
            write_file(&crt, &pem, 0o644)?;
        }
        Ok(creds)
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
    use base64::Engine;
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
    fn ca_half_present_detects_partial_tls_dir() {
        let d = tempfile::tempdir().unwrap();
        let (crt, key) = (d.path().join("a.crt"), d.path().join("a.key"));
        assert!(!ca_half_present(&crt, &key));
        std::fs::write(&crt, "x").unwrap();
        assert!(ca_half_present(&crt, &key));
        std::fs::write(&key, "x").unwrap();
        assert!(!ca_half_present(&crt, &key));
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

    fn read_cert(p: &Path) -> Vec<u8> {
        pem_der(&std::fs::read_to_string(p).unwrap())
    }

    #[test]
    fn creds_have_expected_subjects() {
        let (_d, pki) = mk();
        let c = pki.ensure_component_creds("node1", "10.1.2.3").unwrap();
        let ca_der = pem_der(pki.client_ca_pem());
        let (_, ca) = X509Certificate::from_der(&ca_der).unwrap();
        let mut want: Vec<(&str, String, Vec<&str>)> = COMPONENT_IDENTITIES
            .iter()
            .map(|i| (i.name, i.cn.to_string(), i.orgs.to_vec()))
            .collect();
        want.push(("kubelet", "system:node:node1".into(), vec!["system:nodes"]));
        for (name, cn, orgs) in want {
            let der = read_cert(&c.cert(name));
            let (_, cert) = X509Certificate::from_der(&der).unwrap();
            assert_eq!(
                cert.subject()
                    .iter_common_name()
                    .next()
                    .unwrap()
                    .as_str()
                    .unwrap(),
                cn
            );
            let got: Vec<&str> = cert
                .subject()
                .iter_organization()
                .map(|o| o.as_str().unwrap())
                .collect();
            assert_eq!(got, orgs, "{name}");
            assert_eq!(cert.issuer(), ca.subject());
            cert.verify_signature(Some(ca.public_key())).unwrap();
            assert!(
                cert.extended_key_usage()
                    .unwrap()
                    .unwrap()
                    .value
                    .client_auth
            );
        }
        let der = read_cert(&c.serving_cert());
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let sca_der = pem_der(pki.server_ca_pem());
        let (_, sca) = X509Certificate::from_der(&sca_der).unwrap();
        cert.verify_signature(Some(sca.public_key())).unwrap();
        assert!(
            cert.extended_key_usage()
                .unwrap()
                .unwrap()
                .value
                .server_auth
        );
        let san = cert.subject_alternative_name().unwrap().unwrap();
        let n = &san.value.general_names;
        let dns = |d: &str| {
            n.iter()
                .any(|g| matches!(g, GeneralName::DNSName(x) if *x == d))
        };
        let ip = |b: &[u8]| {
            n.iter()
                .any(|g| matches!(g, GeneralName::IPAddress(x) if *x == b))
        };
        assert!(dns("node1") && dns("localhost"));
        assert!(ip(&[10, 1, 2, 3]) && ip(&[127, 0, 0, 1]));
        assert!(ip(&Ipv6Addr::LOCALHOST.octets()));
    }

    #[test]
    fn creds_idempotent_and_0600() {
        let (d, pki) = mk();
        let c = pki.ensure_component_creds("node1", "10.1.2.3").unwrap();
        let files: Vec<PathBuf> = COMPONENT_IDENTITIES
            .iter()
            .map(|i| i.name)
            .chain(["kubelet"])
            .flat_map(|n| [c.cert(n), c.key(n), c.kubeconfig(n)])
            .chain([c.serving_cert(), c.serving_key()])
            .collect();
        let before: Vec<_> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();
        let pki2 = Pki::load_or_create(d.path(), &[]).unwrap();
        pki2.ensure_component_creds("node1", "10.1.2.3").unwrap();
        let after: Vec<_> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();
        assert_eq!(before, after);
        for f in files
            .iter()
            .filter(|f| f.extension().is_some_and(|e| e == "key"))
        {
            let m = std::fs::metadata(f).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600, "{}", f.display());
        }
    }

    #[test]
    fn changed_node_ip_remints_serving_cert() {
        let (_d, pki) = mk();
        let c = pki.ensure_component_creds("node1", "10.1.2.3").unwrap();
        let before = std::fs::read(c.serving_cert()).unwrap();
        pki.ensure_component_creds("node1", "10.9.9.9").unwrap();
        assert_ne!(before, std::fs::read(c.serving_cert()).unwrap());
    }

    #[test]
    fn stale_leaf_reminted_after_ca_regen() {
        let (d, pki) = mk();
        let c = pki.ensure_component_creds("node1", "10.1.2.3").unwrap();
        let old = read_cert(&c.cert("scheduler"));
        let old_serving = read_cert(&c.serving_cert());
        let tls = d.path().join("tls");
        for f in [
            "client-ca.crt",
            "client-ca.key",
            "server-ca.crt",
            "server-ca.key",
        ] {
            std::fs::remove_file(tls.join(f)).unwrap();
        }
        let pki2 = Pki::load_or_create(d.path(), &[]).unwrap();
        pki2.ensure_component_creds("node1", "10.1.2.3").unwrap();
        assert_ne!(old, read_cert(&c.cert("scheduler")));
        assert_ne!(old_serving, read_cert(&c.serving_cert()));
        let ca_der = pem_der(pki2.client_ca_pem());
        let (_, ca) = X509Certificate::from_der(&ca_der).unwrap();
        for n in ["admin", "scheduler", "kubelet", "apiserver"] {
            let der = read_cert(&c.cert(n));
            let (_, cert) = X509Certificate::from_der(&der).unwrap();
            cert.verify_signature(Some(ca.public_key())).unwrap();
        }
        let sca_der = pem_der(pki2.server_ca_pem());
        let (_, sca) = X509Certificate::from_der(&sca_der).unwrap();
        let der = read_cert(&c.serving_cert());
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        cert.verify_signature(Some(sca.public_key())).unwrap();
        // kubeconfig embeds the new server CA.
        let kc = std::fs::read_to_string(c.kubeconfig("scheduler")).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(pki2.server_ca_pem());
        assert!(kc.contains(&b64));
    }

    #[test]
    fn kubeconfig_points_at_loopback_with_embedded_ca() {
        let (_d, pki) = mk();
        let c = pki.ensure_component_creds("node1", "10.1.2.3").unwrap();
        let kc = std::fs::read_to_string(c.kubeconfig("scheduler")).unwrap();
        assert!(kc.contains("server: https://127.0.0.1:6443"));
        let b64 = base64::engine::general_purpose::STANDARD.encode(pki.server_ca_pem());
        assert!(kc.contains(&format!("certificate-authority-data: {b64}")));
        assert!(kc.contains(&format!(
            "client-certificate: {}",
            c.cert("scheduler").display()
        )));
        assert!(kc.contains(&format!("client-key: {}", c.key("scheduler").display())));
        let m = std::fs::metadata(c.kubeconfig("scheduler")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
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
