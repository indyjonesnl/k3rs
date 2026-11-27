//! Kubelet client certificate bootstrap: port of
//! `pkg/kubelet/certificate/bootstrap/bootstrap.go` (`LoadClientCert` :132,
//! `writeKubeconfigFromBootstrapping`, `isClientConfigStillValid`,
//! `requestNodeCertificate`, `digestedName`), the CSR helpers of
//! `client-go/util/certificate/csr/csr.go` (`RequestCertificateWithContext`,
//! `WaitForCertificate`, `ensureCompatible`) and the file store of
//! `client-go/util/certificate/certificate_store.go` (`fileStore.Update`).
//!
//! Deviations: the private key is generated as ECDSA P-256 PKCS#8 (rcgen),
//! upstream writes SEC1 `EC PRIVATE KEY`; both are accepted on read. Only the
//! `certificates.k8s.io/v1` API is used (no v1beta1 fallback, removed in 1.22).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use kubernetes_rs_client::http::ApiClient;
use kubernetes_rs_client::kubeconfig::KubeConfig;
use kubernetes_rs_common::resources::{
    CertificateSigningRequest, CertificateSigningRequestSpec, KeyUsage,
};
use kubernetes_rs_common::types::ObjectMeta;
use rcgen::PublicKeyData as _;
use rcgen::{CertificateParams, CertificateSigningRequestParams, DnType, KeyPair};
use sha2::{Digest, Sha512_256};

/// `tmpPrivateKeyFile` (bootstrap.go:51).
pub const TMP_PRIVATE_KEY_FILE: &str = "kubelet-client.key.tmp";
/// `certificatesv1.KubeAPIServerClientKubeletSignerName`.
pub const KUBE_APISERVER_CLIENT_KUBELET_SIGNER: &str =
    "kubernetes.io/kube-apiserver-client-kubelet";
const CSR_PATH: &str = "/apis/certificates.k8s.io/v1/certificatesigningrequests";
const STORE_PREFIX: &str = "kubelet-client";

// ---- file store (certificate_store.go) ----

/// `certificate.NewFileStore("kubelet-client", dir, dir, "", "")`.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    fn filename(&self, qualifier: &str) -> PathBuf {
        self.dir.join(format!("{STORE_PREFIX}-{qualifier}.pem"))
    }

    /// `CurrentPath`: the `kubelet-client-current.pem` symlink.
    pub fn current_path(&self) -> PathBuf {
        self.filename("current")
    }

    /// `Current`: the PEM key of the current pair, when the file parses as a
    /// certificate plus key.
    pub fn current_key_pem(&self) -> Option<String> {
        let data = std::fs::read_to_string(self.current_path()).ok()?;
        let blocks = pem::parse_many(&data).ok()?;
        blocks.iter().find(|b| b.tag().ends_with("PRIVATE KEY"))?;
        blocks.iter().find(|b| b.tag() == "CERTIFICATE")?;
        let key = blocks.iter().find(|b| b.tag().ends_with("PRIVATE KEY"))?;
        Some(pem::encode(key))
    }

    /// `Update` (:204): write `kubelet-client-<timestamp>.pem` (certs then key,
    /// mode 0600), then repoint the `current` symlink.
    pub fn update(&self, cert_pem: &[u8], key_pem: &str) -> Result<PathBuf> {
        use std::io::Write;
        use std::os::unix::fs::{symlink, OpenOptionsExt};
        std::fs::create_dir_all(&self.dir).with_context(|| {
            format!(
                "could not create directory {:?} to store certificates",
                self.dir
            )
        })?;
        let ts = chrono::Local::now().format("%Y-%m-%d-%H-%M-%S").to_string();
        let path = self.filename(&ts);
        let certs =
            pem::parse_many(cert_pem).map_err(|e| anyhow!("invalid certificate data: {e}"))?;
        let certs: Vec<_> = certs.iter().filter(|b| b.tag() == "CERTIFICATE").collect();
        if certs.is_empty() {
            bail!("invalid certificate data: no certificates");
        }
        let key = pem::parse(key_pem).map_err(|_| anyhow!("invalid key data"))?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("could not open {path:?}"))?;
        for c in certs {
            f.write_all(pem::encode(c).as_bytes())?;
        }
        f.write_all(pem::encode(&key).as_bytes())?;
        f.sync_all()
            .with_context(|| format!("failed to sync certificate data to disk (file: {path:?})"))?;

        // updateSymlink (:253): `updated` symlink, renamed over `current`.
        let current = self.current_path();
        if let Ok(md) = std::fs::symlink_metadata(&current) {
            if !md.file_type().is_symlink() {
                bail!("expected {current:?} to be a symlink but it is a file");
            }
        }
        let updated = self.filename("updated");
        let _ = std::fs::remove_file(&updated);
        symlink(std::path::absolute(&path)?, &updated)
            .with_context(|| format!("unable to create a symlink from {updated:?} to {path:?}"))?;
        std::fs::rename(&updated, &current)
            .with_context(|| format!("unable to rename {updated:?} to {current:?}"))?;
        Ok(path)
    }
}

// ---- isClientConfigStillValid (bootstrap.go) ----

/// True when the kubeconfig exists and its client certificates are all
/// unexpired. A read error other than not-exist stops bootstrapping; an
/// unparseable config or certificate means "not valid".
pub fn is_client_config_still_valid(kubeconfig_path: &Path) -> Result<bool> {
    match std::fs::metadata(kubeconfig_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => bail!(
            "error reading existing bootstrap kubeconfig {}: {e}",
            kubeconfig_path.display()
        ),
    }
    let Ok(cfg) = KubeConfig::load_from_file(&kubeconfig_path.to_path_buf()) else {
        return Ok(false);
    };
    let Ok(Some(cert_pem)) = cfg.get_client_cert_pem() else {
        return Ok(false);
    };
    Ok(certs_unexpired(cert_pem.as_bytes()).unwrap_or(false))
}

/// `now.After(cert.NotAfter)` for every certificate; false when there is none.
fn certs_unexpired(pem_data: &[u8]) -> Result<bool> {
    let blocks = pem::parse_many(pem_data)?;
    let mut n = 0;
    let now = chrono::Utc::now().timestamp();
    for b in blocks.iter().filter(|b| b.tag() == "CERTIFICATE") {
        let (_, c) = x509_parser::parse_x509_certificate(b.contents())
            .map_err(|e| anyhow!("parsing certificate: {e}"))?;
        if now > c.validity().not_after.timestamp() {
            return Ok(false);
        }
        n += 1;
    }
    Ok(n > 0)
}

// ---- CSR (bootstrap.go requestNodeCertificate / digestedName) ----

fn usages_for_ecdsa() -> Vec<KeyUsage> {
    vec![KeyUsage::DigitalSignature, KeyUsage::ClientAuth]
}

fn usage_str(u: &KeyUsage) -> String {
    serde_json::to_value(u)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// `digestedName` (bootstrap.go:~345): `node-csr-` + base64url(sha512/256) of
/// the delimited public key, CN, organizations and usages.
pub fn digested_name(
    public_key_der: &[u8],
    common_name: &str,
    orgs: &[&str],
    usages: &[KeyUsage],
) -> String {
    let enc = |d: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d);
    let mut h = Sha512_256::new();
    let mut write = |d: &[u8]| {
        h.update(enc(d).as_bytes());
        h.update(b"|");
    };
    write(public_key_der);
    write(common_name.as_bytes());
    for o in orgs {
        write(o.as_bytes());
    }
    for u in usages {
        write(usage_str(u).as_bytes());
    }
    format!("node-csr-{}", enc(&h.finalize()))
}

/// The node client CSR: `O=system:nodes`, `CN=system:node:<name>`.
pub fn node_csr_pem(key: &KeyPair, node_name: &str) -> Result<String> {
    let mut p = CertificateParams::new(Vec::new())?;
    p.distinguished_name
        .push(DnType::OrganizationName, "system:nodes");
    p.distinguished_name
        .push(DnType::CommonName, format!("system:node:{node_name}"));
    Ok(p.serialize_request(key)?.pem()?)
}

/// `ensureCompatible` (csr.go:320): an existing CSR of the same name must
/// carry our key, the same subject and signer, and (if issued) unexpired certs.
pub fn ensure_compatible(
    existing: &CertificateSigningRequest,
    new_csr_pem: &str,
    signer: &str,
    key: &KeyPair,
) -> Result<()> {
    let old_pem = decode_request(&existing.spec.request)?;
    let old = CertificateSigningRequestParams::from_pem(&old_pem)
        .map_err(|e| anyhow!("unable to parse new csr: {e}"))?;
    let new = CertificateSigningRequestParams::from_pem(new_csr_pem)
        .map_err(|e| anyhow!("unable to parse original csr: {e}"))?;
    if old.params.distinguished_name != new.params.distinguished_name {
        bail!(
            "csr subjects differ: new: {:?}, orig: {:?}",
            old.params.distinguished_name,
            new.params.distinguished_name
        );
    }
    if !existing.spec.signer_name.is_empty() && existing.spec.signer_name != signer {
        bail!(
            "csr signerNames differ: new {:?}, orig: {:?}",
            existing.spec.signer_name,
            signer
        );
    }
    // newCSR.PublicKey = signer.Public(); CheckSignature(): the existing request
    // must be signed by our key.
    if old.public_key.der_bytes() != key.der_bytes() {
        bail!("error validating signature new CSR against old key: public key differs");
    }
    if let Some(cert) = existing
        .status
        .as_ref()
        .and_then(|s| s.certificate.as_deref())
        .filter(|c| !c.is_empty())
    {
        let bytes = STANDARD
            .decode(cert.trim())
            .unwrap_or_else(|_| cert.as_bytes().to_vec());
        match certs_unexpired(&bytes) {
            Ok(true) => {}
            Ok(false) => bail!("one of the certificates for the CSR has expired"),
            Err(e) => bail!("error parsing signed certificate for CSR: {e}"),
        }
    }
    Ok(())
}

fn decode_request(req: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(req.trim())
        .unwrap_or_else(|_| req.as_bytes().to_vec());
    String::from_utf8(bytes).context("CSR request is not UTF-8 PEM")
}

/// One evaluation of `WaitForCertificate`'s event handler (csr.go:244-285):
/// `Ok(Some(cert))` once approved and issued, `Err` on UID change, denial or
/// failure, `Ok(None)` to keep waiting.
pub fn check_csr(csr: &CertificateSigningRequest, req_uid: &str) -> Result<Option<Vec<u8>>> {
    if csr.metadata.uid != req_uid {
        bail!("csr {:?} changed UIDs", csr.metadata.name);
    }
    let mut approved = false;
    for c in csr
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .into_iter()
        .flatten()
    {
        let (reason, msg) = (
            c.reason.clone().unwrap_or_default(),
            c.message.clone().unwrap_or_default(),
        );
        match c.type_.as_str() {
            "Denied" => {
                bail!("certificate signing request is denied, reason: {reason}, message: {msg}")
            }
            "Failed" => {
                bail!("certificate signing request failed, reason: {reason}, message: {msg}")
            }
            "Approved" => approved = true,
            _ => {}
        }
    }
    if approved {
        if let Some(cert) = csr
            .status
            .as_ref()
            .and_then(|s| s.certificate.as_deref())
            .filter(|c| !c.is_empty())
        {
            return Ok(Some(
                STANDARD
                    .decode(cert.trim())
                    .unwrap_or_else(|_| cert.as_bytes().to_vec()),
            ));
        }
    }
    Ok(None)
}

/// `RequestCertificateWithContext` (csr.go:61): create the CSR, or reuse a
/// compatible existing one of the same name. Returns `(name, uid)`.
async fn request_certificate(
    client: &ApiClient,
    csr_pem: &str,
    name: &str,
    usages: Vec<KeyUsage>,
    key: &KeyPair,
) -> Result<(String, String)> {
    let csr = CertificateSigningRequest {
        api_version: "certificates.k8s.io/v1".into(),
        kind: "CertificateSigningRequest".into(),
        metadata: ObjectMeta {
            name: name.to_string(),
            ..Default::default()
        },
        spec: CertificateSigningRequestSpec {
            request: STANDARD.encode(csr_pem),
            signer_name: KUBE_APISERVER_CLIENT_KUBELET_SIGNER.into(),
            usages,
            ..Default::default()
        },
        status: None,
    };
    let (code, res) = client
        .post_with_status::<_, CertificateSigningRequest>(CSR_PATH, &csr)
        .await;
    match res {
        Ok(created) => Ok((created.metadata.name, created.metadata.uid)),
        Err(_) if code == 409 => {
            tracing::info!("csr for this node already exists, reusing");
            let req: CertificateSigningRequest = client
                .get(&format!("{CSR_PATH}/{name}"))
                .await
                .map_err(|e| anyhow!("cannot retrieve certificate signing request: {e}"))?;
            ensure_compatible(&req, csr_pem, KUBE_APISERVER_CLIENT_KUBELET_SIGNER, key)
                .map_err(|e| anyhow!("retrieved csr is not compatible: {e}"))?;
            Ok((req.metadata.name, req.metadata.uid))
        }
        Err(e) => Err(anyhow!("cannot create certificate signing request: {e}")),
    }
}

/// `WaitForCertificate` (csr.go:177): poll the CSR until `check_csr` yields a
/// certificate. (Upstream uses list+watch; polling is equivalent for the
/// single named object.)
async fn wait_for_certificate(
    client: &ApiClient,
    name: &str,
    uid: &str,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(csr) = client
            .get::<CertificateSigningRequest>(&format!("{CSR_PATH}/{name}"))
            .await
        {
            if let Some(cert) = check_csr(&csr, uid)? {
                return Ok(cert);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("timed out waiting for the condition");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// `waitForServer` (bootstrap.go): poll `/healthz` for up to `deadline`.
async fn wait_for_server(client: &ApiClient, deadline: Duration) -> Result<()> {
    let end = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < end {
        if client.get_text("/healthz").await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    bail!("timed out waiting to connect to apiserver")
}

/// `writeKubeconfigFromBootstrapping` (bootstrap.go): a kubeconfig with the
/// bootstrap kubeconfig's cluster and the issued cert/key pair.
pub fn write_kubeconfig_from_bootstrapping(
    bootstrap: &KubeConfig,
    kubeconfig_path: &Path,
    pem_path: &Path,
) -> Result<()> {
    let cluster = bootstrap.get_cluster(bootstrap.get_current_context()?)?;
    let mut c = serde_json::json!({ "server": cluster.server });
    if let Some(v) = cluster.insecure_skip_tls_verify.filter(|v| *v) {
        c["insecure-skip-tls-verify"] = v.into();
    }
    // CAFile wins over CAData (`caFile, caData := ...; if len(caFile)==0 {caData=...}`).
    if let Some(f) = &cluster.certificate_authority {
        c["certificate-authority"] = f.clone().into();
    } else if let Some(d) = &cluster.certificate_authority_data {
        c["certificate-authority-data"] = d.clone().into();
    }
    let pem = pem_path.to_string_lossy();
    let cfg = serde_json::json!({
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "default-cluster", "cluster": c}],
        "users": [{"name": "default-auth", "user": {"client-certificate": pem, "client-key": pem}}],
        "contexts": [{"name": "default-context", "context": {"cluster": "default-cluster", "user": "default-auth", "namespace": "default"}}],
        "current-context": "default-context",
    });
    if let Some(dir) = kubeconfig_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(kubeconfig_path)?;
    f.write_all(serde_yaml::to_string(&cfg)?.as_bytes())?;
    Ok(())
}

fn api_client(cfg: &KubeConfig) -> Result<ApiClient> {
    ApiClient::with_tls(
        &cfg.get_server()?,
        cfg.should_skip_tls_verify()?,
        cfg.get_ca_cert_pem()?,
        cfg.get_client_cert_pem()?.map(String::into_bytes),
        cfg.get_client_key_pem()?.map(String::into_bytes),
        cfg.get_token()?,
    )
}

/// `LoadClientCert` (bootstrap.go:132): when `kubeconfig_path` is missing or
/// holds an expired/invalid client cert, request a node client certificate with
/// the bootstrap kubeconfig, store it in `cert_dir` and write `kubeconfig_path`.
pub async fn load_client_cert(
    kubeconfig_path: &Path,
    bootstrap_path: &Path,
    cert_dir: &Path,
    node_name: &str,
) -> Result<()> {
    if is_client_config_still_valid(kubeconfig_path)? {
        tracing::debug!(
            "Kubeconfig exists and is valid, skipping bootstrap: {}",
            kubeconfig_path.display()
        );
        return Ok(());
    }
    let bootstrap = KubeConfig::load_from_file(&bootstrap_path.to_path_buf())
        .map_err(|e| anyhow!("unable to load bootstrap kubeconfig: {e}"))?;
    let client =
        api_client(&bootstrap).context("unable to create certificates signing request client")?;
    let store = FileStore::new(cert_dir);

    // Reuse the key of the current pair, else the cached tmp key, else a new one
    // (LoadOrGenerateKeyFile keeps the key across restarts until the CSR succeeds).
    let priv_key_path = cert_dir.join(TMP_PRIVATE_KEY_FILE);
    let key_pem = match store
        .current_key_pem()
        .filter(|k| KeyPair::from_pem(k).is_ok())
    {
        Some(k) => k,
        None => match std::fs::read_to_string(&priv_key_path)
            .ok()
            .filter(|k| KeyPair::from_pem(k).is_ok())
        {
            Some(k) => k,
            None => {
                let k = KeyPair::generate()?.serialize_pem();
                std::fs::create_dir_all(cert_dir)?;
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .mode(0o600)
                    .open(&priv_key_path)?
                    .write_all(k.as_bytes())?;
                k
            }
        },
    };
    let key = KeyPair::from_pem(&key_pem)
        .map_err(|e| anyhow!("invalid private key for certificate request: {e}"))?;

    if let Err(e) = wait_for_server(&client, Duration::from_secs(60)).await {
        tracing::info!("Error waiting for apiserver to come up: {e}");
    }

    let usages = usages_for_ecdsa();
    let csr_pem = node_csr_pem(&key, node_name)?;
    let name = digested_name(
        &key.public_key_der(),
        &format!("system:node:{node_name}"),
        &["system:nodes"],
        &usages,
    );
    let (req_name, req_uid) = request_certificate(&client, &csr_pem, &name, usages, &key).await?;
    tracing::debug!("Waiting for client certificate to be issued");
    let cert =
        wait_for_certificate(&client, &req_name, &req_uid, Duration::from_secs(3600)).await?;
    store.update(&cert, &key_pem)?;
    if let Err(e) = std::fs::remove_file(&priv_key_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::debug!(
                "Failed cleaning up private key file {}: {e}",
                priv_key_path.display()
            );
        }
    }
    write_kubeconfig_from_bootstrapping(&bootstrap, kubeconfig_path, &store.current_path())
}
