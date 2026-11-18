//! `k3rs agent`: join client and runtime.
//!
//! Join half is a port of k3s `pkg/agent/config/config.go`: `get` (:439) drives
//! the flow, `getKubeletClientCert`/`getKubeletServingCert` POST a DER CSR with
//! the `Node-Name`/`Node-Password`/`Node-IP` headers, `getCSRBytes` (:318)
//! builds an empty-subject CSR from a locally generated key, `ensureNodePassword`
//! (:205) keeps a 16-byte hex password in `<data-dir>/agent/node-password`, and
//! the CA is fetched from `/cacerts` unverified then pinned by the token's CA
//! hash (`pkg/clientaccess/token.go` `ParseAndValidateToken`/`validateCACerts`).
//!
//! Deviations: kubeconfigs are written in the same shape as k3s
//! `pkg/agent/util` `WriteKubeConfig` but reference cert/key files by path; the
//! legacy "server returned a key instead of signing" path is not ported (the
//! k3rs supervisor always signs the CSR).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rand::RngCore;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use sha2::{Digest, Sha256};

use crate::supervisor::ClusterInfo;
use crate::token::parse_token;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct JoinParams {
    pub server: String,
    pub token: String,
    pub node_name: String,
    pub node_ip: Option<String>,
    pub data_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct AgentCreds {
    pub ca_pem: String,
    pub kubelet_kubeconfig: PathBuf,
    pub kube_proxy_kubeconfig: PathBuf,
    pub cluster: ClusterInfo,
    pub serving_cert: PathBuf,
    pub serving_key: PathBuf,
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
    // `mode` only applies on creation; enforce on rewrite too.
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
    Ok(())
}

/// `ensureNodePassword` (config.go:205).
fn ensure_node_password(file: &Path) -> Result<String> {
    if file.exists() {
        return Ok(std::fs::read_to_string(file)?.trim().to_string());
    }
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    let pw = hex::encode(b);
    write_file(file, &format!("{pw}\n"), 0o600)?;
    Ok(pw)
}

/// `getCSRBytes` (config.go:318): load or generate the key, empty-subject CSR.
fn csr_bytes(key_file: &Path) -> Result<Vec<u8>> {
    let kp = if key_file.exists() {
        KeyPair::from_pem(&std::fs::read_to_string(key_file)?)
            .with_context(|| format!("parse {}", key_file.display()))?
    } else {
        let kp = KeyPair::generate()?;
        write_file(key_file, &kp.serialize_pem(), 0o600)?;
        kp
    };
    let mut p = CertificateParams::default();
    p.distinguished_name = DistinguishedName::new();
    Ok(p.serialize_request(&kp)?.der().to_vec())
}

/// `validateCACerts` (clientaccess/token.go): sha256 of the CA's DER.
fn ca_hash(pem_text: &str) -> Result<String> {
    let der = pem::parse(pem_text)
        .context("server returned an invalid CA certificate")?
        .into_contents();
    Ok(hex::encode(Sha256::digest(der)))
}

struct Api {
    http: reqwest::Client,
    base: String,
    user: String,
    pass: String,
}

impl Api {
    async fn send(&self, rb: reqwest::RequestBuilder, what: &str) -> Result<String> {
        let resp = rb
            .basic_auth(&self.user, Some(&self.pass))
            .send()
            .await
            .with_context(|| format!("{what}: request to {} failed", self.base))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("{what}: {status}: {}", body.trim());
        }
        Ok(body)
    }

    /// `getKubeletClientCert` / `getKubeletServingCert` / kube-proxy cert.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_cert(
        &self,
        name: &str,
        agent: &Path,
        node: Option<(&str, &str, Option<&str>)>,
    ) -> Result<()> {
        let key = agent.join(format!("{name}.key"));
        let crt = agent.join(format!("{name}.crt"));
        let csr = csr_bytes(&key)?;
        let mut rb = self
            .http
            .post(format!("{}/v1-k3rs/{name}.crt", self.base))
            .body(csr);
        if let Some((n, pw, ip)) = node {
            rb = rb
                .header("k3rs-Node-Name", n)
                .header("k3rs-Node-Password", pw);
            if let Some(ip) = ip {
                rb = rb.header("k3rs-Node-IP", ip);
            }
        }
        let pem = self.send(rb, &format!("fetch {name}.crt")).await?;
        write_file(&crt, &pem, 0o600)?;
        Ok(())
    }
}

fn kubeconfig(server: &str, ca_pem: &str, user: &str, crt: &Path, key: &Path) -> String {
    let ca = base64::engine::general_purpose::STANDARD.encode(ca_pem);
    format!(
        "apiVersion: v1\nkind: Config\nclusters:\n- name: local\n  cluster:\n    server: {server}\n    certificate-authority-data: {ca}\ncontexts:\n- name: Default\n  context:\n    cluster: local\n    user: {user}\ncurrent-context: Default\nusers:\n- name: {user}\n  user:\n    client-certificate: {crt}\n    client-key: {key}\n",
        crt = crt.display(),
        key = key.display(),
    )
}

/// Several rustls providers are linked into the workspace (ring via reqwest,
/// aws-lc-rs via the api-server), so rustls cannot pick one itself; install
/// aws-lc-rs (the workspace `rustls` feature) unless one is already set.
pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Port of `get` (config.go:439): pin the CA, fetch node certs, write
/// kubeconfigs, read cluster parameters.
pub async fn join(p: &JoinParams) -> Result<AgentCreds> {
    ensure_crypto_provider();
    let tok = parse_token(&p.token).map_err(|e| anyhow!("invalid token: {e}"))?;
    let server = p.server.trim_end_matches('/').to_string();
    let agent = p.data_dir.join("agent");
    std::fs::create_dir_all(&agent)?;

    // /cacerts: TLS verification off for this call only (clientaccess
    // `getCACerts` uses InsecureSkipVerify), then pinned by hash.
    let insecure = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(HTTP_TIMEOUT)
        .build()?;
    let ca_pem = insecure
        .get(format!("{server}/cacerts"))
        .send()
        .await
        .with_context(|| format!("fetch {server}/cacerts"))?
        .error_for_status()?
        .text()
        .await?;
    let got = ca_hash(&ca_pem)?;
    match &tok.ca_hash {
        Some(want) if !want.eq_ignore_ascii_case(&got) => bail!(
            "CA hash mismatch: token has {want}, server CA is {got}; refusing to join"
        ),
        Some(_) => {}
        None => tracing::warn!(
            "token has no CA hash; the server certificate was not pinned. Use the full K10<hash>::server:<secret> token"
        ),
    }

    let root = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;
    let api = Api {
        http: reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(root)
            .timeout(HTTP_TIMEOUT)
            .build()?,
        base: server.clone(),
        user: tok.username.clone(),
        pass: tok.password.clone(),
    };

    let node_pw = ensure_node_password(&agent.join("node-password"))?;
    let node = Some((p.node_name.as_str(), node_pw.as_str(), p.node_ip.as_deref()));
    api.fetch_cert("client-kubelet", &agent, node).await?;
    api.fetch_cert("serving-kubelet", &agent, node).await?;
    api.fetch_cert("client-kube-proxy", &agent, None).await?;

    let kubelet_kubeconfig = agent.join("kubelet.kubeconfig");
    let kube_proxy_kubeconfig = agent.join("kube-proxy.kubeconfig");
    for (file, user, name) in [
        (&kubelet_kubeconfig, "kubelet", "client-kubelet"),
        (&kube_proxy_kubeconfig, "kube-proxy", "client-kube-proxy"),
    ] {
        let kc = kubeconfig(
            &server,
            &ca_pem,
            user,
            &agent.join(format!("{name}.crt")),
            &agent.join(format!("{name}.key")),
        );
        write_file(file, &kc, 0o600)?;
    }

    let body = api
        .send(
            api.http.get(format!("{server}/v1-k3rs/config")),
            "fetch cluster config",
        )
        .await?;
    let cluster: ClusterInfo =
        serde_json::from_str(&body).context("parse cluster config from server")?;

    Ok(AgentCreds {
        ca_pem,
        kubelet_kubeconfig,
        kube_proxy_kubeconfig,
        cluster,
        serving_cert: agent.join("serving-kubelet.crt"),
        serving_key: agent.join("serving-kubelet.key"),
    })
}

pub async fn run_agent(_a: crate::cli::AgentArgs) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}
