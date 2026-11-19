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

/// k3s `config.Get` retry period (`pkg/agent/config/config.go:56-75`).
const JOIN_RETRY_PERIOD: Duration = Duration::from_secs(5);

/// An error that retrying can never fix (see [`is_fatal`]).
#[derive(Debug)]
struct Fatal(String);

impl std::fmt::Display for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fatal {}

fn fatal(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Fatal(msg.into()))
}

/// Retry classification for the join loop. DELIBERATE DEVIATION from k3s:
/// `wait.JitterUntilWithContext` retries every error forever, but a CA hash
/// mismatch, an https-scheme rejection, a multi-cert CA bundle, an invalid
/// token or a 400/401/403 answer (e.g. node-password conflict) are security or
/// configuration failures that cannot succeed later, so the agent exits fast.
fn is_fatal(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Fatal>().is_some()
}

/// `wait.JitterUntil`'s next delay with `sliding=true, jitterFactor=1.0`:
/// `period + rand[0,1) * period`.
fn jittered(period: Duration) -> Duration {
    period + period.mul_f64(rand::random::<f64>())
}

/// Port of `Get` (config.go:56-75): retry [`join`] every 5s (jitter 1.0) until
/// it succeeds, logging "Waiting to retrieve agent configuration; server is not
/// ready". `Ok(None)` means shutdown was requested while waiting.
async fn join_with_retry(
    p: &JoinParams,
    shutdown: &k3rs_common::signal::ShutdownContext,
) -> Result<Option<AgentCreds>> {
    loop {
        let attempt = tokio::select! {
            r = join(p) => r,
            _ = shutdown.cancelled() => return Ok(None),
        };
        match attempt {
            Ok(c) => return Ok(Some(c)),
            Err(e) if is_fatal(&e) => return Err(e),
            Err(e) => {
                tracing::info!(
                    "Waiting to retrieve agent configuration; server is not ready: {e:#}"
                );
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(jittered(JOIN_RETRY_PERIOD)) => {}
            _ = shutdown.cancelled() => return Ok(None),
        }
    }
}

#[derive(Clone, Debug)]
pub struct JoinParams {
    pub server: String,
    pub token: String,
    pub node_name: String,
    pub node_ip: Option<String>,
    pub data_dir: PathBuf,
}

/// `serving_cert`/`serving_key` are fetched and written, but the kubelet still
/// self-signs its :10250 serving certificate; wiring these in is the queued
/// serving-TLS follow-up.
#[derive(Clone, Debug)]
pub struct AgentCreds {
    pub ca_pem: String,
    pub kubelet_kubeconfig: PathBuf,
    pub kube_proxy_kubeconfig: PathBuf,
    pub cluster: ClusterInfo,
    pub serving_cert: PathBuf,
    pub serving_key: PathBuf,
}

use crate::util::write_file_mode as write_file;

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

/// `validateCACerts` (clientaccess/token.go): sha256 of the CA's DER. The
/// response must hold exactly one certificate: reqwest trusts every cert in a
/// PEM buffer, so a bundle could smuggle in an unpinned CA. (k3s selects the
/// root by hash from a bundle; the k3rs supervisor serves a single CA.)
/// Returns (hash, DER, re-encoded single-cert PEM).
fn single_ca(pem_text: &str) -> Result<(String, Vec<u8>, String)> {
    let blocks = pem::parse_many(pem_text).context("server returned an invalid CA certificate")?;
    let [b] = blocks.as_slice() else {
        bail!(
            "server /cacerts returned {} PEM blocks, expected exactly one CA certificate",
            blocks.len()
        );
    };
    if b.tag() != "CERTIFICATE" {
        bail!(
            "server /cacerts returned a {} block, expected CERTIFICATE",
            b.tag()
        );
    }
    let der = b.contents().to_vec();
    Ok((hex::encode(Sha256::digest(&der)), der, pem::encode(b)))
}

/// k3s normalises a bare `host:port` to `https://`; plain http would send the
/// join password in cleartext, so it is refused.
fn normalize_server(s: &str) -> Result<String> {
    let s = s.trim().trim_end_matches('/');
    if let Some(rest) = s.strip_prefix("http://") {
        bail!("refusing insecure server URL http://{rest}: the join token must travel over https");
    }
    Ok(if s.starts_with("https://") {
        s.to_string()
    } else {
        format!("https://{s}")
    })
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
            let msg = format!("{what}: {status}: {}", body.trim());
            // 400/401/403 (bad node name, wrong token, node-password conflict)
            // can never succeed on retry.
            return Err(if matches!(status.as_u16(), 400 | 401 | 403) {
                fatal(msg)
            } else {
                anyhow!(msg)
            });
        }
        Ok(body)
    }

    /// `getKubeletClientCert` / `getKubeletServingCert` / kube-proxy cert.
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
    let tok = parse_token(&p.token).map_err(|e| fatal(format!("invalid token: {e}")))?;
    let server = normalize_server(&p.server).map_err(|e| fatal(format!("{e:#}")))?;
    let agent = p.data_dir.join("agent");
    std::fs::create_dir_all(&agent)?;

    // /cacerts: TLS verification off for this call only (clientaccess
    // `getCACerts` uses InsecureSkipVerify), then pinned by hash.
    let insecure = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(HTTP_TIMEOUT)
        .build()?;
    let fetched = insecure
        .get(format!("{server}/cacerts"))
        .send()
        .await
        .with_context(|| format!("fetch {server}/cacerts"))?
        .error_for_status()?
        .text()
        .await?;
    let (got, ca_der, ca_pem) = single_ca(&fetched).map_err(|e| fatal(format!("{e:#}")))?;
    match &tok.ca_hash {
        Some(want) if !want.eq_ignore_ascii_case(&got) => {
            return Err(fatal(format!(
                "CA hash mismatch: token has {want}, server CA is {got}; refusing to join"
            )))
        }
        Some(_) => {}
        None => tracing::warn!(
            "token has no CA hash; the server certificate was not pinned. Use the full K10<hash>::server:<secret> token"
        ),
    }

    let root = reqwest::Certificate::from_der(&ca_der)?;
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

/// Default node name when `--node-name` is unset: the hostname, as k3s
/// `pkg/agent/config` does (`nodeName` defaults to `os.Hostname()`).
pub fn default_node_name() -> Result<String> {
    let h = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .context("determine hostname; pass --node-name")?;
    Ok(h.trim().to_lowercase())
}

/// Kubelet configuration for an agent node. Field mapping mirrors the
/// all-in-one `main.rs` kubelet block; flag values follow k3s
/// `pkg/daemons/agent/agent.go` `startKubelet` (`cluster-dns`, `node-ip`,
/// `hostname-override`).
fn kubelet_config(
    a: &crate::cli::AgentArgs,
    c: &ClusterInfo,
) -> Result<k3rs_kubelet::KubeletConfig> {
    // Pods reach the API through the `kubernetes` Service ClusterIP (first IP of
    // the service CIDR, options.go:378-382) via kube-proxy, port 443. k3s
    // pkg/daemons/agent sets no KUBERNETES_SERVICE_HOST override. Same helper
    // as the all-in-one main.
    let ranges =
        k3rs_api_server::registry::core::service::ipranges::ServiceIpRanges::parse(&c.service_cidr)
            .map_err(|e| anyhow!("invalid service CIDR from server: {e}"))?;
    let node_name = a.node_name.clone().unwrap_or_default();
    let volume_dir = a
        .volume_dir
        .clone()
        .unwrap_or_else(|| format!("{}/agent/volumes", a.data_dir.trim_end_matches('/')));
    Ok(k3rs_kubelet::KubeletConfig {
        node_name: node_name.clone(),
        volume_dir,
        cluster_dns: c.cluster_dns.clone(),
        node_ip: a.node_ip.clone().unwrap_or_default(),
        hostname_override: node_name,
        kubernetes_service_host: ranges.api_server_service_ip().to_string(),
        ..Default::default()
    })
}

/// kube-proxy configuration: `cluster_cidr` is the ClusterIP (service) CIDR as
/// in kube-proxy's own main (`--cluster-cidr`); `no_masq_cidrs` are the pod and
/// service CIDRs, as kube-proxy main's `[pod_cidr, cluster_cidr]`.
fn kube_proxy_config(node_name: &str, c: &ClusterInfo) -> k3rs_kube_proxy::KubeProxyConfig {
    k3rs_kube_proxy::KubeProxyConfig {
        node_name: node_name.to_string(),
        cluster_cidr: c.service_cidr.clone(),
        node_net: Some(crate::util::node_net_config(node_name, c)),
        ..Default::default()
    }
}

pub async fn run_agent(mut a: crate::cli::AgentArgs) -> anyhow::Result<()> {
    ensure_crypto_provider();
    let token = match (&a.token, &a.token_file) {
        (Some(t), _) => t.clone(),
        (None, Some(f)) => std::fs::read_to_string(f)
            .with_context(|| format!("read token file {f}"))?
            .trim()
            .to_string(),
        (None, None) => bail!("--token or --token-file is required"),
    };
    let node_name = match a.node_name.clone() {
        Some(n) => n,
        None => default_node_name()?,
    };
    a.node_name = Some(node_name.clone());
    let shutdown = k3rs_common::signal::setup_signal_context();
    let Some(creds) = join_with_retry(
        &JoinParams {
            server: a.server.clone(),
            token,
            node_name: node_name.clone(),
            node_ip: a.node_ip.clone(),
            data_dir: PathBuf::from(&a.data_dir),
        },
        &shutdown,
    )
    .await?
    else {
        tracing::info!("received shutdown signal before joining");
        return Ok(());
    };

    // stderr so it shows even before/without a tracing subscriber.
    eprintln!("WARNING: {}", crate::util::KUBELET_ANON_WARNING);
    tracing::warn!("{}", crate::util::KUBELET_ANON_WARNING);

    let kubelet_client = std::sync::Arc::new(crate::util::client_from_kubeconfig(
        &creds.kubelet_kubeconfig,
        None,
    )?);
    let storage = std::sync::Arc::new(k3rs_storage::StorageBackend::new_api(kubelet_client));
    let kcfg = kubelet_config(&a, &creds.cluster)?;
    let pcfg = kube_proxy_config(&node_name, &creds.cluster);
    let proxy_client = std::sync::Arc::new(crate::util::client_from_kubeconfig(
        &creds.kube_proxy_kubeconfig,
        None,
    )?);

    let mut kubelet = tokio::spawn(async move { k3rs_kubelet::run(storage, kcfg).await });
    let mut proxy =
        tokio::spawn(async move { k3rs_kube_proxy::run_with_api(proxy_client, pcfg).await });
    tracing::info!("k3rs agent started: node {node_name}");

    let res = tokio::select! {
        r = &mut kubelet => component_exit("kubelet", r),
        r = &mut proxy => component_exit("kube-proxy", r),
        _ = shutdown.cancelled() => {
            tracing::info!("received shutdown signal, stopping k3rs agent");
            Ok(())
        }
    };
    kubelet.abort();
    proxy.abort();
    res
}

/// A component task must never end on its own: surface any exit as an error.
fn component_exit(name: &str, r: Result<anyhow::Result<()>, tokio::task::JoinError>) -> Result<()> {
    match r {
        Ok(Ok(())) => bail!("{name} exited unexpectedly"),
        Ok(Err(e)) => Err(e.context(format!("{name} failed"))),
        Err(e) => Err(anyhow!("{name} task panicked: {e}")),
    }
}

#[cfg(test)]
mod run_tests {
    use super::*;
    use clap::Parser;

    fn args() -> crate::cli::AgentArgs {
        crate::cli::AgentArgs::try_parse_from([
            "k3rs",
            "--server",
            "https://10.0.0.1:6443",
            "--token",
            "t",
            "--node-name",
            "n1",
            "--node-ip",
            "10.0.0.5",
        ])
        .unwrap()
    }

    fn cluster() -> ClusterInfo {
        ClusterInfo {
            cluster_cidr: "10.244.0.0/16".into(),
            service_cidr: "10.96.0.0/12".into(),
            cluster_dns: "10.96.0.10".into(),
        }
    }

    #[test]
    fn retry_classification() {
        assert!(is_fatal(&fatal("CA hash mismatch")));
        assert!(is_fatal(&fatal("x").context("outer")));
        assert!(!is_fatal(&anyhow!("connection refused")));
        assert!(!is_fatal(&anyhow!("fetch cluster config: 503: not ready")));
        assert!(normalize_server("http://h:6443").is_err());
        let d = jittered(JOIN_RETRY_PERIOD);
        assert!(d >= JOIN_RETRY_PERIOD && d < JOIN_RETRY_PERIOD * 2);
    }

    #[test]
    fn kubelet_config_from_join() {
        let c = kubelet_config(&args(), &cluster()).unwrap();
        assert_eq!(c.cluster_dns, "10.96.0.10");
        assert_eq!(c.node_name, "n1");
        assert_eq!(c.hostname_override, "n1");
        assert_eq!(c.node_ip, "10.0.0.5");
        assert_eq!(c.kubernetes_service_host, "10.96.0.1");
        assert_eq!(c.volume_dir, "/var/lib/k3rs/agent/volumes");
    }

    #[test]
    fn kube_proxy_config_from_join() {
        let c = kube_proxy_config("n1", &cluster());
        assert_eq!(c.cluster_cidr, "10.96.0.0/12");
        let nn = c.node_net.unwrap();
        assert_eq!(nn.node_name, "n1");
        assert_eq!(nn.cni_conf_path, "/etc/cni/net.d/10-k3rs.conflist");
        assert_eq!(nn.no_masq_cidrs, vec!["10.244.0.0/16", "10.96.0.0/12"]);
    }
}
