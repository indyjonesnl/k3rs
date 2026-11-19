//! Helpers shared by the server and agent halves of the library.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use k3rs_client::http::ApiClient;
use k3rs_kube_proxy::node_net::NodeNetConfig;

use crate::supervisor::ClusterInfo;

/// The per-node CNI conflist the node-network agent writes.
pub const CNI_CONF_PATH: &str = "/etc/cni/net.d/10-k3rs.conflist";

/// Operator-facing posture warning for the kubelet API port: `kubelet::run`
/// serves it with `AlwaysAllow` and no client-CA authn. Printed by server and
/// agent startup until the kubelet gets x509 authn + webhook authz.
pub const KUBELET_ANON_WARNING: &str = "the kubelet API on :10250 is anonymous (AlwaysAllow): exec/attach/run/portForward/pprof/debug are open to any client that can reach it; client-CA authn is a follow-up";

/// Write `data` to `path` with `mode`, set at creation and re-applied when an
/// existing file is rewritten (`mode` alone is masked by umask and ignored for
/// existing files).
pub fn write_file_mode(path: &Path, data: &str, mode: u32) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    f.write_all(data.as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Node-network agent configuration, identical for a server's own node and an
/// agent's (`agent::kube_proxy_config`): pod and service CIDRs are not
/// masqueraded.
pub fn node_net_config(node_name: &str, info: &ClusterInfo) -> NodeNetConfig {
    NodeNetConfig {
        node_name: node_name.to_string(),
        cni_conf_path: CNI_CONF_PATH.to_string(),
        no_masq_cidrs: vec![info.cluster_cidr.clone(), info.service_cidr.clone()],
    }
}

/// An mTLS [`ApiClient`] from a component kubeconfig (CA, client cert and key,
/// inline data or file paths), with the component's default User-Agent
/// (`rest.SetKubernetesDefaults`). `server` overrides the kubeconfig's server
/// URL: the server's own components reach the api-server on the loopback port
/// derived from `--bind-address`, which need not be the kubeconfig's 6443.
pub fn client_from_kubeconfig(path: &Path, server: Option<&str>) -> Result<ApiClient> {
    use k3rs_client::kubeconfig::KubeConfig;
    let cfg = KubeConfig::load_from_file(&path.to_path_buf())
        .with_context(|| format!("load kubeconfig {}", path.display()))?;
    let server = match server {
        Some(s) => s.to_string(),
        None => cfg.get_server()?,
    };
    let ca = cfg.get_ca_cert_pem()?;
    let cert = cfg.get_client_cert_pem()?.map(String::into_bytes);
    let key = cfg.get_client_key_pem()?.map(String::into_bytes);
    if cert.is_none() || key.is_none() {
        anyhow::bail!(
            "kubeconfig {} has no client certificate/key",
            path.display()
        );
    }
    Ok(ApiClient::with_tls(&server, false, ca, cert, key, None)?
        .with_default_user_agent(k3rs_common::compatibility::default_kubernetes_user_agent()))
}

/// k3s `WaitForAPIServerReady` interval (`pkg/util/api.go:107`,
/// `wait.PollUntilContextTimeout(ctx, time.Second*2, timeout, true, ...)`).
pub const READYZ_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Poll `GET /readyz` until it answers 2xx or `timeout` passes; the first
/// poll is immediate. Port of k3s `WaitForAPIServerReady`
/// (`pkg/util/api.go:76-127`): a changed error is logged at info, the final
/// error joins the timeout with the last poll error. The embedded components
/// start only after this, so they never crash-loop against an api-server
/// whose bootstrap RBAC policy is not served yet
/// (`poststarthook/rbac/bootstrap-roles` is a readyz check).
pub async fn wait_for_readyz(
    client: &ApiClient,
    timeout: Duration,
    interval: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last = String::from("API server not polled");
    loop {
        match client.get_text("/readyz").await {
            Ok(_) => return Ok(()),
            Err(e) => {
                let e = format!("{e:#}");
                if e != last {
                    tracing::info!("Polling for API server readiness: GET /readyz failed: {e}");
                }
                last = e;
            }
        }
        if tokio::time::Instant::now() + interval > deadline {
            anyhow::bail!(
                "api-server not ready after {:?} (GET /readyz): {last}",
                timeout
            );
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_file_mode_reapplies_mode_on_rewrite() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, "old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_file_mode(&p, "new", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(test)]
mod readyz_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A stub api-server whose `/readyz` answers 503 `fail_first` times, then 200.
    async fn stub(fail_first: usize) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = axum::Router::new().route(
            "/readyz",
            axum::routing::get(move || {
                let h = h.clone();
                async move {
                    if h.fetch_add(1, Ordering::SeqCst) < fail_first {
                        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready")
                    } else {
                        (axum::http::StatusCode::OK, "ok")
                    }
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}"), hits)
    }

    #[tokio::test]
    async fn waits_through_503s_until_ready() {
        let (url, hits) = stub(3).await;
        let c = ApiClient::new(&url, false, None).unwrap();
        wait_for_readyz(&c, Duration::from_secs(5), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn errors_after_timeout() {
        let (url, _) = stub(usize::MAX).await;
        let c = ApiClient::new(&url, false, None).unwrap();
        let err = wait_for_readyz(&c, Duration::from_millis(200), Duration::from_millis(20))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("api-server not ready after 200ms (GET /readyz)"),
            "{err}"
        );
        assert!(err.contains("503"), "{err}");
    }

    #[tokio::test]
    async fn errors_when_nothing_listens() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let c = ApiClient::new(&format!("http://127.0.0.1:{port}"), false, None).unwrap();
        assert!(
            wait_for_readyz(&c, Duration::from_millis(100), Duration::from_millis(20))
                .await
                .is_err()
        );
    }
}
