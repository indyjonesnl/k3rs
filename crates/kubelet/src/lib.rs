pub mod atomic_writer;
pub mod clustertrustbundle;
pub mod cm_helpers;
pub mod config;
pub mod container_log_manager;
pub mod credentialprovider;
pub mod credentialprovider_plugin;
pub mod cri_runtime;
pub mod downward_api;
pub mod events;
pub mod eviction;
pub mod flowcontrol;
#[cfg(target_os = "linux")]
pub mod fsquota;
pub mod go_selinux;
pub mod go_selinux_label;
pub mod healthz;
pub mod host_port;
pub mod image_gc;
pub mod image_gc_cri;
pub mod image_manager;
pub mod kubelet;
pub mod labels;
pub mod lifecycle;
pub mod node_ip;
pub mod node_log_query;
pub mod node_status;
pub mod nodeshutdown;
pub mod pluginmanager;
pub mod pod_dirs;
pub mod pod_status;
pub mod podcertificate;
pub mod poll;
pub mod removeall;
pub mod runtime;
pub mod runtime_state;
pub mod server;
pub mod server_auth;
pub mod server_cri_metrics;
pub mod server_debug;
pub mod server_logs;
pub mod server_metrics;
pub mod server_metrics_endpoints;
pub mod server_resource_metrics;
pub mod server_stats;
pub mod serving_tls;
pub mod static_pod_url;
pub mod static_pod_watch;
pub mod static_pods;
pub mod streaming_server;
pub mod swap_util;
pub mod sync_locks;
pub mod sync_loop_monitor;
pub mod sysctl;
pub mod token_manager;
pub mod volume_manager;
pub mod volume_ownership;
pub mod volume_plugins;
pub mod volumes;

pub use kubelet::PodWorkerState;

use config::KubeletConfiguration;
use k3rs_storage::{Storage, StorageBackend};
use std::sync::Arc;
use tracing::info;

/// Configuration for the kubelet component.
pub struct KubeletConfig {
    pub node_name: String,
    pub volume_dir: String,
    pub cluster_dns: String,
    pub cluster_domain: String,
    pub network: String,
    pub sync_interval: u64,
    pub metrics_port: u16,
    pub kubernetes_service_host: String,
    /// Kubelet `--node-ip` (empty = unset).
    pub node_ip: String,
    /// Kubelet `--cloud-provider` (empty or `external`).
    pub cloud_provider: String,
    /// Kubelet `--hostname-override` (empty = use `node_name` as the
    /// hostname).
    pub hostname_override: String,
    /// The co-located api-server's `--service-account-*` / `--api-audiences`
    /// options, so the storage-direct token fallback signs with the same key
    /// and issuer (all-in-one only; see
    /// [`kubelet::service_account_token_manager`]).
    pub service_account: k3rs_common::auth::ServiceAccountOptions,
}

impl Default for KubeletConfig {
    fn default() -> Self {
        Self {
            node_name: "node-1".to_string(),
            volume_dir: "./volumes".to_string(),
            cluster_dns: "10.96.0.10".to_string(),
            cluster_domain: "cluster.local".to_string(),
            network: "k3rs-network".to_string(),
            sync_interval: 3,
            metrics_port: 10250,
            kubernetes_service_host: "10.96.0.1".to_string(),
            node_ip: String::new(),
            cloud_provider: String::new(),
            hostname_override: String::new(),
            service_account: Default::default(),
        }
    }
}

/// Inputs for an authenticated kubelet API (`:10250`), as k3s configures its
/// kubelet (pkg/daemons/agent/agent.go:199-236): anonymous off, webhook
/// (TokenReview) authentication, `Webhook` (SubjectAccessReview)
/// authorization, `x509.clientCAFile` and `tlsCertFile`/`tlsPrivateKeyFile`.
pub struct KubeletApiAuth {
    /// `authentication.x509.clientCAFile` (k3s `<data-dir>/agent/client-ca.crt`).
    pub client_ca_file: String,
    /// `kubeDeps.KubeClient`: the kubelet's own API client, which posts the
    /// TokenReviews and SubjectAccessReviews.
    pub api_client: Arc<k3rs_client::http::ApiClient>,
    /// `tlsCertFile` (k3s `serving-kubelet.crt`).
    pub serving_cert_file: std::path::PathBuf,
    /// `tlsPrivateKeyFile` (k3s `serving-kubelet.key`).
    pub serving_key_file: std::path::PathBuf,
}

/// What the kubelet API server needs: the auth filter's authenticator and
/// authorizer, the client-CA content to keep reloading, and the TLS config.
pub struct KubeletApiServing {
    pub auth: Arc<server_auth::KubeletAuth>,
    pub client_ca: Option<Arc<server_auth::ClientCaContent>>,
    pub tls: axum_server::tls_rustls::RustlsConfig,
}

/// Build the kubelet API's auth and TLS (`BuildAuth`, cmd/kubelet/app/server.go:
/// 719-725, and `InitializeTLS`, :1100-1180).
///
/// `None`: the all-in-one posture, `BuildAuth` with `kubeDeps.KubeClient ==
/// nil` and the legacy flag defaults (`applyLegacyDefaults`): anonymous
/// requests, `AlwaysAllow`, a self-signed serving cert.
///
/// `Some`: the k3s kubelet configuration (agent.go:199-231) as flags through
/// [`server_auth::resolve_auth_config`]. Every failure is an error: an empty
/// client CA path, an unreadable or empty CA bundle, or an unreadable /
/// unparsable / mismatched serving pair never falls back to anonymous access
/// or a self-signed certificate.
pub fn kubelet_api_serving(
    node_name: &str,
    auth: Option<&KubeletApiAuth>,
) -> anyhow::Result<KubeletApiServing> {
    let Some(a) = auth else {
        // SECURITY POSTURE: with no client-CA authn and `AlwaysAllow`, :10250
        // serves exec/attach/run/portForward/pprof/debug to anonymous clients.
        // `k3rs server`/`k3rs agent` pass `Some` (x509 + webhook); the bare
        // all-in-one keeps this, so :10250 must not be reachable from
        // untrusted nets.
        tracing::warn!(
            "kubelet API :10250 is anonymous (AlwaysAllow): exec/attach/run/portForward/pprof/debug are open to any client that can reach it; client-CA authn is a follow-up"
        );
        let (authn_config, authz_config) =
            server_auth::resolve_auth_config(None, &server_auth::AuthFlags::default());
        let (auth, client_ca) =
            server_auth::build_auth(node_name, None, &authn_config, &authz_config)?;
        let tls = serving_tls::kubelet_serving_tls(node_name)?;
        return Ok(KubeletApiServing {
            auth,
            client_ca,
            tls,
        });
    };

    // `--client-ca-file` with an empty value would leave x509 authn off and
    // webhook-token authn as the only method; refuse rather than serve a
    // kubelet whose client certificates are silently ignored.
    if a.client_ca_file.is_empty() {
        anyhow::bail!("kubelet API authentication: client CA file path is empty");
    }
    // k3s `defaultConfig` (agent.go:199-215, 228-230): Anonymous.Enabled=false,
    // Webhook.Enabled=true (CacheTTL 2m), Authorization.Mode=Webhook
    // (CacheAuthorizedTTL 5m, CacheUnauthorizedTTL 30s), X509.ClientCAFile.
    // The TTLs equal `resolve_auth_config`'s defaults.
    let flags = server_auth::AuthFlags {
        anonymous_auth: Some(false),
        authentication_token_webhook: Some(true),
        authentication_token_webhook_cache_ttl: Some(std::time::Duration::from_secs(120)),
        client_ca_file: Some(a.client_ca_file.clone()),
        authorization_mode: Some("Webhook".to_string()),
        authorization_webhook_cache_authorized_ttl: Some(std::time::Duration::from_secs(300)),
        authorization_webhook_cache_unauthorized_ttl: Some(std::time::Duration::from_secs(30)),
    };
    let (authn_config, authz_config) = server_auth::resolve_auth_config(None, &flags);
    // `NewDynamicCAContentFromFile` fails on a missing or empty bundle.
    let (auth, client_ca) = server_auth::build_auth(
        node_name,
        Some(a.api_client.clone()),
        &authn_config,
        &authz_config,
    )
    .map_err(|e| anyhow::anyhow!("kubelet API authentication: {e:#}"))?;
    let tls = serving_tls::kubelet_serving_tls_from_files(
        &a.serving_cert_file,
        &a.serving_key_file,
        Some(&a.client_ca_file),
    )?;
    Ok(KubeletApiServing {
        auth,
        client_ca,
        tls,
    })
}

/// Bind the kubelet API port up front so a bind failure is returned to the
/// caller instead of ending a detached task.
pub fn bind_kubelet_api(addr: &str) -> anyhow::Result<std::net::TcpListener> {
    let listener = std::net::TcpListener::bind(addr)
        .map_err(|e| anyhow::anyhow!("kubelet API: bind {addr}: {e}"))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Serve the kubelet API (`ListenAndServeKubeletServer`, pkg/kubelet/server/
/// server.go:170-207) on `listener` over HTTPS with the peer certificates
/// surfaced to the x509 authenticator, and run the client-CA reload
/// (`runAuthenticatorCAReload`) for as long as it serves. Returns only on a
/// serve error; upstream exits the process there (`os.Exit(1)`).
pub async fn serve_kubelet_api(
    listener: std::net::TcpListener,
    app: axum::Router,
    serving: KubeletApiServing,
) -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    if let Some(ca) = serving.client_ca {
        tokio::spawn(ca.run(stop_rx));
    }
    let tls = serving.tls;
    let res = axum_server::from_tcp_rustls(listener, tls.clone())
        .acceptor(serving_tls::PeerCertAcceptor::new(tls))
        .serve(app.into_make_service())
        .await;
    let _ = stop_tx.send(true);
    match res {
        Ok(()) => anyhow::bail!("kubelet API server stopped"),
        Err(e) => Err(anyhow::anyhow!("kubelet API server: {e}")),
    }
}

/// Run the kubelet component.
///
/// This is the main entry point for embedding the kubelet in the all-in-one binary.
/// Starts the kubelet sync loop and metrics server, blocks until shutdown.
/// The kubelet API is anonymous (`AlwaysAllow`); see [`run_with_auth`].
pub async fn run(storage: Arc<StorageBackend>, config: KubeletConfig) -> anyhow::Result<()> {
    run_with_auth(storage, config, None).await
}

/// [`run`] with the kubelet API's authentication: `Some` serves `:10250` with
/// x509 + webhook authn and webhook authz (see [`kubelet_api_serving`]). Any
/// auth/TLS failure, or a bind failure, is returned before the kubelet
/// starts; a later serve failure ends this function with an error.
pub async fn run_with_auth(
    storage: Arc<StorageBackend>,
    config: KubeletConfig,
    auth: Option<KubeletApiAuth>,
) -> anyhow::Result<()> {
    info!("Starting k3rs Kubelet for node: {}", config.node_name);

    // `BuildAuth` + `InitializeTLS` run before the kubelet is constructed
    // (server.go:719-725 precede RunKubelet), so a bad credential fails fast.
    let api_serving = kubelet_api_serving(&config.node_name, auth.as_ref())?;

    // RunKubelet: ParseNodeIPArgument + NewMainKubelet's cloud-provider gate
    // (server.go:1216-1222, kubelet.go:461-464, 619).
    let (node_ips, external_cloud_provider) =
        node_ip::node_ip_config(&config.node_ip, &config.cloud_provider)
            .map_err(|e| anyhow::anyhow!(e))?;

    // RunKubelet: `nodeutil.GetHostname(kubeServer.HostnameOverride)`
    // (server.go:1208); `node_name` stands in for the hostname when unset.
    let hostname = node_ip::get_hostname(
        if config.hostname_override.is_empty() {
            &config.node_name
        } else {
            &config.hostname_override
        },
        &|| Ok(String::new()),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    // Discover cluster DNS if not hardcoded
    let cluster_dns = {
        use k3rs_common::resources::Service;
        match storage
            .get::<Service>("/registry/services/kube-system/kube-dns")
            .await
        {
            Ok(service) => {
                if let Some(ref cluster_ip) = service.spec.cluster_ip {
                    info!("Discovered cluster DNS IP: {}", cluster_ip);
                    cluster_ip.clone()
                } else {
                    config.cluster_dns.clone()
                }
            }
            Err(_) => config.cluster_dns.clone(),
        }
    };

    // Metrics server
    let metrics =
        Arc::new(k3rs_common::observability::MetricsRegistry::new().with_kubelet_metrics()?);
    let metrics_clone = metrics.clone();

    let kubelet_config = KubeletConfiguration {
        api_version: "kubelet.config.k8s.io/v1beta1".to_string(),
        kind: "KubeletConfiguration".to_string(),
        root_dir: None,
        volume_dir: Some(config.volume_dir.clone()),
        volume_plugin_dir: None,
        sync_frequency: Some(std::time::Duration::from_secs(config.sync_interval)),
        metrics_bind_port: Some(config.metrics_port),
        log_level: Some("info".to_string()),
        cluster_service_cidr: None,
        ..Default::default()
    };
    let kubelet_config = Arc::new(kubelet_config);
    let kubelet_config_clone = kubelet_config.clone();

    let metrics_addr = format!("0.0.0.0:{}", config.metrics_port);
    info!(
        "Starting kubelet API server on {} (exec/attach/portForward/logs, metrics)",
        metrics_addr
    );

    // For the all-in-one binary, derive the statvfs root from the volume dir's
    // parent (or default to /var/lib/kubelet). Eviction config uses upstream
    // defaults; CLI overrides are only available via the standalone `kubelet`
    // binary today.
    let eviction_root = std::path::PathBuf::from(&config.volume_dir)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/kubelet"));
    // `getCheckpointsDir` (kubelet_getters.go:89): `<rootDir>/checkpoints`,
    // with the same root as above.
    let checkpoints_dir = eviction_root.join("checkpoints");

    let k = Arc::new(
        kubelet::Kubelet::new_with_eviction(
            config.node_name.clone(),
            storage.clone(),
            config.sync_interval,
            config.volume_dir,
            cluster_dns,
            config.cluster_domain,
            config.network,
            config.kubernetes_service_host,
            eviction_root,
            eviction::EvictionManager::new(),
            config.metrics_port,
            // The all-in-one binary doesn't expose --allowed-unsafe-sysctls;
            // default to none (unsafe sysctls rejected with SysctlForbidden).
            Vec::new(),
            node_ips,
            external_cloud_provider,
            kubelet::service_account_token_manager(&config.service_account)?,
        )
        .await?
        .with_hostname(&hostname)
        // Upstream defaults (imageGC{High,Low}ThresholdPercent 85/80,
        // imageMinimumGCAge 2m, imageMaximumGCAge 0); the all-in-one binary
        // takes no KubeletConfiguration file.
        .with_image_gc_policy(image_gc::ImageGcPolicy::from_config(
            &config::KubeletConfiguration::default(),
        ))
        .with_container_log_config(
            config::KubeletConfiguration::default().effective_container_log_config(),
        ),
    );

    k.register_pod_certificate_metrics(&metrics.registry);

    let server_state = server::ServerState {
        node_name: config.node_name.clone(),
        storage: storage.clone(),
        kubelet: Some(k.clone()),
    };
    let app = api_router(
        server_state,
        metrics_clone,
        kubelet_config_clone,
        checkpoints_dir,
        api_serving.auth.clone(),
    );
    // Serve the kubelet API port over HTTPS (#1644) — a Kubernetes
    // api-server proxies logs/exec/attach/metrics via `https://…:10250`.
    let listener = bind_kubelet_api(&metrics_addr)?;
    let mut api_server = tokio::spawn(serve_kubelet_api(listener, app, api_serving));

    tokio::select! {
        r = k.run() => r?,
        r = &mut api_server => {
            // `ListenAndServeKubeletServer` exits the process on a serve
            // error (server.go:200-203); end the kubelet with that error.
            return Err(match r {
                Ok(Err(e)) => e,
                Ok(Ok(())) => anyhow::anyhow!("kubelet API server stopped"),
                Err(e) => anyhow::anyhow!("kubelet API server task: {e}"),
            });
        }
    }

    Ok(())
}

/// The kubelet API (`:10250`) router `run()` serves: `NewServer`'s handlers
/// via the standalone kubelet's `server::build_server_router` (same
/// implementation, so exec/attach/portForward/containerLogs/run that the
/// api-server proxies to are served), with `NewServer`'s defaults for a
/// kubelet without a config file (`ServerRouterOptions::from_config(None)`),
/// wrapped in the auth filter (`InstallAuthFilter`, server.go:312-314) and
/// the request-metrics filter (`ServeHTTP`, server.go:1176).
pub fn api_router(
    state: server::ServerState,
    metrics: Arc<k3rs_common::observability::MetricsRegistry>,
    kubelet_config: Arc<KubeletConfiguration>,
    checkpoints_dir: std::path::PathBuf,
    auth: Arc<server_auth::KubeletAuth>,
) -> axum::Router {
    let opts = server::ServerRouterOptions::from_config(
        None,
        checkpoints_dir,
        std::path::PathBuf::from(server_logs::NODE_LOG_DIR),
    );
    let buckets = server::MetricsBuckets::new_server(server::server_bucket_options(
        opts.enable_debugging_handlers,
    ));
    let app = server::build_server_router(state, metrics, kubelet_config, opts);
    let app = server_auth::install_auth_filter(app, Some(auth));
    server::install_metrics_filter(app, buckets, true)
}
