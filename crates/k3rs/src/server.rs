//! `k3rs server`: control plane plus a node, in one process.
//!
//! Port of k3s `pkg/cli/server/server.go` (`run`: node name/IP defaulting via
//! `util.GetHostnameAndIPs`, cluster/service CIDR and cluster-DNS defaults),
//! `pkg/server/server.go` (`printTokens` / `printToken`) and the kube-apiserver
//! / kube-controller-manager flag maps of `pkg/daemons/control/server.go`
//! (`apiServer` :210-263, `controllerManager` :116-118). Instead of exec'ing
//! components with flag maps, the flags are synthesised into the all-in-one
//! `Args` and the all-in-one runs with server `Overrides` (supervisor routes,
//! node IPAM, node-network agent, per-component client certs).
//!
//! Authentication: like k3s (`apiServer` :216-224, `client-ca-file`,
//! `authorization-mode=Node,RBAC`), the api-server authenticates client certs
//! against the client CA and authorizes with Node,RBAC; every embedded
//! component uses its own cert identity minted by
//! `Pki::ensure_component_creds` (k3s `deps.go:330-420`).
//!
//! Deliberate deviations: default service CIDR / cluster DNS are the k3rs
//! defaults `10.96.0.0/12` / `10.96.0.10` (k3s: `10.43.0.0/16` /
//! `10.43.0.10`), pod CIDR `10.244.0.0/16` (k3s `10.42.0.0/16`). k3s also
//! sets `anonymous-auth=false`; the k3rs api-server has no enforced
//! anonymous-auth switch (see `server_argv`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use k3rs::cli::ServerArgs;
use k3rs::supervisor::{ClusterInfo, SupervisorState};
use k3rs_controller_manager::controllers::node_ipam::{NodeCidrMaskSizes, NodeIpamConfig};

use crate::{api_port, run_all_in_one, Args, Overrides};

/// Service ClusterIP range (`--service-cluster-ip-range`); CIDR form, the
/// agent parses it from `/v1-k3rs/config` with `ServiceIpRanges::parse`.
pub(crate) const SERVICE_CIDR: &str = "10.96.0.0/12";
/// Cluster DNS ClusterIP (`kube-dns`, bootstrap-cluster.yaml).
pub(crate) const CLUSTER_DNS: &str = "10.96.0.10";
/// `cfg.ClusterDomain` default.
const CLUSTER_DOMAIN: &str = "cluster.local";
/// CN of `front-proxy-client.crt` (pki.rs). k3s uses `deps.RequestHeaderCN`
/// = `system:auth-proxy` for its own front-proxy cert; the allowed name must
/// match the cert this PKI issues.
const FRONT_PROXY_CN: &str = "front-proxy-client";
/// `printToken` (pkg/server/server.go:496-498), with the node IP as the
/// advertise address and the token inline rather than a `${VAR}` placeholder.
pub(crate) fn join_line(node_ip: &str, port: u16, token: &str) -> String {
    let host = node_ip.split(',').next().unwrap_or(node_ip).trim();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("To join a node: k3rs agent --server https://{host}:{port} --token {token}")
}

/// The all-in-one argv for a server (pkg/daemons/control/server.go `apiServer`
/// argsMap :210-263): serving cert, client CA, `authorization-mode=Node,RBAC`
/// (:217-221), front-proxy request-header flags, service-account key pair,
/// issuer and audiences; sqlite datastore under `<data-dir>/db` (k3s
/// `<data-dir>/server/db/state.db`). No `--skip-auth`: requests are
/// authenticated (x509 client cert, SA/bootstrap tokens) and authorized.
///
/// `anonymous-auth=false` (:222-226) has no enforced equivalent in the k3rs
/// api-server (`--anonymous-auth=false` is accepted but ignored by the
/// standalone binary, `upstream_flags.rs`): an unauthenticated request is
/// `system:anonymous`, which RBAC denies on API routes (403, not k3s' 401),
/// while `/healthz`, `/livez`, `/readyz`, `/metrics` and `/version` stay
/// unauthenticated public routes.
pub(crate) fn server_argv(a: &ServerArgs, node_name: &str, node_ip: &str) -> Vec<String> {
    let dir = a.data_dir.trim_end_matches('/');
    let dns_bind = dns_bind(node_ip);
    let tls = format!("{dir}/tls");
    let issuer = format!("https://kubernetes.default.svc.{CLUSTER_DOMAIN}");
    let mut v: Vec<String> = [
        "k3rs",
        "--tls",
        "--tls-cert-file",
        &format!("{tls}/serving.crt"),
        "--tls-key-file",
        &format!("{tls}/serving.key"),
        "--client-ca-file",
        &format!("{tls}/client-ca.crt"),
        "--requestheader-client-ca-file",
        &format!("{tls}/request-header-ca.crt"),
        "--requestheader-allowed-names",
        FRONT_PROXY_CN,
        "--requestheader-extra-headers-prefix",
        "X-Remote-Extra-",
        "--requestheader-group-headers",
        "X-Remote-Group",
        "--requestheader-username-headers",
        "X-Remote-User",
        "--service-account-key-file",
        &format!("{tls}/sa.pub"),
        "--service-account-signing-key-file",
        &format!("{tls}/sa.key"),
        "--service-account-issuer",
        &issuer,
        "--api-audiences",
        &format!("{issuer},k3rs"),
        "--service-cluster-ip-range",
        SERVICE_CIDR,
        "--cluster-dns",
        CLUSTER_DNS,
        "--storage-backend",
        "sqlite",
        "--data-dir",
        &format!("{dir}/db/state.db"),
        "--volume-dir",
        &format!("{dir}/agent/volumes"),
        "--bind-address",
        &a.bind_address,
        "--node-name",
        node_name,
        "--node-ip",
        node_ip,
        "--dns-bind",
        &dns_bind,
        "--authorization-mode",
        "Node,RBAC",
        "--skip-auth=false",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if a.disable_dns {
        v.push("--disable-dns".into());
    }
    if a.disable_proxy {
        v.push("--disable-proxy".into());
    }
    v
}

/// Where the in-process k3rs-dns listens: the node IP the kube-dns
/// EndpointSlice advertises (`bootstrap::objects`, first address), port 53.
/// k3rs-only (k3s runs CoreDNS as a pod, in its own netns). Not the
/// all-in-one's `0.0.0.0:53`: on a host running a stub resolver
/// (systemd-resolved on 127.0.0.53:53 / 127.0.0.54:53, e.g. Debian cloud
/// images) the wildcard bind fails with EADDRINUSE and the cluster has no DNS.
pub(crate) fn dns_bind(node_ip: &str) -> String {
    let ip = node_ip.split(',').next().unwrap_or(node_ip).trim();
    if ip.contains(':') {
        format!("[{ip}]:53")
    } else {
        format!("{ip}:53")
    }
}

/// Parse an all-in-one argv the way `async_main` does, including the raw
/// matches the legacy authorization flags need.
pub(crate) fn parse_args_from(argv: Vec<String>) -> Result<Args> {
    let matches = <Args as clap::CommandFactory>::command().try_get_matches_from(argv)?;
    let mut args = <Args as clap::FromArgMatches>::from_arg_matches(&matches)?;
    args.authorization.mark_legacy_flags_set(&matches);
    Ok(args)
}

/// What `/v1-k3rs/config` tells agents.
pub(crate) fn cluster_info(a: &ServerArgs) -> ClusterInfo {
    ClusterInfo {
        cluster_cidr: a.cluster_cidr.clone(),
        service_cidr: SERVICE_CIDR.to_string(),
        cluster_dns: CLUSTER_DNS.to_string(),
    }
}

/// k3s runs kube-controller-manager with `allocate-node-cidrs=true`,
/// `cluster-cidr` and `service-cluster-ip-range` (pkg/daemons/control/
/// server.go:116-118) and no mask flag, so upstream's IPv4 default /24
/// applies (`defaultNodeMaskCIDRIPv4`, cmd/kube-controller-manager/app/
/// core.go:79, via `setNodeCIDRMaskSizes`).
pub(crate) fn node_ipam(info: &ClusterInfo) -> Result<NodeIpamConfig> {
    NodeIpamConfig::from_flags(
        &info.cluster_cidr,
        NodeCidrMaskSizes::default(),
        Some(&info.service_cidr),
    )
    .map_err(|e| anyhow!("node IPAM: {e}"))
}

/// The api-server reads the cluster CA (kube-root-ca.crt, SA token `ca.crt`)
/// from `ca.crt` next to `--tls-cert-file` (`resolve_ca_cert_pem`). Point it
/// at the server CA, which signs the serving cert, so it never falls back to
/// an unrelated `/etc/kubernetes/pki/ca.crt` or `~/.k3rs/certs/ca.crt`.
pub(crate) fn link_cluster_ca(tls_dir: &Path) -> Result<()> {
    let link = tls_dir.join("ca.crt");
    if std::fs::read_link(&link).ok().as_deref() == Some(Path::new("server-ca.crt")) {
        return Ok(());
    }
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink("server-ca.crt", &link)
        .with_context(|| format!("symlink {}", link.display()))
}

pub async fn run_server(a: ServerArgs) -> Result<()> {
    // Node name and IP defaults: `util.GetHostnameAndIPs`
    // (k3s pkg/cli/server/server.go:293, pkg/util/net.go:138-168).
    let node_name = match &a.node_name {
        Some(n) => n.clone(),
        None => k3rs::agent::default_node_name()?,
    };
    let node_ip = match &a.node_ip {
        Some(ip) => ip.clone(),
        None => k3rs::pki::primary_ipv4()
            .ok_or_else(|| anyhow!("no non-loopback IPv4 address found; pass --node-ip"))?
            .to_string(),
    };

    // SANs: `--tls-san` plus node name and IPs (server.go:293-300 appends
    // them to `ControlConfig.SANs`).
    let data_dir = PathBuf::from(&a.data_dir);
    let mut sans = a.tls_san.clone();
    sans.push(node_name.clone());
    sans.extend(node_ip.split(',').map(|s| s.trim().to_string()));
    let pki = k3rs::pki::Pki::load_or_create(&data_dir, &sans).context("server PKI")?;
    link_cluster_ca(&pki.dir)?;
    std::fs::create_dir_all(data_dir.join("db"))?;

    // `--token` / `--token-file` pin the secret (k3s `--token`); otherwise
    // the persisted token is reused or a new one generated (`printTokens`).
    let preset = match (&a.token, &a.token_file) {
        (Some(t), _) => Some(t.clone()),
        (None, Some(f)) => Some(
            std::fs::read_to_string(f)
                .with_context(|| format!("read token file {f}"))?
                .trim()
                .to_string(),
        ),
        (None, None) => None,
    };
    let token = k3rs::token::load_or_create_token(&data_dir, &pki.ca_hash(), preset.as_deref())?;
    let token_password = k3rs::token::parse_token(&token)?.password;
    // `printTokens` logs the token file and the join command (server.go:371-372).
    println!(
        "Server node token is available at {}",
        data_dir.join("token").display()
    );
    let port = api_port(&a.bind_address);
    println!("{}", join_line(&node_ip, port, &token));
    // The node's kubelet API still serves anonymously until it gets x509
    // authn + webhook authz. stderr so it shows without a tracing subscriber
    // (tracing is initialised later, inside run_all_in_one).
    eprintln!("WARNING: {}", k3rs::util::KUBELET_ANON_WARNING);
    tracing::warn!("{}", k3rs::util::KUBELET_ANON_WARNING);

    // Per-component client identities (k3s `genClientCerts`,
    // pkg/daemons/control/deps/deps.go:330-420), plus this node's kubelet
    // identity and serving cert. The first node IP goes into the serving
    // cert's SANs.
    let first_ip = node_ip.split(',').next().unwrap_or(&node_ip).trim();
    let component_creds = pki
        .ensure_component_creds(&node_name, first_ip)
        .context("component credentials")?;
    k3rs::agent::ensure_crypto_provider();

    let args = parse_args_from(server_argv(&a, &node_name, &node_ip))?;
    let info = cluster_info(&a);
    let pki = Arc::new(pki);
    let sup_info = info.clone();
    let ov = Overrides {
        extra_router: Some(Box::new(move |storage| {
            k3rs::supervisor::router(SupervisorState {
                pki,
                token_password,
                storage,
                cluster_info: sup_info,
            })
        })),
        node_ipam: Some(node_ipam(&info)?),
        node_net: Some(k3rs::util::node_net_config(&node_name, &info)),
        // kube-dns Service + EndpointSlice (k3rs-dns runs in-process). The hook
        // is synchronous and runs before signal setup, so spawn the retrying
        // apply and only log on failure.
        post_start: Some(Box::new(|ctx| {
            tokio::spawn(async move {
                let objs = k3rs::bootstrap::objects(&ctx.node_ip);
                if let Err(e) = k3rs::bootstrap::apply_all(&ctx.loopback_client, &objs).await {
                    tracing::error!("applying bootstrap objects failed: {e:#}");
                }
            });
        })),
        component_creds: Some(component_creds),
    };
    run_all_in_one(args, ov).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn server_args(dir: &str) -> k3rs::cli::ServerArgs {
        k3rs::cli::ServerArgs::try_parse_from(["server", "--data-dir", dir]).unwrap()
    }

    #[test]
    fn server_flags_synthesise_valid_args() {
        let argv = server_argv(&server_args("/srv/k3rs"), "node-a", "192.0.2.10");
        let args = parse_args_from(argv).unwrap();
        assert!(args.tls);
        assert!(!args.skip_auth);
        assert_eq!(
            args.tls_cert_file.as_deref(),
            Some("/srv/k3rs/tls/serving.crt")
        );
        assert_eq!(
            args.tls_key_file.as_deref(),
            Some("/srv/k3rs/tls/serving.key")
        );
        assert_eq!(
            args.client_ca_file.as_deref(),
            Some("/srv/k3rs/tls/client-ca.crt")
        );
        assert_eq!(
            args.request_header.client_ca_file,
            "/srv/k3rs/tls/request-header-ca.crt"
        );
        assert_eq!(args.request_header.allowed_names, ["front-proxy-client"]);
        assert_eq!(args.request_header.username_headers, ["X-Remote-User"]);
        assert_eq!(args.request_header.group_headers, ["X-Remote-Group"]);
        assert_eq!(
            args.request_header.extra_headers_prefix,
            ["X-Remote-Extra-"]
        );
        assert_eq!(args.data_dir, "/srv/k3rs/db/state.db");
        assert_eq!(args.storage_backend, "sqlite");
        assert_eq!(args.node_name, "node-a");
        assert_eq!(args.node_ip, "192.0.2.10");
        assert_eq!(args.bind_address, "0.0.0.0:6443");
        assert_eq!(args.volume_dir, "/srv/k3rs/agent/volumes");
        assert_eq!(args.service_cluster_ip_range, SERVICE_CIDR);
        assert_eq!(args.cluster_dns, CLUSTER_DNS);
        // k3rs-dns binds the node IP the kube-dns EndpointSlice advertises.
        assert_eq!(args.dns_bind, "192.0.2.10:53");
        assert_eq!(
            args.service_account.service_account_key_file,
            ["/srv/k3rs/tls/sa.pub"]
        );
        assert_eq!(
            args.service_account
                .service_account_signing_key_file
                .as_deref(),
            Some("/srv/k3rs/tls/sa.key")
        );
        assert!(!args.disable_dns);
        assert!(!args.disable_proxy);
        // The front-proxy CA must differ from the client CA (authentication.go
        // overlap rule): resolve() accepts the synthesised pair.
        assert!(args
            .request_header
            .resolve(args.client_ca_file.as_deref())
            .is_ok());
    }

    #[test]
    fn server_disable_flags_pass_through() {
        let a = k3rs::cli::ServerArgs::try_parse_from([
            "server",
            "--data-dir",
            "/d",
            "--disable-dns",
            "--disable-proxy",
            "--bind-address",
            "127.0.0.1:16443",
        ])
        .unwrap();
        let args = parse_args_from(server_argv(&a, "n", "192.0.2.1")).unwrap();
        assert!(args.disable_dns);
        assert!(args.disable_proxy);
        assert_eq!(args.bind_address, "127.0.0.1:16443");
        assert_eq!(api_port(&a.bind_address), 16443);
    }

    /// k3s `apiServer` (pkg/daemons/control/server.go:217-221, :259): client
    /// CA set, `authorization-mode=Node,RBAC`; never the all-in-one's
    /// `--skip-auth` default.
    #[test]
    fn server_argv_has_no_skip_auth_and_sets_authz() {
        let argv = server_argv(&server_args("/srv/k3rs"), "node-a", "192.0.2.10");
        assert!(!argv.iter().any(|a| a == "--skip-auth"), "{argv:?}");
        let at = argv.iter().position(|a| a == "--client-ca-file").unwrap();
        assert_eq!(argv[at + 1], "/srv/k3rs/tls/client-ca.crt");
        let at = argv
            .iter()
            .position(|a| a == "--authorization-mode")
            .unwrap();
        assert_eq!(argv[at + 1], "Node,RBAC");
        let args = parse_args_from(argv).unwrap();
        assert!(!args.skip_auth);
        assert_eq!(args.authorization.authorization_mode, ["Node", "RBAC"]);
        assert_eq!(
            args.client_ca_file.as_deref(),
            Some("/srv/k3rs/tls/client-ca.crt")
        );
    }

    /// Must match the address `bootstrap::objects` puts in the kube-dns
    /// EndpointSlice (first node IP), and never be the wildcard, which
    /// collides with a host stub resolver on 127.0.0.53:53.
    #[test]
    fn dns_binds_the_advertised_node_ip() {
        assert_eq!(dns_bind("10.72.0.2"), "10.72.0.2:53");
        assert_eq!(dns_bind("10.72.0.2, fd00::2"), "10.72.0.2:53");
        assert_eq!(dns_bind("fd00::2"), "[fd00::2]:53");
        let eps = k3rs::bootstrap::objects("10.72.0.2,fd00::2");
        let advertised = serde_json::to_string(&eps.iter().map(|o| &o.body).collect::<Vec<_>>())
            .unwrap_or_default();
        assert!(advertised.contains("\"10.72.0.2\""));
        assert!(dns_bind("10.72.0.2,fd00::2")
            .parse::<std::net::SocketAddr>()
            .is_ok());
    }

    #[test]
    fn join_line_names_node_ip_port_and_token() {
        assert_eq!(
            join_line("192.0.2.10", 6443, "K10abc::server:pw"),
            "To join a node: k3rs agent --server https://192.0.2.10:6443 --token K10abc::server:pw"
        );
    }

    #[test]
    fn overrides_turn_on_ipam_and_node_net() {
        let a = server_args("/d");
        let info = cluster_info(&a);
        assert_eq!(info.cluster_cidr, "10.244.0.0/16");
        assert_eq!(info.service_cidr, "10.96.0.0/12");
        assert_eq!(info.cluster_dns, "10.96.0.10");
        let ipam = node_ipam(&info).unwrap();
        assert_eq!(ipam.cluster_cidrs, ["10.244.0.0/16".parse().unwrap()]);
        assert_eq!(ipam.node_masks, [24]);
        assert_eq!(ipam.service_cidrs, ["10.96.0.0/12".parse().unwrap()]);
        let nn = k3rs::util::node_net_config("node-a", &info);
        assert_eq!(nn.node_name, "node-a");
        assert_eq!(nn.cni_conf_path, "/etc/cni/net.d/10-k3rs.conflist");
        assert_eq!(nn.no_masq_cidrs, ["10.244.0.0/16", "10.96.0.0/12"]);
    }

    /// The generated service-account key pair loads through the same code the
    /// api-server uses for `--service-account-key-file` /
    /// `--service-account-signing-key-file`.
    #[test]
    fn pki_sa_keys_load_through_sa_keys() {
        let dir = tempfile::tempdir().unwrap();
        let pki = k3rs::pki::Pki::load_or_create(dir.path(), &[]).unwrap();
        let pubs =
            k3rs_common::sa_keys::public_keys_from_file(pki.dir.join("sa.pub").to_str().unwrap())
                .unwrap();
        assert_eq!(pubs.len(), 1);
        let signing = k3rs_common::sa_keys::signing_key_from_pem(
            &std::fs::read(pki.dir.join("sa.key")).unwrap(),
        )
        .unwrap();
        assert_eq!(signing.key_id, pubs[0].key_id);
    }

    /// kube-root-ca.crt / SA token CA come from `ca.crt` next to the serving
    /// cert (`resolve_ca_cert_pem`); it must be the server CA.
    #[test]
    fn cluster_ca_next_to_serving_cert_is_server_ca() {
        let dir = tempfile::tempdir().unwrap();
        let pki = k3rs::pki::Pki::load_or_create(dir.path(), &[]).unwrap();
        link_cluster_ca(&pki.dir).unwrap();
        link_cluster_ca(&pki.dir).unwrap(); // idempotent
        let serving = pki.dir.join("serving.crt");
        let pem = k3rs_api_server::resolve_ca_cert_pem(serving.to_str(), "SERVING");
        assert_eq!(pem, pki.server_ca_pem());
    }
}
