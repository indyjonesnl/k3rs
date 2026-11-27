//! Global connection/identity flags and kubeconfig loading, ported from
//! upstream kubectl:
//!
//! - `cli-runtime/pkg/genericclioptions/config_flags.go` `ConfigFlags.AddFlags`
//!   (:367) and `toRawKubeConfigLoader` (:160): flag -> `ConfigOverrides`.
//! - `client-go/tools/clientcmd/loader.go` `ClientConfigLoadingRules`
//!   (`NewDefaultClientConfigLoadingRules` :159, `Load` :194, `deduplicate`
//!   :668, `ResolveLocalPaths` :509).
//! - `client-go/tools/clientcmd/client_config.go` `DirectClientConfig`
//!   (`getContextName` :464, `getContext` :498, `getAuthInfo` :520,
//!   `getCluster` :557, `Namespace` :399) and `helpers.go` `ParseTimeout`.
//! - `client-go/rest/config.go` `ImpersonationConfig` (Impersonate-User/-Uid/
//!   -Group/-Extra-* headers, `transport/round_trippers.go`).
//!
//! `main.rs` builds its client from [`build_api_client`]. The
//! kubeconfig is parsed into this module's own types so that fields the shared
//! `kubernetes_rs_client::kubeconfig` types lack (`tls-server-name`, `as`,
//! `as-groups`, `disable-compression`, ...) are not dropped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use serde::Deserialize;

/// The kubectl global flags (`ConfigFlags.AddFlags`). Flag names, short forms
/// and help text are upstream's.
#[derive(Args, Debug, Clone, Default)]
pub struct ConfigFlags {
    /// Path to the kubeconfig file to use for CLI requests.
    #[arg(long = "kubeconfig", global = true)]
    pub kubeconfig: Option<String>,
    /// Default cache directory
    #[arg(long = "cache-dir", global = true)]
    pub cache_dir: Option<String>,
    /// Path to a client certificate file for TLS
    #[arg(long = "client-certificate", global = true)]
    pub client_certificate: Option<String>,
    /// Path to a client key file for TLS
    #[arg(long = "client-key", global = true)]
    pub client_key: Option<String>,
    /// Bearer token for authentication to the API server
    #[arg(long = "token", global = true)]
    pub token: Option<String>,
    /// Username to impersonate for the operation. User could be a regular user or a service account in a namespace.
    #[arg(long = "as", global = true)]
    pub impersonate: Option<String>,
    /// UID to impersonate for the operation.
    #[arg(long = "as-uid", global = true)]
    pub impersonate_uid: Option<String>,
    /// Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
    #[arg(long = "as-group", global = true)]
    pub impersonate_group: Vec<String>,
    /// User extras to impersonate for the operation, this flag can be repeated to specify multiple values for the same key.
    #[arg(long = "as-user-extra", global = true)]
    pub impersonate_user_extra: Vec<String>,
    /// Username for basic authentication to the API server
    #[arg(long = "username", global = true)]
    pub username: Option<String>,
    /// Password for basic authentication to the API server
    #[arg(long = "password", global = true)]
    pub password: Option<String>,
    /// The name of the kubeconfig cluster to use
    #[arg(long = "cluster", global = true)]
    pub cluster: Option<String>,
    /// The name of the kubeconfig user to use
    #[arg(long = "user", global = true)]
    pub user: Option<String>,
    /// If present, the namespace scope for this CLI request
    #[arg(short = 'n', long = "namespace", global = true)]
    pub namespace: Option<String>,
    /// The name of the kubeconfig context to use
    #[arg(long = "context", global = true)]
    pub context: Option<String>,
    /// The address and port of the Kubernetes API server
    #[arg(short = 's', long = "server", global = true)]
    pub server: Option<String>,
    /// Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used
    #[arg(long = "tls-server-name", global = true)]
    pub tls_server_name: Option<String>,
    /// If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
    #[arg(long = "insecure-skip-tls-verify", global = true)]
    pub insecure_skip_tls_verify: bool,
    /// Path to a cert file for the certificate authority
    #[arg(long = "certificate-authority", global = true)]
    pub certificate_authority: Option<String>,
    /// The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests.
    #[arg(long = "request-timeout", global = true, default_value = "0")]
    pub request_timeout: String,
    /// If true, opt-out of response compression for all requests to the server
    #[arg(long = "disable-compression", global = true)]
    pub disable_compression: bool,
}

// ---- kubeconfig model (clientcmd/api/v1 types) ----

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case", default)]
pub struct Cluster {
    pub server: String,
    pub tls_server_name: String,
    pub insecure_skip_tls_verify: bool,
    pub certificate_authority: String,
    pub certificate_authority_data: String,
    pub disable_compression: bool,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case", default)]
pub struct AuthInfo {
    pub client_certificate: String,
    pub client_certificate_data: String,
    pub client_key: String,
    pub client_key_data: String,
    pub token: String,
    pub token_file: String,
    #[serde(rename = "as")]
    pub impersonate: String,
    #[serde(rename = "as-uid")]
    pub impersonate_uid: String,
    #[serde(rename = "as-groups")]
    pub impersonate_groups: Vec<String>,
    #[serde(rename = "as-user-extra")]
    pub impersonate_user_extra: BTreeMap<String, Vec<String>>,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Context {
    pub cluster: String,
    pub user: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NamedCluster {
    name: String,
    #[serde(default)]
    cluster: Cluster,
}
#[derive(Debug, Clone, Default, Deserialize)]
struct NamedAuthInfo {
    name: String,
    #[serde(default)]
    user: AuthInfo,
}
#[derive(Debug, Clone, Default, Deserialize)]
struct NamedContext {
    name: String,
    #[serde(default)]
    context: Context,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
struct RawFile {
    clusters: Vec<NamedCluster>,
    users: Vec<NamedAuthInfo>,
    contexts: Vec<NamedContext>,
    current_context: String,
}

/// `clientcmdapi.Config`: named maps (insertion order is irrelevant) plus the
/// current context.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Config {
    pub clusters: BTreeMap<String, Cluster>,
    pub auth_infos: BTreeMap<String, AuthInfo>,
    pub contexts: BTreeMap<String, Context>,
    pub current_context: String,
}

/// `LoadFromFile` + `ResolveLocalPaths` for one file: relative file references
/// are resolved against the kubeconfig's directory (`GetClusterFileReferences`:
/// certificate-authority; `GetAuthInfoFileReferences`: client-certificate,
/// client-key, token-file).
pub fn load_from_file(path: &Path) -> std::io::Result<Config> {
    let text = std::fs::read_to_string(path)?;
    let raw: RawFile = serde_yaml::from_str(&text)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let base = std::path::absolute(path)
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_default();
    let resolve = |p: &mut String| {
        if !p.is_empty() && !Path::new(p.as_str()).is_absolute() {
            *p = base.join(&*p).to_string_lossy().into_owned();
        }
    };
    let mut c = Config {
        current_context: raw.current_context,
        ..Config::default()
    };
    for mut n in raw.clusters {
        resolve(&mut n.cluster.certificate_authority);
        c.clusters.insert(n.name, n.cluster);
    }
    for mut n in raw.users {
        resolve(&mut n.user.client_certificate);
        resolve(&mut n.user.client_key);
        resolve(&mut n.user.token_file);
        c.auth_infos.insert(n.name, n.user);
    }
    for n in raw.contexts {
        c.contexts.insert(n.name, n.context);
    }
    Ok(c)
}

// ---- ClientConfigLoadingRules ----

/// `ClientConfigLoadingRules` (loader.go:99-134), reduced to the fields kubectl
/// sets: `ExplicitPath` and `Precedence`.
#[derive(Debug, Clone, Default)]
pub struct LoadingRules {
    pub explicit_path: String,
    pub precedence: Vec<String>,
}

/// `deduplicate` (loader.go:668).
fn deduplicate(s: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    s.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

impl LoadingRules {
    /// `NewDefaultClientConfigLoadingRules` (loader.go:159-182): the
    /// `KUBECONFIG` path list (`filepath.SplitList`, deduplicated), else
    /// `~/.kube/config`.
    pub fn new_default(kubeconfig_env: Option<&str>, home: Option<&Path>) -> Self {
        let chain = match kubeconfig_env.filter(|v| !v.is_empty()) {
            Some(v) => deduplicate(
                std::env::split_paths(v)
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect(),
            ),
            None => home
                .map(|h| {
                    vec![h
                        .join(".kube")
                        .join("config")
                        .to_string_lossy()
                        .into_owned()]
                })
                .unwrap_or_default(),
        };
        Self {
            explicit_path: String::new(),
            precedence: chain,
        }
    }

    /// `GetLoadingPrecedence` (loader.go:354).
    pub fn loading_precedence(&self) -> Vec<String> {
        if !self.explicit_path.is_empty() {
            return vec![self.explicit_path.clone()];
        }
        self.precedence.clone()
    }

    /// `Load` (loader.go:194-285). A missing explicit file is an error; empty
    /// and missing precedence entries are skipped; an unreadable or
    /// unparseable file is an error (`error loading config file "<f>": ...`).
    ///
    /// Merge: for the named maps the first file to define a name wins and the
    /// entry is never merged with later ones; `current-context` is the first
    /// non-empty value. This is the contract documented on `Load`
    /// (loader.go:186-193), the mapConfig/nonMapConfig split.
    pub fn load(&self) -> Result<Config, String> {
        let files: Vec<String> = if !self.explicit_path.is_empty() {
            if !Path::new(&self.explicit_path).exists() {
                return Err(format!(
                    "stat {}: no such file or directory",
                    self.explicit_path
                ));
            }
            vec![self.explicit_path.clone()]
        } else {
            self.precedence.clone()
        };
        let mut errs = Vec::new();
        let mut merged = Config::default();
        for f in files.iter().filter(|f| !f.is_empty()) {
            match load_from_file(Path::new(f)) {
                Ok(c) => {
                    for (k, v) in c.clusters {
                        merged.clusters.entry(k).or_insert(v);
                    }
                    for (k, v) in c.auth_infos {
                        merged.auth_infos.entry(k).or_insert(v);
                    }
                    for (k, v) in c.contexts {
                        merged.contexts.entry(k).or_insert(v);
                    }
                    if merged.current_context.is_empty() {
                        merged.current_context = c.current_context;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => errs.push(format!("error loading config file \"{f}\": {e}")),
            }
        }
        if errs.is_empty() {
            Ok(merged)
        } else {
            Err(format!("[{}]", errs.join(", ")))
        }
    }
}

// ---- ConfigOverrides and DirectClientConfig ----

/// `clientcmd.ConfigOverrides` (overrides.go), the fields `ConfigFlags` binds.
#[derive(Debug, Clone, Default)]
pub struct ConfigOverrides {
    pub auth_info: AuthInfo,
    pub cluster_info: Cluster,
    pub context: Context,
    pub current_context: String,
    pub timeout: String,
}

impl ConfigFlags {
    /// `toRawKubeConfigLoader` (config_flags.go:160-250): bind flag values to
    /// overrides. The client cert/key flags clear their `-data` twins.
    pub fn to_overrides(&self) -> ConfigOverrides {
        let s = |o: &Option<String>| o.clone().unwrap_or_default();
        let mut extra: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for e in &self.impersonate_user_extra {
            // SplitN(extra, "=", 2): entries without "=" are skipped.
            if let Some((k, v)) = e.split_once('=') {
                extra.entry(k.to_string()).or_default().push(v.to_string());
            }
        }
        ConfigOverrides {
            auth_info: AuthInfo {
                client_certificate: s(&self.client_certificate),
                client_key: s(&self.client_key),
                token: s(&self.token),
                impersonate: s(&self.impersonate),
                impersonate_user_extra: extra,
                impersonate_uid: s(&self.impersonate_uid),
                impersonate_groups: self.impersonate_group.clone(),
                username: s(&self.username),
                password: s(&self.password),
                ..AuthInfo::default()
            },
            cluster_info: Cluster {
                server: s(&self.server),
                tls_server_name: s(&self.tls_server_name),
                certificate_authority: s(&self.certificate_authority),
                insecure_skip_tls_verify: self.insecure_skip_tls_verify,
                disable_compression: self.disable_compression,
                ..Cluster::default()
            },
            context: Context {
                cluster: s(&self.cluster),
                user: s(&self.user),
                namespace: s(&self.namespace),
            },
            current_context: s(&self.context),
            timeout: self.request_timeout.clone(),
        }
    }
}

/// The result of `DirectClientConfig` resolution (the parts of
/// `restclient.Config` kubectl's flags influence).
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedConfig {
    pub cluster: Cluster,
    pub auth_info: AuthInfo,
    pub namespace: String,
    /// `clientConfig.Timeout`; `None` when the flag is empty, `Some(0)` = none.
    pub timeout: Option<Duration>,
}

fn set(dst: &mut String, src: &str) {
    if !src.is_empty() {
        *dst = src.to_string();
    }
}

/// `DirectClientConfig.ClientConfig` resolution (client_config.go:197-). The
/// error strings are upstream's.
pub fn resolve(config: &Config, ov: &ConfigOverrides) -> Result<ResolvedConfig, String> {
    // getContextName / getContext
    let (ctx_name, ctx_required) = if !ov.current_context.is_empty() {
        (ov.current_context.clone(), true)
    } else {
        (config.current_context.clone(), false)
    };
    let mut context = Context::default();
    match config.contexts.get(&ctx_name) {
        Some(c) => context = c.clone(),
        None if ctx_required => return Err(format!("context {ctx_name:?} does not exist")),
        None => {}
    }
    set(&mut context.cluster, &ov.context.cluster);
    set(&mut context.user, &ov.context.user);
    set(&mut context.namespace, &ov.context.namespace);

    // getAuthInfo
    let (user_name, user_required) = if !ov.context.user.is_empty() {
        (ov.context.user.clone(), true)
    } else {
        (context.user.clone(), false)
    };
    let mut a = match config.auth_infos.get(&user_name) {
        Some(a) => a.clone(),
        None if user_required => return Err(format!("auth info {user_name:?} does not exist")),
        None => AuthInfo::default(),
    };
    let o = &ov.auth_info;
    for (d, s) in [
        (&mut a.token, &o.token),
        (&mut a.token_file, &o.token_file),
        (&mut a.impersonate, &o.impersonate),
        (&mut a.impersonate_uid, &o.impersonate_uid),
        (&mut a.username, &o.username),
        (&mut a.password, &o.password),
    ] {
        set(d, s);
    }
    if !o.impersonate_groups.is_empty() {
        a.impersonate_groups = o.impersonate_groups.clone();
    }
    for (k, v) in &o.impersonate_user_extra {
        a.impersonate_user_extra.insert(k.clone(), v.clone());
    }
    // An override of the cert/key replaces the file AND data (client_config.go:537-550).
    if !o.client_key.is_empty() || !o.client_key_data.is_empty() {
        a.client_key = o.client_key.clone();
        a.client_key_data = o.client_key_data.clone();
    }
    if !o.client_certificate.is_empty() || !o.client_certificate_data.is_empty() {
        a.client_certificate = o.client_certificate.clone();
        a.client_certificate_data = o.client_certificate_data.clone();
    }

    // getCluster
    let (cl_name, cl_required) = if !ov.context.cluster.is_empty() {
        (ov.context.cluster.clone(), true)
    } else {
        (context.cluster.clone(), false)
    };
    let mut c = match config.clusters.get(&cl_name) {
        Some(c) => c.clone(),
        None if cl_required => return Err(format!("cluster {cl_name:?} does not exist")),
        None => Cluster::default(),
    };
    let oc = &ov.cluster_info;
    set(&mut c.server, &oc.server);
    set(&mut c.tls_server_name, &oc.tls_server_name);
    set(&mut c.certificate_authority, &oc.certificate_authority);
    set(
        &mut c.certificate_authority_data,
        &oc.certificate_authority_data,
    );
    c.insecure_skip_tls_verify |= oc.insecure_skip_tls_verify;
    c.disable_compression |= oc.disable_compression;
    // --insecure-skip-tls-verify / --certificate-authority replace the file's
    // CA settings so they cannot conflict (client_config.go:580-590).
    if oc.insecure_skip_tls_verify
        || !oc.certificate_authority.is_empty()
        || !oc.certificate_authority_data.is_empty()
    {
        c.insecure_skip_tls_verify = oc.insecure_skip_tls_verify;
        c.certificate_authority = oc.certificate_authority.clone();
        c.certificate_authority_data = oc.certificate_authority_data.clone();
    }
    // --server clears the file's tls-server-name unless --tls-server-name is set (:592-598).
    if !oc.tls_server_name.is_empty() || !oc.server.is_empty() {
        c.tls_server_name = oc.tls_server_name.clone();
    }

    // Namespace (client_config.go:399-422): the override wins, else the context's, else "default".
    let namespace = if !ov.context.namespace.is_empty() {
        ov.context.namespace.clone()
    } else if context.namespace.is_empty() {
        "default".to_string()
    } else {
        context.namespace.clone()
    };

    let timeout = if ov.timeout.is_empty() {
        None
    } else {
        Some(parse_timeout(&ov.timeout)?)
    };
    Ok(ResolvedConfig {
        cluster: c,
        auth_info: a,
        namespace,
        timeout,
    })
}

/// `ParseTimeout` (helpers.go:28): a non-negative integer is seconds, else a
/// Go duration (`1s`, `2m`, `1h30m`, `500ms`).
pub fn parse_timeout(s: &str) -> Result<Duration, String> {
    if let Ok(i) = s.parse::<i64>() {
        if i >= 0 {
            return Ok(Duration::from_secs(i as u64));
        }
    }
    if let Some(d) = parse_go_duration(s) {
        return Ok(d);
    }
    Err("Invalid timeout value. Timeout must be a single integer in seconds, or an integer followed by a corresponding time unit (e.g. 1s | 2m | 3h)".to_string())
}

/// `time.ParseDuration` for non-negative durations.
fn parse_go_duration(s: &str) -> Option<Duration> {
    let s = s.strip_prefix('+').unwrap_or(s);
    if s == "0" {
        return Some(Duration::ZERO);
    }
    if s.is_empty() {
        return None;
    }
    let mut rest = s;
    let mut total_ns: f64 = 0.0;
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let num: f64 = rest[..end].parse().ok()?;
        rest = &rest[end..];
        let uend = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let unit = match &rest[..uend] {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 6e10,
            "h" => 3.6e12,
            _ => return None,
        };
        rest = &rest[uend..];
        total_ns += num * unit;
    }
    Some(Duration::from_nanos(total_ns as u64))
}

/// `headerKeyEscape` (transport/round_trippers.go:697): %-encode every byte
/// that is not a legal header-key byte, and `%` itself.
fn header_key_escape(key: &str) -> String {
    let legal = |b: u8| b.is_ascii_alphanumeric() || b"!#$&'*+-.^_`|~".contains(&b);
    key.bytes()
        .map(|b| {
            if legal(b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

impl AuthInfo {
    /// The impersonation headers client-go adds: `HTTPWrappersForConfig`
    /// (transport/transport.go) wraps the transport when any of user, uid,
    /// groups or extra is set, and `impersonatingRoundTripper.RoundTrip`
    /// (round_trippers.go:247-267) sets `Impersonate-User`, `Impersonate-Uid`,
    /// one `Impersonate-Group` per group and `Impersonate-Extra-<escaped key>`
    /// per value.
    pub fn impersonation_headers(&self) -> Vec<(String, String)> {
        if self.impersonate.is_empty()
            && self.impersonate_uid.is_empty()
            && self.impersonate_groups.is_empty()
            && self.impersonate_user_extra.is_empty()
        {
            return Vec::new();
        }
        let mut h = vec![("Impersonate-User".to_string(), self.impersonate.clone())];
        if !self.impersonate_uid.is_empty() {
            h.push(("Impersonate-Uid".to_string(), self.impersonate_uid.clone()));
        }
        for g in &self.impersonate_groups {
            h.push(("Impersonate-Group".to_string(), g.clone()));
        }
        for (k, vs) in &self.impersonate_user_extra {
            for v in vs {
                h.push((
                    format!("Impersonate-Extra-{}", header_key_escape(k)),
                    v.clone(),
                ));
            }
        }
        h
    }
}

/// Convenience: the kubeconfig path list for the process environment.
pub fn default_loading_rules() -> LoadingRules {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    LoadingRules::new_default(std::env::var("KUBECONFIG").ok().as_deref(), home.as_deref())
}

/// `dataFromSliceOrFile` (client-go transport/transport.go): inline `-data`
/// (base64 in a kubeconfig) wins over the file.
fn data_or_file(data: &str, file: &str, what: &str) -> Result<Option<Vec<u8>>, String> {
    use base64::Engine;
    if !data.is_empty() {
        return base64::engine::general_purpose::STANDARD
            .decode(data.trim())
            .map(Some)
            .map_err(|e| format!("{what}: illegal base64 data: {e}"));
    }
    if !file.is_empty() {
        return std::fs::read(file)
            .map(Some)
            .map_err(|e| format!("open {file}: {e}"));
    }
    Ok(None)
}

/// The bearer token: `BearerToken`, else the trimmed content of
/// `BearerTokenFile` (`NewBearerAuthWithRefreshRoundTripper`, which reads and
/// `TrimSpace`s the file).
fn bearer_token(a: &AuthInfo) -> Result<Option<String>, String> {
    if !a.token.is_empty() {
        return Ok(Some(a.token.clone()));
    }
    if a.token_file.is_empty() {
        return Ok(None);
    }
    std::fs::read_to_string(&a.token_file)
        .map(|t| Some(t.trim().to_string()))
        .map_err(|e| format!("open {}: {e}", a.token_file))
}

/// Build the HTTP client from a resolved kubeconfig: CA, client certificate
/// and key (data or file), bearer token (or token file), basic auth, and the
/// impersonation headers. `--insecure-skip-tls-verify` ignores the CA, as
/// `getServerIdentificationPartialConfig` does; the client identity is
/// presented regardless.
///
/// Not carried over yet: `--tls-server-name`, `--request-timeout` and
/// `--disable-compression` are parsed and validated but have no effect
/// (reqwest has no SNI override, the shared client keeps its 60s request
/// timeout, and compression is not negotiated at all).
pub fn build_api_client(
    r: &ResolvedConfig,
) -> Result<kubernetes_rs_client::http::ApiClient, String> {
    let c = &r.cluster;
    let a = &r.auth_info;
    let server = if c.server.is_empty() {
        "https://localhost:6443".to_string()
    } else {
        c.server.clone()
    };
    let ca = if c.insecure_skip_tls_verify {
        None
    } else {
        data_or_file(
            &c.certificate_authority_data,
            &c.certificate_authority,
            "certificate-authority-data",
        )?
    };
    let cert = data_or_file(
        &a.client_certificate_data,
        &a.client_certificate,
        "client-certificate-data",
    )?;
    let key = data_or_file(&a.client_key_data, &a.client_key, "client-key-data")?;
    let token = bearer_token(a)?;
    if token.is_some() && !a.username.is_empty() {
        return Err("username/password or bearer token may be set, but not both".to_string());
    }
    let mut client = kubernetes_rs_client::http::ApiClient::with_tls(
        &server,
        c.insecure_skip_tls_verify,
        ca,
        cert,
        key,
        token,
    )
    .map_err(|e| format!("{e:#}"))?
    .with_extra_headers(a.impersonation_headers());
    if !a.username.is_empty() {
        client = client
            .with_basic_auth(&a.username, &a.password)
            .map_err(|e| e.to_string())?;
    }
    Ok(client)
}

/// The loading rules for a `--kubeconfig` flag (`ExplicitPath`) or, without
/// it, the `KUBECONFIG` / `~/.kube/config` chain.
pub fn loading_rules_for(flags: &ConfigFlags) -> LoadingRules {
    let mut rules = default_loading_rules();
    if let Some(p) = flags.kubeconfig.as_deref().filter(|p| !p.is_empty()) {
        rules.explicit_path = p.to_string();
    }
    rules
}
