//! client-go exec credential plugin runner (`client.authentication.k8s.io`).
//!
//! Port of `staging/src/k8s.io/client-go/plugin/pkg/client/auth/exec/exec.go`
//! (release-1.35): `newAuthenticator` (:165: apiVersion and plugin-policy
//! validation, `filepath.Clean(command)`, env), `isInteractive` (:236),
//! `refreshCredsLocked` (:434: `KUBERNETES_EXEC_INFO`, run, decode, status
//! validation), `wrapCmdRunErrorLocked` (:548: install hint, exit code),
//! `updateCommandAndCheckAllowlistLocked` / `checkAllowlistLocked` /
//! `resolveAllowListEntriesLocked` (:580-:640), `ValidatePluginPolicy` (:660)
//! and the `sometimes` rate limiter for the install hint.
//!
//! This slice runs the plugin and returns its status. Credential caching and
//! expiry, X.509 parsing of the returned pair, connection rotation and wiring
//! into the HTTP client are separate (backlog client-P2-15b).

use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// `execInfoEnv` (exec.go:56).
pub const EXEC_INFO_ENV: &str = "KUBERNETES_EXEC_INFO";

/// `installHintVerboseHelp` (exec.go:57).
pub const INSTALL_HINT_VERBOSE_HELP: &str = "\n\nIt looks like you are trying to use a client-go credential plugin that is not installed.\n\nTo learn more about this feature, consult the documentation available at:\n      https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins";

const V1: &str = "client.authentication.k8s.io/v1";
const V1BETA1: &str = "client.authentication.k8s.io/v1beta1";

/// `api.ExecEnvVar`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecEnvVar {
    pub name: String,
    pub value: String,
}

/// `api.AllowlistEntry`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AllowlistEntry {
    #[serde(default)]
    pub name: String,
}

/// `api.PluginPolicy`: `"" | "AllowAll" | "DenyAll" | "Allowlist"`.
/// `allowlist: None` is a nil Go slice (distinct from an empty one).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginPolicy {
    #[serde(default)]
    pub policy_type: String,
    #[serde(default)]
    pub allowlist: Option<Vec<AllowlistEntry>>,
}

/// `api.ExecConfig` (client-go/tools/clientcmd/api/types.go).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecConfig {
    #[serde(default)]
    pub api_version: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<ExecEnvVar>,
    /// `Never | IfAvailable | Always`; empty is rejected, as upstream.
    #[serde(default)]
    pub interactive_mode: String,
    #[serde(default)]
    pub provide_cluster_info: bool,
    #[serde(default)]
    pub install_hint: String,
    #[serde(default)]
    pub plugin_policy: PluginPolicy,
    /// `StdinUnavailable` (set by the client, not from kubeconfig YAML).
    #[serde(skip)]
    pub stdin_unavailable: bool,
    #[serde(skip)]
    pub stdin_unavailable_message: String,
}

/// `clientauthentication.Cluster` (sent when `provideClusterInfo`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Cluster {
    pub server: String,
    #[serde(
        rename = "tls-server-name",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub tls_server_name: String,
    #[serde(
        rename = "insecure-skip-tls-verify",
        skip_serializing_if = "std::ops::Not::not",
        default
    )]
    pub insecure_skip_tls_verify: bool,
    /// Raw PEM; base64 on the wire (`[]byte`).
    #[serde(
        rename = "certificate-authority-data",
        skip_serializing_if = "Vec::is_empty",
        default,
        with = "b64"
    )]
    pub certificate_authority_data: Vec<u8>,
    #[serde(
        rename = "proxy-url",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub proxy_url: String,
    #[serde(
        rename = "disable-compression",
        skip_serializing_if = "std::ops::Not::not",
        default
    )]
    pub disable_compression: bool,
}

mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

/// `ExecCredentialStatus`: what the plugin returned.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExecCredentialStatus {
    pub token: String,
    pub client_certificate_data: String,
    pub client_key_data: String,
    /// `a.exp`: when the credentials expire (`None` is the zero time).
    pub expiration: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireStatus {
    #[serde(default)]
    expiration_timestamp: Option<String>,
    #[serde(default)]
    token: String,
    #[serde(default)]
    client_certificate_data: String,
    #[serde(default)]
    client_key_data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireCredential {
    #[serde(default)]
    api_version: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    status: Option<WireStatus>,
}

/// `sometimes` (exec.go:100): runs a function at most `threshold` times per
/// `interval` window.
struct Sometimes {
    threshold: usize,
    interval: Duration,
    state: Mutex<(usize, Option<Instant>)>,
}

impl Sometimes {
    fn do_once(&self, f: impl FnOnce()) {
        let mut st = self.state.lock().unwrap();
        let now = Instant::now();
        let window = *st.1.get_or_insert(now);
        if now.duration_since(window) >= self.interval {
            *st = (0, Some(now));
        }
        if st.0 < self.threshold {
            st.0 += 1;
            f();
        }
    }
}

/// `filepath.Clean` for the command (lexical: `.`, `..`, repeated `/`).
fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut parts: Vec<String> = Vec::new();
    for c in Path::new(p).components() {
        match c {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::ParentDir => {
                if parts.last().is_some_and(|l| l != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..".into());
                }
            }
            _ => {}
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// `exec.LookPath`: a name with a separator is checked as is, otherwise each
/// `PATH` entry is searched for an executable file.
pub fn look_path(file: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let executable = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    let not_found = || {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("exec: {file:?}: executable file not found in $PATH"),
        )
    };
    if file.contains('/') {
        return if executable(Path::new(file)) {
            Ok(PathBuf::from(file))
        } else {
            Err(not_found())
        };
    }
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let p = Path::new(dir).join(file);
        if executable(&p) {
            return Ok(p);
        }
    }
    Err(not_found())
}

/// `ValidatePluginPolicy` (exec.go:660).
pub fn validate_plugin_policy(policy: &PluginPolicy) -> Result<(), String> {
    match policy.policy_type.as_str() {
        "" | "AllowAll" | "DenyAll" => {
            if policy.allowlist.is_some() {
                return Err(format!(
                    "misconfigured credential plugin allowlist: plugin policy is {:?} but allowlist is non-nil",
                    policy.policy_type
                ));
            }
            Ok(())
        }
        "Allowlist" => validate_allowlist(policy.allowlist.as_deref()),
        other => Err(format!("unknown plugin policy: {other:?}")),
    }
}

/// `validateAllowlist` (exec.go:677).
fn validate_allowlist(list: Option<&[AllowlistEntry]>) -> Result<(), String> {
    let Some(list) = list else {
        return Err(
            "credential plugin policy set to \"Allowlist\", but allowlist is unspecified".into(),
        );
    };
    if list.is_empty() {
        return Err("credential plugin policy set to \"Allowlist\", but allowlist is empty; use \"DenyAll\" policy instead".into());
    }
    for (i, item) in list.iter().enumerate() {
        if *item == AllowlistEntry::default() {
            return Err(format!(
                "misconfigured credential plugin allowlist: empty allowlist entry #{}",
                i + 1
            ));
        }
        let cleaned = clean_path(&item.name);
        if cleaned != item.name {
            return Err(format!(
                "non-normalized file path: {:?} vs {:?}",
                item.name, cleaned
            ));
        }
    }
    Ok(())
}

/// The exec plugin authenticator (`Authenticator`, exec.go:262) without the
/// credential cache.
pub struct Authenticator {
    cmd: String,
    args: Vec<String>,
    group_version: &'static str,
    env: Vec<String>,
    cluster: Option<Cluster>,
    provide_cluster_info: bool,
    allowlist_lookup: Mutex<HashSet<String>>,
    plugin_policy: PluginPolicy,
    install_hint: String,
    sometimes: Sometimes,
    interactive_mode: String,
    stdin_unavailable: bool,
    stdin_unavailable_message: String,
    is_terminal: Box<dyn Fn() -> bool + Send + Sync>,
}

impl Authenticator {
    /// `newAuthenticator` (exec.go:165) with the real terminal check.
    pub fn new(config: &ExecConfig, cluster: Option<Cluster>) -> Result<Self, String> {
        Self::with_terminal(config, cluster, Box::new(|| std::io::stdin().is_terminal()))
    }

    /// `newAuthenticator` with an injectable `isTerminalFunc`.
    pub fn with_terminal(
        config: &ExecConfig,
        cluster: Option<Cluster>,
        is_terminal: Box<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Self, String> {
        let group_version = match config.api_version.as_str() {
            V1 => V1,
            V1BETA1 => V1BETA1,
            other => return Err(format!("exec plugin: invalid apiVersion {other:?}")),
        };
        validate_plugin_policy(&config.plugin_policy)
            .map_err(|e| format!("invalid plugin policy: {e}"))?;
        let allowlist_lookup = config
            .plugin_policy
            .allowlist
            .iter()
            .flatten()
            .filter(|e| !e.name.is_empty())
            .map(|e| e.name.clone())
            .collect();
        Ok(Self {
            cmd: clean_path(&config.command),
            args: config.args.clone(),
            group_version,
            env: config
                .env
                .iter()
                .map(|e| format!("{}={}", e.name, e.value))
                .collect(),
            cluster,
            provide_cluster_info: config.provide_cluster_info,
            allowlist_lookup: Mutex::new(allowlist_lookup),
            plugin_policy: config.plugin_policy.clone(),
            install_hint: config.install_hint.clone(),
            sometimes: Sometimes {
                threshold: 10,
                interval: Duration::from_secs(3600),
                state: Mutex::new((0, None)),
            },
            interactive_mode: config.interactive_mode.clone(),
            stdin_unavailable: config.stdin_unavailable,
            stdin_unavailable_message: config.stdin_unavailable_message.clone(),
            is_terminal,
        })
    }

    /// `isInteractive` (exec.go:236).
    fn interactive(&self) -> Result<bool, String> {
        match self.interactive_mode.as_str() {
            "Never" => Ok(false),
            "IfAvailable" => Ok(!self.stdin_unavailable && (self.is_terminal)()),
            "Always" => {
                if !(self.is_terminal)() {
                    return Err("standard input is not a terminal".into());
                }
                if self.stdin_unavailable {
                    let suffix = if self.stdin_unavailable_message.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", self.stdin_unavailable_message)
                    };
                    return Err(format!("standard input is unavailable{suffix}"));
                }
                Ok(true)
            }
            other => Err(format!("unknown interactiveMode: {other:?}")),
        }
    }

    /// `updateCommandAndCheckAllowlistLocked` (exec.go:580). Returns the
    /// (possibly resolved) command path.
    fn check_policy(&self) -> Result<String, String> {
        match self.plugin_policy.policy_type.as_str() {
            "" | "AllowAll" => Ok(self.cmd.clone()),
            "DenyAll" => Err(format!(
                "plugin {:?} not allowed: policy set to \"DenyAll\"",
                self.cmd
            )),
            "Allowlist" => self.check_allowlist(),
            other => Err(format!("unknown plugin policy {other:?}")),
        }
    }

    /// `checkAllowlistLocked` (exec.go:595). `exec.Command` resolves a bare
    /// name through `LookPath`; a name with a separator is used as is.
    fn check_allowlist(&self) -> Result<String, String> {
        let (mut path, resolve_err) = if self.cmd.contains('/') {
            (self.cmd.clone(), None)
        } else {
            match look_path(&self.cmd) {
                Ok(p) => (p.to_string_lossy().into_owned(), None),
                Err(e) => (self.cmd.clone(), Some(e)),
            }
        };
        {
            let l = self.allowlist_lookup.lock().unwrap();
            if l.contains(&self.cmd) || l.contains(&path) {
                return Ok(path);
            }
        }
        let resolved = if path != self.cmd {
            match resolve_err {
                Some(e) => Err(e),
                None => Ok(PathBuf::from(&path)),
            }
        } else {
            look_path(&path)
        };
        let resolved = match resolved {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                return Err(format!(
                    "plugin path {path:?} cannot be resolved for credential plugin allowlist check: {e}"
                ))
            }
        };
        path.clone_from(&resolved);
        if self.allowlist_lookup.lock().unwrap().contains(&resolved) {
            return Ok(path);
        }
        self.resolve_allow_list_entries(&path);
        if self.allowlist_lookup.lock().unwrap().contains(&resolved) {
            return Ok(path);
        }
        Err(format!(
            "plugin path {path:?} is not permitted by the credential plugin allowlist"
        ))
    }

    /// `resolveAllowListEntriesLocked` (exec.go:640): add the `LookPath`
    /// resolution of every allowlist entry that shares the command's basename.
    fn resolve_allow_list_entries(&self, command_hint: &str) {
        let base = |s: &str| {
            Path::new(s)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        let hint = base(command_hint);
        for entry in self.plugin_policy.allowlist.iter().flatten() {
            if !hint.is_empty() && hint != base(&entry.name) {
                continue;
            }
            if let Ok(p) = look_path(&entry.name) {
                self.allowlist_lookup
                    .lock()
                    .unwrap()
                    .insert(p.to_string_lossy().into_owned());
            }
        }
    }

    /// `wrapCmdRunErrorLocked` (exec.go:548).
    fn wrap_run_error(
        &self,
        err: &std::io::Error,
        status: Option<std::process::ExitStatus>,
    ) -> String {
        if let Some(st) = status {
            return format!(
                "exec: executable {} failed with exit code {}",
                self.cmd,
                st.code().unwrap_or(-1)
            );
        }
        if err.kind() == std::io::ErrorKind::NotFound {
            let mut b = format!("exec: executable {} not found", self.cmd);
            self.sometimes.do_once(|| {
                b.push_str(INSTALL_HINT_VERBOSE_HELP);
                if !self.install_hint.is_empty() {
                    b.push_str("\n\n");
                    b.push_str(&self.install_hint);
                }
            });
            return b;
        }
        format!("exec: {err}")
    }

    /// `refreshCredsLocked` (exec.go:434): run the plugin and return the
    /// validated status. Blocking (it waits for the child); async callers
    /// use `spawn_blocking`.
    pub fn refresh_creds(&self) -> Result<ExecCredentialStatus, String> {
        let interactive = self
            .interactive()
            .map_err(|e| format!("exec plugin cannot support interactive mode: {e}"))?;

        let mut spec = serde_json::json!({ "interactive": interactive });
        if self.provide_cluster_info {
            if let Some(c) = &self.cluster {
                spec["cluster"] =
                    serde_json::to_value(c).map_err(|e| format!("encode ExecCredentials: {e}"))?;
            }
        }
        let info = serde_json::json!({
            "kind": "ExecCredential",
            "apiVersion": self.group_version,
            "spec": spec,
        });
        let data =
            serde_json::to_string(&info).map_err(|e| format!("encode ExecCredentials: {e}"))?;

        let program = self.check_policy()?;
        let mut cmd = Command::new(&program);
        cmd.args(&self.args);
        for e in &self.env {
            if let Some((k, v)) = e.split_once('=') {
                cmd.env(k, v);
            }
        }
        cmd.env(EXEC_INFO_ENV, data);
        cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
        cmd.stdin(if interactive {
            Stdio::inherit()
        } else {
            Stdio::null()
        });

        let out = cmd.output().map_err(|e| self.wrap_run_error(&e, None))?;
        if !out.status.success() {
            return Err(self.wrap_run_error(&std::io::Error::other("exit"), Some(out.status)));
        }

        let cred: WireCredential =
            serde_json::from_slice(&out.stdout).map_err(|e| format!("decoding stdout: {e}"))?;
        if cred.kind != "ExecCredential" {
            return Err(format!(
                "decoding stdout: no kind {:?} is registered for version {:?}",
                cred.kind, cred.api_version
            ));
        }
        if cred.api_version != V1 && cred.api_version != V1BETA1 {
            return Err(format!(
                "decoding stdout: no kind \"ExecCredential\" is registered for version {:?}",
                cred.api_version
            ));
        }
        if cred.api_version != self.group_version {
            return Err(format!(
                "exec plugin is configured to use API version {}, plugin returned version {}",
                self.group_version, cred.api_version
            ));
        }
        let status = cred
            .status
            .ok_or("exec plugin didn't return a status field")?;
        if status.token.is_empty()
            && status.client_certificate_data.is_empty()
            && status.client_key_data.is_empty()
        {
            return Err("exec plugin didn't return a token or cert/key pair".into());
        }
        if status.client_certificate_data.is_empty() != status.client_key_data.is_empty() {
            return Err("exec plugin returned only certificate or key, not both".into());
        }
        let expiration = match status.expiration_timestamp.as_deref() {
            None | Some("") => None,
            Some(ts) => Some(
                DateTime::parse_from_rfc3339(ts)
                    .map_err(|e| format!("decoding stdout: parsing time {ts:?}: {e}"))?
                    .with_timezone(&Utc),
            ),
        };
        Ok(ExecCredentialStatus {
            token: status.token,
            client_certificate_data: status.client_certificate_data,
            client_key_data: status.client_key_data,
            expiration,
        })
    }
}
