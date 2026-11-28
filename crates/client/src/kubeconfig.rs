use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct KubeConfig {
    pub api_version: Option<String>,
    pub kind: Option<String>,
    #[serde(default)]
    pub current_context: String,
    #[serde(default)]
    pub contexts: Vec<ContextEntry>,
    #[serde(default)]
    pub clusters: Vec<ClusterEntry>,
    #[serde(default)]
    pub users: Vec<UserEntry>,
    #[serde(default)]
    pub preferences: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContextEntry {
    pub name: String,
    pub context: Context,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Context {
    #[serde(default)]
    pub cluster: String,
    #[serde(default)]
    pub user: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

fn default_namespace() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterEntry {
    pub name: String,
    pub cluster: Cluster,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Cluster {
    #[serde(default)]
    pub server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_authority_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure_skip_tls_verify: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserEntry {
    pub name: String,
    pub user: User,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct User {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_certificate_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// `tokenFile` in the v1 kubeconfig schema (camelCase, unlike its siblings).
    #[serde(default, rename = "tokenFile", skip_serializing_if = "Option::is_none")]
    pub token_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_provider: Option<AuthProvider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthProvider {
    pub name: String,
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecConfig {
    pub api_version: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<EnvVar>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

impl KubeConfig {
    /// Load kubeconfig the way kubectl does: `KUBECONFIG` as a path list (or
    /// `~/.kube/config`), merged with the first file winning, relative paths
    /// resolved against each file's directory
    /// (`NewDefaultClientConfigLoadingRules().Load()`).
    pub fn load_default() -> Result<Self> {
        LoadingRules::new_default()?.load()
    }

    /// The file `kubectl config` writes to: `ConfigAccess.GetDefaultFilename`
    /// (loader.go:353) — the first existing file of the loading precedence,
    /// else the first entry of it.
    pub fn default_path() -> Result<PathBuf> {
        Ok(PathBuf::from(
            LoadingRules::new_default()?.default_filename(),
        ))
    }

    /// Load kubeconfig from a specific file (`clientcmd.LoadFromFile`,
    /// loader.go:396): no merging and no path resolution.
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read kubeconfig from {:?}: {}", path, e))?;
        Self::parse(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse kubeconfig from {:?}: {}", path, e))
    }

    /// `clientcmd.Load`: decode, then reject duplicate names the way the
    /// list-to-map conversion does.
    pub fn parse(contents: &str) -> Result<Self, String> {
        if contents.trim().is_empty() {
            return Ok(Self::empty());
        }
        let config: KubeConfig = serde_yaml::from_str(contents).map_err(|e| e.to_string())?;
        fn dup<'a>(
            names: impl Iterator<Item = &'a String>,
            list: &str,
            map: &str,
        ) -> Result<(), String> {
            let mut seen = std::collections::HashSet::new();
            for n in names {
                if !seen.insert(n) {
                    return Err(format!(
                        "error converting *[]{list} into *map[string]{map}: duplicate name \"{n}\" in list"
                    ));
                }
            }
            Ok(())
        }
        dup(
            config.clusters.iter().map(|c| &c.name),
            "NamedCluster",
            "*api.Cluster",
        )?;
        dup(
            config.users.iter().map(|c| &c.name),
            "NamedAuthInfo",
            "*api.AuthInfo",
        )?;
        dup(
            config.contexts.iter().map(|c| &c.name),
            "NamedContext",
            "*api.Context",
        )?;
        Ok(config)
    }

    /// `clientcmdapi.NewConfig()`.
    pub fn empty() -> Self {
        Self {
            api_version: None,
            kind: None,
            current_context: String::new(),
            contexts: vec![],
            clusters: vec![],
            users: vec![],
            preferences: HashMap::new(),
        }
    }

    /// Get the current context
    pub fn get_current_context(&self) -> Result<&Context> {
        self.contexts
            .iter()
            .find(|c| c.name == self.current_context)
            .map(|c| &c.context)
            .ok_or_else(|| anyhow::anyhow!("Current context '{}' not found", self.current_context))
    }

    /// Get the cluster for a given context
    pub fn get_cluster(&self, context: &Context) -> Result<&Cluster> {
        self.clusters
            .iter()
            .find(|c| c.name == context.cluster)
            .map(|c| &c.cluster)
            .ok_or_else(|| anyhow::anyhow!("Cluster '{}' not found", context.cluster))
    }

    /// Get the user for a given context
    pub fn get_user(&self, context: &Context) -> Result<&User> {
        self.users
            .iter()
            .find(|u| u.name == context.user)
            .map(|u| &u.user)
            .ok_or_else(|| anyhow::anyhow!("User '{}' not found", context.user))
    }

    /// Get the server URL for the current context
    pub fn get_server(&self) -> Result<String> {
        let context = self.get_current_context()?;
        let cluster = self.get_cluster(context)?;
        Ok(cluster.server.clone())
    }

    /// Get the namespace for the current context
    pub fn get_namespace(&self) -> Result<String> {
        let context = self.get_current_context()?;
        Ok(context.namespace.clone())
    }

    /// Check if TLS verification should be skipped
    pub fn should_skip_tls_verify(&self) -> Result<bool> {
        let context = self.get_current_context()?;
        let cluster = self.get_cluster(context)?;
        Ok(cluster.insecure_skip_tls_verify.unwrap_or(false))
    }

    /// Get the authentication token if available
    pub fn get_token(&self) -> Result<Option<String>> {
        let context = self.get_current_context()?;
        let user = self.get_user(context)?;
        Ok(user.token.clone())
    }

    /// Get the cluster CA certificate as PEM bytes, if the kubeconfig provides
    /// one. Prefers inline `certificate-authority-data` (base64-encoded PEM);
    /// otherwise reads the `certificate-authority` file path. Returns `None`
    /// when neither is set (e.g. an insecure cluster).
    pub fn get_ca_cert_pem(&self) -> Result<Option<Vec<u8>>> {
        use anyhow::Context as _;
        let context = self.get_current_context()?;
        let cluster = self.get_cluster(context)?;
        if let Some(data) = &cluster.certificate_authority_data {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(data.trim())
                .context("decoding certificate-authority-data")?;
            return Ok(Some(decoded));
        }
        if let Some(path) = &cluster.certificate_authority {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading certificate-authority file {path}"))?;
            return Ok(Some(bytes));
        }
        Ok(None)
    }

    /// Get the client certificate as PEM text, if the kubeconfig user provides
    /// one for mTLS auth. Prefers inline `client-certificate-data` (base64 PEM);
    /// otherwise reads the `client-certificate` file path. Returns `None` when
    /// neither is set (token/anonymous auth). Mirrors upstream client-go
    /// precedence — "CertData takes precedence over CertFile"
    /// (`rest/config.go`), resolved via `dataFromSliceOrFile`
    /// (`transport/transport.go`).
    pub fn get_client_cert_pem(&self) -> Result<Option<String>> {
        let context = self.get_current_context()?;
        let user = self.get_user(context)?;
        Self::resolve_pem(
            user.client_certificate_data.as_deref(),
            user.client_certificate.as_deref(),
            "client-certificate",
        )
    }

    /// Get the client key as PEM text, if the kubeconfig user provides one for
    /// mTLS auth. Prefers inline `client-key-data` (base64 PEM); otherwise reads
    /// the `client-key` file path. Returns `None` when neither is set. Same
    /// upstream precedence as [`Self::get_client_cert_pem`].
    pub fn get_client_key_pem(&self) -> Result<Option<String>> {
        let context = self.get_current_context()?;
        let user = self.get_user(context)?;
        Self::resolve_pem(
            user.client_key_data.as_deref(),
            user.client_key.as_deref(),
            "client-key",
        )
    }

    /// Resolve PEM text from an inline base64 `*-data` field (preferred) or a
    /// file path, matching upstream `dataFromSliceOrFile` precedence: inline
    /// data wins, else the file is read, else `None`.
    fn resolve_pem(
        data_b64: Option<&str>,
        file_path: Option<&str>,
        field: &str,
    ) -> Result<Option<String>> {
        use anyhow::Context as _;
        if let Some(data) = data_b64 {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(data.trim())
                .with_context(|| format!("decoding {field}-data"))?;
            let pem = String::from_utf8(decoded)
                .with_context(|| format!("{field}-data is not valid UTF-8 PEM"))?;
            return Ok(Some(pem));
        }
        if let Some(path) = file_path {
            let pem =
                std::fs::read_to_string(path).with_context(|| format!("reading {field} {path}"))?;
            return Ok(Some(pem));
        }
        Ok(None)
    }
}

/// `clientcmd.RecommendedConfigPathEnvVar`.
pub const RECOMMENDED_CONFIG_PATH_ENV_VAR: &str = "KUBECONFIG";

type Warner = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

/// `clientcmd.ClientConfigLoadingRules` (loader.go:106): where kubeconfig
/// comes from and how the files combine.
#[derive(Clone, Default)]
pub struct LoadingRules {
    /// A file the user asked for; used alone (never merged) and an error if
    /// it is missing.
    pub explicit_path: String,
    /// The files to merge, first one wins on conflicts.
    pub precedence: Vec<String>,
    /// destination -> source: a missing destination is copied from its source
    /// before anything is loaded.
    pub migration_rules: Vec<(String, String)>,
    /// Leave relative `certificate-authority`, `client-certificate`,
    /// `client-key`, `tokenFile` and exec command paths as they are.
    pub do_not_resolve_paths: bool,
    /// Warn when every `KUBECONFIG` file is missing.
    pub warn_if_all_missing: bool,
    /// Warning sink; unset logs at info level (klog `V(1)`).
    pub warner: Option<Warner>,
}

impl LoadingRules {
    /// `NewDefaultClientConfigLoadingRules` (loader.go:121).
    pub fn new_default() -> Result<Self> {
        let mut chain = Vec::new();
        let mut warn_if_all_missing = false;
        match std::env::var(RECOMMENDED_CONFIG_PATH_ENV_VAR) {
            Ok(v) if !v.is_empty() => {
                // filepath.SplitList + deduplicate
                let mut seen = std::collections::HashSet::new();
                for f in v.split(':') {
                    if seen.insert(f.to_string()) {
                        chain.push(f.to_string());
                    }
                }
                warn_if_all_missing = true;
            }
            _ => chain.push(recommended_home_file()?.to_string_lossy().into_owned()),
        }
        Ok(Self {
            precedence: chain,
            migration_rules: current_migration_rules()?,
            warn_if_all_missing,
            ..Default::default()
        })
    }

    /// `GetLoadingPrecedence` (loader.go:328).
    pub fn loading_precedence(&self) -> Vec<String> {
        if !self.explicit_path.is_empty() {
            return vec![self.explicit_path.clone()];
        }
        self.precedence.clone()
    }

    /// `GetDefaultFilename` (loader.go:353).
    pub fn default_filename(&self) -> String {
        if !self.explicit_path.is_empty() {
            return self.explicit_path.clone();
        }
        for f in self.loading_precedence() {
            if std::path::Path::new(&f).exists() {
                return f;
            }
        }
        self.precedence.first().cloned().unwrap_or_default()
    }

    /// `Migrate` (loader.go:277).
    pub fn migrate(&self) -> Result<()> {
        for (destination, source) in &self.migration_rules {
            match fs::metadata(destination) {
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => continue,
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    anyhow::bail!("stat {destination}: {e}")
                }
                Err(_) => {}
            }
            match fs::metadata(source) {
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue
                }
                Err(e) => anyhow::bail!("stat {source}: {e}"),
                Ok(m) if m.is_dir() => anyhow::bail!(
                    "cannot migrate {source} to {destination} because it is a directory"
                ),
                Ok(_) => {}
            }
            let data = fs::read(source)?;
            fs::write(destination, data)?;
        }
        Ok(())
    }

    /// `Load` (loader.go:196): the explicit file alone, else the precedence
    /// files merged; an error if any file failed to load.
    pub fn load(&self) -> Result<KubeConfig> {
        let (config, errs) = self.load_with_errors()?;
        match aggregate_errors(errs) {
            Some(e) => Err(anyhow::anyhow!(e)),
            None => Ok(config),
        }
    }

    /// `Load` with its two results kept apart, as upstream returns the merged
    /// config together with the aggregate of per-file errors. The outer error
    /// is the one upstream returns with a nil config (missing explicit file,
    /// failed migration).
    pub fn load_with_errors(&self) -> Result<(KubeConfig, Vec<String>)> {
        self.migrate()?;
        let mut errs: Vec<String> = Vec::new();
        let mut missing: Vec<String> = Vec::new();

        let files: Vec<String> = if !self.explicit_path.is_empty() {
            if !std::path::Path::new(&self.explicit_path).exists() {
                anyhow::bail!("stat {}: no such file or directory", self.explicit_path);
            }
            vec![self.explicit_path.clone()]
        } else {
            self.precedence.clone()
        };

        let mut configs: Vec<KubeConfig> = Vec::new();
        for filename in &files {
            if filename.is_empty() {
                continue;
            }
            let contents = match fs::read_to_string(filename) {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(filename.clone());
                    continue;
                }
                Err(e) => {
                    errs.push(format!(
                        "error loading config file \"{filename}\": read {filename}: {e}"
                    ));
                    continue;
                }
            };
            match KubeConfig::parse(&contents) {
                Ok(mut c) => {
                    if !self.do_not_resolve_paths {
                        if let Err(e) = resolve_local_paths(&mut c, filename) {
                            errs.push(e);
                        }
                    }
                    configs.push(c);
                }
                Err(e) => errs.push(format!("error loading config file \"{filename}\": {e}")),
            }
        }

        if self.warn_if_all_missing && !missing.is_empty() && configs.is_empty() {
            let msg = format!("Config not found: {}", missing.join(", "));
            match &self.warner {
                Some(w) => w(&msg),
                None => tracing::info!("{msg}"),
            }
        }
        Ok((merge_first_wins(configs), errs))
    }
}

/// `errors.NewAggregate(...).Error()`: one message as is, several as `[a, b]`.
fn aggregate_errors(errs: Vec<String>) -> Option<String> {
    match errs.len() {
        0 => None,
        1 => errs.into_iter().next(),
        _ => Some(format!("[{}]", errs.join(", "))),
    }
}

/// `RecommendedHomeFile` (`~/.kube/config`).
fn recommended_home_file() -> Result<PathBuf> {
    let home =
        std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME environment variable not set"))?;
    Ok(PathBuf::from(home).join(".kube").join("config"))
}

/// `currentMigrationRules` (loader.go:55): `~/.kube/config` is migrated from
/// the pre-1.0 `~/.kube/.kubeconfig`.
fn current_migration_rules() -> Result<Vec<(String, String)>> {
    let home =
        std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME environment variable not set"))?;
    Ok(vec![(
        recommended_home_file()?.to_string_lossy().into_owned(),
        PathBuf::from(home)
            .join(".kube")
            .join(".kubeconfig")
            .to_string_lossy()
            .into_owned(),
    )])
}

/// The merge `Load` ends up with (loader.go:262-297, merge.go): named entries
/// and struct values from the earliest file win, an entry is never combined
/// with a same-named one from a later file, and unset values take the first
/// file that sets them.
pub fn merge_first_wins(configs: Vec<KubeConfig>) -> KubeConfig {
    let mut out = KubeConfig::empty();
    for c in configs {
        if out.api_version.is_none() {
            out.api_version = c.api_version;
        }
        if out.kind.is_none() {
            out.kind = c.kind;
        }
        if out.current_context.is_empty() {
            out.current_context = c.current_context;
        }
        for e in c.clusters {
            if !out.clusters.iter().any(|x| x.name == e.name) {
                out.clusters.push(e);
            }
        }
        for e in c.users {
            if !out.users.iter().any(|x| x.name == e.name) {
                out.users.push(e);
            }
        }
        for e in c.contexts {
            if !out.contexts.iter().any(|x| x.name == e.name) {
                out.contexts.push(e);
            }
        }
        for (k, v) in c.preferences {
            out.preferences.entry(k).or_insert(v);
        }
    }
    out
}

/// `filepath.Clean` for the lexical part (no symlinks, like Go).
fn clean_path(p: &std::path::Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() && !p.is_absolute() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

/// `ResolvePaths` for one reference: relative paths are joined onto `base`.
fn resolve_path(reference: &mut String, base: &std::path::Path) {
    if !reference.is_empty() && !std::path::Path::new(reference.as_str()).is_absolute() {
        *reference = clean_path(&base.join(reference.as_str()))
            .to_string_lossy()
            .into_owned();
    }
}

/// `ResolveLocalPaths` (loader.go:497) for the entries read from `origin`:
/// cluster `certificate-authority`; user `client-certificate`, `client-key`,
/// `tokenFile` and an exec `command` that contains a path separator (a bare
/// command name is looked up on `PATH`, so it is left alone).
pub fn resolve_local_paths(config: &mut KubeConfig, origin: &str) -> Result<(), String> {
    let abs = if std::path::Path::new(origin).is_absolute() {
        PathBuf::from(origin)
    } else {
        std::env::current_dir()
            .map_err(|e| {
                format!("could not determine the absolute path of config file {origin}: {e}")
            })?
            .join(origin)
    };
    let base = clean_path(abs.parent().unwrap_or(std::path::Path::new("/")));
    for c in &mut config.clusters {
        if let Some(ca) = c.cluster.certificate_authority.as_mut() {
            resolve_path(ca, &base);
        }
    }
    for u in &mut config.users {
        let u = &mut u.user;
        for r in [
            &mut u.client_certificate,
            &mut u.client_key,
            &mut u.token_file,
        ] {
            if let Some(r) = r.as_mut() {
                resolve_path(r, &base);
            }
        }
        if let Some(exec) = u.exec.as_mut() {
            if exec.command.contains(std::path::MAIN_SEPARATOR) {
                resolve_path(&mut exec.command, &base);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kubeconfig() {
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: minikube
contexts:
- name: minikube
  context:
    cluster: minikube
    user: minikube
    namespace: default
clusters:
- name: minikube
  cluster:
    server: https://192.168.49.2:8443
    certificate-authority-data: LS0tLS1...
users:
- name: minikube
  user:
    client-certificate-data: LS0tLS1...
    client-key-data: LS0tLS1...
"#;

        let config: KubeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.current_context, "minikube");
        assert_eq!(config.contexts.len(), 1);
        assert_eq!(config.clusters.len(), 1);
        assert_eq!(config.users.len(), 1);
    }

    #[test]
    fn test_should_skip_tls_verify_honored_from_cluster() {
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: c
contexts:
- name: c
  context: { cluster: c, user: u }
clusters:
- name: c
  cluster: { server: https://localhost:6443, insecure-skip-tls-verify: true }
users:
- name: u
  user: { token: anonymous }
"#;
        let config: KubeConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.should_skip_tls_verify().unwrap());
    }

    #[test]
    fn test_should_skip_tls_verify_defaults_false_with_ca() {
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: c
contexts:
- name: c
  context: { cluster: c, user: u }
clusters:
- name: c
  cluster:
    server: https://localhost:6443
    certificate-authority-data: LS0tLS1CRUdJTg==
users:
- name: u
  user: { token: anonymous }
"#;
        let config: KubeConfig = serde_yaml::from_str(yaml).unwrap();
        // No insecure field + a CA present -> not skipped by the kubeconfig.
        assert!(!config.should_skip_tls_verify().unwrap());
    }

    #[test]
    fn test_get_ca_cert_pem_decodes_inline_data() {
        use base64::Engine;
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(pem);
        let yaml = format!(
            r#"
apiVersion: v1
kind: Config
current-context: c
contexts:
- name: c
  context: {{ cluster: c, user: u }}
clusters:
- name: c
  cluster:
    server: https://localhost:6443
    certificate-authority-data: {b64}
users:
- name: u
  user: {{ token: anonymous }}
"#
        );
        let config: KubeConfig = serde_yaml::from_str(&yaml).unwrap();
        let ca = config.get_ca_cert_pem().unwrap();
        assert_eq!(
            ca.as_deref(),
            Some(pem.as_bytes()),
            "inline certificate-authority-data must base64-decode to the CA PEM",
        );
    }

    #[test]
    fn test_get_ca_cert_pem_none_when_absent() {
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: c
contexts:
- name: c
  context: { cluster: c, user: u }
clusters:
- name: c
  cluster: { server: https://localhost:6443, insecure-skip-tls-verify: true }
users:
- name: u
  user: { token: anonymous }
"#;
        let config: KubeConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.get_ca_cert_pem().unwrap().is_none());
    }

    // Mirrors the call-site logic in main.rs: insecure is forced if EITHER the
    // CLI flag is set OR the kubeconfig cluster opts into it.
    fn compute_skip_tls(cli_flag: bool, kubeconfig_insecure: bool) -> bool {
        cli_flag || kubeconfig_insecure
    }

    #[test]
    fn test_insecure_bool_flag_overrides_ca() {
        // CLI flag set, kubeconfig has a CA (insecure=false) -> still insecure.
        assert!(compute_skip_tls(true, false));
        // kubeconfig opts in, no flag -> insecure.
        assert!(compute_skip_tls(false, true));
        // neither -> secure.
        assert!(!compute_skip_tls(false, false));
        // both -> insecure.
        assert!(compute_skip_tls(true, true));
    }

    // mTLS client-identity resolution (#1578). Mirrors upstream client-go
    // precedence: inline `*-data` (base64 PEM) wins over the file path
    // (transport.go `dataFromSliceOrFile`, config.go "CertData takes
    // precedence over CertFile").
    #[test]
    fn test_get_client_cert_key_pem_decodes_inline_data() {
        use base64::Engine;
        let cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n";
        let key_pem = "-----BEGIN PRIVATE KEY-----\nMIIBkey\n-----END PRIVATE KEY-----\n";
        let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert_pem);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_pem);
        let yaml = format!(
            r#"
apiVersion: v1
kind: Config
current-context: c
contexts:
- name: c
  context: {{ cluster: c, user: u }}
clusters:
- name: c
  cluster: {{ server: https://localhost:6443, insecure-skip-tls-verify: true }}
users:
- name: u
  user:
    client-certificate-data: {cert_b64}
    client-key-data: {key_b64}
"#
        );
        let config: KubeConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            config.get_client_cert_pem().unwrap().as_deref(),
            Some(cert_pem),
            "inline client-certificate-data must base64-decode to the cert PEM",
        );
        assert_eq!(
            config.get_client_key_pem().unwrap().as_deref(),
            Some(key_pem),
            "inline client-key-data must base64-decode to the key PEM",
        );
    }

    #[test]
    fn test_get_client_cert_key_pem_reads_file_path() {
        use std::io::Write;
        let cert_pem = "-----BEGIN CERTIFICATE-----\nFILEcert\n-----END CERTIFICATE-----\n";
        let key_pem = "-----BEGIN PRIVATE KEY-----\nFILEkey\n-----END PRIVATE KEY-----\n";
        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file.write_all(key_pem.as_bytes()).unwrap();
        let yaml = format!(
            r#"
apiVersion: v1
kind: Config
current-context: c
contexts:
- name: c
  context: {{ cluster: c, user: u }}
clusters:
- name: c
  cluster: {{ server: https://localhost:6443, insecure-skip-tls-verify: true }}
users:
- name: u
  user:
    client-certificate: {}
    client-key: {}
"#,
            cert_file.path().display(),
            key_file.path().display(),
        );
        let config: KubeConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            config.get_client_cert_pem().unwrap().as_deref(),
            Some(cert_pem),
            "client-certificate file path must be read as the cert PEM",
        );
        assert_eq!(
            config.get_client_key_pem().unwrap().as_deref(),
            Some(key_pem),
            "client-key file path must be read as the key PEM",
        );
    }

    #[test]
    fn test_get_client_cert_key_pem_none_when_absent() {
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: c
contexts:
- name: c
  context: { cluster: c, user: u }
clusters:
- name: c
  cluster: { server: https://localhost:6443, insecure-skip-tls-verify: true }
users:
- name: u
  user: { token: anonymous }
"#;
        let config: KubeConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.get_client_cert_pem().unwrap().is_none());
        assert!(config.get_client_key_pem().unwrap().is_none());
    }
}
