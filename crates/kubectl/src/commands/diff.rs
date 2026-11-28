use crate::discovery::RestMapper;
use crate::ops::build_path;
use anyhow::{Context, Result};
use kubernetes_rs_client::http::{ApiClient, GetError};
use serde_json::Value;

/// Options of `kubectl diff` (`DiffOptions`, diff.go:117).
#[derive(Debug, Clone, Default)]
pub struct DiffOptions {
    /// `-f` files or directories (`-` is stdin).
    pub files: Vec<String>,
    /// `-R`.
    pub recursive: bool,
    /// `--server-side`.
    pub server_side: bool,
    /// `--field-manager`.
    pub field_manager: String,
    /// `--force-conflicts`.
    pub force_conflicts: bool,
    /// `--show-managed-fields`.
    pub show_managed_fields: bool,
}

/// `apply.GetApplyFieldManagerFlag` (apply/apply.go:1109): the flag when set,
/// else `kubectl` for server-side apply and `kubectl-client-side-apply`.
pub fn apply_field_manager(flag: Option<&str>, server_side: bool) -> String {
    match flag {
        Some(f) => f.to_string(),
        None if server_side => "kubectl".to_string(),
        None => "kubectl-client-side-apply".to_string(),
    }
}

/// `DiffOptions.Complete`'s flag checks (diff.go:631-651).
pub fn validate_options(o: &DiffOptions) -> Result<()> {
    if o.files.is_empty() {
        anyhow::bail!("must specify one of -f and -k");
    }
    if o.force_conflicts && !o.server_side {
        anyhow::bail!("--force-conflicts only works with --server-side");
    }
    Ok(())
}

/// `Differ` (diff.go:545): the LIVE and MERGED temp directories, diffed by
/// one run of the diff program after every object was printed into them.
pub struct Differ {
    from: tempfile::TempDir,
    to: tempfile::TempDir,
}

impl Differ {
    /// `NewDiffer("LIVE", "MERGED")`; the directories are removed on drop
    /// (`TearDown`).
    pub fn new(from: &str, to: &str) -> Result<Self> {
        let mk = |p: &str| tempfile::Builder::new().prefix(&format!("{p}-")).tempdir();
        Ok(Self {
            from: mk(from)?,
            to: mk(to)?,
        })
    }

    /// `Differ.Diff` (diff.go:566): print both versions of one object into
    /// the directories, omitting managed fields and masking v1 Secret data.
    /// `None` is an object that does not exist on that side.
    pub fn diff(
        &self,
        name: &str,
        live: Option<Value>,
        merged: Option<Value>,
        show_managed_fields: bool,
    ) -> Result<()> {
        let (mut from, mut to) = (live, merged);
        if !show_managed_fields {
            from.iter_mut().for_each(omit_managed_fields);
            to.iter_mut().for_each(omit_managed_fields);
        }
        if to.as_ref().is_some_and(is_v1_secret) {
            let m = Masker::new(from, to)?;
            from = m.from().cloned();
            to = m.to().cloned();
        }
        print_object(self.from.path(), name, from.as_ref())?;
        print_object(self.to.path(), name, to.as_ref())?;
        Ok(())
    }

    /// `Differ.Run` (diff.go:603).
    pub fn run(&self, program: &mut DiffProgram) -> Result<()> {
        program.run(
            &self.from.path().to_string_lossy(),
            &self.to.path().to_string_lossy(),
        )
    }
}

/// `DiffVersion.Print` + `Printer.Print` (diff.go:236, 160): the object as
/// YAML into a new file; a missing object leaves an empty file.
fn print_object(dir: &std::path::Path, name: &str, obj: Option<&Value>) -> Result<()> {
    let data = match obj {
        Some(o) => serde_yaml::to_string(o)?,
        None => String::new(),
    };
    std::fs::write(dir.join(name), data)?;
    Ok(())
}

/// `InfoObject.Name` (diff.go:376): `[group.]version.Kind.namespace.name`.
pub fn object_name(group: &str, version: &str, kind: &str, namespace: &str, name: &str) -> String {
    let group = if group.is_empty() {
        String::new()
    } else {
        format!("{group}.")
    };
    format!("{group}{version}.{kind}.{namespace}.{name}")
}

/// `kubectl diff`: diff the live version of every object of the `-f` files
/// against the version that apply would produce (`DiffOptions.Run`,
/// diff.go:700). Returns the diff program's result: `Err` holding a
/// [`DiffExitError`] with status 1 means differences were found.
pub async fn execute(
    client: &ApiClient,
    opts: &DiffOptions,
    default_namespace: &str,
    program: &mut DiffProgram,
) -> Result<()> {
    validate_options(opts)?;
    let differ = Differ::new("LIVE", "MERGED")?;
    let files = crate::commands::apply::collect_files(&opts.files, opts.recursive)?;
    let mapper = RestMapper::from_server(client).await?;
    for file in &files {
        for value in crate::manifest::read_documents(file)? {
            diff_object(client, &mapper, &differ, &value, default_namespace, opts).await?;
        }
    }
    differ.run(program)
}

async fn diff_object(
    client: &ApiClient,
    mapper: &RestMapper,
    differ: &Differ,
    value: &serde_yaml::Value,
    default_namespace: &str,
    opts: &DiffOptions,
) -> Result<()> {
    let local: Value = serde_json::to_value(value)?;
    let kind = local
        .get("kind")
        .and_then(|k| k.as_str())
        .context("Missing 'kind' field")?
        .to_string();
    let name = crate::ops::value_name(&local).context("Missing 'name' in metadata")?;
    let mapping = mapper.resolve(&kind).ok_or_else(|| {
        anyhow::anyhow!("error: the server doesn't have a resource type \"{kind}\"")
    })?;
    let ns: Option<String> = mapping.namespaced.then(|| {
        crate::ops::value_namespace(&local).unwrap_or_else(|| default_namespace.to_string())
    });
    let item = build_path(mapping, ns.as_deref(), Some(&name));

    // `info.Get()`: NotFound means the object does not exist yet.
    let live = match client.get::<Value>(&item).await {
        Ok(v) => Some(v),
        Err(GetError::NotFound(_)) => None,
        Err(GetError::Other(e)) => return Err(e),
    };
    let merged = merged_object(
        client,
        mapping,
        &item,
        ns.as_deref(),
        &local,
        live.is_some(),
        opts,
    )
    .await?;
    let file = object_name(
        &mapping.group,
        &mapping.version,
        &mapping.kind,
        ns.as_deref().unwrap_or(""),
        &name,
    );
    differ.diff(&file, live, Some(merged), opts.show_managed_fields)
}

/// `InfoObject.Merged` (diff.go:346): the object as it would look if applied
/// or created, from a dry-run request. Server-side apply patches with the
/// apply patch type, forcing conflicts when asked; otherwise a missing object
/// is dry-run created and an existing one dry-run replaced, as `kubectl apply`
/// of this crate does (`ops::apply_value`), including the last-applied
/// annotation.
async fn merged_object(
    client: &ApiClient,
    mapping: &crate::discovery::ResourceMapping,
    item: &str,
    ns: Option<&str>,
    local: &Value,
    exists: bool,
    opts: &DiffOptions,
) -> Result<Value> {
    if opts.server_side {
        let q = format!(
            "?dryRun=All&fieldManager={}&force={}",
            opts.field_manager, opts.force_conflicts
        );
        return client
            .patch(&format!("{item}{q}"), local, "application/apply-patch+yaml")
            .await;
    }
    let mut body = local.clone();
    crate::commands::apply::set_last_applied_annotation(&mut body);
    let query = "?dryRun=All";
    if exists {
        client.put(&format!("{item}{query}"), &body).await
    } else {
        client
            .post(&format!("{}{query}", build_path(mapping, ns, None)), &body)
            .await
    }
}

/// Remove server-managed fields that the user's manifest never sets, so `diff`
/// shows only meaningful changes (approximation of kubectl's server-side-apply
/// dry-run diff).
pub fn strip_server_managed(v: &mut serde_json::Value) {
    if let Some(meta) = v.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        for k in [
            "uid",
            "resourceVersion",
            "generation",
            "creationTimestamp",
            "managedFields",
            "selfLink",
            "ownerReferences",
        ] {
            meta.remove(k);
        }
        if let Some(ann) = meta.get_mut("annotations").and_then(|a| a.as_object_mut()) {
            ann.remove("kubectl.kubernetes.io/last-applied-configuration");
            // drop now-empty annotations to avoid an empty-map diff
            let empty = ann.is_empty();
            if empty {
                meta.remove("annotations");
            }
        }
    }
    if let Some(obj) = v.as_object_mut() {
        obj.remove("status");
    }
}

// ---------------------------------------------------------------------------
// Ports of staging/src/k8s.io/kubectl/pkg/cmd/diff/diff.go: constants,
// `diffError`, `DiffProgram`, `omitManagedFields` and `Masker`.
// ---------------------------------------------------------------------------

use std::io::Write;

/// `sensitiveMaskDefault` (diff.go:92).
pub const SENSITIVE_MASK_DEFAULT: &str = "***";
/// `sensitiveMaskBefore` (diff.go:93).
pub const SENSITIVE_MASK_BEFORE: &str = "*** (before)";
/// `sensitiveMaskAfter` (diff.go:94).
pub const SENSITIVE_MASK_AFTER: &str = "*** (after)";

/// The `exec.ExitError` of a diff program that exited with a status of at most
/// 1 (`diffError`, diff.go:98): 0 and 1 mean "no differences" / "differences
/// found", not failure. A process killed by a signal has `ExitStatus() == -1`
/// in k8s.io/utils/exec and so counts too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffExitError {
    pub status: i32,
}

impl std::fmt::Display for DiffExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exit status {}", self.status)
    }
}

impl std::error::Error for DiffExitError {}

/// `diffError` (diff.go:98): the exit error if `err` is one with a status of
/// less than 2, `None` otherwise.
pub fn diff_error(err: &anyhow::Error) -> Option<&DiffExitError> {
    err.downcast_ref::<DiffExitError>()
        .filter(|e| e.status <= 1)
}

/// `DiffProgram` (diff.go:178): finds and runs the diff program. The value of
/// `KUBECTL_EXTERNAL_DIFF` is used as the program; by default `diff(1)`.
pub struct DiffProgram {
    pub out: Box<dyn Write + Send>,
    pub err_out: Box<dyn Write + Send>,
}

impl DiffProgram {
    /// `getCommand` (diff.go:183): the program name and its arguments for
    /// `from` and `to`. Extra words of `KUBECTL_EXTERNAL_DIFF` are appended
    /// after the paths, and only those made of `[a-zA-Z0-9-=]`.
    pub fn get_command(&self, from: &str, to: &str) -> (String, Vec<String>) {
        let mut args = vec![from.to_string(), to.to_string()];
        match std::env::var("KUBECTL_EXTERNAL_DIFF") {
            Ok(env_diff) if !env_diff.is_empty() => {
                let words: Vec<&str> = env_diff.split(' ').collect();
                let valid = |w: &str| {
                    !w.is_empty()
                        && w.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '=')
                };
                for w in &words[1..] {
                    if valid(w) {
                        args.push((*w).to_string());
                    }
                }
                (words[0].to_string(), args)
            }
            _ => {
                let mut full = vec!["-u".to_string(), "-N".to_string()];
                full.extend(args);
                ("diff".to_string(), full)
            }
        }
    }

    /// `Run` (diff.go:213): run the detected diff program on the `from` and
    /// `to` directories. An exit status of 0 is `Ok`; 1 is a [`DiffExitError`]
    /// (unwrapped, so callers can tell it apart); anything else is
    /// `failed to run "<diff>": <err>`.
    pub fn run(&mut self, from: &str, to: &str) -> Result<()> {
        let (diff, args) = self.get_command(from, to);
        let output = std::process::Command::new(&diff)
            .args(&args)
            .output()
            .map_err(|e| anyhow::anyhow!("failed to run {diff:?}: {e}"))?;
        self.out.write_all(&output.stdout)?;
        self.err_out.write_all(&output.stderr)?;
        if output.status.success() {
            return Ok(());
        }
        let status = output.status.code().unwrap_or(-1);
        let exit = DiffExitError { status };
        if status <= 1 {
            return Err(exit.into());
        }
        Err(anyhow::anyhow!("failed to run {diff:?}: {exit}"))
    }
}

/// `omitManagedFields` (diff.go:609): clear `metadata.managedFields`.
pub fn omit_managed_fields(obj: &mut Value) {
    if let Some(meta) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        meta.remove("managedFields");
    }
}

/// `Masker` (diff.go:438): masks sensitive values (the `data` of a v1 Secret)
/// with a fixed-length mask while keeping changes diff-able: a key whose value
/// differs on both sides gets a `(before)` / `(after)` suffix.
pub struct Masker {
    from: Option<Value>,
    to: Option<Value>,
}

impl Masker {
    /// `NewMasker` (diff.go:449). `None` is an object that does not exist
    /// (not yet created, or removed).
    pub fn new(from: Option<Value>, to: Option<Value>) -> Result<Self> {
        let mut m = Masker { from, to };
        m.run().context("run masker")?;
        Ok(m)
    }

    /// `dataFromUnstructured` (diff.go:472): the nested map at `data`;
    /// `None` when absent. A `data` that is not a map is an error
    /// (`unstructured.NestedMap`).
    fn data_from(u: &Option<Value>) -> Result<Option<serde_json::Map<String, Value>>> {
        let Some(u) = u else { return Ok(None) };
        match u.get("data") {
            None => Ok(None),
            Some(Value::Object(m)) => Ok(Some(m.clone())),
            Some(other) => Err(anyhow::anyhow!(
                "extract 'data' field: get nested map: .data accessor error: {other} is of the type {}, expected map[string]interface{{}}",
                match other {
                    Value::Null => "<nil>",
                    Value::Bool(_) => "bool",
                    Value::Number(_) => "number",
                    Value::String(_) => "string",
                    Value::Array(_) => "[]interface {}",
                    Value::Object(_) => "map[string]interface {}",
                }
            )),
        }
    }

    /// `run` (diff.go:487): compare and patch sensitive values.
    fn run(&mut self) -> Result<()> {
        let mut from = Self::data_from(&self.from)?;
        let mut to = Self::data_from(&self.to)?;
        let mask = |s: &str| Value::String(s.to_string());

        if let Some(f) = from.as_mut() {
            let keys: Vec<String> = f.keys().cloned().collect();
            for k in keys {
                // Add before/after suffix when the key exists on both objects
                // and differs, so that it is visible in diffs.
                if let Some(t) = to.as_mut().and_then(|t| t.get_mut(&k)) {
                    if f[&k] != *t {
                        f.insert(k.clone(), mask(SENSITIVE_MASK_BEFORE));
                        *t = mask(SENSITIVE_MASK_AFTER);
                        continue;
                    }
                    *t = mask(SENSITIVE_MASK_DEFAULT);
                }
                f.insert(k, mask(SENSITIVE_MASK_DEFAULT));
            }
        }
        if let Some(t) = to.as_mut() {
            // Mask the remaining keys that were not in 'from'.
            for (k, v) in t.iter_mut() {
                if !from.as_ref().is_some_and(|f| f.contains_key(k)) {
                    *v = mask(SENSITIVE_MASK_DEFAULT);
                }
            }
        }

        // Patch the objects with the masked data.
        if let (Some(obj), Some(data)) = (self.from.as_mut(), from) {
            obj["data"] = Value::Object(data);
        }
        if let (Some(obj), Some(data)) = (self.to.as_mut(), to) {
            obj["data"] = Value::Object(data);
        }
        Ok(())
    }

    /// `From` (diff.go:534): the masked `from` object.
    pub fn from(&self) -> Option<&Value> {
        self.from.as_ref()
    }

    /// `To` (diff.go:539): the masked `to` object.
    pub fn to(&self) -> Option<&Value> {
        self.to.as_ref()
    }
}

/// The Secret check of `Differ.Diff` (diff.go:571): only `v1` `Secret`s are masked.
pub fn is_v1_secret(obj: &Value) -> bool {
    obj.get("apiVersion").and_then(|v| v.as_str()) == Some("v1")
        && obj.get("kind").and_then(|v| v.as_str()) == Some("Secret")
}
