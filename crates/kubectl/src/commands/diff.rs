use crate::discovery::RestMapper;
use crate::ops::build_path;
use anyhow::{Context, Result};
use kubernetes_rs_client::http::{ApiClient, GetError};
use serde_json::Value;

/// Show diff between current and applied configuration
pub async fn execute(client: &ApiClient, file: &str, namespace: &str) -> Result<()> {
    // Read + split the source into its YAML documents. Empty documents (e.g. a
    // trailing `---`) are skipped by the shared helper.
    let documents = crate::manifest::read_documents(file)?;

    // Build the REST mapper once for all documents in this file.
    let mapper = RestMapper::from_server(client).await?;

    for value in &documents {
        diff_resource(client, &mapper, value, namespace).await?;
    }

    Ok(())
}

async fn diff_resource(
    client: &ApiClient,
    mapper: &RestMapper,
    value: &serde_yaml::Value,
    default_namespace: &str,
) -> Result<()> {
    let kind = value
        .get("kind")
        .and_then(|k| k.as_str())
        .context("Missing 'kind' field")?;

    let metadata = value.get("metadata").context("Missing 'metadata' field")?;
    let name = metadata
        .get("name")
        .and_then(|n| n.as_str())
        .context("Missing 'name' in metadata")?;

    // Resolve the kind via the server-side REST mapper.
    let mapping = mapper.resolve(kind).ok_or_else(|| {
        anyhow::anyhow!("error: the server doesn't have a resource type \"{kind}\"")
    })?;

    // Determine the effective namespace.
    let ns: Option<String> = if mapping.namespaced {
        let from_body = metadata.get("namespace").and_then(|n| n.as_str());
        Some(from_body.unwrap_or(default_namespace).to_string())
    } else {
        None
    };

    // Build the item path and fetch the live object.
    let api_path = build_path(mapping, ns.as_deref(), Some(name));

    // Fetch the live object. We match on GetError so we can cleanly distinguish
    // a genuine 404 (resource doesn't exist yet → show a creation diff) from
    // any other error (connection failure, permission denied, etc.) which we
    // propagate to the caller.
    // Can't use ops::get_value here — it erases GetError::NotFound(_), which we need
    // for the creation-diff branch.
    let current_yaml = match client.get::<Value>(&api_path).await {
        Ok(mut current) => {
            // Strip server-managed fields the manifest never carries so the diff
            // shows only meaningful changes.
            strip_server_managed(&mut current);
            // Convert to YAML for diffing
            serde_yaml::to_string(&current)?
        }
        Err(GetError::NotFound(_)) => {
            println!("--- /dev/null");
            println!("+++ {}/{} (create)", kind, name);
            // Round-trip through serde_json::Value so keys sort the same way the
            // live side does (see the changed-resource branch below).
            let mut new_json: serde_json::Value = serde_yaml::from_value(value.clone())?;
            strip_server_managed(&mut new_json);
            let new_yaml = serde_yaml::to_string(&new_json)?;
            for line in new_yaml.lines() {
                println!("+{}", line);
            }
            println!();
            return Ok(());
        }
        Err(GetError::Other(e)) => {
            return Err(e);
        }
    };

    // Prepare new resource YAML. Round-trip the desired object through
    // serde_json::Value so its keys sort identically to the live side (which is
    // a serde_json::Value → sorted via BTreeMap). Without this, manifests whose
    // keys aren't already alphabetical would show spurious diffs every run.
    let mut new_json: serde_json::Value = serde_yaml::from_value(value.clone())?;
    // Strip the same server-managed fields from the desired side so a field that
    // exists only on the live side never renders as a deletion.
    strip_server_managed(&mut new_json);
    let new_yaml = serde_yaml::to_string(&new_json)?;

    // Calculate and display diff
    if current_yaml.trim() == new_yaml.trim() {
        println!("No changes for {}/{}", kind, name);
        println!();
        return Ok(());
    }

    println!("--- {}/{} (current)", kind, name);
    println!("+++ {}/{} (new)", kind, name);

    // Simple line-by-line diff
    let current_lines: Vec<&str> = current_yaml.lines().collect();
    let new_lines: Vec<&str> = new_yaml.lines().collect();

    let max_len = current_lines.len().max(new_lines.len());
    for i in 0..max_len {
        let current_line = current_lines.get(i).copied();
        let new_line = new_lines.get(i).copied();

        match (current_line, new_line) {
            (Some(c), Some(n)) if c == n => println!(" {}", c),
            (Some(c), Some(n)) => {
                println!("-{}", c);
                println!("+{}", n);
            }
            (Some(c), None) => println!("-{}", c),
            (None, Some(n)) => println!("+{}", n),
            (None, None) => unreachable!(),
        }
    }
    println!();

    Ok(())
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
