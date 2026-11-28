//! `kubectl edit`.
//!
//! The editor launcher is a port of
//! `staging/src/k8s.io/kubectl/pkg/cmd/util/editor/editor.go` (`Editor`,
//! `NewDefaultEditor`, `defaultEnvEditor`, `defaultEnvShell`, `LaunchTempFile`)
//! and `launcher_others.go` (`args`, `Launch`). Upstream also wraps the editor
//! run in `term.TTY.Safe` (terminal state save/restore); not ported here.

/// `editor.Editor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Editor {
    pub args: Vec<String>,
    pub shell: bool,
}

/// `defaultEnvShell`.
fn default_env_shell(lookup: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let windows = cfg!(windows);
    let shell = lookup("SHELL")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| if windows { "cmd" } else { "/bin/bash" }.to_string());
    let flag = if shell == "cmd" { "/C" } else { "-c" };
    vec![shell, flag.to_string()]
}

/// `defaultEnvEditor`: first non-empty variable of `envs` wins, else `vi`
/// (`notepad` on Windows); an editor with spaces is split on spaces unless it
/// contains quotes or a backslash, which are punted to the shell.
pub fn default_env_editor(
    envs: &[&str],
    lookup: &dyn Fn(&str) -> Option<String>,
) -> (Vec<String>, bool) {
    let mut editor = String::new();
    for env in envs {
        if !env.is_empty() {
            editor = lookup(env).unwrap_or_default();
        }
        if !editor.is_empty() {
            break;
        }
    }
    if editor.is_empty() {
        editor = if cfg!(windows) { "notepad" } else { "vi" }.to_string();
    }
    if !editor.contains(' ') {
        return (vec![editor], false);
    }
    if !editor.contains(['"', '\'', '\\']) {
        return (editor.split(' ').map(str::to_string).collect(), false);
    }
    // rather than parse the shell arguments ourselves, punt to the shell
    let mut args = default_env_shell(lookup);
    args.push(editor);
    (args, true)
}

impl Editor {
    /// `NewDefaultEditor`.
    pub fn new_default(envs: &[&str]) -> Editor {
        let (args, shell) = default_env_editor(envs, &|k| std::env::var(k).ok());
        Editor { args, shell }
    }

    /// `Editor.args` (launcher_others.go): `%q` quotes the path.
    pub fn args_for(&self, path: &str) -> Vec<String> {
        let mut args = self.args.clone();
        if self.shell {
            let last = args.pop().unwrap_or_default();
            args.push(format!("{last} {path:?}"));
        } else {
            args.push(path.to_string());
        }
        args
    }

    /// `Editor.Launch` (launcher_others.go).
    pub fn launch(&self, path: &std::path::Path) -> Result<()> {
        if self.args.is_empty() {
            anyhow::bail!("no editor defined, can't open {}", path.display());
        }
        let abs = std::path::absolute(path)?;
        let args = self.args_for(&abs.to_string_lossy());
        match Command::new(&args[0]).args(&args[1..]).status() {
            Ok(st) if st.success() => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                anyhow::bail!("unable to launch the editor {:?}", self.args.join(" "))
            }
            _ => anyhow::bail!(
                "there was a problem with the editor {:?}",
                self.args.join(" ")
            ),
        }
    }

    /// `Editor.LaunchTempFile`: returns the edited bytes and the temp path
    /// (kept for the caller to clean up).
    pub fn launch_temp_file(
        &self,
        prefix: &str,
        suffix: &str,
        content: &[u8],
    ) -> Result<(Vec<u8>, std::path::PathBuf)> {
        let file = tempfile::Builder::new()
            .prefix(prefix)
            .suffix(suffix)
            .tempfile()?;
        let (_, path) = file.keep().map_err(|e| e.error)?;
        if let Err(e) = fs::write(&path, content) {
            let _ = fs::remove_file(&path);
            return Err(e.into());
        }
        self.launch(&path)?;
        let bytes = fs::read(&path)?;
        Ok((bytes, path))
    }
}

use anyhow::{Context, Result};
use kubernetes_rs_client::http::ApiClient;
use std::fs;
use std::process::Command;

/// Edit a resource in an editor
pub async fn execute(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: &str,
    output_format: &str,
) -> Result<()> {
    // `editor.NewDefaultEditor(editorEnvs())`: KUBE_EDITOR, then EDITOR
    // (editoptions.go `editorEnvs`).
    let editor = Editor::new_default(&["KUBE_EDITOR", "EDITOR"]);

    // Get API path for resource
    let api_path = get_resource_api_path(resource_type, namespace, name)?;

    // Fetch current resource
    let resource: serde_json::Value = client
        .get(&api_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get {} {}: {}", resource_type, name, e))?;

    // Convert to desired format
    let content = if output_format == "json" {
        serde_json::to_string_pretty(&resource)?
    } else {
        serde_yaml::to_string(&resource)?
    };

    // Launch the editor on a temp file (`LaunchTempFile`).
    let suffix = if output_format == "json" {
        ".json"
    } else {
        ".yaml"
    };
    let (edited_bytes, temp_path) =
        editor.launch_temp_file("kubectl-edit-", suffix, content.as_bytes())?;
    let _ = fs::remove_file(&temp_path);
    let edited_content = String::from_utf8(edited_bytes).context("Failed to read edited file")?;

    // Check if content changed
    if edited_content.trim() == content.trim() {
        println!("Edit cancelled, no changes made.");
        return Ok(());
    }

    // Parse edited content
    let edited_resource: serde_json::Value = if output_format == "json" {
        serde_json::from_str(&edited_content).context("Failed to parse edited JSON")?
    } else {
        serde_yaml::from_str(&edited_content).context("Failed to parse edited YAML")?
    };

    // Update resource
    let _updated: serde_json::Value = client
        .put(&api_path, &edited_resource)
        .await
        .context("Failed to update resource")?;

    println!("{}/{} edited", resource_type, name);

    Ok(())
}

pub fn get_resource_api_path(resource_type: &str, namespace: &str, name: &str) -> Result<String> {
    Ok(match resource_type {
        "pod" | "pods" | "po" => format!("/api/v1/namespaces/{}/pods/{}", namespace, name),
        "service" | "services" | "svc" => {
            format!("/api/v1/namespaces/{}/services/{}", namespace, name)
        }
        "deployment" | "deployments" | "deploy" => format!(
            "/apis/apps/v1/namespaces/{}/deployments/{}",
            namespace, name
        ),
        "statefulset" | "statefulsets" | "sts" => format!(
            "/apis/apps/v1/namespaces/{}/statefulsets/{}",
            namespace, name
        ),
        "daemonset" | "daemonsets" | "ds" => {
            format!("/apis/apps/v1/namespaces/{}/daemonsets/{}", namespace, name)
        }
        "replicaset" | "replicasets" | "rs" => format!(
            "/apis/apps/v1/namespaces/{}/replicasets/{}",
            namespace, name
        ),
        "job" | "jobs" => format!("/apis/batch/v1/namespaces/{}/jobs/{}", namespace, name),
        "cronjob" | "cronjobs" | "cj" => {
            format!("/apis/batch/v1/namespaces/{}/cronjobs/{}", namespace, name)
        }
        "configmap" | "configmaps" | "cm" => {
            format!("/api/v1/namespaces/{}/configmaps/{}", namespace, name)
        }
        "secret" | "secrets" => format!("/api/v1/namespaces/{}/secrets/{}", namespace, name),
        "serviceaccount" | "serviceaccounts" | "sa" => {
            format!("/api/v1/namespaces/{}/serviceaccounts/{}", namespace, name)
        }
        "ingress" | "ingresses" | "ing" => format!(
            "/apis/networking.k8s.io/v1/namespaces/{}/ingresses/{}",
            namespace, name
        ),
        "persistentvolumeclaim" | "persistentvolumeclaims" | "pvc" => format!(
            "/api/v1/namespaces/{}/persistentvolumeclaims/{}",
            namespace, name
        ),
        "persistentvolume" | "persistentvolumes" | "pv" => {
            format!("/api/v1/persistentvolumes/{}", name)
        }
        "storageclass" | "storageclasses" | "sc" => {
            format!("/apis/storage.k8s.io/v1/storageclasses/{}", name)
        }
        "namespace" | "namespaces" | "ns" => format!("/api/v1/namespaces/{}", name),
        "node" | "nodes" | "no" => format!("/api/v1/nodes/{}", name),
        "role" | "roles" => format!(
            "/apis/rbac.authorization.k8s.io/v1/namespaces/{}/roles/{}",
            namespace, name
        ),
        "rolebinding" | "rolebindings" => format!(
            "/apis/rbac.authorization.k8s.io/v1/namespaces/{}/rolebindings/{}",
            namespace, name
        ),
        "clusterrole" | "clusterroles" => {
            format!("/apis/rbac.authorization.k8s.io/v1/clusterroles/{}", name)
        }
        "clusterrolebinding" | "clusterrolebindings" => format!(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{}",
            name
        ),
        _ => anyhow::bail!("Unsupported resource type: {}", resource_type),
    })
}
