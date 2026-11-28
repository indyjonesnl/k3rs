use crate::discovery::RestMapper;
use crate::types::AuthCommands;
use anyhow::{Context, Result};
use kubernetes_rs_client::http::ApiClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfSubjectAccessReview {
    pub api_version: String,
    pub kind: String,
    pub spec: SelfSubjectAccessReviewSpec,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfSubjectAccessReviewSpec {
    pub resource_attributes: Option<ResourceAttributes>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAttributes {
    pub namespace: Option<String>,
    pub verb: String,
    pub resource: String,
    pub name: Option<String>,
}

/// Verbs known for resource requests, upstream `resourceVerbs`
/// (kubectl/pkg/cmd/auth/cani.go).
const RESOURCE_VERBS: &[&str] = &[
    "get",
    "list",
    "watch",
    "create",
    "update",
    "patch",
    "delete",
    "deletecollection",
    "use",
    "bind",
    "impersonate",
    "*",
    "approve",
    "sign",
    "escalate",
    "attest",
];

/// Verbs known for non-resource URLs, upstream `nonResourceURLVerbs`.
const NON_RESOURCE_URL_VERBS: &[&str] = &[
    "get", "put", "post", "head", "options", "delete", "patch", "*",
];

/// Resources the server supports but discovery cannot list, upstream
/// `nonStandardResourceNames`.
const NON_STANDARD_RESOURCE_NAMES: &[&str] = &["users", "groups"];

/// Group/version/resource triple, upstream `schema.GroupVersionResource`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gvr {
    pub group: String,
    pub version: String,
    pub resource: String,
}

impl Gvr {
    /// Whether the GVR is the zero value (`gvr == GroupVersionResource{}`).
    pub fn is_zero(&self) -> bool {
        self.group.is_empty() && self.version.is_empty() && self.resource.is_empty()
    }
}

/// Options of `kubectl auth can-i`, upstream `CanIOptions` (cani.go).
#[derive(Debug, Default)]
pub struct CanIOptions {
    pub all_namespaces: bool,
    pub quiet: bool,
    pub no_headers: bool,
    pub list: bool,
    pub namespace: String,
    pub verb: String,
    pub resource: Gvr,
    pub non_resource_url: String,
    pub subresource: String,
    pub resource_name: String,
    /// Warnings collected for stderr, each printed as `Warning: <msg>`.
    pub warnings: Vec<String>,
}

/// `o.resourceFor` (cani.go): resolve a resource argument through the REST
/// mapper, warning when the server does not know it.
pub fn resource_for(mapper: &RestMapper, arg: &str, warnings: &mut Vec<String>) -> Gvr {
    if arg == "*" {
        return Gvr {
            resource: arg.to_string(),
            ..Default::default()
        };
    }
    // schema.ParseResourceArg: "resource.version.group" or "resource.group".
    let lower = arg.to_lowercase();
    let (resource, group) = match lower.split_once('.') {
        Some((r, g)) => (r.to_string(), g.to_string()),
        None => (lower.clone(), String::new()),
    };
    let fully_specified = lower.splitn(3, '.').collect::<Vec<_>>();
    let mut found = None;
    if fully_specified.len() == 3 {
        let (r, v, g) = (fully_specified[0], fully_specified[1], fully_specified[2]);
        found = mapper
            .resolve(r)
            .filter(|m| m.group == g && (m.version == v))
            .cloned();
    }
    if found.is_none() {
        found = mapper
            .resolve(&resource)
            .filter(|m| group.is_empty() || m.group == group)
            .cloned();
    }
    match found {
        Some(m) => Gvr {
            group: m.group,
            version: m.version,
            resource: m.plural,
        },
        None => {
            let group_resource = if group.is_empty() {
                resource.clone()
            } else {
                format!("{resource}.{group}")
            };
            if !NON_STANDARD_RESOURCE_NAMES.contains(&group_resource.as_str()) {
                if group.is_empty() {
                    warnings.push(format!(
                        "the server doesn't have a resource type '{resource}'\n"
                    ));
                } else {
                    warnings.push(format!(
                        "the server doesn't have a resource type '{resource}' in group '{group}'\n"
                    ));
                }
            }
            Gvr {
                resource: arg.to_string(),
                ..Default::default()
            }
        }
    }
}

impl CanIOptions {
    /// `Complete` (cani.go) for the argument handling.
    pub fn complete(
        &mut self,
        args: &[String],
        default_namespace: &str,
        mapper: Option<&RestMapper>,
    ) -> Result<()> {
        if self.list {
            if !args.is_empty() {
                anyhow::bail!("list option must be specified with no arguments");
            }
        } else {
            if args.len() != 2 {
                anyhow::bail!(
                    "you must specify two arguments: verb resource or verb resource/resourceName.\nSee 'kubectl auth can-i -h' for help and examples."
                );
            }
            self.verb = args[0].clone();
            if args[1].starts_with('/') {
                self.non_resource_url = args[1].clone();
            } else {
                let (resource, name) = match args[1].split_once('/') {
                    Some((r, n)) => (r, Some(n)),
                    None => (args[1].as_str(), None),
                };
                let empty = RestMapper::new(Vec::new());
                self.resource =
                    resource_for(mapper.unwrap_or(&empty), resource, &mut self.warnings);
                if let Some(n) = name {
                    self.resource_name = n.to_string();
                }
            }
        }
        self.namespace = if self.all_namespaces {
            String::new()
        } else {
            default_namespace.to_string()
        };
        Ok(())
    }

    /// `Validate` (cani.go).
    pub fn validate(&mut self, mapper: Option<&RestMapper>) -> Result<()> {
        if self.list {
            if self.quiet || self.all_namespaces || !self.subresource.is_empty() {
                anyhow::bail!(
                    "list option can't be specified with neither quiet, all-namespaces nor subresource options"
                );
            }
            return Ok(());
        }

        if !self.non_resource_url.is_empty() {
            if !self.subresource.is_empty() {
                anyhow::bail!("--subresource can not be used with NonResourceURL");
            }
            if !self.resource.is_zero() || !self.resource_name.is_empty() {
                anyhow::bail!("NonResourceURL and ResourceName can not specified together");
            }
            if !NON_RESOURCE_URL_VERBS.contains(&self.verb.as_str()) {
                self.warnings
                    .push(format!("verb '{}' is not a known verb\n", self.verb));
            }
        } else if !self.resource.is_zero() && !self.all_namespaces && mapper.is_some() {
            // isNamespaced: "*" is namespaced; an unknown resource yields an
            // error, which upstream ignores.
            let namespaced = if self.resource.resource == "*" {
                Some(true)
            } else {
                mapper
                    .and_then(|m| m.resolve(&self.resource.resource))
                    .filter(|m| m.group == self.resource.group)
                    .map(|m| m.namespaced)
            };
            if namespaced == Some(false) {
                if self.resource.group.is_empty() {
                    self.warnings.push(format!(
                        "resource '{}' is not namespace scoped\n",
                        self.resource.resource
                    ));
                } else {
                    self.warnings.push(format!(
                        "resource '{}' is not namespace scoped in group '{}'\n",
                        self.resource.resource, self.resource.group
                    ));
                }
            }
            if !RESOURCE_VERBS.contains(&self.verb.as_str()) {
                self.warnings
                    .push(format!("verb '{}' is not a known verb\n", self.verb));
            }
        }

        if self.no_headers {
            anyhow::bail!("--no-headers cannot be set without --list specified");
        }
        Ok(())
    }

    /// The `SelfSubjectAccessReview` that `RunAccessCheck` (cani.go) posts.
    pub fn access_review(&self) -> Value {
        let spec = if self.non_resource_url.is_empty() {
            let mut attrs = serde_json::Map::new();
            if !self.namespace.is_empty() {
                attrs.insert("namespace".into(), json!(self.namespace));
            }
            attrs.insert("verb".into(), json!(self.verb));
            for (k, v) in [
                ("group", &self.resource.group),
                ("resource", &self.resource.resource),
                ("subresource", &self.subresource),
                ("name", &self.resource_name),
            ] {
                if !v.is_empty() {
                    attrs.insert(k.into(), json!(v));
                }
            }
            json!({ "resourceAttributes": attrs })
        } else {
            json!({ "nonResourceAttributes": {
                "verb": self.verb,
                "path": self.non_resource_url,
            }})
        };
        json!({
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": spec,
        })
    }
}

/// Text printed by `RunAccessCheck` (cani.go) for a review result.
pub fn format_access_result(status: &Value) -> String {
    if status
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return "yes\n".to_string();
    }
    let mut out = String::from("no");
    for key in ["reason", "evaluationError"] {
        if let Some(v) = status.get(key).and_then(Value::as_str) {
            if !v.is_empty() {
                out.push_str(&format!(" - {v}"));
            }
        }
    }
    out.push('\n');
    out
}

/// Execute auth commands
pub async fn execute(
    client: &ApiClient,
    command: AuthCommands,
    default_namespace: &str,
) -> Result<()> {
    match command {
        AuthCommands::CanI {
            args,
            namespace,
            all_namespaces,
            quiet,
            subresource,
            list,
            no_headers,
        } => {
            let mut o = CanIOptions {
                all_namespaces,
                quiet,
                no_headers,
                list,
                subresource,
                ..Default::default()
            };
            let ns = namespace.as_deref().unwrap_or(default_namespace);
            let mapper = if list {
                None
            } else {
                RestMapper::from_server(client).await.ok()
            };
            o.complete(&args, ns, mapper.as_ref())?;
            o.validate(mapper.as_ref())?;
            for w in &o.warnings {
                eprintln!("Warning: {w}");
            }
            if o.list {
                anyhow::bail!("--list is not supported yet");
            }
            let response: Value = client
                .post(
                    "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                    &o.access_review(),
                )
                .await
                .context("Failed to check authorization")?;
            let status = response.get("status").cloned().unwrap_or(Value::Null);
            if !o.quiet {
                print!("{}", format_access_result(&status));
            }
            if !status
                .get("allowed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                std::process::exit(1);
            }
        }
        AuthCommands::Whoami { output } => {
            // Use SelfSubjectReview (k8s 1.27+) or fallback to token review
            let result: Value = client
                .post(
                    "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                    &json!({
                        "apiVersion": "authentication.k8s.io/v1",
                        "kind": "SelfSubjectReview",
                    }),
                )
                .await
                .context("Failed to get user identity")?;

            if let Some(fmt) = output {
                match fmt.as_str() {
                    "json" => println!("{}", serde_json::to_string_pretty(&result)?),
                    "yaml" => println!("{}", serde_yaml::to_string(&result)?),
                    _ => println!("{}", serde_json::to_string_pretty(&result)?),
                }
            } else {
                // Extract user info for simple output
                if let Some(user_info) = result.get("status").and_then(|s| s.get("userInfo")) {
                    if let Some(username) = user_info.get("username") {
                        println!("Username: {}", username);
                    }
                    if let Some(uid) = user_info.get("uid") {
                        println!("UID: {}", uid);
                    }
                    if let Some(groups) = user_info.get("groups") {
                        println!("Groups: {}", groups);
                    }
                }
            }
        }
        AuthCommands::Reconcile {
            filename,
            namespace,
            remove_extra_permissions,
            remove_extra_subjects,
        } => {
            let ns = namespace.as_deref().unwrap_or(default_namespace);
            execute_reconcile(
                client,
                &filename,
                ns,
                remove_extra_permissions,
                remove_extra_subjects,
            )
            .await?;
        }
    }

    Ok(())
}

/// Reconcile RBAC resources from a file against the server.
///
/// Reads Role, ClusterRole, RoleBinding, and ClusterRoleBinding resources from
/// a file and ensures they exist on the server with the correct rules/subjects.
async fn execute_reconcile(
    client: &ApiClient,
    filename: &str,
    namespace: &str,
    remove_extra_permissions: bool,
    remove_extra_subjects: bool,
) -> Result<()> {
    let contents = fs::read_to_string(filename).context("Failed to read file")?;

    for document in serde_yaml::Deserializer::from_str(&contents) {
        let value: serde_yaml::Value =
            serde_yaml::Value::deserialize(document).context("Failed to parse YAML document")?;

        if value.is_null() {
            continue;
        }

        let kind = value
            .get("kind")
            .and_then(|k| k.as_str())
            .context("Missing 'kind' field")?;

        let name = value
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .context("Missing 'metadata.name' field")?;

        let json_value: Value = serde_yaml::from_value(value.clone())?;

        match kind {
            "ClusterRole" => {
                let path = format!("/apis/rbac.authorization.k8s.io/v1/clusterroles/{}", name);
                reconcile_resource(
                    client,
                    &path,
                    kind,
                    name,
                    &json_value,
                    remove_extra_permissions,
                )
                .await?;
            }
            "ClusterRoleBinding" => {
                let path = format!(
                    "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{}",
                    name
                );
                reconcile_binding(
                    client,
                    &path,
                    kind,
                    name,
                    &json_value,
                    remove_extra_subjects,
                )
                .await?;
            }
            "Role" => {
                let res_ns = value
                    .get("metadata")
                    .and_then(|m| m.get("namespace"))
                    .and_then(|n| n.as_str())
                    .unwrap_or(namespace);
                let path = format!(
                    "/apis/rbac.authorization.k8s.io/v1/namespaces/{}/roles/{}",
                    res_ns, name
                );
                reconcile_resource(
                    client,
                    &path,
                    kind,
                    name,
                    &json_value,
                    remove_extra_permissions,
                )
                .await?;
            }
            "RoleBinding" => {
                let res_ns = value
                    .get("metadata")
                    .and_then(|m| m.get("namespace"))
                    .and_then(|n| n.as_str())
                    .unwrap_or(namespace);
                let path = format!(
                    "/apis/rbac.authorization.k8s.io/v1/namespaces/{}/rolebindings/{}",
                    res_ns, name
                );
                reconcile_binding(
                    client,
                    &path,
                    kind,
                    name,
                    &json_value,
                    remove_extra_subjects,
                )
                .await?;
            }
            _ => {
                eprintln!(
                    "Warning: skipping non-RBAC resource kind '{}' in reconcile",
                    kind
                );
            }
        }
    }

    Ok(())
}

/// Reconcile a Role or ClusterRole resource.
async fn reconcile_resource(
    client: &ApiClient,
    path: &str,
    kind: &str,
    name: &str,
    desired: &Value,
    remove_extra_permissions: bool,
) -> Result<()> {
    let existing: std::result::Result<Value, _> = client.get(path).await;

    match existing {
        Ok(current) => {
            // Build patch with desired rules
            let mut patch = json!({});
            if let Some(rules) = desired.get("rules") {
                if remove_extra_permissions {
                    // Replace rules entirely
                    patch["rules"] = rules.clone();
                } else {
                    // Merge: add any missing rules from desired
                    let current_rules = current
                        .get("rules")
                        .and_then(|r| r.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let desired_rules = rules.as_array().cloned().unwrap_or_default();

                    let mut merged = current_rules;
                    for rule in desired_rules {
                        if !merged.contains(&rule) {
                            merged.push(rule);
                        }
                    }
                    patch["rules"] = Value::Array(merged);
                }
            }

            if let Some(labels) = desired.get("metadata").and_then(|m| m.get("labels")) {
                patch["metadata"] = json!({"labels": labels.clone()});
            }

            let _: Value = client
                .patch(path, &patch, "application/strategic-merge-patch+json")
                .await
                .context(format!("Failed to reconcile {}/{}", kind, name))?;
            println!("{}/{} reconciled", kind.to_lowercase(), name);
        }
        Err(_) => {
            // Create the resource
            let collection_path = path.rsplit_once('/').map(|(p, _)| p).unwrap_or(path);
            let _: Value = client
                .post(collection_path, desired)
                .await
                .context(format!("Failed to create {}/{}", kind, name))?;
            println!("{}/{} created", kind.to_lowercase(), name);
        }
    }

    Ok(())
}

/// Reconcile a RoleBinding or ClusterRoleBinding resource.
async fn reconcile_binding(
    client: &ApiClient,
    path: &str,
    kind: &str,
    name: &str,
    desired: &Value,
    remove_extra_subjects: bool,
) -> Result<()> {
    let existing: std::result::Result<Value, _> = client.get(path).await;

    match existing {
        Ok(current) => {
            let mut patch = json!({});

            // Reconcile roleRef (must match)
            if let Some(role_ref) = desired.get("roleRef") {
                let current_role_ref = current.get("roleRef");
                if current_role_ref.is_some() && current_role_ref != Some(role_ref) {
                    anyhow::bail!(
                        "{}/{}: roleRef is immutable and does not match desired state",
                        kind,
                        name
                    );
                }
            }

            // Reconcile subjects
            if let Some(desired_subjects) = desired.get("subjects") {
                if remove_extra_subjects {
                    patch["subjects"] = desired_subjects.clone();
                } else {
                    let current_subjects = current
                        .get("subjects")
                        .and_then(|s| s.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let desired_subs = desired_subjects.as_array().cloned().unwrap_or_default();

                    let mut merged = current_subjects;
                    for sub in desired_subs {
                        if !merged.contains(&sub) {
                            merged.push(sub);
                        }
                    }
                    patch["subjects"] = Value::Array(merged);
                }
            }

            let _: Value = client
                .patch(path, &patch, "application/strategic-merge-patch+json")
                .await
                .context(format!("Failed to reconcile {}/{}", kind, name))?;
            println!("{}/{} reconciled", kind.to_lowercase(), name);
        }
        Err(_) => {
            let collection_path = path.rsplit_once('/').map(|(p, _)| p).unwrap_or(path);
            let _: Value = client
                .post(collection_path, desired)
                .await
                .context(format!("Failed to create {}/{}", kind, name))?;
            println!("{}/{} created", kind.to_lowercase(), name);
        }
    }

    Ok(())
}
