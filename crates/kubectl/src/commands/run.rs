use anyhow::{Context, Result};
use kubernetes_rs_client::http::ApiClient;
use kubernetes_rs_common::quantity::Quantity;
use kubernetes_rs_common::validation::metav1::is_env_var_name;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// The `kubectl run` flags consumed by the pod generator
/// (`pkg/cmd/run/run.go` `addRunFlags`).
#[derive(Debug, Default, Clone)]
pub struct RunPodParams {
    pub name: String,
    pub image: String,
    pub port: Option<u16>,
    pub env: Vec<String>,
    pub labels: Option<String>,
    pub annotations: Vec<String>,
    /// `--restart`; empty means unset.
    pub restart: String,
    pub image_pull_policy: String,
    pub stdin: bool,
    pub tty: bool,
    pub leave_stdin_open: bool,
    pub privileged: bool,
    pub requests: String,
    pub limits: String,
    pub serviceaccount: String,
    /// `--command`: use the extra args as `command` instead of `args`.
    pub command: bool,
    pub args: Vec<String>,
}

/// `getRestartPolicy` (`pkg/cmd/run/run.go:515`).
pub fn get_restart_policy(restart: &str, interactive: bool) -> Result<String> {
    if restart.is_empty() {
        return Ok(if interactive { "OnFailure" } else { "Always" }.to_string());
    }
    match restart {
        "Always" | "OnFailure" | "Never" => Ok(restart.to_string()),
        _ => anyhow::bail!("invalid restart policy: {}", restart),
    }
}

/// `verifyImagePullPolicy` (`pkg/cmd/run/run.go:534`).
pub fn verify_image_pull_policy(policy: &str) -> Result<()> {
    match policy {
        "Always" | "IfNotPresent" | "Never" | "" => Ok(()),
        _ => anyhow::bail!("invalid image pull policy: {}", policy),
    }
}

/// `generate.ParseLabels` (`pkg/generate/generate.go:178`).
pub fn parse_labels(spec: &str) -> Result<BTreeMap<String, String>> {
    if spec.is_empty() {
        anyhow::bail!("no label spec passed");
    }
    let mut labels = BTreeMap::new();
    for part in spec.split(',') {
        let kv: Vec<&str> = part.split('=').collect();
        if kv.len() != 2 {
            anyhow::bail!("unexpected label spec: {}", part);
        }
        if kv[0].is_empty() {
            anyhow::bail!("unexpected empty label key");
        }
        labels.insert(kv[0].to_string(), kv[1].to_string());
    }
    Ok(labels)
}

/// `cmdutil.ParsePairs` with `supportRemove=false`
/// (`pkg/cmd/util/helpers.go:778`).
pub fn parse_pairs(pairs: &[String], pair_type: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut invalid: Vec<&str> = Vec::new();
    for p in pairs {
        match p.split_once('=') {
            Some((k, v)) if !p.starts_with('=') => {
                out.insert(k.to_string(), v.to_string());
            }
            _ => invalid.push(p),
        }
    }
    if !invalid.is_empty() {
        anyhow::bail!("invalid {} format: {}", pair_type, invalid.join(", "));
    }
    Ok(out)
}

/// `parseEnvs` (`pkg/generate/versioned/run.go`).
pub fn parse_envs(envs: &[String]) -> Result<Vec<Value>> {
    let mut out = Vec::with_capacity(envs.len());
    for env in envs {
        let Some((name, value)) = env.split_once('=') else {
            anyhow::bail!("invalid env: {}", env);
        };
        if name.is_empty() || !is_env_var_name(name).is_empty() {
            anyhow::bail!("invalid env: {}", env);
        }
        out.push(json!({"name": name, "value": value}));
    }
    Ok(out)
}

/// `populateResourceListV1` (`pkg/generate/versioned/run.go:133`).
pub fn populate_resource_list(spec: &str) -> Result<Option<Map<String, Value>>> {
    if spec.is_empty() {
        return Ok(None);
    }
    let mut result = Map::new();
    for statement in spec.split(',') {
        let parts: Vec<&str> = statement.split('=').collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "Invalid argument syntax {}, expected <resource>=<value>",
                statement
            );
        }
        let q = Quantity::parse(parts[1]).map_err(|e| anyhow::anyhow!("{}", e))?;
        result.insert(parts[0].to_string(), Value::String(q.to_string()));
    }
    Ok(Some(result))
}

/// `BasicPod.Generate` (`pkg/generate/versioned/run.go`): the Pod
/// `kubectl run` creates.
pub fn generate_pod(p: &RunPodParams) -> Result<Value> {
    if p.name.is_empty() {
        anyhow::bail!("'name' is a required parameter");
    }
    let envs = parse_envs(&p.env)?;
    let annotations = parse_pairs(&p.annotations, "annotations")?;
    let labels = match p.labels.as_deref() {
        Some(l) if !l.is_empty() => parse_labels(l)?,
        _ => BTreeMap::from([("run".to_string(), p.name.clone())]),
    };
    let mut resources = Map::new();
    if let Some(l) = populate_resource_list(&p.limits)? {
        resources.insert("limits".into(), Value::Object(l));
    }
    if let Some(r) = populate_resource_list(&p.requests)? {
        resources.insert("requests".into(), Value::Object(r));
    }
    let restart = if p.restart.is_empty() {
        "Always"
    } else {
        p.restart.as_str()
    };

    let mut container = json!({"name": p.name, "image": p.image});
    if p.stdin {
        container["stdin"] = json!(true);
        if !p.leave_stdin_open {
            container["stdinOnce"] = json!(true);
        }
    }
    if p.tty {
        container["tty"] = json!(true);
    }
    if !resources.is_empty() {
        container["resources"] = Value::Object(resources);
    }
    if p.privileged {
        container["securityContext"] = json!({"privileged": true});
    }
    // updatePodContainers
    if !p.args.is_empty() {
        let key = if p.command { "command" } else { "args" };
        container[key] = json!(p.args);
    }
    if !envs.is_empty() {
        container["env"] = json!(envs);
    }
    if !p.image_pull_policy.is_empty() {
        container["imagePullPolicy"] = json!(p.image_pull_policy);
    }
    // updatePodPorts
    if let Some(port) = p.port {
        container["ports"] = json!([{"containerPort": port}]);
    }

    let mut metadata = json!({"name": p.name, "labels": labels});
    if !annotations.is_empty() {
        metadata["annotations"] = json!(annotations);
    }
    let mut spec = json!({
        "containers": [container],
        "dnsPolicy": "ClusterFirst",
        "restartPolicy": restart,
    });
    if !p.serviceaccount.is_empty() {
        spec["serviceAccountName"] = json!(p.serviceaccount);
    }
    Ok(json!({"apiVersion": "v1", "kind": "Pod", "metadata": metadata, "spec": spec}))
}

/// `RunOptions.Run` validations that precede generation
/// (`pkg/cmd/run/run.go:244`), minus attach/expose.
pub fn validate_run(p: &RunPodParams) -> Result<String> {
    if p.image.is_empty() {
        anyhow::bail!("--image is required");
    }
    if p.tty && !p.stdin {
        anyhow::bail!("-i/--stdin is required for containers with -t/--tty=true");
    }
    let restart = get_restart_policy(&p.restart, p.stdin)?;
    verify_image_pull_policy(&p.image_pull_policy)?;
    Ok(restart)
}

pub async fn execute(
    client: &ApiClient,
    namespace: &str,
    mut params: RunPodParams,
    dry_run: Option<&str>,
) -> Result<()> {
    let restart = validate_run(&params)?;
    params.restart = restart;
    let name = params.name.clone();
    let mut pod = generate_pod(&params)?;
    pod["metadata"]["namespace"] = json!(namespace);

    // Handle dry-run
    if let Some(dr) = dry_run {
        if dr == "client" {
            // Just print the resource
            let yaml = serde_yaml::to_string(&pod)?;
            print!("{}", yaml);
            return Ok(());
        }
    }

    let path = format!("/api/v1/namespaces/{}/pods", namespace);
    let query = if let Some(dr) = dry_run {
        if dr == "server" {
            format!("{}?dryRun=All", path)
        } else {
            path
        }
    } else {
        path
    };

    let _result: serde_json::Value = client
        .post(&query, &pod)
        .await
        .context("Failed to create pod")?;

    println!("pod/{} created", name);
    Ok(())
}
