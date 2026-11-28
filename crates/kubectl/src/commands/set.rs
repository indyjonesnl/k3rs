use crate::discovery::ResourceMapping;
use crate::types::SetCommands;
use anyhow::{Context, Result};
use kubernetes_rs_client::http::ApiClient;
use serde_json::{json, Value};

/// Dispatch set subcommands.
pub async fn execute_set(
    client: &ApiClient,
    command: SetCommands,
    default_namespace: &str,
) -> Result<()> {
    match command {
        SetCommands::Image {
            resource,
            container_images,
            namespace,
        } => {
            execute_image(
                client,
                &resource,
                &container_images,
                namespace.as_deref().unwrap_or(default_namespace),
            )
            .await
        }
        SetCommands::Env {
            resource,
            env_vars,
            namespace,
            container,
            list,
        } => {
            execute_env(
                client,
                &resource,
                &env_vars,
                namespace.as_deref().unwrap_or(default_namespace),
                container.as_deref(),
                list,
            )
            .await
        }
        SetCommands::Resources {
            resource,
            namespace,
            container,
            limits,
            requests,
        } => {
            execute_resources(
                client,
                &resource,
                namespace.as_deref().unwrap_or(default_namespace),
                container.as_deref(),
                limits.as_deref(),
                requests.as_deref(),
            )
            .await
        }
        SetCommands::Selector {
            resource,
            expressions,
            namespace,
            all: _,
            resource_version: _,
        } => {
            execute_selector(
                client,
                &resource,
                &expressions,
                namespace.as_deref().unwrap_or(default_namespace),
            )
            .await
        }
        SetCommands::ServiceAccount {
            resource,
            service_account_name,
            namespace,
        } => {
            execute_serviceaccount(
                client,
                &resource,
                &service_account_name,
                namespace.as_deref().unwrap_or(default_namespace),
            )
            .await
        }
        SetCommands::Subject {
            resource,
            namespace,
            serviceaccount,
            user,
            group,
        } => {
            execute_subject(
                client,
                &resource,
                namespace.as_deref().unwrap_or(default_namespace),
                serviceaccount.as_deref(),
                user.as_deref(),
                group.as_deref(),
            )
            .await
        }
    }
}

/// Resolve the API path and mapping for a resource type/name via server
/// discovery.
///
/// Uses `RestMapper` so any kind the server exposes (plural, singular, short
/// name, or Kind) is addressable, rather than a hardcoded alias table. Returns
/// the item path plus the resolved `ResourceMapping`, so callers can build a
/// group-qualified label (via `ops::resource_label`) and apply kind guards
/// without a second `RestMapper::from_server` round-trip. This is the single
/// discovery call site shared by every `set` subcommand.
async fn resolve_resource(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: &str,
) -> Result<(String, ResourceMapping)> {
    let mapper = crate::discovery::RestMapper::from_server(client).await?;
    let mapping = mapper.resolve(resource_type).ok_or_else(|| {
        anyhow::anyhow!("error: the server doesn't have a resource type \"{resource_type}\"")
    })?;
    let ns = if mapping.namespaced {
        Some(namespace)
    } else {
        None
    };
    let path = crate::ops::build_path(mapping, ns, Some(name));
    Ok((path, mapping.clone()))
}

/// Parse "resource_type/name" format into (type, name).
pub fn parse_resource_arg(arg: &str) -> Result<(String, String)> {
    if let Some((rt, name)) = arg.split_once('/') {
        Ok((rt.to_string(), name.to_string()))
    } else {
        anyhow::bail!(
            "Invalid resource format: '{}'. Expected TYPE/NAME (e.g., deployment/nginx)",
            arg
        );
    }
}

/// Update container images in a resource.
///
/// Usage: `kubectl set image deployment/nginx nginx=nginx:1.9.1`
pub async fn execute_image(
    client: &ApiClient,
    resource: &str,
    container_images: &[String],
    namespace: &str,
) -> Result<()> {
    let (resource_type, name) = parse_resource_arg(resource)?;
    let (path, mapping) = resolve_resource(client, &resource_type, &name, namespace).await?;

    // Parse container=image pairs
    let mut image_updates: Vec<(String, String)> = Vec::new();
    for ci in container_images {
        if let Some((container, image)) = ci.split_once('=') {
            image_updates.push((container.to_string(), image.to_string()));
        } else {
            anyhow::bail!("Invalid image format: '{}'. Expected CONTAINER=IMAGE", ci);
        }
    }

    if image_updates.is_empty() {
        anyhow::bail!("At least one CONTAINER=IMAGE argument is required");
    }

    // Get the current resource to find container indices
    let current: Value = client
        .get(&path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))
        .context("Failed to get resource")?;

    // Find the containers array path (handles both pod and pod template specs)
    let containers = if current
        .get("spec")
        .and_then(|s| s.get("template"))
        .is_some()
    {
        // Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob
        current["spec"]["template"]["spec"]["containers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    } else {
        // Pod
        current["spec"]["containers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    };

    // Build the strategic merge patch for containers
    let mut patch_containers: Vec<Value> = Vec::new();
    for (container_name, image) in &image_updates {
        if container_name == "*" {
            // Update all containers
            for c in &containers {
                if let Some(cname) = c.get("name").and_then(|n| n.as_str()) {
                    patch_containers.push(json!({
                        "name": cname,
                        "image": image,
                    }));
                }
            }
        } else {
            // Check container exists
            let found = containers
                .iter()
                .any(|c| c.get("name").and_then(|n| n.as_str()) == Some(container_name));
            if !found {
                anyhow::bail!(
                    "Container '{}' not found in resource {}/{}",
                    container_name,
                    resource_type,
                    name
                );
            }
            patch_containers.push(json!({
                "name": container_name,
                "image": image,
            }));
        }
    }

    // Build patch based on resource type
    let patch_body = if current
        .get("spec")
        .and_then(|s| s.get("template"))
        .is_some()
    {
        json!({
            "spec": {
                "template": {
                    "spec": {
                        "containers": patch_containers,
                    }
                }
            }
        })
    } else {
        json!({
            "spec": {
                "containers": patch_containers,
            }
        })
    };

    let _result: Value = client
        .patch(&path, &patch_body, "application/strategic-merge-patch+json")
        .await
        .context("Failed to update image")?;

    let label = crate::ops::resource_label(&mapping, &name);
    for (container_name, image) in &image_updates {
        if container_name == "*" {
            println!("{label} image updated to {image} (all containers)");
        } else {
            println!("{label} container {container_name} image updated to {image}");
        }
    }

    Ok(())
}

/// Update environment variables on a resource.
///
/// Usage: `kubectl set env deployment/registry STORAGE_DIR=/local`
///
/// Ports `EnvOptions.RunEnv` (set_env.go:280): `ParseEnv`, `selectContainers`
/// over containers plus init containers, `validateNoOverwrites` (skipped, as
/// `--overwrite` defaults to true), `updateEnv`, and the `--list` output.
pub async fn execute_env(
    client: &ApiClient,
    resource: &str,
    env_vars: &[String],
    namespace: &str,
    container_name: Option<&str>,
    list: bool,
) -> Result<()> {
    let (resource_type, name) = parse_resource_arg(resource)?;
    let (path, mapping) = resolve_resource(client, &resource_type, &name, namespace).await?;

    // ParseEnv(append(o.EnvParams, o.envArgs...), o.In)
    let mut stdin = std::io::stdin();
    let (env, remove, _used_stdin) = parse_env(env_vars, Some(&mut stdin))?;

    // Get current resource
    let current: Value = client
        .get(&path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))
        .context("Failed to get resource")?;

    // ContainerSelector defaults to "*" (NewEnvOptions).
    let selector = container_name.unwrap_or("*");
    let spec_ptr = pod_spec_pointer(&current);
    let pod_spec = current.pointer(&spec_ptr).cloned().unwrap_or(Value::Null);
    let kind = current.get("kind").and_then(|k| k.as_str()).unwrap_or("");
    let obj_name = current
        .pointer("/metadata/name")
        .and_then(|n| n.as_str())
        .unwrap_or(&name);

    // containers = selectContainers(spec.Containers) + selectContainers(spec.InitContainers)
    let empty = Vec::new();
    let mut selected: Vec<(String, usize, &Value)> = Vec::new();
    for field in ["containers", "initContainers"] {
        for (i, c) in pod_spec
            .get(field)
            .and_then(|c| c.as_array())
            .unwrap_or(&empty)
            .iter()
            .enumerate()
        {
            let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if select_string(cname, selector) {
                selected.push((field.to_string(), i, c));
            }
        }
    }
    if selected.is_empty() {
        eprintln!("Warning: {kind}/{obj_name} does not have any containers matching {selector:?}");
        return Ok(());
    }

    let mut ops: Vec<Value> = Vec::new();
    for (field, i, c) in &selected {
        let existing: Vec<Value> = c
            .get("env")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();
        let updated = update_env(&existing, &env, &remove);
        if list {
            let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("");
            println!("# {kind} {obj_name}, container {cname}");
            for e in &updated {
                let n = e.get("name").and_then(|n| n.as_str()).unwrap_or("");
                match e.get("valueFrom") {
                    None | Some(Value::Null) => {
                        let v = e.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        println!("{n}={v}");
                    }
                    Some(_) => println!("# {n} from {}", env_var_ref_string(&e["valueFrom"])),
                }
            }
            continue;
        }
        let env_path = format!("{spec_ptr}/{field}/{i}/env");
        if updated == existing {
            continue;
        }
        if updated.is_empty() {
            ops.push(json!({"op": "remove", "path": env_path}));
        } else {
            ops.push(json!({"op": "add", "path": env_path, "value": updated}));
        }
    }
    if list {
        return Ok(());
    }

    // make sure arguments to set or replace environment variables are set
    // before returning a successful message (set_env.go:545)
    if ops.is_empty() {
        // no changes
        return Ok(());
    }
    if env.is_empty() && remove.is_empty() {
        anyhow::bail!("at least one environment variable must be provided");
    }

    let _result: Value = client
        .patch(&path, &Value::Array(ops), "application/json-patch+json")
        .await
        .context("failed to patch env update to pod template")?;

    println!(
        "{} env updated",
        crate::ops::resource_label(&mapping, &name)
    );

    Ok(())
}

/// JSON pointer to the pod spec of a pod or of an object with a pod template
/// (`polymorphichelpers.UpdatePodSpecForObject`).
fn pod_spec_pointer(obj: &Value) -> String {
    if obj
        .pointer("/spec/jobTemplate/spec/template/spec")
        .is_some()
    {
        "/spec/jobTemplate/spec/template/spec".to_string()
    } else if obj.pointer("/spec/template/spec").is_some() {
        "/spec/template/spec".to_string()
    } else {
        "/spec".to_string()
    }
}

/// `GetEnvVarRefString` (cmd/set/env/env_resolve.go): a short description of
/// an env var's `valueFrom`.
fn env_var_ref_string(from: &Value) -> String {
    let sel = |k: &str| -> Option<(String, String)> {
        let r = from.get(k)?;
        Some((
            r.get("name")?.as_str()?.to_string(),
            r.get("key")?.as_str()?.to_string(),
        ))
    };
    if let Some(f) = from.get("fieldRef") {
        return format!(
            "field path {}",
            f.get("fieldPath").and_then(|v| v.as_str()).unwrap_or("")
        );
    }
    if let Some(r) = from.get("resourceFieldRef") {
        return format!(
            "resource {}",
            r.get("resource").and_then(|v| v.as_str()).unwrap_or("")
        );
    }
    if let Some((n, k)) = sel("configMapKeyRef") {
        return format!("configmap {n}, key {k}");
    }
    if let Some((n, k)) = sel("secretKeyRef") {
        return format!("secret {n}, key {k}");
    }
    String::new()
}

/// `IsEnvironmentArgument` (cmd/set/env/env_parse.go:35): the regexp
/// `(?ms)^(.+)\=(.*)$` matches iff there is an `=` after at least one char.
pub fn is_environment_argument(s: &str) -> bool {
    s.char_indices().any(|(i, c)| c == '=' && i > 0)
}

/// `SplitEnvironmentFromResources` (env_parse.go:40): resources come first,
/// then environment arguments (`KEY=VALUE` or `KEY-`). `None` when a resource
/// follows an environment argument.
pub fn split_environment_from_resources(args: &[String]) -> Option<(Vec<String>, Vec<String>)> {
    let (mut resources, mut env_args) = (Vec::new(), Vec::new());
    let mut first = true;
    for s in args {
        let is_env = is_environment_argument(s) || s.ends_with('-');
        match (first, is_env) {
            (true, true) => {
                first = false;
                env_args.push(s.clone());
            }
            (false, true) => env_args.push(s.clone()),
            (true, false) => resources.push(s.clone()),
            (false, false) => return None,
        }
    }
    Some((resources, env_args))
}

fn env_var(name: &str, value: &str) -> Value {
    json!({"name": name, "value": value})
}

/// `readEnv` (env_parse.go:125): `KEY=VALUE` lines, `#` starts a comment.
fn read_env(r: &mut dyn std::io::Read) -> Result<Vec<Value>> {
    use std::io::BufRead;
    let mut env = Vec::new();
    for line in std::io::BufReader::new(r).lines() {
        let line = line?;
        let spec = line.split('#').next().unwrap_or("");
        if let Some((k, v)) = spec.split_once('=') {
            env.push(env_var(k, v));
        }
    }
    Ok(env)
}

/// `ParseEnv` (env_parse.go:108) via `parseIntoEnvVar` (:55): the variables to
/// set, the names to remove, and whether stdin was read (`-`). The same
/// variable cannot be both modified and removed.
pub fn parse_env(
    spec: &[String],
    mut default_reader: Option<&mut dyn std::io::Read>,
) -> Result<(Vec<Value>, Vec<String>, bool)> {
    const TYPE: &str = "environment variable";
    let mut env = Vec::new();
    let mut exists = std::collections::HashSet::new();
    let mut remove: Vec<String> = Vec::new();
    let mut used_stdin = false;
    for env_spec in spec {
        if env_spec == "-" {
            let Some(r) = default_reader.as_deref_mut() else {
                anyhow::bail!("when '-' is used, STDIN must be open");
            };
            env.extend(read_env(r)?);
            used_stdin = true;
        } else if let Some((k, v)) = env_spec.split_once('=') {
            let errs = kubernetes_rs_common::validation::metav1::is_env_var_name(k);
            if !errs.is_empty() {
                anyhow::bail!("{k:?} is not a valid key name: {}", errs.join(";"));
            }
            exists.insert(k.to_string());
            env.push(env_var(k, v));
        } else if let Some(key) = env_spec.strip_suffix('-') {
            remove.push(key.to_string());
        } else {
            anyhow::bail!("unknown {TYPE}: {env_spec}");
        }
    }
    if remove.iter().any(|r| exists.contains(r)) {
        anyhow::bail!("can not both modify and remove the same {TYPE} in the same command");
    }
    Ok((env, remove, used_stdin))
}

fn env_name(e: &Value) -> &str {
    e.get("name").and_then(|n| n.as_str()).unwrap_or("")
}

/// `findEnv` (cmd/set/helper.go:125).
pub fn find_env<'a>(env: &'a [Value], name: &str) -> Option<&'a Value> {
    env.iter().find(|e| env_name(e) == name)
}

/// `updateEnv` (helper.go:140): adds and deletes environment variables. An
/// added variable replaces every existing one of the same name; removing a
/// variable removes every existing one of that name; unrelated duplicates are
/// left intact; a removal wins over an addition.
pub fn update_env(existing: &[Value], env: &[Value], remove: &[String]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut covered: std::collections::HashSet<String> = remove.iter().cloned().collect();
    for e in existing {
        if covered.contains(env_name(e)) {
            continue;
        }
        if let Some(newer) = find_env(env, env_name(e)) {
            covered.insert(env_name(e).to_string());
            out.push(newer.clone());
            continue;
        }
        out.push(e.clone());
    }
    for e in env {
        if covered.contains(env_name(e)) {
            continue;
        }
        covered.insert(env_name(e).to_string());
        out.push(e.clone());
    }
    out
}

/// `validateNoOverwrites` (set_env.go:186): without `--overwrite`, a variable
/// that already has a different value is an error.
pub fn validate_no_overwrites(existing: &[Value], env: &[Value]) -> Result<()> {
    for e in env {
        if let Some(current) = find_env(existing, env_name(e)) {
            let (cv, ev) = (current.get("value"), e.get("value"));
            if cv.and_then(|v| v.as_str()).unwrap_or("")
                != ev.and_then(|v| v.as_str()).unwrap_or("")
            {
                anyhow::bail!(
                    "'{}' already has a value ({}), and --overwrite is false",
                    env_name(current),
                    cv.and_then(|v| v.as_str()).unwrap_or("")
                );
            }
        }
    }
    Ok(())
}

/// `contains` (set_env.go:195): an empty key list contains every key.
pub fn env_keys_contain(key: &str, key_list: &[String]) -> bool {
    key_list.is_empty() || key_list.iter().any(|k| k == key)
}

/// `keyToEnvName` (set_env.go:208): upper-cased with every character outside
/// `[a-zA-Z0-9_]` replaced by `_`. The caller prints the
/// `key %s transferred to %s` warning when the result differs.
pub fn key_to_env_name(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .to_uppercase()
}

/// `selectString` (cmd/set/helper.go:46): `spec` is a string with a non-greedy
/// `*` wildcard. Ported with its quirks (relative `pos`, `next < pos`).
pub fn select_string(s: &str, spec: &str) -> bool {
    if spec == "*" {
        return true;
    }
    if !spec.contains('*') {
        return s == spec;
    }
    let mut pos: i64 = 0;
    let parts: Vec<&str> = spec.split('*').collect();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let tail = s.get(pos as usize..).unwrap_or("");
        let next: i64 = tail.find(part).map_or(-1, |n| n as i64);
        if next < pos
            || (i == 0 && pos != 0)
            || (i == parts.len() - 1 && s.len() as i64 != part.len() as i64 + next)
        {
            return false;
        }
        pos = next;
    }
    true
}

/// Update resource requests/limits on a resource.
///
/// Usage: `kubectl set resources deployment nginx --limits=cpu=200m,memory=512Mi`
pub async fn execute_resources(
    client: &ApiClient,
    resource: &str,
    namespace: &str,
    container_name: Option<&str>,
    limits: Option<&str>,
    requests: Option<&str>,
) -> Result<()> {
    let (resource_type, name) = parse_resource_arg(resource)?;
    let (path, mapping) = resolve_resource(client, &resource_type, &name, namespace).await?;

    // Get current resource
    let current: Value = client
        .get(&path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))
        .context("Failed to get resource")?;

    let containers = if current
        .get("spec")
        .and_then(|s| s.get("template"))
        .is_some()
    {
        current["spec"]["template"]["spec"]["containers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    } else {
        current["spec"]["containers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    };

    // Parse limits and requests
    let limits_map = parse_resource_spec(limits)?;
    let requests_map = parse_resource_spec(requests)?;

    // Build updated containers
    let mut updated_containers: Vec<Value> = Vec::new();

    for c in &containers {
        let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("");

        if let Some(target) = container_name {
            if cname != target {
                continue;
            }
        }

        let mut resources = json!({});

        if !limits_map.is_empty() {
            resources["limits"] = json!(limits_map);
        }
        if !requests_map.is_empty() {
            resources["requests"] = json!(requests_map);
        }

        updated_containers.push(json!({
            "name": cname,
            "resources": resources,
        }));
    }

    let patch_body = if current
        .get("spec")
        .and_then(|s| s.get("template"))
        .is_some()
    {
        json!({
            "spec": {
                "template": {
                    "spec": {
                        "containers": updated_containers,
                    }
                }
            }
        })
    } else {
        json!({
            "spec": {
                "containers": updated_containers,
            }
        })
    };

    let _result: Value = client
        .patch(&path, &patch_body, "application/strategic-merge-patch+json")
        .await
        .context("Failed to update resource requirements")?;

    println!(
        "{} resource requirements updated",
        crate::ops::resource_label(&mapping, &name)
    );

    Ok(())
}

/// Set the selector on a resource (e.g., a Service).
///
/// Usage: `kubectl set selector service/myapp app=myapp`
pub async fn execute_selector(
    client: &ApiClient,
    resource: &str,
    expressions: &[String],
    namespace: &str,
) -> Result<()> {
    let (resource_type, name) = parse_resource_arg(resource)?;

    // Build selector map from key=value expressions
    let mut selector = serde_json::Map::new();
    for expr in expressions {
        if let Some((key, value)) = expr.split_once('=') {
            selector.insert(key.to_string(), json!(value));
        } else {
            anyhow::bail!(
                "Invalid selector expression: '{}'. Expected key=value",
                expr
            );
        }
    }

    if selector.is_empty() {
        anyhow::bail!("At least one selector expression (key=value) is required");
    }

    // Resolve the API path via server discovery (handles services and any
    // other selector-bearing kind).
    let (path, mapping) = resolve_resource(client, &resource_type, &name, namespace).await?;

    let patch_body = json!({
        "spec": {
            "selector": selector,
        }
    });

    let _result: Value = client
        .patch(&path, &patch_body, "application/strategic-merge-patch+json")
        .await
        .context("Failed to update selector")?;

    println!(
        "{} selector updated",
        crate::ops::resource_label(&mapping, &name)
    );

    Ok(())
}

/// Set serviceAccountName on pod templates in a resource.
///
/// Usage: `kubectl set serviceaccount deployment/nginx my-service-account`
pub async fn execute_serviceaccount(
    client: &ApiClient,
    resource: &str,
    service_account_name: &str,
    namespace: &str,
) -> Result<()> {
    let (resource_type, name) = parse_resource_arg(resource)?;
    let (path, mapping) = resolve_resource(client, &resource_type, &name, namespace).await?;

    // Get current resource to determine if it has a template
    let current: Value = client
        .get(&path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))
        .context("Failed to get resource")?;

    let patch_body = if current
        .get("spec")
        .and_then(|s| s.get("template"))
        .is_some()
    {
        json!({
            "spec": {
                "template": {
                    "spec": {
                        "serviceAccountName": service_account_name,
                    }
                }
            }
        })
    } else {
        json!({
            "spec": {
                "serviceAccountName": service_account_name,
            }
        })
    };

    let _result: Value = client
        .patch(&path, &patch_body, "application/strategic-merge-patch+json")
        .await
        .context("Failed to update serviceAccountName")?;

    println!(
        "{} serviceaccount updated to {}",
        crate::ops::resource_label(&mapping, &name),
        service_account_name
    );

    Ok(())
}

/// Update subjects in a RoleBinding or ClusterRoleBinding.
///
/// Usage: `kubectl set subject clusterrolebinding/admin --user=admin --group=devs`
pub async fn execute_subject(
    client: &ApiClient,
    resource: &str,
    namespace: &str,
    serviceaccount: Option<&str>,
    user: Option<&str>,
    group: Option<&str>,
) -> Result<()> {
    let (resource_type, name) = parse_resource_arg(resource)?;

    // set subject only operates on (Cluster)RoleBindings. Resolve the type via
    // the shared discovery resolver, then guard on the resolved Kind so the
    // path is built by the shared RestMapper rather than a hardcoded
    // group/version literal.
    let (path, mapping) = resolve_resource(client, &resource_type, &name, namespace).await?;
    // Guard runs after discovery (we need the resolved Kind); a wrong kind costs one discovery round-trip before rejection.
    if mapping.kind != "RoleBinding" && mapping.kind != "ClusterRoleBinding" {
        anyhow::bail!(
            "set subject only supports rolebinding and clusterrolebinding, got: {}",
            resource_type
        );
    }

    // Get current binding
    let mut current: Value = client
        .get(&path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))
        .context("Failed to get resource")?;

    let subjects = current
        .get_mut("subjects")
        .and_then(|s| s.as_array_mut())
        .map(|a| a.clone())
        .unwrap_or_default();

    let mut new_subjects = subjects;

    if let Some(sa) = serviceaccount {
        let (sa_namespace, sa_name) = if let Some((ns, n)) = sa.split_once(':') {
            (ns.to_string(), n.to_string())
        } else {
            (namespace.to_string(), sa.to_string())
        };
        // Check if subject already exists
        let exists = new_subjects.iter().any(|s| {
            s.get("kind").and_then(|k| k.as_str()) == Some("ServiceAccount")
                && s.get("name").and_then(|n| n.as_str()) == Some(&sa_name)
                && s.get("namespace").and_then(|n| n.as_str()) == Some(&sa_namespace)
        });
        if !exists {
            new_subjects.push(json!({
                "kind": "ServiceAccount",
                "name": sa_name,
                "namespace": sa_namespace,
            }));
        }
    }

    if let Some(u) = user {
        let exists = new_subjects.iter().any(|s| {
            s.get("kind").and_then(|k| k.as_str()) == Some("User")
                && s.get("name").and_then(|n| n.as_str()) == Some(u)
        });
        if !exists {
            new_subjects.push(json!({
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "User",
                "name": u,
            }));
        }
    }

    if let Some(g) = group {
        let exists = new_subjects.iter().any(|s| {
            s.get("kind").and_then(|k| k.as_str()) == Some("Group")
                && s.get("name").and_then(|n| n.as_str()) == Some(g)
        });
        if !exists {
            new_subjects.push(json!({
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Group",
                "name": g,
            }));
        }
    }

    let patch_body = json!({
        "subjects": new_subjects,
    });

    let _result: Value = client
        .patch(&path, &patch_body, "application/strategic-merge-patch+json")
        .await
        .context("Failed to update subjects")?;

    println!(
        "{} subjects updated",
        crate::ops::resource_label(&mapping, &name)
    );

    Ok(())
}

/// Parse a resource spec string like "cpu=200m,memory=512Mi" into a map.
pub fn parse_resource_spec(
    spec: Option<&str>,
) -> Result<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    if let Some(s) = spec {
        for pair in s.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some((key, value)) = pair.split_once('=') {
                map.insert(key.to_string(), value.to_string());
            } else {
                anyhow::bail!("Invalid resource spec: '{}'. Expected key=value", pair);
            }
        }
    }
    Ok(map)
}
