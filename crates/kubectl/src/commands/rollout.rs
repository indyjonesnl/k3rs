use crate::types::RolloutCommands;
use anyhow::{Context, Result};
use kubernetes_rs_client::http::ApiClient;
use serde_json::{json, Value};

/// Execute rollout commands
pub async fn execute(
    client: &ApiClient,
    command: RolloutCommands,
    default_namespace: &str,
) -> Result<()> {
    match command {
        RolloutCommands::Status {
            args,
            namespace,
            filename,
            watch,
            revision,
            timeout,
            selector,
        } => {
            let ns = namespace.as_deref().unwrap_or(default_namespace);
            let opts = RolloutStatusOptions {
                watch,
                revision,
                timeout: Some(super::exec::parse_go_duration(&timeout)?),
            };
            rollout_status_run(client, &args, &filename, selector.as_deref(), ns, &opts).await?;
        }
        RolloutCommands::History {
            resource_type,
            name,
            namespace,
            revision,
        } => {
            let ns = namespace.as_deref().unwrap_or(default_namespace);
            rollout_history(client, &resource_type, &name, ns, revision).await?;
        }
        RolloutCommands::Undo {
            resource_type,
            name,
            namespace,
            to_revision,
        } => {
            let ns = namespace.as_deref().unwrap_or(default_namespace);
            rollout_undo(client, &resource_type, &name, ns, to_revision).await?;
        }
        RolloutCommands::Restart {
            resource_type,
            name,
            namespace,
        } => {
            let ns = namespace.as_deref().unwrap_or(default_namespace);
            rollout_restart(client, &resource_type, &name, ns).await?;
        }
        RolloutCommands::Pause {
            resource_type,
            name,
            namespace,
        } => {
            let ns = namespace.as_deref().unwrap_or(default_namespace);
            rollout_pause(client, &resource_type, &name, ns).await?;
        }
        RolloutCommands::Resume {
            resource_type,
            name,
            namespace,
        } => {
            let ns = namespace.as_deref().unwrap_or(default_namespace);
            rollout_resume(client, &resource_type, &name, ns).await?;
        }
    }

    Ok(())
}

/// Options of `kubectl rollout status` (rollout_status.go `RolloutStatusOptions`).
#[derive(Debug, Clone)]
pub struct RolloutStatusOptions {
    /// `--watch` (default true): keep watching until the rollout is done.
    pub watch: bool,
    /// `--revision`: pin to a revision (0 = latest).
    pub revision: i64,
    /// `--timeout`: give up watching after this long (None = forever).
    pub timeout: Option<std::time::Duration>,
}

impl Default for RolloutStatusOptions {
    fn default() -> Self {
        Self {
            watch: true,
            revision: 0,
            timeout: None,
        }
    }
}

fn i64_at(v: &Value, path: &[&str]) -> i64 {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(n) => cur = n,
            None => return 0,
        }
    }
    cur.as_i64().unwrap_or(0)
}

fn opt_i64_at(v: &Value, path: &[&str]) -> Option<i64> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_i64()
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(n) => cur = n,
            None => return "",
        }
    }
    cur.as_str().unwrap_or("")
}

/// `StatusViewerFor` + `StatusViewer.Status`
/// (`staging/src/k8s.io/kubectl/pkg/polymorphichelpers/rollout_status.go`,
/// release-1.35): returns the message, whether the rollout is done, or the
/// error. `Err((msg, done))` mirrors the DaemonSet/StatefulSet strategy error
/// that is returned together with `done=true`.
pub fn rollout_status_message(
    kind: &str,
    obj: &Value,
    revision: i64,
) -> std::result::Result<(String, bool), String> {
    match kind {
        "Deployment" => deployment_status(obj, revision),
        "DaemonSet" => daemon_set_status(obj),
        "StatefulSet" => stateful_set_status(obj),
        other => Err(format!("no status viewer has been implemented for {other}")),
    }
}

/// `DeploymentStatusViewer.Status`.
fn deployment_status(obj: &Value, revision: i64) -> std::result::Result<(String, bool), String> {
    let name = str_at(obj, &["metadata", "name"]);
    if revision > 0 {
        // deploymentutil.Revision: absent annotation is 0, else ParseInt.
        let deployment_rev = match obj
            .get("metadata")
            .and_then(|m| m.get("annotations"))
            .and_then(|a| a.get("deployment.kubernetes.io/revision"))
            .and_then(|v| v.as_str())
        {
            None => 0,
            Some(v) => v
                .parse::<i64>()
                .map_err(|e| format!("cannot get the revision of deployment \"{name}\": {e}"))?,
        };
        if revision != deployment_rev {
            return Err(format!(
                "desired revision ({revision}) is different from the running revision ({deployment_rev})"
            ));
        }
    }
    if i64_at(obj, &["metadata", "generation"]) <= i64_at(obj, &["status", "observedGeneration"]) {
        // GetDeploymentCondition(Progressing) / TimedOutReason
        let timed_out = obj
            .get("status")
            .and_then(|s| s.get("conditions"))
            .and_then(|c| c.as_array())
            .and_then(|cs| {
                cs.iter()
                    .find(|c| c.get("type").and_then(|t| t.as_str()) == Some("Progressing"))
            })
            .map(|c| c.get("reason").and_then(|r| r.as_str()) == Some("ProgressDeadlineExceeded"))
            .unwrap_or(false);
        if timed_out {
            return Err(format!(
                "deployment \"{name}\" exceeded its progress deadline"
            ));
        }
        let updated = i64_at(obj, &["status", "updatedReplicas"]);
        let replicas = i64_at(obj, &["status", "replicas"]);
        let available = i64_at(obj, &["status", "availableReplicas"]);
        if let Some(spec_replicas) = opt_i64_at(obj, &["spec", "replicas"]) {
            if updated < spec_replicas {
                return Ok((
                    format!("Waiting for deployment \"{name}\" rollout to finish: {updated} out of {spec_replicas} new replicas have been updated...\n"),
                    false,
                ));
            }
        }
        if replicas > updated {
            return Ok((
                format!("Waiting for deployment \"{name}\" rollout to finish: {} old replicas are pending termination...\n", replicas - updated),
                false,
            ));
        }
        if available < updated {
            return Ok((
                format!("Waiting for deployment \"{name}\" rollout to finish: {available} of {updated} updated replicas are available...\n"),
                false,
            ));
        }
        return Ok((
            format!("deployment \"{name}\" successfully rolled out\n"),
            true,
        ));
    }
    Ok((
        "Waiting for deployment spec update to be observed...\n".into(),
        false,
    ))
}

/// `DaemonSetStatusViewer.Status`. The upstream strategy error message names
/// `RollingUpdateStatefulSetStrategyType` (also "RollingUpdate").
fn daemon_set_status(obj: &Value) -> std::result::Result<(String, bool), String> {
    let name = str_at(obj, &["metadata", "name"]);
    // appsv1 defaults an empty type to RollingUpdate on the server side; an
    // object without the field is only produced by a defaulting-less caller.
    let strategy = str_at(obj, &["spec", "updateStrategy", "type"]);
    if strategy != "RollingUpdate" {
        return Err("rollout status is only available for RollingUpdate strategy type".into());
    }
    if i64_at(obj, &["metadata", "generation"]) <= i64_at(obj, &["status", "observedGeneration"]) {
        let updated = i64_at(obj, &["status", "updatedNumberScheduled"]);
        let desired = i64_at(obj, &["status", "desiredNumberScheduled"]);
        let available = i64_at(obj, &["status", "numberAvailable"]);
        if updated < desired {
            return Ok((
                format!("Waiting for daemon set \"{name}\" rollout to finish: {updated} out of {desired} new pods have been updated...\n"),
                false,
            ));
        }
        if available < desired {
            return Ok((
                format!("Waiting for daemon set \"{name}\" rollout to finish: {available} of {desired} updated pods are available...\n"),
                false,
            ));
        }
        return Ok((
            format!("daemon set \"{name}\" successfully rolled out\n"),
            true,
        ));
    }
    Ok((
        "Waiting for daemon set spec update to be observed...\n".into(),
        false,
    ))
}

/// `StatefulSetStatusViewer.Status`.
fn stateful_set_status(obj: &Value) -> std::result::Result<(String, bool), String> {
    if str_at(obj, &["spec", "updateStrategy", "type"]) != "RollingUpdate" {
        return Err("rollout status is only available for RollingUpdate strategy type".into());
    }
    let observed = i64_at(obj, &["status", "observedGeneration"]);
    if observed == 0 || i64_at(obj, &["metadata", "generation"]) > observed {
        return Ok((
            "Waiting for statefulset spec update to be observed...\n".into(),
            false,
        ));
    }
    let replicas = opt_i64_at(obj, &["spec", "replicas"]);
    let ready = i64_at(obj, &["status", "readyReplicas"]);
    let updated = i64_at(obj, &["status", "updatedReplicas"]);
    if let Some(r) = replicas {
        if ready < r {
            return Ok((
                format!("Waiting for {} pods to be ready...\n", r - ready),
                false,
            ));
        }
    }
    // The strategy type is RollingUpdate here, so upstream's
    // `RollingUpdate != nil` branch decides.
    if obj
        .get("spec")
        .and_then(|s| s.get("updateStrategy"))
        .and_then(|u| u.get("rollingUpdate"))
        .is_some_and(|v| !v.is_null())
    {
        if let (Some(r), Some(partition)) = (
            replicas,
            opt_i64_at(
                obj,
                &["spec", "updateStrategy", "rollingUpdate", "partition"],
            ),
        ) {
            if updated < r - partition {
                return Ok((
                    format!("Waiting for partitioned roll out to finish: {updated} out of {} new pods have been updated...\n", r - partition),
                    false,
                ));
            }
        }
        return Ok((
            format!("partitioned roll out complete: {updated} new pods have been updated...\n"),
            true,
        ));
    }
    let update_rev = str_at(obj, &["status", "updateRevision"]);
    let current_rev = str_at(obj, &["status", "currentRevision"]);
    if update_rev != current_rev {
        return Ok((
            format!("waiting for statefulset rolling update to complete {updated} pods at revision {update_rev}...\n"),
            false,
        ));
    }
    Ok((
        format!(
            "statefulset rolling update complete {} pods at revision {current_rev}...\n",
            i64_at(obj, &["status", "currentReplicas"])
        ),
        true,
    ))
}

fn rollout_kind(resource_type: &str) -> &'static str {
    match resource_type {
        "deployment" | "deployments" | "deploy" => "Deployment",
        "statefulset" | "statefulsets" | "sts" => "StatefulSet",
        _ => "DaemonSet",
    }
}

/// `RolloutStatusOptions.Validate` (rollout_status.go:147).
pub fn validate_status_args(args: &[String], filenames: &[String], revision: i64) -> Result<()> {
    if args.is_empty() && filenames.is_empty() {
        anyhow::bail!("required resource not specified");
    }
    if revision < 0 {
        anyhow::bail!("revision must be a positive integer: {revision}");
    }
    Ok(())
}

/// `ResourceTypeOrNameArgs(true, args...)`: `TYPE NAME`, `TYPE/NAME` and
/// `TYPE` (every object of the type, narrowed by `-l`) as (type, name?).
pub fn split_status_args(args: &[String]) -> Result<Vec<(String, Option<String>)>> {
    match args {
        [] => Ok(vec![]),
        [one] => Ok(match one.split_once('/') {
            Some((t, n)) => vec![(t.to_string(), Some(n.to_string()))],
            None => vec![(one.clone(), None)],
        }),
        [t, rest @ ..] if !t.contains('/') => {
            Ok(rest.iter().map(|n| (t.clone(), Some(n.clone()))).collect())
        }
        _ => args
            .iter()
            .map(|a| match a.split_once('/') {
                Some((t, n)) => Ok((t.to_string(), Some(n.to_string()))),
                None => anyhow::bail!(
                    "there is no need to specify a resource type as a separate argument when passing arguments in resource/name form (e.g. 'kubectl get resource/<resource_name>' instead of 'kubectl get resource resource/<resource_name>'"
                ),
            })
            .collect(),
    }
}

/// `RolloutStatusOptions.Run` over every resource the builder yields
/// (rollout_status.go:160-200): named args, `-l` listing, and `-f` files.
pub async fn rollout_status_run(
    client: &ApiClient,
    args: &[String],
    filenames: &[String],
    selector: Option<&str>,
    namespace: &str,
    opts: &RolloutStatusOptions,
) -> Result<()> {
    validate_status_args(args, filenames, opts.revision)?;
    // (resource type, name, namespace)
    let mut targets: Vec<(String, String, String)> = Vec::new();
    for (t, n) in split_status_args(args)? {
        match n {
            Some(n) => targets.push((t, n, namespace.to_string())),
            None => {
                let (probe, _) = get_resource_api_path(&t, namespace, "x")?;
                let coll = probe.rsplit_once('/').map(|(c, _)| c).unwrap_or_default();
                let q = crate::ops::label_selector_query(selector);
                let list: Value = client
                    .get(&format!("{coll}{q}"))
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to list {t}: {e}"))?;
                for item in list
                    .get("items")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    targets.push((
                        t.clone(),
                        str_at(item, &["metadata", "name"]).to_string(),
                        namespace.to_string(),
                    ));
                }
            }
        }
    }
    for f in filenames {
        for doc in crate::manifest::read_documents(f)? {
            let doc: Value = serde_json::to_value(doc)?;
            let kind = str_at(&doc, &["kind"]).to_string();
            let ns = match str_at(&doc, &["metadata", "namespace"]) {
                "" => namespace,
                n => n,
            };
            targets.push((
                kind.to_lowercase(),
                str_at(&doc, &["metadata", "name"]).to_string(),
                ns.to_string(),
            ));
        }
    }
    if targets.is_empty() {
        eprintln!("No resources found in {namespace} namespace.");
        return Ok(());
    }
    for (t, n, ns) in targets {
        rollout_status_with(client, &t, &n, &ns, opts).await?;
    }
    Ok(())
}

pub async fn rollout_status(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: &str,
) -> Result<()> {
    rollout_status_with(
        client,
        resource_type,
        name,
        namespace,
        &RolloutStatusOptions::default(),
    )
    .await
}

/// `RolloutStatusOptions.Run` (cmd/rollout/rollout_status.go:160): list+watch
/// the object by `metadata.name` (`UntilWithSync`), print each status message
/// and stop when done, when `--watch=false`, on delete (an error) or timeout.
pub async fn rollout_status_with(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: &str,
    opts: &RolloutStatusOptions,
) -> Result<()> {
    use futures::StreamExt;
    use kubernetes_rs_client::watch::{watch_stream, WatchEvent};

    if opts.revision < 0 {
        anyhow::bail!("revision must be a positive integer: {}", opts.revision);
    }
    let kind = rollout_kind(resource_type);
    let (obj_path, _) = get_resource_api_path(resource_type, namespace, name)?;
    let coll_path = obj_path
        .rsplit_once('/')
        .map(|(c, _)| c.to_string())
        .unwrap_or_default();
    let selector = format!("?fieldSelector=metadata.name%3D{name}");

    let run = async {
        // The reflector's initial list; each item arrives as an Added event.
        let list: Value = client
            .get(&format!("{coll_path}{selector}"))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get {resource_type} {name}: {e}"))?;
        let mut rv = str_at(&list, &["metadata", "resourceVersion"]).to_string();
        let handle = |obj: &Value| -> Result<bool> {
            let (msg, done) =
                rollout_status_message(kind, obj, opts.revision).map_err(anyhow::Error::msg)?;
            print!("{msg}");
            Ok(done || !opts.watch)
        };
        for item in list
            .get("items")
            .and_then(|i| i.as_array())
            .into_iter()
            .flatten()
        {
            if handle(item)? {
                return Ok(());
            }
        }
        loop {
            let mut stream = std::pin::pin!(
                watch_stream::<Value>(
                    client,
                    &format!("{coll_path}{selector}"),
                    (!rv.is_empty()).then_some(rv.as_str())
                )
                .await?
            );
            while let Some(ev) = stream.next().await {
                match ev? {
                    WatchEvent::Added(o) | WatchEvent::Modified(o) => {
                        let v = str_at(&o, &["metadata", "resourceVersion"]);
                        if !v.is_empty() {
                            rv = v.to_string();
                        }
                        if handle(&o)? {
                            return Ok(());
                        }
                    }
                    WatchEvent::Bookmark(o) => {
                        let v = str_at(&o, &["metadata", "resourceVersion"]);
                        if !v.is_empty() {
                            rv = v.to_string();
                        }
                    }
                    WatchEvent::Deleted(_) => anyhow::bail!("object has been deleted"),
                }
            }
            // server closed the watch: re-watch from the last seen version
        }
    };
    match opts.timeout {
        Some(t) if !t.is_zero() => tokio::time::timeout(t, run)
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for the condition"))?,
        _ => run.await,
    }
}

pub async fn rollout_history(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: &str,
    revision: Option<i32>,
) -> Result<()> {
    let (_api_base, _) = get_resource_api_path(resource_type, namespace, name)?;
    let rs_path = format!("/apis/apps/v1/namespaces/{}/replicasets", namespace);

    let replicasets: Value = client
        .get(&rs_path)
        .await
        .context("Failed to get replicasets")?;

    if let Some(items) = replicasets.get("items").and_then(|v| v.as_array()) {
        let mut history: Vec<_> = items
            .iter()
            .filter(|rs| {
                rs.get("metadata")
                    .and_then(|m| m.get("ownerReferences"))
                    .and_then(|o| o.as_array())
                    .map(|refs| {
                        refs.iter()
                            .any(|r| r.get("name").and_then(|n| n.as_str()) == Some(name))
                    })
                    .unwrap_or(false)
            })
            .collect();

        history.sort_by_key(|rs| {
            rs.get("metadata")
                .and_then(|m| m.get("annotations"))
                .and_then(|a| a.get("deployment.kubernetes.io/revision"))
                .and_then(|r| r.as_str())
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0)
        });

        if let Some(rev) = revision {
            // Show specific revision
            if let Some(rs) = history.iter().find(|rs| {
                rs.get("metadata")
                    .and_then(|m| m.get("annotations"))
                    .and_then(|a| a.get("deployment.kubernetes.io/revision"))
                    .and_then(|r| r.as_str())
                    .and_then(|s| s.parse::<i32>().ok())
                    == Some(rev)
            }) {
                println!("Revision {}:", rev);
                if let Some(spec) = rs.get("spec") {
                    println!("{}", serde_json::to_string_pretty(spec)?);
                }
            } else {
                anyhow::bail!("Revision {} not found", rev);
            }
        } else {
            // Show all revisions
            println!("{:<10} {:<30}", "REVISION", "CHANGE-CAUSE");
            for rs in history {
                let rev = rs
                    .get("metadata")
                    .and_then(|m| m.get("annotations"))
                    .and_then(|a| a.get("deployment.kubernetes.io/revision"))
                    .and_then(|r| r.as_str())
                    .unwrap_or("0");
                let cause = rs
                    .get("metadata")
                    .and_then(|m| m.get("annotations"))
                    .and_then(|a| a.get("kubernetes.io/change-cause"))
                    .and_then(|c| c.as_str())
                    .unwrap_or("<none>");
                println!("{:<10} {:<30}", rev, cause);
            }
        }
    }

    Ok(())
}

pub async fn rollout_undo(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: &str,
    to_revision: Option<i32>,
) -> Result<()> {
    let (api_path, _) = get_resource_api_path(resource_type, namespace, name)?;

    if resource_type != "deployment" {
        anyhow::bail!("Rollout undo is only supported for deployments");
    }

    // Get the deployment
    let _deployment: Value = client
        .get(&api_path)
        .await
        .context("Failed to get deployment")?;

    // Get replicasets to find the target revision
    let rs_path = format!("/apis/apps/v1/namespaces/{}/replicasets", namespace);
    let replicasets: Value = client
        .get(&rs_path)
        .await
        .context("Failed to get replicasets")?;

    if let Some(items) = replicasets.get("items").and_then(|v| v.as_array()) {
        let mut history: Vec<_> = items
            .iter()
            .filter(|rs| {
                rs.get("metadata")
                    .and_then(|m| m.get("ownerReferences"))
                    .and_then(|o| o.as_array())
                    .map(|refs| {
                        refs.iter()
                            .any(|r| r.get("name").and_then(|n| n.as_str()) == Some(name))
                    })
                    .unwrap_or(false)
            })
            .collect();

        history.sort_by_key(|rs| {
            rs.get("metadata")
                .and_then(|m| m.get("annotations"))
                .and_then(|a| a.get("deployment.kubernetes.io/revision"))
                .and_then(|r| r.as_str())
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0)
        });

        let target_rs = if let Some(rev) = to_revision {
            history.iter().find(|rs| {
                rs.get("metadata")
                    .and_then(|m| m.get("annotations"))
                    .and_then(|a| a.get("deployment.kubernetes.io/revision"))
                    .and_then(|r| r.as_str())
                    .and_then(|s| s.parse::<i32>().ok())
                    == Some(rev)
            })
        } else {
            // Get previous revision (second to last)
            history.iter().rev().nth(1)
        };

        if let Some(rs) = target_rs {
            // Update deployment with the template from the target replicaset
            if let Some(template) = rs.get("spec").and_then(|s| s.get("template")) {
                let patch = json!({
                    "spec": {
                        "template": template
                    }
                });

                let _: Value = client
                    .patch(&api_path, &patch, "application/merge-patch+json")
                    .await
                    .context("Failed to rollback deployment")?;

                let target_rev = rs
                    .get("metadata")
                    .and_then(|m| m.get("annotations"))
                    .and_then(|a| a.get("deployment.kubernetes.io/revision"))
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown");

                println!(
                    "deployment.apps/{} rolled back to revision {}",
                    name, target_rev
                );
            } else {
                anyhow::bail!("Target replicaset has no template");
            }
        } else {
            anyhow::bail!("Target revision not found");
        }
    }

    Ok(())
}

pub async fn rollout_restart(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: &str,
) -> Result<()> {
    let (api_path, _) = get_resource_api_path(resource_type, namespace, name)?;

    // Trigger a restart by updating the restart annotation
    let now = chrono::Utc::now().to_rfc3339();
    let patch = json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": now
                    }
                }
            }
        }
    });

    let _: Value = client
        .patch(&api_path, &patch, "application/merge-patch+json")
        .await
        .context("Failed to restart resource")?;

    println!("{} {} restarted", resource_type, name);

    Ok(())
}

pub async fn rollout_pause(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: &str,
) -> Result<()> {
    if resource_type != "deployment" {
        anyhow::bail!("Rollout pause is only supported for deployments");
    }

    let api_path = format!(
        "/apis/apps/v1/namespaces/{}/deployments/{}",
        namespace, name
    );

    let patch = json!({
        "spec": {
            "paused": true
        }
    });

    let _: Value = client
        .patch(&api_path, &patch, "application/merge-patch+json")
        .await
        .context("Failed to pause deployment")?;

    println!("deployment.apps/{} paused", name);

    Ok(())
}

pub async fn rollout_resume(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: &str,
) -> Result<()> {
    if resource_type != "deployment" {
        anyhow::bail!("Rollout resume is only supported for deployments");
    }

    let api_path = format!(
        "/apis/apps/v1/namespaces/{}/deployments/{}",
        namespace, name
    );

    let patch = json!({
        "spec": {
            "paused": false
        }
    });

    let _: Value = client
        .patch(&api_path, &patch, "application/merge-patch+json")
        .await
        .context("Failed to resume deployment")?;

    println!("deployment.apps/{} resumed", name);

    Ok(())
}

pub fn get_resource_api_path(
    resource_type: &str,
    namespace: &str,
    name: &str,
) -> Result<(String, String)> {
    match resource_type {
        "deployment" | "deployments" | "deploy" => Ok((
            format!(
                "/apis/apps/v1/namespaces/{}/deployments/{}",
                namespace, name
            ),
            "apps/v1".to_string(),
        )),
        "statefulset" | "statefulsets" | "sts" => Ok((
            format!(
                "/apis/apps/v1/namespaces/{}/statefulsets/{}",
                namespace, name
            ),
            "apps/v1".to_string(),
        )),
        "daemonset" | "daemonsets" | "ds" => Ok((
            format!("/apis/apps/v1/namespaces/{}/daemonsets/{}", namespace, name),
            "apps/v1".to_string(),
        )),
        _ => anyhow::bail!("Unsupported resource type for rollout: {}", resource_type),
    }
}
