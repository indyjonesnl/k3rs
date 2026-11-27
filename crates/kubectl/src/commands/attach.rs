//! `kubectl attach` (release-1.35 `staging/src/k8s.io/kubectl/pkg/cmd/attach/attach.go`
//! `AttachOptions.Run`): `POD | TYPE/NAME` target resolved like `exec`
//! (`commands::exec::resolve_pod`), completed-pod check, container
//! defaulting, `-q` and `--pod-running-timeout`.

use crate::commands::exec::{check_pod_running, find_or_default_container, resolve_pod, Target};
use crate::websocket;
use anyhow::Result;
use kubernetes_rs_client::http::ApiClient;
use serde_json::Value;

/// `defaultPodAttachTimeout`.
pub const DEFAULT_POD_ATTACH_TIMEOUT: &str = "1m0s";

/// Attach to a running container in a pod.
///
/// This is similar to exec but attaches to the main process (PID 1)
/// of the container rather than running a new command.
pub async fn execute(
    client: &ApiClient,
    target: &Target<'_>,
    container: Option<&str>,
    tty: bool,
    stdin: bool,
    quiet: bool,
) -> Result<()> {
    let pod = resolve_pod(client, target, "attach").await?;
    check_pod_running(&pod, "attach")?;
    let container_name =
        find_or_default_container(&pod, container.unwrap_or(""), quiet, &mut std::io::stderr())?;
    let pod_name = pod
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let pod_ns = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or(target.namespace);

    // Build the attach URL path
    let mut url_path = format!("/api/v1/namespaces/{pod_ns}/pods/{pod_name}/attach");
    let mut query_params = vec![format!("container={container_name}")];
    query_params.push("stdout=true".to_string());
    query_params.push("stderr=true".to_string());
    if stdin {
        query_params.push("stdin=true".to_string());
    }
    if tty {
        query_params.push("tty=true".to_string());
    }
    url_path.push('?');
    url_path.push_str(&query_params.join("&"));

    // Convert HTTP(S) URL to WebSocket URL
    let ws_url = client.get_ws_url(&url_path)?;

    // Execute with WebSocket streaming (same mechanism as exec)
    websocket::exec_stream(ws_url, stdin, tty).await
}
