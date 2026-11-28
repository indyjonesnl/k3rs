//! Pod subresource handlers
//!
//! Implements pod subresources required for Kubernetes conformance:
//! - /logs - Get container logs
//! - /exec - Execute commands in containers (proxied to kubelet)
//! - /attach - Attach to running containers (proxied to kubelet)
//! - /portforward - Forward ports to pods (proxied to kubelet)

use crate::{
    handlers::node_conn::{node_conn, NodeConn},
    middleware::AuthContext,
    state::ApiServerState,
    streaming,
};
use axum::{
    body::Body,
    extract::{ws::WebSocketUpgrade, Path, Query, Request, State},
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    Extension,
};
use futures::TryStreamExt as _;
use kubernetes_rs_common::{
    authz::{Decision, RequestAttributes},
    Error, Result,
};
use kubernetes_rs_storage::Storage;
use serde::Deserialize;
use std::sync::Arc;
use tracing::{debug, info};

/// Simple percent-decoding for URL query parameters
fn percent_decode_str(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let hex = [hi, lo];
            if let Ok(s) = std::str::from_utf8(&hex) {
                if let Ok(val) = u8::from_str_radix(s, 16) {
                    result.push(val as char);
                    continue;
                }
            }
            result.push('%');
            result.push(hi as char);
            result.push(lo as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

#[derive(Debug, Deserialize)]
pub struct ExecQuery {
    /// Container in which to execute the command
    pub container: Option<String>,
    /// Command to execute
    pub command: Vec<String>,
    /// Redirect stdin
    #[serde(default)]
    pub stdin: bool,
    /// Redirect stdout
    #[serde(default)]
    pub stdout: bool,
    /// Redirect stderr
    #[serde(default)]
    pub stderr: bool,
    /// Use TTY
    #[serde(default)]
    pub tty: bool,
}

/// Decode the exec/attach query string into [`ExecQuery`].
///
/// Extracted from the handler so the boolean decoding is unit-testable. The
/// stream flags go through `k8s_query_bool` because upstream decodes them with
/// `runtime.Convert_Slice_string_To_bool`
/// (`apimachinery/pkg/runtime/conversion.go:79-95`): only absence, `"0"` and a
/// case-insensitive `"false"` are false, so `?stdin=t`, `?stdin=yes` and even
/// `?stdin=` all mean true. The previous `value == "true" || value == "1"`
/// comparison silently dropped every other spelling, which for `tty` means a
/// client asking for a TTY quietly not getting one.
pub fn parse_exec_query(raw_query: &str) -> ExecQuery {
    let mut command = Vec::new();
    let mut container = None;
    let mut stdin = false;
    let mut stdout = false;
    let mut stderr = false;
    let mut tty = false;
    for pair in raw_query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let value = percent_decode_str(value);
            match key {
                "command" => command.push(value),
                "container" => container = Some(value),
                "stdin" => stdin = kubernetes_rs_common::query::k8s_query_bool(&value),
                "stdout" => stdout = kubernetes_rs_common::query::k8s_query_bool(&value),
                "stderr" => stderr = kubernetes_rs_common::query::k8s_query_bool(&value),
                "tty" => tty = kubernetes_rs_common::query::k8s_query_bool(&value),
                _ => {}
            }
        }
    }
    ExecQuery {
        container,
        command,
        stdin,
        stdout,
        stderr,
        tty,
    }
}

#[derive(Debug, Deserialize)]
pub struct AttachQuery {
    /// Container to attach to
    pub container: Option<String>,
    /// Redirect stdin
    #[serde(default)]
    pub stdin: bool,
    /// Redirect stdout
    #[serde(default)]
    pub stdout: bool,
    /// Redirect stderr
    #[serde(default)]
    pub stderr: bool,
    /// Use TTY
    #[serde(default)]
    pub tty: bool,
}

/// GET /api/v1/namespaces/{namespace}/pods/{name}/log
///
/// Proxies log retrieval to the pod's kubelet using a plain HTTP reverse proxy.
/// Mirrors `pkg/registry/core/pod/rest/log.go` (LogREST) + upstream's
/// `streamLocation` — the kubelet exposes `/containerLogs/{ns}/{pod}/{ctr}?<params>`
/// and handles all follow/tailLines/limitBytes logic server-side.
/// Maximum bytes read from a kubelet error response body — upstream
/// `maxReadLength` (staging/src/k8s.io/apiserver/pkg/registry/generic/rest/response_checker.go:37).
const KUBELET_ERROR_MAX_READ: usize = 50_000;

/// Upstream `GenericHttpResponseChecker.Check`
/// (staging/src/k8s.io/apiserver/pkg/registry/generic/rest/response_checker.go:46-67),
/// installed on `pods/log` by `pkg/registry/core/pod/rest/log.go:111` as
/// `NewGenericHttpResponseChecker(api.Resource("pods/log"), name)`.
///
/// The api-server never streams a kubelet error response through to the
/// client: `LocationStreamer` runs this check before it hands over the body
/// (`generic/rest/streamer.go:100-105`) and converts anything outside
/// `200..=206` into a typed API error, so the client always gets a `Status`.
///
/// We used to proxy the kubelet's response verbatim, which meant a plain-text
/// `400` body. client-go cannot decode that as a `Status`, falls back to
/// `NewGenericServerResponse`, and prints its canned 400 wording — so the
/// kubelet's actual explanation was lost:
///
/// ```text
/// Unable to fetch gc-1009/pod1/nginx logs: the server rejected our request
/// for an unknown reason (get pods pod1)
/// ```
///
/// That cost the e2e framework its container logs on exactly the runs where a
/// spec had failed (#1920).
async fn check_kubelet_log_response(resp: Response, pod_name: &str) -> Response {
    let code = resp.status();
    // Upstream: `resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusPartialContent`.
    if (StatusCode::OK..=StatusCode::PARTIAL_CONTENT).contains(&code) {
        return resp;
    }

    let (_parts, body) = resp.into_parts();
    let text = read_limited(body, KUBELET_ERROR_MAX_READ).await;
    kubelet_error_response(code, text, pod_name)
}

/// The checker's three arms, then `NewGenericServerResponse` for everything
/// else. Shared by both log paths: the plain proxy and the websocket fetch
/// below, which upstream also covers because its websocket reader consumes the
/// very stream `InputStream` returns — after the checker has run.
fn kubelet_error_response(code: StatusCode, text: String, pod_name: &str) -> Response {
    match code {
        StatusCode::BAD_REQUEST => Error::BadRequest(text).into_response(),
        // `errors.NewInternalError(fmt.Errorf("%s", bodyText))`, whose message
        // is `fmt.Sprintf("Internal error occurred: %v", err)`
        // (apimachinery/pkg/api/errors/errors.go:387-397).
        StatusCode::INTERNAL_SERVER_ERROR => {
            Error::Internal(format!("Internal error occurred: {text}")).into_response()
        }
        _ => generic_server_response(code, pod_name),
    }
}

/// `errors.NewGenericServerResponse(code, "", api.Resource("pods/log"), name, bodyText, 0, false)`
/// (apimachinery/pkg/api/errors/errors.go:437-524).
///
/// Note what upstream does **not** do here: with `isUnexpectedResponse: false`
/// the kubelet's `bodyText` is dropped entirely for these codes, and the
/// message is the canned one for the status code with the qualified resource
/// appended. The empty verb is what leaves a double space after the `(` —
/// `fmt.Sprintf("%s (%s %s %s)", message, strings.ToLower(verb), ...)` with
/// `verb == ""`. Reproduced exactly rather than tidied: the wording is what
/// clients match on.
fn generic_server_response(code: StatusCode, pod_name: &str) -> Response {
    let (reason, message) = match code {
        StatusCode::CONFLICT => ("Conflict", "the server reported a conflict".to_string()),
        StatusCode::NOT_FOUND => (
            "NotFound",
            "the server could not find the requested resource".to_string(),
        ),
        StatusCode::UNAUTHORIZED => (
            "Unauthorized",
            "the server has asked for the client to provide credentials".to_string(),
        ),
        StatusCode::FORBIDDEN => ("Forbidden", String::new()),
        StatusCode::METHOD_NOT_ALLOWED => (
            "MethodNotAllowed",
            "the server does not allow this method on the requested resource".to_string(),
        ),
        StatusCode::UNPROCESSABLE_ENTITY => (
            "Invalid",
            "the server rejected our request due to an error in our request".to_string(),
        ),
        StatusCode::SERVICE_UNAVAILABLE => (
            "ServiceUnavailable",
            "the server is currently unable to handle the request".to_string(),
        ),
        StatusCode::GATEWAY_TIMEOUT => (
            "Timeout",
            "the server was unable to return a response in the time allotted, but may still be processing the request".to_string(),
        ),
        StatusCode::TOO_MANY_REQUESTS => (
            "TooManyRequests",
            "the server has received too many requests and has asked us to try again later"
                .to_string(),
        ),
        _ => (
            "Unknown",
            format!(
                "the server responded with the status code {} but did not return more information",
                code.as_u16()
            ),
        ),
    };

    let message = format!("{message} ( pods/log {pod_name})");
    let details = kubernetes_rs_common::types::StatusDetails {
        name: Some(pod_name.to_string()),
        group: None,
        kind: Some("pods/log".to_string()),
        uid: None,
        causes: None,
        retry_after_seconds: None,
    };
    (
        code,
        crate::audit::json_response(kubernetes_rs_common::types::Status::failure_with_details(
            message,
            reason,
            code.as_u16(),
            details,
        )),
    )
        .into_response()
}

/// `io.ReadAll(io.LimitReader(resp.Body, maxReadLength))` — truncate rather
/// than fail, which is what `LimitReader` does. `axum::body::to_bytes` errors
/// out on an oversized body instead, and an error here would replace the
/// kubelet's explanation with a message about the explanation.
async fn read_limited(body: Body, limit: usize) -> String {
    use http_body_util::BodyExt;
    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < limit {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    let take = (limit - buf.len()).min(data.len());
                    buf.extend_from_slice(&data[..take]);
                }
            }
            Some(Err(_)) | None => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

pub async fn get_logs(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((namespace, name)): Path<(String, String)>,
    ws: Option<WebSocketUpgrade>,
    req: Request,
) -> Result<Response> {
    debug!("Getting logs for pod {}/{}", namespace, name);

    // Check authorization
    let attrs = RequestAttributes::new(auth_ctx.user, "get", "pods")
        .with_namespace(&namespace)
        .with_name(&name)
        .with_subresource("log");

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(Error::Forbidden(reason));
        }
    }

    // Determine the container from the query string before consuming `req`.
    let raw_query = req.uri().query().unwrap_or("").to_string();
    let container_name: Option<String> = raw_query.split('&').find_map(|pair| {
        pair.split_once('=')
            .filter(|(k, _)| *k == "container")
            .map(|(_, v)| v.to_string())
    });

    // `LogREST.Get` validates the options before `LogLocation` loads the pod
    // (pkg/registry/core/pod/rest/log.go:99-101).
    validate_log_query(&name, &raw_query)?;

    // Load the pod to verify it exists and resolve container + node.
    let pod_key = kubernetes_rs_storage::build_key("pods", Some(&namespace), &name);
    let pod: kubernetes_rs_common::resources::Pod = state.storage.get(&pod_key).await?;

    // Resolve container name (default to first container).
    let container = if let Some(c) = container_name {
        c
    } else {
        pod.spec
            .as_ref()
            .and_then(|spec| spec.containers.first())
            .map(|c| c.name.clone())
            .ok_or_else(|| Error::InvalidResource("Pod has no containers".to_string()))?
    };

    // Require spec.nodeName — upstream returns 400 when the pod is unscheduled.
    let node_name = pod
        .spec
        .as_ref()
        .and_then(|s| s.node_name.as_deref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::InvalidResource(format!(
                "pod {}/{} has not been assigned to a node",
                namespace, name
            ))
        })?
        .to_string();

    // Resolve kubelet connection parameters from the node.
    let node_key = kubernetes_rs_storage::build_key("nodes", None::<&str>, &node_name);
    let node: kubernetes_rs_common::resources::Node = state.storage.get(&node_key).await?;
    let conn = node_conn(&node, None)?;

    // `LogLocation` picks `InsecureSkipTLSVerifyTransport` for
    // `insecureSkipTLSVerifyBackend=true` (strategy.go:667-670).
    let insecure_backend = insecure_skip_tls_verify_backend(&raw_query);

    // Build the upstream-faithful kubelet containerLogs URL.
    let target_url = build_kubelet_stream_url(
        &conn,
        "containerLogs",
        &namespace,
        &name,
        &container,
        &raw_query,
    );
    info!(
        "Proxying logs {}/{} to kubelet: {}",
        namespace, name, target_url
    );

    // WebSocket path: the e2e conformance client opens a websocket to the /log
    // subresource (subprotocol "binary.k8s.io") and reads the log bytes back as
    // websocket messages. Upstream serves this via
    // `responsewriters.StreamObject` -> `wsstream.NewReader(out, true, ...)`
    // (staging/.../endpoints/handlers/responsewriters/writers.go:65-66): the
    // api-server terminates the websocket and reuses the SAME plain-HTTP kubelet
    // log fetch, framing each chunk per the single-stream wsstream protocol
    // (no channel byte).
    if let Some(ws) = ws {
        // Decide the framing from the negotiated subprotocol BEFORE consuming
        // the request. Mirrors upstream `handshake` (wsstream/conn.go:142):
        // "base64.binary.k8s.io" base64-encodes; everything else is raw binary.
        let requested_protocol = req
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let base64 = streaming::log_protocol_is_base64(requested_protocol.as_deref());

        // Fetch the kubelet log stream over plain HTTP (same target URL the
        // non-upgrade path proxies). We build a fresh GET so the websocket
        // upgrade headers are not forwarded to the kubelet.
        let stream =
            match fetch_kubelet_log_stream(&target_url, &name, kubelet_dialer(), insecure_backend)
                .await?
            {
                Ok(stream) => stream,
                // The kubelet refused: answer the HTTP request with a Status
                // instead of upgrading and framing the error text as log output.
                Err(resp) => return Ok(resp),
            };

        // The 101 returns at once and the stream runs in a detached task:
        // carry the instrumentation hold (`longrunning_requests` gauge and the
        // deferred `MonitorRequest`) across it, as `proxy_upgrade` does.
        let hold = req
            .extensions()
            .get::<kubernetes_rs_streamproxy::ConnectionHold>()
            .cloned();
        return Ok(ws
            .protocols(streaming::LOG_WS_PROTOCOLS)
            .on_upgrade(move |socket| async move {
                let _hold = hold;
                streaming::handle_logs_websocket(socket, stream, base64).await
            })
            .into_response());
    }

    // Plain HTTP proxy (non-upgrade) — handles both follow and non-follow since
    // the kubelet log endpoint is plain HTTP (no WebSocket / SPDY upgrade).
    // A kubelet error is converted to a Status before anything is streamed,
    // exactly as upstream's ResponseChecker does (#1920).
    let proxied = proxy_kubelet_stream(target_url, req, kubelet_dialer(), insecure_backend).await;
    Ok(check_kubelet_log_response(proxied, &name).await)
}

/// Fetch the kubelet `containerLogs` stream over plain HTTP and expose it as a
/// byte stream for pumping over a websocket. Used only by the websocket log
/// path; the non-upgrade path uses `kubernetes_rs_streamproxy::proxy_stream`.
///
/// The kubelet handles all `follow`/`tailLines`/`limitBytes`/`sinceSeconds`
/// query parameters server-side — they are already baked into `target_url`.
type LogByteStream = std::pin::Pin<
    Box<
        dyn futures::Stream<Item = std::result::Result<axum::body::Bytes, std::io::Error>>
            + Send
            + 'static,
    >,
>;

/// `kubelet_client.go:96-104` `makeTransport`: with an egress selector the
/// kubelet client's `DialHolder` is `Lookup(Cluster)` (set from
/// `cmd/kube-apiserver/app/server.go:251`). No selector, or none for
/// `Cluster`, keeps the default dial.
pub fn kubelet_dialer() -> Option<crate::egress_selector::Dialer> {
    crate::egress_selector::egress_selector()
        .and_then(|s| s.lookup(crate::egress_selector::EgressType::Cluster))
}

/// The kubelet client transport over `dialer`: the same TLS config as the
/// default connector (`kubernetes_rs_streamproxy::kubelet_tls_config`: serving cert
/// verified against `--kubelet-certificate-authority` when set, the
/// api-server's kubelet client identity when present; `transportConfig` in
/// kubelet_client.go:114-128) with the dial through the egress selector.
/// `insecure_skip_tls_verify` selects `InsecureSkipTLSVerifyTransport`.
fn kubelet_egress_connector(
    dialer: crate::egress_selector::Dialer,
    insecure_skip_tls_verify: bool,
) -> Result<crate::egress_http::EgressConnector> {
    let tls = kubernetes_rs_streamproxy::kubelet_tls_config(insecure_skip_tls_verify)
        .map_err(|e| Error::Internal(format!("failed to build kubelet client: {e}")))?;
    Ok(crate::egress_http::EgressConnector::new(dialer, tls, None))
}

/// The default-dial kubelet connector: `ConnectionInfo.Transport`, or
/// `InsecureSkipTLSVerifyTransport` when `insecure_skip_tls_verify`.
fn kubelet_connector(
    insecure_skip_tls_verify: bool,
) -> Result<kubernetes_rs_streamproxy::KubeletProxyConnector> {
    let c = if insecure_skip_tls_verify {
        kubernetes_rs_streamproxy::kubelet_proxy_connector_insecure()
    } else {
        kubernetes_rs_streamproxy::kubelet_proxy_connector()
    };
    c.map_err(|e| Error::Internal(format!("failed to build kubelet client: {e}")))
}

/// Decode the `/log` query into `PodLogOptions` (`ParameterCodec.DecodeParameters`;
/// a decode error is a 400) and run `LogREST.Get`'s checks
/// (`pkg/registry/core/pod/rest/log.go:89-101`): with `PodLogsQuerySplitStreams`
/// on, an absent `stream` defaults to `All`; then `ValidatePodLogOptions`,
/// whose errors are a 422 `PodLogOptions "<name>" is invalid`.
pub fn validate_log_query(name: &str, raw_query: &str) -> Result<()> {
    use kubernetes_rs_common::resources::pod::{PodLogOptions, LOG_STREAM_ALL};
    let mut params = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        // Only the first value of a parameter is read (`Convert_Slice_string_To_*`).
        params
            .entry(k.into_owned())
            .or_insert_with(|| v.into_owned());
    }
    let mut opts = PodLogOptions::from_query(&params).map_err(Error::BadRequest)?;
    let split_streams =
        kubernetes_rs_common::feature_gates::gate_enabled("PodLogsQuerySplitStreams")
            .unwrap_or(false);
    if split_streams && opts.stream.is_none() {
        opts.stream = Some(LOG_STREAM_ALL.to_string());
    }
    let errs = kubernetes_rs_common::validation::pod_subresource::validate_pod_log_options(
        &opts,
        split_streams,
    );
    if !errs.is_empty() {
        return Err(Error::new_invalid("", "PodLogOptions", name, errs));
    }
    Ok(())
}

/// `PodLogOptions.InsecureSkipTLSVerifyBackend` from the raw query:
/// `Convert_Slice_string_To_bool` on the parameter's values, which reads the
/// first one (apimachinery/pkg/runtime/conversion.go:79-95).
pub fn insecure_skip_tls_verify_backend(raw_query: &str) -> bool {
    raw_query
        .split('&')
        .find_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (k == "insecureSkipTLSVerifyBackend")
                .then(|| kubernetes_rs_common::query::k8s_query_bool(v))
        })
        .unwrap_or(false)
}

fn bad_gateway() -> Response {
    StatusCode::BAD_GATEWAY.into_response()
}

/// `proxy_upgrade` to the kubelet, dialing through `dialer` when set.
/// exec/attach/portforward always use the verifying transport
/// (`streamLocation`/`portForwardLocation` return `nodeInfo.Transport`,
/// pkg/registry/core/pod/strategy.go:794, :829).
pub async fn proxy_kubelet_upgrade(
    target: Uri,
    req: Request,
    dialer: Option<crate::egress_selector::Dialer>,
) -> Response {
    match dialer {
        None => kubernetes_rs_streamproxy::proxy_upgrade(target, req).await,
        Some(d) => match kubelet_egress_connector(d, false) {
            Ok(c) => kubernetes_rs_streamproxy::proxy_upgrade_with(target, req, c).await,
            Err(e) => {
                tracing::warn!("kubelet upgrade proxy: {e}");
                bad_gateway()
            }
        },
    }
}

/// `proxy_stream` from the kubelet, dialing through `dialer` when set.
/// `insecure_skip_tls_verify` is the log request's
/// `insecureSkipTLSVerifyBackend` (`LogLocation`, strategy.go:667-670).
pub async fn proxy_kubelet_stream(
    target: Uri,
    req: Request,
    dialer: Option<crate::egress_selector::Dialer>,
    insecure_skip_tls_verify: bool,
) -> Response {
    match dialer {
        None if !insecure_skip_tls_verify => {
            kubernetes_rs_streamproxy::proxy_stream(target, req).await
        }
        None => match kubelet_connector(true) {
            Ok(c) => kubernetes_rs_streamproxy::proxy_stream_with(target, req, c).await,
            Err(e) => {
                tracing::warn!("kubelet stream proxy: {e}");
                bad_gateway()
            }
        },
        Some(d) => match kubelet_egress_connector(d, insecure_skip_tls_verify) {
            Ok(c) => kubernetes_rs_streamproxy::proxy_stream_with(target, req, c).await,
            Err(e) => {
                tracing::warn!("kubelet stream proxy: {e}");
                bad_gateway()
            }
        },
    }
}

/// [`fetch_kubelet_log_stream`] over `connector`: a hyper client streaming
/// the body.
async fn fetch_kubelet_log_stream_with<C>(
    target_url: &Uri,
    pod_name: &str,
    connector: C,
) -> Result<std::result::Result<LogByteStream, Response>>
where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    use http_body_util::BodyExt;
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build::<_, axum::body::Body>(connector);
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(target_url.clone())
        .body(axum::body::Body::empty())
        .map_err(|e| Error::Internal(format!("kubelet log request failed: {e}")))?;
    let resp = client.request(req).await.map_err(|e| {
        // Display, with the wrapped causes (the TLS verification error sits
        // under hyper's "client error (Connect)"), like Go's `url.Error`
        // message — never the Debug form.
        let mut message = format!("kubelet log request failed: {e}");
        let mut src = std::error::Error::source(&e);
        while let Some(s) = src {
            message.push_str(&format!(": {s}"));
            src = s.source();
        }
        Error::Internal(message)
    })?;
    let (parts, body) = resp.into_parts();
    let code = parts.status;
    if !(StatusCode::OK..=StatusCode::PARTIAL_CONTENT).contains(&code) {
        // `io.ReadAll(io.LimitReader(resp.Body, maxReadLength))`, chunk by
        // chunk so an oversized body is truncated rather than rejected.
        let mut body = body;
        let mut buf: Vec<u8> = Vec::new();
        while buf.len() < KUBELET_ERROR_MAX_READ {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        let take = (KUBELET_ERROR_MAX_READ - buf.len()).min(data.len());
                        buf.extend_from_slice(&data[..take]);
                    }
                }
                _ => break,
            }
        }
        let text = String::from_utf8_lossy(&buf).into_owned();
        return Ok(Err(kubelet_error_response(code, text, pod_name)));
    }
    Ok(Ok(Box::pin(
        body.into_data_stream().map_err(std::io::Error::other),
    )))
}

/// Fetch the kubelet log stream, or the `Response` that must be returned
/// instead when the kubelet refused.
///
/// The websocket path needs the same check as the plain proxy: without it the
/// kubelet's error text is framed into the websocket as if it were log output,
/// which is worse than the plain path's bad content type — the client cannot
/// tell an error from a log line at all.
///
/// Uses the same kubelet transport as the plain proxy (CA verification, client
/// identity, egress dial); `insecure_skip_tls_verify` is the request's
/// `insecureSkipTLSVerifyBackend`.
pub async fn fetch_kubelet_log_stream(
    target_url: &Uri,
    pod_name: &str,
    dialer: Option<crate::egress_selector::Dialer>,
    insecure_skip_tls_verify: bool,
) -> Result<std::result::Result<LogByteStream, Response>> {
    match dialer {
        Some(d) => {
            let c = kubelet_egress_connector(d, insecure_skip_tls_verify)?;
            fetch_kubelet_log_stream_with(target_url, pod_name, c).await
        }
        None => {
            let c = kubelet_connector(insecure_skip_tls_verify)?;
            fetch_kubelet_log_stream_with(target_url, pod_name, c).await
        }
    }
}

/// Build the kubelet stream URL for an exec or attach subresource.
///
/// Upstream: `pkg/registry/core/pod/strategy.go::streamLocation` builds
/// `/{kind}/{ns}/{pod}/{container}?<raw_query>` on the pod's node and
/// upgrade-proxies.  We replicate that exact shape here.
pub fn build_kubelet_stream_url(
    conn: &NodeConn,
    kind: &str,
    ns: &str,
    pod: &str,
    container: &str,
    raw_query: &str,
) -> Uri {
    let path = format!("/{kind}/{ns}/{pod}/{container}");
    let uri_str = if raw_query.is_empty() {
        format!("{}://{}:{}{}", conn.scheme, conn.host, conn.port, path)
    } else {
        format!(
            "{}://{}:{}{}?{}",
            conn.scheme, conn.host, conn.port, path, raw_query
        )
    };
    uri_str.parse().expect("kubelet stream URL is always valid")
}

/// Reject a CONNECT request that carries a `dryRun` query key.
///
/// Upstream: `ConnectResource`
/// (`staging/src/k8s.io/apiserver/pkg/endpoints/handlers/rest.go:179-182`)
/// answers `NewBadRequest("dryRun is not supported")` before anything else;
/// `isDryRun` (`rest.go:399-401`) is `len(url.Query()["dryRun"]) != 0`, so the
/// mere presence of the key counts, even with an empty value.
pub(crate) fn reject_connect_dry_run(raw_query: &str) -> Result<()> {
    if url::form_urlencoded::parse(raw_query.as_bytes()).any(|(k, _)| k == "dryRun") {
        return Err(Error::BadRequest("dryRun is not supported".to_string()));
    }
    Ok(())
}

/// Build the kubelet stream query from (possibly webhook-mutated) options.
///
/// Port of `streamParams` (`pkg/registry/core/pod/strategy.go:688-724`):
/// `stdin/stdout/stderr/tty` become `input/output/error/tty=1` when set
/// (`pkg/apis/core/types.go:6724-6730`), `command` repeats per element (exec
/// only). Used only when a mutating webhook changed the options, so an
/// unmutated request keeps forwarding the client's raw query.
fn stream_query_from_options(options: &serde_json::Value, with_command: bool) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (field, param) in [
        ("stdin", "input"),
        ("stdout", "output"),
        ("stderr", "error"),
        ("tty", "tty"),
    ] {
        if options[field].as_bool().unwrap_or(false) {
            ser.append_pair(param, "1");
        }
    }
    if with_command {
        for c in options["command"].as_array().into_iter().flatten() {
            if let Some(c) = c.as_str() {
                ser.append_pair("command", c);
            }
        }
    }
    ser.finish()
}

/// Container named by the final options, if any.
fn options_container(options: &serde_json::Value) -> Option<String> {
    options["container"]
        .as_str()
        .filter(|c| !c.is_empty())
        .map(str::to_string)
}

/// Run mutating then validating webhooks for an `admission.Connect` on a pod
/// subresource and return the (possibly mutated) options object.
///
/// Upstream: `ConnectResource`
/// (`staging/src/k8s.io/apiserver/pkg/endpoints/handlers/rest.go:199-216`)
/// admits the decoded connect-options object (`PodExecOptions`,
/// `PodAttachOptions`, `PodPortForwardOptions`) with `admission.Connect`
/// before `connecter.Connect` is invoked: first the mutating `Admit`, then the
/// validating `Validate` on the SAME (already mutated) `opts` pointer, which
/// `connecter.Connect` then consumes. Shared by exec, attach and portforward.
/// Dry-run never reaches here (`reject_connect_dry_run`), so the dispatchers
/// run with `dry_run = false`.
pub async fn run_connect_admission(
    state: &ApiServerState,
    kind: &str,
    resource: &str,
    namespace: &str,
    name: &str,
    options: serde_json::Value,
    user: &kubernetes_rs_common::admission::UserInfo,
) -> Result<serde_json::Value> {
    use kubernetes_rs_common::admission::{
        AdmissionResponse, GroupVersionKind, GroupVersionResource, Operation,
    };
    let gvk = GroupVersionKind {
        group: "".to_string(),
        version: "v1".to_string(),
        kind: kind.to_string(),
    };
    let gvr = GroupVersionResource {
        group: "".to_string(),
        version: "v1".to_string(),
        resource: resource.to_string(),
    };
    use kubernetes_rs_admission_webhook::admission_metrics::{
        with_step_metrics, STEP_ADMIT, STEP_VALIDATE,
    };
    // `WithStepMetrics` wraps the whole chain (server/options/admission.go:179),
    // so each phase is one step observation, `rejected` being `err != nil`.
    let options = with_step_metrics(&Operation::Connect, STEP_ADMIT, async {
        let (mutating, mutated) = state
            .webhook_manager
            .run_mutating_webhooks_with_dryrun(
                &Operation::Connect,
                &gvk,
                &gvr,
                Some(namespace),
                name,
                Some(options.clone()),
                None,
                user,
                false,
            )
            .await?;
        if let AdmissionResponse::Deny(reason) = mutating {
            return Err(Error::Forbidden(format!(
                "admission webhook denied the request: {}",
                reason
            )));
        }
        Ok(mutated.unwrap_or(options))
    })
    .await?;
    with_step_metrics(&Operation::Connect, STEP_VALIDATE, async {
        if let AdmissionResponse::Deny(reason) = state
            .webhook_manager
            .run_validating_webhooks(
                &Operation::Connect,
                &gvk,
                &gvr,
                Some(namespace),
                name,
                Some(options.clone()),
                None,
                user,
            )
            .await?
        {
            return Err(Error::Forbidden(format!(
                "admission webhook denied the request: {}",
                reason
            )));
        }
        Ok(())
    })
    .await?;
    Ok(options)
}

/// GET/POST /api/v1/namespaces/{namespace}/pods/{name}/exec
///
/// Proxies exec to the pod's kubelet using an upgrade-aware reverse proxy.
/// Mirrors `pkg/registry/core/pod/strategy.go::streamLocation`.
pub async fn exec(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((namespace, name)): Path<(String, String)>,
    req: Request,
) -> Result<Response> {
    let raw_query = req.uri().query().unwrap_or("").to_string();

    // Parse query params to build webhook admission object (command/container).
    let query = parse_exec_query(&raw_query);

    info!("Exec {}/{}: cmd={:?}", namespace, name, query.command);

    // Save user info for webhook check before auth moves ownership
    let webhook_user_info = kubernetes_rs_common::admission::UserInfo {
        username: auth_ctx.user.username.clone(),
        uid: auth_ctx.user.uid.clone(),
        groups: auth_ctx.user.groups.clone(),
    };

    // Check authorization
    let attrs = RequestAttributes::new(auth_ctx.user, "create", "pods")
        .with_namespace(&namespace)
        .with_name(&name)
        .with_subresource("exec");

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(Error::Forbidden(reason));
        }
    }

    // rest.go:179-182: dryRun is rejected for every CONNECT.
    reject_connect_dry_run(&raw_query)?;

    // Run admission webhooks for Connect operation (exec)
    let exec_options = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PodExecOptions",
        "stdin": query.stdin,
        "stdout": query.stdout,
        "stderr": query.stderr,
        "tty": query.tty,
        "container": query.container.as_deref().unwrap_or(""),
        "command": query.command
    });
    let admitted = run_connect_admission(
        &state,
        "PodExecOptions",
        "pods/exec",
        &namespace,
        &name,
        exec_options.clone(),
        &webhook_user_info,
    )
    .await?;
    // `connecter.Connect` consumes the MUTATED opts (rest.go:204-216): when a
    // webhook changed them, rebuild the kubelet query via `streamParams`.
    let (raw_query, query_container) = if admitted != exec_options {
        (
            stream_query_from_options(&admitted, true),
            options_container(&admitted),
        )
    } else {
        (raw_query, query.container.clone())
    };

    // Fetch the pod and require spec.nodeName (upstream: 400 if unset).
    let pod_key = kubernetes_rs_storage::build_key("pods", Some(&namespace), &name);
    let pod: kubernetes_rs_common::resources::Pod = state.storage.get(&pod_key).await?;

    let node_name = pod
        .spec
        .as_ref()
        .and_then(|s| s.node_name.as_deref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::InvalidResource(format!(
                "pod {}/{} has not been assigned to a node",
                namespace, name
            ))
        })?
        .to_string();

    // Resolve the container name (default to first container).
    let container_name = if let Some(container) = query_container {
        container
    } else {
        pod.spec
            .as_ref()
            .and_then(|spec| spec.containers.first())
            .map(|c| c.name.clone())
            .ok_or_else(|| Error::InvalidResource("Pod has no containers".to_string()))?
    };

    // Fetch the node and resolve kubelet connection parameters.
    let node_key = kubernetes_rs_storage::build_key("nodes", None::<&str>, &node_name);
    let node: kubernetes_rs_common::resources::Node = state.storage.get(&node_key).await?;
    let conn = node_conn(&node, None)?;

    // Build the upstream-faithful kubelet exec URL.
    let target_url = build_kubelet_stream_url(
        &conn,
        "exec",
        &namespace,
        &name,
        &container_name,
        &raw_query,
    );
    info!(
        "Proxying exec {}/{} to kubelet: {}",
        namespace, name, target_url
    );

    // Upgrade-proxy the request to the kubelet (handles SPDY, WebSocket, and plain HTTP).
    // The WebSocket upgrade (if any) is handled transparently by proxy_upgrade via the
    // raw hyper OnUpgrade future; we don't need to handle it separately.
    Ok(proxy_kubelet_upgrade(target_url, req, kubelet_dialer()).await)
}

/// GET/POST /api/v1/namespaces/{namespace}/pods/{name}/attach
///
/// Proxies attach to the pod's kubelet using an upgrade-aware reverse proxy.
/// Mirrors `pkg/registry/core/pod/strategy.go::streamLocation`.
pub async fn attach(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((namespace, name)): Path<(String, String)>,
    Query(query): Query<AttachQuery>,
    req: Request,
) -> Result<Response> {
    info!("Attaching to pod {}/{}", namespace, name);

    let raw_query = req.uri().query().unwrap_or("").to_string();

    // Save user info for webhook check before auth moves ownership
    let webhook_user_info = kubernetes_rs_common::admission::UserInfo {
        username: auth_ctx.user.username.clone(),
        uid: auth_ctx.user.uid.clone(),
        groups: auth_ctx.user.groups.clone(),
    };

    // Check authorization
    let attrs = RequestAttributes::new(auth_ctx.user, "create", "pods")
        .with_namespace(&namespace)
        .with_name(&name)
        .with_subresource("attach");

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(Error::Forbidden(reason));
        }
    }

    // rest.go:179-182: dryRun is rejected for every CONNECT.
    reject_connect_dry_run(&raw_query)?;

    // Run admission webhooks for Connect operation (attach)
    let attach_options = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PodAttachOptions",
        "stdin": query.stdin,
        "stdout": query.stdout,
        "stderr": query.stderr,
        "tty": query.tty,
        "container": query.container.as_deref().unwrap_or("")
    });
    let admitted = run_connect_admission(
        &state,
        "PodAttachOptions",
        "pods/attach",
        &namespace,
        &name,
        attach_options.clone(),
        &webhook_user_info,
    )
    .await?;
    // `connecter.Connect` consumes the MUTATED opts (rest.go:204-216).
    let (raw_query, query_container) = if admitted != attach_options {
        (
            stream_query_from_options(&admitted, false),
            options_container(&admitted),
        )
    } else {
        (raw_query, query.container.clone())
    };

    // Fetch the pod and require spec.nodeName (upstream: 400 if unset).
    let pod_key = kubernetes_rs_storage::build_key("pods", Some(&namespace), &name);
    let pod: kubernetes_rs_common::resources::Pod = state.storage.get(&pod_key).await?;

    let node_name = pod
        .spec
        .as_ref()
        .and_then(|s| s.node_name.as_deref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::InvalidResource(format!(
                "pod {}/{} has not been assigned to a node",
                namespace, name
            ))
        })?
        .to_string();

    // Resolve the container name (default to first container).
    let container_name = if let Some(container) = query_container {
        container
    } else {
        pod.spec
            .as_ref()
            .and_then(|spec| spec.containers.first())
            .map(|c| c.name.clone())
            .ok_or_else(|| Error::InvalidResource("Pod has no containers".to_string()))?
    };

    // Fetch the node and resolve kubelet connection parameters.
    let node_key = kubernetes_rs_storage::build_key("nodes", None::<&str>, &node_name);
    let node: kubernetes_rs_common::resources::Node = state.storage.get(&node_key).await?;
    let conn = node_conn(&node, None)?;

    // Build the upstream-faithful kubelet attach URL.
    let target_url = build_kubelet_stream_url(
        &conn,
        "attach",
        &namespace,
        &name,
        &container_name,
        &raw_query,
    );
    info!(
        "Proxying attach {}/{} to kubelet: {}",
        namespace, name, target_url
    );

    // Upgrade-proxy the request to the kubelet (handles SPDY, WebSocket, and plain HTTP).
    // Suppress the unused `ws` warning — the upgrade is handled transparently by
    // proxy_upgrade via the raw hyper OnUpgrade future.
    Ok(proxy_kubelet_upgrade(target_url, req, kubelet_dialer()).await)
}

/// Build the kubelet `portForward` query from the request's `ports` options.
///
/// Port of `streamParams` for `*api.PodPortForwardOptions`
/// (`pkg/registry/core/pod/strategy.go:716-723`): the ports become a single
/// comma-joined `port=` param, and no param at all when there are none (kubectl's
/// SPDY client sends its ports in stream headers, not the query).
pub fn port_forward_stream_query(raw_query: &str) -> Result<String> {
    let ports = parse_port_forward_ports(raw_query)?;
    if ports.is_empty() {
        return Ok(String::new());
    }
    let joined = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!("port={joined}"))
}

/// Decode `PodPortForwardOptions.Ports` from the request query: the `ports`
/// key (v1 json tag, `types.go:7321`), repeated and/or comma-separated.
pub fn parse_port_forward_ports(raw_query: &str) -> Result<Vec<u16>> {
    let mut ports: Vec<u16> = Vec::new();
    for (k, v) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        if k != "ports" {
            continue;
        }
        for p in v.split(',') {
            let port: u16 = p.trim().parse().map_err(|_| {
                Error::BadRequest(format!("unable to parse {p:?} as a port in \"ports\""))
            })?;
            ports.push(port);
        }
    }
    Ok(ports)
}

/// Build the kubelet `/portForward/{ns}/{pod}` URL.
///
/// Upstream: `PortForwardLocation` (`pkg/registry/core/pod/strategy.go:798-830`)
/// — `Path: /portForward/<ns>/<name>` (note the capital F).
pub fn build_kubelet_portforward_url(
    conn: &NodeConn,
    ns: &str,
    pod: &str,
    stream_query: &str,
) -> Uri {
    let path = format!("/portForward/{ns}/{pod}");
    let uri_str = if stream_query.is_empty() {
        format!("{}://{}:{}{}", conn.scheme, conn.host, conn.port, path)
    } else {
        format!(
            "{}://{}:{}{}?{}",
            conn.scheme, conn.host, conn.port, path, stream_query
        )
    };
    uri_str
        .parse()
        .expect("kubelet portForward URL is always valid")
}

/// GET/POST /api/v1/namespaces/{namespace}/pods/{name}/portforward
///
/// Proxies port-forward to the pod's kubelet with an upgrade-aware reverse proxy.
/// Mirrors `PortForwardREST.Connect` (`pkg/registry/core/pod/rest/subresources.go:256-279`)
/// and `PortForwardLocation`. The kubelet resolves the sandbox and calls CRI
/// `PortForward`; the SPDY/WebSocket bytes pass through untouched.
pub async fn portforward(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((namespace, name)): Path<(String, String)>,
    req: Request,
) -> Result<Response> {
    info!("Port forwarding to pod {}/{}", namespace, name);

    let raw_query = req.uri().query().unwrap_or("").to_string();

    let webhook_user_info = kubernetes_rs_common::admission::UserInfo {
        username: auth_ctx.user.username.clone(),
        uid: auth_ctx.user.uid.clone(),
        groups: auth_ctx.user.groups.clone(),
    };

    // Check authorization
    let attrs = RequestAttributes::new(auth_ctx.user, "create", "pods")
        .with_namespace(&namespace)
        .with_name(&name)
        .with_subresource("portforward");

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(Error::Forbidden(reason));
        }
    }

    // `getRequestOptions` (rest.go:194-198) decodes the options and 400s on a
    // bad query BEFORE admission; then admission.Connect (rest.go:199-216)
    // runs on the decoded `PodPortForwardOptions`, before the pod is fetched.
    // rest.go:179-182: dryRun is rejected first, before options are decoded.
    reject_connect_dry_run(&raw_query)?;
    let ports = parse_port_forward_ports(&raw_query)?;
    let mut stream_query = port_forward_stream_query(&raw_query)?;
    let port_options = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PodPortForwardOptions",
        "ports": ports,
    });
    let admitted = run_connect_admission(
        &state,
        "PodPortForwardOptions",
        "pods/portforward",
        &namespace,
        &name,
        port_options.clone(),
        &webhook_user_info,
    )
    .await?;
    // `streamParams` runs on the MUTATED opts (strategy.go:716-723).
    if admitted != port_options {
        let mutated: Vec<String> = admitted["ports"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| p.as_i64())
            .map(|p| p.to_string())
            .collect();
        stream_query = if mutated.is_empty() {
            String::new()
        } else {
            format!("port={}", mutated.join(","))
        };
    }

    // Fetch the pod and require spec.nodeName (upstream: 400 if unset).
    let pod_key = kubernetes_rs_storage::build_key("pods", Some(&namespace), &name);
    let pod: kubernetes_rs_common::resources::Pod = state.storage.get(&pod_key).await?;

    let node_name = pod
        .spec
        .as_ref()
        .and_then(|s| s.node_name.as_deref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::BadRequest(format!("pod {} does not have a host assigned", name)))?
        .to_string();

    let node_key = kubernetes_rs_storage::build_key("nodes", None::<&str>, &node_name);
    let node: kubernetes_rs_common::resources::Node = state.storage.get(&node_key).await?;
    let conn = node_conn(&node, None)?;

    let target_url = build_kubelet_portforward_url(&conn, &namespace, &name, &stream_query);
    info!(
        "Proxying portforward {}/{} to kubelet: {}",
        namespace, name, target_url
    );

    Ok(proxy_kubelet_upgrade(target_url, req, kubelet_dialer()).await)
}

/// Feature name kubelets advertise in `node.status.declaredFeatures` once they
/// support the CPU-resize path for Guaranteed-QoS pods (KEP-5328 — KEP-1287
/// integration). The api-server uses this constant when deciding whether to
/// admit a `/pods/{name}/resize` request that mutates a Guaranteed pod's CPU.
pub(crate) const GUARANTEED_QOS_POD_CPU_RESIZE: &str = "GuaranteedQoSPodCPUResize";

/// Returns `true` if `pod` is Guaranteed-QoS.
///
/// Delegates to [`kubernetes_rs_common::qos::get_pod_qos`], the port of
/// `pkg/apis/core/v1/helper/qos/qos.go::GetPodQOS`. Upstream's gate reads the
/// **published** class off the pod being resized
/// (`guaranteed_cpu_resize.go:64`, `oldPodInfo.Status.QOSClass !=
/// v1.PodQOSGuaranteed`), which is what `get_pod_qos` prefers before falling
/// back to computing.
///
/// The partial Guaranteed-only check this used to carry — `spec.containers`
/// only, quantities compared as strings — is gone: a pod whose init container
/// declares no limits is `Burstable`, so the CPU-resize gate must not fire for
/// it.
fn is_guaranteed_qos(pod: &kubernetes_rs_common::resources::Pod) -> bool {
    kubernetes_rs_common::qos::get_pod_qos(pod) == kubernetes_rs_common::qos::QoSClass::Guaranteed
}

/// Returns `true` if the CPU resource request OR limit differs between any
/// matching container in `desired` vs `current`. The match is by container
/// name; missing-on-one-side counts as a change.
fn resize_changes_cpu(
    current: &kubernetes_rs_common::resources::Pod,
    desired: &kubernetes_rs_common::resources::Pod,
) -> bool {
    let (Some(cur_spec), Some(des_spec)) = (current.spec.as_ref(), desired.spec.as_ref()) else {
        return false;
    };
    for desired_c in &des_spec.containers {
        let Some(current_c) = cur_spec
            .containers
            .iter()
            .find(|c| c.name == desired_c.name)
        else {
            continue;
        };
        let cur_cpu_req = current_c
            .resources
            .as_ref()
            .and_then(|r| r.requests.as_ref())
            .and_then(|m| m.get("cpu"));
        let des_cpu_req = desired_c
            .resources
            .as_ref()
            .and_then(|r| r.requests.as_ref())
            .and_then(|m| m.get("cpu"));
        let cur_cpu_lim = current_c
            .resources
            .as_ref()
            .and_then(|r| r.limits.as_ref())
            .and_then(|m| m.get("cpu"));
        let des_cpu_lim = desired_c
            .resources
            .as_ref()
            .and_then(|r| r.limits.as_ref())
            .and_then(|m| m.get("cpu"));
        if cur_cpu_req != des_cpu_req || cur_cpu_lim != des_cpu_lim {
            return true;
        }
    }
    false
}

/// Node-declared-feature admission for `/pods/{name}/resize` (KEP-5328 +
/// KEP-1287). When both `NodeDeclaredFeatures` and `InPlacePodVerticalScaling`
/// are enabled, a CPU resize against a Guaranteed-QoS pod is admitted only if
/// the target node has advertised `GuaranteedQoSPodCPUResize` in
/// `status.declaredFeatures`.
///
/// Returns:
///   - `Ok(())` when the gate combination does not apply (either gate off, or
///     the change does not touch CPU, or the pod is not Guaranteed), when the
///     pod is not yet bound to a node, when the node does not exist (the
///     resize is allowed in that case — upstream defers to scheduler), or
///     when the node *has* declared the feature.
///   - `Err(Error::Forbidden(_))` when the target node exists, both gates are
///     on, the pod is Guaranteed, the resize touches CPU, and the node has
///     not declared `GuaranteedQoSPodCPUResize`.
///
/// Upstream: `plugin/pkg/admission/noderestriction/admission.go` consults
/// `nodeFeatures` when admitting `/pods/{name}/resize`; missing
/// `GuaranteedQoSPodCPUResize` produces:
///   "spec.containers[*].resources: Forbidden: node \"<n>\" has not declared
///    feature \"GuaranteedQoSPodCPUResize\""
pub(crate) async fn check_node_declared_features_for_resize<S: Storage>(
    storage: &S,
    current: &kubernetes_rs_common::resources::Pod,
    desired: &kubernetes_rs_common::resources::Pod,
) -> Result<()> {
    use kubernetes_rs_common::feature_gates::{enabled, Feature};

    // Both gates must be on. Mirrors upstream's
    // `if utilfeature.DefaultFeatureGate.Enabled(features.NodeDeclaredFeatures)
    //   && utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling)`
    // in the resize strategy.
    if !enabled(Feature::NodeDeclaredFeatures) || !enabled(Feature::InPlacePodVerticalScaling) {
        return Ok(());
    }

    // The check only fires when the change actually touches CPU on a
    // Guaranteed pod — label-only resizes (or memory-only) sail through.
    if !is_guaranteed_qos(current) || !resize_changes_cpu(current, desired) {
        return Ok(());
    }

    // Pod must already be bound to a node — there is nothing to consult
    // otherwise. Upstream returns nil in that case.
    let Some(node_name) = current
        .spec
        .as_ref()
        .and_then(|s| s.node_name.as_ref())
        .filter(|n| !n.is_empty())
    else {
        return Ok(());
    };

    let node_key = kubernetes_rs_storage::build_key("nodes", None, node_name);
    let node: kubernetes_rs_common::resources::Node = match storage.get(&node_key).await {
        Ok(n) => n,
        // Missing node: upstream's NodeRestriction admission allows the
        // request through and lets the scheduler / node controller catch up.
        Err(Error::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
    };

    let declares_resize = node
        .status
        .as_ref()
        .and_then(|s| s.declared_features.as_ref())
        .map(|features| features.iter().any(|f| f == GUARANTEED_QOS_POD_CPU_RESIZE))
        .unwrap_or(false);

    if declares_resize {
        Ok(())
    } else {
        Err(Error::Forbidden(format!(
            "spec.containers[*].resources: Forbidden: node \"{}\" has not declared feature \"{}\"",
            node_name, GUARANTEED_QOS_POD_CPU_RESIZE
        )))
    }
}
