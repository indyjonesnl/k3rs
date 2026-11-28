//! Port-forward tunneling: SPDY framed inside a websocket.
//!
//! Port of `staging/src/k8s.io/apiserver/pkg/util/proxy/streamtunnel.go`
//! (release-1.35): `NewTunnelingHandler`, `ServeHTTP` (:62),
//! `createSPDYRequest` (:96), `spdyProtocolsFromWebsocketProtocols` (:116),
//! `tunnelingResponseWriter` / `headerInterceptingConn` /
//! `tunnelingWebsocketUpgraderConn` (:149-330), plus apimachinery
//! `wsstream.IsWebSocketRequestWithTunnelingProtocol` (conn.go:113) and
//! client-go `portforward.TunnelingConnection`
//! (`tools/portforward/tunneling_connection.go`).
//!
//! The client speaks a websocket whose binary messages carry SPDY bytes; the
//! upstream (kubelet) is spoken plain SPDY. Upstream wires the two with a fake
//! `http.Hijacker` so the stock upgrade-aware proxy can be reused. Here the
//! same observable behaviour is produced directly: send the SPDY upgrade
//! request, then (a) on a backend 101, complete the websocket handshake with
//! the client (selecting `SPDY/3.1+<backend protocol>`) and copy bytes both
//! ways, or (b) pass any other backend response through unchanged.
//!
//! Each request is counted in `apiserver_stream_tunnel_requests_total{code}`
//! (see [`stream_tunnel_request_counts`]).

use axum::body::Body;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use http_body_util::BodyExt;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Message, Role};
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, warn};

/// `constants.WebsocketsSPDYTunnelingPrefix`
/// (apimachinery `util/portforward/constants.go:21`).
pub const WEBSOCKETS_SPDY_TUNNELING_PREFIX: &str = "SPDY/3.1+";
/// `constants.KubernetesSuffix` (`constants.go:22`).
pub const KUBERNETES_SUFFIX: &str = ".k8s.io";
/// `spdy.HeaderSpdy31`.
const HEADER_SPDY31: &str = "SPDY/3.1";
/// `httpstream.HeaderProtocolVersion`.
const HEADER_PROTOCOL_VERSION: &str = "X-Stream-Protocol-Version";
const WEBSOCKET_PROTOCOL_HEADER: &str = "Sec-WebSocket-Protocol";

fn counters() -> &'static Mutex<BTreeMap<u16, u64>> {
    static C: OnceLock<Mutex<BTreeMap<u16, u64>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// `metrics.IncStreamTunnelRequest` (`util/proxy/metrics/metrics.go`).
fn inc_stream_tunnel_request(code: u16) {
    *counters().lock().unwrap().entry(code).or_insert(0) += 1;
}

/// Snapshot of `apiserver_stream_tunnel_requests_total`, keyed by status code.
pub fn stream_tunnel_request_counts() -> BTreeMap<u16, u64> {
    counters().lock().unwrap().clone()
}

/// `IsUpgradeRequest` (`httpstream/httpstream.go`): `Connection` contains the
/// token `upgrade` and an `Upgrade` header is present.
fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let connection_has_upgrade = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    connection_has_upgrade && headers.get(header::UPGRADE).is_some_and(|v| !v.is_empty())
}

/// `wsstream.IsWebSocketRequest` (conn.go:86).
pub fn is_websocket_request(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && is_upgrade_request(headers)
}

/// Subprotocols the client offered (`gwebsocket.Subprotocols`: every
/// comma-separated token across `Sec-WebSocket-Protocol` headers, trimmed).
fn websocket_subprotocols(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(WEBSOCKET_PROTOCOL_HEADER)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// `protocolSupportsWebsocketTunneling` (conn.go:324).
fn protocol_supports_websocket_tunneling(protocol: &str) -> bool {
    protocol.starts_with(WEBSOCKETS_SPDY_TUNNELING_PREFIX) && protocol.ends_with(KUBERNETES_SUFFIX)
}

/// `wsstream.IsWebSocketRequestWithTunnelingProtocol` (conn.go:113).
pub fn is_websocket_request_with_tunneling_protocol(headers: &HeaderMap) -> bool {
    is_websocket_request(headers)
        && websocket_subprotocols(headers)
            .iter()
            .any(|p| protocol_supports_websocket_tunneling(p))
}

/// `spdyProtocolsFromWebsocketProtocols` (streamtunnel.go:116): the
/// `SPDY/3.1+...k8s.io` subprotocols with the prefix removed.
pub fn spdy_protocols_from_websocket_protocols(headers: &HeaderMap) -> Vec<String> {
    websocket_subprotocols(headers)
        .into_iter()
        .filter(|p| protocol_supports_websocket_tunneling(p))
        .map(|p| p[WEBSOCKETS_SPDY_TUNNELING_PREFIX.len()..].to_string())
        .collect()
}

/// `createSPDYRequest` (streamtunnel.go:96): the request with the websocket
/// headers removed and the SPDY upgrade headers added, as a bodyless `POST`
/// to `target`.
pub fn create_spdy_request(
    headers: &HeaderMap,
    target: Uri,
    spdy_protocols: &[String],
) -> Result<http::Request<Body>, http::Error> {
    let nominated = super::connection_nominated_headers(headers);
    let mut builder = http::Request::builder().method(Method::POST).uri(target);
    {
        let out = builder.headers_mut().unwrap();
        for (name, value) in headers {
            let n = name.as_str();
            if n.eq_ignore_ascii_case(WEBSOCKET_PROTOCOL_HEADER)
                || n.eq_ignore_ascii_case("sec-websocket-key")
                || n.eq_ignore_ascii_case("sec-websocket-version")
                || n.eq_ignore_ascii_case(HEADER_PROTOCOL_VERSION)
                // Hop-by-hop and the bodyless POST's framing headers.
                || super::should_strip(n, &nominated)
                || n.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            out.append(name.clone(), value.clone());
        }
        out.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        out.insert(header::UPGRADE, HeaderValue::from_static(HEADER_SPDY31));
        let name = HeaderName::from_static("x-stream-protocol-version");
        for p in spdy_protocols {
            if let Ok(v) = HeaderValue::from_str(p) {
                out.append(name.clone(), v);
            }
        }
    }
    builder.body(Body::empty())
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    inc_stream_tunnel_request(status.as_u16());
    (status, format!("{msg}\n")).into_response()
}

/// `TunnelingHandler.ServeHTTP` (streamtunnel.go:62) over the process-wide
/// kubelet connector (see [`super::proxy_upgrade`]).
pub async fn tunneling_handler(target: Uri, req: Request) -> Response {
    match super::tls::kubelet_proxy_connector() {
        Ok(c) => tunneling_handler_with(target, req, c).await,
        Err(e) => super::connector_error(&e),
    }
}

/// [`tunneling_handler`] over a caller-supplied connector.
pub async fn tunneling_handler_with<C>(target: Uri, req: Request, connector: C) -> Response
where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    let (mut parts, _body) = req.into_parts();

    let spdy_protocols = spdy_protocols_from_websocket_protocols(&parts.headers);
    if spdy_protocols.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "unable to upgrade: no tunneling spdy protocols provided",
        );
    }

    let spdy_req = match create_spdy_request(&parts.headers, target, &spdy_protocols) {
        Ok(r) => r,
        Err(e) => {
            warn!("tunneling: failed to build SPDY request: {e}");
            return error_response(StatusCode::BAD_GATEWAY, "bad gateway");
        }
    };

    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(connector);
    let mut backend_resp = match client.request(spdy_req).await {
        Ok(r) => r,
        Err(e) => {
            warn!("tunneling: backend request failed: {e}");
            return error_response(StatusCode::BAD_GATEWAY, "bad gateway");
        }
    };

    // `InitializeWrite`: anything other than an upgrade passes the backend
    // response through (streamtunnel.go:300-322).
    if backend_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        inc_stream_tunnel_request(backend_resp.status().as_u16());
        let (rp, rb) = backend_resp.into_parts();
        let nominated = super::connection_nominated_headers(&rp.headers);
        let mut b = Response::builder().status(rp.status);
        for (name, value) in &rp.headers {
            if !super::should_strip(name.as_str(), &nominated) {
                b = b.header(name, value);
            }
        }
        return b
            .body(Body::from_stream(rb.into_data_stream()))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    // streamtunnel.go:262-269: the backend must really have switched to SPDY/3.1.
    let connection_ok = backend_resp
        .headers()
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains("upgrade"));
    let upgrade_ok = backend_resp
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.to_ascii_lowercase()
                .contains(&HEADER_SPDY31.to_ascii_lowercase())
        });
    if !connection_ok || !upgrade_ok {
        warn!("unable to upgrade: missing upgrade headers in response");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unable to upgrade: missing upgrade headers in response",
        );
    }

    // Translate the server's chosen SPDY protocol into the tunneled websocket
    // protocol for the handshake (:272-278); gorilla's Upgrader only selects it
    // if the client offered it.
    let backend_spdy_protocol = backend_resp
        .headers()
        .get(HEADER_PROTOCOL_VERSION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let selected_ws_protocol = backend_spdy_protocol
        .map(|p| format!("{WEBSOCKETS_SPDY_TUNNELING_PREFIX}{p}"))
        .filter(|p| websocket_subprotocols(&parts.headers).contains(p));

    // The websocket upgrade (`gwebsocket.Upgrader.Upgrade`): GET, upgrade
    // headers, version 13 and a key, else 400. Origin is not checked
    // (`CheckOrigin` always true).
    let key = parts
        .headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string);
    let version_ok = parts
        .headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "13");
    let (Some(key), true, true) = (
        key,
        version_ok,
        parts.method == Method::GET && is_websocket_request(&parts.headers),
    ) else {
        return error_response(StatusCode::BAD_REQUEST, "websocket: bad handshake");
    };
    let Some(client_on_upgrade) = parts.extensions.remove::<hyper::upgrade::OnUpgrade>() else {
        warn!("tunneling: client OnUpgrade not present, refusing to upgrade");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "unable to upgrade");
    };
    let hold = parts.extensions.get::<super::ConnectionHold>().cloned();
    let backend_on_upgrade = hyper::upgrade::on(&mut backend_resp);

    let mut resp = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header("sec-websocket-accept", derive_accept_key(key.as_bytes()));
    if let Some(p) = &selected_ws_protocol {
        resp = resp.header(WEBSOCKET_PROTOCOL_HEADER, p);
    }
    inc_stream_tunnel_request(StatusCode::SWITCHING_PROTOCOLS.as_u16());

    tokio::spawn(async move {
        let _hold = hold;
        match tokio::try_join!(client_on_upgrade, backend_on_upgrade) {
            Ok((client, backend)) => {
                let ws = WebSocketStream::from_raw_socket(
                    hyper_util::rt::TokioIo::new(client),
                    Role::Server,
                    None,
                )
                .await;
                let backend = hyper_util::rt::TokioIo::new(backend);
                if let Err(e) = tunnel(ws, backend).await {
                    debug!("stream tunnel ended: {e}");
                }
            }
            Err(e) => warn!("tunneling: upgrade handshake failed: {e}"),
        }
    });

    resp.body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Copy SPDY bytes between the tunneling websocket and the backend:
/// `TunnelingConnection.Read` (binary messages only; a normal close is EOF,
/// anything else is "invalid message type received") and
/// `TunnelingConnection.Write` (one binary message per write).
pub async fn tunnel<W, B>(ws: WebSocketStream<W>, mut backend: B) -> Result<(), String>
where
    W: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut ws_tx, mut ws_rx) = ws.split();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            msg = ws_rx.next() => match msg {
                Some(Ok(Message::Binary(data))) => {
                    backend.write_all(&data).await.map_err(|e| e.to_string())?;
                }
                // Ping/pong are answered by the websocket layer.
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    let _ = backend.shutdown().await;
                    return Ok(());
                }
                Some(Ok(_)) => {
                    let _ = ws_tx.close().await;
                    return Err("invalid message type received".to_string());
                }
                Some(Err(e)) => return Err(e.to_string()),
            },
            n = backend.read(&mut buf) => match n {
                Ok(0) => {
                    let _ = ws_tx.close().await;
                    return Ok(());
                }
                Ok(n) => ws_tx
                    .send(Message::Binary(buf[..n].to_vec()))
                    .await
                    .map_err(|e| e.to_string())?,
                Err(e) => return Err(e.to_string()),
            },
        }
    }
}
