//! Ports of apiserver `util/proxy/streamtunnel_test.go`:
//! TestTunnelingHandler_UpgradeStreamingAndTunneling,
//! _BadRequestWithoutProtcols, _BadHandshakeError,
//! _UpstreamSPDYServerErrorPropagated, plus the missing-upgrade-header case of
//! `tunnelingWebsocketUpgraderConn.InitializeWrite`.

use futures::{SinkExt, StreamExt};
use kubernetes_rs_streamproxy::tunnel::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// Fake kubelet: reads one request head, replies with `reply`, and (for a 101)
/// echoes upper-cased bytes. Returns its address and the request head it saw.
async fn backend(
    reply: &'static str,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read(&mut b).await.unwrap() == 0 {
                return;
            }
            head.push(b[0]);
        }
        let _ = tx.send(String::from_utf8_lossy(&head).to_string());
        s.write_all(reply.as_bytes()).await.unwrap();
        if reply.starts_with("HTTP/1.1 101") {
            let mut buf = [0u8; 4096];
            while let Ok(n) = s.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n].to_ascii_uppercase()).await.unwrap();
            }
        }
    });
    (addr, rx)
}

async fn tunnel_server(backend: std::net::SocketAddr) -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let target: http::Uri = format!("http://{backend}/portforward").parse().unwrap();
    tokio::spawn(async move {
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let t = target.clone();
            async move { tunneling_handler(t, req).await }
        });
        axum::serve(l, app).await.unwrap();
    });
    addr
}

fn ws_request(addr: std::net::SocketAddr, protocols: Option<&str>) -> http::Request<()> {
    let mut req = format!("ws://{addr}/portforward")
        .into_client_request()
        .unwrap();
    if let Some(p) = protocols {
        req.headers_mut()
            .insert("Sec-WebSocket-Protocol", p.parse().unwrap());
    }
    req
}

const SPDY_OK: &str = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: portforward.k8s.io\r\n\r\n";

#[tokio::test]
async fn tunneling_handler_upgrade_streaming_and_tunneling() {
    let (b, seen) = backend(SPDY_OK).await;
    let addr = tunnel_server(b).await;
    let (ws, resp) =
        tokio_tungstenite::connect_async(ws_request(addr, Some("SPDY/3.1+portforward.k8s.io")))
            .await
            .unwrap();
    assert_eq!(resp.status(), 101);
    assert_eq!(
        resp.headers()["sec-websocket-protocol"],
        "SPDY/3.1+portforward.k8s.io"
    );

    // createSPDYRequest: websocket headers gone, SPDY upgrade headers set.
    let head = seen.await.unwrap().to_ascii_lowercase();
    assert!(head.starts_with("post /portforward "), "{head}");
    assert!(head.contains("upgrade: spdy/3.1"), "{head}");
    assert!(
        head.contains("x-stream-protocol-version: portforward.k8s.io"),
        "{head}"
    );
    assert!(!head.contains("sec-websocket"), "{head}");

    // SPDY bytes survive the tunnel in both directions (binary messages).
    let payload = vec![b'a'; 1024 * 1024];
    let send = payload.clone();
    let (mut tx, mut rx) = ws.split();
    tokio::spawn(async move {
        for chunk in send.chunks(16 * 1024) {
            tx.send(Message::Binary(chunk.to_vec())).await.unwrap();
        }
    });
    let mut got = 0;
    while got < payload.len() {
        match rx.next().await.unwrap().unwrap() {
            Message::Binary(d) => {
                assert!(d.iter().all(|c| *c == b'A'));
                got += d.len();
            }
            other => panic!("unexpected message {other:?}"),
        }
    }
    assert!(
        stream_tunnel_request_counts()
            .get(&101)
            .copied()
            .unwrap_or(0)
            >= 1
    );
}

#[tokio::test]
async fn tunneling_handler_bad_request_without_protocols() {
    // The upstream is never contacted: any address works.
    let addr = tunnel_server("127.0.0.1:9".parse().unwrap()).await;
    for protocols in [None, Some("v4.channel.k8s.io")] {
        let err = tokio_tungstenite::connect_async(ws_request(addr, protocols))
            .await
            .unwrap_err();
        match err {
            WsError::Http(r) => assert_eq!(r.status(), 400),
            other => panic!("expected an HTTP 400, got {other:?}"),
        }
    }
    assert!(
        stream_tunnel_request_counts()
            .get(&400)
            .copied()
            .unwrap_or(0)
            >= 1
    );
}

#[tokio::test]
async fn tunneling_handler_bad_handshake_error() {
    let (b, _seen) = backend("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
    let addr = tunnel_server(b).await;
    let err = tokio_tungstenite::connect_async(ws_request(
        addr,
        Some("SPDY/3.1+UNKNOWN_SUBPROTOCOL.k8s.io"),
    ))
    .await
    .unwrap_err();
    match err {
        WsError::Http(r) => assert_eq!(r.status(), 403),
        other => panic!("expected an HTTP 403, got {other:?}"),
    }
}

#[tokio::test]
async fn tunneling_handler_upstream_server_error_propagated() {
    for (reply, code) in [
        (
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
            500,
        ),
        ("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", 502),
        (
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            503,
        ),
    ] {
        let (b, _seen) = backend(reply).await;
        let addr = tunnel_server(b).await;
        let err =
            tokio_tungstenite::connect_async(ws_request(addr, Some("SPDY/3.1+portforward.k8s.io")))
                .await
                .unwrap_err();
        match err {
            WsError::Http(r) => assert_eq!(r.status(), code),
            other => panic!("expected an HTTP {code}, got {other:?}"),
        }
        assert!(
            stream_tunnel_request_counts()
                .get(&code)
                .copied()
                .unwrap_or(0)
                >= 1
        );
    }
}

#[tokio::test]
async fn tunneling_handler_backend_101_without_spdy_headers_is_500() {
    let (b, _seen) = backend(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    )
    .await;
    let addr = tunnel_server(b).await;
    let err =
        tokio_tungstenite::connect_async(ws_request(addr, Some("SPDY/3.1+portforward.k8s.io")))
            .await
            .unwrap_err();
    match err {
        WsError::Http(r) => assert_eq!(r.status(), 500),
        other => panic!("expected an HTTP 500, got {other:?}"),
    }
}

#[test]
fn tunneling_handler_protocol_helpers() {
    let mut h = http::HeaderMap::new();
    h.insert("connection", "Upgrade".parse().unwrap());
    h.insert("upgrade", "websocket".parse().unwrap());
    h.insert(
        "sec-websocket-protocol",
        "v4.channel.k8s.io, SPDY/3.1+portforward.k8s.io, SPDY/3.1+x"
            .parse()
            .unwrap(),
    );
    assert!(is_websocket_request_with_tunneling_protocol(&h));
    // The suffix is required (streamtunnel.go:116-125).
    assert_eq!(
        spdy_protocols_from_websocket_protocols(&h),
        vec!["portforward.k8s.io".to_string()]
    );
    h.remove("upgrade");
    assert!(!is_websocket_request_with_tunneling_protocol(&h));
}
