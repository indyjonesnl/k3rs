//! `UpgradeAwareHandler` error semantics
//! (`staging/src/k8s.io/apimachinery/pkg/util/proxy/upgradeaware.go`:
//! `ServeHTTP` :213-220, `tryUpgrade` :309-415; tests
//! `TestProxyUpgradeErrorResponse` :667, `TestProxyUpgradeConnectionErrorResponse`
//! :562, `TestProxyUpgradeErrorResponseTerminates` :608).

use axum::extract::Request;
use axum::routing::any;
use axum::Router;
use hyper_util::client::legacy::connect::HttpConnector;
use kubernetes_rs_streamproxy::proxy_upgrade_with;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A proxy in front of `backend`; returns its address.
async fn proxy_to(backend: SocketAddr) -> SocketAddr {
    let app = Router::new().fallback(any(move |req: Request| async move {
        let target = format!("http://{backend}/x").parse().unwrap();
        proxy_upgrade_with(target, req, HttpConnector::new()).await
    }));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    addr
}

/// A backend that reads one request head, stores it, and writes `reply`.
async fn backend(
    reply: &'static str,
    keep_open: bool,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = s.read(&mut buf).await.unwrap();
        let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
        s.write_all(reply.as_bytes()).await.unwrap();
        if keep_open {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    (addr, rx)
}

const UPGRADE: &str =
    "GET /p HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n";

/// Send `req` and collect the response until the connection closes or goes
/// quiet (an HTTP/1.1 error response keeps the connection alive).
async fn roundtrip(proxy: SocketAddr, req: &str) -> String {
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(700), c.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&out).to_string()
}

#[tokio::test]
async fn proxy_upgrade_errors_non_upgrade_request_is_bad_request() {
    let (b, _) = backend("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n", false).await;
    let p = proxy_to(b).await;
    let r = roundtrip(p, "GET /p HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert!(r.starts_with("HTTP/1.1 400"), "{r}");
    assert!(r.contains(r#""message":"Upgrade request required""#), "{r}");
    assert!(r.contains(r#""reason":"BadRequest""#), "{r}");
}

#[tokio::test]
async fn proxy_upgrade_errors_backend_success_without_upgrade_is_an_error() {
    let (b, _) = backend(
        "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        false,
    )
    .await;
    let p = proxy_to(b).await;
    let r = roundtrip(p, UPGRADE).await;
    assert!(r.starts_with("HTTP/1.1 500"), "{r}");
    assert!(
        r.contains("invalid upgrade response: status code 200"),
        "{r}"
    );
    assert!(r.contains(r#""kind":"Status""#), "{r}");
}

#[tokio::test]
async fn proxy_upgrade_errors_backend_error_status_is_forwarded() {
    let (b, _) = backend(
        "HTTP/1.1 403 Forbidden\r\ncontent-length: 4\r\nconnection: close\r\n\r\nnope",
        false,
    )
    .await;
    let p = proxy_to(b).await;
    let r = roundtrip(p, UPGRADE).await;
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    assert!(r.ends_with("nope"), "{r}");
}

#[tokio::test]
async fn proxy_upgrade_errors_dial_failure_is_a_status() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap();
    drop(l);
    let p = proxy_to(dead).await;
    let r = roundtrip(p, UPGRADE).await;
    assert!(r.starts_with("HTTP/1.1 500"), "{r}");
    assert!(r.contains("error dialing backend"), "{r}");
}

#[tokio::test]
async fn proxy_upgrade_errors_forwards_x_forwarded_for() {
    let (b, head) = backend(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n",
        false,
    )
    .await;
    let p = proxy_to(b).await;
    let _ = roundtrip(p, UPGRADE).await;
    let head = head.await.unwrap().to_ascii_lowercase();
    assert!(head.contains("x-forwarded-for: 127.0.0.1"), "{head}");
}

#[tokio::test]
async fn proxy_upgrade_errors_splice_ends_when_either_half_ends() {
    // Backend upgrades and then closes; the client half stays open. Upstream
    // tears the connection down as soon as one half ends.
    let (b, _) = backend(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n",
        false,
    )
    .await;
    let p = proxy_to(b).await;
    let mut c = TcpStream::connect(p).await.unwrap();
    c.write_all(UPGRADE.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let done = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await;
    assert!(done.is_ok(), "client side was not torn down");
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 101"));
}
