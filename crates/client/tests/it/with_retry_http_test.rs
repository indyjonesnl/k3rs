//! `ApiClient` honours `Retry-After` on 429 / 5xx (rest/request.go
//! `request()` retry loop with `withRetry`), but never for a non-GET error.

use kubernetes_rs_client::http::ApiClient;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serve `responses` (status, extra headers, body) in order on 127.0.0.1.
async fn serve(responses: Vec<(u16, &'static str, &'static str)>) -> (String, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let n = h.fetch_add(1, Ordering::SeqCst);
            let (code, hdr, body) = responses[n.min(responses.len() - 1)];
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let r = format!(
                    "HTTP/1.1 {code} X\r\n{hdr}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(r.as_bytes()).await;
            });
        }
    });
    (format!("http://{addr}"), hits)
}

#[tokio::test]
async fn with_retry_get_retries_429_with_retry_after() {
    let (url, hits) = serve(vec![
        (429, "Retry-After: 0\r\n", "{}"),
        (503, "Retry-After: 0\r\n", "{}"),
        (200, "", r#"{"ok":true}"#),
    ])
    .await;
    let c = ApiClient::new(&url, false, None).unwrap();
    let v: serde_json::Value = c.get("/x").await.unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn with_retry_no_retry_without_retry_after() {
    let (url, hits) = serve(vec![(503, "", "{}"), (200, "", "{}")]).await;
    let c = ApiClient::new(&url, false, None).unwrap();
    assert!(c.get::<serde_json::Value>("/x").await.is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn with_retry_gives_up_after_ten_retries() {
    let (url, hits) = serve(vec![(429, "Retry-After: 0\r\n", "{}")]).await;
    let c = ApiClient::new(&url, false, None).unwrap();
    assert!(c.get::<serde_json::Value>("/x").await.is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 11);
}
