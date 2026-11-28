//! `roundTripper.RoundTrip` (client-go plugin/pkg/client/auth/exec/exec.go:346)
//! wired into `ApiClient`: Bearer from the plugin, and the 401 refresh.

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use kubernetes_rs_client::exec_auth::{Authenticator, ExecConfig};
use kubernetes_rs_client::http::ApiClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const V1: &str = "client.authentication.k8s.io/v1";

/// Serve `statuses` in order, one per connection; record each Authorization.
async fn server(statuses: Vec<u16>) -> (String, Arc<Mutex<Vec<String>>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    tokio::spawn(async move {
        for code in statuses {
            let (mut sock, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let auth = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .unwrap_or("")
                .to_string();
            s2.lock().unwrap().push(auth);
            let body = "{}";
            let resp = format!(
                "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });
    (format!("http://{addr}"), seen)
}

fn counting_auth(dir: &std::path::Path) -> Arc<Authenticator> {
    let log = dir.join("runs");
    let p = dir.join("p");
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\necho x >> {log}\nn=$(wc -l < {log} | tr -d ' ')\ncat <<EOF\n{{\"kind\":\"ExecCredential\",\"apiVersion\":\"{V1}\",\"status\":{{\"token\":\"tok-$n\"}}}}\nEOF\n",
            log = log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    let c = ExecConfig {
        api_version: V1.into(),
        command: p.to_string_lossy().into_owned(),
        interactive_mode: "Never".into(),
        ..Default::default()
    };
    Arc::new(Authenticator::with_terminal(&c, None, Box::new(|| false)).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_credential_bearer_sent_and_refreshed_on_401() {
    let d = tempfile::tempdir().unwrap();
    let (url, seen) = server(vec![401, 200]).await;
    let c = ApiClient::new(&url, false, None)
        .unwrap()
        .with_exec_authenticator(counting_auth(d.path()));
    let _ = c.get::<serde_json::Value>("/api").await;
    let _ = c.get::<serde_json::Value>("/api").await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].ends_with("Bearer tok-1"), "{seen:?}");
    // 401 -> maybeRefreshCreds re-ran the plugin: next request carries tok-2.
    assert!(seen[1].ends_with("Bearer tok-2"), "{seen:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_credential_existing_authorization_passes_through() {
    let d = tempfile::tempdir().unwrap();
    let (url, seen) = server(vec![200]).await;
    let c = ApiClient::new(&url, false, Some("static".into()))
        .unwrap()
        .with_exec_authenticator(counting_auth(d.path()));
    let _ = c.get::<serde_json::Value>("/api").await;
    assert!(seen.lock().unwrap()[0].ends_with("Bearer static"));
    assert!(!d.path().join("runs").exists(), "plugin must not run");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_credential_plugin_failure_is_getting_credentials_error() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("p");
    std::fs::write(&p, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    let c = ExecConfig {
        api_version: V1.into(),
        command: p.to_string_lossy().into_owned(),
        interactive_mode: "Never".into(),
        ..Default::default()
    };
    let a = Arc::new(Authenticator::with_terminal(&c, None, Box::new(|| false)).unwrap());
    let (url, seen) = server(vec![]).await;
    let c = ApiClient::new(&url, false, None)
        .unwrap()
        .with_exec_authenticator(a);
    let e = c.get::<serde_json::Value>("/api").await.unwrap_err();
    assert!(format!("{e:?}").contains("getting credentials"), "{e:?}");
    assert!(seen.lock().unwrap().is_empty());
}
