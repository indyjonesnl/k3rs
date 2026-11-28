//! Ports of the credential-cache parts of `client-go/.../exec/exec_test.go`
//! (`TestRoundTripper` caching/expiry/refresh-on-401 semantics via
//! `getCreds` / `maybeRefreshCreds`, `TestTLSCredentials` validation).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use kubernetes_rs_client::exec_auth::*;

const V1: &str = "client.authentication.k8s.io/v1";

fn plugin(dir: &Path, body: &str) -> String {
    let p = dir.join("p");
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p.to_string_lossy().into_owned()
}

fn auth(command: &str) -> Authenticator {
    let c = ExecConfig {
        api_version: V1.into(),
        command: command.into(),
        interactive_mode: "Never".into(),
        ..Default::default()
    };
    Authenticator::with_terminal(&c, None, Box::new(|| false)).unwrap()
}

/// A plugin that logs each run and returns token "tok-<run number>".
fn counting_plugin(dir: &Path, extra_status: &str) -> String {
    let log = dir.join("runs");
    plugin(
        dir,
        &format!(
            "echo x >> {log}\nn=$(wc -l < {log} | tr -d ' ')\ncat <<EOF\n{{\"kind\":\"ExecCredential\",\"apiVersion\":\"{V1}\",\"status\":{{\"token\":\"tok-$n\"{extra_status}}}}}\nEOF",
            log = log.display()
        ),
    )
}

fn runs(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("runs"))
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

#[test]
fn exec_credential_cache_reuses_until_expired() {
    let d = tempfile::tempdir().unwrap();
    let p = counting_plugin(d.path(), r#","expirationTimestamp":"2030-01-01T00:00:00Z""#);
    let now = Arc::new(std::sync::Mutex::new(
        Utc.with_ymd_and_hms(2029, 1, 1, 0, 0, 0).unwrap(),
    ));
    let n2 = now.clone();
    let a = auth(&p).with_now(Box::new(move || *n2.lock().unwrap()));
    assert_eq!(a.get_creds().unwrap().token, "tok-1");
    assert_eq!(a.get_creds().unwrap().token, "tok-1");
    assert_eq!(runs(d.path()), 1);
    // after exp the plugin runs again
    *now.lock().unwrap() = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 1).unwrap();
    assert_eq!(a.get_creds().unwrap().token, "tok-2");
    assert_eq!(runs(d.path()), 2);
}

#[test]
fn exec_credential_cache_no_expiry_never_expires() {
    let d = tempfile::tempdir().unwrap();
    let p = counting_plugin(d.path(), "");
    let a = auth(&p);
    for _ in 0..3 {
        assert_eq!(a.get_creds().unwrap().token, "tok-1");
    }
    assert_eq!(runs(d.path()), 1);
}

/// `maybeRefreshCreds`: a 401 rotates only if the creds are still current.
#[test]
fn exec_credential_cache_refresh_on_401_unless_rotated() {
    let d = tempfile::tempdir().unwrap();
    let p = counting_plugin(d.path(), "");
    let a = auth(&p);
    let c1 = a.get_creds().unwrap();
    a.maybe_refresh_creds(&c1).unwrap();
    let c2 = a.get_creds().unwrap();
    assert_eq!((c1.token.as_str(), c2.token.as_str()), ("tok-1", "tok-2"));
    // a second 401 for the stale creds does not run the plugin again
    a.maybe_refresh_creds(&c1).unwrap();
    assert_eq!(runs(d.path()), 2);
    assert_eq!(a.get_creds().unwrap().token, "tok-2");
    // token rotation is not a certificate rotation
    assert_eq!(a.cert_rotations(), 0);
}

#[test]
fn exec_credential_cache_plugin_error_is_not_cached() {
    let d = tempfile::tempdir().unwrap();
    let p = plugin(d.path(), "exit 1");
    let a = auth(&p);
    assert!(a.get_creds().is_err());
    assert!(a.get_creds().is_err());
}

fn status_json(cert: &str, key: &str) -> String {
    serde_json::json!({"clientCertificateData": cert, "clientKeyData": key}).to_string()
}

fn pair_plugin(dir: &Path, cert: &str, key: &str) -> String {
    plugin(
        dir,
        &format!(
            "cat <<'EOF'\n{{\"kind\":\"ExecCredential\",\"apiVersion\":\"{V1}\",\"status\":{}}}\nEOF",
            status_json(cert, key)
        ),
    )
}

#[test]
fn exec_credential_tls_valid_pair_populates_leaf() {
    let d = tempfile::tempdir().unwrap();
    let kp = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["client".into()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    let a = auth(&pair_plugin(d.path(), &cert.pem(), &kp.serialize_pem()));
    let c = a.get_creds().unwrap();
    let cc = c.cert.as_ref().expect("cert parsed");
    assert!(cc.not_before < cc.not_after);
    assert!(c.token.is_empty());
}

#[test]
fn exec_credential_tls_rejects_bad_pairs() {
    let d = tempfile::tempdir().unwrap();
    let a = auth(&pair_plugin(d.path(), "not a cert", "not a key"));
    let e = a.get_creds().unwrap_err();
    assert!(
        e.starts_with("failed parsing client key/certificate: "),
        "{e}"
    );

    // a key that does not belong to the certificate
    let kp1 = rcgen::KeyPair::generate().unwrap();
    let kp2 = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["client".into()])
        .unwrap()
        .self_signed(&kp1)
        .unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let a = auth(&pair_plugin(d2.path(), &cert.pem(), &kp2.serialize_pem()));
    assert_eq!(
        a.get_creds().unwrap_err(),
        "failed parsing client key/certificate: tls: private key does not match public key"
    );
}
