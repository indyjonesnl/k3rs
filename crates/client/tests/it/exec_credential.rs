//! Ports of `client-go/plugin/pkg/client/auth/exec/exec_test.go`
//! (TestRefreshCreds, TestExecPluginEnvVars, the plugin-policy tests and the
//! install-hint rate limit) using shell-script plugins.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use kubernetes_rs_client::exec_auth::*;

fn plugin(dir: &Path, name: &str, body: &str) -> String {
    let p: PathBuf = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p.to_string_lossy().into_owned()
}

fn cfg(api: &str, command: &str) -> ExecConfig {
    ExecConfig {
        api_version: api.into(),
        command: command.into(),
        interactive_mode: "IfAvailable".into(),
        ..Default::default()
    }
}

fn auth(c: &ExecConfig, cluster: Option<Cluster>, terminal: bool) -> Authenticator {
    Authenticator::with_terminal(c, cluster, Box::new(move || terminal)).unwrap()
}

const V1: &str = "client.authentication.k8s.io/v1";
const BETA: &str = "client.authentication.k8s.io/v1beta1";

fn echo_out(api: &str, status: &str) -> String {
    format!(
        r#"cat <<'EOF'
{{"kind":"ExecCredential","apiVersion":"{api}","status":{status}}}
EOF"#
    )
}

#[test]
fn exec_credential_token_and_expiry() {
    let d = tempfile::tempdir().unwrap();
    let p = plugin(
        d.path(),
        "p",
        &echo_out(
            V1,
            r#"{"token":"foo-bar","expirationTimestamp":"2030-01-02T03:04:05Z"}"#,
        ),
    );
    let st = auth(&cfg(V1, &p), None, false).refresh_creds().unwrap();
    assert_eq!(st.token, "foo-bar");
    assert_eq!(
        st.expiration.unwrap().to_rfc3339(),
        "2030-01-02T03:04:05+00:00"
    );
}

#[test]
fn exec_credential_beta_tls_credentials() {
    let d = tempfile::tempdir().unwrap();
    let p = plugin(
        d.path(),
        "p",
        &echo_out(
            BETA,
            r#"{"clientCertificateData":"CERT","clientKeyData":"KEY"}"#,
        ),
    );
    let st = auth(&cfg(BETA, &p), None, false).refresh_creds().unwrap();
    assert_eq!(
        (
            st.client_certificate_data.as_str(),
            st.client_key_data.as_str()
        ),
        ("CERT", "KEY")
    );
    assert!(st.token.is_empty() && st.expiration.is_none());
}

/// KUBERNETES_EXEC_INFO carries spec.interactive and, when asked, the cluster.
#[test]
fn exec_credential_exec_info_env() {
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("info");
    let body = format!(
        "printf '%s' \"$KUBERNETES_EXEC_INFO\" > {}\n{}",
        out.display(),
        echo_out(V1, r#"{"token":"t"}"#)
    );
    let p = plugin(d.path(), "p", &body);

    auth(&cfg(V1, &p), None, false).refresh_creds().unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(v["kind"], "ExecCredential");
    assert_eq!(v["apiVersion"], V1);
    assert_eq!(v["spec"]["interactive"], false);
    assert!(v["spec"]["cluster"].is_null());

    let mut c = cfg(V1, &p);
    c.provide_cluster_info = true;
    let cluster = Cluster {
        server: "https://1.2.3.4".into(),
        tls_server_name: "foo".into(),
        certificate_authority_data: b"ca".to_vec(),
        ..Default::default()
    };
    auth(&c, Some(cluster), true).refresh_creds().unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(v["spec"]["interactive"], true);
    assert_eq!(v["spec"]["cluster"]["server"], "https://1.2.3.4");
    assert_eq!(v["spec"]["cluster"]["tls-server-name"], "foo");
    assert_eq!(v["spec"]["cluster"]["certificate-authority-data"], "Y2E=");
}

/// TestExecPluginEnvVars: config env is added to the plugin's environment.
#[test]
fn exec_credential_env_vars() {
    let d = tempfile::tempdir().unwrap();
    let p = plugin(
        d.path(),
        "p",
        r#"printf '{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1","status":{"token":"%s"}}' "$MY_VAR""#,
    );
    let mut c = cfg(V1, &p);
    c.env = vec![ExecEnvVar {
        name: "MY_VAR".into(),
        value: "from-config".into(),
    }];
    assert_eq!(
        auth(&c, None, false).refresh_creds().unwrap().token,
        "from-config"
    );
}

#[test]
fn exec_credential_errors() {
    let d = tempfile::tempdir().unwrap();
    let run = |api: &str, body: &str| {
        let p = plugin(d.path(), "p", body);
        auth(&cfg(api, &p), None, false)
            .refresh_creds()
            .unwrap_err()
    };
    assert!(run(V1, &echo_out(V1, "null")).contains("exec plugin didn't return a status field"));
    assert_eq!(
        run(V1, &echo_out(V1, "{}")),
        "exec plugin didn't return a token or cert/key pair"
    );
    assert_eq!(
        run(V1, &echo_out(V1, r#"{"clientCertificateData":"c"}"#)),
        "exec plugin returned only certificate or key, not both"
    );
    assert_eq!(
        run(V1, &echo_out(BETA, r#"{"token":"t"}"#)),
        format!(
            "exec plugin is configured to use API version {V1}, plugin returned version {BETA}"
        )
    );
    assert!(run(V1, "echo not-json").starts_with("decoding stdout:"));
    let e = run(V1, "exit 73");
    assert!(e.contains("failed with exit code 73"), "{e}");
}

#[test]
fn exec_credential_interactive_modes() {
    let d = tempfile::tempdir().unwrap();
    let p = plugin(d.path(), "p", &echo_out(V1, r#"{"token":"t"}"#));
    let err = |mode: &str, unavailable: bool, msg: &str, terminal: bool| {
        let mut c = cfg(V1, &p);
        c.interactive_mode = mode.into();
        c.stdin_unavailable = unavailable;
        c.stdin_unavailable_message = msg.into();
        auth(&c, None, terminal).refresh_creds().unwrap_err()
    };
    assert_eq!(
        err("Always", false, "", false),
        "exec plugin cannot support interactive mode: standard input is not a terminal"
    );
    assert_eq!(
        err("Always", true, "", true),
        "exec plugin cannot support interactive mode: standard input is unavailable"
    );
    assert_eq!(
        err("Always", true, "some message", true),
        "exec plugin cannot support interactive mode: standard input is unavailable: some message"
    );
    assert_eq!(
        err("", false, "", true),
        "exec plugin cannot support interactive mode: unknown interactiveMode: \"\""
    );
    // Never / IfAvailable succeed.
    for m in ["Never", "IfAvailable"] {
        let mut c = cfg(V1, &p);
        c.interactive_mode = m.into();
        auth(&c, None, true).refresh_creds().unwrap();
    }
}

#[test]
fn exec_credential_invalid_api_version() {
    let e = Authenticator::new(&cfg("bogus/v9", "x"), None)
        .err()
        .unwrap();
    assert_eq!(e, "exec plugin: invalid apiVersion \"bogus/v9\"");
}

/// exec.go:548 wrapCmdRunErrorLocked: a missing binary names the command, adds
/// the verbose help and the install hint, but only `threshold` (10) times.
#[test]
fn exec_credential_install_hint_is_rate_limited() {
    let mut c = cfg(V1, "/nonexistent/plugin-bin");
    c.install_hint = "some install hint".into();
    let a = auth(&c, None, false);
    let first = a.refresh_creds().unwrap_err();
    assert!(
        first.starts_with("exec: executable /nonexistent/plugin-bin not found"),
        "{first}"
    );
    assert!(first.contains("some install hint"));
    assert!(first.contains("client-go credential plugin that is not installed"));
    for _ in 0..9 {
        a.refresh_creds().unwrap_err();
    }
    let eleventh = a.refresh_creds().unwrap_err();
    assert_eq!(
        eleventh,
        "exec: executable /nonexistent/plugin-bin not found"
    );
}

/// ValidatePluginPolicy (exec.go:660).
#[test]
fn exec_credential_plugin_policy_validation() {
    let pol = |t: &str, l: Option<Vec<&str>>| PluginPolicy {
        policy_type: t.into(),
        allowlist: l.map(|v| {
            v.into_iter()
                .map(|n| AllowlistEntry { name: n.into() })
                .collect()
        }),
    };
    assert!(validate_plugin_policy(&pol("", None)).is_ok());
    assert!(validate_plugin_policy(&pol("AllowAll", None)).is_ok());
    assert!(validate_plugin_policy(&pol("DenyAll", None)).is_ok());
    assert!(validate_plugin_policy(&pol("AllowAll", Some(vec!["/a"])))
        .unwrap_err()
        .contains("plugin policy is \"AllowAll\" but allowlist is non-nil"));
    assert!(validate_plugin_policy(&pol("Allowlist", None))
        .unwrap_err()
        .contains("allowlist is unspecified"));
    assert!(validate_plugin_policy(&pol("Allowlist", Some(vec![])))
        .unwrap_err()
        .contains("allowlist is empty; use \"DenyAll\""));
    assert!(validate_plugin_policy(&pol("Allowlist", Some(vec![""])))
        .unwrap_err()
        .contains("empty allowlist entry #1"));
    assert!(
        validate_plugin_policy(&pol("Allowlist", Some(vec!["/a//b"])))
            .unwrap_err()
            .contains("non-normalized file path")
    );
    assert!(validate_plugin_policy(&pol("Allowlist", Some(vec!["/a/b"]))).is_ok());
    assert!(validate_plugin_policy(&pol("Nope", None))
        .unwrap_err()
        .contains("unknown plugin policy"));
}

/// exec.go:580 policy enforcement when running.
#[test]
fn exec_credential_plugin_policy_enforced() {
    let d = tempfile::tempdir().unwrap();
    let p = plugin(d.path(), "p", &echo_out(V1, r#"{"token":"t"}"#));
    let other = plugin(d.path(), "other", &echo_out(V1, r#"{"token":"t"}"#));

    let mut c = cfg(V1, &p);
    c.plugin_policy.policy_type = "DenyAll".into();
    let e = auth(&c, None, false).refresh_creds().unwrap_err();
    assert_eq!(
        e,
        format!("plugin {p:?} not allowed: policy set to \"DenyAll\"")
    );

    let mut c = cfg(V1, &p);
    c.plugin_policy = PluginPolicy {
        policy_type: "Allowlist".into(),
        allowlist: Some(vec![AllowlistEntry { name: p.clone() }]),
    };
    assert_eq!(auth(&c, None, false).refresh_creds().unwrap().token, "t");

    let mut c = cfg(V1, &other);
    c.plugin_policy = PluginPolicy {
        policy_type: "Allowlist".into(),
        allowlist: Some(vec![AllowlistEntry { name: p.clone() }]),
    };
    let e = auth(&c, None, false).refresh_creds().unwrap_err();
    assert_eq!(
        e,
        format!("plugin path {other:?} is not permitted by the credential plugin allowlist")
    );
}
