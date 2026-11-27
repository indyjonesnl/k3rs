//! Tests for `kubernetes_rs_kubectl::config_flags`, after client-go
//! `clientcmd/loader_test.go` (TestConflictingCurrentContext, TestDeduplicate,
//! TestLoadingGetLoadingPrecedence, TestResolveRelativePaths,
//! TestWarningMissingFiles) and `client_config_test.go` (override precedence).

mod config_flags {
    use clap::Parser;
    use kubernetes_rs_kubectl::config_flags::*;
    use std::path::Path;
    use std::time::Duration;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        flags: ConfigFlags,
    }

    fn flags(args: &[&str]) -> ConfigFlags {
        let mut v = vec!["kubectl"];
        v.extend_from_slice(args);
        Cli::try_parse_from(v).unwrap().flags
    }

    fn write(dir: &Path, name: &str, body: &str) -> String {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().into_owned()
    }

    const A: &str = "
apiVersion: v1
kind: Config
current-context: ctx-a
clusters:
- name: c1
  cluster: {server: 'https://a.example:6443', certificate-authority: ca.crt, tls-server-name: from-file}
contexts:
- name: ctx-a
  context: {cluster: c1, user: u1, namespace: ns-a}
users:
- name: u1
  user: {token: file-token, client-certificate: cert.pem, client-key: key.pem, as: file-as}
";
    const B: &str = "
current-context: ctx-b
clusters:
- name: c1
  cluster: {server: 'https://b.example:6443'}
- name: c2
  cluster: {server: 'https://c2.example:6443'}
contexts:
- name: ctx-b
  context: {cluster: c2, user: u1}
";

    #[test]
    fn config_flags_parse_names_and_short_forms() {
        let f = flags(&[
            "-n",
            "ns",
            "-s",
            "https://x",
            "--as",
            "bob",
            "--as-group",
            "g1",
            "--as-group",
            "g2",
            "--as-uid",
            "u-1",
            "--client-certificate",
            "c",
            "--client-key",
            "k",
            "--certificate-authority",
            "ca",
            "--tls-server-name",
            "tls",
            "--request-timeout",
            "5s",
            "--username",
            "u",
            "--password",
            "p",
            "--cluster",
            "c",
            "--user",
            "x",
            "--context",
            "cx",
            "--insecure-skip-tls-verify",
            "--disable-compression",
            "--cache-dir",
            "/c",
            "--kubeconfig",
            "/kc",
            "--token",
            "t",
        ]);
        assert_eq!(f.namespace.as_deref(), Some("ns"));
        assert_eq!(f.impersonate_group, ["g1", "g2"]);
        assert_eq!(f.request_timeout, "5s");
        assert!(f.insecure_skip_tls_verify && f.disable_compression);
        assert_eq!(flags(&[]).request_timeout, "0");
    }

    #[test]
    fn config_flags_loading_rules_env_list_is_split_and_deduplicated() {
        let r = LoadingRules::new_default(Some("/a:/b:/a::/c"), Some(Path::new("/home/x")));
        // filepath.SplitList keeps the empty entry; Load skips it.
        assert_eq!(r.precedence, ["/a", "/b", "", "/c"]);
        let r = LoadingRules::new_default(None, Some(Path::new("/home/x")));
        assert_eq!(r.precedence, ["/home/x/.kube/config"]);
        let mut r = LoadingRules::new_default(Some("/a:/b"), None);
        assert_eq!(r.loading_precedence(), ["/a", "/b"]);
        r.explicit_path = "/explicit".into();
        assert_eq!(r.loading_precedence(), ["/explicit"]);
    }

    #[test]
    fn config_flags_load_merges_first_file_wins_and_resolves_relative_paths() {
        let d = tempfile::tempdir().unwrap();
        let a = write(d.path(), "a", A);
        let b = write(d.path(), "b", B);
        let rules = LoadingRules {
            explicit_path: String::new(),
            precedence: vec![a, String::new(), "/nonexistent/kubeconfig".into(), b],
        };
        let c = rules.load().unwrap();
        // current-context: the first file that sets one.
        assert_eq!(c.current_context, "ctx-a");
        // c1 is defined by both files: the first definition is used whole.
        assert_eq!(c.clusters["c1"].server, "https://a.example:6443");
        // c2 only exists in the second file.
        assert_eq!(c.clusters["c2"].server, "https://c2.example:6443");
        assert!(c.contexts.contains_key("ctx-a") && c.contexts.contains_key("ctx-b"));
        // Relative file references resolve against the kubeconfig's directory.
        let base = d.path().to_string_lossy();
        assert_eq!(
            c.clusters["c1"].certificate_authority,
            format!("{base}/ca.crt")
        );
        assert_eq!(
            c.auth_infos["u1"].client_certificate,
            format!("{base}/cert.pem")
        );
        assert_eq!(c.auth_infos["u1"].client_key, format!("{base}/key.pem"));
    }

    #[test]
    fn config_flags_load_explicit_path_must_exist_and_bad_files_are_errors() {
        let r = LoadingRules {
            explicit_path: "/nonexistent/kc".into(),
            precedence: vec![],
        };
        assert_eq!(
            r.load().unwrap_err(),
            "stat /nonexistent/kc: no such file or directory"
        );
        let d = tempfile::tempdir().unwrap();
        let bad = write(d.path(), "bad", "clusters: [unterminated");
        let r = LoadingRules {
            explicit_path: String::new(),
            precedence: vec![bad.clone()],
        };
        let e = r.load().unwrap_err();
        assert!(
            e.contains(&format!("error loading config file \"{bad}\"")),
            "{e}"
        );
    }

    fn loaded() -> Config {
        let d = tempfile::tempdir().unwrap();
        let a = write(d.path(), "a", A);
        let b = write(d.path(), "b", B);
        let c = LoadingRules {
            explicit_path: String::new(),
            precedence: vec![a, b],
        }
        .load()
        .unwrap();
        d.close().ok();
        c
    }

    #[test]
    fn config_flags_resolve_without_overrides_uses_current_context() {
        let r = resolve(&loaded(), &ConfigOverrides::default()).unwrap();
        assert_eq!(r.cluster.server, "https://a.example:6443");
        assert_eq!(r.namespace, "ns-a");
        assert_eq!(r.auth_info.token, "file-token");
        assert_eq!(r.timeout, None);
    }

    #[test]
    fn config_flags_resolve_overrides_win_and_server_clears_tls_server_name() {
        let ov = flags(&[
            "--server",
            "https://override:1",
            "--token",
            "flag-token",
            "--as",
            "bob",
            "--as-group",
            "g",
            "-n",
            "other",
            "--request-timeout",
            "2m",
        ])
        .to_overrides();
        let r = resolve(&loaded(), &ov).unwrap();
        assert_eq!(r.cluster.server, "https://override:1");
        // --server without --tls-server-name clears the file's value.
        assert_eq!(r.cluster.tls_server_name, "");
        assert_eq!(r.auth_info.token, "flag-token");
        assert_eq!(r.auth_info.impersonate, "bob");
        assert_eq!(r.namespace, "other");
        assert_eq!(r.timeout, Some(Duration::from_secs(120)));
        let ov = flags(&["--tls-server-name", "x"]).to_overrides();
        assert_eq!(
            resolve(&loaded(), &ov).unwrap().cluster.tls_server_name,
            "x"
        );
    }

    #[test]
    fn config_flags_resolve_insecure_clears_ca_and_ca_flag_clears_insecure() {
        let r = resolve(
            &loaded(),
            &flags(&["--insecure-skip-tls-verify"]).to_overrides(),
        )
        .unwrap();
        assert!(r.cluster.insecure_skip_tls_verify);
        assert_eq!(r.cluster.certificate_authority, "");
        let r = resolve(
            &loaded(),
            &flags(&["--certificate-authority", "/my/ca"]).to_overrides(),
        )
        .unwrap();
        assert_eq!(r.cluster.certificate_authority, "/my/ca");
        assert!(!r.cluster.insecure_skip_tls_verify);
    }

    #[test]
    fn config_flags_resolve_named_context_cluster_user_must_exist() {
        let c = loaded();
        let e = |a: &[&str]| resolve(&c, &flags(a).to_overrides()).unwrap_err();
        assert_eq!(e(&["--context", "nope"]), "context \"nope\" does not exist");
        assert_eq!(e(&["--cluster", "nope"]), "cluster \"nope\" does not exist");
        assert_eq!(e(&["--user", "nope"]), "auth info \"nope\" does not exist");
        let r = resolve(&c, &flags(&["--context", "ctx-b"]).to_overrides()).unwrap();
        assert_eq!(r.cluster.server, "https://c2.example:6443");
        assert_eq!(r.namespace, "default");
        // An invalid timeout is rejected with upstream's message.
        assert!(e(&["--request-timeout", "soon"]).starts_with("Invalid timeout value."));
    }

    #[test]
    fn config_flags_client_cert_flag_replaces_file_and_data() {
        let mut c = loaded();
        c.auth_infos.get_mut("u1").unwrap().client_certificate_data = "ZGF0YQ==".into();
        let r = resolve(
            &c,
            &flags(&["--client-certificate", "/my/cert"]).to_overrides(),
        )
        .unwrap();
        assert_eq!(r.auth_info.client_certificate, "/my/cert");
        assert_eq!(r.auth_info.client_certificate_data, "");
    }

    #[test]
    fn config_flags_parse_timeout_matches_clientcmd() {
        assert_eq!(parse_timeout("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_timeout("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_timeout("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_timeout("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_timeout("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_timeout("500ms").unwrap(), Duration::from_millis(500));
        for bad in ["-1", "-1s", "abc", "1x", "s", ""] {
            assert!(parse_timeout(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn config_flags_impersonation_headers() {
        let r = resolve(
            &loaded(),
            &flags(&[
                "--as",
                "bob",
                "--as-uid",
                "42",
                "--as-group",
                "g1",
                "--as-group",
                "g2",
                "--as-user-extra",
                "scopes=a",
                "--as-user-extra",
                "scopes=b",
                "--as-user-extra",
                "a/b=c",
                "--as-user-extra",
                "novalue",
            ])
            .to_overrides(),
        )
        .unwrap();
        let h = r.auth_info.impersonation_headers();
        let get = |k: &str| -> Vec<&str> {
            h.iter()
                .filter(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
                .collect()
        };
        assert_eq!(get("Impersonate-User"), ["bob"]);
        assert_eq!(get("Impersonate-Uid"), ["42"]);
        assert_eq!(get("Impersonate-Group"), ["g1", "g2"]);
        assert_eq!(get("Impersonate-Extra-scopes"), ["a", "b"]);
        // the key is %-escaped like transport.headerKeyEscape
        assert_eq!(get("Impersonate-Extra-a%2Fb"), ["c"]);
        assert!(h.iter().all(|(n, _)| !n.contains("novalue")));
        // No impersonation configured: no headers at all.
        let none = resolve(&loaded(), &ConfigOverrides::default()).unwrap();
        // (the fixture's user has `as: file-as`, so strip it for the negative case)
        let mut a = none.auth_info;
        a.impersonate.clear();
        assert!(a.impersonation_headers().is_empty());
    }
}
