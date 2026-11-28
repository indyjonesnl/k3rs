//! Ported from `client-go/tools/clientcmd/loader_test.go`: TestNonExistent
//! CommandLineFile, TestToleratingMissingFiles, TestWarningMissingFiles,
//! TestErrorReadingFile, TestErrorReadingNonFile, TestConflictingCurrentContext,
//! TestLoadingEmptyMaps, TestDuplicate{Cluster,Context,User}Name,
//! TestResolveRelativePaths, TestMigratingFile*, TestDeduplicate (via
//! KUBECONFIG), TestLoadingGetLoadingPrecedence, plus the first-file-wins merge
//! of `Load` (Example_mergingEverythingNoConflicts / Example_mergingSomeWithConflict).
use kubernetes_rs_client::kubeconfig::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

static ENV: Mutex<()> = Mutex::new(());

fn write(dir: &std::path::Path, name: &str, yaml: &str) -> String {
    let p = dir.join(name);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, yaml).unwrap();
    p.to_string_lossy().into_owned()
}

fn cfg(clusters: &[(&str, &str)], users: &[(&str, &str)], current: &str) -> String {
    let mut y = String::from("apiVersion: v1\nkind: Config\n");
    if !current.is_empty() {
        y += &format!("current-context: {current}\n");
    }
    if !clusters.is_empty() {
        y += "clusters:\n";
        for (n, s) in clusters {
            y += &format!("- name: {n}\n  cluster:\n    server: {s}\n");
        }
    }
    if !users.is_empty() {
        y += "users:\n";
        for (n, t) in users {
            y += &format!("- name: {n}\n  user:\n    token: {t}\n");
        }
    }
    y
}

fn rules(precedence: Vec<String>) -> LoadingRules {
    LoadingRules {
        precedence,
        ..Default::default()
    }
}

#[test]
fn kubeconfig_loading_nonexistent_explicit_file() {
    let r = LoadingRules {
        explicit_path: "bogus_file".into(),
        ..Default::default()
    };
    let e = r.load().unwrap_err().to_string();
    assert!(e.contains("bogus_file"), "{e}");
}

#[test]
fn kubeconfig_loading_tolerates_and_warns_about_missing_files() {
    let warnings = Arc::new(Mutex::new(Vec::<String>::new()));
    let w = warnings.clone();
    let r = LoadingRules {
        precedence: vec!["bogus1".into(), "bogus2".into(), "bogus3".into()],
        warn_if_all_missing: true,
        warner: Some(Arc::new(move |m| w.lock().unwrap().push(m.to_string()))),
        ..Default::default()
    };
    r.load().unwrap();
    assert_eq!(
        warnings.lock().unwrap().as_slice(),
        ["Config not found: bogus1, bogus2, bogus3"]
    );
    // No warning unless asked for.
    let w2 = warnings.clone();
    let r = LoadingRules {
        precedence: vec!["bogus".into()],
        warner: Some(Arc::new(move |m| w2.lock().unwrap().push(m.to_string()))),
        ..Default::default()
    };
    r.load().unwrap();
    assert_eq!(warnings.lock().unwrap().len(), 1);
}

#[test]
fn kubeconfig_loading_error_reading_file_and_non_file() {
    let d = tempfile::tempdir().unwrap();
    let f = write(d.path(), "bad", "bogus value");
    let e = LoadingRules {
        explicit_path: f.clone(),
        ..Default::default()
    }
    .load()
    .unwrap_err()
    .to_string();
    assert!(e.contains(&f), "{e}");
    let dir = d.path().to_string_lossy().into_owned();
    let e = LoadingRules {
        explicit_path: dir.clone(),
        ..Default::default()
    }
    .load()
    .unwrap_err()
    .to_string();
    assert!(e.contains(&dir), "{e}");
}

#[test]
fn kubeconfig_loading_explicit_path_is_not_merged() {
    let d = tempfile::tempdir().unwrap();
    let cmd = write(d.path(), "cmd", "current-context: any-context-value\n");
    let env = write(d.path(), "env", "current-context: a-different-context\n");
    let r = LoadingRules {
        explicit_path: cmd,
        precedence: vec![env],
        ..Default::default()
    };
    assert_eq!(r.load().unwrap().current_context, "any-context-value");
}

#[test]
fn kubeconfig_loading_empty_maps() {
    let d = tempfile::tempdir().unwrap();
    let f = write(d.path(), "c", "current-context: any-context-value\n");
    let c = KubeConfig::load_from_file(&PathBuf::from(f)).unwrap();
    assert_eq!(c.current_context, "any-context-value");
    assert!(c.clusters.is_empty() && c.users.is_empty() && c.contexts.is_empty());
}

#[test]
fn kubeconfig_loading_duplicate_names() {
    let dup = |section: &str| {
        format!(
            "kind: Config\napiVersion: v1\n{section}:\n- name: dup\n  {key}: {{}}\n- name: dup\n  {key}: {{}}\n",
            key = match section {
                "clusters" => "cluster",
                "contexts" => "context",
                _ => "user",
            }
        )
    };
    for (section, want) in [
        ("clusters", "error converting *[]NamedCluster into *map[string]*api.Cluster: duplicate name \"dup\" in list"),
        ("contexts", "error converting *[]NamedContext into *map[string]*api.Context: duplicate name \"dup\" in list"),
        ("users", "error converting *[]NamedAuthInfo into *map[string]*api.AuthInfo: duplicate name \"dup\" in list"),
    ] {
        let e = KubeConfig::parse(&dup(section)).unwrap_err();
        assert!(e.contains(want), "{e}");
    }
}

#[test]
fn kubeconfig_loading_resolve_relative_paths() {
    let d = tempfile::tempdir().unwrap();
    let dir1 = d.path().join("one");
    let dir2 = d.path().join("two").join("inner");
    let f1 = write(
        &dir1,
        ".kubeconfig",
        r#"
clusters:
- name: relative-server-1
  cluster: { server: "https://a", certificate-authority: ../relative/ca }
- name: absolute-server-1
  cluster: { server: "https://a", certificate-authority: /absolute/ca }
users:
- name: relative-user-1
  user: { client-certificate: relative/client/cert, client-key: ../relative/client/key, tokenFile: tok/file }
- name: absolute-user-1
  user: { client-certificate: /absolute/client/cert, client-key: /absolute/client/key }
- name: relative-cmd-1
  user: { exec: { apiVersion: client.authentication.k8s.io/v1, command: ../relative/client/cmd } }
- name: absolute-cmd-1
  user: { exec: { apiVersion: client.authentication.k8s.io/v1, command: /absolute/client/cmd } }
- name: PATH-cmd-1
  user: { exec: { apiVersion: client.authentication.k8s.io/v1, command: cmd } }
"#,
    );
    let f2 = write(
        &dir2,
        ".kubeconfig",
        r#"
clusters:
- name: relative-server-2
  cluster: { server: "https://b", certificate-authority: ../relative/ca2 }
users:
- name: relative-user-2
  user: { client-certificate: relative/client/cert2, client-key: ../relative/client/key2 }
"#,
    );
    let c = rules(vec![f1, f2]).load().unwrap();
    let cl = |n: &str| {
        c.clusters
            .iter()
            .find(|x| x.name == n)
            .unwrap()
            .cluster
            .clone()
    };
    let us = |n: &str| c.users.iter().find(|x| x.name == n).unwrap().user.clone();
    let s = |p: PathBuf| p.to_string_lossy().into_owned();
    assert_eq!(
        cl("relative-server-1").certificate_authority.unwrap(),
        s(d.path().join("relative/ca"))
    );
    assert_eq!(
        cl("absolute-server-1").certificate_authority.unwrap(),
        "/absolute/ca"
    );
    assert_eq!(
        cl("relative-server-2").certificate_authority.unwrap(),
        s(d.path().join("two/relative/ca2"))
    );
    let u = us("relative-user-1");
    assert_eq!(
        u.client_certificate.unwrap(),
        s(dir1.join("relative/client/cert"))
    );
    assert_eq!(
        u.client_key.unwrap(),
        s(d.path().join("relative/client/key"))
    );
    assert_eq!(u.token_file.unwrap(), s(dir1.join("tok/file")));
    let u = us("relative-user-2");
    assert_eq!(
        u.client_certificate.unwrap(),
        s(dir2.join("relative/client/cert2"))
    );
    assert_eq!(
        u.client_key.unwrap(),
        s(d.path().join("two/relative/client/key2"))
    );
    assert_eq!(
        us("absolute-user-1").client_key.unwrap(),
        "/absolute/client/key"
    );
    assert_eq!(
        us("relative-cmd-1").exec.unwrap().command,
        s(d.path().join("relative/client/cmd"))
    );
    assert_eq!(
        us("absolute-cmd-1").exec.unwrap().command,
        "/absolute/client/cmd"
    );
    assert_eq!(us("PATH-cmd-1").exec.unwrap().command, "cmd");
    assert_eq!(c.clusters.len() + c.users.len(), 3 + 6);

    // DoNotResolvePaths keeps them as written.
    let mut r = rules(vec![f_first(&d)]);
    r.do_not_resolve_paths = true;
    let c = r.load().unwrap();
    assert_eq!(
        c.clusters[0].cluster.certificate_authority.as_deref(),
        Some("../relative/ca")
    );
}

fn f_first(d: &tempfile::TempDir) -> String {
    d.path()
        .join("one")
        .join(".kubeconfig")
        .to_string_lossy()
        .into_owned()
}

#[test]
fn kubeconfig_loading_merge_first_file_wins() {
    let d = tempfile::tempdir().unwrap();
    let a = write(
        d.path(),
        "a",
        &cfg(
            &[("cow", "http://cow.org"), ("horse", "http://horse.org")],
            &[("red", "red-token")],
            "",
        ),
    );
    let b = write(
        d.path(),
        "b",
        &cfg(
            &[
                ("cow", "http://a-different-cow.org"),
                ("donkey", "http://donkey.org"),
            ],
            &[("red", "a-different-red-token"), ("yellow", "yellow-token")],
            "federal-context",
        ),
    );
    let c = rules(vec![a, b]).load().unwrap();
    let server = |n: &str| {
        c.clusters
            .iter()
            .find(|x| x.name == n)
            .unwrap()
            .cluster
            .server
            .clone()
    };
    // first file wins; entries are never combined
    assert_eq!(server("cow"), "http://cow.org");
    assert_eq!(server("horse"), "http://horse.org");
    assert_eq!(server("donkey"), "http://donkey.org");
    let tok = |n: &str| {
        c.users
            .iter()
            .find(|x| x.name == n)
            .unwrap()
            .user
            .token
            .clone()
    };
    assert_eq!(tok("red").as_deref(), Some("red-token"));
    assert_eq!(tok("yellow").as_deref(), Some("yellow-token"));
    // a value unset in the first file comes from the next one
    assert_eq!(c.current_context, "federal-context");
    // an empty entry in the precedence list is skipped
    assert_eq!(rules(vec![String::new()]).load().unwrap().clusters.len(), 0);
}

#[test]
fn kubeconfig_loading_migrating_file() {
    let d = tempfile::tempdir().unwrap();
    let src = write(d.path(), "source", &cfg(&[("a", "http://a")], &[], ""));
    let dest = d.path().join("dest").to_string_lossy().into_owned();
    let r = LoadingRules {
        migration_rules: vec![(dest.clone(), src.clone())],
        ..Default::default()
    };
    r.load().unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), std::fs::read(&src).unwrap());

    // An existing destination is left alone.
    let existing = write(d.path(), "existing", "");
    let r = LoadingRules {
        migration_rules: vec![(existing.clone(), src)],
        ..Default::default()
    };
    r.load().unwrap();
    assert!(std::fs::read(&existing).unwrap().is_empty());

    // A missing source is skipped.
    let dest2 = d.path().join("dest2").to_string_lossy().into_owned();
    let r = LoadingRules {
        migration_rules: vec![(dest2.clone(), "some-missing-file".into())],
        ..Default::default()
    };
    r.load().unwrap();
    assert!(!std::path::Path::new(&dest2).exists());
}

#[test]
fn kubeconfig_loading_precedence_from_env() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let home = std::env::var("HOME").unwrap();
    let home_cfg = format!("{home}/.kube/config");
    let case = |env: Option<&str>| {
        match env {
            Some(v) => std::env::set_var("KUBECONFIG", v),
            None => std::env::remove_var("KUBECONFIG"),
        }
        LoadingRules::new_default().unwrap()
    };
    assert_eq!(case(None).loading_precedence(), vec![home_cfg.clone()]);
    assert_eq!(case(Some("")).loading_precedence(), vec![home_cfg]);
    assert_eq!(
        case(Some("/env/kubeconfig")).loading_precedence(),
        vec!["/env/kubeconfig"]
    );
    assert_eq!(
        case(Some("/env/kubeconfig:/other/kubeconfig")).loading_precedence(),
        vec!["/env/kubeconfig", "/other/kubeconfig"]
    );
    // TestDeduplicate: the same path is loaded once.
    assert_eq!(
        case(Some("a:b:c:b:e:f")).loading_precedence(),
        vec!["a", "b", "c", "e", "f"]
    );
    assert_eq!(
        case(Some("a:a:b:b:c:b")).loading_precedence(),
        vec!["a", "b", "c"]
    );
    assert!(case(Some("a:b")).warn_if_all_missing);

    // explicit path wins over the chain.
    let r = LoadingRules {
        explicit_path: "/explicit/kubeconfig".into(),
        ..Default::default()
    };
    assert_eq!(r.loading_precedence(), vec!["/explicit/kubeconfig"]);

    // GetDefaultFilename: first existing file, else the first entry.
    let d = tempfile::tempdir().unwrap();
    let second = write(d.path(), "second", "");
    let r = rules(vec!["/nonexistent/one".into(), second.clone()]);
    assert_eq!(r.default_filename(), second);
    let r = rules(vec!["/nonexistent/one".into(), "/nonexistent/two".into()]);
    assert_eq!(r.default_filename(), "/nonexistent/one");
    std::env::remove_var("KUBECONFIG");
}
