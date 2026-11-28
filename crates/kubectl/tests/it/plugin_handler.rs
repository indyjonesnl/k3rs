//! Ports of cmd_test.go `TestKubectlCommandHandlesPlugins` and
//! `TestKubectlSubcommandShadowPlugin` (pkg/cmd/cmd_test.go:68-300), driving
//! the same plugin dispatch decision with a recording handler over a
//! directory of fake plugins (testdata/kubectl-create-foo, kubectl-foo,
//! kubectl-version).
use kubernetes_rs_kubectl::plugin_handler::{
    dispatch_plugin, handle_plugin_command, is_subcommand_plugin_allowed, DefaultPluginHandler,
    FoundCommand, PluginHandler,
};
use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct TestHandler {
    dir: PathBuf,
    executed: RefCell<Option<(PathBuf, Vec<String>)>>,
}

impl PluginHandler for TestHandler {
    fn lookup(&self, filename: &str) -> Option<PathBuf> {
        let p = self.dir.join(format!("kubectl-{filename}"));
        p.exists().then_some(p)
    }
    fn execute(
        &self,
        path: &Path,
        args: &[String],
        _env: &[(String, String)],
    ) -> std::io::Result<()> {
        *self.executed.borrow_mut() = Some((path.to_path_buf(), args.to_vec()));
        Ok(())
    }
}

fn handler() -> (tempfile::TempDir, TestHandler) {
    let d = tempfile::tempdir().unwrap();
    for n in ["kubectl-create-foo", "kubectl-foo", "kubectl-version"] {
        std::fs::write(d.path().join(n), "#!/bin/sh\n").unwrap();
    }
    let h = TestHandler {
        dir: d.path().to_path_buf(),
        executed: RefCell::new(None),
    };
    (d, h)
}

fn v(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn builtin(name: &str, args: &[&str], subs: &[&str]) -> FoundCommand {
    FoundCommand {
        name: name.into(),
        args: v(args),
        subcommands: v(subs),
    }
}

#[test]
fn plugin_handler_unknown_command_runs_plugin_with_remaining_args() {
    let (_d, h) = handler();
    dispatch_plugin(&h, &v(&["kubectl", "foo", "--bar"]), None).unwrap();
    let (p, args) = h.executed.borrow().clone().unwrap();
    assert!(p.ends_with("kubectl-foo"));
    assert_eq!(args, v(&["--bar"]));
}

#[test]
fn plugin_handler_positional_args_follow_longest_match() {
    let (_d, h) = handler();
    dispatch_plugin(&h, &v(&["kubectl", "foo", "positional", "--bar"]), None).unwrap();
    let (p, args) = h.executed.borrow().clone().unwrap();
    assert!(p.ends_with("kubectl-foo"));
    assert_eq!(args, v(&["positional", "--bar"]));
}

#[test]
fn plugin_handler_builtin_command_is_not_shadowed() {
    let (_d, h) = handler();
    let found = builtin("version", &["--client=true"], &[]);
    dispatch_plugin(
        &h,
        &v(&["kubectl", "version", "--client=true"]),
        Some(&found),
    )
    .unwrap();
    assert!(h.executed.borrow().is_none());
}

#[test]
fn plugin_handler_cobra_commands_are_never_shadowed() {
    let (_d, h) = handler();
    for args in [
        vec!["kubectl", "help"],
        vec!["kubectl", "__complete", "de"],
        vec!["kubectl", "__completeNoDesc", "de"],
        vec!["kubectl", "--kubeconfig=/path/to/kubeconfig", "help"],
        vec!["kubectl", "--kubeconfig=/path/to/kubeconfig", "__complete"],
        vec![
            "kubectl",
            "--kubeconfig=/path/to/kubeconfig",
            "__completeNoDesc",
        ],
    ] {
        dispatch_plugin(&h, &v(&args), None).unwrap();
        assert!(h.executed.borrow().is_none(), "{args:?}");
    }
}

#[test]
fn plugin_handler_create_subcommand_plugin_when_no_builtin() {
    let (_d, h) = handler();
    let found = builtin(
        "create",
        &["foo", "--bar", "--namespace", "ns"],
        &["job", "secret"],
    );
    dispatch_plugin(
        &h,
        &v(&["kubectl", "create", "foo", "--bar", "--namespace", "ns"]),
        Some(&found),
    )
    .unwrap();
    let (p, args) = h.executed.borrow().clone().unwrap();
    assert!(p.ends_with("kubectl-create-foo"));
    assert_eq!(args, v(&["--bar", "--namespace", "ns"]));
}

#[test]
fn plugin_handler_create_subcommand_plugin_with_positional() {
    let (_d, h) = handler();
    let found = builtin("create", &["foo", "positional", "--bar"], &["job"]);
    dispatch_plugin(
        &h,
        &v(&["kubectl", "create", "foo", "positional", "--bar"]),
        Some(&found),
    )
    .unwrap();
    let (_, args) = h.executed.borrow().clone().unwrap();
    assert_eq!(args, v(&["positional", "--bar"]));
}

#[test]
fn plugin_handler_create_does_not_fall_back_to_kubectl_create() {
    // kubectl-create-foo2 missing: minArgs stops the search before the
    // (nonexistent here, but never-considered) kubectl-create plugin.
    let (d, h) = handler();
    std::fs::write(d.path().join("kubectl-create"), "").unwrap();
    let found = builtin("create", &["foo2", "--bar"], &["job"]);
    dispatch_plugin(
        &h,
        &v(&["kubectl", "create", "foo2", "--bar"]),
        Some(&found),
    )
    .unwrap();
    assert!(h.executed.borrow().is_none());
}

#[test]
fn plugin_handler_existing_builtin_subcommand_wins() {
    let (_d, h) = handler();
    let found = builtin("create", &["job", "foo", "--image=busybox"], &["job"]);
    dispatch_plugin(&h, &v(&["kubectl", "create", "job", "foo"]), Some(&found)).unwrap();
    assert!(h.executed.borrow().is_none());
    // `kubectl create -f x`: a flag is not a subcommand.
    let found = builtin("create", &["-f", "x"], &["job"]);
    dispatch_plugin(&h, &v(&["kubectl", "create", "-f", "x"]), Some(&found)).unwrap();
    assert!(h.executed.borrow().is_none());
}

#[test]
fn plugin_handler_flags_before_plugin_name_is_an_error() {
    let (_d, h) = handler();
    let err = handle_plugin_command(&h, &v(&["--bar", "foo"]), 1).unwrap_err();
    assert_eq!(err, "flags cannot be placed before plugin name: --bar");
}

#[test]
fn plugin_handler_dashes_become_underscores_in_lookup() {
    let (d, h) = handler();
    std::fs::write(d.path().join("kubectl-my_plugin"), "").unwrap();
    handle_plugin_command(&h, &v(&["my-plugin", "--x"]), 1).unwrap();
    let (p, args) = h.executed.borrow().clone().unwrap();
    assert!(p.ends_with("kubectl-my_plugin"));
    assert_eq!(args, v(&["--x"]));
}

#[test]
fn plugin_handler_only_create_allows_subcommand_plugins() {
    assert!(is_subcommand_plugin_allowed("create"));
    assert!(!is_subcommand_plugin_allowed("get"));
}

#[test]
fn plugin_handler_default_lookup_uses_path_and_exec_bit() {
    let d = tempfile::tempdir().unwrap();
    let plugin = d.path().join("kubectl-zzfoo");
    std::fs::write(&plugin, "#!/bin/sh\n").unwrap();
    let path = format!("/nonexistent:{}", d.path().display());
    let h = DefaultPluginHandler::default();
    assert_eq!(h.lookup_in("zzfoo", &path), None, "not executable yet");
    std::fs::set_permissions(&plugin, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(h.lookup_in("zzfoo", &path), Some(plugin));
    assert_eq!(h.lookup_in("zzmissing", &path), None);
}
