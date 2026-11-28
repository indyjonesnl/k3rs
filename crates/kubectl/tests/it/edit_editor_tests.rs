//! Ports of `staging/src/k8s.io/kubectl/pkg/cmd/util/editor/editor_test.go`
//! (`TestArgs`, `TestEditor`) and `defaultEnvEditor`/`editorEnvs`.

use kubernetes_rs_kubectl::commands::edit::{default_env_editor, Editor};

fn ed(args: &[&str], shell: bool) -> Editor {
    Editor {
        args: args.iter().map(|s| s.to_string()).collect(),
        shell,
    }
}

#[test]
fn edit_editor_args() {
    assert_eq!(
        ed(&["/bin/bash", "-c"], true).args_for("test"),
        ["/bin/bash", "-c \"test\""]
    );
    assert_eq!(
        ed(&["/bin/bash", "-c"], false).args_for("test"),
        ["/bin/bash", "-c", "test"]
    );
    assert_eq!(
        ed(&["/bin/bash", "-i -c"], true).args_for("test"),
        ["/bin/bash", "-i -c \"test\""]
    );
    assert_eq!(ed(&["/test"], false).args_for("test"), ["/test", "test"]);
}

#[test]
fn edit_editor_launch_temp_file() {
    let e = ed(&["cat"], false);
    let (contents, path) = e
        .launch_temp_file("", "someprefix", b"test something\n")
        .unwrap();
    assert!(path.exists());
    assert_eq!(std::fs::read(&path).unwrap(), contents);
    assert_eq!(contents, b"test something\n");
    assert!(path.to_string_lossy().contains("someprefix"));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn edit_editor_launch_errors() {
    assert_eq!(
        ed(&[], false)
            .launch(std::path::Path::new("x"))
            .unwrap_err()
            .to_string(),
        "no editor defined, can't open x"
    );
    assert_eq!(
        ed(&["/nonexistent-editor"], false)
            .launch(std::path::Path::new("x"))
            .unwrap_err()
            .to_string(),
        "unable to launch the editor \"/nonexistent-editor\""
    );
    assert_eq!(
        ed(&["false"], false)
            .launch(std::path::Path::new("x"))
            .unwrap_err()
            .to_string(),
        "there was a problem with the editor \"false\""
    );
}

#[test]
fn edit_editor_env_selection() {
    let env = |pairs: &'static [(&str, &str)]| {
        move |k: &str| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    };
    let envs = ["KUBE_EDITOR", "EDITOR"];
    // KUBE_EDITOR wins over EDITOR.
    let l = env(&[("KUBE_EDITOR", "nano"), ("EDITOR", "emacs")]);
    assert_eq!(
        default_env_editor(&envs, &l),
        (vec!["nano".to_string()], false)
    );
    // Falls through an empty value; VISUAL is not consulted.
    let l = env(&[("KUBE_EDITOR", ""), ("EDITOR", "emacs"), ("VISUAL", "x")]);
    assert_eq!(
        default_env_editor(&envs, &l),
        (vec!["emacs".to_string()], false)
    );
    let l = env(&[("VISUAL", "x")]);
    assert_eq!(
        default_env_editor(&envs, &l),
        (vec!["vi".to_string()], false)
    );
    // Spaces: split; quotes/backslash: shell.
    let l = env(&[("EDITOR", "code --wait")]);
    assert_eq!(
        default_env_editor(&envs, &l),
        (vec!["code".into(), "--wait".into()], false)
    );
    let l = env(&[("EDITOR", "sh -c 'vi'"), ("SHELL", "/bin/zsh")]);
    assert_eq!(
        default_env_editor(&envs, &l),
        (
            vec!["/bin/zsh".into(), "-c".into(), "sh -c 'vi'".into()],
            true
        )
    );
}
