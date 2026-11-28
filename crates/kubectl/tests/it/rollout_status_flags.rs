//! `rollout status` flags and validation (cmd/rollout/rollout_status.go:96
//! flags, :147 Validate, rollout_status_test.go).

use clap::Parser;
use kubernetes_rs_kubectl::commands::rollout::{split_status_args, validate_status_args};
use kubernetes_rs_kubectl::types::RolloutCommands;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: RolloutCommands,
}

type Parsed = (Vec<String>, Vec<String>, bool, i64, String, Option<String>);

fn parse(argv: &[&str]) -> Parsed {
    let mut full = vec!["rollout"];
    full.extend_from_slice(argv);
    match Cli::try_parse_from(full).unwrap().command {
        RolloutCommands::Status {
            args,
            filename,
            watch,
            revision,
            timeout,
            selector,
            ..
        } => (args, filename, watch, revision, timeout, selector),
        _ => panic!("not status"),
    }
}

#[test]
fn rollout_status_flag_defaults() {
    let (args, files, watch, rev, timeout, sel) = parse(&["status", "deployment/nginx"]);
    assert_eq!(args, ["deployment/nginx"]);
    assert!(files.is_empty() && watch && rev == 0 && sel.is_none());
    assert_eq!(timeout, "0s");
}

#[test]
fn rollout_status_flags_parse() {
    let (args, files, watch, rev, timeout, sel) = parse(&[
        "status",
        "deploy",
        "web",
        "--watch=false",
        "--revision",
        "3",
        "--timeout",
        "2m",
        "-l",
        "app=web",
        "-f",
        "a.yaml",
    ]);
    assert_eq!(args, ["deploy", "web"]);
    assert_eq!(files, ["a.yaml"]);
    assert!(!watch);
    assert_eq!(
        (rev, timeout.as_str(), sel.as_deref()),
        (3, "2m", Some("app=web"))
    );
    // `-w` alone keeps the default true.
    assert!(parse(&["status", "-w", "deploy/web"]).2);
}

#[test]
fn rollout_status_validate() {
    let none: Vec<String> = vec![];
    let a = vec!["deployment/x".to_string()];
    let f = vec!["x.yaml".to_string()];
    assert_eq!(
        validate_status_args(&none, &none, 0)
            .unwrap_err()
            .to_string(),
        "required resource not specified"
    );
    assert!(validate_status_args(&none, &f, 0).is_ok());
    assert_eq!(
        validate_status_args(&a, &none, -1).unwrap_err().to_string(),
        "revision must be a positive integer: -1"
    );
    assert!(validate_status_args(&a, &none, 2).is_ok());
}

#[test]
fn rollout_status_resource_args() {
    let v = |a: &[&str]| split_status_args(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    assert_eq!(
        v(&["deploy", "web"]).unwrap(),
        [("deploy".into(), Some("web".into()))]
    );
    assert_eq!(
        v(&["deploy/web"]).unwrap(),
        [("deploy".into(), Some("web".into()))]
    );
    assert_eq!(v(&["deploy"]).unwrap(), [("deploy".into(), None)]);
    assert_eq!(
        v(&["deploy/a", "sts/b"]).unwrap(),
        [
            ("deploy".into(), Some("a".into())),
            ("sts".into(), Some("b".into()))
        ]
    );
    assert!(v(&["deploy/a", "b"]).is_err());
}
