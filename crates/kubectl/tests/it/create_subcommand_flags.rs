//! `kubectl create <subcommand>` shared flags: --dry-run, -o, --save-config,
//! --validate, --field-manager (create_subcommand.go `CreateSubcommandOptions`,
//! `cmdutil.AddDryRunFlag`, `AddValidateFlags`, `AddFieldManagerFlagVar`;
//! create_test.go / create_deployment_test.go flag cases).

use clap::Parser;
use kubernetes_rs_client::http::ApiClient;
use kubernetes_rs_kubectl::commands::create::{complete_options, execute_subcommand};
use kubernetes_rs_kubectl::commands::create_common::DryRunStrategy;
use kubernetes_rs_kubectl::types::{CreateCommands, CreateFlags, SecretCommands, ServiceCommands};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: CreateCommands,
}

fn parse(argv: &[&str]) -> CreateCommands {
    let mut full = vec!["create"];
    full.extend_from_slice(argv);
    Cli::try_parse_from(full).unwrap().command
}

fn flags_of(c: &CreateCommands) -> CreateFlags {
    match c {
        CreateCommands::Deployment { flags, .. }
        | CreateCommands::Namespace { flags, .. }
        | CreateCommands::ConfigMap { flags, .. }
        | CreateCommands::Role { flags, .. } => flags.clone(),
        CreateCommands::Secret {
            subcommand: SecretCommands::Generic { flags, .. },
        }
        | CreateCommands::Service {
            subcommand: ServiceCommands::ClusterIP { flags, .. },
        } => flags.clone(),
        _ => panic!("unexpected subcommand"),
    }
}

#[test]
fn create_subcommand_flags_defaults() {
    let f = flags_of(&parse(&["namespace", "x"]));
    assert_eq!(f.dry_run, "none");
    assert_eq!(f.validate, "strict");
    assert_eq!(f.field_manager, "kubectl-create");
    assert_eq!(f.output, None);
    assert!(!f.save_config);
    let o = complete_options(&f, "default").unwrap();
    assert_eq!(o.dry_run, DryRunStrategy::None);
    assert_eq!(o.validation_directive, "Strict");
}

#[test]
fn create_subcommand_flags_parse_on_every_nesting_level() {
    for argv in [
        &["deployment", "d", "--image=nginx"][..],
        &["namespace", "n"],
        &["configmap", "c"],
        &["role", "r"],
        &["secret", "generic", "s"],
        &["service", "clusterip", "svc"],
    ] {
        let mut v = argv.to_vec();
        v.extend([
            "--dry-run=client",
            "-o",
            "yaml",
            "--save-config",
            "--validate=warn",
            "--field-manager=me",
        ]);
        let f = flags_of(&parse(&v));
        assert_eq!(f.dry_run, "client", "{argv:?}");
        assert_eq!(f.output.as_deref(), Some("yaml"), "{argv:?}");
        assert!(f.save_config, "{argv:?}");
        let o = complete_options(&f, "ns").unwrap();
        assert_eq!(o.dry_run, DryRunStrategy::Client);
        assert_eq!(o.validation_directive, "Warn");
        assert_eq!(o.field_manager, "me");
        assert!(o.create_annotation);
        assert_eq!(o.output, "yaml");
    }
}

#[test]
fn create_subcommand_flags_bare_dry_run_is_deprecated_client() {
    // AddDryRunFlag: NoOptDefVal "unchanged" -> client.
    let f = flags_of(&parse(&["namespace", "x", "--dry-run"]));
    assert_eq!(f.dry_run, "unchanged");
    assert_eq!(
        complete_options(&f, "d").unwrap().dry_run,
        DryRunStrategy::Client
    );
}

#[test]
fn create_subcommand_flags_invalid_values_rejected() {
    let f = flags_of(&parse(&["namespace", "x", "--dry-run=bogus"]));
    let e = complete_options(&f, "d").unwrap_err().to_string();
    assert!(e.contains("Invalid dry-run value (bogus)"), "{e}");
    let f = flags_of(&parse(&["namespace", "x", "--validate=bogus"]));
    let e = complete_options(&f, "d").unwrap_err().to_string();
    assert!(e.contains("invalid - validate option"), "{e}");
}

fn dead_client() -> ApiClient {
    ApiClient::new("http://127.0.0.1:1", true, None).unwrap()
}

#[tokio::test]
async fn create_subcommand_flags_client_dry_run_never_contacts_server() {
    // `kubectl create deployment x --image=y --dry-run=client -o yaml` works
    // with no reachable API server: the manifest generator use case.
    let cmd = parse(&[
        "deployment",
        "x",
        "--image=y",
        "--dry-run=client",
        "-o",
        "yaml",
    ]);
    execute_subcommand(&dead_client(), &cmd, "default")
        .await
        .unwrap();
}

#[tokio::test]
async fn create_subcommand_flags_real_create_needs_server() {
    let cmd = parse(&["namespace", "x"]);
    assert!(execute_subcommand(&dead_client(), &cmd, "default")
        .await
        .is_err());
    let cmd = parse(&["namespace", "x", "--dry-run=server"]);
    assert!(execute_subcommand(&dead_client(), &cmd, "default")
        .await
        .is_err());
}

#[tokio::test]
async fn create_subcommand_flags_unknown_output_format_rejected() {
    let cmd = parse(&["namespace", "x", "--dry-run=client", "-o", "wide"]);
    let e = execute_subcommand(&dead_client(), &cmd, "default")
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("unable to match a printer"), "{e}");
}
