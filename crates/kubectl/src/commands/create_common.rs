//! Shared plumbing of every `kubectl create <subcommand>`: `--dry-run`,
//! `-o`, `--save-config`, `--validate`, `--field-manager`.
//!
//! Ported from `staging/src/k8s.io/kubectl/pkg/cmd/create/create.go`
//! (release-1.35): `CreateSubcommandOptions.Complete` (:372) and `.Run` (:420),
//! `util.GetDryRunStrategy` (`pkg/cmd/util/helpers.go:712`),
//! `util.GetValidationDirective` (:667), `PrintFlagsWithDryRunStrategy`,
//! `util.CreateOrUpdateAnnotation` (`pkg/util/apply.go`) and the cli-runtime
//! printers it selects (`NamePrinter`, JSON/YAML printers wrapped in
//! `OmitManagedFieldsPrinter`).
//!
//! Wiring this into `types.rs` / the subcommand dispatch (new flags on every
//! `CreateCommands` variant) is a separate task.

use crate::commands::apply::{set_last_applied_annotation, LAST_APPLIED_ANNOTATION};
use crate::discovery::RestMapper;
use anyhow::{Context, Result};
use kubernetes_rs_client::http::ApiClient;
use serde_json::Value;

/// `cmdutil.DryRunStrategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DryRunStrategy {
    None,
    Client,
    Server,
}

/// The `--dry-run` flag's `NoOptDefVal` (`AddDryRunFlag`): a bare `--dry-run`.
pub const DRY_RUN_NO_OPT_DEF_VAL: &str = "unchanged";

/// `GetDryRunStrategy` (helpers.go:712). Deprecation warnings go to stderr
/// like klog.
pub fn get_dry_run_strategy(flag: &str) -> Result<DryRunStrategy> {
    match parse_go_bool(flag) {
        None => match flag {
            DRY_RUN_NO_OPT_DEF_VAL => {
                eprintln!("--dry-run is deprecated and can be replaced with --dry-run=client.");
                Ok(DryRunStrategy::Client)
            }
            "client" => Ok(DryRunStrategy::Client),
            "server" => Ok(DryRunStrategy::Server),
            "none" => Ok(DryRunStrategy::None),
            _ => anyhow::bail!(
                "Invalid dry-run value ({flag}). Must be \"none\", \"server\", or \"client\"."
            ),
        },
        Some(true) => {
            eprintln!(
                "--dry-run={flag} is deprecated (boolean value) and can be replaced with --dry-run=client."
            );
            Ok(DryRunStrategy::Client)
        }
        Some(false) => {
            eprintln!(
                "--dry-run={flag} is deprecated (boolean value) and can be replaced with --dry-run=none."
            );
            Ok(DryRunStrategy::None)
        }
    }
}

/// `strconv.ParseBool`: 1, t, T, TRUE, true, True / 0, f, F, FALSE, false, False.
fn parse_go_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// `GetValidationDirective` (helpers.go:667): the `fieldValidation` query value.
pub fn get_validation_directive(flag: &str) -> Result<&'static str> {
    match parse_go_bool(flag) {
        Some(true) => Ok("Strict"),
        Some(false) => Ok("Ignore"),
        None => match flag {
            "strict" => Ok("Strict"),
            "warn" => Ok("Warn"),
            "ignore" => Ok("Ignore"),
            _ => anyhow::bail!(
                "invalid - validate option \"{flag}\"; must be one of: strict (or true), warn, ignore (or false)"
            ),
        },
    }
}

/// `util.CreateOrUpdateAnnotation` (pkg/util/apply.go): with `--save-config`
/// always write the last-applied annotation, otherwise only refresh it when the
/// object already carries one (`updateApplyAnnotation`).
pub fn create_or_update_annotation(create_annotation: bool, obj: &mut Value) {
    let has_original = obj
        .pointer("/metadata/annotations")
        .and_then(|a| a.get(LAST_APPLIED_ANNOTATION))
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if create_annotation || has_original {
        set_last_applied_annotation(obj);
    }
}

/// `metav1.CreateOptions` as a query string: `fieldManager`, `fieldValidation`
/// and `dryRun=All` for the server strategy (create.go:455-466).
pub fn create_query(
    field_manager: &str,
    validation_directive: &str,
    dry_run: DryRunStrategy,
) -> String {
    let mut parts = Vec::new();
    if !field_manager.is_empty() {
        parts.push(format!("fieldManager={}", query_escape(field_manager)));
    }
    if !validation_directive.is_empty() {
        parts.push(format!(
            "fieldValidation={}",
            query_escape(validation_directive)
        ));
    }
    if dry_run == DryRunStrategy::Server {
        parts.push("dryRun=All".to_string());
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The `created` operation text after `PrintFlagsWithDryRunStrategy`
/// (`NamePrintFlags.Complete("%s (dry run)")`).
pub fn operation_text(dry_run: DryRunStrategy) -> String {
    match dry_run {
        DryRunStrategy::Client => "created (dry run)".to_string(),
        DryRunStrategy::Server => "created (server dry run)".to_string(),
        DryRunStrategy::None => "created".to_string(),
    }
}

/// Port of the printer chosen by `PrintFlags.ToPrinter` for `-o`: json/yaml
/// (managed fields omitted), name (short), or the default name printer with
/// the operation text. Returns the text to write to stdout.
pub fn print_obj(obj: &Value, output: &str, dry_run: DryRunStrategy) -> Result<String> {
    match output.to_lowercase().as_str() {
        "json" => {
            let mut o = obj.clone();
            omit_managed_fields(&mut o);
            Ok(format!("{}\n", serde_json::to_string_pretty(&o)?))
        }
        "yaml" => {
            let mut o = obj.clone();
            omit_managed_fields(&mut o);
            Ok(serde_yaml::to_string(&o)?)
        }
        "name" => print_name(obj, ""),
        "" => print_name(obj, &operation_text(dry_run)),
        other => anyhow::bail!(
            "unable to match a printer suitable for the output format \"{other}\", allowed formats are: json,yaml,name"
        ),
    }
}

/// `OmitManagedFieldsPrinter`: drop `metadata.managedFields`.
fn omit_managed_fields(obj: &mut Value) {
    if let Some(m) = obj.get_mut("metadata").and_then(Value::as_object_mut) {
        m.remove("managedFields");
    }
}

/// `NamePrinter.PrintObj` + `printObj` (cli-runtime printers/name.go).
fn print_name(obj: &Value, operation: &str) -> Result<String> {
    let api_version = obj.get("apiVersion").and_then(Value::as_str).unwrap_or("");
    let kind = obj.get("kind").and_then(Value::as_str).unwrap_or("");
    if api_version.is_empty() && kind.is_empty() {
        anyhow::bail!(
            "missing apiVersion or kind; try GetObjectKind().SetGroupVersionKind() if you know the type"
        );
    }
    let name = obj
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
        .unwrap_or("<unknown>");
    if kind.is_empty() {
        anyhow::bail!("missing kind for resource with name {name}");
    }
    let group = api_version.rsplit_once('/').map_or("", |(g, _)| g);
    let op = if operation.is_empty() {
        String::new()
    } else {
        format!(" {operation}")
    };
    let kind = kind.to_lowercase();
    Ok(if group.is_empty() {
        format!("{kind}/{name}{op}\n")
    } else {
        format!("{kind}.{group}/{name}{op}\n")
    })
}

/// `CreateSubcommandOptions` after `Complete`.
#[derive(Debug, Clone)]
pub struct CreateSubcommandOptions {
    pub dry_run: DryRunStrategy,
    /// `--save-config`.
    pub create_annotation: bool,
    pub field_manager: String,
    /// `fieldValidation` value from [`get_validation_directive`].
    pub validation_directive: String,
    /// `-o` value ("" when unset).
    pub output: String,
    pub namespace: String,
    /// `EnforceNamespace`: the namespace came from `--namespace` / kubeconfig.
    pub enforce_namespace: bool,
}

impl CreateSubcommandOptions {
    /// `Run` (create.go:420) for an already generated object. Returns the text
    /// to print to stdout.
    pub async fn run(
        &self,
        client: &ApiClient,
        mapper: &RestMapper,
        mut obj: Value,
    ) -> Result<String> {
        create_or_update_annotation(self.create_annotation, &mut obj);
        if self.dry_run != DryRunStrategy::Client {
            let kind = obj
                .get("kind")
                .and_then(Value::as_str)
                .context("missing kind")?
                .to_string();
            let mapping = mapper
                .resolve(&kind)
                .with_context(|| format!("no matches for kind \"{kind}\""))?;
            // root-scoped kinds are created without a namespace
            let ns = mapping.namespaced.then_some(self.namespace.as_str());
            let path = format!(
                "{}{}",
                crate::ops::build_path(mapping, ns, None),
                create_query(
                    &self.field_manager,
                    &self.validation_directive,
                    self.dry_run
                )
            );
            obj = client.post(&path, &obj).await?;
        } else if self.enforce_namespace {
            if let Some(m) = obj.get_mut("metadata").and_then(Value::as_object_mut) {
                m.insert("namespace".into(), Value::String(self.namespace.clone()));
            }
        }
        print_obj(&obj, &self.output, self.dry_run)
    }
}
