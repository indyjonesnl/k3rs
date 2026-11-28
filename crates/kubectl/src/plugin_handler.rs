//! Plugin dispatch: port of
//! `staging/src/k8s.io/kubectl/pkg/cmd/plugin.go` (`PluginHandler`,
//! `DefaultPluginHandler`, `HandlePluginCommand`, `IsSubcommandPluginAllowed`)
//! and the dispatch decision in `cmd.go:107-163`
//! (`NewDefaultKubectlCommandWithArgs`).
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

/// `plugin.ValidPluginFilenamePrefixes` (cmd/plugin/plugin.go:63).
pub const VALID_PLUGIN_FILENAME_PREFIXES: &[&str] = &["kubectl"];

/// plugin.go:30-43 `PluginHandler`.
pub trait PluginHandler {
    /// Path of an executable named `<prefix>-<filename>` for the first
    /// matching valid prefix.
    fn lookup(&self, filename: &str) -> Option<PathBuf>;
    /// Run the plugin with `cmd_args` and `environment`.
    fn execute(
        &self,
        executable_path: &Path,
        cmd_args: &[String],
        environment: &[(String, String)],
    ) -> std::io::Result<()>;
}

/// plugin.go:46-57 `DefaultPluginHandler`.
pub struct DefaultPluginHandler {
    pub valid_prefixes: Vec<String>,
}

impl DefaultPluginHandler {
    pub fn new(valid_prefixes: &[&str]) -> Self {
        Self {
            valid_prefixes: valid_prefixes.iter().map(|p| (*p).to_owned()).collect(),
        }
    }
}

impl Default for DefaultPluginHandler {
    fn default() -> Self {
        Self::new(VALID_PLUGIN_FILENAME_PREFIXES)
    }
}

/// Go `exec.LookPath` on unix (os/exec/lp_unix.go): a name containing a
/// slash is checked directly, otherwise every PATH element is searched (an
/// empty element means the current directory) for a non-directory with an
/// execute bit. A match found through a relative element is still returned,
/// since `shouldSkipOnLookPathErr` (skiplookerr_go119.go) only skips errors
/// other than `exec.ErrDot`.
fn look_path(name: &str, path_var: &str) -> Option<PathBuf> {
    let executable = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| !m.is_dir() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    if name.contains('/') {
        let p = Path::new(name);
        return executable(p).then(|| p.to_path_buf());
    }
    for dir in path_var.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let p = Path::new(dir).join(name);
        if executable(&p) {
            return Some(p);
        }
    }
    None
}

impl DefaultPluginHandler {
    /// plugin.go:60-69 against an explicit `PATH` value.
    pub fn lookup_in(&self, filename: &str, path_var: &str) -> Option<PathBuf> {
        self.valid_prefixes
            .iter()
            .find_map(|prefix| look_path(&format!("{prefix}-{filename}"), path_var))
    }
}

impl PluginHandler for DefaultPluginHandler {
    /// plugin.go:60-69.
    fn lookup(&self, filename: &str) -> Option<PathBuf> {
        self.lookup_in(filename, &std::env::var("PATH").unwrap_or_default())
    }

    /// plugin.go:72-90: `syscall.Exec(executablePath,
    /// append([]string{executablePath}, cmdArgs...), environment)`. Only
    /// returns on failure.
    fn execute(
        &self,
        executable_path: &Path,
        cmd_args: &[String],
        environment: &[(String, String)],
    ) -> std::io::Result<()> {
        let err = std::process::Command::new(executable_path)
            .arg0(executable_path)
            .args(cmd_args)
            .env_clear()
            .envs(environment.iter().map(|(k, v)| (k, v)))
            .exec();
        Err(err)
    }
}

/// plugin.go:119-155 `HandlePluginCommand`: find a plugin for `cmd_args`,
/// starting at the longest possible name and never searching below
/// `min_args` words; execute it with the remaining arguments.
pub fn handle_plugin_command(
    handler: &dyn PluginHandler,
    cmd_args: &[String],
    min_args: usize,
) -> Result<(), String> {
    let mut remaining: Vec<String> = Vec::new(); // all "non-flag" arguments
    for arg in cmd_args {
        if arg.starts_with('-') {
            break;
        }
        remaining.push(arg.replace('-', "_"));
    }
    if remaining.is_empty() {
        // the length of cmd_args is at least 1
        return Err(format!(
            "flags cannot be placed before plugin name: {}",
            cmd_args.first().map(String::as_str).unwrap_or_default()
        ));
    }

    let mut found_binary_path = None;
    // attempt to find binary, starting at longest possible name with given cmd_args
    while !remaining.is_empty() {
        match handler.lookup(&remaining.join("-")) {
            None => {
                remaining.pop();
                if remaining.len() < min_args {
                    // don't search shorter names, e.g. kubectl-create when
                    // kubectl-create-foo is not found.
                    break;
                }
            }
            Some(path) => {
                found_binary_path = Some(path);
                break;
            }
        }
    }
    let Some(path) = found_binary_path else {
        return Ok(());
    };

    // invoke cmd binary relaying the current environment and args given
    let env: Vec<(String, String)> = std::env::vars().collect();
    handler
        .execute(&path, &cmd_args[remaining.len()..], &env)
        .map_err(|e| e.to_string())
}

/// plugin.go:156-161 `IsSubcommandPluginAllowed`.
pub fn is_subcommand_plugin_allowed(found_cmd: &str) -> bool {
    found_cmd == "create"
}

/// What cobra's `cmd.Find(args)` returned (cmd.go:116) when it succeeded.
pub struct FoundCommand {
    /// `foundCmd.Name()`.
    pub name: String,
    /// `foundArgs`: arguments left after the command path.
    pub args: Vec<String>,
    /// Names of `foundCmd.Commands()`.
    pub subcommands: Vec<String>,
}

/// cmd.go:107-163 `NewDefaultKubectlCommandWithArgs` plugin dispatch.
/// `arguments` is `os.Args`; `found` is `None` when cobra's `Find` errored
/// (no such command). `Err` carries the text for `Error: %v` (the caller exits 1).
pub fn dispatch_plugin(
    handler: &dyn PluginHandler,
    arguments: &[String],
    found: Option<&FoundCommand>,
) -> Result<(), String> {
    if arguments.len() <= 1 {
        return Ok(());
    }
    let cmd_path_pieces = &arguments[1..];
    match found {
        None => {
            // Also check the commands Cobra adds on Execute (cmd.go:118-137).
            let cmd_name = cmd_path_pieces
                .iter()
                .find(|a| !a.starts_with('-'))
                .map(String::as_str)
                .unwrap_or_default();
            match cmd_name {
                "help" | "__complete" | "__completeNoDesc" => {} // don't search for a plugin
                _ => handle_plugin_command(handler, cmd_path_pieces, 1)?,
            }
        }
        // Command exists (e.g. kubectl create), but the subcommand may not
        // (e.g. kubectl create networkpolicy); eliminate `kubectl create -f`.
        Some(found) => {
            if is_subcommand_plugin_allowed(&found.name)
                && !found.args.is_empty()
                && !found.args[0].starts_with('-')
                && !found.subcommands.iter().any(|s| *s == found.args[0])
            {
                handle_plugin_command(
                    handler,
                    cmd_path_pieces,
                    cmd_path_pieces.len() - found.args.len() + 1,
                )?;
            }
        }
    }
    Ok(())
}
