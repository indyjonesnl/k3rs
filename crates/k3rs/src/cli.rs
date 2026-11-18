//! Subcommand selection for `k3rs`.
//!
//! `k3rs server` / `k3rs agent` are recognised from `argv[1]`; anything else
//! (including bare `k3rs [flags]`) stays the all-in-one and is parsed by the
//! binary's existing `Args`, unchanged.

use clap::Parser;

#[derive(Debug)]
pub enum Mode {
    AllInOne,
    Server(ServerArgs),
    Agent(AgentArgs),
}

#[derive(Parser, Debug, Clone)]
#[command(name = "k3rs server", about = "k3rs server (control plane + node)")]
pub struct ServerArgs {
    #[arg(long, default_value = "/var/lib/k3rs")]
    pub data_dir: String,
    #[arg(long)]
    pub node_name: Option<String>,
    #[arg(long)]
    pub node_ip: Option<String>,
    /// Extra TLS SANs for the serving certificate (repeatable).
    #[arg(long = "tls-san")]
    pub tls_san: Vec<String>,
    #[arg(long)]
    pub token: Option<String>,
    #[arg(long)]
    pub token_file: Option<String>,
    #[arg(long, default_value = "0.0.0.0:6443")]
    pub bind_address: String,
    #[arg(long, default_value = "10.244.0.0/16")]
    pub cluster_cidr: String,
    #[arg(long)]
    pub disable_dns: bool,
    #[arg(long)]
    pub disable_proxy: bool,
}

#[derive(Parser, Debug, Clone)]
#[command(name = "k3rs agent", about = "k3rs agent (node joining a server)")]
#[command(group(clap::ArgGroup::new("token_src").required(true).multiple(false)
    .args(["token", "token_file"])))]
pub struct AgentArgs {
    /// Server URL to join, e.g. https://server:6443
    #[arg(long, required = true)]
    pub server: String,
    #[arg(long)]
    pub token: Option<String>,
    #[arg(long)]
    pub token_file: Option<String>,
    #[arg(long)]
    pub node_name: Option<String>,
    #[arg(long)]
    pub node_ip: Option<String>,
    #[arg(long, default_value = "/var/lib/k3rs")]
    pub data_dir: String,
    #[arg(long)]
    pub volume_dir: Option<String>,
    #[arg(long, default_value = "10.96.0.10")]
    pub cluster_dns: String,
}

/// Decide the run mode from the full argv (`argv[0]` is the program name).
pub fn parse_mode(argv: &[String]) -> anyhow::Result<Mode> {
    match argv.get(1).map(String::as_str) {
        Some("server") => Ok(Mode::Server(ServerArgs::try_parse_from(&argv[1..])?)),
        Some("agent") => Ok(Mode::Agent(AgentArgs::try_parse_from(&argv[1..])?)),
        _ => Ok(Mode::AllInOne),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn bare_k3rs_is_all_in_one() {
        assert!(matches!(parse_mode(&v(&["k3rs"])).unwrap(), Mode::AllInOne));
    }

    #[test]
    fn bare_flags_still_all_in_one() {
        assert!(matches!(
            parse_mode(&v(&["k3rs", "--tls"])).unwrap(),
            Mode::AllInOne
        ));
    }

    #[test]
    fn server_defaults() {
        match parse_mode(&v(&["k3rs", "server"])).unwrap() {
            Mode::Server(s) => {
                assert_eq!(s.data_dir, "/var/lib/k3rs");
                assert_eq!(s.bind_address, "0.0.0.0:6443");
                assert_eq!(s.cluster_cidr, "10.244.0.0/16");
            }
            _ => panic!("expected server"),
        }
    }

    #[test]
    fn agent_requires_server_and_token() {
        assert!(parse_mode(&v(&["k3rs", "agent"])).is_err());
        assert!(parse_mode(&v(&["k3rs", "agent", "--server", "https://s:6443"])).is_err());
        match parse_mode(&v(&[
            "k3rs",
            "agent",
            "--server",
            "https://s:6443",
            "--token-file",
            "/t",
        ]))
        .unwrap()
        {
            Mode::Agent(a) => {
                assert_eq!(a.token_file.as_deref(), Some("/t"));
                assert_eq!(a.cluster_dns, "10.96.0.10");
            }
            _ => panic!("expected agent"),
        }
    }
}
