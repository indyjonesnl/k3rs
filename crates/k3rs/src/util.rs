//! Helpers shared by the server and agent halves of the library.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};
use k3rs_kube_proxy::node_net::NodeNetConfig;

use crate::supervisor::ClusterInfo;

/// The per-node CNI conflist the node-network agent writes.
pub const CNI_CONF_PATH: &str = "/etc/cni/net.d/10-k3rs.conflist";

/// Operator-facing posture warning for the kubelet API port: `kubelet::run`
/// serves it with `AlwaysAllow` and no client-CA authn. Printed by the server
/// (inside `skip_auth_warning`) and by agent startup.
pub const KUBELET_ANON_WARNING: &str = "the kubelet API on :10250 is anonymous (AlwaysAllow): exec/attach/run/portForward/pprof/debug are open to any client that can reach it; client-CA authn is a follow-up";

/// Write `data` to `path` with `mode`, set at creation and re-applied when an
/// existing file is rewritten (`mode` alone is masked by umask and ignored for
/// existing files).
pub fn write_file_mode(path: &Path, data: &str, mode: u32) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    f.write_all(data.as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Node-network agent configuration, identical for a server's own node and an
/// agent's (`agent::kube_proxy_config`): pod and service CIDRs are not
/// masqueraded.
pub fn node_net_config(node_name: &str, info: &ClusterInfo) -> NodeNetConfig {
    NodeNetConfig {
        node_name: node_name.to_string(),
        cni_conf_path: CNI_CONF_PATH.to_string(),
        no_masq_cidrs: vec![info.cluster_cidr.clone(), info.service_cidr.clone()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_file_mode_reapplies_mode_on_rewrite() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, "old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_file_mode(&p, "new", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
