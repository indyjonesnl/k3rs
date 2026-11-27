use crate::websocket;
use anyhow::Result;
use kubernetes_rs_client::http::ApiClient;

/// Forward one or more local ports to a pod
pub async fn execute(
    client: &ApiClient,
    pod_name: &str,
    namespace: &str,
    ports: &[String],
    address: &str,
) -> Result<()> {
    if ports.is_empty() {
        anyhow::bail!("At least one port must be specified");
    }

    // Parse port mapping (format: "local:remote" or "port")
    let (local_port, remote_port) = parse_port_mapping(&ports[0])?;

    // Build WebSocket URL
    let url_path = format!(
        "/api/v1/namespaces/{}/pods/{}/portforward?ports={}",
        namespace, pod_name, remote_port
    );

    let ws_url = client.get_ws_url(&url_path)?;

    // Start port forwarding
    websocket::port_forward_stream(ws_url, local_port, remote_port, address).await
}

pub fn parse_port_mapping(port_spec: &str) -> Result<(u16, u16)> {
    if let Some((local, remote)) = port_spec.split_once(':') {
        let local_port = local.parse::<u16>()?;
        let remote_port = remote.parse::<u16>()?;
        Ok((local_port, remote_port))
    } else {
        // If only one port specified, use same for both local and remote
        let port = port_spec.parse::<u16>()?;
        Ok((port, port))
    }
}

// ---------------------------------------------------------------------------
// Port-spec handling ported from kubectl (release-1.35). Pure functions; the
// streaming side (several pairs per connection) is a separate task.
// ---------------------------------------------------------------------------

use kubernetes_rs_common::resources::{IntOrString, Pod, Service};
use std::collections::BTreeSet;

/// `splitPort` (kubectl/pkg/cmd/portforward/portforward.go:172).
pub fn split_port(port: &str) -> (String, String) {
    let parts: Vec<&str> = port.split(':').collect();
    if parts.len() == 2 {
        return (parts[0].to_string(), parts[1].to_string());
    }
    (parts[0].to_string(), parts[0].to_string())
}

/// `parsePorts` (client-go/tools/portforward/portforward.go:85): `PORT`,
/// `LOCAL:REMOTE` and `:REMOTE` (local port 0 = pick a random free one).
pub fn parse_ports(ports: &[String]) -> Result<Vec<(u16, u16)>> {
    let mut forwards = Vec::new();
    for port_string in ports {
        let parts: Vec<&str> = port_string.split(':').collect();
        let (local, remote) = match parts.len() {
            1 => (parts[0], parts[0]),
            2 => (if parts[0].is_empty() { "0" } else { parts[0] }, parts[1]),
            _ => anyhow::bail!("invalid port format '{}'", port_string),
        };
        let local_port: u16 = local
            .parse()
            .map_err(|e| anyhow::anyhow!("error parsing local port '{}': {}", local, e))?;
        let remote_port: u16 = remote
            .parse()
            .map_err(|e| anyhow::anyhow!("error parsing remote port '{}': {}", remote, e))?;
        if remote_port == 0 {
            anyhow::bail!("remote port must be > 0");
        }
        forwards.push((local_port, remote_port));
    }
    Ok(forwards)
}

fn pod_name(pod: &Pod) -> &str {
    &pod.metadata.name
}

/// `LookupContainerPortNumberByName` (kubectl/pkg/util/pod_port.go).
pub fn lookup_container_port_number_by_name(pod: &Pod, name: &str) -> Result<u16> {
    if let Some(spec) = &pod.spec {
        let init = spec.init_containers.iter().flatten();
        for ctr in spec.containers.iter().chain(init) {
            for p in ctr.ports.iter().flatten() {
                if p.name.as_deref() == Some(name) {
                    return Ok(p.container_port);
                }
            }
        }
    }
    anyhow::bail!(
        "Pod '{}' does not have a named port '{}'",
        pod_name(pod),
        name
    )
}

/// `LookupServicePortNumberByName` (kubectl/pkg/util/service_port.go).
pub fn lookup_service_port_number_by_name(svc: &Service, name: &str) -> Result<u16> {
    for p in &svc.spec.ports {
        if p.name.as_deref() == Some(name) {
            return Ok(p.port);
        }
    }
    anyhow::bail!(
        "Service '{}' does not have a named port '{}'",
        svc.metadata.name,
        name
    )
}

/// `LookupContainerPortNumberByServicePort` (kubectl/pkg/util/service_port.go).
pub fn lookup_container_port_number_by_service_port(
    svc: &Service,
    pod: &Pod,
    port: i64,
) -> Result<u16> {
    for sp in &svc.spec.ports {
        if i64::from(sp.port) != port {
            continue;
        }
        if svc.spec.cluster_ip.as_deref() == Some("None") {
            return Ok(sp.port);
        }
        return match &sp.target_port {
            // targetPort omitted: IntValue() is zero, fall back to the port
            None | Some(IntOrString::Int(0)) => Ok(sp.port),
            Some(IntOrString::Int(n)) => u16::try_from(*n)
                .map_err(|_| anyhow::anyhow!("invalid target port {} for port {}", n, port)),
            Some(IntOrString::String(name)) => lookup_container_port_number_by_name(pod, name),
        };
    }
    anyhow::bail!(
        "Service {} does not have a service port {}",
        svc.metadata.name,
        port
    )
}

/// `convertPodNamedPortToNumber` (portforward.go:222).
pub fn convert_pod_named_port_to_number(ports: &[String], pod: &Pod) -> Result<Vec<String>> {
    let mut converted = Vec::new();
    for port in ports {
        let (local, remote) = split_port(port);
        if remote.is_empty() {
            anyhow::bail!("remote port cannot be empty");
        }
        let container_port = if remote.parse::<i64>().is_ok() {
            remote.clone()
        } else {
            lookup_container_port_number_by_name(pod, &remote)?.to_string()
        };
        if local != remote {
            converted.push(format!("{local}:{container_port}"));
        } else {
            converted.push(container_port);
        }
    }
    Ok(converted)
}

/// `translateServicePortToTargetPort` (portforward.go:185): rewrites service
/// ports to the pod's target ports, resolving named ports.
pub fn translate_service_port_to_target_port(
    ports: &[String],
    svc: &Service,
    pod: &Pod,
) -> Result<Vec<String>> {
    let mut translated = Vec::new();
    for port in ports {
        let (mut local, mut remote) = split_port(port);
        let portnum = match remote.parse::<i64>() {
            Ok(n) => n,
            Err(_) => {
                let n = i64::from(lookup_service_port_number_by_name(svc, &remote)?);
                if local == remote {
                    local = n.to_string();
                }
                n
            }
        };
        let container_port = lookup_container_port_number_by_service_port(svc, pod, portnum)?;
        remote = container_port.to_string();
        if local != remote {
            translated.push(format!("{local}:{remote}"));
        } else {
            translated.push(remote);
        }
    }
    Ok(translated)
}

fn check_udp_ports(
    udp_only: &BTreeSet<i64>,
    ports: &[String],
    resolve_named: &dyn Fn(&str) -> Result<u16>,
) -> Result<()> {
    for port in ports {
        let (_, remote) = split_port(port);
        let num = match remote.parse::<i64>() {
            Ok(n) => n,
            Err(_) => i64::from(resolve_named(&remote)?),
        };
        if udp_only.contains(&num) {
            anyhow::bail!("UDP protocol is not supported for {}", remote);
        }
    }
    Ok(())
}

/// `checkUDPPortInService` (portforward.go:283).
pub fn check_udp_port_in_service(ports: &[String], svc: &Service) -> Result<()> {
    let (mut udp, mut tcp) = (BTreeSet::new(), BTreeSet::new());
    for p in &svc.spec.ports {
        match p.protocol.as_str() {
            "UDP" => udp.insert(i64::from(p.port)),
            "TCP" => tcp.insert(i64::from(p.port)),
            _ => false,
        };
    }
    let udp_only: BTreeSet<i64> = udp.difference(&tcp).copied().collect();
    check_udp_ports(&udp_only, ports, &|n| {
        lookup_service_port_number_by_name(svc, n)
    })
}

/// `checkUDPPortInPod` (portforward.go:300).
pub fn check_udp_port_in_pod(ports: &[String], pod: &Pod) -> Result<()> {
    let (mut udp, mut tcp) = (BTreeSet::new(), BTreeSet::new());
    if let Some(spec) = &pod.spec {
        for ctr in &spec.containers {
            for p in ctr.ports.iter().flatten() {
                match p.protocol.as_str() {
                    "UDP" => udp.insert(i64::from(p.container_port)),
                    "TCP" => tcp.insert(i64::from(p.container_port)),
                    _ => false,
                };
            }
        }
    }
    let udp_only: BTreeSet<i64> = udp.difference(&tcp).copied().collect();
    check_udp_ports(&udp_only, ports, &|n| {
        lookup_container_port_number_by_name(pod, n)
    })
}
