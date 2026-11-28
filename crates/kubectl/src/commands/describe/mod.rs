pub mod core_a;
pub mod events;
pub mod workloads;

use anyhow::Result;
use chrono::Utc;
use kubernetes_rs_client::http::{ApiClient, GetError};
use kubernetes_rs_common::resources::{Deployment, Namespace, Node, Pod, Service};

/// `DescriberSettings` (describe.go): `--show-events` (default true) and
/// `--chunk-size` (`cmdutil.DefaultChunkSize` = 500).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriberSettings {
    pub show_events: bool,
    pub chunk_size: i64,
}

impl Default for DescriberSettings {
    fn default() -> Self {
        Self {
            show_events: true,
            chunk_size: 500,
        }
    }
}

pub async fn execute_enhanced(
    client: &ApiClient,
    resource_type: &str,
    name: Option<&str>,
    namespace: &str,
    selector: Option<&str>,
    all_namespaces: bool,
) -> Result<()> {
    execute_enhanced_with_settings(
        client,
        resource_type,
        name,
        namespace,
        selector,
        all_namespaces,
        DescriberSettings::default(),
    )
    .await
}

pub async fn execute_enhanced_with_settings(
    client: &ApiClient,
    resource_type: &str,
    name: Option<&str>,
    namespace: &str,
    selector: Option<&str>,
    all_namespaces: bool,
    settings: DescriberSettings,
) -> Result<()> {
    // -l <selector> and/or --all-namespaces: list the matching resources, then
    // describe each (upstream `kubectl describe` lists via the label selector /
    // across namespaces and describes every match).
    if selector.is_some() || all_namespaces {
        let mapper = crate::discovery::RestMapper::from_server(client).await?;
        let mapping = mapper.resolve(resource_type).ok_or_else(|| {
            anyhow::anyhow!("the server doesn't have a resource type \"{resource_type}\"")
        })?;
        let query = crate::ops::label_selector_query(selector);
        let ns_opt = if all_namespaces {
            None
        } else {
            Some(namespace)
        };
        let items = crate::ops::list_value(client, mapping, ns_opt, all_namespaces, &query).await?;
        if items.is_empty() {
            println!("No resources found");
            return Ok(());
        }
        let mut first = true;
        for item in &items {
            let item_name = item
                .pointer("/metadata/name")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if item_name.is_empty() {
                continue;
            }
            // Namespaced items carry their own namespace (needed under
            // --all-namespaces); cluster-scoped ones fall back to the request ns.
            let item_ns = item
                .pointer("/metadata/namespace")
                .and_then(|v| v.as_str())
                .unwrap_or(namespace);
            if !first {
                println!();
            }
            first = false;
            execute_with_settings(client, resource_type, item_name, Some(item_ns), settings)
                .await?;
        }
        return Ok(());
    }
    if let Some(n) = name {
        execute_with_settings(client, resource_type, n, Some(namespace), settings).await
    } else {
        anyhow::bail!("Resource name required for describe");
    }
}

// Helper to convert GetError to anyhow::Error
pub fn map_get_error(err: GetError) -> anyhow::Error {
    match err {
        GetError::NotFound(_) => anyhow::anyhow!("Resource not found"),
        GetError::Other(e) => e,
    }
}

pub fn format_duration(duration: chrono::Duration) -> String {
    let days = duration.num_days();
    if days > 0 {
        return format!("{}d", days);
    }
    let hours = duration.num_hours();
    if hours > 0 {
        return format!("{}h", hours);
    }
    let minutes = duration.num_minutes();
    if minutes > 0 {
        return format!("{}m", minutes);
    }
    let seconds = duration.num_seconds();
    format!("{}s", seconds)
}

pub async fn execute(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: Option<&str>,
) -> Result<()> {
    execute_with_settings(
        client,
        resource_type,
        name,
        namespace,
        DescriberSettings::default(),
    )
    .await
}

/// Events block of a typed describer (`DescribeEvents` after the object, when
/// `ShowEvents`): empty when events are not requested. Like upstream, a failed
/// events search is not an error (`events, _ = searchEvents(..)`): the block is
/// then omitted.
pub async fn events_block(
    client: &ApiClient,
    kind: &str,
    obj: &impl serde::Serialize,
    settings: DescriberSettings,
) -> String {
    if !settings.show_events {
        return String::new();
    }
    let Ok(mut v) = serde_json::to_value(obj) else {
        return String::new();
    };
    if v.get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("")
        .is_empty()
    {
        v["kind"] = serde_json::Value::String(kind.to_string());
    }
    let Ok(evs) = events::search_events(client, &v, settings.chunk_size).await else {
        return String::new();
    };
    let mut w = events::PrefixWriter::new();
    events::describe_events_at(&evs, &mut w, Utc::now());
    w.finish()
}

pub async fn execute_with_settings(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: Option<&str>,
    settings: DescriberSettings,
) -> Result<()> {
    let default_namespace = "default";
    let ns = namespace.unwrap_or(default_namespace);

    match resource_type {
        "pod" | "pods" => {
            let pod: Pod = client
                .get(&format!("/api/v1/namespaces/{}/pods/{}", ns, name))
                .await
                .map_err(map_get_error)?;
            describe_pod(&pod);
            print!("{}", events_block(client, "Pod", &pod, settings).await);
        }
        "service" | "services" | "svc" => {
            let service: Service = client
                .get(&format!("/api/v1/namespaces/{}/services/{}", ns, name))
                .await
                .map_err(map_get_error)?;
            describe_service(&service);
            print!(
                "{}",
                events_block(client, "Service", &service, settings).await
            );
        }
        "deployment" | "deployments" | "deploy" => {
            let deployment: Deployment = client
                .get(&format!(
                    "/apis/apps/v1/namespaces/{}/deployments/{}",
                    ns, name
                ))
                .await
                .map_err(map_get_error)?;
            describe_deployment(&deployment);
            print!(
                "{}",
                events_block(client, "Deployment", &deployment, settings).await
            );
        }
        "node" | "nodes" => {
            let node: Node = client
                .get(&format!("/api/v1/nodes/{}", name))
                .await
                .map_err(map_get_error)?;
            describe_node(&node);
            print!("{}", events_block(client, "Node", &node, settings).await);
        }
        "namespace" | "namespaces" | "ns" => {
            let namespace: Namespace = client
                .get(&format!("/api/v1/namespaces/{}", name))
                .await
                .map_err(map_get_error)?;
            describe_namespace(&namespace);
            print!(
                "{}",
                events_block(client, "Namespace", &namespace, settings).await
            );
        }
        _ => {
            print!(
                "{}",
                describe_generic_to_string(client, resource_type, name, namespace, settings)
                    .await?
            )
        }
    }

    Ok(())
}

pub fn describe_pod(pod: &Pod) {
    println!("Name:         {}", pod.metadata.name);
    println!(
        "Namespace:    {}",
        pod.metadata.namespace.as_deref().unwrap_or("default")
    );

    if let Some(labels) = &pod.metadata.labels {
        println!(
            "Labels:       {}",
            labels
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n              ")
        );
    }

    if let Some(annotations) = &pod.metadata.annotations {
        println!(
            "Annotations:  {}",
            annotations
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n              ")
        );
    }

    if let Some(status) = &pod.status {
        println!("Status:       {:?}", status.phase);
        if let Some(pod_ip) = &status.pod_ip {
            println!("IP:           {}", pod_ip);
        }
    }

    if let Some(spec) = &pod.spec {
        if let Some(node_name) = &spec.node_name {
            println!("Node:         {}", node_name);
        }

        println!("\nContainers:");
        for container in &spec.containers {
            println!("  {}:", container.name);
            println!("    Image:      {}", container.image);
            if let Some(ports) = &container.ports {
                if !ports.is_empty() {
                    println!(
                        "    Ports:      {}",
                        ports
                            .iter()
                            .map(|p| format!("{}/{}", p.container_port, p.protocol.as_str()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
            }
            if let Some(resources) = &container.resources {
                if let Some(limits) = &resources.limits {
                    println!("    Limits:");
                    for (k, v) in limits {
                        println!("      {}: {}", k, v);
                    }
                }
                if let Some(requests) = &resources.requests {
                    println!("    Requests:");
                    for (k, v) in requests {
                        println!("      {}: {}", k, v);
                    }
                }
            }
        }
    }

    if let Some(ts) = pod.metadata.creation_timestamp {
        let age = format_duration(Utc::now().signed_duration_since(ts));
        println!("\nAge:          {}", age);
    }
}

pub fn describe_service(service: &Service) {
    println!("Name:         {}", service.metadata.name);
    println!(
        "Namespace:    {}",
        service.metadata.namespace.as_deref().unwrap_or("default")
    );

    if let Some(labels) = &service.metadata.labels {
        println!(
            "Labels:       {}",
            labels
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n              ")
        );
    }

    if let Some(service_type) = &service.spec.service_type {
        println!("Type:         {:?}", service_type);
    } else {
        println!("Type:         ClusterIP");
    }

    if let Some(cluster_ip) = &service.spec.cluster_ip {
        println!("IP:           {}", cluster_ip);
    }

    println!(
        "Ports:        {}",
        service
            .spec
            .ports
            .iter()
            .map(|p| format!(
                "{}/{} -> {}",
                p.port,
                p.protocol.as_str(),
                match &p.target_port {
                    Some(kubernetes_rs_common::resources::IntOrString::Int(tp)) => tp.to_string(),
                    Some(kubernetes_rs_common::resources::IntOrString::String(tp)) => tp.clone(),
                    None => "default".to_string(),
                }
            ))
            .collect::<Vec<_>>()
            .join("\n              ")
    );

    if let Some(selector) = &service.spec.selector {
        if !selector.is_empty() {
            println!(
                "Selector:     {}",
                selector
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
    }

    if let Some(ts) = service.metadata.creation_timestamp {
        let age = format_duration(Utc::now().signed_duration_since(ts));
        println!("\nAge:          {}", age);
    }
}

pub fn describe_deployment(deployment: &Deployment) {
    println!("Name:         {}", deployment.metadata.name);
    println!(
        "Namespace:    {}",
        deployment
            .metadata
            .namespace
            .as_deref()
            .unwrap_or("default")
    );

    if let Some(labels) = &deployment.metadata.labels {
        println!(
            "Labels:       {}",
            labels
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n              ")
        );
    }

    println!(
        "Replicas:     {} desired",
        deployment.spec.replicas.unwrap_or(1)
    );

    if let Some(status) = &deployment.status {
        if let Some(ready) = status.ready_replicas {
            println!("              {} ready", ready);
        }
        if let Some(updated) = status.updated_replicas {
            println!("              {} updated", updated);
        }
        if let Some(available) = status.available_replicas {
            println!("              {} available", available);
        }
    }

    println!(
        "Selector:     match_labels={:?}",
        deployment.spec.selector.match_labels
    );

    if let Some(ts) = deployment.metadata.creation_timestamp {
        let age = format_duration(Utc::now().signed_duration_since(ts));
        println!("\nAge:          {}", age);
    }
}

pub fn describe_node(node: &Node) {
    println!("Name:         {}", node.metadata.name);

    if let Some(labels) = &node.metadata.labels {
        println!(
            "Labels:       {}",
            labels
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n              ")
        );
    }

    if let Some(status) = &node.status {
        if let Some(conditions) = &status.conditions {
            println!("\nConditions:");
            for condition in conditions {
                println!("  {}:  {}", condition.condition_type, condition.status);
            }
        }

        if let Some(addresses) = &status.addresses {
            println!("\nAddresses:");
            for addr in addresses {
                println!("  {}: {}", addr.address_type, addr.address);
            }
        }

        if let Some(capacity) = &status.capacity {
            println!("\nCapacity:");
            for (k, v) in capacity {
                println!("  {}: {}", k, v);
            }
        }

        if let Some(allocatable) = &status.allocatable {
            println!("\nAllocatable:");
            for (k, v) in allocatable {
                println!("  {}: {}", k, v);
            }
        }
    }

    if let Some(ts) = node.metadata.creation_timestamp {
        let age = format_duration(Utc::now().signed_duration_since(ts));
        println!("\nAge:          {}", age);
    }
}

pub fn describe_namespace(namespace: &Namespace) {
    println!("Name:         {}", namespace.metadata.name);

    if let Some(labels) = &namespace.metadata.labels {
        println!(
            "Labels:       {}",
            labels
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n              ")
        );
    }

    if let Some(status) = &namespace.status {
        println!("Status:       {:?}", status.phase);
    }

    if let Some(ts) = namespace.metadata.creation_timestamp {
        let age = format_duration(Utc::now().signed_duration_since(ts));
        println!("\nAge:          {}", age);
    }
}

/// `GenericDescriberFor` (describe.go:258): kinds without a dedicated
/// describer are fetched as unstructured and printed generically, with the
/// Events section when `settings.show_events` (the default). Serves any kind
/// the server serves, CRDs included.
pub async fn describe_generic_to_string(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: Option<&str>,
    settings: DescriberSettings,
) -> Result<String> {
    let mapper = crate::discovery::RestMapper::from_server(client).await?;
    let mapping = mapper.resolve(resource_type).ok_or_else(|| {
        anyhow::anyhow!("the server doesn't have a resource type \"{resource_type}\"")
    })?;
    let obj = crate::ops::get_value(client, mapping, namespace, name).await?;
    let evs = if settings.show_events {
        events::search_events(client, &obj, settings.chunk_size)
            .await
            .ok()
    } else {
        None
    };
    Ok(events::describe_generic(
        &obj,
        evs.as_deref(),
        chrono::Utc::now(),
    ))
}
