//! Kubelet pod admission predicates.
//!
//! Port of `pkg/kubelet/lifecycle/predicate.go` (`predicateAdmitHandler.Admit`,
//! `generalFilter`, `rejectPodAdmissionBasedOn*`, `removeMissingExtendedResources`)
//! plus the scheduler filters it reuses through `scheduler.AdmissionCheck`
//! (`pkg/scheduler/eventhandlers.go:754`): `noderesources.Fits`
//! (`framework/plugins/noderesources/fit.go:645-740`), required node
//! affinity/selector (`component-helpers/scheduling/corev1/nodeaffinity`),
//! `nodename.Fits`, and `nodeports.Fits`.
//!
//! Not ported (tracked in the backlog): the `admissionFailureHandler`
//! (critical-pod preemption, `pkg/kubelet/preemption`), the device-plugin
//! `pluginResourceUpdateFunc`, and the `TaintTolerationComparisonOperators`
//! gate (treated as disabled, so `Gt`/`Lt` tolerations never match, as with the
//! gate off).

use kubernetes_rs_common::affinity::matches_node_selector;
use kubernetes_rs_common::quantity::parse_resource_value;
use kubernetes_rs_common::quota::{self, is_extended_resource_name};
use kubernetes_rs_common::resources::{Container, Node, Pod, Taint, Toleration};
use std::collections::BTreeMap;
use std::fmt;

// Reason constants, `predicate.go:40-116`.
pub const POD_OS_SELECTOR_NODE_LABEL_DOES_NOT_MATCH: &str = "PodOSSelectorNodeLabelDoesNotMatch";
pub const POD_OS_NOT_SUPPORTED: &str = "PodOSNotSupported";
pub const INVALID_NODE_INFO: &str = "InvalidNodeInfo";
pub const SUPPLEMENTAL_GROUPS_POLICY_NOT_SUPPORTED: &str = "SupplementalGroupsPolicyNotSupported";
pub const UNKNOWN_REASON: &str = "UnknownReason";
pub const INSUFFICIENT_RESOURCE_PREFIX: &str = "OutOf";
pub const OUT_OF_CPU: &str = "OutOfcpu";
pub const OUT_OF_MEMORY: &str = "OutOfmemory";
pub const OUT_OF_EPHEMERAL_STORAGE: &str = "OutOfephemeral-storage";
pub const OUT_OF_PODS: &str = "OutOfpods";

/// `v1.LabelOSStable`.
pub const LABEL_OS_STABLE: &str = "kubernetes.io/os";
/// `runtime.GOOS` for this kubelet; kubernetes-rs only runs Linux nodes.
pub const RUNTIME_GOOS: &str = "linux";

/// `kubetypes.ConfigSourceAnnotationKey` / `kubetypes.ApiserverSource`.
const CONFIG_SOURCE_ANNOTATION: &str = "kubernetes.io/config.source";
const API_SERVER_SOURCE: &str = "api";

// Scheduler plugin names and reasons used by `AdmissionCheck`.
const NODE_AFFINITY_NAME: &str = "NodeAffinity";
/// `nodeaffinity.ErrReasonPod` (`node_affinity.go:64`).
pub const ERR_REASON_NODE_AFFINITY: &str = "node(s) didn't match Pod's node affinity/selector";
const NODE_NAME_NAME: &str = "NodeName";
const ERR_REASON_NODE_NAME: &str = "node(s) didn't match the requested node name";
const NODE_PORTS_NAME: &str = "NodePorts";
const ERR_REASON_NODE_PORTS: &str = "node(s) didn't have free ports for the requested pod ports";
const TAINT_TOLERATION_NAME: &str = "TaintToleration";
const ERR_REASON_TAINT_NOT_MATCH: &str = "node(s) had taints that the pod didn't tolerate";

/// `lifecycle.PodAdmitAttributes`.
pub struct PodAdmitAttributes<'a> {
    pub pod: &'a Pod,
    /// Pods already admitted on this node (`OtherPods`).
    pub other_pods: &'a [Pod],
}

/// `lifecycle.PodAdmitResult`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PodAdmitResult {
    pub admit: bool,
    pub reason: String,
    pub message: String,
}

impl PodAdmitResult {
    fn reject(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            admit: false,
            reason: reason.into(),
            message: message.into(),
        }
    }
}

/// `lifecycle.InsufficientResourceError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsufficientResourceError {
    pub resource_name: String,
    pub requested: i64,
    pub used: i64,
    pub capacity: i64,
}

impl fmt::Display for InsufficientResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Node didn't have enough resource: {}, requested: {}, used: {}, capacity: {}",
            self.resource_name, self.requested, self.used, self.capacity
        )
    }
}

/// `lifecycle.PredicateFailureError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateFailureError {
    pub predicate_name: String,
    pub predicate_desc: String,
}

impl fmt::Display for PredicateFailureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Predicate {} failed: {}",
            self.predicate_name, self.predicate_desc
        )
    }
}

/// `lifecycle.PredicateFailureReason`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredicateFailure {
    InsufficientResource(InsufficientResourceError),
    Predicate(PredicateFailureError),
}

impl PredicateFailure {
    fn predicate(name: &str, desc: &str) -> Self {
        Self::Predicate(PredicateFailureError {
            predicate_name: name.to_string(),
            predicate_desc: desc.to_string(),
        })
    }

    /// `GetReason()`.
    pub fn get_reason(&self) -> String {
        match self {
            Self::InsufficientResource(e) => format!("Insufficient {}", e.resource_name),
            Self::Predicate(e) => e.predicate_desc.clone(),
        }
    }
}

/// `rejectPodAdmissionBasedOnOSSelector` (`predicate.go:253`). The node's own
/// OS label is overridden with `runtime.GOOS` when absent or different.
pub fn reject_pod_admission_based_on_os_selector(pod: &Pod, _node: &Node) -> bool {
    let Some(pod_os) = pod
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(LABEL_OS_STABLE))
    else {
        // No selector: keep current behavior.
        return false;
    };
    // The effective node label is always runtime.GOOS after the override.
    pod_os != RUNTIME_GOOS
}

/// `rejectPodAdmissionBasedOnOSField` (`predicate.go:277`).
pub fn reject_pod_admission_based_on_os_field(pod: &Pod) -> bool {
    match pod.spec.as_ref().and_then(|s| s.os.as_ref()) {
        None => false,
        Some(os) => os.name != RUNTIME_GOOS,
    }
}

/// `rejectPodAdmissionBasedOnSupplementalGroupsPolicy` (`predicate.go:292`).
/// The feature is GA/beta in 1.35, so it is always enforced.
pub fn reject_pod_admission_based_on_supplemental_groups_policy(pod: &Pod, node: &Node) -> bool {
    let Some(policy) = pod
        .spec
        .as_ref()
        .and_then(|s| s.security_context.as_ref())
        .and_then(|sc| sc.supplemental_groups_policy.as_ref())
    else {
        return false;
    };
    let supported = node
        .status
        .as_ref()
        .and_then(|s| s.features.as_ref())
        .and_then(|f| f.supplemental_groups_policy)
        .unwrap_or(false);
    policy == "Strict" && !supported
}

fn node_allocatable(node: &Node) -> BTreeMap<String, i64> {
    let mut out = BTreeMap::new();
    if let Some(alloc) = node.status.as_ref().and_then(|s| s.allocatable.as_ref()) {
        for (name, qty) in alloc {
            if let Ok(v) = parse_resource_value(qty, name) {
                out.insert(name.clone(), v);
            }
        }
    }
    out
}

/// Requests of `pod` as integer amounts (cpu in milli-units), as
/// `computePodResourceRequest` / `NodeInfo.Requested` use them.
fn request_amounts(pod: &Pod) -> BTreeMap<String, i64> {
    quota::pod_requests(pod)
        .into_iter()
        .map(|(name, q)| {
            let v = if name == "cpu" {
                q.milli_value()
            } else {
                q.value()
            };
            (name, v.clamp(i64::MIN as i128, i64::MAX as i128) as i64)
        })
        .collect()
}

/// `removeMissingExtendedResources` (`predicate.go:326`): drop requests for
/// extended resources the node does not advertise in allocatable.
pub fn remove_missing_extended_resources(pod: &Pod, node: &Node) -> Pod {
    let alloc = node.status.as_ref().and_then(|s| s.allocatable.as_ref());
    let filter = |containers: &mut [Container]| {
        for c in containers {
            if let Some(reqs) = c.resources.as_mut().and_then(|r| r.requests.as_mut()) {
                reqs.retain(|name, _| {
                    !is_extended_resource_name(name) || alloc.is_some_and(|a| a.contains_key(name))
                });
            }
        }
    };
    let mut copy = pod.clone();
    if let Some(spec) = copy.spec.as_mut() {
        filter(&mut spec.containers);
        if let Some(init) = spec.init_containers.as_mut() {
            filter(init);
        }
    }
    copy
}

/// `noderesources.Fits` (`fit.go:645`) against a node whose requested totals
/// come from `other_pods` (`NodeInfo.Requested`).
fn fits_resources(pod: &Pod, node: &Node, other_pods: &[Pod]) -> Vec<InsufficientResourceError> {
    let alloc = node_allocatable(node);
    let mut used: BTreeMap<String, i64> = BTreeMap::new();
    for p in other_pods {
        for (k, v) in request_amounts(p) {
            *used.entry(k).or_insert(0) += v;
        }
    }
    let get = |m: &BTreeMap<String, i64>, k: &str| m.get(k).copied().unwrap_or(0);
    let req = request_amounts(pod);
    let mut out = Vec::new();

    let allowed_pods = get(&alloc, "pods");
    if other_pods.len() as i64 + 1 > allowed_pods {
        out.push(InsufficientResourceError {
            resource_name: "pods".into(),
            requested: 1,
            used: other_pods.len() as i64,
            capacity: allowed_pods,
        });
    }

    let positive = |k: &str| req.get(k).copied().unwrap_or(0).max(0);
    let scalars: Vec<(&String, i64)> = req
        .iter()
        .filter(|(k, v)| {
            !matches!(k.as_str(), "cpu" | "memory" | "ephemeral-storage" | "pods") && **v != 0
        })
        .map(|(k, v)| (k, *v))
        .collect();
    if positive("cpu") == 0
        && positive("memory") == 0
        && positive("ephemeral-storage") == 0
        && scalars.is_empty()
    {
        return out;
    }

    for name in ["cpu", "memory", "ephemeral-storage"] {
        let r = positive(name);
        if r > 0 && r > get(&alloc, name) - get(&used, name) {
            out.push(InsufficientResourceError {
                resource_name: name.into(),
                requested: r,
                used: get(&used, name),
                capacity: get(&alloc, name),
            });
        }
    }
    for (name, r) in scalars {
        if r > get(&alloc, name) - get(&used, name) {
            out.push(InsufficientResourceError {
                resource_name: name.clone(),
                requested: r,
                used: get(&used, name),
                capacity: get(&alloc, name),
            });
        }
    }
    out
}

/// `GetRequiredNodeAffinity(pod).Match(node)`: nodeSelector AND required
/// node affinity.
fn matches_required_node_affinity(pod: &Pod, node: &Node) -> bool {
    let Some(spec) = pod.spec.as_ref() else {
        return true;
    };
    if let Some(sel) = spec.node_selector.as_ref().filter(|s| !s.is_empty()) {
        let labels = node.metadata.labels.as_ref();
        if !sel
            .iter()
            .all(|(k, v)| labels.and_then(|l| l.get(k)) == Some(v))
        {
            return false;
        }
    }
    if let Some(required) = spec
        .affinity
        .as_ref()
        .and_then(|a| a.node_affinity.as_ref())
        .and_then(|n| {
            n.required_during_scheduling_ignored_during_execution
                .as_ref()
        })
    {
        return matches_node_selector(node, required);
    }
    true
}

/// `nodename.Fits`.
fn fits_node_name(pod: &Pod, node: &Node) -> bool {
    match pod
        .spec
        .as_ref()
        .and_then(|s| s.node_name.as_deref())
        .filter(|n| !n.is_empty())
    {
        None => true,
        Some(n) => n == node.metadata.name,
    }
}

/// `schedutil.GetHostPorts` (`pkg/scheduler/util/utils.go:183`): host ports of
/// app containers and of restartable (sidecar) init containers.
fn host_ports(pod: &Pod) -> Vec<(String, String, i32)> {
    let mut out = Vec::new();
    let Some(spec) = pod.spec.as_ref() else {
        return out;
    };
    let mut add = |c: &Container| {
        for p in c.ports.iter().flatten() {
            if let Some(hp) = p.host_port.filter(|hp| *hp > 0) {
                out.push((
                    p.host_ip.clone().unwrap_or_default(),
                    p.protocol.clone(),
                    i32::from(hp),
                ));
            }
        }
    };
    for c in spec.init_containers.iter().flatten() {
        if c.restart_policy.as_deref() == Some("Always") {
            add(c);
        }
    }
    for c in &spec.containers {
        add(c);
    }
    out
}

/// `HostPortInfo.sanitize`.
fn sanitize(ip: &str, protocol: &str) -> (String, String) {
    (
        if ip.is_empty() { "0.0.0.0" } else { ip }.to_string(),
        if protocol.is_empty() { "TCP" } else { protocol }.to_string(),
    )
}

/// `nodeports.Fits` / `HostPortInfo.CheckConflict`.
fn fits_ports(pod: &Pod, other_pods: &[Pod]) -> bool {
    let used: Vec<(String, String, i32)> = other_pods
        .iter()
        .flat_map(host_ports)
        .map(|(ip, proto, port)| {
            let (ip, proto) = sanitize(&ip, &proto);
            (ip, proto, port)
        })
        .collect();
    for (ip, proto, port) in host_ports(pod) {
        let (ip, proto) = sanitize(&ip, &proto);
        let conflict = used.iter().any(|(uip, uproto, uport)| {
            *uport == port
                && *uproto == proto
                && (ip == "0.0.0.0" || uip == "0.0.0.0" || *uip == ip)
        });
        if conflict {
            return false;
        }
    }
    true
}

/// `ToleratesTaint` with `TaintTolerationComparisonOperators` disabled
/// (`staging/src/k8s.io/api/core/v1/toleration.go`).
fn toleration_tolerates_taint(t: &Toleration, taint: &Taint) -> bool {
    if let Some(effect) = t.effect.as_deref().filter(|e| !e.is_empty()) {
        if effect != taint.effect {
            return false;
        }
    }
    let key = t.key.as_deref().unwrap_or("");
    if !key.is_empty() && key != taint.key {
        return false;
    }
    match t.operator.as_deref().unwrap_or("") {
        "" | "Equal" => t.value.as_deref().unwrap_or("") == taint.value.as_deref().unwrap_or(""),
        "Exists" => true,
        _ => false,
    }
}

/// `types.IsStaticPod` (`pkg/kubelet/types/pod_update.go:154`).
pub fn is_static_pod(pod: &Pod) -> bool {
    pod.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(CONFIG_SOURCE_ANNOTATION))
        .is_some_and(|s| s != API_SERVER_SOURCE)
}

/// `scheduler.AdmissionCheck(pod, nodeInfo, includeAllFailures=true)`
/// (`eventhandlers.go:754`) followed by the kubelet's NoExecute taint check.
pub fn general_filter(pod: &Pod, node: &Node, other_pods: &[Pod]) -> Vec<PredicateFailure> {
    let mut reasons: Vec<PredicateFailure> = fits_resources(pod, node, other_pods)
        .into_iter()
        .map(PredicateFailure::InsufficientResource)
        .collect();
    if !matches_required_node_affinity(pod, node) {
        reasons.push(PredicateFailure::predicate(
            NODE_AFFINITY_NAME,
            ERR_REASON_NODE_AFFINITY,
        ));
    }
    if !fits_node_name(pod, node) {
        reasons.push(PredicateFailure::predicate(
            NODE_NAME_NAME,
            ERR_REASON_NODE_NAME,
        ));
    }
    if !fits_ports(pod, other_pods) {
        reasons.push(PredicateFailure::predicate(
            NODE_PORTS_NAME,
            ERR_REASON_NODE_PORTS,
        ));
    }
    // Taint/toleration check except for static pods; kubelet only cares
    // about NoExecute.
    if !is_static_pod(pod) {
        let tolerations: &[Toleration] = pod
            .spec
            .as_ref()
            .and_then(|s| s.tolerations.as_deref())
            .unwrap_or(&[]);
        let untolerated = node
            .spec
            .as_ref()
            .and_then(|s| s.taints.as_ref())
            .into_iter()
            .flatten()
            .filter(|t| t.effect == "NoExecute")
            .any(|t| {
                !tolerations
                    .iter()
                    .any(|tol| toleration_tolerates_taint(tol, t))
            });
        if untolerated {
            reasons.push(PredicateFailure::predicate(
                TAINT_TOLERATION_NAME,
                ERR_REASON_TAINT_NOT_MATCH,
            ));
        }
    }
    reasons
}

/// `predicateAdmitHandler.generalFilter` (`predicate.go:227`): when node
/// affinity is the only failure, re-fetch the node synchronously and retry.
fn general_filter_with_retry<F>(
    pod: &Pod,
    node: &mut Node,
    other_pods: &[Pod],
    get_node: &mut F,
) -> Vec<PredicateFailure>
where
    F: FnMut(bool) -> Result<Node, String>,
{
    let mut reasons = general_filter(pod, node, other_pods);
    if reasons.is_empty()
        || reasons
            .iter()
            .any(|r| r.get_reason() != ERR_REASON_NODE_AFFINITY)
    {
        return reasons;
    }
    match get_node(false) {
        Ok(fresh) => {
            *node = fresh;
            reasons = general_filter(pod, node, other_pods);
            reasons
        }
        Err(_) => reasons,
    }
}

/// `predicateAdmitHandler.Admit` (`predicate.go:118`). `get_node(use_cache)`
/// is `getNodeAnyWayFunc`.
pub fn admit<F>(attrs: &PodAdmitAttributes<'_>, mut get_node: F) -> PodAdmitResult
where
    F: FnMut(bool) -> Result<Node, String>,
{
    let mut node = match get_node(true) {
        Ok(n) => n,
        Err(_) => {
            return PodAdmitResult::reject(INVALID_NODE_INFO, "Kubelet cannot get node info.");
        }
    };
    let pod = attrs.pod;

    // Checks that preemption cannot help come first.
    if reject_pod_admission_based_on_os_selector(pod, &node) {
        return PodAdmitResult::reject(
            POD_OS_SELECTOR_NODE_LABEL_DOES_NOT_MATCH,
            "Failed to admit pod as the `kubernetes.io/os` label doesn't match node label",
        );
    }
    if reject_pod_admission_based_on_os_field(pod) {
        return PodAdmitResult::reject(
            POD_OS_NOT_SUPPORTED,
            "Failed to admit pod as the OS field doesn't match node OS",
        );
    }
    if reject_pod_admission_based_on_supplemental_groups_policy(pod, &node) {
        return PodAdmitResult::reject(
            SUPPLEMENTAL_GROUPS_POLICY_NOT_SUPPORTED,
            "SupplementalGroupsPolicy=Strict is not supported in this node",
        );
    }

    let filtered = remove_missing_extended_resources(pod, &node);
    let reasons = general_filter_with_retry(&filtered, &mut node, attrs.other_pods, &mut get_node);
    // Only the first failed predicate is reported.
    let Some(first) = reasons.first() else {
        return PodAdmitResult {
            admit: true,
            ..Default::default()
        };
    };
    match first {
        PredicateFailure::Predicate(e) => {
            PodAdmitResult::reject(e.predicate_name.clone(), e.to_string())
        }
        PredicateFailure::InsufficientResource(e) => {
            let reason = match e.resource_name.as_str() {
                "cpu" => OUT_OF_CPU.to_string(),
                "memory" => OUT_OF_MEMORY.to_string(),
                "ephemeral-storage" => OUT_OF_EPHEMERAL_STORAGE.to_string(),
                "pods" => OUT_OF_PODS.to_string(),
                other => format!("{INSUFFICIENT_RESOURCE_PREFIX}{other}"),
            };
            PodAdmitResult::reject(reason, e.to_string())
        }
    }
}
