//! Scheduling Framework Plugin System
//!
//! This module implements the Kubernetes Scheduling Framework, which provides
//! an extensible plugin architecture for customizing scheduling decisions.
//!
//! The framework defines several extension points during the scheduling cycle:
//! - PreFilter: Pre-processing before filtering
//! - Filter: Hard constraints (node must pass to be considered)
//! - PostFilter: Invoked when no nodes pass filtering (for preemption, etc.)
//! - PreScore: Pre-processing before scoring
//! - Score: Soft constraints (nodes are scored/ranked)
//! - Reserve: Reserve resources for a pod on a node
//! - Permit: Final approval before binding
//! - PreBind: Pre-processing before binding
//! - Bind: Bind pod to node
//! - PostBind: Post-processing after binding
//!
//! Reference: https://kubernetes.io/docs/concepts/scheduling-eviction/scheduling-framework/

use async_trait::async_trait;
use kubernetes_rs_common::resources::{Node, Pod};
use std::collections::HashMap;
use std::fmt;

/// Result of a plugin operation
#[derive(Debug, Clone)]
pub struct PluginResult {
    pub code: PluginResultCode,
    pub message: Option<String>,
}

/// Plugin result codes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginResultCode {
    /// Plugin execution succeeded
    Success,
    /// Plugin wants to skip this node (only for Filter)
    Unschedulable,
    /// Plugin error occurred
    Error,
    /// Plugin allows scheduling to proceed (Permit only)
    Wait,
}

impl PluginResult {
    pub fn success() -> Self {
        Self {
            code: PluginResultCode::Success,
            message: None,
        }
    }

    pub fn unschedulable(message: String) -> Self {
        Self {
            code: PluginResultCode::Unschedulable,
            message: Some(message),
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            code: PluginResultCode::Error,
            message: Some(message),
        }
    }

    pub fn is_success(&self) -> bool {
        self.code == PluginResultCode::Success
    }
}

impl fmt::Display for PluginResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(msg) => write!(f, "{:?}: {}", self.code, msg),
            None => write!(f, "{:?}", self.code),
        }
    }
}

/// Node score returned by scoring plugins
#[derive(Debug, Clone)]
pub struct NodeScore {
    pub node_name: String,
    pub score: i64,
}

/// Context passed to plugins during scheduling
pub struct CycleState {
    /// Custom data that plugins can store and retrieve during the scheduling cycle
    pub data: HashMap<String, Box<dyn std::any::Any + Send + Sync>>,
}

impl CycleState {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl Default for CycleState {
    fn default() -> Self {
        Self::new()
    }
}

/// Framework handle provides access to framework APIs for plugins
pub struct FrameworkHandle {
    /// All pods in the cluster (for affinity/anti-affinity checks)
    pub all_pods: Vec<Pod>,
    /// All nodes in the cluster
    pub all_nodes: Vec<Node>,
}

impl FrameworkHandle {
    pub fn new(all_pods: Vec<Pod>, all_nodes: Vec<Node>) -> Self {
        Self {
            all_pods,
            all_nodes,
        }
    }
}

// ============================================================================
// Plugin Traits
// ============================================================================

/// PreFilter plugin is called before filtering to pre-process pod or cluster info
#[async_trait]
pub trait PreFilterPlugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// PreFilter is called at the beginning of the scheduling cycle
    async fn pre_filter(
        &self,
        state: &mut CycleState,
        pod: &Pod,
        handle: &FrameworkHandle,
    ) -> PluginResult;
}

/// Filter plugin filters out nodes that cannot run the pod
#[async_trait]
pub trait FilterPlugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// Filter is called during the filtering phase to check if a node is suitable
    async fn filter(
        &self,
        state: &CycleState,
        pod: &Pod,
        node: &Node,
        handle: &FrameworkHandle,
    ) -> PluginResult;
}

/// PostFilter plugin is called when no nodes are available after filtering
/// Typical use case: preemption
#[async_trait]
pub trait PostFilterPlugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// PostFilter is called after filtering when no feasible nodes found
    /// Returns the result of the post-filtering (e.g., preemption)
    async fn post_filter(
        &self,
        state: &mut CycleState,
        pod: &Pod,
        filtered_nodes: &[Node],
        handle: &FrameworkHandle,
    ) -> PluginResult;
}

/// PreScore plugin is called before scoring to pre-process information
#[async_trait]
pub trait PreScorePlugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// PreScore is called at the beginning of the scoring phase
    async fn pre_score(
        &self,
        state: &mut CycleState,
        pod: &Pod,
        nodes: &[Node],
        handle: &FrameworkHandle,
    ) -> PluginResult;
}

/// Score plugin ranks filtered nodes by assigning scores
#[async_trait]
pub trait ScorePlugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// Score is called on each filtered node to compute a score (0-100)
    async fn score(
        &self,
        state: &CycleState,
        pod: &Pod,
        node: &Node,
        handle: &FrameworkHandle,
    ) -> Result<i64, String>;

    /// Optional: normalize scores across all nodes after scoring
    async fn normalize_score(
        &self,
        _state: &CycleState,
        _pod: &Pod,
        scores: Vec<NodeScore>,
    ) -> Result<Vec<NodeScore>, String> {
        Ok(scores) // Default: no normalization
    }
}

/// Reserve plugin reserves resources on the selected node
#[async_trait]
pub trait ReservePlugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// Reserve resources for the pod on the node
    async fn reserve(
        &self,
        state: &mut CycleState,
        pod: &Pod,
        node_name: &str,
        handle: &FrameworkHandle,
    ) -> PluginResult;

    /// Unreserve is called when reserve failed or binding failed
    async fn unreserve(
        &self,
        state: &mut CycleState,
        pod: &Pod,
        node_name: &str,
        handle: &FrameworkHandle,
    );
}

/// Permit plugin is the final check before binding
#[async_trait]
pub trait PermitPlugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// Permit is called before binding to approve or deny scheduling
    async fn permit(
        &self,
        state: &mut CycleState,
        pod: &Pod,
        node_name: &str,
        handle: &FrameworkHandle,
    ) -> PluginResult;
}

/// PreBind plugin performs work before binding
#[async_trait]
pub trait PreBindPlugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// PreBind is called before binding the pod
    async fn pre_bind(
        &self,
        state: &mut CycleState,
        pod: &Pod,
        node_name: &str,
        handle: &FrameworkHandle,
    ) -> PluginResult;
}

/// Bind plugin binds the pod to a node
#[async_trait]
pub trait BindPlugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// Bind the pod to the node
    async fn bind(
        &self,
        state: &mut CycleState,
        pod: &Pod,
        node_name: &str,
        handle: &FrameworkHandle,
    ) -> PluginResult;
}

/// PostBind plugin performs work after binding
#[async_trait]
pub trait PostBindPlugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// PostBind is called after binding the pod
    async fn post_bind(
        &self,
        state: &mut CycleState,
        pod: &Pod,
        node_name: &str,
        handle: &FrameworkHandle,
    );
}
