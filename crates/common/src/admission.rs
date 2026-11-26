// Admission webhook wire types (AdmissionReview v1) and shared request types.
//
// The admission plugins themselves live in `kubernetes-rs-api-server`
// (`src/admission/**`), ported from upstream `plugin/pkg/admission/**` and
// `staging/src/k8s.io/pod-security-admission`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of an admission decision
#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionResponse {
    /// Request is allowed
    Allow,
    /// Request is denied with a reason
    Deny(String),
    /// Request is allowed with mutations (JSON Patch format)
    AllowWithPatch(Vec<PatchOperation>),
}

impl AdmissionResponse {
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            AdmissionResponse::Allow | AdmissionResponse::AllowWithPatch(_)
        )
    }

    pub fn deny_reason(&self) -> Option<&str> {
        match self {
            AdmissionResponse::Deny(reason) => Some(reason),
            _ => None,
        }
    }

    pub fn patches(&self) -> Option<&[PatchOperation]> {
        match self {
            AdmissionResponse::AllowWithPatch(patches) => Some(patches),
            _ => None,
        }
    }
}

/// JSON Patch operation (RFC 6902)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchOperation {
    pub op: PatchOp,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatchOp {
    Add,
    Remove,
    Replace,
    Move,
    Copy,
    Test,
}

/// Admission request containing the resource to be validated/mutated.
///
/// Mirrors the K8s admission `request` payload exposed to CEL expressions in
/// `ValidatingAdmissionPolicy.spec.matchConditions[*]` and
/// `Webhook.matchConditions[*]`. CEL expressions reference these fields via
/// `request.kind.group`, `request.kind.version`, `request.kind.kind`,
/// `request.operation`, etc.
///
/// Upstream Go reference: `staging/src/k8s.io/api/admission/v1/types.go`
/// (`AdmissionRequest` — the wire request that webhooks receive).
#[derive(Debug, Clone)]
pub struct AdmissionRequest {
    /// The operation being performed (CREATE, UPDATE, DELETE)
    pub operation: Operation,
    /// The API group of the resource (e.g. "apps", or "" for core).
    pub group: String,
    /// The API version of the resource (e.g. "v1", "v1beta1").
    pub version: String,
    /// The resource kind (Pod, Service, etc.)
    pub kind: String,
    /// The resource namespace (if namespaced)
    pub namespace: Option<String>,
    /// The resource name
    pub name: String,
    /// The resource object (JSON)
    pub object: serde_json::Value,
    /// The old resource object for UPDATE operations
    pub old_object: Option<serde_json::Value>,
    /// The user making the request
    pub user_info: UserInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Operation {
    Create,
    Update,
    Delete,
    Connect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub uid: String,
    pub groups: Vec<String>,
}

// ===== Admission Webhook Types (for external webhooks) =====

/// AdmissionReview is the top-level request/response object for admission webhooks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReview {
    pub api_version: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<AdmissionReviewRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<AdmissionReviewResponse>,
}

impl AdmissionReview {
    /// Create a new AdmissionReview request
    pub fn new_request(request: AdmissionReviewRequest) -> Self {
        Self {
            api_version: "admission.k8s.io/v1".to_string(),
            kind: "AdmissionReview".to_string(),
            request: Some(request),
            response: None,
        }
    }

    /// Create a new AdmissionReview response
    pub fn new_response(response: AdmissionReviewResponse) -> Self {
        Self {
            api_version: "admission.k8s.io/v1".to_string(),
            kind: "AdmissionReview".to_string(),
            request: None,
            response: Some(response),
        }
    }
}

/// AdmissionReviewRequest describes an admission request sent to a webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReviewRequest {
    /// UID is a unique identifier for this admission request
    pub uid: String,

    /// Kind is the fully-qualified type of the object being submitted
    pub kind: GroupVersionKind,

    /// Resource is the fully-qualified resource being requested
    pub resource: GroupVersionResource,

    /// SubResource is the sub-resource being requested, if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_resource: Option<String>,

    /// RequestKind is the type of the object in the original request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_kind: Option<GroupVersionKind>,

    /// RequestResource is the resource in the original request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_resource: Option<GroupVersionResource>,

    /// RequestSubResource is the sub-resource in the original request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_sub_resource: Option<String>,

    /// Name is the name of the object being modified
    pub name: String,

    /// Namespace is the namespace of the object being modified (if namespaced)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Operation is the operation being performed
    pub operation: Operation,

    /// UserInfo contains information about the user making the request
    pub user_info: UserInfo,

    /// Object is the object being admitted (for CREATE and UPDATE operations)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<serde_json::Value>,

    /// OldObject is the existing object (for UPDATE and DELETE operations)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_object: Option<serde_json::Value>,

    /// DryRun indicates the request is for a dry-run
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,

    /// Options contains the operation options (e.g., CreateOptions, UpdateOptions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<serde_json::Value>,
}

/// GroupVersionKind identifies a type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupVersionKind {
    pub group: String,
    pub version: String,
    pub kind: String,
}

/// GroupVersionResource identifies a resource
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupVersionResource {
    pub group: String,
    pub version: String,
    pub resource: String,
}

/// AdmissionReviewResponse describes the admission response from a webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReviewResponse {
    /// UID echoes the UID from the request
    pub uid: String,

    /// Allowed indicates whether the request is allowed
    pub allowed: bool,

    /// Status contains extra details about the result (for denials)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AdmissionStatus>,

    /// Patch is a JSONPatch to apply to the object (for mutating webhooks)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>, // Base64-encoded JSON patch

    /// PatchType is the type of patch (currently only "JSONPatch" is supported)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_type: Option<String>,

    /// AuditAnnotations are key-value pairs to add to the audit event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_annotations: Option<HashMap<String, String>>,

    /// Warnings are messages to return to the user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

impl AdmissionReviewResponse {
    /// Create an allowed response
    pub fn allow(uid: String) -> Self {
        Self {
            uid,
            allowed: true,
            status: None,
            patch: None,
            patch_type: None,
            audit_annotations: None,
            warnings: None,
        }
    }

    /// Create a denied response
    pub fn deny(uid: String, message: String) -> Self {
        Self {
            uid,
            allowed: false,
            status: Some(AdmissionStatus {
                status: "Failure".to_string(),
                message: Some(message),
                reason: Some("Denied by webhook".to_string()),
                code: Some(403),
                metadata: None,
            }),
            patch: None,
            patch_type: None,
            audit_annotations: None,
            warnings: None,
        }
    }

    /// Create an allowed response with a JSON patch
    pub fn allow_with_patch(uid: String, patch: Vec<PatchOperation>) -> Self {
        let patch_json = serde_json::to_string(&patch).unwrap_or_default();
        let patch_base64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            patch_json.as_bytes(),
        );

        Self {
            uid,
            allowed: true,
            status: None,
            patch: Some(patch_base64),
            patch_type: Some("JSONPatch".to_string()),
            audit_annotations: None,
            warnings: None,
        }
    }
}

/// AdmissionStatus contains extra details about the admission response.
/// Maps to metav1.Status in K8s which has metadata, status, message, reason, code.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionStatus {
    #[serde(default)]
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    /// K8s metav1.Status includes metadata — we ignore it but accept it
    #[serde(default, skip_serializing)]
    pub metadata: Option<serde_json::Value>,
}
