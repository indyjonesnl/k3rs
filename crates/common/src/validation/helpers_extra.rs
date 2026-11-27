//! Domain helpers used by the EndpointSlice, LimitRange and ResourceQuota
//! validators.
//!
//! Ports (release-1.35): `IsFullyQualifiedDomainName`
//! (apimachinery `util/validation/validation.go:57-80`),
//! `LabelSelectorHasInvalidLabelValue` (`apis/meta/v1/validation/validation.go:46`),
//! `IsStandardLimitRangeType` (`pkg/apis/core/helper/helpers.go:210-219`),
//! `IsResourceQuotaScopeValidForResource` (:116-164) and
//! `IsAttachableVolumeResourceName` (`pkg/apis/core/v1/helper/helpers.go:136`).

use crate::types::LabelSelector;
use crate::validation::field::{Error, ErrorList, Path};
use crate::validation::metav1::{is_dns1123_label, is_dns1123_subdomain, is_valid_label_value};

/// `v1.ResourceAttachableVolumesPrefix`.
pub const RESOURCE_ATTACHABLE_VOLUMES_PREFIX: &str = "attachable-volumes-";

/// `IsFullyQualifiedDomainName`: like `IsFullyQualifiedName` but needs at
/// least two segments and accepts one trailing dot.
pub fn is_fully_qualified_domain_name(fld_path: &Path, name: &str) -> ErrorList {
    if name.is_empty() {
        return vec![Error::required(fld_path, "")];
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    let errs = is_dns1123_subdomain(name);
    if !errs.is_empty() {
        return vec![Error::invalid(fld_path, name.to_string(), errs.join(","))];
    }
    if name.split('.').count() < 2 {
        return vec![Error::invalid(
            fld_path,
            name.to_string(),
            "should be a domain with at least two segments separated by dots",
        )];
    }
    for label in name.split('.') {
        let errs = is_dns1123_label(label);
        if !errs.is_empty() {
            return vec![Error::invalid(fld_path, label.to_string(), errs.join(","))];
        }
    }
    Vec::new()
}

/// `LabelSelectorHasInvalidLabelValue`: whether any `matchExpressions` value
/// is not a valid label value.
pub fn label_selector_has_invalid_label_value(ps: Option<&LabelSelector>) -> bool {
    let Some(ps) = ps else { return false };
    ps.match_expressions
        .iter()
        .flatten()
        .flat_map(|e| e.values.iter().flatten())
        .any(|v| !is_valid_label_value(v).is_empty())
}

/// `IsStandardLimitRangeType` (Pod, Container, PersistentVolumeClaim).
pub fn is_standard_limit_range_type(value: &str) -> bool {
    matches!(value, "Pod" | "Container" | "PersistentVolumeClaim")
}

/// `IsAttachableVolumeResourceName`.
pub fn is_attachable_volume_resource_name(name: &str) -> bool {
    name.starts_with(RESOURCE_ATTACHABLE_VOLUMES_PREFIX)
}

const POD_OBJECT_COUNT_QUOTA_RESOURCES: &[&str] = &["pods"];
const POD_COMPUTE_QUOTA_RESOURCES: &[&str] = &[
    "cpu",
    "memory",
    "limits.cpu",
    "limits.memory",
    "requests.cpu",
    "requests.memory",
];
const PVC_OBJECT_COUNT_QUOTA_RESOURCES: &[&str] = &["persistentvolumeclaims"];
const PVC_STORAGE_QUOTA_RESOURCES: &[&str] = &["requests.storage"];

/// `IsResourceQuotaScopeValidForResource`: whether the quota resource applies
/// to the scope; an unknown scope accepts everything.
pub fn is_resource_quota_scope_valid_for_resource(scope: &str, resource: &str) -> bool {
    let has = |set: &[&str]| set.contains(&resource);
    match scope {
        "Terminating"
        | "NotTerminating"
        | "NotBestEffort"
        | "PriorityClass"
        | "CrossNamespacePodAffinity" => {
            has(POD_OBJECT_COUNT_QUOTA_RESOURCES) || has(POD_COMPUTE_QUOTA_RESOURCES)
        }
        "BestEffort" => has(POD_OBJECT_COUNT_QUOTA_RESOURCES),
        "VolumeAttributesClass" => {
            has(PVC_OBJECT_COUNT_QUOTA_RESOURCES) || has(PVC_STORAGE_QUOTA_RESOURCES)
        }
        _ => true,
    }
}
