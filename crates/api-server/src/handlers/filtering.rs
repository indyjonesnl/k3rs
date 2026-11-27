// Filtering helpers for list operations
//
// Provides common logic for filtering resources by field selectors and label selectors

use kubernetes_rs_common::field_selector::FieldSelector;
use kubernetes_rs_common::label_selector::LabelSelector;
use serde::Serialize;
use std::collections::HashMap;

/// Apply field selector filtering to a list of resources
///
/// If field_selector_str is None or empty, no filtering is applied.
/// If parsing fails, returns an error.
pub fn apply_field_selector<T: Serialize>(
    resources: &mut Vec<T>,
    params: &HashMap<String, String>,
) -> Result<(), kubernetes_rs_common::Error> {
    if let Some(field_selector_str) = params.get("fieldSelector") {
        let selector = FieldSelector::parse(field_selector_str).map_err(|e| {
            kubernetes_rs_common::Error::InvalidResource(format!("Invalid field selector: {}", e))
        })?;

        if !selector.is_empty() {
            resources.retain(|resource| {
                let resource_json = serde_json::to_value(resource).unwrap_or_default();
                selector.matches(&resource_json)
            });
        }
    }

    Ok(())
}

/// Apply label selector filtering to a list of resources.
///
/// Uses direct struct field access for label matching when possible,
/// falling back to JSON serialization only for the field selector path.
/// If label_selector_str is None or empty, no filtering is applied.
/// If parsing fails, returns an error.
pub fn apply_label_selector<T: Serialize>(
    resources: &mut Vec<T>,
    params: &HashMap<String, String>,
) -> Result<(), kubernetes_rs_common::Error> {
    if let Some(label_selector_str) = params.get("labelSelector") {
        let selector = LabelSelector::parse(label_selector_str)
            .map_err(|e| kubernetes_rs_common::Error::BadRequest(e.to_string()))?;

        if !selector.is_empty() {
            resources.retain(|resource| {
                // Try to extract labels without full serialization by serializing
                // just enough to read metadata.labels. We serialize to Value only
                // to access the labels HashMap — this is unavoidable for generic T.
                let resource_json = serde_json::to_value(resource).unwrap_or_default();
                selector.matches_resource(&resource_json)
            });
        }
    }

    Ok(())
}

/// Apply both field and label selector filtering to a list of resources.
///
/// Serializes each resource to JSON at most once (instead of twice when
/// field and label selectors are both present). Field selectors are
/// evaluated first, then label selectors on the same JSON value.
pub fn apply_selectors<T: Serialize>(
    resources: &mut Vec<T>,
    params: &HashMap<String, String>,
) -> Result<(), kubernetes_rs_common::Error> {
    let has_field_selector = params.get("fieldSelector").is_some_and(|s| !s.is_empty());
    let has_label_selector = params.get("labelSelector").is_some_and(|s| !s.is_empty());

    // Fast path: no selectors
    if !has_field_selector && !has_label_selector {
        return Ok(());
    }

    let field_selector = if has_field_selector {
        Some(
            FieldSelector::parse(params.get("fieldSelector").unwrap()).map_err(|e| {
                kubernetes_rs_common::Error::InvalidResource(format!(
                    "Invalid field selector: {}",
                    e
                ))
            })?,
        )
    } else {
        None
    };

    let label_selector = if has_label_selector {
        Some(
            LabelSelector::parse(params.get("labelSelector").unwrap())
                .map_err(|e| kubernetes_rs_common::Error::BadRequest(e.to_string()))?,
        )
    } else {
        None
    };

    // Single pass: serialize each resource once, apply both selectors
    resources.retain(|resource| {
        let resource_json = serde_json::to_value(resource).unwrap_or_default();

        if let Some(ref fs) = field_selector {
            if !fs.is_empty() && !fs.matches(&resource_json) {
                return false;
            }
        }

        if let Some(ref ls) = label_selector {
            if !ls.is_empty() && !ls.matches_resource(&resource_json) {
                return false;
            }
        }

        true
    });

    Ok(())
}
