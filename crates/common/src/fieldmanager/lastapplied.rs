//! The last-applied manager: client-side apply to server-side apply migration.
//!
//! Port of `staging/src/k8s.io/apimachinery/pkg/util/managedfields/internal/lastappliedmanager.go`
//! (release-1.35) `lastAppliedManager.Apply` (:57-90) and
//! `allowedConflictsFromLastApplied` (:92-160), layered as in
//! `NewDefaultFieldManager` (fieldmanager.go:46-61). When `kubectl apply
//! --server-side` (field manager `kubectl`) conflicts with fields that a
//! client-side `kubectl apply` set, and the object's
//! `kubectl.kubernetes.io/last-applied-configuration` annotation says that
//! those fields were set by that apply and still hold the applied value, the
//! apply is forced instead of reporting conflicts.

use std::collections::HashSet;

use serde_json::Value;

use super::apply::path_string;
use super::fieldset::Set;
use super::versionconverter::UpdateFailure;
use super::FieldManager;

/// `LastAppliedConfigAnnotation` (lastapplied.go:31).
pub const LAST_APPLIED_CONFIG_ANNOTATION: &str = "kubectl.kubernetes.io/last-applied-configuration";

impl FieldManager {
    /// `lastAppliedManager.Apply` (lastappliedmanager.go:57).
    pub(super) fn apply_value_last_applied(
        &self,
        live: Option<&Value>,
        config: &Value,
        manager: &str,
        force: bool,
    ) -> Result<Value, UpdateFailure> {
        let result = self.apply_value_inner(live, config, manager, force);
        // Upgrade the client-side apply annotation only from kubectl
        // server-side-apply. To opt out, specify a different field manager.
        if manager != "kubectl" {
            return result;
        }
        let Err(UpdateFailure::Conflicts(conflicts)) = &result else {
            return result;
        };
        let Ok(allowed) = self.allowed_conflicts_from_last_applied(live) else {
            return result;
        };
        let allowed: HashSet<String> = allowed.members().iter().map(|p| path_string(p)).collect();
        // conflictsDifference: the conflicts last-applied does not excuse.
        let remaining: Vec<_> = conflicts
            .iter()
            .filter(|c| !allowed.contains(&c.path))
            .cloned()
            .collect();
        if !remaining.is_empty() {
            return Err(UpdateFailure::Conflicts(remaining));
        }
        self.apply_value_inner(live, config, manager, true)
    }

    /// `allowedConflictsFromLastApplied` (lastappliedmanager.go:92): the
    /// fields of the last-applied configuration that the live object still
    /// matches. Any problem is an error, which the caller treats as "no
    /// fields are excused".
    fn allowed_conflicts_from_last_applied(&self, live: Option<&Value>) -> Result<Set, String> {
        let live = live.ok_or("no last applied annotation")?;
        let last_applied = live
            .pointer("/metadata/annotations")
            .and_then(|a| a.get(LAST_APPLIED_CONFIG_ANNOTATION))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("no last applied annotation")?;

        let live_versioned = self
            .convert_to(live, &self.api_version)
            .map_err(|e| format!("failed to convert live obj to versioned: {e}"))?;

        let last_applied_obj: Value = serde_json::from_str(last_applied)
            .map_err(|e| format!("failed to decode last applied obj: {e} in '{last_applied}'"))?;
        let got = last_applied_obj
            .get("apiVersion")
            .and_then(Value::as_str)
            .unwrap_or("");
        if got != self.api_version {
            return Err(format!(
                "expected version of last applied to match live object '{}', but got '{}'",
                self.api_version, got
            ));
        }

        let live_fields = self.fields_of(&live_versioned);
        let last_fields = self.fields_of(&last_applied_obj);
        let comparison = last_fields.compare(&live_fields);

        // Remove fields in last applied that are different, added, or missing
        // in the live object: those are not owned by the client-side apply.
        Ok(last_fields
            .set
            .difference(&comparison.modified)
            .difference(&comparison.added)
            .difference(&comparison.removed))
    }
}
