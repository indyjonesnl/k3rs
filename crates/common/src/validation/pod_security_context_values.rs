//! Pod and container securityContext value validation.
//!
//! Port of pkg/apis/core/validation/validation.go (release-1.35):
//! `validatePodSpecSecurityContext` (:5527, the uid/gid, shareProcessNamespace,
//! fsGroupChangePolicy and supplementalGroupsPolicy checks),
//! `validateFSGroupChangePolicy` (:4115), `validateSupplementalGroupsPolicy`
//! (:9384), `ValidateSecurityContext` (:8358) and `ValidateProcMountType`
//! (:8728).
//!
//! The pod-level checks are called from `validate_pod_spec_for` (pod.rs) in
//! upstream's order; sysctls, seccomp, windowsOptions, appArmor and
//! seLinuxChangePolicy live next to it in pod.rs.

use crate::resources::pod::{PodSecurityContext, SecurityContext};
use crate::validation::field::{Error, ErrorList, Path};
use crate::validation::metav1::{is_valid_group_id, is_valid_user_id};

/// `validFSGroupChangePolicies`, in `sets.List` (sorted) order.
const VALID_FS_GROUP_CHANGE_POLICIES: [&str; 2] = ["Always", "OnRootMismatch"];
/// `validSupplementalGroupsPolicies`, sorted.
const VALID_SUPPLEMENTAL_GROUPS_POLICIES: [&str; 2] = ["Merge", "Strict"];

/// `validateFSGroupChangePolicy` (validation.go:4115).
pub fn validate_fs_group_change_policy(policy: &str, fld_path: &Path) -> ErrorList {
    if VALID_FS_GROUP_CHANGE_POLICIES.contains(&policy) {
        return Vec::new();
    }
    vec![Error::not_supported(
        fld_path,
        policy,
        &VALID_FS_GROUP_CHANGE_POLICIES,
    )]
}

/// `validateSupplementalGroupsPolicy` (validation.go:9384).
pub fn validate_supplemental_groups_policy(policy: &str, fld_path: &Path) -> ErrorList {
    if VALID_SUPPLEMENTAL_GROUPS_POLICIES.contains(&policy) {
        return Vec::new();
    }
    vec![Error::not_supported(
        fld_path,
        policy,
        &VALID_SUPPLEMENTAL_GROUPS_POLICIES,
    )]
}

/// `ValidateProcMountType` (validation.go:8728).
pub fn validate_proc_mount_type(fld_path: &Path, proc_mount: &str) -> Option<Error> {
    match proc_mount {
        "Default" | "Unmasked" => None,
        other => Some(Error::not_supported(
            fld_path,
            other,
            &["Default", "Unmasked"],
        )),
    }
}

/// The value-level checks of `validatePodSpecSecurityContext`
/// (validation.go:5527-5576). `share_process_namespace` and `host_pid` live
/// on the internal PodSecurityContext upstream; here they come from the
/// PodSpec. Callers that interleave the other sub-validators in upstream's
/// order use [`validate_pod_spec_security_context_ids`] and the individual
/// policy validators instead.
pub fn validate_pod_spec_security_context_values(
    security_context: Option<&PodSecurityContext>,
    share_process_namespace: Option<bool>,
    host_pid: bool,
    fld_path: &Path,
) -> ErrorList {
    let mut errs = validate_pod_spec_security_context_ids(
        security_context,
        share_process_namespace,
        host_pid,
        fld_path,
    );
    let Some(sc) = security_context else {
        return errs;
    };
    if let Some(p) = &sc.fs_group_change_policy {
        errs.extend(validate_fs_group_change_policy(
            p,
            &fld_path.child("fsGroupChangePolicy"),
        ));
    }
    if let Some(p) = &sc.supplemental_groups_policy {
        errs.extend(validate_supplemental_groups_policy(
            p,
            &fld_path.child("supplementalGroupsPolicy"),
        ));
    }
    errs
}

/// The first group of `validatePodSpecSecurityContext` (validation.go:5531-5551):
/// fsGroup, runAsUser, runAsGroup, supplementalGroups ranges and the
/// shareProcessNamespace/hostPID conflict.
pub fn validate_pod_spec_security_context_ids(
    security_context: Option<&PodSecurityContext>,
    share_process_namespace: Option<bool>,
    host_pid: bool,
    fld_path: &Path,
) -> ErrorList {
    let mut errs = Vec::new();
    let Some(sc) = security_context else {
        return errs;
    };
    if let Some(v) = sc.fs_group {
        for msg in is_valid_group_id(v) {
            errs.push(Error::invalid(&fld_path.child("fsGroup"), v, msg));
        }
    }
    if let Some(v) = sc.run_as_user {
        for msg in is_valid_user_id(v) {
            errs.push(Error::invalid(&fld_path.child("runAsUser"), v, msg));
        }
    }
    if let Some(v) = sc.run_as_group {
        for msg in is_valid_group_id(v) {
            errs.push(Error::invalid(&fld_path.child("runAsGroup"), v, msg));
        }
    }
    for (g, gid) in sc.supplemental_groups.iter().flatten().enumerate() {
        for msg in is_valid_group_id(*gid) {
            errs.push(Error::invalid(
                &fld_path.child("supplementalGroups").index(g),
                *gid,
                msg,
            ));
        }
    }
    if share_process_namespace == Some(true) && host_pid {
        errs.push(Error::invalid(
            &fld_path.child("shareProcessNamespace"),
            true,
            "ShareProcessNamespace and HostPID cannot both be enabled",
        ));
    }
    errs
}

/// The value-level checks of `ValidateSecurityContext` (validation.go:8358).
/// `allow_privileged` is `capabilities.Get().AllowPrivileged`.
pub fn validate_security_context_values(
    sc: Option<&SecurityContext>,
    fld_path: &Path,
    host_users: bool,
    allow_privileged: bool,
) -> ErrorList {
    let mut errs = Vec::new();
    // Only true for testing: SecurityContext is defaulted by the core.
    let Some(sc) = sc else { return errs };

    if sc.privileged == Some(true) && !allow_privileged {
        errs.push(Error::forbidden(
            &fld_path.child("privileged"),
            "disallowed by cluster policy",
        ));
    }
    if let Some(v) = sc.run_as_user {
        for msg in is_valid_user_id(v) {
            errs.push(Error::invalid(&fld_path.child("runAsUser"), v, msg));
        }
    }
    if let Some(v) = sc.run_as_group {
        for msg in is_valid_group_id(v) {
            errs.push(Error::invalid(&fld_path.child("runAsGroup"), v, msg));
        }
    }
    if let Some(pm) = &sc.proc_mount {
        if let Some(e) = validate_proc_mount_type(&fld_path.child("procMount"), pm) {
            errs.push(e);
        }
        if host_users && pm == "Unmasked" {
            errs.push(Error::invalid(
                &fld_path.child("procMount"),
                pm.as_str(),
                "`hostUsers` must be false to use `Unmasked`",
            ));
        }
    }
    if sc.allow_privilege_escalation == Some(false) {
        let whole = serde_json::to_value(sc).unwrap_or(serde_json::Value::Null);
        if sc.privileged == Some(true) {
            errs.push(Error::invalid(
                fld_path,
                whole.clone(),
                "cannot set `allowPrivilegeEscalation` to false and `privileged` to true",
            ));
        }
        if let Some(caps) = &sc.capabilities {
            for cap in caps.add.iter().flatten() {
                if cap == "CAP_SYS_ADMIN" {
                    errs.push(Error::invalid(
                        fld_path,
                        whole.clone(),
                        "cannot set `allowPrivilegeEscalation` to false and `capabilities.Add` CAP_SYS_ADMIN",
                    ));
                }
            }
        }
    }
    errs
}
