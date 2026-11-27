//! Ports of apimachinery TestIsValidUserID/TestIsValidGroupID and apis/core
//! TestValidateSecurityContext, plus the pod-level checks of
//! `validatePodSpecSecurityContext`.

use kubernetes_rs_common::resources::pod::{Capabilities, PodSecurityContext, SecurityContext};
use kubernetes_rs_common::validation::field::{ErrorType, Path};
use kubernetes_rs_common::validation::metav1::{is_valid_group_id, is_valid_user_id};
use kubernetes_rs_common::validation::pod_security_context_values::*;

#[test]
fn security_context_values_is_valid_ids() {
    for v in [0, 1, 1000, 65535, 2147483647] {
        assert!(is_valid_user_id(v).is_empty(), "uid {v}");
        assert!(is_valid_group_id(v).is_empty(), "gid {v}");
    }
    for v in [-1, -1003, 2147483648, 4147483647] {
        assert_eq!(
            is_valid_user_id(v),
            vec!["must be between 0 and 2147483647, inclusive".to_string()]
        );
        assert_eq!(is_valid_group_id(v).len(), 1, "gid {v}");
    }
}

fn full_valid_sc() -> SecurityContext {
    serde_json::from_value(serde_json::json!({
        "privileged": false,
        "capabilities": {"add": ["foo"], "drop": ["bar"]},
        "seLinuxOptions": {"user": "user", "role": "role", "type": "type", "level": "level"},
        "runAsUser": 1
    }))
    .unwrap()
}

#[test]
fn security_context_values_container_success_cases() {
    let p = Path::new("field");
    let mut no_caps = full_valid_sc();
    no_caps.capabilities = None;
    let mut no_priv = full_valid_sc();
    no_priv.privileged = None;
    let mut no_user = full_valid_sc();
    no_user.run_as_user = None;
    let mut pm_default = full_valid_sc();
    pm_default.proc_mount = Some("Default".into());
    let mut pm_unmasked = full_valid_sc();
    pm_unmasked.proc_mount = Some("Unmasked".into());
    for (name, sc, host_users) in [
        ("all settings", full_valid_sc(), false),
        ("no capabilities", no_caps, false),
        ("no priv request", no_priv, false),
        ("no run as user", no_user, false),
        ("proc mount set", pm_default, true),
        ("proc mount unmasked", pm_unmasked, false),
    ] {
        let errs = validate_security_context_values(Some(&sc), &p, host_users, false);
        assert!(errs.is_empty(), "[{name}] {errs:?}");
    }
    assert!(validate_security_context_values(None, &p, true, false).is_empty());
}

#[test]
fn security_context_values_container_error_cases() {
    let p = Path::new("field");
    let mut priv_deny = full_valid_sc();
    priv_deny.privileged = Some(true);
    let mut neg = full_valid_sc();
    neg.run_as_user = Some(-1);
    let mut cap_sys_admin = full_valid_sc();
    cap_sys_admin.capabilities = Some(Capabilities {
        add: Some(vec!["CAP_SYS_ADMIN".into()]),
        drop: None,
    });
    cap_sys_admin.allow_privilege_escalation = Some(false);
    let mut priv_no_esc = full_valid_sc();
    priv_no_esc.privileged = Some(true);
    priv_no_esc.allow_privilege_escalation = Some(false);
    let mut unmasked = full_valid_sc();
    unmasked.proc_mount = Some("Unmasked".into());
    let mut bad_pm = full_valid_sc();
    bad_pm.proc_mount = Some("Nope".into());

    let cases = [
        (
            "privileged when forbidden",
            priv_deny,
            false,
            ErrorType::Forbidden,
            "disallowed by cluster policy",
        ),
        (
            "negative RunAsUser",
            neg,
            false,
            ErrorType::Invalid,
            "must be between",
        ),
        (
            "CAP_SYS_ADMIN and allowPrivilegeEscalation false",
            cap_sys_admin,
            true,
            ErrorType::Invalid,
            "cannot set `allowPrivilegeEscalation` to false and `capabilities.Add` CAP_SYS_ADMIN",
        ),
        (
            "privileged and allowPrivilegeEscalation false",
            priv_no_esc,
            true,
            ErrorType::Invalid,
            "cannot set `allowPrivilegeEscalation` to false and `privileged` to true",
        ),
        (
            "unmasked proc mount with host users",
            unmasked,
            true,
            ErrorType::Invalid,
            "`hostUsers` must be false to use `Unmasked`",
        ),
        (
            "unknown proc mount",
            bad_pm,
            false,
            ErrorType::NotSupported,
            "supported values: \"Default\", \"Unmasked\"",
        ),
    ];
    for (name, sc, allow_priv, ty, detail) in cases {
        let errs = validate_security_context_values(Some(&sc), &p, true, allow_priv);
        assert!(
            !errs.is_empty() && errs[0].error_type == ty && errs[0].detail.contains(detail),
            "[{name}] want {ty:?} {detail:?}, got {errs:?}"
        );
    }
}

#[test]
fn security_context_values_pod_level() {
    let p = Path::new("spec").child("securityContext");
    assert!(validate_pod_spec_security_context_values(None, Some(true), true, &p).is_empty());

    let sc = PodSecurityContext {
        fs_group: Some(-1),
        run_as_user: Some(2147483648),
        run_as_group: Some(-5),
        supplemental_groups: Some(vec![1, -2]),
        fs_group_change_policy: Some("Sometimes".into()),
        supplemental_groups_policy: Some("Never".into()),
        ..Default::default()
    };
    let errs = validate_pod_spec_security_context_values(Some(&sc), Some(true), true, &p);
    let fields: Vec<&str> = errs.iter().map(|e| e.field.as_str()).collect();
    assert_eq!(
        fields,
        vec![
            "spec.securityContext.fsGroup",
            "spec.securityContext.runAsUser",
            "spec.securityContext.runAsGroup",
            "spec.securityContext.supplementalGroups[1]",
            "spec.securityContext.shareProcessNamespace",
            "spec.securityContext.fsGroupChangePolicy",
            "spec.securityContext.supplementalGroupsPolicy",
        ]
    );
    assert_eq!(
        errs[4].detail,
        "ShareProcessNamespace and HostPID cannot both be enabled"
    );
    assert_eq!(errs[5].error_type, ErrorType::NotSupported);
    assert!(errs[5].detail.contains("\"Always\", \"OnRootMismatch\""));
    assert!(errs[6].detail.contains("\"Merge\", \"Strict\""));

    // Valid values and no HostPID conflict.
    let ok = PodSecurityContext {
        fs_group: Some(0),
        run_as_user: Some(2147483647),
        supplemental_groups: Some(vec![0, 100]),
        fs_group_change_policy: Some("OnRootMismatch".into()),
        supplemental_groups_policy: Some("Strict".into()),
        ..Default::default()
    };
    assert!(validate_pod_spec_security_context_values(Some(&ok), Some(true), false, &p).is_empty());
    assert!(validate_pod_spec_security_context_values(Some(&ok), Some(false), true, &p).is_empty());
}
