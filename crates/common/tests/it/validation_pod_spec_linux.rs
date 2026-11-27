//! Ports of `TestValidatePodHostName` (validation_test.go:26252) and
//! `TestValidateLinuxPodSecurityContext` (:8551).

use kubernetes_rs_common::resources::pod::{
    Container, PodSecurityContext, PodSpec, SecurityContext, WindowsSecurityContextOptions,
};
use kubernetes_rs_common::validation::field::{Error, ErrorType, Path};
use kubernetes_rs_common::validation::pod_spec_linux::{validate_linux, validate_pod_host_name};

fn spec_with_override(h: &str) -> PodSpec {
    PodSpec {
        hostname_override: Some(h.to_string()),
        ..Default::default()
    }
}

fn kinds(errs: &[Error]) -> Vec<(ErrorType, String, String)> {
    errs.iter()
        .map(|e| (e.error_type, e.field.clone(), e.origin.clone()))
        .collect()
}

#[test]
fn pod_hostname_override_unset_is_ok() {
    assert!(validate_pod_host_name(&PodSpec::default(), &Path::new("spec")).is_empty());
}

#[test]
fn pod_hostname_override_valid_values() {
    for h in ["a", "custom-host", &"a".repeat(64)] {
        let errs = validate_pod_host_name(&spec_with_override(h), &Path::new("spec"));
        assert!(errs.is_empty(), "{h}: {errs:?}");
    }
}

#[test]
fn pod_hostname_override_empty_and_non_rfc1123_are_invalid() {
    for h in ["", "Not-RFC1123"] {
        let errs = validate_pod_host_name(&spec_with_override(h), &Path::new("spec"));
        assert_eq!(
            kinds(&errs),
            vec![(
                ErrorType::Invalid,
                "spec.hostnameOverride".into(),
                "format=k8s-long-name".into()
            )],
            "{h}"
        );
    }
}

#[test]
fn pod_hostname_override_too_long() {
    let errs = validate_pod_host_name(&spec_with_override(&"a".repeat(65)), &Path::new("spec"));
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].error_type, ErrorType::TooLong);
    assert_eq!(errs[0].field, "spec.hostnameOverride");
}

#[test]
fn pod_hostname_override_forbidden_with_fqdn_or_host_network() {
    let mut s = spec_with_override("custom-host");
    s.set_hostname_as_fqdn = Some(true);
    let errs = validate_pod_host_name(&s, &Path::new("spec"));
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].error_type, ErrorType::Forbidden);
    assert!(errs[0].detail.contains("setHostnameAsFQDN"));

    let mut s = spec_with_override("custom-host");
    s.host_network = Some(true);
    let errs = validate_pod_host_name(&s, &Path::new("spec"));
    assert_eq!(errs.len(), 1);
    assert!(errs[0].detail.contains("hostNetwork"));

    let mut s = spec_with_override("custom-host");
    s.set_hostname_as_fqdn = Some(false);
    s.host_network = Some(false);
    assert!(validate_pod_host_name(&s, &Path::new("spec")).is_empty());
}

fn win() -> Option<WindowsSecurityContextOptions> {
    Some(WindowsSecurityContextOptions {
        gmsa_credential_spec_name: None,
        gmsa_credential_spec: None,
        run_as_user_name: Some("myUser".into()),
        host_process: None,
    })
}

#[test]
fn pod_hostname_override_linux_pod_security_context() {
    let valid = PodSpec {
        security_context: Some(PodSecurityContext {
            run_as_user: Some(1),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(validate_linux(&valid, &Path::new("field")).is_empty());

    let invalid = PodSpec {
        security_context: Some(PodSecurityContext {
            windows_options: win(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let errs = validate_linux(&invalid, &Path::new("field"));
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].error_type, ErrorType::Forbidden);
    assert_eq!(errs[0].field, "field.securityContext.windowsOptions");
    assert!(errs[0]
        .detail
        .contains("windows options cannot be set for a linux pod"));
}

#[test]
fn pod_hostname_override_linux_container_windows_options() {
    let sc = SecurityContext {
        windows_options: win(),
        ..Default::default()
    };
    let mk = |name: &str| Container {
        name: name.into(),
        security_context: Some(sc.clone()),
        ..Default::default()
    };
    let spec = PodSpec {
        init_containers: Some(vec![mk("i")]),
        containers: vec![mk("c")],
        ..Default::default()
    };
    let errs = validate_linux(&spec, &Path::new("spec"));
    let fields: Vec<_> = errs.iter().map(|e| e.field.as_str()).collect();
    assert_eq!(
        fields,
        vec![
            "spec.initContainers[0].securityContext.windowsOptions",
            "spec.containers[0].securityContext.windowsOptions"
        ]
    );
}
