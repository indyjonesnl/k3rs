//! `validatePodHostName` and `validateLinux`.
//!
//! Port of `pkg/apis/core/validation/validation.go` `validatePodHostName`
//! (:3999-4025) and `validateLinux` (:4842-4857), release-1.35. The Windows
//! branch (`validateWindows`) is out of scope.

use crate::resources::pod::PodSpec;
use crate::validation::field::{Error, ErrorList, Path};
use crate::validation::metav1::is_dns1123_subdomain;

/// `validatePodHostName`: `spec.hostnameOverride` checks.
pub fn validate_pod_host_name(spec: &PodSpec, fld_path: &Path) -> ErrorList {
    let mut errs = Vec::new();
    let Some(hostname) = spec.hostname_override.as_deref() else {
        return errs;
    };
    let path = fld_path.child("hostnameOverride");

    // If SetHostnameAsFQDN is true, HostnameOverride must not be set.
    if spec.set_hostname_as_fqdn == Some(true) {
        errs.push(Error::forbidden(
            &path,
            "may not be specified when setHostnameAsFQDN is true",
        ));
    }
    // If HostNetwork is true, HostnameOverride must not be set.
    if spec.host_network == Some(true) {
        errs.push(Error::forbidden(
            &path,
            "may not be specified when hostNetwork is true",
        ));
    }
    if hostname.len() > 64 {
        errs.push(Error::too_long(&path, 64));
    }
    // `ValidateDNS1123Subdomain` (validation.go:185-191).
    for msg in is_dns1123_subdomain(hostname) {
        errs.push(
            Error::invalid(&path, hostname.to_string(), msg).with_origin("format=k8s-long-name"),
        );
    }
    errs
}

/// `validateLinux`: Windows options are forbidden on a Linux pod, on the pod
/// and on every container (init, regular, ephemeral, in
/// `VisitContainersWithPath` order, pkg/apis/core/pods/helpers.go:35).
pub fn validate_linux(spec: &PodSpec, fld_path: &Path) -> ErrorList {
    const DETAIL: &str = "windows options cannot be set for a linux pod";
    let mut errs = Vec::new();
    if spec
        .security_context
        .as_ref()
        .is_some_and(|sc| sc.windows_options.is_some())
    {
        errs.push(Error::forbidden(
            &fld_path.child("securityContext").child("windowsOptions"),
            DETAIL,
        ));
    }
    let mut check = |path: Path, sc: Option<&crate::resources::pod::SecurityContext>| {
        if sc.is_some_and(|sc| sc.windows_options.is_some()) {
            errs.push(Error::forbidden(
                &path.child("securityContext").child("windowsOptions"),
                DETAIL,
            ));
        }
    };
    for (i, c) in spec.init_containers.iter().flatten().enumerate() {
        check(
            fld_path.child("initContainers").index(i),
            c.security_context.as_ref(),
        );
    }
    for (i, c) in spec.containers.iter().enumerate() {
        check(
            fld_path.child("containers").index(i),
            c.security_context.as_ref(),
        );
    }
    for (i, c) in spec.ephemeral_containers.iter().flatten().enumerate() {
        check(
            fld_path.child("ephemeralContainers").index(i),
            c.security_context.as_ref(),
        );
    }
    errs
}
