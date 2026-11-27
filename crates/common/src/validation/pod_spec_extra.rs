//! Pod spec field validators that `validate_pod_spec_for` does not call yet.
//!
//! Ported from `pkg/apis/core/validation/validation.go` (release-1.35),
//! `ValidatePodSpec` (:4625-4740):
//! - `ValidateLabels(spec.NodeSelector)` (:4664)
//! - `ValidateServiceAccountName` (:321), `ValidateNodeName` (:295),
//!   `ValidatePriorityClassName` (:335): all `NameIsDNSSubdomain`
//! - hostname / subdomain: `ValidateDNS1123Label` (:4698-4704)
//! - `ValidateHostAliases` (:4348)
//! - `ValidateRuntimeClassName` (:360)
//! - `ValidatePreemptionPolicy` (:4087)
//!
//! Not ported here: `validateImagePullSecrets` (:4248, "only name may be set")
//! can never fire on our typed `LocalObjectReference`, which has only `name`
//! (unknown fields are dropped on decode), and `validateOverhead` (:369)
//! needs the private `validate_resource_requirements` in `pod.rs`; both are in
//! the wiring follow-up (common-P1-02b).

use crate::resources::pod::PodSpec;
use crate::validation::field::{Error, ErrorList, Path};
use crate::validation::metav1::{is_dns1123_subdomain, validate_labels};
use crate::validation::objectmeta::name_is_dns_subdomain;
use crate::validation::service::{is_valid_ip_for_legacy_field, validate_dns1123_label};

fn name_is_subdomain(name: &str, fld: &Path) -> ErrorList {
    name_is_dns_subdomain(name, false)
        .into_iter()
        .map(|msg| Error::invalid(fld, name, msg))
        .collect()
}

/// `ValidateServiceAccountName` applied at `serviceAccountName` (:4655).
pub fn validate_service_account_name(name: &str, fld: &Path) -> ErrorList {
    name_is_subdomain(name, fld)
}

/// `ValidateNodeName` applied at `nodeName` (:4662).
pub fn validate_node_name(name: &str, fld: &Path) -> ErrorList {
    name_is_subdomain(name, fld)
}

/// `ValidatePriorityClassName` applied at `priorityClassName`.
pub fn validate_priority_class_name(name: &str, fld: &Path) -> ErrorList {
    name_is_subdomain(name, fld)
}

/// `ValidateRuntimeClassName` (:360).
pub fn validate_runtime_class_name(name: &str, fld: &Path) -> ErrorList {
    name_is_subdomain(name, fld)
}

/// `ValidateDNS1123Subdomain`.
fn validate_dns1123_subdomain(value: &str, fld: &Path) -> ErrorList {
    is_dns1123_subdomain(value)
        .into_iter()
        .map(|msg| Error::invalid(fld, value, msg))
        .collect()
}

/// `ValidateHostAliases` (:4348).
pub fn validate_host_aliases(
    host_aliases: &[crate::resources::pod::HostAlias],
    fld: &Path,
) -> ErrorList {
    let mut errs = ErrorList::new();
    for (i, alias) in host_aliases.iter().enumerate() {
        let ip = fld.index(i).child("ip");
        errs.extend(is_valid_ip_for_legacy_field(&ip, &alias.ip, &[]));
        for (j, hostname) in alias.hostnames.iter().flatten().enumerate() {
            errs.extend(validate_dns1123_subdomain(
                hostname,
                &fld.index(i).child("hostnames").index(j),
            ));
        }
    }
    errs
}

/// `ValidatePreemptionPolicy` (:4087).
pub fn validate_preemption_policy(policy: &str, fld: &Path) -> ErrorList {
    match policy {
        "PreemptLowerPriority" | "Never" => ErrorList::new(),
        "" => vec![Error::required(fld, "")],
        other => vec![Error::not_supported(
            fld,
            other,
            &["PreemptLowerPriority", "Never"],
        )],
    }
}

/// The `ValidatePodSpec` checks above, in upstream order. `fld` is the path of
/// the spec (`spec`).
pub fn validate_pod_spec_extra(spec: &PodSpec, fld: &Path) -> ErrorList {
    let mut errs = ErrorList::new();
    if let Some(ns) = &spec.node_selector {
        errs.extend(validate_labels(ns, &fld.child("nodeSelector")));
    }
    if let Some(n) = spec
        .service_account_name
        .as_deref()
        .filter(|n| !n.is_empty())
    {
        errs.extend(validate_service_account_name(
            n,
            &fld.child("serviceAccountName"),
        ));
    }
    if let Some(n) = spec.node_name.as_deref().filter(|n| !n.is_empty()) {
        errs.extend(validate_node_name(n, &fld.child("nodeName")));
    }
    if let Some(h) = spec.hostname.as_deref().filter(|n| !n.is_empty()) {
        errs.extend(validate_dns1123_label(h, &fld.child("hostname")));
    }
    if let Some(s) = spec.subdomain.as_deref().filter(|n| !n.is_empty()) {
        errs.extend(validate_dns1123_label(s, &fld.child("subdomain")));
    }
    if let Some(h) = spec.host_aliases.as_deref().filter(|h| !h.is_empty()) {
        errs.extend(validate_host_aliases(h, &fld.child("hostAliases")));
    }
    if let Some(n) = spec
        .priority_class_name
        .as_deref()
        .filter(|n| !n.is_empty())
    {
        errs.extend(validate_priority_class_name(
            n,
            &fld.child("priorityClassName"),
        ));
    }
    if let Some(n) = spec.runtime_class_name.as_deref() {
        errs.extend(validate_runtime_class_name(
            n,
            &fld.child("runtimeClassName"),
        ));
    }
    if let Some(p) = spec.preemption_policy.as_deref() {
        errs.extend(validate_preemption_policy(
            p,
            &fld.child("preemptionPolicy"),
        ));
    }
    errs
}
