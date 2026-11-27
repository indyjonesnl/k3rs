//! Per-signer CSR request verification.
//!
//! Ported from `pkg/controller/certificates/signer/signer.go` (release-1.35):
//! `getCSRVerificationFuncForSignerName` (:241), `isKubeletServing` /
//! `isKubeletClient` / `isKubeAPIServerClient` / `isLegacyUnknown` (:259-286),
//! `validAPIServerClientUsages` (:289), plus the helpers they call in
//! `pkg/apis/certificates/helpers.go` (`ValidateKubeletServingCSR`,
//! `ValidateKubeletClientCSR`, `ParseCSR`).
//!
//! Pure functions, no controller wiring. Security: every check fails closed
//! (unknown signer, unparsable CSR, wrong usages are all errors).

use std::collections::BTreeSet;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

pub const KUBE_APISERVER_CLIENT_SIGNER_NAME: &str = "kubernetes.io/kube-apiserver-client";
pub const KUBE_APISERVER_CLIENT_KUBELET_SIGNER_NAME: &str =
    "kubernetes.io/kube-apiserver-client-kubelet";
pub const KUBELET_SERVING_SIGNER_NAME: &str = "kubernetes.io/kubelet-serving";
/// `capiv1beta1.LegacyUnknownSignerName`.
pub const LEGACY_UNKNOWN_SIGNER_NAME: &str = "kubernetes.io/legacy-unknown";

/// The fields of an `x509.CertificateRequest` the verifiers look at.
#[derive(Debug, Clone, Default)]
pub struct ParsedCsr {
    pub organization: Vec<String>,
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub email_addresses: Vec<String>,
    pub ip_addresses: Vec<Vec<u8>>,
    pub uris: Vec<String>,
}

/// `ParseCSR` (helpers.go): PEM block must be `CERTIFICATE REQUEST`.
pub fn parse_csr(pem_bytes: &[u8]) -> Result<ParsedCsr, String> {
    let block = match x509_parser::pem::parse_x509_pem(pem_bytes) {
        Ok((_, b)) if b.label == "CERTIFICATE REQUEST" => b,
        _ => return Err("PEM block type must be CERTIFICATE REQUEST".to_string()),
    };
    let (_, req) = X509CertificationRequest::from_der(&block.contents)
        .map_err(|e| format!("x509: malformed certificate request: {e}"))?;
    let subject = &req.certification_request_info.subject;
    let mut out = ParsedCsr {
        organization: subject
            .iter_organization()
            .filter_map(|a| a.as_str().ok().map(str::to_string))
            .collect(),
        common_name: subject
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or_default()
            .to_string(),
        ..Default::default()
    };
    if let Some(exts) = req.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for gn in &san.general_names {
                    match gn {
                        GeneralName::DNSName(d) => out.dns_names.push(d.to_string()),
                        GeneralName::RFC822Name(e) => out.email_addresses.push(e.to_string()),
                        GeneralName::URI(u) => out.uris.push(u.to_string()),
                        GeneralName::IPAddress(ip) => out.ip_addresses.push(ip.to_vec()),
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(out)
}

fn usage_set(usages: &[String]) -> BTreeSet<&str> {
    usages.iter().map(String::as_str).collect()
}

fn usages_equal(usages: &BTreeSet<&str>, want: &[&str]) -> bool {
    usages.len() == want.len() && want.iter().all(|w| usages.contains(w))
}

pub const ORG_NOT_SYSTEM_NODES: &str = "subject organization is not system:nodes";
pub const CN_NOT_SYSTEM_NODE: &str = "subject common name does not begin with system:node:";

/// `ValidateKubeletServingCSR` (helpers.go).
pub fn validate_kubelet_serving_csr(req: &ParsedCsr, usages: &[String]) -> Result<(), String> {
    if req.organization != ["system:nodes"] {
        return Err(ORG_NOT_SYSTEM_NODES.into());
    }
    if req.dns_names.is_empty() && req.ip_addresses.is_empty() {
        return Err("DNS or IP subjectAltName is required".into());
    }
    if !req.email_addresses.is_empty() {
        return Err("Email subjectAltNames are not allowed".into());
    }
    if !req.uris.is_empty() {
        return Err("URI subjectAltNames are not allowed".into());
    }
    let u = usage_set(usages);
    if !usages_equal(
        &u,
        &["digital signature", "key encipherment", "server auth"],
    ) && !usages_equal(&u, &["digital signature", "server auth"])
    {
        return Err("usages did not match [digital signature key encipherment server auth]".into());
    }
    if !req.common_name.starts_with("system:node:") {
        return Err(CN_NOT_SYSTEM_NODE.into());
    }
    Ok(())
}

/// `ValidateKubeletClientCSR` (helpers.go).
pub fn validate_kubelet_client_csr(req: &ParsedCsr, usages: &[String]) -> Result<(), String> {
    if req.organization != ["system:nodes"] {
        return Err(ORG_NOT_SYSTEM_NODES.into());
    }
    if !req.dns_names.is_empty() {
        return Err("DNS subjectAltNames are not allowed".into());
    }
    if !req.email_addresses.is_empty() {
        return Err("Email subjectAltNames are not allowed".into());
    }
    if !req.ip_addresses.is_empty() {
        return Err("IP subjectAltNames are not allowed".into());
    }
    if !req.uris.is_empty() {
        return Err("URI subjectAltNames are not allowed".into());
    }
    if !req.common_name.starts_with("system:node:") {
        return Err(CN_NOT_SYSTEM_NODE.into());
    }
    let u = usage_set(usages);
    if !usages_equal(
        &u,
        &["digital signature", "key encipherment", "client auth"],
    ) && !usages_equal(&u, &["digital signature", "client auth"])
    {
        return Err("usages did not match [client auth digital signature key encipherment]".into());
    }
    Ok(())
}

/// `validAPIServerClientUsages` (signer.go:289).
pub fn valid_apiserver_client_usages(usages: &[String]) -> Result<(), String> {
    let mut has_client_auth = false;
    for u in usages {
        match u.as_str() {
            "digital signature" | "key encipherment" => {}
            "client auth" => has_client_auth = true,
            other => return Err(format!("invalid usage for client certificate: {other}")),
        }
    }
    if !has_client_auth {
        return Err("missing required usage for client certificate: client auth".into());
    }
    Ok(())
}

/// Outcome of an `isRequestForSignerFunc`: `(handled, err)` in Go.
pub type Verdict = (bool, Result<(), String>);

/// `isRequestForSignerFunc`.
pub type VerifyFn = fn(&ParsedCsr, &[String], &str) -> Verdict;

fn is_kubelet_serving(req: &ParsedCsr, usages: &[String], signer: &str) -> Verdict {
    if signer != KUBELET_SERVING_SIGNER_NAME {
        return (false, Ok(()));
    }
    (true, validate_kubelet_serving_csr(req, usages))
}

fn is_kubelet_client(req: &ParsedCsr, usages: &[String], signer: &str) -> Verdict {
    if signer != KUBE_APISERVER_CLIENT_KUBELET_SIGNER_NAME {
        return (false, Ok(()));
    }
    (true, validate_kubelet_client_csr(req, usages))
}

fn is_kube_apiserver_client(_req: &ParsedCsr, usages: &[String], signer: &str) -> Verdict {
    if signer != KUBE_APISERVER_CLIENT_SIGNER_NAME {
        return (false, Ok(()));
    }
    (true, valid_apiserver_client_usages(usages))
}

fn is_legacy_unknown(_req: &ParsedCsr, _usages: &[String], signer: &str) -> Verdict {
    if signer != LEGACY_UNKNOWN_SIGNER_NAME {
        return (false, Ok(()));
    }
    // No restrictions for legacy-unknown (backward compatibility in v1).
    (true, Ok(()))
}

/// `getCSRVerificationFuncForSignerName` (signer.go:241).
pub fn csr_verification_func_for_signer_name(signer_name: &str) -> Result<VerifyFn, String> {
    match signer_name {
        KUBELET_SERVING_SIGNER_NAME => Ok(is_kubelet_serving),
        KUBE_APISERVER_CLIENT_KUBELET_SIGNER_NAME => Ok(is_kubelet_client),
        KUBE_APISERVER_CLIENT_SIGNER_NAME => Ok(is_kube_apiserver_client),
        LEGACY_UNKNOWN_SIGNER_NAME => Ok(is_legacy_unknown),
        other => Err(format!("unrecognized signerName: {other:?}")),
    }
}
