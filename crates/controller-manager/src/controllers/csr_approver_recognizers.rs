//! CSR approver recognizers: `isNodeClientCert` and `isSelfNodeClientCert`.
//!
//! Ported from upstream Kubernetes release-1.35:
//! - `pkg/controller/certificates/approver/sarapprove.go`
//!   (`isNodeClientCert`, `isSelfNodeClientCert`, `usagesToSet`)
//! - `pkg/apis/certificates/helpers.go` (`ValidateKubeletClientCSR`,
//!   `kubeletClientRequiredUsages`, `kubeletClientRequiredUsagesNoRSA`)
//! - `pkg/apis/certificates/v1/helpers.go` (`ParseCSR`)
//! - test: `approver/sarapprove_test.go` `TestRecognizers`
//!
//! Security: these gate auto-approval, so every parse or shape failure
//! answers "not recognized" (fail closed). There is no SubjectAccessReview
//! here; that is a separate step upstream (`sarApprover.handle`).

use kubernetes_rs_common::resources::certificates::{CertificateSigningRequest, KeyUsage};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

/// `capi.KubeAPIServerClientKubeletSignerName`.
pub const KUBE_APISERVER_CLIENT_KUBELET_SIGNER_NAME: &str =
    "kubernetes.io/kube-apiserver-client-kubelet";

/// The subset of `x509.CertificateRequest` the recognizers read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedCsr {
    /// `Subject.CommonName` (Go keeps the last CN in the RDN sequence).
    pub common_name: String,
    /// `Subject.Organization`, in order.
    pub organization: Vec<String>,
    pub dns_names: Vec<String>,
    pub email_addresses: Vec<String>,
    pub ip_addresses: usize,
    pub uris: Vec<String>,
}

/// Port of `k8s_certificates_v1.ParseCSR` over the `spec.request` field,
/// which is base64-encoded PEM on the wire (raw PEM is also accepted).
/// The PEM block type must be `CERTIFICATE REQUEST`.
pub fn parse_csr(request: &str) -> Result<ParsedCsr, String> {
    use base64::{engine::general_purpose, Engine as _};
    let bytes = general_purpose::STANDARD
        .decode(request.trim())
        .unwrap_or_else(|_| request.as_bytes().to_vec());
    let block = pem::parse(&bytes).map_err(|e| format!("invalid PEM: {e}"))?;
    if block.tag() != "CERTIFICATE REQUEST" {
        return Err("PEM block type must be CERTIFICATE REQUEST".to_string());
    }
    let (rest, csr) = X509CertificationRequest::from_der(block.contents())
        .map_err(|e| format!("invalid certificate request: {e}"))?;
    if !rest.is_empty() {
        return Err("trailing data after certificate request".to_string());
    }

    let info = &csr.certification_request_info;
    let mut out = ParsedCsr::default();
    for attr in info.subject.iter_attributes() {
        let oid = attr.attr_type().to_id_string();
        let value = attr
            .as_str()
            .map_err(|e| format!("invalid subject attribute: {e}"))?
            .to_string();
        match oid.as_str() {
            "2.5.4.3" => out.common_name = value,
            "2.5.4.10" => out.organization.push(value),
            _ => {}
        }
    }

    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            match ext {
                ParsedExtension::SubjectAlternativeName(san) => {
                    for name in &san.general_names {
                        match name {
                            GeneralName::DNSName(n) => out.dns_names.push(n.to_string()),
                            GeneralName::RFC822Name(n) => out.email_addresses.push(n.to_string()),
                            GeneralName::IPAddress(_) => out.ip_addresses += 1,
                            GeneralName::URI(n) => out.uris.push(n.to_string()),
                            _ => {}
                        }
                    }
                }
                // Fail closed: a SAN extension we could not decode may hide a
                // SAN that ValidateKubeletClientCSR would reject.
                ParsedExtension::UnsupportedExtension { oid }
                    if oid.to_id_string() == "2.5.29.17" =>
                {
                    return Err("invalid subject alternative name extension".to_string());
                }
                ParsedExtension::ParseError { error: _ } => {
                    return Err("invalid certificate request extension".to_string());
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

/// Set equality (`sets.String.Equal`); `KeyUsage` is not `Hash`, so compare by
/// containment both ways.
fn usages_equal(usages: &[KeyUsage], want: &[KeyUsage]) -> bool {
    usages.iter().all(|u| want.contains(u)) && want.iter().all(|u| usages.contains(u))
}

/// Port of `ValidateKubeletClientCSR` (`pkg/apis/certificates/helpers.go`).
pub fn validate_kubelet_client_csr(req: &ParsedCsr, usages: &[KeyUsage]) -> Result<(), String> {
    if req.organization != ["system:nodes"] {
        return Err("subject organization is not system:nodes".to_string());
    }
    if !req.dns_names.is_empty() {
        return Err("DNS subjectAltNames are not allowed".to_string());
    }
    if !req.email_addresses.is_empty() {
        return Err("Email subjectAltNames are not allowed".to_string());
    }
    if req.ip_addresses > 0 {
        return Err("IP subjectAltNames are not allowed".to_string());
    }
    if !req.uris.is_empty() {
        return Err("URI subjectAltNames are not allowed".to_string());
    }
    if !req.common_name.starts_with("system:node:") {
        return Err("subject common name does not begin with system:node:".to_string());
    }

    let want_rsa = [
        KeyUsage::DigitalSignature,
        KeyUsage::KeyEncipherment,
        KeyUsage::ClientAuth,
    ];
    let want_no_rsa = [KeyUsage::DigitalSignature, KeyUsage::ClientAuth];
    if !usages_equal(usages, &want_rsa) && !usages_equal(usages, &want_no_rsa) {
        return Err(
            "usages did not match [client auth, digital signature, key encipherment]".to_string(),
        );
    }
    Ok(())
}

/// Port of `isNodeClientCert`.
pub fn is_node_client_cert(csr: &CertificateSigningRequest, x509cr: &ParsedCsr) -> bool {
    if csr.spec.signer_name != KUBE_APISERVER_CLIENT_KUBELET_SIGNER_NAME {
        return false;
    }
    validate_kubelet_client_csr(x509cr, &csr.spec.usages).is_ok()
}

/// Port of `isSelfNodeClientCert`.
pub fn is_self_node_client_cert(csr: &CertificateSigningRequest, x509cr: &ParsedCsr) -> bool {
    // Go compares the plain string; an unset username is "".
    if csr.spec.username.as_deref().unwrap_or("") != x509cr.common_name {
        return false;
    }
    is_node_client_cert(csr, x509cr)
}
