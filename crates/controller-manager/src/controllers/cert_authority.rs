//! A minimal X.509 certificate authority used by the CSR signing controller to
//! issue certificates for approved [`CertificateSigningRequest`]s.
//!
//! Mirrors the upstream kube-controller-manager signer
//! (`pkg/controller/certificates/signer` + `pkg/controller/certificates/authority`):
//! the signer parses the PKCS#10 request, builds an X.509 leaf whose Subject and
//! SANs come from the request, sets KeyUsage/ExtKeyUsage from the API
//! `spec.usages` (NOT the embedded CSR extensions — the API field is
//! authoritative upstream), and signs it with the cluster CA key, writing the
//! PEM into `status.certificate`.
//!
//! [`CertificateSigningRequest`]: kubernetes_rs_common::resources::CertificateSigningRequest

use anyhow::{anyhow, Context, Result};
use kubernetes_rs_common::resources::KeyUsage;
use rcgen::{
    Certificate, CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

/// Default issued-certificate lifetime when a CSR does not request one, matching
/// upstream's 1-year default (`pkg/controller/certificates/signer`).
const DEFAULT_DURATION_SECS: i64 = 365 * 24 * 60 * 60;

/// Backdate applied to NotBefore. Upstream `signer.sign`
/// (`pkg/controller/certificates/signer/signer.go`): `Backdate: 5 * time.Minute`.
const BACKDATE_SECS: i64 = 5 * 60;
/// Certificates shorter than this do not backdate NotAfter. Upstream
/// `signer.sign`: `Short: 8 * time.Hour`.
pub const SHORT_SECS: i64 = 8 * 60 * 60;
/// Lower bound on a requested lifetime. Upstream `signer.duration`:
/// `const min = 10 * time.Minute`.
const MIN_DURATION_SECS: i64 = 10 * 60;

/// Port of upstream `signer.duration` (signer.go:219): the requested
/// `expirationSeconds` is honoured when between 10 minutes and `cert_ttl`
/// (`--cluster-signing-duration`), clamped otherwise; `None` yields `cert_ttl`.
pub fn signing_duration(expiration_seconds: Option<i32>, cert_ttl: i64) -> i64 {
    match expiration_seconds {
        None => cert_ttl,
        Some(s) => {
            let requested = i64::from(s);
            if requested > cert_ttl {
                cert_ttl
            } else if requested < MIN_DURATION_SECS {
                MIN_DURATION_SECS
            } else {
                requested
            }
        }
    }
}

/// Port of `PermissiveSigningPolicy.apply` validity logic
/// (`pkg/controller/certificates/authority/policies.go:68-96`). Returns
/// `(not_before, not_after)` as unix seconds. NotAfter is truncated to the
/// signer's NotAfter, and signing fails closed when the signer has expired.
pub fn signing_policy_window(now: i64, ttl: i64, signer_not_after: i64) -> Result<(i64, i64)> {
    let not_before = now - BACKDATE_SECS;
    let mut not_after = if ttl < SHORT_SECS {
        // short lived: do not backdate the end time
        now + ttl
    } else {
        now + ttl - BACKDATE_SECS
    };
    if not_after >= signer_not_after {
        not_after = signer_not_after;
    }
    if not_before >= signer_not_after {
        return Err(anyhow!(
            "the signer has expired: NotAfter={signer_not_after}"
        ));
    }
    if now >= signer_not_after {
        return Err(anyhow!(
            "refusing to sign a certificate that expired in the past: NotAfter={signer_not_after}"
        ));
    }
    Ok((not_before, not_after))
}

pub fn unix_to_dt(secs: i64) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(secs).map_err(|e| anyhow!("invalid timestamp: {e}"))
}

/// A cluster certificate authority capable of signing approved CSRs.
///
/// Built once from the cluster CA cert + key PEM. Cheap to share behind an
/// `Arc`; signing is a pure CPU operation with no shared mutable state.
pub struct CertificateAuthority {
    /// Issuer reconstructed from the CA cert params + key. Only its
    /// distinguished name, key-identifier method and signing key feed into
    /// `signed_by`, so leaves carry the real CA's issuer DN and are signed by
    /// the real CA key — i.e. they chain to the on-disk CA certificate.
    issuer: Certificate,
    ca_key: KeyPair,
    /// The CA certificate's NotAfter; issued certs are truncated to it.
    ca_not_after: time::OffsetDateTime,
}

impl CertificateAuthority {
    /// Build a CA from the cluster CA certificate and private key, both PEM.
    pub fn from_pem(ca_cert_pem: &str, ca_key_pem: &str) -> Result<Self> {
        let ca_key = KeyPair::from_pem(ca_key_pem).context("parsing CA private key PEM")?;
        let params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .context("parsing CA certificate PEM")?;
        let ca_not_after = params.not_after;
        let issuer = params
            .self_signed(&ca_key)
            .context("reconstructing CA issuer certificate")?;
        Ok(Self {
            issuer,
            ca_key,
            ca_not_after,
        })
    }

    /// Sign an approved CSR, returning the issued leaf certificate as PEM.
    ///
    /// `request_pem` is the PKCS#10 `CERTIFICATE REQUEST` PEM (the CSR's
    /// `spec.request`). `usages` is the API `spec.usages` list, which is
    /// authoritative for the issued cert's KeyUsage/ExtKeyUsage. `expiration`
    /// is `spec.expirationSeconds`, defaulting to one year.
    pub fn sign(
        &self,
        request_pem: &str,
        usages: &[KeyUsage],
        expiration_seconds: Option<i32>,
    ) -> Result<String> {
        // Parse + verify the PKCS#10 request. `from_pem` also checks the CSR's
        // self-signature, so a tampered request is rejected here.
        let mut csr = CertificateSigningRequestParams::from_pem(request_pem)
            .map_err(|e| anyhow!("parsing certificate signing request: {e}"))?;

        // `spec.usages` is authoritative for the issued certificate's usages,
        // mirroring the upstream signer — override anything embedded in the
        // request's own extensions.
        let (key_usages, extended_key_usages) = map_usages(usages);
        csr.params.key_usages = key_usages;
        csr.params.extended_key_usages = extended_key_usages;

        // A signed leaf is never itself a CA.
        csr.params.is_ca = IsCa::ExplicitNoCa;

        // Validity per upstream PermissiveSigningPolicy (see
        // `signing_policy_window`); TTL per `signing_duration`.
        let ttl = signing_duration(expiration_seconds, DEFAULT_DURATION_SECS);
        let (nb, na) = signing_policy_window(
            chrono::Utc::now().timestamp(),
            ttl,
            self.ca_not_after.unix_timestamp(),
        )?;
        csr.params.not_before = unix_to_dt(nb)?;
        csr.params.not_after = unix_to_dt(na)?;

        let cert = csr
            .signed_by(&self.issuer, &self.ca_key)
            .map_err(|e| anyhow!("signing certificate: {e}"))?;
        Ok(cert.pem())
    }

    /// Build a CA by reading the cert + key PEM from the given file paths.
    pub fn from_files(cert_path: &str, key_path: &str) -> Result<Self> {
        let cert = std::fs::read_to_string(cert_path)
            .with_context(|| format!("reading CA certificate {cert_path}"))?;
        let key = std::fs::read_to_string(key_path)
            .with_context(|| format!("reading CA private key {key_path}"))?;
        Self::from_pem(&cert, &key)
    }
}

/// Load the cluster CA from the `KUBERNETES_RS_CA_CERT_FILE` +
/// `KUBERNETES_RS_CA_KEY_FILE` environment variables, enabling the in-process CSR
/// signer. Returns `None` (signer disabled, issuance left to an external signer)
/// when either var is unset or the material cannot be loaded.
pub fn load_cluster_ca_from_env() -> Option<std::sync::Arc<CertificateAuthority>> {
    let cert_path = std::env::var("KUBERNETES_RS_CA_CERT_FILE").ok()?;
    let key_path = std::env::var("KUBERNETES_RS_CA_KEY_FILE").ok()?;
    match CertificateAuthority::from_files(&cert_path, &key_path) {
        Ok(ca) => {
            tracing::info!("CSR signer enabled (cluster CA loaded from {cert_path})");
            Some(std::sync::Arc::new(ca))
        }
        Err(e) => {
            tracing::warn!("CSR signer disabled — failed to load cluster CA: {e:#}");
            None
        }
    }
}

/// Map the Kubernetes `spec.usages` strings to rcgen KeyUsage / ExtendedKeyUsage
/// purposes. Mirrors upstream `keyUsagesFromStrings`. IPsec and SGC usages have
/// no rcgen equivalent and are skipped (they are not used by the in-cluster
/// signers).
fn map_usages(usages: &[KeyUsage]) -> (Vec<KeyUsagePurpose>, Vec<ExtendedKeyUsagePurpose>) {
    use KeyUsage as K;
    let mut ku = Vec::new();
    let mut eku = Vec::new();
    for usage in usages {
        match usage {
            K::Signing | K::DigitalSignature => {
                push_unique(&mut ku, KeyUsagePurpose::DigitalSignature)
            }
            K::ContentCommitment => push_unique(&mut ku, KeyUsagePurpose::ContentCommitment),
            K::KeyEncipherment => push_unique(&mut ku, KeyUsagePurpose::KeyEncipherment),
            K::KeyAgreement => push_unique(&mut ku, KeyUsagePurpose::KeyAgreement),
            K::DataEncipherment => push_unique(&mut ku, KeyUsagePurpose::DataEncipherment),
            K::CertSign => push_unique(&mut ku, KeyUsagePurpose::KeyCertSign),
            K::CRLSign => push_unique(&mut ku, KeyUsagePurpose::CrlSign),
            K::EncipherOnly => push_unique(&mut ku, KeyUsagePurpose::EncipherOnly),
            K::DecipherOnly => push_unique(&mut ku, KeyUsagePurpose::DecipherOnly),
            K::ServerAuth => push_unique(&mut eku, ExtendedKeyUsagePurpose::ServerAuth),
            K::ClientAuth => push_unique(&mut eku, ExtendedKeyUsagePurpose::ClientAuth),
            K::CodeSigning => push_unique(&mut eku, ExtendedKeyUsagePurpose::CodeSigning),
            K::EmailProtection | K::SMIME => {
                push_unique(&mut eku, ExtendedKeyUsagePurpose::EmailProtection)
            }
            K::Timestamping => push_unique(&mut eku, ExtendedKeyUsagePurpose::TimeStamping),
            K::Any => push_unique(&mut eku, ExtendedKeyUsagePurpose::Any),
            // ipsec end system / tunnel / user, microsoft/netscape SGC: no rcgen
            // mapping, and unused by the in-cluster signers.
            _ => {}
        }
    }
    (ku, eku)
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}
