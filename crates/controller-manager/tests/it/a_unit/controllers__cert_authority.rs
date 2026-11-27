//! Unit tests moved from `src/controllers/cert_authority.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use anyhow::{anyhow, Context, Result};
    pub use chrono::Datelike;
    pub use kubernetes_rs_common::resources::KeyUsage;
    pub use rcgen::{
        Certificate, CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
}

mod tests {
    use super::__parent::*;
    use kubernetes_rs_controller_manager::controllers::cert_authority::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, KeyPair};
    use x509_parser::prelude::*;
    // Disambiguate from `x509_parser::prelude::KeyUsage` (a different type that
    // the glob above also brings into scope).
    use kubernetes_rs_common::resources::KeyUsage;

    /// Generate a self-signed CA, returning `(cert_pem, key_pem)`.
    fn make_ca() -> (String, String) {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "kubernetes-rs-test-ca");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// Generate a PKCS#10 CSR PEM for the given subject common name.
    fn make_csr(common_name: &str) -> String {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let key = KeyPair::generate().unwrap();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    fn parse<'a>(pem: &'a ::pem::Pem) -> X509Certificate<'a> {
        X509Certificate::from_der(pem.contents()).unwrap().1
    }

    #[test]
    fn sign_issues_cert_that_chains_to_the_ca() {
        let (ca_cert_pem, ca_key_pem) = make_ca();
        let ca = CertificateAuthority::from_pem(&ca_cert_pem, &ca_key_pem).unwrap();
        let csr = make_csr("system:node:node-1");

        let issued = ca
            .sign(
                &csr,
                &[KeyUsage::DigitalSignature, KeyUsage::ClientAuth],
                None,
            )
            .expect("signing an approved CSR must succeed");

        let issued_pem = ::pem::parse(&issued).expect("issued cert must be valid PEM");
        let ca_pem = ::pem::parse(&ca_cert_pem).unwrap();
        let leaf = parse(&issued_pem);
        let ca_x = parse(&ca_pem);

        // The leaf carries the requested subject.
        assert!(
            leaf.subject().to_string().contains("system:node:node-1"),
            "leaf subject must come from the CSR; got {}",
            leaf.subject()
        );
        // The leaf's issuer is the CA's subject — and its signature verifies
        // against the CA public key, i.e. it chains to the on-disk CA.
        assert_eq!(
            leaf.issuer().to_string(),
            ca_x.subject().to_string(),
            "leaf issuer DN must equal CA subject DN"
        );
        leaf.verify_signature(Some(ca_x.public_key()))
            .expect("issued leaf must be signed by the CA key");
    }

    #[test]
    fn sign_applies_usages_from_spec_not_csr() {
        let (ca_cert_pem, ca_key_pem) = make_ca();
        let ca = CertificateAuthority::from_pem(&ca_cert_pem, &ca_key_pem).unwrap();
        let csr = make_csr("serving.example.com");

        let issued = ca
            .sign(
                &csr,
                &[
                    KeyUsage::DigitalSignature,
                    KeyUsage::KeyEncipherment,
                    KeyUsage::ServerAuth,
                ],
                Some(3600),
            )
            .unwrap();

        let issued_pem = ::pem::parse(&issued).unwrap();
        let leaf = parse(&issued_pem);

        let eku = leaf
            .extended_key_usage()
            .unwrap()
            .expect("issued cert must carry extended key usage")
            .value;
        assert!(
            eku.server_auth,
            "server auth EKU must be set from spec.usages"
        );
        assert!(
            !eku.client_auth,
            "client auth must NOT be set (not requested)"
        );

        let ku = leaf
            .key_usage()
            .unwrap()
            .expect("issued cert must carry key usage")
            .value;
        assert!(ku.digital_signature(), "digital signature KU must be set");
        assert!(ku.key_encipherment(), "key encipherment KU must be set");
    }

    #[test]
    fn sign_rejects_a_malformed_request() {
        let (ca_cert_pem, ca_key_pem) = make_ca();
        let ca = CertificateAuthority::from_pem(&ca_cert_pem, &ca_key_pem).unwrap();
        let err = ca.sign(
            "-----BEGIN CERTIFICATE REQUEST-----\nnot-a-csr\n-----END CERTIFICATE REQUEST-----\n",
            &[KeyUsage::ClientAuth],
            None,
        );
        assert!(err.is_err(), "a malformed CSR must be rejected, not signed");
    }

    const CA_END: i64 = 10_000_000;

    // Ports of authority/policies_test.go TestPermissiveSigningPolicy cases.
    #[test]
    fn signing_policy_long_lived_backdates_both_ends() {
        let now = 1_000_000;
        let (nb, na) = signing_policy_window(now, 24 * 3600, CA_END).unwrap();
        assert_eq!(nb, now - 300);
        assert_eq!(na, now + 24 * 3600 - 300);
    }

    #[test]
    fn signing_policy_short_lived_does_not_backdate_end() {
        let now = 1_000_000;
        let (nb, na) = signing_policy_window(now, 3600, CA_END).unwrap();
        assert_eq!(nb, now - 300);
        assert_eq!(na, now + 3600);
    }

    #[test]
    fn signing_policy_short_threshold_boundary() {
        let now = 1_000_000;
        let (_, na) = signing_policy_window(now, SHORT_SECS, CA_END).unwrap();
        assert_eq!(na, now + SHORT_SECS - 300);
    }

    #[test]
    fn signing_policy_caps_not_after_to_signer() {
        let now = 1_000_000;
        let (_, na) = signing_policy_window(now, 365 * 86400, now + 3600).unwrap();
        assert_eq!(na, now + 3600);
    }

    #[test]
    fn signing_policy_rejects_expired_signer() {
        let now = 1_000_000;
        // NotBefore (now-5m) is at or after the signer's NotAfter.
        let e = signing_policy_window(now, 3600, now - 1000).unwrap_err();
        assert!(e.to_string().contains("the signer has expired"), "{e}");
        // NotBefore is before NotAfter but now is not.
        let e = signing_policy_window(now, 3600, now - 1).unwrap_err();
        assert!(e.to_string().contains("refusing to sign"), "{e}");
        let e = signing_policy_window(now, 3600, now).unwrap_err();
        assert!(e.to_string().contains("refusing to sign"), "{e}");
    }

    // Port of signer_test.go duration cases.
    #[test]
    fn signing_policy_duration_clamps() {
        let ttl = 365 * 86400;
        assert_eq!(signing_duration(None, ttl), ttl);
        assert_eq!(signing_duration(Some(3600), ttl), 3600);
        assert_eq!(signing_duration(Some(i32::MAX), ttl), ttl);
        assert_eq!(signing_duration(Some(1), ttl), 600);
        assert_eq!(signing_duration(Some(-5), ttl), 600);
        assert_eq!(signing_duration(Some(600), ttl), 600);
    }

    #[test]
    fn signing_policy_sign_end_to_end_caps_at_ca_not_after() {
        let ca_key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.not_before = unix_to_dt(chrono::Utc::now().timestamp() - 3600).unwrap();
        let ca_end = chrono::Utc::now().timestamp() + 2 * 86400;
        p.not_after = unix_to_dt(ca_end).unwrap();
        let ca_cert = p.self_signed(&ca_key).unwrap();
        let ca = CertificateAuthority::from_pem(&ca_cert.pem(), &ca_key.serialize_pem()).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(vec!["x".into()])
            .unwrap()
            .serialize_request(&leaf_key)
            .unwrap()
            .pem()
            .unwrap();
        let pem = ca.sign(&csr, &[KeyUsage::ServerAuth], None).unwrap();
        let der = ::pem::parse(pem).unwrap();
        let (_, cert) = X509Certificate::from_der(der.contents()).unwrap();
        let v = cert.validity();
        assert_eq!(v.not_after.timestamp(), ca_end);
        assert!(v.not_before.timestamp() <= chrono::Utc::now().timestamp() - 290);
    }
}
