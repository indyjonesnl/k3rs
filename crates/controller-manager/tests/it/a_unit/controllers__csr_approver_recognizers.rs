//! Tests for `src/controllers/csr_approver_recognizers.rs` (port of sarapprove_test.go TestRecognizers).

mod tests {
    use base64::{engine::general_purpose, Engine as _};
    use kubernetes_rs_common::resources::certificates::{CertificateSigningRequest, KeyUsage};
    use kubernetes_rs_controller_manager::controllers::csr_approver_recognizers::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    #[derive(Clone)]
    struct Builder {
        cn: &'static str,
        orgs: Vec<&'static str>,
        requestor: &'static str,
        usages: Vec<KeyUsage>,
        dns: Vec<&'static str>,
        signer: &'static str,
    }

    fn base(usages: Vec<KeyUsage>) -> Builder {
        Builder {
            cn: "system:node:foo",
            orgs: vec!["system:nodes"],
            requestor: "system:node:foo",
            usages,
            dns: vec![],
            signer: KUBE_APISERVER_CLIENT_KUBELET_SIGNER_NAME,
        }
    }

    fn make(b: &Builder) -> (CertificateSigningRequest, ParsedCsr) {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, b.cn);
        for o in &b.orgs {
            dn.push(DnType::OrganizationName, *o);
        }
        params.distinguished_name = dn;
        for d in &b.dns {
            params
                .subject_alt_names
                .push(SanType::DnsName((*d).try_into().unwrap()));
        }
        let key = KeyPair::generate().unwrap();
        let pem = params.serialize_request(&key).unwrap().pem().unwrap();
        let mut csr = CertificateSigningRequest {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "CertificateSigningRequest".into(),
            metadata: Default::default(),
            spec: Default::default(),
            status: None,
        };
        csr.spec.request = general_purpose::STANDARD.encode(pem);
        csr.spec.signer_name = b.signer.to_string();
        csr.spec.username = Some(b.requestor.to_string());
        csr.spec.usages = b.usages.clone();
        let parsed = parse_csr(&csr.spec.request).unwrap();
        (csr, parsed)
    }

    fn both_usages() -> Vec<Vec<KeyUsage>> {
        vec![
            vec![
                KeyUsage::KeyEncipherment,
                KeyUsage::DigitalSignature,
                KeyUsage::ClientAuth,
            ],
            vec![KeyUsage::DigitalSignature, KeyUsage::ClientAuth],
        ]
    }

    fn check(mutate: impl Fn(&mut Builder), node: bool, self_node: bool) {
        for usages in both_usages() {
            let mut b = base(usages);
            mutate(&mut b);
            let (csr, x) = make(&b);
            assert_eq!(is_node_client_cert(&csr, &x), node);
            assert_eq!(is_self_node_client_cert(&csr, &x), self_node);
        }
    }

    #[test]
    fn csr_recognizers_good_case() {
        check(|_| {}, true, true);
    }

    #[test]
    fn csr_recognizers_bad_cases() {
        check(|b| b.cn = "mike", false, false);
        check(|b| b.orgs = vec![], false, false);
        check(|b| b.orgs = vec!["system:master"], false, false);
        check(|b| b.usages.push(KeyUsage::ServerAuth), false, false);
        check(|b| b.signer = "example.com/not-correct", false, false);
        check(|b| b.signer = "kubernetes.io/kubelet-serving", false, false);
    }

    #[test]
    fn csr_recognizers_different_requestor() {
        check(|b| b.requestor = "joe", true, false);
        check(|b| b.cn = "system:node:bar", true, false);
    }

    #[test]
    fn csr_recognizers_reject_sans_and_extra_orgs() {
        check(|b| b.dns = vec!["evil.example.com"], false, false);
        check(
            |b| b.orgs = vec!["system:nodes", "system:masters"],
            false,
            false,
        );
    }

    #[test]
    fn csr_recognizers_malformed_request_fails_closed() {
        assert!(parse_csr("not a csr").is_err());
        let wrong = pem::encode(&pem::Pem::new("CERTIFICATE", vec![1, 2, 3]));
        assert!(parse_csr(&wrong).is_err());
        let bad = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", vec![1, 2, 3]));
        assert!(parse_csr(&bad).is_err());
    }
}
