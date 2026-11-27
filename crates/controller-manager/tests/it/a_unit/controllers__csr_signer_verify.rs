//! Unit tests for `src/controllers/csr_signer_verify.rs` (ported from
//! signer_test.go TestSignerSign cases).

mod tests {
    use kubernetes_rs_controller_manager::controllers::csr_signer_verify::*;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    fn u(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn make_csr(cn: &str, org: Option<&str>, sans: Vec<SanType>) -> ParsedCsr {
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, cn);
        if let Some(o) = org {
            p.distinguished_name.push(DnType::OrganizationName, o);
        }
        p.subject_alt_names = sans;
        let key = KeyPair::generate().unwrap();
        let pem = p.serialize_request(&key).unwrap().pem().unwrap();
        parse_csr(pem.as_bytes()).unwrap()
    }

    fn dns(n: &str) -> SanType {
        SanType::DnsName(n.try_into().unwrap())
    }

    const SERVING: &[&str] = &["server auth", "digital signature", "key encipherment"];
    const CLIENT: &[&str] = &["client auth", "digital signature", "key encipherment"];

    fn run(signer: &str, csr: &ParsedCsr, usages: &[&str]) -> Result<(), String> {
        let f = csr_verification_func_for_signer_name(signer)?;
        let (handled, r) = f(csr, &u(usages), signer);
        assert!(handled);
        r
    }

    #[test]
    fn csr_signer_verify_apiserver_client() {
        let c = make_csr("any", None, vec![]);
        let s = KUBE_APISERVER_CLIENT_SIGNER_NAME;
        assert!(run(s, &c, CLIENT).is_ok());
        assert!(run(s, &c, &["client auth", "digital signature"]).is_ok());
        // unexpected usage is rejected (signer_test.go :204)
        let e = run(s, &c, &["server auth", "client auth", "digital signature"]).unwrap_err();
        assert_eq!(e, "invalid usage for client certificate: server auth");
        // fail closed without client auth
        assert!(run(s, &c, &["digital signature"]).is_err());
        assert!(run(s, &c, &[]).is_err());
    }

    #[test]
    fn csr_signer_verify_kubelet_client() {
        let s = KUBE_APISERVER_CLIENT_KUBELET_SIGNER_NAME;
        let ok = make_csr("system:node:n1", Some("system:nodes"), vec![]);
        assert!(run(s, &ok, CLIENT).is_ok());
        assert!(run(s, &ok, &["client auth", "digital signature"]).is_ok());
        assert!(run(s, &ok, &["client auth"]).is_err());
        assert!(run(s, &ok, SERVING).is_err());
        let bad_org = make_csr("system:node:n1", Some("other"), vec![]);
        assert_eq!(run(s, &bad_org, CLIENT).unwrap_err(), ORG_NOT_SYSTEM_NODES);
        let no_org = make_csr("system:node:n1", None, vec![]);
        assert!(run(s, &no_org, CLIENT).is_err());
        let bad_cn = make_csr("bob", Some("system:nodes"), vec![]);
        assert_eq!(run(s, &bad_cn, CLIENT).unwrap_err(), CN_NOT_SYSTEM_NODE);
        let with_dns = make_csr("system:node:n1", Some("system:nodes"), vec![dns("a.b")]);
        assert_eq!(
            run(s, &with_dns, CLIENT).unwrap_err(),
            "DNS subjectAltNames are not allowed"
        );
        let with_ip = make_csr(
            "system:node:n1",
            Some("system:nodes"),
            vec![SanType::IpAddress("10.0.0.1".parse().unwrap())],
        );
        assert_eq!(
            run(s, &with_ip, CLIENT).unwrap_err(),
            "IP subjectAltNames are not allowed"
        );
    }

    #[test]
    fn csr_signer_verify_kubelet_serving() {
        let s = KUBELET_SERVING_SIGNER_NAME;
        let ok = make_csr(
            "system:node:n1",
            Some("system:nodes"),
            vec![dns("n1.local")],
        );
        assert!(run(s, &ok, SERVING).is_ok());
        assert!(run(s, &ok, &["server auth", "digital signature"]).is_ok());
        assert!(run(s, &ok, CLIENT).is_err());
        let ip_only = make_csr(
            "system:node:n1",
            Some("system:nodes"),
            vec![SanType::IpAddress("10.0.0.1".parse().unwrap())],
        );
        assert!(run(s, &ip_only, SERVING).is_ok());
        let no_san = make_csr("system:node:n1", Some("system:nodes"), vec![]);
        assert_eq!(
            run(s, &no_san, SERVING).unwrap_err(),
            "DNS or IP subjectAltName is required"
        );
        let email = make_csr(
            "system:node:n1",
            Some("system:nodes"),
            vec![dns("a.b"), SanType::Rfc822Name("a@b.c".try_into().unwrap())],
        );
        assert_eq!(
            run(s, &email, SERVING).unwrap_err(),
            "Email subjectAltNames are not allowed"
        );
        let uri = make_csr(
            "system:node:n1",
            Some("system:nodes"),
            vec![dns("a.b"), SanType::URI("spiffe://x/y".try_into().unwrap())],
        );
        assert_eq!(
            run(s, &uri, SERVING).unwrap_err(),
            "URI subjectAltNames are not allowed"
        );
        let bad_org = make_csr("system:node:n1", Some("x"), vec![dns("a.b")]);
        assert!(run(s, &bad_org, SERVING).is_err());
        let bad_cn = make_csr("n1", Some("system:nodes"), vec![dns("a.b")]);
        assert_eq!(run(s, &bad_cn, SERVING).unwrap_err(), CN_NOT_SYSTEM_NODE);
    }

    #[test]
    fn csr_signer_verify_legacy_unknown_and_unrecognized() {
        let c = make_csr("anything", None, vec![]);
        assert!(run(LEGACY_UNKNOWN_SIGNER_NAME, &c, &[]).is_ok());
        for bad in ["kubernetes.io/other", "example.com/x", ""] {
            let e = csr_verification_func_for_signer_name(bad).err().unwrap();
            assert_eq!(e, format!("unrecognized signerName: {bad:?}"));
        }
    }

    #[test]
    fn csr_signer_verify_wrong_signer_not_handled() {
        let c = make_csr("system:node:n1", Some("system:nodes"), vec![]);
        let f = csr_verification_func_for_signer_name(KUBELET_SERVING_SIGNER_NAME).unwrap();
        let (handled, r) = f(&c, &[], KUBE_APISERVER_CLIENT_SIGNER_NAME);
        assert!(!handled && r.is_ok());
    }

    #[test]
    fn csr_signer_verify_parse_csr_rejects_non_csr() {
        let e = parse_csr(b"not pem").unwrap_err();
        assert_eq!(e, "PEM block type must be CERTIFICATE REQUEST");
    }
}
