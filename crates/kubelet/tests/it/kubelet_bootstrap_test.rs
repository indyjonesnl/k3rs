//! Tests for `kubelet::certificate::bootstrap`, after
//! `pkg/kubelet/certificate/bootstrap/bootstrap_test.go` and client-go
//! `csr_test.go` (ensureCompatible, WaitForCertificate handler).

mod kubelet_bootstrap {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use kubernetes_rs_common::resources::{CertificateSigningRequest, KeyUsage};
    use kubernetes_rs_kubelet::certificate::bootstrap::*;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
    use std::path::Path;

    fn self_signed(not_after_secs_from_now: i64, key: &KeyPair) -> String {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.distinguished_name
            .push(DnType::CommonName, "system:node:n1");
        p.is_ca = IsCa::ExplicitNoCa;
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::days(2);
        p.not_after = now + time::Duration::seconds(not_after_secs_from_now);
        p.self_signed(key).unwrap().pem()
    }

    fn kubeconfig(dir: &Path, cert: &Path, key: &Path) -> std::path::PathBuf {
        let p = dir.join("kubeconfig");
        std::fs::write(
            &p,
            format!(
                "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: k\n  cluster: {{server: 'https://127.0.0.1:1', insecure-skip-tls-verify: true}}\n\
                 users:\n- name: u\n  user: {{client-certificate: {}, client-key: {}}}\ncontexts:\n- name: c\n  context: {{cluster: k, user: u}}\n",
                cert.display(),
                key.display()
            ),
        )
        .unwrap();
        p
    }

    #[test]
    fn kubelet_bootstrap_still_valid_missing_valid_expired_garbage() {
        let d = tempfile::tempdir().unwrap();
        // Missing kubeconfig: bootstrap needed.
        assert!(!is_client_config_still_valid(&d.path().join("nope")).unwrap());
        let key = KeyPair::generate().unwrap();
        let (c, k) = (d.path().join("c.pem"), d.path().join("k.pem"));
        std::fs::write(&k, key.serialize_pem()).unwrap();
        std::fs::write(&c, self_signed(3600, &key)).unwrap();
        let kc = kubeconfig(d.path(), &c, &k);
        assert!(is_client_config_still_valid(&kc).unwrap());
        // Expired cert: not valid (fail closed, bootstrap again).
        std::fs::write(&c, self_signed(-60, &key)).unwrap();
        assert!(!is_client_config_still_valid(&kc).unwrap());
        // Garbage cert / unparseable kubeconfig: not valid.
        std::fs::write(&c, "garbage").unwrap();
        assert!(!is_client_config_still_valid(&kc).unwrap());
        std::fs::write(&kc, "clusters: [").unwrap();
        assert!(!is_client_config_still_valid(&kc).unwrap());
    }

    #[test]
    fn kubelet_bootstrap_digested_name_is_stable_and_input_sensitive() {
        let u = vec![KeyUsage::DigitalSignature, KeyUsage::ClientAuth];
        let a = digested_name(b"pub", "system:node:n1", &["system:nodes"], &u);
        assert!(a.starts_with("node-csr-"));
        assert_eq!(
            a,
            digested_name(b"pub", "system:node:n1", &["system:nodes"], &u)
        );
        assert_ne!(
            a,
            digested_name(b"pub2", "system:node:n1", &["system:nodes"], &u)
        );
        assert_ne!(
            a,
            digested_name(b"pub", "system:node:n2", &["system:nodes"], &u)
        );
        assert_ne!(
            a,
            digested_name(b"pub", "system:node:n1", &["system:nodes"], &u[..1])
        );
        // The delimiter keeps CN/O boundaries distinct.
        assert_ne!(
            digested_name(b"p", "foo", &["bar"], &u),
            digested_name(b"p", "foob", &["ar"], &u)
        );
    }

    fn csr_obj(
        request_pem: &str,
        uid: &str,
        conds: &[&str],
        cert: Option<&str>,
    ) -> CertificateSigningRequest {
        let conditions: Vec<_> = conds
            .iter()
            .map(
                |t| serde_json::json!({"type": t, "status": "True", "reason": "R", "message": "M"}),
            )
            .collect();
        serde_json::from_value(serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "csr1", "uid": uid},
            "spec": {
                "request": STANDARD.encode(request_pem),
                "signerName": KUBE_APISERVER_CLIENT_KUBELET_SIGNER,
                "usages": ["digital signature", "client auth"],
            },
            "status": {"conditions": conditions, "certificate": cert.map(|c| STANDARD.encode(c))},
        }))
        .unwrap()
    }

    #[test]
    fn kubelet_bootstrap_wait_handler_denied_failed_uid_and_issued() {
        let key = KeyPair::generate().unwrap();
        let cert = self_signed(3600, &key);
        let req = node_csr_pem(&key, "n1").unwrap();
        assert_eq!(
            check_csr(&csr_obj(&req, "u", &[], None), "u").unwrap(),
            None
        );
        // approved but not yet issued: keep waiting
        assert_eq!(
            check_csr(&csr_obj(&req, "u", &["Approved"], None), "u").unwrap(),
            None
        );
        // issued but not approved: never accepted (fail closed)
        assert_eq!(
            check_csr(&csr_obj(&req, "u", &[], Some(&cert)), "u").unwrap(),
            None
        );
        let got = check_csr(&csr_obj(&req, "u", &["Approved"], Some(&cert)), "u").unwrap();
        assert_eq!(got.as_deref(), Some(cert.as_bytes()));
        let e = check_csr(&csr_obj(&req, "u", &["Denied"], None), "u").unwrap_err();
        assert_eq!(
            e.to_string(),
            "certificate signing request is denied, reason: R, message: M"
        );
        let e = check_csr(&csr_obj(&req, "u", &["Failed"], None), "u").unwrap_err();
        assert_eq!(
            e.to_string(),
            "certificate signing request failed, reason: R, message: M"
        );
        let e = check_csr(&csr_obj(&req, "other", &["Approved"], Some(&cert)), "u").unwrap_err();
        assert_eq!(e.to_string(), "csr \"csr1\" changed UIDs");
    }

    #[test]
    fn kubelet_bootstrap_ensure_compatible() {
        let key = KeyPair::generate().unwrap();
        let req = node_csr_pem(&key, "n1").unwrap();
        let signer = KUBE_APISERVER_CLIENT_KUBELET_SIGNER;
        let existing = csr_obj(&req, "u", &[], None);
        ensure_compatible(&existing, &req, signer, &key).unwrap();
        // different subject
        let other_subject = node_csr_pem(&key, "n2").unwrap();
        let e = ensure_compatible(&csr_obj(&other_subject, "u", &[], None), &req, signer, &key)
            .unwrap_err();
        assert!(e.to_string().starts_with("csr subjects differ"), "{e}");
        // different signer
        let mut s = existing.clone();
        s.spec.signer_name = "example.com/x".into();
        let e = ensure_compatible(&s, &req, signer, &key).unwrap_err();
        assert!(e.to_string().starts_with("csr signerNames differ"), "{e}");
        // request signed by another key
        let other = KeyPair::generate().unwrap();
        let foreign = node_csr_pem(&other, "n1").unwrap();
        let e =
            ensure_compatible(&csr_obj(&foreign, "u", &[], None), &req, signer, &key).unwrap_err();
        assert!(e.to_string().contains("old key"), "{e}");
        // issued but expired certificate
        let expired = self_signed(-60, &key);
        let e = ensure_compatible(
            &csr_obj(&req, "u", &["Approved"], Some(&expired)),
            &req,
            signer,
            &key,
        )
        .unwrap_err();
        assert!(e.to_string().contains("expired"), "{e}");
    }

    #[test]
    fn kubelet_bootstrap_file_store_update_and_current_key() {
        let d = tempfile::tempdir().unwrap();
        let store = FileStore::new(d.path());
        assert!(store.current_key_pem().is_none());
        let key = KeyPair::generate().unwrap();
        let path = store
            .update(self_signed(3600, &key).as_bytes(), &key.serialize_pem())
            .unwrap();
        assert!(path.exists());
        let cur = store.current_path();
        assert!(std::fs::symlink_metadata(&cur)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(store.current_key_pem().is_some());
        // a second update repoints the symlink
        store
            .update(self_signed(7200, &key).as_bytes(), &key.serialize_pem())
            .unwrap();
        // invalid data is refused
        assert!(store.update(b"junk", &key.serialize_pem()).is_err());
        assert!(store
            .update(self_signed(60, &key).as_bytes(), "junk")
            .is_err());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn kubelet_bootstrap_writes_kubeconfig_pointing_at_the_pem() {
        let d = tempfile::tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let (c, k) = (d.path().join("c.pem"), d.path().join("k.pem"));
        std::fs::write(&k, key.serialize_pem()).unwrap();
        std::fs::write(&c, self_signed(3600, &key)).unwrap();
        let boot = kubeconfig(d.path(), &c, &k);
        let bootstrap =
            kubernetes_rs_client::kubeconfig::KubeConfig::load_from_file(&boot).unwrap();
        let out = d.path().join("sub/kubelet.conf");
        write_kubeconfig_from_bootstrapping(
            &bootstrap,
            &out,
            Path::new("/pki/kubelet-client-current.pem"),
        )
        .unwrap();
        let written = kubernetes_rs_client::kubeconfig::KubeConfig::load_from_file(&out).unwrap();
        assert_eq!(written.get_server().unwrap(), "https://127.0.0.1:1");
        assert!(written.should_skip_tls_verify().unwrap());
        let ctx = written.get_current_context().unwrap();
        assert_eq!(ctx.namespace, "default");
        let u = written.get_user(ctx).unwrap();
        assert_eq!(
            u.client_certificate.as_deref(),
            Some("/pki/kubelet-client-current.pem")
        );
        assert_eq!(
            u.client_key.as_deref(),
            Some("/pki/kubelet-client-current.pem")
        );
    }
}
