//! End to end: a legacy `kubernetes.io/service-account-token` Secret, signed
//! by the tokens controller with `k3rs server`'s ECDSA `sa.key`, authenticates
//! against the api-server configured like `k3rs server`
//! (`--service-account-key-file=sa.pub`, `--service-account-signing-key-file=sa.key`).
//!
//! Upstream: the KCM's tokens controller signs with
//! `JWTTokenGenerator(LegacyIssuer, privateKey)` (any RSA/ECDSA key,
//! pkg/serviceaccount/jwt.go:61-89, cmd/kube-controller-manager/app/service_accounts.go),
//! k3s gives it the api-server's signing key (pkg/daemons/control/server.go:115,
//! :226), and the api-server's legacy authenticator verifies with the
//! `--service-account-key-file` keys (pkg/kubeapiserver/authenticator/config.go).
//!
//! Run with `cargo nextest run -p k3rs --test legacy_sa_token`.

mod common;

use base64::Engine;
use common::{base_builder, client_for, start_authn_api_configured};
use k3rs::pki::Pki;
use k3rs_controller_manager::controllers::serviceaccount::{
    load_signing_key_file, ServiceAccountController,
};
use k3rs_storage::{build_key, Storage, StorageBackend};
use serde_json::{json, Value};
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_token_secret_signed_with_server_sa_key_authenticates() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::load_or_create(dir.path(), &["localhost".to_string()]).unwrap();
    let storage = Arc::new(StorageBackend::new_memory());
    let tls = pki.dir.clone();
    let issuer = "https://kubernetes.default.svc.cluster.local".to_string();
    let (base, _h) = start_authn_api_configured(&pki, storage.clone(), false, |cfg| {
        cfg.service_account.key_files = vec![tls.join("sa.pub").to_string_lossy().into()];
        cfg.service_account.signing_key_file = Some(tls.join("sa.key").to_string_lossy().into());
        cfg.service_account.issuers = vec![issuer.clone()];
        cfg.service_account.api_audiences = vec![issuer.clone(), "k3rs".into()];
    })
    .await;

    // The ServiceAccount and a user-created legacy token Secret for it
    // (`LegacyServiceAccountTokenNoAutoGeneration`: users create these).
    let admin = client_for(&pki, "system:admin", &["system:masters"]);
    let sa: Value = admin
        .post(format!("{base}/api/v1/namespaces/default/serviceaccounts"))
        .json(&json!({"apiVersion": "v1", "kind": "ServiceAccount",
                      "metadata": {"name": "legacy"}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let uid = sa["metadata"]["uid"].as_str().expect("SA uid").to_string();
    let r = admin
        .post(format!("{base}/api/v1/namespaces/default/secrets"))
        .json(&json!({"apiVersion": "v1", "kind": "Secret",
                      "type": "kubernetes.io/service-account-token",
                      "metadata": {"name": "legacy-token", "annotations": {
                          "kubernetes.io/service-account.name": "legacy",
                          "kubernetes.io/service-account.uid": uid}}}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "create secret: {}", r.status());

    // The tokens controller, keyed like `k3rs server` (sa.key is ECDSA P-256).
    let key = load_signing_key_file(&pki.dir.join("sa.key")).unwrap();
    assert_eq!(format!("{:?}", key.algorithm), "ES256");
    let controller = ServiceAccountController::new(storage.clone()).with_signing_key(key);
    controller
        .sync_token_secret("default", "legacy-token")
        .await
        .unwrap();
    let secret: Value = storage
        .get(&build_key("secrets", Some("default"), "legacy-token"))
        .await
        .unwrap();
    let token = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(secret["data"]["token"].as_str().expect("token populated"))
            .unwrap(),
    )
    .unwrap();

    // Authenticate with it: SelfSubjectReview echoes the authenticated user.
    let anon = base_builder(&pki).build().unwrap();
    let review = |t: String| {
        let anon = anon.clone();
        let base = base.clone();
        async move {
            anon.post(format!(
                "{base}/apis/authentication.k8s.io/v1/selfsubjectreviews"
            ))
            .bearer_auth(t)
            .json(&json!({"apiVersion": "authentication.k8s.io/v1",
                          "kind": "SelfSubjectReview"}))
            .send()
            .await
            .unwrap()
        }
    };
    let r = review(token.clone()).await;
    assert_eq!(r.status().as_u16(), 201, "legacy token must authenticate");
    let body: Value = r.json().await.unwrap();
    assert_eq!(
        body["status"]["userInfo"]["username"],
        "system:serviceaccount:default:legacy"
    );

    // A token signed by another key is rejected (401).
    let other = rcgen::KeyPair::generate().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let other_path = other_dir.path().join("other.key");
    std::fs::write(&other_path, other.serialize_pem()).unwrap();
    let forged = ServiceAccountController::new(storage.clone())
        .with_signing_key(load_signing_key_file(&other_path).unwrap())
        .generate_token("default", "legacy", &uid, "legacy-token")
        .unwrap();
    assert_eq!(review(forged).await.status().as_u16(), 401);
}
