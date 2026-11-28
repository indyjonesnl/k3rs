//! `trackedToImagePullCreds` and the `getPodCredentials` conversion of
//! `EnsureImageExists` (`pkg/kubelet/images/image_manager.go:213-248`,
//! `:433-460`): which credential a pull record keeps, and which of a pod's
//! credentials count for a verification (never node-accessible ones).

use kubernetes_rs_kubelet::credentialprovider::{
    AuthConfig, CredentialSource, SecretCoordinates, ServiceAccountCoordinates, TrackedAuthConfig,
};
use kubernetes_rs_kubelet::image_manager::{
    pod_credentials_from_tracked, tracked_to_image_pull_creds,
};

fn tracked(source: Option<CredentialSource>, hash: &str) -> TrackedAuthConfig {
    TrackedAuthConfig {
        auth: AuthConfig::default(),
        auth_config_hash: hash.to_string(),
        source,
    }
}

fn secret(name: &str) -> CredentialSource {
    CredentialSource::Secret(SecretCoordinates {
        uid: format!("uid-{name}"),
        namespace: "ns".into(),
        name: name.into(),
    })
}

fn sa(name: &str) -> CredentialSource {
    CredentialSource::ServiceAccount(ServiceAccountCoordinates {
        uid: format!("uid-{name}"),
        namespace: "ns".into(),
        name: name.into(),
    })
}

#[test]
fn image_pull_policy_verify_tracked_to_creds() {
    // anonymous pull, and a node-global credential: node accessible.
    assert!(tracked_to_image_pull_creds(None).node_pods_accessible);
    assert!(tracked_to_image_pull_creds(Some(&tracked(None, "h"))).node_pods_accessible);

    let c = tracked_to_image_pull_creds(Some(&tracked(Some(secret("s1")), "hash1")));
    assert!(!c.node_pods_accessible);
    assert_eq!(c.kubernetes_secrets.len(), 1);
    assert_eq!(c.kubernetes_secrets[0].name, "s1");
    assert_eq!(c.kubernetes_secrets[0].uid, "uid-s1");
    assert_eq!(c.kubernetes_secrets[0].credential_hash, "hash1");
    assert!(c.kubernetes_service_accounts.is_empty());

    let c = tracked_to_image_pull_creds(Some(&tracked(Some(sa("sa1")), "ignored")));
    assert!(c.kubernetes_secrets.is_empty());
    assert_eq!(c.kubernetes_service_accounts.len(), 1);
    assert_eq!(c.kubernetes_service_accounts[0].name, "sa1");
}

#[test]
fn image_pull_policy_verify_pod_credentials_skip_node_accessible() {
    let creds = vec![
        tracked(None, "node"),
        tracked(Some(secret("a")), "ha"),
        tracked(Some(sa("first")), ""),
        tracked(Some(secret("b")), "hb"),
        tracked(Some(sa("second")), ""),
    ];
    let (secrets, account) = pod_credentials_from_tracked(&creds);
    assert_eq!(
        secrets.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
    assert_eq!(secrets[1].credential_hash, "hb");
    // one service account per pod: the first wins.
    assert_eq!(account.unwrap().name, "first");

    let (secrets, account) = pod_credentials_from_tracked(&[tracked(None, "node")]);
    assert!(secrets.is_empty() && account.is_none());
}
