//! Ported from upstream `plugin/pkg/auth/authenticator/token/bootstrap/bootstrap_test.go`
//! `TestTokenAuthenticator`, plus negative cases for the fail-closed paths.
//! (Unit tests of the lib live here, see `Cargo.toml` `[lib] test = false`.)

use chrono::Utc;
use kubernetes_rs_api_server::bootstrap_token_authenticator::*;
use kubernetes_rs_common::auth::UserInfo;
use kubernetes_rs_common::resources::Secret;
use kubernetes_rs_storage::{build_key, MemoryStorage, Storage};
use std::collections::HashMap;

const ID: &str = "abc123";
const SEC: &str = "0123456789abcdef";

fn secret(extra: &[(&str, &str)]) -> Secret {
    let mut data: HashMap<String, Vec<u8>> = [
        (BOOTSTRAP_TOKEN_ID_KEY, ID),
        (BOOTSTRAP_TOKEN_SECRET_KEY, SEC),
        (BOOTSTRAP_TOKEN_USAGE_AUTHENTICATION, "true"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
    .collect();
    for (k, v) in extra {
        if v.is_empty() {
            data.remove(*k);
        } else {
            data.insert(k.to_string(), v.as_bytes().to_vec());
        }
    }
    Secret::new(format!("bootstrap-token-{ID}"), "kube-system")
        .with_type(SECRET_TYPE_BOOTSTRAP_TOKEN)
        .with_data(data)
}

async fn authn(s: Option<Secret>, token: &str) -> Option<UserInfo> {
    let st = MemoryStorage::new();
    if let Some(s) = s {
        let key = build_key("secrets", Some("kube-system"), &s.metadata.name);
        st.create(&key, &s).await.unwrap();
    }
    BootstrapTokenAuthenticator::new(&st)
        .authenticate_token(token)
        .await
        .unwrap()
}

fn tok() -> String {
    format!("{ID}.{SEC}")
}

#[tokio::test]
async fn bootstrap_token_authn_valid() {
    let u = authn(Some(secret(&[])), &tok()).await.unwrap();
    assert_eq!(u.username, "system:bootstrap:abc123");
    assert_eq!(u.groups, vec!["system:bootstrappers"]);
}

#[tokio::test]
async fn bootstrap_token_authn_extra_groups_sorted_deduped() {
    let s = secret(&[(
        BOOTSTRAP_TOKEN_EXTRA_GROUPS_KEY,
        "system:bootstrappers:zeta,system:bootstrappers:alpha,system:bootstrappers:zeta",
    )]);
    let u = authn(Some(s), &tok()).await.unwrap();
    assert_eq!(
        u.groups,
        vec![
            "system:bootstrappers",
            "system:bootstrappers:alpha",
            "system:bootstrappers:zeta"
        ]
    );
}

#[tokio::test]
async fn bootstrap_token_authn_rejects_invalid_group() {
    for g in [
        "system:masters",
        "system:bootstrappers:",
        "system:bootstrappers:bad-",
        "system:bootstrappers:UP",
        "system:bootstrappers:ok,system:masters",
    ] {
        let s = secret(&[(BOOTSTRAP_TOKEN_EXTRA_GROUPS_KEY, g)]);
        assert!(authn(Some(s), &tok()).await.is_none(), "{g}");
    }
}

#[tokio::test]
async fn bootstrap_token_authn_malformed_token() {
    for t in [
        "",
        "abc123",
        "abc12.0123456789abcdef",
        "ABC123.0123456789abcdef",
        "abc123.0123456789abcde",
        "abc123.0123456789abcdef\n",
        "abc123.0123456789abcdef.x",
    ] {
        assert!(authn(Some(secret(&[])), t).await.is_none(), "{t:?}");
    }
}

#[tokio::test]
async fn bootstrap_token_authn_missing_secret() {
    assert!(authn(None, &tok()).await.is_none());
}

#[tokio::test]
async fn bootstrap_token_authn_wrong_secret_or_id() {
    assert!(authn(Some(secret(&[])), "abc123.fedcba9876543210")
        .await
        .is_none());
    let s = secret(&[(BOOTSTRAP_TOKEN_ID_KEY, "zzzzzz")]);
    assert!(authn(Some(s), &tok()).await.is_none());
}

#[tokio::test]
async fn bootstrap_token_authn_wrong_type_or_no_data() {
    let s = secret(&[]).with_type("Opaque");
    assert!(authn(Some(s), &tok()).await.is_none());
    let mut s = secret(&[]);
    s.data = None;
    assert!(authn(Some(s), &tok()).await.is_none());
}

#[tokio::test]
async fn bootstrap_token_authn_usage_flag() {
    for v in ["false", "", "True"] {
        let s = secret(&[(BOOTSTRAP_TOKEN_USAGE_AUTHENTICATION, v)]);
        assert!(authn(Some(s), &tok()).await.is_none(), "{v:?}");
    }
}

#[tokio::test]
async fn bootstrap_token_authn_deleted() {
    let mut s = secret(&[]);
    s.metadata.deletion_timestamp = Some(Utc::now());
    assert!(authn(Some(s), &tok()).await.is_none());
}

#[tokio::test]
async fn bootstrap_token_authn_expiration() {
    let future = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let s = secret(&[(BOOTSTRAP_TOKEN_EXPIRATION_KEY, &future)]);
    assert!(authn(Some(s), &tok()).await.is_some());
    let s = secret(&[(BOOTSTRAP_TOKEN_EXPIRATION_KEY, &past)]);
    assert!(authn(Some(s), &tok()).await.is_none());
    // Unparseable expiration is treated as expired (fail closed).
    let s = secret(&[(BOOTSTRAP_TOKEN_EXPIRATION_KEY, "tomorrow")]);
    assert!(authn(Some(s), &tok()).await.is_none());
}
