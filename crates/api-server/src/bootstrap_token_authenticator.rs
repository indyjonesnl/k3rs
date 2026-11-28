//! Bootstrap-token authenticator, backed by `bootstrap-token-<id>` Secrets in
//! `kube-system`.
//!
//! Ported from upstream
//! `plugin/pkg/auth/authenticator/token/bootstrap/bootstrap.go`
//! (`NewTokenAuthenticator` :47, `AuthenticateToken` :90, `tokenErrorf` :60)
//! plus the helpers it calls:
//! `staging/src/k8s.io/cluster-bootstrap/util/tokens/tokens.go` `ParseToken`,
//! `util/secrets/secrets.go` `GetData`, `HasExpired`/`GetExpiration`,
//! `GetGroups`, and `token/util/helpers.go` `ValidateBootstrapGroupName`;
//! constants from `token/api/types.go`.
//!
//! Security: fails closed. Every mismatch (bad type, wrong secret, wrong id,
//! expired or unparseable expiration, missing usage flag, invalid group)
//! returns `Ok(None)` ("not authenticated"); only a storage error other than
//! NotFound is surfaced as `Err`, as upstream returns the lister error.
//!
//! Wired into the chain by `main` with `--enable-bootstrap-token-auth`
//! (`kubernetes_rs_middleware::set_bootstrap_token_authenticator`).

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use kubernetes_rs_common::auth::UserInfo;
use kubernetes_rs_common::resources::Secret;
use kubernetes_rs_common::Error;
use kubernetes_rs_storage::{build_key, Storage};
use tracing::debug;

/// Namespace the lister is scoped to ("Lister is expected to be for the
/// "kube-system" namespace", bootstrap.go:45).
pub const BOOTSTRAP_TOKEN_NAMESPACE: &str = "kube-system";
/// `BootstrapTokenSecretPrefix` (types.go:28).
pub const BOOTSTRAP_TOKEN_SECRET_PREFIX: &str = "bootstrap-token-";
/// `SecretTypeBootstrapToken` (types.go:33).
pub const SECRET_TYPE_BOOTSTRAP_TOKEN: &str = "bootstrap.kubernetes.io/token";
/// `BootstrapTokenIDKey` (types.go:38).
pub const BOOTSTRAP_TOKEN_ID_KEY: &str = "token-id";
/// `BootstrapTokenSecretKey` (types.go:42).
pub const BOOTSTRAP_TOKEN_SECRET_KEY: &str = "token-secret";
/// `BootstrapTokenExpirationKey` (types.go:48).
pub const BOOTSTRAP_TOKEN_EXPIRATION_KEY: &str = "expiration";
/// `BootstrapTokenExtraGroupsKey` (types.go:57).
pub const BOOTSTRAP_TOKEN_EXTRA_GROUPS_KEY: &str = "auth-extra-groups";
/// `BootstrapTokenUsageAuthentication` (types.go:74).
pub const BOOTSTRAP_TOKEN_USAGE_AUTHENTICATION: &str = "usage-bootstrap-authentication";
/// `BootstrapUserPrefix` (types.go:87).
pub const BOOTSTRAP_USER_PREFIX: &str = "system:bootstrap:";
/// `BootstrapDefaultGroup` (types.go:90).
pub const BOOTSTRAP_DEFAULT_GROUP: &str = "system:bootstrappers";
/// Prefix of `BootstrapGroupPattern` (types.go:96).
const BOOTSTRAP_GROUP_PREFIX: &str = "system:bootstrappers:";

/// `ParseToken` with `BootstrapTokenPattern`
/// `\A([a-z0-9]{6})\.([a-z0-9]{16})\z` (types.go:99).
fn parse_token(s: &str) -> Option<(&str, &str)> {
    let (id, secret) = s.split_once('.')?;
    let ok = |p: &str, n: usize| {
        p.len() == n
            && p.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    };
    (ok(id, 6) && ok(secret, 16)).then_some((id, secret))
}

/// `ValidateBootstrapGroupName`: `BootstrapGroupPattern`
/// `\Asystem:bootstrappers:[a-z0-9:-]{0,255}[a-z0-9]\z` (types.go:96).
fn validate_bootstrap_group_name(name: &str) -> Result<(), String> {
    let valid = name
        .strip_prefix(BOOTSTRAP_GROUP_PREFIX)
        .is_some_and(|rest| {
            let b = rest.as_bytes();
            !b.is_empty()
                && b.len() <= 256
                && b[b.len() - 1].is_ascii_lowercase() | b[b.len() - 1].is_ascii_digit()
                && b.iter().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b':' || *c == b'-'
                })
        });
    if valid {
        Ok(())
    } else {
        Err(format!(
            "bootstrap group {name:?} is invalid (must match \\Asystem:bootstrappers:[a-z0-9:-]{{0,255}}[a-z0-9]\\z)"
        ))
    }
}

/// `GetData`: the value for `key`, or "" when absent (secrets.go).
fn get_data(secret: &Secret, key: &str) -> String {
    secret
        .data
        .as_ref()
        .and_then(|d| d.get(key))
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

/// `HasExpired`/`GetExpiration`: an unparseable expiration is treated as
/// expired (secrets.go).
fn has_expired(secret: &Secret, now: DateTime<Utc>) -> bool {
    let expiration = get_data(secret, BOOTSTRAP_TOKEN_EXPIRATION_KEY);
    if expiration.is_empty() {
        return false;
    }
    match DateTime::parse_from_rfc3339(&expiration) {
        Err(e) => {
            debug!(
                "Unparseable expiration time ({expiration}) in {}/{} Secret: {e}. Treating as expired.",
                secret.metadata.namespace.as_deref().unwrap_or_default(),
                secret.metadata.name
            );
            true
        }
        Ok(t) => t.with_timezone(&Utc) <= now,
    }
}

/// `GetGroups`: the default group plus validated extras, deduplicated and
/// sorted.
fn get_groups(secret: &Secret) -> Result<Vec<String>, String> {
    let mut groups = BTreeSet::new();
    groups.insert(BOOTSTRAP_DEFAULT_GROUP.to_string());
    let extra = get_data(secret, BOOTSTRAP_TOKEN_EXTRA_GROUPS_KEY);
    if !extra.is_empty() {
        for g in extra.split(',') {
            validate_bootstrap_group_name(g)?;
            groups.insert(g.to_string());
        }
    }
    Ok(groups.into_iter().collect())
}

/// `tokenErrorf` (bootstrap.go:60): log (V(3)) a secret that matched the
/// bearer token but failed another criterion.
fn token_errorf(secret: &Secret, msg: &str) {
    debug!(
        "Bootstrap secret {}/{} matching bearer token {msg}",
        secret.metadata.namespace.as_deref().unwrap_or_default(),
        secret.metadata.name
    );
}

/// `subtle.ConstantTimeCompare(a, b) == 1`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `TokenAuthenticator` (bootstrap.go:41).
pub struct BootstrapTokenAuthenticator<'a, S: Storage> {
    storage: &'a S,
}

impl<'a, S: Storage> BootstrapTokenAuthenticator<'a, S> {
    /// `NewTokenAuthenticator` (bootstrap.go:47).
    pub fn new(storage: &'a S) -> Self {
        Self { storage }
    }

    /// `AuthenticateToken` (bootstrap.go:90). `Ok(None)` is upstream's
    /// `(nil, false, nil)`.
    pub async fn authenticate_token(&self, token: &str) -> Result<Option<UserInfo>, Error> {
        self.authenticate_token_at(token, Utc::now()).await
    }

    async fn authenticate_token_at(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<UserInfo>, Error> {
        // Token isn't of the correct form, ignore it.
        let Some((token_id, token_secret)) = parse_token(token) else {
            return Ok(None);
        };

        let secret_name = format!("{BOOTSTRAP_TOKEN_SECRET_PREFIX}{token_id}");
        let key = build_key("secrets", Some(BOOTSTRAP_TOKEN_NAMESPACE), &secret_name);
        let secret: Secret = match self.storage.get(&key).await {
            Ok(s) => s,
            Err(Error::NotFound(_)) => {
                debug!("No secret of name {secret_name} to match bootstrap bearer token");
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        if secret.metadata.deletion_timestamp.is_some() {
            token_errorf(&secret, "is deleted and awaiting removal");
            return Ok(None);
        }

        if secret.secret_type.as_deref() != Some(SECRET_TYPE_BOOTSTRAP_TOKEN)
            || secret.data.is_none()
        {
            token_errorf(
                &secret,
                &format!("has invalid type, expected {SECRET_TYPE_BOOTSTRAP_TOKEN}."),
            );
            return Ok(None);
        }

        let ts = get_data(&secret, BOOTSTRAP_TOKEN_SECRET_KEY);
        if !constant_time_eq(ts.as_bytes(), token_secret.as_bytes()) {
            token_errorf(
                &secret,
                &format!("has invalid value for key {BOOTSTRAP_TOKEN_SECRET_KEY}."),
            );
            return Ok(None);
        }

        let id = get_data(&secret, BOOTSTRAP_TOKEN_ID_KEY);
        if id != token_id {
            token_errorf(
                &secret,
                &format!("has invalid value for key {BOOTSTRAP_TOKEN_ID_KEY}."),
            );
            return Ok(None);
        }

        if has_expired(&secret, now) {
            return Ok(None);
        }

        if get_data(&secret, BOOTSTRAP_TOKEN_USAGE_AUTHENTICATION) != "true" {
            token_errorf(
                &secret,
                &format!("not marked {BOOTSTRAP_TOKEN_USAGE_AUTHENTICATION}=true."),
            );
            return Ok(None);
        }

        let groups = match get_groups(&secret) {
            Ok(g) => g,
            Err(e) => {
                token_errorf(
                    &secret,
                    &format!("has invalid value for key {BOOTSTRAP_TOKEN_EXTRA_GROUPS_KEY}: {e}."),
                );
                return Ok(None);
            }
        };

        Ok(Some(UserInfo {
            username: format!("{BOOTSTRAP_USER_PREFIX}{id}"),
            uid: String::new(),
            groups,
            extra: HashMap::new(),
        }))
    }
}

/// Adapter installed in the middleware's authentication chain.
pub struct ChainBootstrapTokenAuthenticator;

#[async_trait::async_trait]
impl kubernetes_rs_middleware::BootstrapTokenAuthenticate for ChainBootstrapTokenAuthenticator {
    async fn authenticate_token(
        &self,
        storage: &kubernetes_rs_storage::StorageBackend,
        token: &str,
    ) -> Result<Option<UserInfo>, Error> {
        BootstrapTokenAuthenticator::new(storage)
            .authenticate_token(token)
            .await
    }
}
