//! Join token format and token files.
//!
//! Port of k3s `pkg/clientaccess/token.go` (`parseToken` :213-266,
//! `FormatToken` :600, `tokenPrefix`/`caHashLength` :29-30) and the token file
//! handling in `pkg/server/server.go` `printTokens` :355-395 (`token`,
//! `node-token`, `agent-token`).
//!
//! A string without the `K10` prefix is wholly the password, user `server`.
//! Deviation: kubeadm-style bootstrap tokens (`abcdef.0123456789abcdef`) are
//! out of scope; a bare string is the password with user `server`.

use std::path::Path;

use sha2::{Digest, Sha256};

/// `tokenPrefix` (token.go:29).
const TOKEN_PREFIX: &str = "K10";
/// `caHashLength = sha256.Size * 2` (token.go:30).
const CA_HASH_LENGTH: usize = 64;
const DEFAULT_USER: &str = "server";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("token must not be empty")]
    Empty,
    #[error("invalid token CA hash length")]
    BadHashLength,
    #[error("invalid token format")]
    BadFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub ca_hash: Option<String>,
    pub username: String,
    pub password: String,
}

/// Port of `parseToken` (token.go:213-266).
pub fn parse_token(s: &str) -> Result<TokenInfo, TokenError> {
    if s.is_empty() {
        return Err(TokenError::Empty);
    }
    // No `K10` prefix: k3s makes it `K10:::` + token, so the whole string is
    // the password (a colon in it does not split) and the user is `server`.
    let Some(rest) = s.strip_prefix(TOKEN_PREFIX) else {
        return Ok(TokenInfo {
            ca_hash: None,
            username: DEFAULT_USER.to_string(),
            password: s.to_string(),
        });
    };
    let (ca_hash, creds) = match rest.split_once("::") {
        Some((hash, creds)) => {
            if !hash.is_empty() && hash.len() != CA_HASH_LENGTH {
                return Err(TokenError::BadHashLength);
            }
            ((!hash.is_empty()).then(|| hash.to_string()), creds)
        }
        None => (None, rest),
    };
    // `K10<hash>::user:pass` splits on the first ':' of the creds part.
    let Some((username, password)) = creds.split_once(':') else {
        return Err(TokenError::BadFormat);
    };
    if password.is_empty() {
        return Err(TokenError::BadFormat);
    }
    let username = if username.is_empty() {
        DEFAULT_USER
    } else {
        username
    };
    Ok(TokenInfo {
        ca_hash,
        username: username.to_string(),
        password: password.to_string(),
    })
}

/// Port of `FormatToken` (token.go:600): `K10<ca-hash>::server:<password>`
/// (the user is always `server`, the only one `verify_basic` accepts).
pub fn format_token(ca_hash: &str, password: &str) -> String {
    format_creds(ca_hash, DEFAULT_USER, password)
}

fn format_creds(ca_hash: &str, user: &str, password: &str) -> String {
    format!("{TOKEN_PREFIX}{ca_hash}::{user}:{password}")
}

/// Writes `<data-dir>/token` (0600) and symlinks `node-token` and
/// `agent-token` to it (server.go `printTokens` :355-395). An existing token
/// is reused (restart keeps the join token); `preset` overrides it.
pub fn load_or_create_token(
    data_dir: &Path,
    ca_hash: &str,
    preset: Option<&str>,
) -> anyhow::Result<String> {
    use rand::RngCore;
    std::fs::create_dir_all(data_dir)?;
    let path = data_dir.join("token");
    let existing = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| parse_token(t.trim()).ok());

    let info = match (preset, existing) {
        (Some(p), _) => {
            let info = parse_token(p.trim())?;
            if info.username != DEFAULT_USER {
                anyhow::bail!(
                    "invalid token: user must be \"{DEFAULT_USER}\" (got {:?}); the supervisor only accepts that user",
                    info.username
                );
            }
            info
        }
        (None, Some(info)) => info,
        (None, None) => {
            let mut b = [0u8; 24];
            rand::rng().fill_bytes(&mut b);
            TokenInfo {
                ca_hash: None,
                username: DEFAULT_USER.to_string(),
                password: hex::encode(b),
            }
        }
    };
    let token = format_creds(ca_hash, &info.username, &info.password);

    if std::fs::read_to_string(&path)
        .ok()
        .as_deref()
        .map(str::trim)
        != Some(token.as_str())
    {
        write_private(&path, &token)?;
    }
    for name in ["node-token", "agent-token"] {
        link_to_token(data_dir, name)?;
    }
    Ok(token)
}

fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    crate::util::write_file_mode(path, contents, 0o600)
}

fn link_to_token(data_dir: &Path, name: &str) -> anyhow::Result<()> {
    let link = data_dir.join(name);
    if let Ok(target) = std::fs::read_link(&link) {
        if target == Path::new("token") {
            return Ok(());
        }
        std::fs::remove_file(&link)?;
    } else if link.symlink_metadata().is_ok() {
        std::fs::remove_file(&link)?;
    }
    std::os::unix::fs::symlink("token", &link)?;
    Ok(())
}

/// Constant-time check of basic-auth credentials against the token password.
/// Both sides are hashed first so the compared digests have equal length.
pub fn verify_basic(token_password: &str, header_user: &str, header_pass: &str) -> bool {
    let want = Sha256::digest(token_password.as_bytes());
    let got = Sha256::digest(header_pass.as_bytes());
    let diff = want
        .iter()
        .zip(got.iter())
        .fold(0u8, |a, (x, y)| a | (x ^ y));
    let user_ok = header_user == DEFAULT_USER;
    diff == 0 && user_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn hash() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn parse_full_token() {
        let t = format!("K10{}::server:s3cret", hash());
        let i = parse_token(&t).unwrap();
        assert_eq!(i.ca_hash.as_deref(), Some(hash().as_str()));
        assert_eq!(
            (i.username.as_str(), i.password.as_str()),
            ("server", "s3cret")
        );
    }

    #[test]
    fn parse_bare_secret_defaults_user_server() {
        let i = parse_token("s3cret").unwrap();
        assert_eq!(i.ca_hash, None);
        assert_eq!(
            (i.username.as_str(), i.password.as_str()),
            ("server", "s3cret")
        );
    }

    #[test]
    fn parse_user_pass() {
        // k3s turns a bare string into `K10:::` + token: whole string is the password.
        let i = parse_token("bob:pw").unwrap();
        assert_eq!(i.ca_hash, None);
        assert_eq!(
            (i.username.as_str(), i.password.as_str()),
            ("server", "bob:pw")
        );
    }

    #[test]
    fn hash_of_65_chars_rejected() {
        let t = format!("K10{}::server:pw", "a".repeat(65));
        assert_eq!(parse_token(&t), Err(TokenError::BadHashLength));
    }

    #[test]
    fn empty_hash_is_accepted() {
        let i = parse_token("K10::server:pw").unwrap();
        assert_eq!(i.ca_hash, None);
        assert_eq!((i.username.as_str(), i.password.as_str()), ("server", "pw"));
    }

    #[test]
    fn bare_token_with_colon_roundtrips_through_verify_basic() {
        let d = tempfile::tempdir().unwrap();
        let t = load_or_create_token(d.path(), &hash(), Some("a:b")).unwrap();
        let again = load_or_create_token(d.path(), &hash(), None).unwrap();
        assert_eq!(t, again);
        let i = parse_token(&t).unwrap();
        assert_eq!(
            (i.username.as_str(), i.password.as_str()),
            ("server", "a:b")
        );
        assert!(verify_basic(&i.password, "server", "a:b"));
    }

    #[test]
    fn bad_hash_length_rejected() {
        assert_eq!(
            parse_token("K10abcd::server:x"),
            Err(TokenError::BadHashLength)
        );
        assert_eq!(parse_token(""), Err(TokenError::Empty));
    }

    #[test]
    fn load_or_create_token_is_stable_and_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let a = load_or_create_token(d.path(), &hash(), None).unwrap();
        let b = load_or_create_token(d.path(), &hash(), None).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with(&format!("K10{}::server:", hash())));
        assert_eq!(parse_token(&a).unwrap().password.len(), 48);
        for n in ["node-token", "agent-token"] {
            let p = d.path().join(n);
            assert!(p.symlink_metadata().unwrap().file_type().is_symlink());
            assert_eq!(std::fs::read_link(&p).unwrap(), Path::new("token"));
            assert_eq!(std::fs::read_to_string(&p).unwrap().trim(), a);
        }
        let mode = std::fs::metadata(d.path().join("token"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn preset_token_is_honoured() {
        let d = tempfile::tempdir().unwrap();
        let t = load_or_create_token(d.path(), &hash(), Some("mysecret")).unwrap();
        assert_eq!(t, format_token(&hash(), "mysecret"));
        let again = load_or_create_token(d.path(), &hash(), None).unwrap();
        assert_eq!(again, t);
    }

    #[test]
    fn preset_token_with_other_user_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let t = format!("K10{}::admin:pw", hash());
        assert!(load_or_create_token(d.path(), &hash(), Some(&t)).is_err());
        assert!(!d.path().join("token").exists());
        let ok = format!("K10{}::server:pw", hash());
        assert!(load_or_create_token(d.path(), &hash(), Some(&ok)).is_ok());
    }

    #[test]
    fn verify_basic_checks_password_and_user() {
        assert!(verify_basic("pw", "server", "pw"));
        assert!(!verify_basic("pw", "server", "px"));
        assert!(!verify_basic("pw", "other", "pw"));
    }
}
