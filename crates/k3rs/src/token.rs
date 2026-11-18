//! Join token format and token files.
//!
//! Port of k3s `pkg/clientaccess/token.go` (`parseToken` :213-266,
//! `FormatToken` :600, `tokenPrefix`/`caHashLength` :29-30) and the token file
//! handling in `pkg/server/server.go` `printTokens` :355-395 (`token`,
//! `node-token`, `agent-token`).
//!
//! Deviation: kubeadm-style bootstrap tokens (`abcdef.0123456789abcdef`) are
//! out of scope; a bare string is the password with user `server`.

use std::io::Write;
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
    let (ca_hash, creds) = match s.strip_prefix(TOKEN_PREFIX) {
        Some(rest) => match rest.split_once("::") {
            Some((hash, creds)) => {
                if !hash.is_empty() && hash.len() != CA_HASH_LENGTH {
                    return Err(TokenError::BadHashLength);
                }
                ((!hash.is_empty()).then(|| hash.to_string()), creds)
            }
            None => (None, rest),
        },
        None => (None, s),
    };
    let (username, password) = match creds.split_once(':') {
        Some((u, p)) => (u, p),
        // Bare password (k3s: ":::"+token); user defaults to `server`.
        None if !s.starts_with(TOKEN_PREFIX) => (DEFAULT_USER, creds),
        None => return Err(TokenError::BadFormat),
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

/// Port of `FormatToken` (token.go:600): `K10<ca-hash>::<user>:<password>`.
/// A `password` already of the form `user:pass` keeps its user.
pub fn format_token(ca_hash: &str, password: &str) -> String {
    if password.contains(':') {
        format!("{TOKEN_PREFIX}{ca_hash}::{password}")
    } else {
        format!("{TOKEN_PREFIX}{ca_hash}::{DEFAULT_USER}:{password}")
    }
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

    let password = match (preset, &existing) {
        (Some(p), _) => {
            let info = parse_token(p.trim())?;
            format!("{}:{}", info.username, info.password)
        }
        (None, Some(info)) => format!("{}:{}", info.username, info.password),
        (None, None) => {
            let mut b = [0u8; 24];
            rand::rng().fill_bytes(&mut b);
            hex::encode(b)
        }
    };
    let token = format_token(ca_hash, &password);

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
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    // `mode` is masked by umask and ignored for existing files.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
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
        let i = parse_token("bob:pw").unwrap();
        assert_eq!((i.username.as_str(), i.password.as_str()), ("bob", "pw"));
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
    fn verify_basic_checks_password_and_user() {
        assert!(verify_basic("pw", "server", "pw"));
        assert!(!verify_basic("pw", "server", "px"));
        assert!(!verify_basic("pw", "other", "pw"));
    }
}
