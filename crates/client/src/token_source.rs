//! Cached file token source: re-reads a bound ServiceAccount token file.
//!
//! Port of `staging/src/k8s.io/client-go/transport/token_source.go`:
//! `NewCachedFileTokenSource` (:69), `fileTokenSource.Token` (:140),
//! `cachingTokenSource.Token` (:166) and `ResetTokenOlderThan` (:196).
//! Projected tokens are rotated by the kubelet at 80% of their lifetime, so a
//! client that read the file once is rejected after expiry; this source
//! re-reads the file every [`FILE_TOKEN_PERIOD`].

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// `period: time.Minute` in `NewCachedFileTokenSource` (token_source.go:79):
/// half of the gap between the kubelet's refresh (80% of a 10 minute
/// lifetime) and the original token's expiry.
pub const FILE_TOKEN_PERIOD: Duration = Duration::from_secs(60);

/// `leeway: 10 * time.Second` in `NewCachedFileTokenSource` (:70).
pub const FILE_TOKEN_LEEWAY: Duration = Duration::from_secs(10);

/// `oauth2.Token` reduced to what a bearer token needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub access_token: String,
    pub expiry: Instant,
}

/// `oauth2.TokenSource`.
pub trait TokenSource: Send + Sync {
    fn token(&self) -> Result<Token, String>;
}

/// `fileTokenSource` (token_source.go:127).
pub struct FileTokenSource {
    path: PathBuf,
    period: Duration,
}

impl FileTokenSource {
    pub fn new(path: impl Into<PathBuf>, period: Duration) -> Self {
        Self {
            path: path.into(),
            period,
        }
    }
}

impl TokenSource for FileTokenSource {
    // fileTokenSource.Token (:140-153), error strings verbatim.
    fn token(&self) -> Result<Token, String> {
        let bytes = std::fs::read(&self.path).map_err(|e| {
            format!(
                "failed to read token file {:?}: {}",
                self.path.display().to_string(),
                e
            )
        })?;
        let tok = String::from_utf8_lossy(&bytes).trim().to_string();
        if tok.is_empty() {
            return Err(format!(
                "read empty token from file {:?}",
                self.path.display().to_string()
            ));
        }
        Ok(Token {
            access_token: tok,
            expiry: Instant::now() + self.period,
        })
    }
}

struct Cache {
    tok: Option<Token>,
    /// `ts.t`: when `tok` was fetched.
    fetched: Option<Instant>,
}

/// `cachingTokenSource` (:155).
pub struct CachingTokenSource {
    base: Arc<dyn TokenSource>,
    leeway: Duration,
    cache: RwLock<Cache>,
    /// "for testing" in upstream.
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl CachingTokenSource {
    /// `NewCachedFileTokenSource` (:69).
    pub fn new_cached_file(path: impl Into<PathBuf>) -> Self {
        Self::with_parts(
            Arc::new(FileTokenSource::new(path, FILE_TOKEN_PERIOD)),
            FILE_TOKEN_LEEWAY,
            Box::new(Instant::now),
        )
    }

    /// `NewCachedTokenSource` (:89): no leeway.
    pub fn new_cached(base: Arc<dyn TokenSource>) -> Self {
        Self::with_parts(base, Duration::ZERO, Box::new(Instant::now))
    }

    pub fn with_parts(
        base: Arc<dyn TokenSource>,
        leeway: Duration,
        now: Box<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        Self {
            base,
            leeway,
            cache: RwLock::new(Cache {
                tok: None,
                fetched: None,
            }),
            now,
        }
    }

    /// Seed the cache (the upstream test builds the struct with `tok` set).
    pub fn with_cached_token(self, tok: Token) -> Self {
        {
            let mut c = self.cache.write().unwrap_or_else(|e| e.into_inner());
            c.tok = Some(tok);
        }
        self
    }

    fn fresh(&self, tok: &Token, now: Instant) -> bool {
        // tok.Expiry.Add(-leeway).After(now)
        tok.expiry.checked_sub(self.leeway).is_some_and(|e| e > now)
    }

    /// `cachingTokenSource.Token` (:166-203).
    pub fn token(&self) -> Result<Token, String> {
        let now = (self.now)();
        // fast path
        {
            let c = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(tok) = &c.tok {
                if self.fresh(tok, now) {
                    return Ok(tok.clone());
                }
            }
        }
        // slow path
        let mut c = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if let Some(tok) = &c.tok {
            if self.fresh(tok, now) {
                return Ok(tok.clone());
            }
        }
        match self.base.token() {
            Ok(tok) => {
                c.fetched = Some((self.now)());
                c.tok = Some(tok.clone());
                Ok(tok)
            }
            Err(err) => match &c.tok {
                None => Err(err),
                Some(old) => {
                    tracing::error!(error = %err, "Unable to rotate token");
                    Ok(old.clone())
                }
            },
        }
    }

    /// `ResetTokenOlderThan` (:196-203): drop the cached token if it was
    /// fetched before `t`.
    pub fn reset_token_older_than(&self, t: Instant) {
        let mut c = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if c.fetched.is_none_or(|f| f < t) {
            c.tok = None;
            c.fetched = None;
        }
    }
}

impl TokenSource for CachingTokenSource {
    fn token(&self) -> Result<Token, String> {
        CachingTokenSource::token(self)
    }
}
