//! Ports of `TestCachingTokenSource` / `TestCachingTokenSourceRace`
//! (client-go/transport/token_source_test.go:41,126) plus the file source.

use kubernetes_rs_client::token_source::{CachingTokenSource, FileTokenSource, Token, TokenSource};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct TestTokenSource {
    tok: Option<Token>,
    err: Option<String>,
    calls: AtomicUsize,
}

impl TokenSource for TestTokenSource {
    fn token(&self) -> Result<Token, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match (&self.tok, &self.err) {
            (_, Some(e)) => Err(e.clone()),
            (Some(t), None) => Ok(t.clone()),
            (None, None) => Err("no token".into()),
        }
    }
}

#[test]
fn token_source_caching_table() {
    let start = Instant::now();
    let min = Duration::from_secs(60);
    let tok_a = Token {
        access_token: "a".into(),
        expiry: start + 10 * min,
    };
    let tok_b = Token {
        access_token: "b".into(),
        expiry: start + 20 * min,
    };
    // (name, cached, ts_tok, ts_err, wait, want_tok, want_err, want_calls)
    #[allow(clippy::type_complexity)]
    let cases: Vec<(
        &str,
        Option<Token>,
        Option<Token>,
        Option<&str>,
        Duration,
        Option<Token>,
        bool,
        usize,
    )> = vec![
        (
            "valid token returned from cache",
            Some(tok_a.clone()),
            None,
            None,
            Duration::ZERO,
            Some(tok_a.clone()),
            false,
            0,
        ),
        (
            "valid 1 minute before scheduled refresh",
            Some(tok_a.clone()),
            None,
            None,
            8 * min,
            Some(tok_a.clone()),
            false,
            0,
        ),
        (
            "new token when cache is empty",
            None,
            Some(tok_a.clone()),
            None,
            Duration::ZERO,
            Some(tok_a.clone()),
            false,
            1,
        ),
        (
            "new token 1 minute after scheduled refresh",
            Some(tok_a.clone()),
            Some(tok_b.clone()),
            None,
            10 * min,
            Some(tok_b.clone()),
            false,
            1,
        ),
        (
            "error on create token returns error",
            None,
            None,
            Some("error"),
            Duration::ZERO,
            None,
            true,
            1,
        ),
    ];
    for (name, cached, ts_tok, ts_err, wait, want_tok, want_err, want_calls) in cases {
        let tts = Arc::new(TestTokenSource {
            tok: ts_tok,
            err: ts_err.map(String::from),
            calls: AtomicUsize::new(0),
        });
        let mut ts =
            CachingTokenSource::with_parts(tts.clone(), min, Box::new(move || start + wait));
        if let Some(c) = cached {
            ts = ts.with_cached_token(c);
        }
        let got = ts.token();
        assert_eq!(got.is_err(), want_err, "{name}");
        assert_eq!(got.ok(), want_tok, "{name}");
        assert_eq!(tts.calls.load(Ordering::SeqCst), want_calls, "{name}");
    }
}

#[test]
fn token_source_caching_race_single_call() {
    for _ in 0..20 {
        let tts = Arc::new(TestTokenSource {
            tok: Some(Token {
                access_token: "a".into(),
                expiry: Instant::now() + Duration::from_secs(3_600_000),
            }),
            err: None,
            calls: AtomicUsize::new(0),
        });
        let ts = Arc::new(CachingTokenSource::with_parts(
            tts.clone(),
            Duration::from_secs(60),
            Box::new(Instant::now),
        ));
        let hs: Vec<_> = (0..50)
            .map(|_| {
                let ts = ts.clone();
                std::thread::spawn(move || ts.token().unwrap())
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(tts.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn token_source_file_reread_and_errors() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("token");
    let fts = FileTokenSource::new(&p, Duration::from_secs(60));
    let e = fts.token().unwrap_err();
    assert!(e.starts_with("failed to read token file "), "{e}");
    std::fs::write(&p, " \n").unwrap();
    let e = fts.token().unwrap_err();
    assert!(e.starts_with("read empty token from file "), "{e}");
    std::fs::write(&p, " abc\n").unwrap();
    assert_eq!(fts.token().unwrap().access_token, "abc");
}

#[test]
fn token_source_reset_token_older_than() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("token");
    std::fs::write(&p, "one").unwrap();
    let ts = CachingTokenSource::new_cached_file(&p);
    assert_eq!(ts.token().unwrap().access_token, "one");
    std::fs::write(&p, "two").unwrap();
    // Cached: not yet re-read.
    assert_eq!(ts.token().unwrap().access_token, "one");
    // A reset older than the fetch time keeps the token.
    ts.reset_token_older_than(Instant::now() - Duration::from_secs(5));
    assert_eq!(ts.token().unwrap().access_token, "one");
    // A reset newer than the fetch time drops it.
    ts.reset_token_older_than(Instant::now() + Duration::from_secs(1));
    assert_eq!(ts.token().unwrap().access_token, "two");
}
