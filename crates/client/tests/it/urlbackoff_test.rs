//! Ports of client-go rest/urlbackoff_test.go and util/flowcontrol/
//! backoff_test.go (TestSlowBackoff, TestBackoffReset, TestBackoffHighWaterMark,
//! TestBackoffGC, TestIsInBackOffSinceUpdate, TestBackoffWithJitter,
//! TestAlternateHasExpiredFunc) plus the env config.

use std::sync::Arc;
use std::time::Duration;

use kubernetes_rs_client::urlbackoff::*;
use reqwest::Url;

fn parse(s: &str) -> Url {
    Url::parse(s).unwrap()
}

const S: Duration = Duration::from_secs(1);

fn fake(step: Duration, max: Duration) -> (FakeClock, Backoff) {
    let tc = FakeClock::default();
    let b = Backoff::with_clock(Arc::new(tc.clone()), step, max, 0.0);
    (tc, b)
}

#[test]
fn urlbackoff_functionality_collisions() {
    let b = UrlBackoff::new(Backoff::new(S, 60 * S));
    b.update_backoff(&parse("http://100.200.250.250:8080"), None, 500);
    b.update_backoff(&parse("http://1.2.3.4:8080"), None, 500);
    assert_eq!(
        b.calculate_backoff(&parse("http://1.2.3.4:100")),
        Duration::ZERO,
        "URLs are colliding in the backoff map!"
    );
}

#[test]
fn urlbackoff_functionality() {
    let b = UrlBackoff::new(Backoff::new(S, 60 * S));
    // 300 clears the backoff; 429 and 5xx increase it.
    let seconds = [0u64, 1, 2, 4, 8, 0, 1, 2];
    let codes = [429u16, 500, 501, 502, 300, 500, 501, 502];
    for (i, sec) in seconds.iter().enumerate() {
        let got = b.calculate_backoff(&parse("http://1.2.3.4:100"));
        assert!(
            got >= Duration::from_secs(*sec) && got <= Duration::from_secs(sec + 5),
            "step {i}: want {sec}s got {got:?}"
        );
        b.update_backoff(
            &parse("http://1.2.3.4:100/responseCodeForFuncTest"),
            None,
            codes[i],
        );
    }
    assert_ne!(
        b.calculate_backoff(&parse("http://1.2.3.4:100")),
        Duration::ZERO
    );
}

#[test]
fn urlbackoff_4xx_other_than_429_resets() {
    let b = UrlBackoff::new(Backoff::new(S, 60 * S));
    let u = parse("http://h:1/x");
    b.update_backoff(&u, None, 503);
    assert_eq!(b.calculate_backoff(&u), S);
    b.update_backoff(&u, Some("boom"), 404);
    assert_eq!(b.calculate_backoff(&u), Duration::ZERO);
}

#[test]
fn urlbackoff_base_url_key_is_host_port() {
    assert_eq!(
        UrlBackoff::base_url_key(&parse("http://127.0.0.1:8080/api/v2/abcde")),
        "127.0.0.1:8080"
    );
    assert_eq!(
        UrlBackoff::base_url_key(&parse("https://example.com/x")),
        "example.com"
    );
}

#[test]
fn urlbackoff_no_backoff_and_disable() {
    let n = NoBackoff;
    assert_eq!(n.calculate_backoff(&parse("http://h/")), Duration::ZERO);
    let mut b = UrlBackoff::new(Backoff::new(S, 60 * S));
    b.disable();
    b.update_backoff(&parse("http://h/"), None, 500);
    assert_eq!(b.calculate_backoff(&parse("http://h/")), Duration::ZERO);
}

#[test]
fn urlbackoff_env_config() {
    let u = parse("http://h:1/");
    assert_eq!(
        exp_backoff_config(None, None).calculate_backoff(&u),
        Duration::ZERO
    );
    let m = exp_backoff_config(Some("2"), Some("10"));
    m.update_backoff(&u, None, 500);
    assert_eq!(m.calculate_backoff(&u), 2 * S);
    // Unparseable falls back to NoBackoff.
    let m = exp_backoff_config(Some("x"), Some("10"));
    m.update_backoff(&u, None, 500);
    assert_eq!(m.calculate_backoff(&u), Duration::ZERO);
}

#[tokio::test]
async fn urlbackoff_sleep_with_context_cancelled_returns_early() {
    let b = UrlBackoff::new(Backoff::new(S, 60 * S));
    let start = std::time::Instant::now();
    b.sleep_with_context(Duration::from_secs(600), std::future::ready(()))
        .await;
    assert!(start.elapsed() < Duration::from_secs(60));
    b.sleep_with_context(Duration::ZERO, std::future::pending())
        .await;
}

#[test]
fn urlbackoff_flowcontrol_slow_backoff() {
    let id = "_idSlow";
    let (tc, b) = fake(S, 50 * S);
    for (ix, c) in [0u64, 1, 2, 4, 8, 16, 32, 50, 50, 50].iter().enumerate() {
        tc.step(S);
        assert_eq!(b.get(id), Duration::from_secs(*c), "input {ix}");
        b.next(id, tc.now());
    }
    b.next(id, tc.now());
    b.reset(id);
    assert_eq!(b.get(id), Duration::ZERO);
}

#[test]
fn urlbackoff_flowcontrol_reset_after_expiry() {
    let id = "_idReset";
    let max = 5 * S;
    let (tc, b) = fake(S, max);
    for _ in 0..=5 {
        tc.step(S);
        b.next(id, tc.now());
    }
    assert!(b.is_in_back_off_since(id, tc.now()));
    let last_update = tc.now();
    tc.step(2 * max + S);
    assert!(!b.is_in_back_off_since(id, last_update));
}

#[test]
fn urlbackoff_flowcontrol_high_water_mark() {
    let id = "_idHiWaterMark";
    let max = 5 * S;
    let (tc, b) = fake(S, max);
    for _ in 0..=5 {
        tc.step(S);
        b.next(id, tc.now());
    }
    // The high watermark expires only after 2*maxDuration.
    tc.step(max + S);
    b.next(id, tc.now());
    assert_eq!(b.get(id), max);
}

#[test]
fn urlbackoff_flowcontrol_gc() {
    let id = "_idGC";
    let max = 5 * S;
    let (tc, b) = fake(S, max);
    for _ in 0..=5 {
        tc.step(S);
        b.next(id, tc.now());
    }
    tc.step(max);
    b.gc();
    assert_eq!(b.get(id), max, "entry GC'd too early");
    tc.step(max + S);
    b.gc();
    assert_eq!(b.get(id), Duration::ZERO, "entry not GC'd");
}

#[test]
fn urlbackoff_flowcontrol_in_backoff_since_update() {
    let id = "_idIsInBackoff";
    let (tc, b) = fake(S, 10 * S);
    assert!(!b.is_in_back_off_since_update(id, tc.now()));
    b.next(id, tc.now());
    assert!(b.is_in_back_off_since_update(id, tc.now()));
    tc.step(S);
    assert!(!b.is_in_back_off_since_update(id, tc.now()));
}

#[test]
fn urlbackoff_flowcontrol_jitter_bounds() {
    let id = "_idJitter";
    let tc = FakeClock::default();
    let b = Backoff::with_clock(Arc::new(tc.clone()), S, 60 * S, 0.5);
    b.next(id, tc.now());
    let first = b.get(id);
    assert!(first >= S && first <= S + S / 2, "{first:?}");
    let mut prev = first;
    for _ in 0..3 {
        b.next(id, tc.now());
        let cur = b.get(id);
        // delay = 2*prev + jitter(prev), jitter < 0.5*prev.
        assert!(
            cur >= prev * 2 && cur <= prev * 2 + prev / 2,
            "{prev:?} {cur:?}"
        );
        prev = cur;
    }
}

#[test]
fn urlbackoff_flowcontrol_alternate_has_expired_func() {
    let id = "_idAlt";
    let tc = FakeClock::default();
    let mut b = Backoff::with_clock(Arc::new(tc.clone()), S, 10 * S, 0.0);
    // Expire as soon as the maximum duration has passed (not 2x).
    b.has_expired_func = Some(Box::new(|ev, last, max| ev.duration_since(last) > max));
    b.next(id, tc.now());
    b.next(id, tc.now());
    assert_eq!(b.get(id), 2 * S);
    tc.step(11 * S);
    b.next(id, tc.now());
    assert_eq!(b.get(id), S, "backoff restarted after the custom expiry");
}
