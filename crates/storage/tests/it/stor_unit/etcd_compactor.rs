//! Ported from `etcd3/compact_test.go` (TestCompact, TestCompactIntervalZero,
//! TestCompactConflict) against a fake etcd that keeps etcd's revision,
//! per-key version and compaction semantics (`rev <= compacted` is
//! `ErrCompacted`), plus the `runWatchLoop` and per-endpoint registry paths.
//! The upstream tests step a fake clock; here tokio's paused clock plays it.
use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use kubernetes_rs_storage::etcd_compactor::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct State {
    rev: i64,
    key: Option<(i64, Vec<u8>)>, // (version, value)
    compacted: i64,
    watchers: Vec<tokio::sync::mpsc::UnboundedSender<Option<Vec<u8>>>>,
}

struct FakeEtcd {
    st: Mutex<State>,
    txns: AtomicUsize,
    endpoints: Vec<String>,
}

impl FakeEtcd {
    fn new(endpoint: &str) -> Arc<Self> {
        Arc::new(Self {
            st: Mutex::new(State {
                rev: 1,
                key: None,
                compacted: 0,
                watchers: vec![],
            }),
            txns: AtomicUsize::new(0),
            endpoints: vec![endpoint.to_string()],
        })
    }
    /// `client.Put` of a data key: returns the new header revision.
    fn put_data(&self) -> i64 {
        let mut s = self.st.lock().unwrap();
        s.rev += 1;
        s.rev
    }
    fn is_compacted(&self, rev: i64) -> bool {
        rev <= self.st.lock().unwrap().compacted
    }
}

#[async_trait]
impl CompactBackend for FakeEtcd {
    async fn txn(&self, expect: i64, rev: i64) -> Result<CompactTxn, String> {
        self.txns.fetch_add(1, Ordering::SeqCst);
        let mut s = self.st.lock().unwrap();
        let version = s.key.as_ref().map_or(0, |k| k.0);
        if version == expect {
            s.rev += 1;
            let v = rev.to_string().into_bytes();
            s.key = Some((version + 1, v.clone()));
            s.watchers.retain(|w| w.send(Some(v.clone())).is_ok());
            Ok(CompactTxn {
                succeeded: true,
                revision: s.rev,
                else_kv: None,
            })
        } else {
            Ok(CompactTxn {
                succeeded: false,
                revision: s.rev,
                else_kv: s.key.clone(),
            })
        }
    }
    async fn compact(&self, rev: i64) -> Result<(), String> {
        self.st.lock().unwrap().compacted = rev;
        Ok(())
    }
    async fn get_compact_key(&self) -> Result<(Option<Vec<u8>>, i64), String> {
        let s = self.st.lock().unwrap();
        Ok((s.key.as_ref().map(|k| k.1.clone()), s.rev))
    }
    async fn watch_compact_key(
        &self,
        _from: i64,
    ) -> Result<BoxStream<'static, Result<Option<Vec<u8>>, String>>, String> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.st.lock().unwrap().watchers.push(tx);
        Ok(tokio_stream_from(rx).boxed())
    }
    fn endpoints(&self) -> Vec<String> {
        self.endpoints.clone()
    }
}

fn tokio_stream_from(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Option<Vec<u8>>>,
) -> impl futures::Stream<Item = Result<Option<Vec<u8>>, String>> {
    async_stream::stream! {
        while let Some(v) = rx.recv().await {
            yield Ok(v);
        }
    }
}

/// Lets spawned tasks run after the paused clock moved.
async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

async fn step(d: Duration) {
    tokio::time::advance(d).await;
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn etcd_compactor_compact() {
    let etcd = FakeEtcd::new("fake-compact");
    let c = Compactor::new(etcd.clone(), Duration::from_secs(60), false, None);
    settle().await;

    // First compaction cycle saves revision before first write.
    step(Duration::from_secs(60)).await;
    assert_eq!(c.compact_revision(), 0);

    let put = etcd.put_data();
    assert!(!etcd.is_compacted(put));

    // Second cycle compacts before the first write.
    step(Duration::from_secs(60)).await;
    assert!(!etcd.is_compacted(put));
    assert_eq!(c.compact_revision(), put - 1);

    let put1 = etcd.put_data();
    assert!(!etcd.is_compacted(put1));

    // Third cycle compacts the revision after the first write.
    step(Duration::from_secs(60)).await;
    assert!(etcd.is_compacted(put));
    assert_eq!(c.compact_revision(), put + 1);
    assert!(!etcd.is_compacted(put1));

    // Fourth cycle compacts the second write.
    step(Duration::from_secs(60)).await;
    assert!(etcd.is_compacted(put));
    assert!(etcd.is_compacted(put1));
    assert_eq!(c.compact_revision(), put1 + 1);
    c.stop().await;
}

#[tokio::test(start_paused = true)]
async fn etcd_compactor_interval_zero() {
    let etcd = FakeEtcd::new("fake-zero");
    let c = Compactor::new(etcd.clone(), Duration::ZERO, false, None);
    settle().await;
    step(Duration::from_secs(60)).await;
    // Compact loop is disabled: nothing ever touched etcd.
    assert_eq!(etcd.txns.load(Ordering::SeqCst), 0);
    c.stop().await;
}

#[tokio::test]
async fn etcd_compactor_conflict() {
    let etcd = FakeEtcd::new("fake-conflict");
    let put = etcd.put_data();
    let mut want = put;

    // First compact on time 0 succeeds.
    let a = compact(etcd.as_ref(), 0, want).await;
    assert_eq!(a.compact_rev, want);
    assert_eq!(a.current_version, 1);
    let want_current = put + 1;
    assert_eq!(a.current_rev, want_current);

    // Second compact on time 0 fails the CAS: same time, same revision, the
    // already-compacted revision comes back, and it is not an error.
    let b = compact(etcd.as_ref(), 0, want + 1).await;
    assert_eq!(b.err, None);
    assert_eq!(b.compact_rev, want);
    assert_eq!(b.current_version, a.current_version);
    assert_eq!(b.current_rev, want_current);

    // Third compact on time 1 succeeds.
    let c = compact(etcd.as_ref(), 1, want + 1).await;
    want += 1;
    assert_eq!(c.compact_rev, want);
    assert_eq!(c.current_version, 2);
    assert_eq!(c.current_rev, want_current + 1);
}

#[tokio::test]
async fn etcd_compactor_no_compact_on_bootstrap() {
    let etcd = FakeEtcd::new("fake-bootstrap");
    let o = compact(etcd.as_ref(), 0, 0).await;
    assert_eq!((o.current_version, o.compact_rev, o.err), (1, 0, None));
    assert_eq!(etcd.st.lock().unwrap().compacted, 0);
}

#[tokio::test(start_paused = true)]
async fn etcd_compactor_watch_loop_follows_other_compactors() {
    let etcd = FakeEtcd::new("fake-watch");
    // Interval 0: only the watch loop runs (ListFromCacheSnapshot).
    let c = Compactor::new(etcd.clone(), Duration::ZERO, true, None);
    settle().await; // let the loop register its 1s sleep before the clock moves
    step(Duration::from_secs(1)).await;
    assert_eq!(c.compact_revision(), 0);

    // Another apiserver compacts; the watch delivers the new compact revision.
    let o = compact(etcd.as_ref(), 0, 7).await;
    assert_eq!(o.err, None);
    settle().await;
    let o = compact(etcd.as_ref(), 1, 9).await;
    assert_eq!(o.compact_rev, 9);
    settle().await;
    assert_eq!(c.compact_revision(), 9);

    // Never moves backwards, and 0 is ignored.
    c.update_compact_revision(3);
    c.update_compact_revision(0);
    assert_eq!(c.compact_revision(), 9);
    c.stop().await;
}

#[tokio::test(start_paused = true)]
async fn etcd_compactor_one_per_endpoint() {
    let etcd = FakeEtcd::new("fake-registry");
    let a = start_compactor_per_endpoint(etcd.clone(), Duration::from_secs(300));
    let b = start_compactor_per_endpoint(etcd.clone(), Duration::from_secs(300));
    assert!(Arc::ptr_eq(&a, &b));
    // Stop unregisters (onClose): the next start is a new compactor.
    a.stop().await;
    let c = start_compactor_per_endpoint(etcd, Duration::from_secs(300));
    assert!(!Arc::ptr_eq(&a, &c));
    c.stop().await;
}
