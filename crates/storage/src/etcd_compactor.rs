//! The etcd compactor.
//!
//! Port of `staging/src/k8s.io/apiserver/pkg/storage/etcd3/compact.go`
//! (release-1.35): `StartCompactorPerEndpoint` (:52), `NewCompactor` (:83),
//! `runCompactLoop` (:153, the lease-by-CAS protocol on `compact_rev_key`),
//! `Compact` (:219), `UpdateCompactRevision` (:139), `runWatchLoop` (:263,
//! enabled by `ListFromCacheSnapshot`, Beta and default on since 1.34),
//! `getCompactRev` and `fromWatchResponse`. The default interval is 5 minutes
//! (`storagebackend/config.go` `DefaultCompactInterval`); the factory hands
//! `Transport` and `CompactionInterval` to `startCompactorOnce`
//! (`storagebackend/factory/etcd3.go:427`).
//!
//! The etcd calls sit behind [`CompactBackend`] so the protocol is testable
//! without an etcd; [`EtcdCompactBackend`] is the real client.
//!
//! Rust-specific, not in upstream: [`start_compactor_per_endpoint`] ignores a
//! registered compactor whose tasks have all ended (their runtime was dropped),
//! because Go goroutines outlive the caller and Tokio tasks do not.

use async_trait::async_trait;
use etcd_client::{Client, Compare, CompareOp, TxnOp, TxnOpResponse, WatchOptions};
use futures::stream::BoxStream;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tracing::{debug, error};

/// `compactRevKey`.
pub const COMPACT_REV_KEY: &str = "compact_rev_key";
/// `storagebackend.DefaultCompactInterval` (config.go:38).
pub const DEFAULT_COMPACT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// What the `Compact` transaction returned.
#[derive(Debug, Clone)]
pub struct CompactTxn {
    /// `resp.Succeeded`.
    pub succeeded: bool,
    /// `resp.Header.Revision`.
    pub revision: i64,
    /// On a failed compare: the version and value of `compact_rev_key`
    /// (`resp.Responses[0].GetResponseRange().Kvs[0]`).
    pub else_kv: Option<(i64, Vec<u8>)>,
}

/// The etcd operations the compactor uses.
#[async_trait]
pub trait CompactBackend: Send + Sync + 'static {
    /// `If(Version(compactRevKey) = expect).Then(Put(compactRevKey, rev)).Else(Get(compactRevKey))`.
    async fn txn(&self, expect_version: i64, rev: i64) -> Result<CompactTxn, String>;
    /// `client.Compact(ctx, rev)`.
    async fn compact(&self, rev: i64) -> Result<(), String>;
    /// `client.Get(ctx, compactRevKey)`: the value (if any) and the header revision.
    async fn get_compact_key(&self) -> Result<(Option<Vec<u8>>, i64), String>;
    /// `client.Watch(ctx, compactRevKey, WithRev(rev))`. Each item is one
    /// response: the value of its last event, `None` when it has no events.
    async fn watch_compact_key(
        &self,
        from_revision: i64,
    ) -> Result<BoxStream<'static, Result<Option<Vec<u8>>, String>>, String>;
    /// `client.Endpoints()`.
    fn endpoints(&self) -> Vec<String>;
}

/// The values `Compact` returns, error included (the loop assigns all four
/// even when `err` is set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactOutcome {
    pub current_version: i64,
    pub current_rev: i64,
    pub compact_rev: i64,
    pub err: Option<String>,
}

/// `Compact` (compact.go:219): compacts the store and returns the current
/// compact time and global revision. A lost CAS is not an error.
pub async fn compact(
    backend: &dyn CompactBackend,
    expect_version: i64,
    rev: i64,
) -> CompactOutcome {
    let resp = match backend.txn(expect_version, rev).await {
        Ok(r) => r,
        Err(e) => {
            return CompactOutcome {
                current_version: expect_version,
                current_rev: rev,
                compact_rev: 0,
                err: Some(e),
            }
        }
    };
    let current_rev = resp.revision;
    if !resp.succeeded {
        let Some((version, value)) = resp.else_kv else {
            return CompactOutcome {
                current_version: expect_version,
                current_rev,
                compact_rev: 0,
                err: Some("compare failed without a compact_rev_key".into()),
            };
        };
        let compact_rev = parse_rev(&value).unwrap_or(0);
        return CompactOutcome {
            current_version: version,
            current_rev,
            compact_rev,
            err: None,
        };
    }
    let current_version = expect_version + 1;
    if rev == 0 {
        // We don't compact on bootstrap.
        return CompactOutcome {
            current_version,
            current_rev,
            compact_rev: 0,
            err: None,
        };
    }
    if let Err(e) = backend.compact(rev).await {
        return CompactOutcome {
            current_version,
            current_rev,
            compact_rev: 0,
            err: Some(e),
        };
    }
    debug!(
        "etcd: compacted rev ({rev}), endpoints ({:?})",
        backend.endpoints()
    );
    CompactOutcome {
        current_version,
        current_rev,
        compact_rev: rev,
        err: None,
    }
}

fn parse_rev(value: &[u8]) -> Result<i64, String> {
    std::str::from_utf8(value)
        .map_err(|e| e.to_string())?
        .parse::<i64>()
        .map_err(|e| e.to_string())
}

/// A running compactor. Dropping it does not stop it; call [`Compactor::stop`].
pub struct Compactor {
    compact_revision: Arc<AtomicI64>,
    stop_tx: tokio::sync::watch::Sender<bool>,
    handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    on_close: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Compactor {
    /// `NewCompactor` (compact.go:83). `interval == 0` disables the compact
    /// loop. `watch_loop` is the `ListFromCacheSnapshot` gate.
    pub fn new(
        backend: Arc<dyn CompactBackend>,
        interval: Duration,
        watch_loop: bool,
        on_close: Option<Box<dyn FnOnce() + Send>>,
    ) -> Arc<Self> {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let c = Arc::new(Self {
            compact_revision: Arc::new(AtomicI64::new(0)),
            stop_tx,
            handles: Mutex::new(Vec::new()),
            on_close: Mutex::new(on_close),
        });
        let mut handles = Vec::new();
        if !interval.is_zero() {
            handles.push(tokio::spawn(run_compact_loop(
                backend.clone(),
                c.compact_revision.clone(),
                interval,
                stop_rx.clone(),
            )));
        }
        if watch_loop {
            handles.push(tokio::spawn(run_watch_loop(
                backend,
                c.compact_revision.clone(),
                stop_rx,
            )));
        }
        *c.handles.lock().unwrap() = handles;
        c
    }

    /// `CompactRevision()`.
    pub fn compact_revision(&self) -> i64 {
        self.compact_revision.load(Ordering::Relaxed)
    }

    /// The shared cell behind [`Compactor::compact_revision`], for storages that
    /// answer "is this revision compacted" from memory.
    pub fn compact_revision_handle(&self) -> Arc<AtomicI64> {
        self.compact_revision.clone()
    }

    /// `UpdateCompactRevision`.
    pub fn update_compact_revision(&self, rev: i64) {
        update_compact_revision(&self.compact_revision, rev);
    }

    /// `Stop()`: runs `onClose` once, signals the loops and waits for them.
    pub async fn stop(&self) {
        let on_close = self.on_close.lock().unwrap().take();
        if let Some(f) = on_close {
            f();
        }
        let _ = self.stop_tx.send(true);
        let handles = std::mem::take(&mut *self.handles.lock().unwrap());
        for h in handles {
            let _ = h.await;
        }
    }

    fn is_dead(&self) -> bool {
        let h = self.handles.lock().unwrap();
        !h.is_empty() && h.iter().all(|t| t.is_finished())
    }
}

/// `UpdateCompactRevision`: `rev == 0` is ignored, otherwise a max.
fn update_compact_revision(cell: &AtomicI64, rev: i64) {
    if rev == 0 {
        return;
    }
    cell.fetch_max(rev, Ordering::Relaxed);
}

/// `runCompactLoop` (compact.go:153).
async fn run_compact_loop(
    backend: Arc<dyn CompactBackend>,
    compact_revision: Arc<AtomicI64>,
    interval: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let (mut compact_time, mut rev) = (0i64, 0i64);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = stop.changed() => return,
        }
        let out = compact(backend.as_ref(), compact_time, rev).await;
        compact_time = out.current_version;
        rev = out.current_rev;
        if let Some(e) = out.err {
            error!(
                "etcd: endpoint ({:?}) compact failed: {e}",
                backend.endpoints()
            );
            continue;
        }
        if out.compact_rev != 0 {
            update_compact_revision(&compact_revision, out.compact_rev);
        }
    }
}

/// `getCompactRev`: `(compactRev, currentRev)`.
async fn get_compact_rev(backend: &dyn CompactBackend) -> Result<(i64, i64), String> {
    let (value, current_rev) = backend
        .get_compact_key()
        .await
        .map_err(|e| format!("get \"{COMPACT_REV_KEY}\" failed: {e}"))?;
    let compact_rev = match value {
        Some(v) => parse_rev(&v).map_err(|e| format!("failed to parse compact revision: {e}"))?,
        None => 0,
    };
    Ok((compact_rev, current_rev))
}

/// `runWatchLoop` (compact.go:263).
async fn run_watch_loop(
    backend: Arc<dyn CompactBackend>,
    compact_revision: Arc<AtomicI64>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = stop.changed() => return,
        }
        let (compact_rev, current_rev) = match get_compact_rev(backend.as_ref()).await {
            Ok(v) => v,
            Err(e) => {
                error!("etcd: endpoint ({:?}): {e}", backend.endpoints());
                continue;
            }
        };
        update_compact_revision(&compact_revision, compact_rev);
        let mut watch = match backend.watch_compact_key(current_rev).await {
            Ok(w) => w,
            Err(e) => {
                error!("etcd: endpoint ({:?}): {e}", backend.endpoints());
                continue;
            }
        };
        loop {
            let item = tokio::select! {
                i = watch.next() => i,
                _ = stop.changed() => return,
            };
            let Some(item) = item else { break };
            // fromWatchResponse.
            let rev = match item {
                Err(e) => Err(e),
                Ok(None) => Ok(0),
                Ok(Some(v)) => {
                    parse_rev(&v).map_err(|e| format!("failed to parse compact revision: {e}"))
                }
            };
            match rev {
                Ok(r) => update_compact_revision(&compact_revision, r),
                Err(e) => error!("etcd: endpoint ({:?}): {e}", backend.endpoints()),
            }
        }
    }
}

fn registry() -> &'static Mutex<HashMap<String, Arc<Compactor>>> {
    static R: OnceLock<Mutex<HashMap<String, Arc<Compactor>>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// `StartCompactorPerEndpoint` (compact.go:52): one compactor per client
/// endpoint in the process; a second call on the same endpoints returns the
/// first. The watch loop is on (`ListFromCacheSnapshot` default).
pub fn start_compactor_per_endpoint(
    backend: Arc<dyn CompactBackend>,
    interval: Duration,
) -> Arc<Compactor> {
    let endpoints = backend.endpoints();
    let mut map = registry().lock().unwrap();
    for ep in &endpoints {
        if let Some(c) = map.get(ep) {
            if !c.is_dead() {
                debug!("compactor already exists for endpoints {endpoints:?}");
                return c.clone();
            }
        }
    }
    let eps = endpoints.clone();
    let c = Compactor::new(
        backend,
        interval,
        true,
        Some(Box::new(move || {
            let mut map = registry().lock().unwrap();
            for ep in &eps {
                map.remove(ep);
            }
        })),
    );
    for ep in endpoints {
        map.insert(ep, c.clone());
    }
    c
}

/// [`CompactBackend`] over a real etcd client.
pub struct EtcdCompactBackend {
    client: Client,
    endpoints: Vec<String>,
}

impl EtcdCompactBackend {
    pub fn new(client: Client, endpoints: Vec<String>) -> Self {
        Self { client, endpoints }
    }
}

#[async_trait]
impl CompactBackend for EtcdCompactBackend {
    async fn txn(&self, expect_version: i64, rev: i64) -> Result<CompactTxn, String> {
        let txn = etcd_client::Txn::new()
            .when(vec![Compare::version(
                COMPACT_REV_KEY,
                CompareOp::Equal,
                expect_version,
            )])
            .and_then(vec![TxnOp::put(COMPACT_REV_KEY, rev.to_string(), None)])
            .or_else(vec![TxnOp::get(COMPACT_REV_KEY, None)]);
        let resp = crate::etcd::kv_client(&self.client)
            .txn(txn)
            .await
            .map_err(|e| e.to_string())?;
        let else_kv = resp.op_responses().into_iter().find_map(|r| match r {
            TxnOpResponse::Get(g) => g
                .kvs()
                .first()
                .map(|kv| (kv.version(), kv.value().to_vec())),
            _ => None,
        });
        Ok(CompactTxn {
            succeeded: resp.succeeded(),
            revision: resp.header().map(|h| h.revision()).unwrap_or(0),
            else_kv,
        })
    }

    async fn compact(&self, rev: i64) -> Result<(), String> {
        crate::etcd::kv_client(&self.client)
            .compact(rev, None)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn get_compact_key(&self) -> Result<(Option<Vec<u8>>, i64), String> {
        let resp = crate::etcd::kv_client(&self.client)
            .get(COMPACT_REV_KEY, None)
            .await
            .map_err(|e| e.to_string())?;
        let header = resp.header().ok_or("empty response header")?;
        Ok((
            resp.kvs().first().map(|kv| kv.value().to_vec()),
            header.revision(),
        ))
    }

    async fn watch_compact_key(
        &self,
        from_revision: i64,
    ) -> Result<BoxStream<'static, Result<Option<Vec<u8>>, String>>, String> {
        let (watcher, stream) = crate::etcd::watch_client(&self.client)
            .watch(
                COMPACT_REV_KEY,
                Some(WatchOptions::new().with_start_revision(from_revision)),
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(stream
            .map(move |r| {
                let _ = &watcher; // dropping the watcher ends the watch
                match r {
                    Err(e) => Err(e.to_string()),
                    Ok(resp) => Ok(resp
                        .events()
                        .last()
                        .and_then(|ev| ev.kv())
                        .map(|kv| kv.value().to_vec())),
                }
            })
            .boxed())
    }

    fn endpoints(&self) -> Vec<String> {
        self.endpoints.clone()
    }
}
