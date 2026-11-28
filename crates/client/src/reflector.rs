//! List+watch reflector with resourceVersion resume and an in-memory store.
//!
//! Upstream: `k8s.io/client-go/tools/cache` (Reflector + ThreadSafeStore),
//! simplified: no DeltaFIFO — a keyed store plus a broadcast event channel.
//!
//! The reflector is generic over a [`ListWatch`] trait so unit tests inject a
//! scripted mock; the production impl ([`ApiListWatch`]) wraps
//! [`ApiClient`] + [`watch_stream`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::stream::BoxStream;
use futures::StreamExt;
use serde::de::DeserializeOwned;
use tokio::sync::broadcast;

use crate::api_status::{is_expired_error, is_too_large_resource_version};
use crate::http::{ApiClient, GetError, KubernetesList};
use crate::pager::{ListOptions, ListPage, ListPager};
use crate::watch::{watch_stream, WatchEvent};

/// One watch event paired with the resourceVersion observed on its object
/// (`None` for an event whose object carries no `metadata.resourceVersion`).
pub type WatchItem<T> = Result<(WatchEvent<T>, Option<String>)>;

/// List+watch source. `list` returns `(items, listResourceVersion)`.
///
/// `watch` opens a session from `rv` and returns a **stream** that yields
/// events as they arrive, each paired with the object's resourceVersion. A
/// Kubernetes watch is long-lived — it does not deliver a finite batch and
/// then return — so the reflector MUST consume events incrementally off this
/// stream. (The previous batch-returning shape blocked forever against a real
/// api-server: it accumulated events and only returned once the never-ending
/// stream closed, so the store was never updated past the initial list.)
/// The stream ends when the server closes the watch (timeout / disconnect);
/// the reflector's `run` loop then reconnects from the last held rv.
#[async_trait::async_trait]
pub trait ListWatch<T>: Send + Sync {
    async fn list(&self) -> Result<(Vec<T>, String)>;

    /// The reflector's `list` (reflector.go:587-): list at `resource_version`
    /// ("" = consistent read, "0" = any, else not older than) paging with
    /// `page_size` (`None` = the pager default, `Some(0)` = no paging).
    /// Returns the items, the list resourceVersion and whether the result was
    /// paginated. The default ignores the request and calls
    /// [`ListWatch::list`], for list-watchers that do not page.
    async fn list_from(
        &self,
        _resource_version: &str,
        _page_size: Option<i64>,
    ) -> Result<(Vec<T>, String, bool)> {
        let (items, rv) = self.list().await?;
        Ok((items, rv, false))
    }
    async fn watch<'a>(&'a self, rv: Option<String>) -> Result<BoxStream<'a, WatchItem<T>>>;
}

/// Store mutation emitted to subscribers (bookmarks are not emitted).
#[derive(Clone, Debug)]
pub enum StoreEvent<T> {
    Added(T),
    Modified(T),
    Deleted(T),
}

/// Read view over the reflector's keyed store. `get` clones.
pub struct Store<T> {
    inner: Arc<RwLock<HashMap<String, T>>>,
}

impl<T: Clone> Store<T> {
    pub fn get(&self, key: &str) -> Option<T> {
        self.inner.read().unwrap().get(key).cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    /// Snapshot of all items.
    pub fn items(&self) -> Vec<T> {
        self.inner.read().unwrap().values().cloned().collect()
    }
}

pub struct Reflector<T, K: Fn(&T) -> String> {
    lw: Arc<dyn ListWatch<T>>,
    key_fn: K,
    store: Arc<RwLock<HashMap<String, T>>>,
    tx: broadcast::Sender<StoreEvent<T>>,
    last_rv: RwLock<Option<String>>,
    /// Set once the initial list has populated the store
    /// (`sharedIndexInformer.HasSynced`).
    synced: AtomicBool,
    /// `lastSyncResourceVersion`: the rv of the last list or watch event. Not
    /// cleared by a re-list, unlike `last_rv` (which gates whether to list).
    last_sync_rv: RwLock<String>,
    /// `isLastSyncResourceVersionUnavailable`.
    last_sync_rv_unavailable: AtomicBool,
    /// `paginatedResult`: the initial RV="0" list came back paginated.
    paginated_result: AtomicBool,
}

impl<T, K> Reflector<T, K>
where
    T: Clone + Send + Sync + 'static,
    K: Fn(&T) -> String,
{
    pub fn new(lw: Arc<dyn ListWatch<T>>, key_fn: K) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            lw,
            key_fn,
            store: Arc::new(RwLock::new(HashMap::new())),
            tx,
            last_rv: RwLock::new(None),
            synced: AtomicBool::new(false),
            last_sync_rv: RwLock::new(String::new()),
            last_sync_rv_unavailable: AtomicBool::new(false),
            paginated_result: AtomicBool::new(false),
        }
    }

    /// `relistResourceVersion` (reflector.go:1014-1030).
    fn relist_resource_version(&self) -> String {
        if self.last_sync_rv_unavailable.load(Ordering::SeqCst) {
            // Paginated list requests skip the watch cache at an unavailable
            // rv, so ask for a consistent read from the latest.
            return String::new();
        }
        let rv = self.last_sync_rv.read().unwrap();
        if rv.is_empty() {
            // The initial list uses "0" so the watch cache can serve it.
            return "0".to_string();
        }
        rv.clone()
    }

    /// The page-size selection of `list` (reflector.go:610-633).
    fn list_page_size(&self, resource_version: &str) -> Option<i64> {
        if self.paginated_result.load(Ordering::SeqCst) {
            // Paged initially: this resource and server honour paging
            // (watch cache probably off); keep the pager default.
            None
        } else if !resource_version.is_empty() && resource_version != "0" {
            // Not asked to paginate: with an rv we can list from the watch
            // cache, which it only does when Limit is unset.
            Some(0)
        } else {
            None
        }
    }

    fn set_last_sync_resource_version(&self, rv: &str) {
        *self.last_sync_rv.write().unwrap() = rv.to_string();
    }

    /// `HasSynced` (client-go `shared_informer.go:588`): true once the initial
    /// list is in the store. Stays true across later re-lists.
    pub fn has_synced(&self) -> bool {
        self.synced.load(Ordering::SeqCst)
    }

    /// `WaitForCacheSync` (client-go `tools/cache/shared_informer.go`, polling
    /// `HasSynced` every 100ms): resolves once the initial list is in the store.
    pub async fn wait_for_cache_sync(&self) {
        while !self.has_synced() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Read view over the current store contents.
    pub fn store(&self) -> Store<T> {
        Store {
            inner: Arc::clone(&self.store),
        }
    }

    /// Subscribe to store mutations. Initial-list population does not emit;
    /// consumers needing the initial state read `store()` after the first
    /// sync.
    pub fn subscribe(&self) -> broadcast::Receiver<StoreEvent<T>> {
        self.tx.subscribe()
    }

    /// `Reflector.list` (reflector.go:587-): list at `relistResourceVersion`
    /// with the selected page size; an Expired / too-large-rv failure marks
    /// the last sync rv unavailable and retries at rv="".
    async fn list(&self) -> Result<(Vec<T>, String)> {
        let rv = self.relist_resource_version();
        let page_size = self.list_page_size(&rv);
        let mut result = self.lw.list_from(&rv, page_size).await;
        if let Err(e) = &result {
            if is_expired_error(e) || is_too_large_resource_version(e) {
                self.last_sync_rv_unavailable.store(true, Ordering::SeqCst);
                result = self
                    .lw
                    .list_from(&self.relist_resource_version(), page_size)
                    .await;
            }
        }
        let (items, list_rv, paginated) = result?;
        // Only the initial list (rv="0") says whether the watch cache is on
        // (reflector.go:658-672).
        if rv == "0" && paginated {
            self.paginated_result.store(true, Ordering::SeqCst);
        }
        self.last_sync_rv_unavailable.store(false, Ordering::SeqCst);
        Ok((items, list_rv))
    }

    /// One list (only when no resourceVersion is held yet) + one watch
    /// session, applying every event to the store **as it streams in**. Returns
    /// when the watch stream ends (server timeout / disconnect); the caller's
    /// `run` loop reconnects. An error mid-stream (e.g. the api-server's
    /// `Expired` envelope) propagates so `run` can decide to re-list.
    pub async fn sync_once(&self) -> Result<()> {
        if self.last_rv.read().unwrap().is_none() {
            let (items, rv) = self.list().await.context("reflector list")?;
            let mut store = self.store.write().unwrap();
            store.clear();
            for item in items {
                store.insert((self.key_fn)(&item), item);
            }
            drop(store);
            self.set_last_sync_resource_version(&rv);
            *self.last_rv.write().unwrap() = Some(rv);
            self.synced.store(true, Ordering::SeqCst);
        }

        let rv = self.last_rv.read().unwrap().clone();
        let mut stream = self.lw.watch(rv).await.context("reflector watch")?;
        while let Some(item) = stream.next().await {
            let (event, obj_rv) = item.context("reflector watch event")?;
            match event {
                WatchEvent::Added(obj) => {
                    self.store
                        .write()
                        .unwrap()
                        .insert((self.key_fn)(&obj), obj.clone());
                    let _ = self.tx.send(StoreEvent::Added(obj));
                }
                WatchEvent::Modified(obj) => {
                    self.store
                        .write()
                        .unwrap()
                        .insert((self.key_fn)(&obj), obj.clone());
                    let _ = self.tx.send(StoreEvent::Modified(obj));
                }
                WatchEvent::Deleted(obj) => {
                    self.store.write().unwrap().remove(&(self.key_fn)(&obj));
                    let _ = self.tx.send(StoreEvent::Deleted(obj));
                }
                // Bookmark: rv progress only — no store change, no emit.
                WatchEvent::Bookmark(_) => {}
            }
            // Advance the held rv after every event so a reconnect resumes
            // from the last thing we actually applied.
            if let Some(rv) = &obj_rv {
                self.set_last_sync_resource_version(rv);
            }
            if obj_rv.is_some() {
                *self.last_rv.write().unwrap() = obj_rv;
            }
        }
        Ok(())
    }

    /// Forget the held watch rv so the next [`Reflector::sync_once`] lists
    /// again (what `run` does after any error). The last sync rv is kept: the
    /// relist uses it (`relistResourceVersion`).
    pub fn reset_for_relist(&self) {
        *self.last_rv.write().unwrap() = None;
    }

    /// Run forever: list+watch with exponential backoff (1s → 30s, reset on
    /// success). ANY error clears the held rv so the next cycle RE-LISTS, which
    /// mirrors upstream client-go (`ListAndWatch` always begins with a fresh
    /// list after it returns). A graceful watch close returns `Ok` and keeps
    /// the rv, so the efficient resume-from-rv path still applies to the normal
    /// case; only real failures (watch failed to establish, mid-stream error,
    /// or a 410-Gone/`Expired` compacted rv) trigger the re-list.
    ///
    /// Keeping the rv on a *failing* watch was a latent stall: if the watch
    /// could not be sustained (e.g. a CPU-starved client on a loaded node whose
    /// h2 watch to the api-server keeps dropping), `sync_once` skipped the list
    /// and only re-watched, so the store froze at the last successful list.
    /// Any store consumer that never re-lists on its own — notably the API-mode
    /// scheduler, which schedules off the reflector store — then never observed
    /// objects created after that point.
    pub async fn run(&self) {
        let mut backoff = Duration::from_secs(1);
        loop {
            match self.sync_once().await {
                Ok(()) => {
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    let text = format!("{e:#}");
                    // `isExpiredError` / `isTooLargeResourceVersionError`
                    // (tools/cache/reflector.go:1051-1089), by the typed
                    // status rather than the message text.
                    if is_expired_error(&e) || is_too_large_resource_version(&e) {
                        tracing::warn!("reflector: resourceVersion expired, re-listing: {text}");
                    } else {
                        tracing::warn!("reflector: sync failed (will re-list + retry): {text}");
                    }
                    // Clear the held rv so the next cycle re-lists and refreshes
                    // the store, rather than resuming a watch that may never
                    // deliver the objects created since the last good list.
                    self.reset_for_relist();
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }
}

/// Production [`ListWatch`] over a live api-server: `list` GETs `path` as a
/// [`KubernetesList`]; `watch` runs [`watch_stream`] until the connection
/// ends, tracking the last `metadata.resourceVersion` observed.
pub struct ApiListWatch {
    client: Arc<ApiClient>,
    /// Resource collection path, e.g. `/api/v1/pods`.
    path: String,
}

impl ApiListWatch {
    pub fn new(client: Arc<ApiClient>, path: impl Into<String>) -> Self {
        Self {
            client,
            path: path.into(),
        }
    }
}

/// `limit` / `continue` query parameters for one page request.
fn page_path(path: &str, opts: &ListOptions) -> String {
    let mut params = Vec::new();
    if opts.limit > 0 {
        params.push(format!("limit={}", opts.limit));
    }
    if !opts.continue_token.is_empty() {
        params.push(format!("continue={}", encode_query(&opts.continue_token)));
    }
    if !opts.resource_version.is_empty() {
        params.push(format!(
            "resourceVersion={}",
            encode_query(&opts.resource_version)
        ));
    }
    if params.is_empty() {
        return path.to_string();
    }
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}{}", params.join("&"))
}

fn encode_query(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[async_trait::async_trait]
impl<T: DeserializeOwned + Send + Sync + 'static> ListWatch<T> for ApiListWatch {
    async fn list(&self) -> Result<(Vec<T>, String)> {
        let (items, rv, _) = self.list_from("", None).await?;
        Ok((items, rv))
    }

    async fn list_from(
        &self,
        resource_version: &str,
        page_size: Option<i64>,
    ) -> Result<(Vec<T>, String, bool)> {
        // reflector.go list(): `pager.New(...)` over the list-watcher, so the
        // initial list is fetched in `limit`/`continue` chunks (default page
        // size 500, Expired continuation falls back to a full list).
        let mut pager = ListPager::new(|opts: ListOptions| async move {
            let list: KubernetesList<T> = self
                .client
                .get(&page_path(&self.path, &opts))
                .await
                .map_err(|e| match e {
                    // keep the typed Status so the pager sees `Expired`
                    GetError::NotFound(s) => anyhow::Error::from(s),
                    GetError::Other(e) => e,
                })?;
            let meta = list.metadata;
            Ok(ListPage {
                items: list.items,
                resource_version: meta
                    .as_ref()
                    .and_then(|m| m.resource_version.clone())
                    .unwrap_or_default(),
                continue_token: meta.and_then(|m| m.continue_token).unwrap_or_default(),
            })
        });
        if let Some(size) = page_size {
            pager.page_size = size;
        }
        let (list, paginated) = pager
            .list(ListOptions {
                resource_version: resource_version.to_string(),
                ..Default::default()
            })
            .await
            .with_context(|| format!("list {} failed", self.path))?;
        let rv = if list.resource_version.is_empty() {
            "0".to_string()
        } else {
            list.resource_version
        };
        Ok((list.items, rv, paginated))
    }

    async fn watch<'a>(&'a self, rv: Option<String>) -> Result<BoxStream<'a, WatchItem<T>>> {
        // Stream raw JSON values so each event's metadata.resourceVersion can
        // be extracted, then decode the object into T. Events are mapped
        // lazily and yielded one at a time — the reflector applies each to its
        // store as it arrives, so a never-ending watch never blocks.
        //
        // Bookmark frames are dropped (their payload is not a full object, only
        // an rv marker). The reflector still advances its rv on every real
        // Added/Modified/Deleted event, so dropping bookmarks only forgoes rv
        // progress during fully-idle windows — acceptable here.
        let raw =
            watch_stream::<serde_json::Value>(&self.client, &self.path, rv.as_deref()).await?;
        let mapped = raw.filter_map(|item| async move {
            let event = match item {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            let value = match &event {
                WatchEvent::Added(v)
                | WatchEvent::Modified(v)
                | WatchEvent::Deleted(v)
                | WatchEvent::Bookmark(v) => v.clone(),
            };
            if matches!(event, WatchEvent::Bookmark(_)) {
                return None; // rv-only marker, nothing to apply
            }
            let obj_rv = value
                .get("metadata")
                .and_then(|m| m.get("resourceVersion"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let typed: T = match serde_json::from_value(value).context("decoding watch object") {
                Ok(t) => t,
                Err(e) => return Some(Err(e)),
            };
            let out = match event {
                WatchEvent::Added(_) => WatchEvent::Added(typed),
                WatchEvent::Modified(_) => WatchEvent::Modified(typed),
                WatchEvent::Deleted(_) => WatchEvent::Deleted(typed),
                WatchEvent::Bookmark(_) => unreachable!("handled above"),
            };
            Some(Ok((out, obj_rv)))
        });
        Ok(Box::pin(mapped))
    }
}

#[cfg(test)]
mod pager_wiring_tests {
    use super::*;

    #[test]
    fn pager_page_path_appends_limit_and_continue() {
        let o = ListOptions {
            limit: 500,
            continue_token: "a b/c".into(),
            ..Default::default()
        };
        assert_eq!(
            page_path("/api/v1/pods", &o),
            "/api/v1/pods?limit=500&continue=a%20b%2Fc"
        );
        assert_eq!(
            page_path(
                "/api/v1/pods?labelSelector=a%3Db",
                &ListOptions {
                    limit: 1,
                    ..Default::default()
                }
            ),
            "/api/v1/pods?labelSelector=a%3Db&limit=1"
        );
        assert_eq!(page_path("/x", &ListOptions::default()), "/x");
        assert_eq!(
            page_path(
                "/x",
                &ListOptions {
                    resource_version: "0".into(),
                    limit: 5,
                    ..Default::default()
                }
            ),
            "/x?limit=5&resourceVersion=0"
        );
    }
}
