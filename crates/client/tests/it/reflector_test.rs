use futures::stream::BoxStream;
use kubernetes_rs_client::reflector::{ListWatch, Reflector, StoreEvent, WatchItem};
use kubernetes_rs_client::watch::WatchEvent;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
struct Obj {
    name: String,
    v: u64,
}

/// One scripted watch session: a sequence of (event, observed rv) the mock
/// yields one at a time, mirroring the real streaming `ListWatch::watch`.
type WatchSession = Vec<(WatchEvent<Obj>, Option<String>)>;

struct MockLw {
    // each watch() call pops the next scripted session and streams it
    batches: Mutex<Vec<WatchSession>>,
    list_result: (Vec<Obj>, String),
    watch_calls: Mutex<Vec<Option<String>>>, // recorded resourceVersions
}

#[async_trait::async_trait]
impl ListWatch<Obj> for MockLw {
    async fn list(&self) -> anyhow::Result<(Vec<Obj>, String)> {
        Ok(self.list_result.clone())
    }
    async fn watch<'a>(
        &'a self,
        rv: Option<String>,
    ) -> anyhow::Result<BoxStream<'a, WatchItem<Obj>>> {
        self.watch_calls.lock().unwrap().push(rv);
        let session = self.batches.lock().unwrap().remove(0);
        let items: Vec<WatchItem<Obj>> = session.into_iter().map(Ok).collect();
        Ok(Box::pin(futures::stream::iter(items)))
    }
}

fn key(o: &Obj) -> String {
    o.name.clone()
}

/// Mock whose `list` reads a shared, test-mutable source and whose `watch`
/// ALWAYS fails to establish (mirrors the real reqwest "error sending request"
/// seen when a CPU-starved co-located client can't sustain the watch to the
/// api-server). Records how many times `list` is called.
struct FailingWatchLw {
    source: Arc<Mutex<(Vec<Obj>, String)>>,
    list_calls: Arc<Mutex<usize>>,
}

#[async_trait::async_trait]
impl ListWatch<Obj> for FailingWatchLw {
    async fn list(&self) -> anyhow::Result<(Vec<Obj>, String)> {
        *self.list_calls.lock().unwrap() += 1;
        Ok(self.source.lock().unwrap().clone())
    }
    async fn watch<'a>(
        &'a self,
        _rv: Option<String>,
    ) -> anyhow::Result<BoxStream<'a, WatchItem<Obj>>> {
        // Watch never establishes — the reflector must recover by re-listing.
        anyhow::bail!("Failed to send GET request: error sending request")
    }
}

/// When the watch keeps failing to establish, the reflector's `run` loop must
/// keep RE-LISTING so objects created after the initial list still land in the
/// store. Regression test for the M2d 4-node scheduler stall: the reflector
/// used to keep `last_rv` on a (non-Expired) watch error, so `sync_once`
/// skipped the list and only re-watched — freezing the store at the startup
/// list, and the API-mode scheduler (which reads the reflector store) never
/// saw newly-created pods. Upstream client-go re-lists whenever ListAndWatch
/// returns an error.
#[tokio::test(start_paused = true)]
async fn relists_when_watch_keeps_failing_so_new_objects_surface() {
    let source = Arc::new(Mutex::new((
        vec![Obj {
            name: "a".into(),
            v: 1,
        }],
        "10".into(),
    )));
    let list_calls = Arc::new(Mutex::new(0usize));
    let lw = Arc::new(FailingWatchLw {
        source: source.clone(),
        list_calls: list_calls.clone(),
    });
    let r = Arc::new(Reflector::new(lw, key));

    let r_run = Arc::clone(&r);
    let handle = tokio::spawn(async move { r_run.run().await });

    // Let the initial list + first (failing) watch happen.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert!(
        r.store().get("a").is_some(),
        "initial list must populate the store"
    );

    // A new object appears AFTER the initial list (as the DNS/PHP pods did,
    // created after the scheduler started). Only a re-list can surface it,
    // because the watch never delivers events.
    {
        let mut src = source.lock().unwrap();
        src.0.push(Obj {
            name: "b".into(),
            v: 1,
        });
        src.1 = "11".into();
    }

    // Give the run loop time to cycle through its backoff and re-list.
    tokio::time::sleep(std::time::Duration::from_secs(90)).await;

    assert!(
        r.store().get("b").is_some(),
        "reflector must re-list after a failing watch so post-list objects appear \
         (regression: store frozen at initial list -> scheduler never sees new pods)"
    );
    assert!(
        *list_calls.lock().unwrap() > 1,
        "watch kept failing, so the reflector must have re-listed more than once \
         (got {} list calls)",
        *list_calls.lock().unwrap()
    );

    handle.abort();
}

#[tokio::test]
async fn initial_list_populates_store_and_watch_resumes_from_list_rv() {
    let lw = Arc::new(MockLw {
        batches: Mutex::new(vec![vec![]]),
        list_result: (
            vec![Obj {
                name: "a".into(),
                v: 1,
            }],
            "10".into(),
        ),
        watch_calls: Mutex::new(vec![]),
    });
    let r = Reflector::new(lw.clone(), key);
    r.sync_once().await.unwrap(); // one list + one (empty) watch session
    assert_eq!(r.store().get("a").unwrap().v, 1);
    // watch must have been started from the list's resourceVersion
    assert_eq!(
        lw.watch_calls.lock().unwrap().as_slice(),
        &[Some("10".to_string())]
    );
}

#[tokio::test]
async fn watch_events_mutate_store_and_emit() {
    let lw = Arc::new(MockLw {
        batches: Mutex::new(vec![vec![
            (
                WatchEvent::Added(Obj {
                    name: "b".into(),
                    v: 1,
                }),
                Some("2".into()),
            ),
            (
                WatchEvent::Modified(Obj {
                    name: "b".into(),
                    v: 2,
                }),
                Some("3".into()),
            ),
            (
                WatchEvent::Deleted(Obj {
                    name: "b".into(),
                    v: 2,
                }),
                Some("4".into()),
            ),
        ]]),
        list_result: (vec![], "1".into()),
        watch_calls: Mutex::new(vec![]),
    });
    let r = Reflector::new(lw, key);
    let mut events = r.subscribe();
    r.sync_once().await.unwrap();
    assert!(r.store().get("b").is_none()); // added, modified, then deleted
    assert!(matches!(events.try_recv().unwrap(), StoreEvent::Added(_)));
    assert!(matches!(
        events.try_recv().unwrap(),
        StoreEvent::Modified(_)
    ));
    assert!(matches!(events.try_recv().unwrap(), StoreEvent::Deleted(_)));
}

#[tokio::test]
async fn bookmark_advances_rv_without_store_change() {
    let lw = Arc::new(MockLw {
        batches: Mutex::new(vec![
            // first watch session: only a bookmark carrying rv 20
            vec![(
                WatchEvent::Bookmark(Obj {
                    name: "ignored".into(),
                    v: 0,
                }),
                Some("20".to_string()),
            )],
            // second watch session: nothing
            vec![],
        ]),
        list_result: (
            vec![Obj {
                name: "a".into(),
                v: 1,
            }],
            "10".into(),
        ),
        watch_calls: Mutex::new(vec![]),
    });
    let r = Reflector::new(lw.clone(), key);
    let mut events = r.subscribe();
    r.sync_once().await.unwrap();
    r.sync_once().await.unwrap();
    // second watch resumed from the bookmark-advanced rv
    assert_eq!(
        lw.watch_calls.lock().unwrap().as_slice(),
        &[Some("10".to_string()), Some("20".to_string())]
    );
    // bookmark neither mutates the store nor emits a StoreEvent
    assert_eq!(r.store().get("a").unwrap().v, 1);
    assert!(r.store().get("ignored").is_none());
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn has_synced_after_initial_list() {
    let lw = Arc::new(MockLw {
        batches: Mutex::new(vec![vec![]]),
        list_result: (vec![], "1".into()),
        watch_calls: Mutex::new(vec![]),
    });
    let r = Reflector::new(lw, key);
    assert!(!r.has_synced());
    r.sync_once().await.unwrap();
    assert!(r.has_synced());
    r.wait_for_cache_sync().await;
}

/// Records the `(resourceVersion, page size)` the reflector lists with, and
/// scripts the results (`list_from` errors are popped first).
struct ListFromLw {
    calls: Mutex<Vec<(String, Option<i64>)>>,
    errors: Mutex<Vec<anyhow::Error>>,
    paginated: bool,
}

#[async_trait::async_trait]
impl ListWatch<Obj> for ListFromLw {
    async fn list(&self) -> anyhow::Result<(Vec<Obj>, String)> {
        unreachable!("the reflector lists through list_from")
    }
    async fn list_from(
        &self,
        rv: &str,
        page_size: Option<i64>,
    ) -> anyhow::Result<(Vec<Obj>, String, bool)> {
        self.calls.lock().unwrap().push((rv.to_string(), page_size));
        if let Some(e) = self.errors.lock().unwrap().pop() {
            return Err(e);
        }
        Ok((vec![], "77".to_string(), self.paginated))
    }
    async fn watch<'a>(
        &'a self,
        _rv: Option<String>,
    ) -> anyhow::Result<BoxStream<'a, WatchItem<Obj>>> {
        Ok(Box::pin(futures::stream::empty()))
    }
}

fn status(code: u16, reason: &str) -> anyhow::Error {
    kubernetes_rs_client::api_status::ApiStatusError {
        code,
        reason: reason.into(),
        message: "m".into(),
        retry_after_seconds: None,
        causes: vec![],
        cause_messages: Vec::new(),
    }
    .into()
}

/// reflector.go:1014-1030 + :610-633: the first list is rv="0" with the pager
/// default; a relist at a held rv turns paging off (PageSize 0) so the watch
/// cache serves it, unless the initial list was paginated.
#[tokio::test]
async fn reflector_list_page_size_selection() {
    let lw = Arc::new(ListFromLw {
        calls: Mutex::new(vec![]),
        errors: Mutex::new(vec![]),
        paginated: false,
    });
    let r = Reflector::new(lw.clone(), key);
    r.sync_once().await.unwrap();
    // `run` re-lists only after an error; force one.
    r.reset_for_relist();
    r.sync_once().await.unwrap();
    let calls = lw.calls.lock().unwrap().clone();
    assert_eq!(calls[0], ("0".to_string(), None));
    assert_eq!(calls[1], ("77".to_string(), Some(0)));
}

#[tokio::test]
async fn reflector_list_keeps_paging_after_a_paginated_initial_list() {
    let lw = Arc::new(ListFromLw {
        calls: Mutex::new(vec![]),
        errors: Mutex::new(vec![]),
        paginated: true,
    });
    let r = Reflector::new(lw.clone(), key);
    r.sync_once().await.unwrap();
    r.reset_for_relist();
    r.sync_once().await.unwrap();
    let calls = lw.calls.lock().unwrap().clone();
    assert_eq!(calls[0], ("0".to_string(), None));
    assert_eq!(calls[1], ("77".to_string(), None));
}

/// An Expired list at the held rv is retried at rv="" (consistent read).
#[tokio::test]
async fn reflector_list_expired_retries_at_empty_rv() {
    let lw = Arc::new(ListFromLw {
        calls: Mutex::new(vec![]),
        errors: Mutex::new(vec![]),
        paginated: false,
    });
    let r = Reflector::new(lw.clone(), key);
    r.sync_once().await.unwrap();
    r.reset_for_relist();
    lw.errors.lock().unwrap().push(status(410, "Expired"));
    r.sync_once().await.unwrap();
    let calls = lw.calls.lock().unwrap().clone();
    assert_eq!(calls[1].0, "77");
    assert_eq!(calls[2], ("".to_string(), Some(0)));
}

/// `isExpiredError` (reflector.go:1051-1057): Expired or Gone (the 1.17 and
/// earlier servers answer 410 with both reasons).
#[test]
fn reflector_is_expired_error_expired_or_gone() {
    use kubernetes_rs_client::api_status::is_expired_error;
    assert!(is_expired_error(&status(410, "Expired")));
    assert!(is_expired_error(&status(410, "Gone")));
    assert!(is_expired_error(&status(410, "")));
    assert!(!is_expired_error(&status(500, "InternalError")));
}

/// `isTooLargeResourceVersionError` (reflector.go:1060-1089): the typed cause,
/// then the legacy-server fallbacks (Timeout + cause message from 1.17.0-1.18.5,
/// Timeout + status message from before 1.17.0). Not a Timeout, or no details:
/// false.
#[test]
fn reflector_is_too_large_resource_version_legacy_fallback() {
    use kubernetes_rs_client::api_status::{is_too_large_resource_version, ApiStatusError};
    let mk =
        |code: u16, reason: &str, message: &str, retry: Option<i32>, causes: &[(&str, &str)]| {
            anyhow::Error::new(ApiStatusError {
                code,
                reason: reason.into(),
                message: message.into(),
                retry_after_seconds: retry,
                causes: causes.iter().map(|c| c.0.to_string()).collect(),
                cause_messages: causes.iter().map(|c| c.1.to_string()).collect(),
            })
        };
    // typed cause
    assert!(is_too_large_resource_version(&mk(
        504,
        "Timeout",
        "m",
        Some(1),
        &[("ResourceVersionTooLarge", "x")]
    )));
    // 1.17.0-1.18.5: Timeout, cause message
    assert!(is_too_large_resource_version(&mk(
        504,
        "Timeout",
        "m",
        Some(1),
        &[("", "Too large resource version")]
    )));
    // before 1.17.0: Timeout, status message
    assert!(is_too_large_resource_version(&mk(
        504,
        "Timeout",
        "Timeout: Too large resource version: 5, current: 4",
        Some(1),
        &[]
    )));
    // not a Timeout
    assert!(!is_too_large_resource_version(&mk(
        500,
        "InternalError",
        "Too large resource version",
        Some(0),
        &[("", "Too large resource version")]
    )));
    // Timeout without details
    assert!(!is_too_large_resource_version(&mk(
        504,
        "Timeout",
        "Too large resource version",
        None,
        &[]
    )));
    // Timeout with details, unrelated messages
    assert!(!is_too_large_resource_version(&mk(
        504,
        "Timeout",
        "m",
        Some(1),
        &[("", "other")]
    )));
}
