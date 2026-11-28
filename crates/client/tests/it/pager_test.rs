//! Ports of tools/pager/pager_test.go `TestListPager*` and
//! `TestListPagerList` (expired-continue fallback).

use anyhow::{anyhow, Result};
use kubernetes_rs_client::api_status::ApiStatusError;
use kubernetes_rs_client::pager::{ListOptions, ListPage, ListPager, DEFAULT_PAGE_SIZE};
use std::sync::Mutex;

fn expired() -> anyhow::Error {
    ApiStatusError {
        code: 410,
        reason: "Expired".into(),
        message: "too old resource version".into(),
        retry_after_seconds: None,
        causes: vec![],
        cause_messages: Vec::new(),
    }
    .into()
}

/// Serves `total` integers in `limit`-sized pages, like the apiserver.
fn serve(total: usize, opts: &ListOptions) -> Result<ListPage<usize>> {
    let start: usize = if opts.continue_token.is_empty() {
        0
    } else {
        opts.continue_token.parse()?
    };
    let limit = if opts.limit == 0 {
        total
    } else {
        opts.limit as usize
    };
    let end = (start + limit).min(total);
    Ok(ListPage {
        items: (start..end).collect(),
        resource_version: "10".into(),
        continue_token: if end < total {
            end.to_string()
        } else {
            String::new()
        },
    })
}

#[tokio::test]
async fn pager_list_pages_and_merges() {
    let seen = Mutex::new(Vec::new());
    let mut p = ListPager::new(|o: ListOptions| {
        seen.lock().unwrap().push(o.clone());
        async move { serve(25, &o) }
    });
    p.page_size = 10;
    let (list, paginated) = p
        .list(ListOptions {
            resource_version: "5".into(),
            resource_version_match: "NotOlderThan".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(paginated);
    assert_eq!(list.items, (0..25).collect::<Vec<_>>());
    assert_eq!(list.resource_version, "10");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    // first request keeps the RV, later ones clear it (pager.go:166-169)
    assert_eq!(seen[0].resource_version, "5");
    assert_eq!(seen[0].limit, 10);
    assert_eq!(seen[1].resource_version, "");
    assert_eq!(seen[1].resource_version_match, "");
    assert_eq!(seen[1].continue_token, "10");
}

#[tokio::test]
async fn pager_single_page_is_not_paginated() {
    let p = ListPager::new(|o: ListOptions| async move {
        assert_eq!(o.limit, DEFAULT_PAGE_SIZE);
        serve(3, &o)
    });
    let (list, paginated) = p.list(ListOptions::default()).await.unwrap();
    assert!(!paginated);
    assert_eq!(list.items.len(), 3);
}

#[tokio::test]
async fn pager_expired_continue_falls_back_to_full_list() {
    let calls = Mutex::new(Vec::new());
    let mut p = ListPager::new(|o: ListOptions| {
        calls.lock().unwrap().push(o.clone());
        async move {
            if !o.continue_token.is_empty() {
                return Err(expired());
            }
            serve(25, &o)
        }
    });
    p.page_size = 10;
    let (list, paginated) = p
        .list(ListOptions {
            resource_version: "5".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    // page 1 ok, page 2 expired, full list at the requested RV with no limit
    assert!(paginated);
    assert_eq!(list.items.len(), 25);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[2].limit, 0);
    assert_eq!(calls[2].continue_token, "");
    assert_eq!(calls[2].resource_version, "5");
}

#[tokio::test]
async fn pager_expired_on_first_page_is_an_error() {
    let p = ListPager::new(|_o: ListOptions| async move { Err::<ListPage<usize>, _>(expired()) });
    assert!(p.list(ListOptions::default()).await.is_err());
}

#[tokio::test]
async fn pager_no_fallback_when_disabled_or_other_error() {
    let mut p = ListPager::new(|o: ListOptions| async move {
        if o.continue_token.is_empty() {
            serve(25, &o)
        } else {
            Err(expired())
        }
    });
    p.page_size = 10;
    p.full_list_if_expired = false;
    assert!(p.list(ListOptions::default()).await.is_err());

    let mut q = ListPager::new(|o: ListOptions| async move {
        if o.continue_token.is_empty() {
            serve(25, &o)
        } else {
            Err(anyhow!("boom"))
        }
    });
    q.page_size = 10;
    assert_eq!(
        q.list(ListOptions::default())
            .await
            .unwrap_err()
            .to_string(),
        "boom"
    );
}

#[tokio::test]
async fn pager_each_list_chunk_visits_pages_in_order() {
    let mut p = ListPager::new(|o: ListOptions| async move { serve(25, &o) });
    p.page_size = 10;
    let mut sizes = vec![];
    p.each_list_chunk(ListOptions::default(), |pg| {
        sizes.push(pg.items.len());
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(sizes, vec![10, 10, 5]);
    // fn error stops processing
    let e = p
        .each_list_chunk(ListOptions::default(), |_| Err(anyhow!("stop")))
        .await
        .unwrap_err();
    assert_eq!(e.to_string(), "stop");
}

/// `TestListPagerEachListItem`-style: the buffered reader yields every item
/// in order and fetches pages ahead of the consumer (pager.go:237-283).
#[tokio::test]
async fn pager_each_list_item_buffered_yields_all_in_order() {
    let mut p = ListPager::new(|o: ListOptions| async move { serve(25, &o) });
    p.page_size = 10;
    let mut got = Vec::new();
    p.each_list_item(ListOptions::default(), |i| {
        got.push(i);
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(got, (0..25).collect::<Vec<_>>());
}

#[tokio::test]
async fn pager_each_list_chunk_buffered_fetches_ahead() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fetched = AtomicUsize::new(0);
    let mut p = ListPager::new(|o: ListOptions| {
        fetched.fetch_add(1, Ordering::SeqCst);
        async move { serve(50, &o) }
    });
    p.page_size = 10;
    p.page_buffer_size = 10;
    let mut at_first_chunk = 0;
    p.each_list_chunk_buffered(ListOptions::default(), |_| {
        if at_first_chunk == 0 {
            at_first_chunk = 1;
        }
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(fetched.load(Ordering::SeqCst), 5);
}

/// An `f` error is returned immediately; a fetch error surfaces after the
/// pages before it were processed; a buffer size below 1 still works.
#[tokio::test]
async fn pager_each_list_chunk_buffered_errors() {
    let mut p = ListPager::new(|o: ListOptions| async move { serve(30, &o) });
    p.page_size = 10;
    p.page_buffer_size = 0;
    let mut n = 0;
    let err = p
        .each_list_chunk_buffered(ListOptions::default(), |_| {
            n += 1;
            if n == 2 {
                Err(anyhow!("stop"))
            } else {
                Ok(())
            }
        })
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "stop");

    let p = ListPager::new(|o: ListOptions| async move {
        if o.continue_token.is_empty() {
            serve(30, &o)
        } else {
            Err(anyhow!("boom"))
        }
    });
    let mut pages = 0;
    let err = p
        .each_list_chunk_buffered(
            ListOptions {
                limit: 10,
                ..Default::default()
            },
            |_| {
                pages += 1;
                Ok(())
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "boom");
    assert_eq!(pages, 1);
}
