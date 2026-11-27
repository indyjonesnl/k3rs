//! List pager: break a large LIST into `limit`/`continue` chunks.
//!
//! Port of `staging/src/k8s.io/client-go/tools/pager/pager.go`:
//! `ListPager` (:50), `New` (:61), `List` (:84) / `list` (:100) and
//! `eachListChunk` (:285). Differences from Go, by design: no `context`
//! argument (cancel by dropping the future), no `ListWithAlloc`, and the
//! buffered `EachListItem` (`eachListChunkBuffered`, :237) is not ported
//! (sequential `each_list_chunk` only).

use std::future::Future;

use anyhow::Result;

use crate::api_status::is_resource_expired;

/// `defaultPageSize` (pager.go:30).
pub const DEFAULT_PAGE_SIZE: i64 = 500;

/// The subset of `metav1.ListOptions` the pager reads and rewrites.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListOptions {
    pub limit: i64,
    pub continue_token: String,
    pub resource_version: String,
    pub resource_version_match: String,
}

/// One list response (`meta.ListAccessor` view plus the items).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListPage<T> {
    pub items: Vec<T>,
    pub resource_version: String,
    pub continue_token: String,
}

/// `ListPager` (pager.go:50).
pub struct ListPager<F> {
    pub page_size: i64,
    pub page_fn: F,
    pub full_list_if_expired: bool,
}

impl<T, Fut, F> ListPager<F>
where
    F: Fn(ListOptions) -> Fut,
    Fut: Future<Output = Result<ListPage<T>>>,
{
    /// `New` (pager.go:61): default page size, full-list fallback on.
    pub fn new(page_fn: F) -> Self {
        Self {
            page_size: DEFAULT_PAGE_SIZE,
            page_fn,
            full_list_if_expired: true,
        }
    }

    /// `ListPager.List` (pager.go:84-176). Returns the list and whether the
    /// result was paginated.
    pub async fn list(&self, mut options: ListOptions) -> Result<(ListPage<T>, bool)> {
        if options.limit == 0 {
            options.limit = self.page_size;
        }
        let requested_rv = options.resource_version.clone();
        let requested_rv_match = options.resource_version_match.clone();
        let mut list: Option<ListPage<T>> = None;
        let mut paginated = false;

        loop {
            let page = match (self.page_fn)(options.clone()).await {
                Ok(p) => p,
                Err(err) => {
                    // Only fall back to a full list if the error is
                    // "Expired", FullListIfExpired is set, and it happened
                    // on page 2 or later (pager.go:113-124).
                    if !is_resource_expired(&err)
                        || !self.full_list_if_expired
                        || options.continue_token.is_empty()
                    {
                        return Err(err);
                    }
                    options.limit = 0;
                    options.continue_token.clear();
                    options.resource_version = requested_rv;
                    options.resource_version_match = requested_rv_match;
                    let result = (self.page_fn)(options).await?;
                    return Ok((result, paginated));
                }
            };

            // exit early with the object we got if no page was processed
            if page.continue_token.is_empty() && list.is_none() {
                return Ok((page, paginated));
            }

            // initialise the list from the first page (:143-148)
            let acc = list.get_or_insert_with(|| ListPage {
                items: Vec::with_capacity(options.limit.max(0) as usize + 1),
                resource_version: page.resource_version.clone(),
                continue_token: String::new(),
            });
            acc.items.extend(page.items);

            if page.continue_token.is_empty() {
                return Ok((
                    ListPage {
                        items: std::mem::take(&mut acc.items),
                        resource_version: std::mem::take(&mut acc.resource_version),
                        continue_token: String::new(),
                    },
                    paginated,
                ));
            }

            options.continue_token = page.continue_token;
            // `specifying resource version is not allowed when using
            // continue` (pager.go:166-169, kubernetes#85221).
            options.resource_version.clear();
            options.resource_version_match.clear();
            paginated = true;
        }
    }

    /// `eachListChunk` (pager.go:285-313): call `f` on each page in order.
    pub async fn each_list_chunk<G>(&self, mut options: ListOptions, mut f: G) -> Result<()>
    where
        G: FnMut(ListPage<T>) -> Result<()>,
    {
        if options.limit == 0 {
            options.limit = self.page_size;
        }
        loop {
            let page = (self.page_fn)(options.clone()).await?;
            let next = page.continue_token.clone();
            f(page)?;
            if next.is_empty() {
                return Ok(());
            }
            options.continue_token = next;
        }
    }
}
