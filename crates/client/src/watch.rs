//! Typed watch events over the api-server's JSON-lines watch protocol
//! (`crates/api-server/src/handlers/watch.rs`).
//!
//! The wire format is one JSON object per `\n`-terminated line:
//! `{"type":"ADDED|MODIFIED|DELETED|BOOKMARK|ERROR","object":{...}}`.
//! Fatal conditions (e.g. a compacted resourceVersion) arrive in-stream as an
//! `ERROR` envelope carrying a `Status` object (`code:410`, `reason:"Expired"`,
//! `message:"too old resource version: X (Y)"`) — never as an HTTP error,
//! because the 200 + chunked headers are already on the wire.

use std::collections::VecDeque;

use anyhow::Result;
use futures::StreamExt;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::http::ApiClient;

/// A typed watch event, one per JSON line of a `?watch=true` response.
#[derive(Debug, Clone)]
pub enum WatchEvent<T> {
    Added(T),
    Modified(T),
    Deleted(T),
    Bookmark(T),
}

#[derive(Deserialize)]
struct RawEvent<T> {
    #[serde(rename = "type")]
    kind: String,
    object: T,
}

/// Parse one JSON line of a watch stream into a typed event.
///
/// `ERROR` envelopes are surfaced as `Err(ApiStatusError)` built from the
/// `Status` object (`apierrors.FromObject`), so callers can use the
/// `api_status` predicates, e.g. `is_resource_expired` to re-list.
pub fn parse_watch_line<T: DeserializeOwned>(line: &str) -> Result<WatchEvent<T>> {
    // Sniff the envelope type first with a raw-value object so an ERROR
    // envelope (whose object is a Status, not a T) doesn't fail T-decoding.
    let raw: RawEvent<serde_json::Value> = serde_json::from_str(line)?;
    if raw.kind == "ERROR" {
        // `Request.Watch` / `handleAnyWatch`: `apierrors.FromObject(event.Object)`,
        // so `is_forbidden` / `is_resource_expired` / `is_too_large_resource_version`
        // match. The text is the Status message.
        return Err(crate::api_status::from_status_object(&raw.object)?.into());
    }
    let object: T = serde_json::from_value(raw.object)?;
    Ok(match raw.kind.as_str() {
        "ADDED" => WatchEvent::Added(object),
        "MODIFIED" => WatchEvent::Modified(object),
        "DELETED" => WatchEvent::Deleted(object),
        "BOOKMARK" => WatchEvent::Bookmark(object),
        other => anyhow::bail!("unknown watch event type {other}"),
    })
}

/// GET `<path>?watch=true[&resourceVersion=rv]` and yield typed events.
///
/// Uses [`ApiClient::get_stream`] and splits the byte stream on newlines —
/// chunks are NOT line-aligned, so a line buffer carries partial lines across
/// chunk boundaries. Empty (keepalive) lines are skipped. The stream ends when
/// the server closes the connection.
pub async fn watch_stream<T: DeserializeOwned>(
    client: &ApiClient,
    path: &str,
    resource_version: Option<&str>,
) -> Result<impl futures::Stream<Item = Result<WatchEvent<T>>>> {
    // Match kubectl's query-append logic: ?watch=true if no query yet,
    // &watch=true otherwise (crates/kubectl/src/commands/get.rs).
    let separator = if path.contains('?') { "&" } else { "?" };
    let mut watch_path = format!("{path}{separator}watch=true");
    if let Some(rv) = resource_version {
        watch_path.push_str(&format!("&resourceVersion={rv}"));
    }

    let response = client
        .get_stream(&watch_path)
        .await
        .map_err(|e| anyhow::anyhow!("watch request failed: {e}"))?;

    struct State<S, T> {
        bytes: S,
        buffer: Vec<u8>,
        pending: VecDeque<Result<WatchEvent<T>>>,
        done: bool,
    }

    let state = State {
        bytes: response.bytes_stream(),
        buffer: Vec::new(),
        pending: VecDeque::new(),
        done: false,
    };

    Ok(futures::stream::unfold(state, |mut st| async move {
        loop {
            if let Some(item) = st.pending.pop_front() {
                return Some((item, st));
            }
            if st.done {
                return None;
            }
            match st.bytes.next().await {
                Some(Ok(chunk)) => {
                    st.buffer.extend_from_slice(&chunk);
                    // Drain every complete \n-terminated line from the buffer.
                    while let Some(pos) = st.buffer.iter().position(|&b| b == b'\n') {
                        let line_bytes: Vec<u8> = st.buffer.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&line_bytes[..pos]);
                        let line = line.trim();
                        if line.is_empty() {
                            continue; // keepalive
                        }
                        st.pending.push_back(parse_watch_line(line));
                    }
                }
                Some(Err(e)) => {
                    st.done = true;
                    st.pending
                        .push_back(Err(anyhow::anyhow!("watch stream error: {e}")));
                }
                None => {
                    st.done = true;
                    // A trailing partial line without a newline: try to parse
                    // it rather than silently dropping a final event.
                    let leftover = String::from_utf8_lossy(&st.buffer).trim().to_string();
                    st.buffer.clear();
                    if !leftover.is_empty() {
                        st.pending.push_back(parse_watch_line(&leftover));
                    }
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_status::*;

    fn err_for(status: &str) -> anyhow::Error {
        let line = format!(r#"{{"type":"ERROR","object":{status}}}"#);
        parse_watch_line::<serde_json::Value>(&line).unwrap_err()
    }

    /// `TestReflectorListAndWatchWithErrors`: an expired watch.
    #[test]
    fn watch_error_expired_is_typed() {
        let e = err_for(
            r#"{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Expired","code":410,"message":"too old resource version: 5 (10)"}"#,
        );
        assert!(is_resource_expired(&e));
        assert_eq!(e.to_string(), "too old resource version: 5 (10)");
        assert_eq!(reason_and_code_for_error(&e), ("Expired".to_string(), 410));
    }

    #[test]
    fn watch_error_forbidden_and_too_large_rv() {
        let e = err_for(
            r#"{"kind":"Status","status":"Failure","reason":"Forbidden","code":403,"message":"no"}"#,
        );
        assert!(is_forbidden(&e) && !is_resource_expired(&e));
        let e = err_for(
            r#"{"kind":"Status","status":"Failure","reason":"Timeout","code":504,"message":"x","details":{"causes":[{"reason":"ResourceVersionTooLarge","message":"Too large resource version"}],"retryAfterSeconds":1}}"#,
        );
        assert!(is_too_large_resource_version(&e));
        assert!(is_timeout(&e));
        assert_eq!(suggests_client_delay(&e), Some(1));
    }

    #[test]
    fn watch_error_non_status_object_is_rejected() {
        let e = err_for(r#"{"kind":"Pod","metadata":{"name":"p"}}"#);
        assert!(e.to_string().starts_with("unexpected object: "));
        assert!(!is_resource_expired(&e));
    }
}
