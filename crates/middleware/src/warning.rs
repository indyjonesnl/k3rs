//! Port of the request warning recorder: `WithWarningRecorder`
//! (`staging/src/k8s.io/apiserver/pkg/endpoints/filters/warning.go:31`), the
//! `warning.AddWarning` context API
//! (`staging/src/k8s.io/apiserver/pkg/warning/context.go`) and
//! `net.NewWarningHeader` / `makeQuotedString`
//! (`staging/src/k8s.io/apimachinery/pkg/util/net/http.go:655-699`).
//!
//! A [`WarningRecorder`] is attached to every request by [`with_warning_recorder`];
//! handlers add warnings through [`add_warning`]. Warnings are de-duplicated by
//! text, written as RFC 7234 `Warning: 299 <agent> "<text>"` headers, and capped
//! at 4096 runes in total. Past the cap every warning is truncated to 256 runes
//! (already-recorded ones are replayed truncated) and, once the truncated
//! total also reaches the cap, further warnings are dropped.
//!
//! Difference from Go, caused by axum owning the response headers until the
//! handler returns: the recorder buffers its headers and [`with_warning_recorder`]
//! appends them to the response when the handler is done. When the cap was
//! exceeded, `Header().Del("Warning")` of the replay corresponds to removing
//! `Warning` headers set on the response before the recorder's are appended.
//!
//! Converting the ad hoc call sites (registry/rest.rs, handlers/validation.rs,
//! deprecation/mod.rs, router.rs) is tracked separately.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header::HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// `truncateAtTotalRunes`.
pub const TRUNCATE_AT_TOTAL_RUNES: usize = 4 * 1024;
/// `truncateItemRunes`.
pub const TRUNCATE_ITEM_RUNES: usize = 256;

#[derive(Debug, Clone)]
struct RecordedWarning {
    agent: String,
    text: String,
}

#[derive(Debug, Default)]
struct State {
    /// `recorded`: whether AddWarning was already called with a given text.
    recorded: std::collections::HashSet<String>,
    /// `ordered`: warnings added so they can be replayed and truncated.
    ordered: Vec<RecordedWarning>,
    /// `written`: runes of text added as warning headers.
    written: usize,
    /// `truncating`: the cap was exceeded and warnings are now truncated.
    truncating: bool,
    /// The `Warning` headers written so far (the Go `writer.Header()["Warning"]`).
    headers: Vec<String>,
}

/// `recorder` (filters/warning.go:46-65).
#[derive(Debug)]
pub struct WarningRecorder {
    state: Mutex<State>,
    truncate_at_total_runes: usize,
    truncate_item_runes: usize,
}

impl Default for WarningRecorder {
    fn default() -> Self {
        Self::with_limits(TRUNCATE_AT_TOTAL_RUNES, TRUNCATE_ITEM_RUNES)
    }
}

/// `net.NewWarningHeader(code, agent, text)` (util/net/http.go:655-668).
pub fn new_warning_header(code: i32, agent: &str, text: &str) -> Result<String, String> {
    if !(0..=999).contains(&code) {
        return Err("code must be between 0 and 999".into());
    }
    let agent = if agent.is_empty() {
        "-"
    } else if agent.contains(['\\', '"'])
        || agent.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("agent must be valid UTF-8 and must not contain spaces, quotes, backslashes, or control characters".into());
    } else {
        agent
    };
    if text.chars().any(char::is_control) {
        return Err("text must be valid UTF-8 and must not contain control characters".into());
    }
    Ok(format!("{code:03} {agent} {}", make_quoted_string(text)))
}

/// `makeQuotedString`: quote, escaping `"` and `\`.
fn make_quoted_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn truncate_runes(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

impl WarningRecorder {
    /// A recorder with explicit limits (the Go tests swap the package vars).
    pub fn with_limits(truncate_at_total_runes: usize, truncate_item_runes: usize) -> Self {
        Self {
            state: Mutex::new(State::default()),
            truncate_at_total_runes,
            truncate_item_runes,
        }
    }

    /// `recorder.AddWarning(agent, text)` (filters/warning.go:67-129).
    ///
    /// `agent` must not contain spaces, quotes, backslashes or control
    /// characters and `text` must not contain control characters; a violating
    /// warning is dropped (it still counts as recorded, as upstream).
    pub fn add_warning(&self, agent: &str, text: &str) {
        if text.is_empty() {
            return;
        }
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // already over the limit and truncating: nothing more is written
        if st.written >= self.truncate_at_total_runes && st.truncating {
            return;
        }

        // dedupe if already warned
        if !st.recorded.insert(text.to_string()) {
            return;
        }
        st.ordered.push(RecordedWarning {
            agent: agent.to_string(),
            text: text.to_string(),
        });

        // truncate on a rune boundary, if needed
        let mut text = text.to_string();
        let mut rune_len = text.chars().count();
        if st.truncating && rune_len > self.truncate_item_runes {
            text = truncate_runes(&text, self.truncate_item_runes);
            rune_len = self.truncate_item_runes;
        }

        let Ok(header) = new_warning_header(299, agent, &text) else {
            return;
        };

        // fits within the limit, or already truncating: write and return
        if st.written + rune_len <= self.truncate_at_total_runes || st.truncating {
            st.written += rune_len;
            st.headers.push(header);
            return;
        }

        // otherwise enable truncation, reset, and replay the existing items truncated
        st.truncating = true;
        st.written = 0;
        st.headers.clear();
        tracing::error!("exceeded max warning header size, truncating");
        let ordered = st.ordered.clone();
        for w in ordered {
            let mut text = w.text;
            let mut rune_len = text.chars().count();
            if rune_len > self.truncate_item_runes {
                text = truncate_runes(&text, self.truncate_item_runes);
                rune_len = self.truncate_item_runes;
            }
            if let Ok(header) = new_warning_header(299, &w.agent, &text) {
                st.written += rune_len;
                st.headers.push(header);
            }
        }
    }

    /// The `Warning` header values recorded so far, in order.
    pub fn headers(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .headers
            .clone()
    }

    fn truncating(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .truncating
    }
}

/// `warning.AddWarning(ctx, agent, text)`: records on the request's recorder;
/// a no-op when none is attached.
pub fn add_warning(extensions: &axum::http::Extensions, agent: &str, text: &str) {
    if let Some(r) = extensions.get::<Arc<WarningRecorder>>() {
        r.add_warning(agent, text);
    }
}

/// `WithWarningRecorder`: attach a recorder to the request and write its
/// `Warning` headers to the response.
pub async fn with_warning_recorder(mut req: Request<Body>, next: Next) -> Response {
    let recorder = Arc::new(WarningRecorder::default());
    req.extensions_mut().insert(recorder.clone());
    let mut resp = next.run(req).await;
    apply_warning_headers(&recorder, &mut resp);
    resp
}

/// Write the recorder's headers to `resp` (`writer.Header().Add("Warning", ..)`).
pub fn apply_warning_headers(recorder: &WarningRecorder, resp: &mut Response) {
    let name = HeaderName::from_static("warning");
    if recorder.truncating() {
        // `r.writer.Header().Del("Warning")` of the truncation replay
        resp.headers_mut().remove(&name);
    }
    for h in recorder.headers() {
        // Go writes the bytes as they are; obs-text (non-ASCII) is accepted.
        if let Ok(v) = HeaderValue::from_bytes(h.as_bytes()) {
            resp.headers_mut().append(name.clone(), v);
        }
    }
}
