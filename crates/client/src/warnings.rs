//! API warning (`Warning` header) handling.
//!
//! Port of `client-go/rest/warnings.go` (`WarningHandler`, `NoWarnings`,
//! `WarningLogger`, `NewWarningWriter`, default handler, `handleWarnings`) and
//! of `apimachinery/pkg/util/net/http.go` (`ParseWarningHeaders`,
//! `ParseWarningHeader`, `parseQuotedString`, RFC 2047 text decoding).

use base64::Engine;
use std::collections::HashSet;
use std::io::Write;
use std::sync::{Arc, Mutex, RwLock};

/// `net.WarningHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarningHeader {
    pub code: i32,
    pub agent: String,
    pub text: String,
}

/// `ParseWarningHeaders`: every parseable warning plus one error per header
/// that failed (the rest of a failing header is skipped).
pub fn parse_warning_headers(headers: &[String]) -> (Vec<WarningHeader>, Vec<String>) {
    let mut results = Vec::new();
    let mut errs = Vec::new();
    for header in headers {
        let mut header = header.clone();
        while !header.is_empty() {
            match parse_warning_header(&header) {
                Ok((r, rem)) => {
                    results.push(r);
                    header = rem;
                }
                Err(e) => {
                    errs.push(e);
                    break;
                }
            }
        }
    }
    (results, errs)
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

/// `ParseWarningHeader` (RFC 7234 5.5): one `code agent "text" ["date"]`
/// warning; returns it with the remainder after an optional comma.
pub fn parse_warning_header(header: &str) -> Result<(WarningHeader, String), String> {
    let header = header.trim();
    let parts: Vec<&str> = header.splitn(3, ' ').collect();
    if parts.len() != 3 {
        return Err("invalid warning header: fewer than 3 segments".into());
    }
    let (code, agent, text_date_remainder) = (parts[0], parts[1], parts[2]);
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid warning header: code segment is not 3 digits between 100-299".into());
    }
    let code_int: i32 = code.parse().unwrap_or(0);
    if agent.is_empty() {
        return Err("invalid warning header: empty agent segment".into());
    }
    if has_control(agent) {
        return Err("invalid warning header: invalid agent".into());
    }
    if text_date_remainder.is_empty() {
        return Err("invalid warning header: empty text segment".into());
    }
    let (mut text, date_and_remainder) = parse_quoted_string(text_date_remainder)
        .map_err(|e| format!("invalid warning header: {e}"))?;
    // tolerate RFC2047-encoded text from warnings produced according to RFC2616
    if let Some(decoded) = decode_header(&text) {
        text = decoded;
    }
    if has_control(&text) {
        return Err("invalid warning header: invalid text".into());
    }
    let result = WarningHeader {
        code: code_int,
        agent: agent.to_string(),
        text,
    };
    let mut remainder = String::new();
    if !date_and_remainder.is_empty() {
        if let Some(rest) = date_and_remainder.strip_prefix('"') {
            // consume date
            match rest.find('"') {
                Some(i) => remainder = rest[i + 1..].trim().to_string(),
                None => return Err("invalid warning header: unterminated date segment".into()),
            }
        } else {
            remainder = date_and_remainder;
        }
    }
    if !remainder.is_empty() {
        if let Some(rest) = remainder.strip_prefix(',') {
            remainder = rest.trim().to_string();
        } else {
            return Err("invalid warning header: unexpected token after warn-date".into());
        }
    }
    Ok((result, remainder))
}

/// `parseQuotedString`: a backslash-escaped quoted string and what follows.
fn parse_quoted_string(quoted: &str) -> Result<(String, String), String> {
    if quoted.is_empty() {
        return Err("invalid quoted string: 0-length".into());
    }
    let Some(body) = quoted.strip_prefix('"') else {
        return Err("invalid quoted string: missing initial quote".into());
    };
    let mut out = String::new();
    let mut escaping = false;
    for (i, c) in body.char_indices() {
        match c {
            '"' if !escaping => return Ok((out, body[i + 1..].trim().to_string())),
            '\\' if !escaping => escaping = true,
            _ => {
                out.push(c);
                escaping = false;
            }
        }
    }
    Err("invalid quoted string: missing closing quote".into())
}

/// `mime.WordDecoder.DecodeHeader` for utf-8, us-ascii and iso-8859-1 words;
/// `None` when nothing could be decoded (Go keeps the input on error).
fn decode_header(s: &str) -> Option<String> {
    if !s.contains("=?") {
        return Some(s.to_string());
    }
    let mut out = String::new();
    let mut rest = s;
    let mut last_encoded = false;
    while let Some(start) = rest.find("=?") {
        let (before, tail) = rest.split_at(start);
        match decode_word(tail) {
            Some((decoded, consumed)) => {
                // whitespace between two encoded words is dropped
                if !(last_encoded && before.chars().all(char::is_whitespace)) {
                    out.push_str(before);
                }
                out.push_str(&decoded);
                rest = &tail[consumed..];
                last_encoded = true;
            }
            None => {
                // Go returns an error (unknown charset / bad word) and the
                // caller keeps the original text.
                if tail[2..].contains("?=") {
                    return None;
                }
                out.push_str(before);
                out.push_str(&tail[..2]);
                rest = &tail[2..];
                last_encoded = false;
            }
        }
    }
    out.push_str(rest);
    Some(out)
}

/// One `=?charset?enc?text?=` word at the start of `s`: (decoded, bytes used).
fn decode_word(s: &str) -> Option<(String, usize)> {
    let body = s.strip_prefix("=?")?;
    let end = body.find("?=")?;
    let word = &body[..end];
    let mut it = word.splitn(3, '?');
    let (charset, enc, text) = (it.next()?, it.next()?, it.next()?);
    let bytes = match enc {
        "B" | "b" => base64::engine::general_purpose::STANDARD
            .decode(text)
            .ok()?,
        "Q" | "q" => {
            let t = text.as_bytes();
            let mut v = Vec::new();
            let mut i = 0;
            while i < t.len() {
                match t[i] {
                    b'_' => v.push(b' '),
                    b'=' => {
                        let h = std::str::from_utf8(t.get(i + 1..i + 3)?).ok()?;
                        v.push(u8::from_str_radix(h, 16).ok()?);
                        i += 2;
                    }
                    c => v.push(c),
                }
                i += 1;
            }
            v
        }
        _ => return None,
    };
    let decoded = match charset.to_ascii_lowercase().as_str() {
        "utf-8" => String::from_utf8(bytes).ok()?,
        "iso-8859-1" => bytes.iter().map(|&b| b as char).collect(),
        "us-ascii" => {
            if !bytes.is_ascii() {
                return None;
            }
            bytes.iter().map(|&b| b as char).collect()
        }
        _ => return None,
    };
    Some((decoded, 2 + end + 2))
}

/// `WarningHandler`.
pub trait WarningHandler: Send + Sync {
    fn handle_warning_header(&self, code: i32, agent: &str, text: &str);
}

/// `NoWarnings`: discard everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoWarnings;

impl WarningHandler for NoWarnings {
    fn handle_warning_header(&self, _: i32, _: &str, _: &str) {}
}

/// `WarningLogger`: log `299` warnings.
#[derive(Debug, Default, Clone, Copy)]
pub struct WarningLogger;

impl WarningHandler for WarningLogger {
    fn handle_warning_header(&self, code: i32, _agent: &str, text: &str) {
        if code != 299 || text.is_empty() {
            return;
        }
        tracing::info!("Warning: {text}");
    }
}

/// `WarningWriterOptions`.
#[derive(Debug, Default, Clone, Copy)]
pub struct WarningWriterOptions {
    pub deduplicate: bool,
    pub color: bool,
}

const YELLOW_COLOR: &str = "\u{1b}[33;1m";
const RESET_COLOR: &str = "\u{1b}[0m";

struct WriterState<W> {
    out: W,
    written_count: usize,
    written: HashSet<String>,
}

/// `warningWriter` (`NewWarningWriter`).
pub struct WarningWriter<W: Write + Send> {
    opts: WarningWriterOptions,
    state: Mutex<WriterState<W>>,
}

impl<W: Write + Send> WarningWriter<W> {
    pub fn new(out: W, opts: WarningWriterOptions) -> Self {
        Self {
            opts,
            state: Mutex::new(WriterState {
                out,
                written_count: 0,
                written: HashSet::new(),
            }),
        }
    }

    /// `WarningCount`.
    pub fn warning_count(&self) -> usize {
        self.state.lock().unwrap().written_count
    }

    /// Take the writer back (tests).
    pub fn into_inner(self) -> W {
        self.state.into_inner().unwrap().out
    }
}

impl<W: Write + Send> WarningHandler for WarningWriter<W> {
    fn handle_warning_header(&self, code: i32, _agent: &str, text: &str) {
        if code != 299 || text.is_empty() {
            return;
        }
        let mut st = self.state.lock().unwrap();
        if self.opts.deduplicate && !st.written.insert(text.to_string()) {
            return;
        }
        st.written_count += 1;
        let _ = if self.opts.color {
            writeln!(st.out, "{YELLOW_COLOR}Warning:{RESET_COLOR} {text}")
        } else {
            writeln!(st.out, "Warning: {text}")
        };
    }
}

static DEFAULT_WARNING_HANDLER: RwLock<Option<Arc<dyn WarningHandler>>> = RwLock::new(None);
static DEFAULT_INIT: std::sync::Once = std::sync::Once::new();

/// `SetDefaultWarningHandler`; `None` disables warnings entirely.
pub fn set_default_warning_handler(l: Option<Arc<dyn WarningHandler>>) {
    DEFAULT_INIT.call_once(|| {});
    *DEFAULT_WARNING_HANDLER.write().unwrap() = l;
}

/// `getDefaultWarningHandler`: `WarningLogger` until set.
pub fn get_default_warning_handler() -> Option<Arc<dyn WarningHandler>> {
    let mut initialised = true;
    DEFAULT_INIT.call_once(|| initialised = false);
    if !initialised {
        *DEFAULT_WARNING_HANDLER.write().unwrap() = Some(Arc::new(WarningLogger));
    }
    DEFAULT_WARNING_HANDLER.read().unwrap().clone()
}

/// `handleWarnings`: parse the `Warning` headers and feed `handler` (or the
/// default one); returns the parsed warnings.
pub fn handle_warnings(
    warning_headers: &[String],
    handler: Option<&dyn WarningHandler>,
) -> Vec<WarningHeader> {
    let default;
    let handler: Option<&dyn WarningHandler> = match handler {
        Some(h) => Some(h),
        None => {
            default = get_default_warning_handler();
            default.as_deref()
        }
    };
    let (warnings, _) = parse_warning_headers(warning_headers);
    if let Some(h) = handler {
        for w in &warnings {
            h.handle_warning_header(w.code, &w.agent, &w.text);
        }
    }
    warnings
}
