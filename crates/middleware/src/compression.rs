//! Response gzip compression (`APIResponseCompression`).
//!
//! Ported from upstream
//! `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/responsewriters/writers.go`:
//! `defaultGzipContentEncodingLevel` / `defaultGzipThresholdBytes` /
//! `firstWriteStreamingThresholdBytes` (:153-165), `negotiateContentEncoding`
//! (:171-198 in release-1.35) and `deferredResponseWriter` (`Write`,
//! `unbufferedWrite`, `Close`).
//!
//! The mechanism is upstream's: the writer sits between the serializer and the
//! HTTP response and decides on the *first* writes whether to gzip. A first
//! write longer than the threshold gzips at once; a first write of at most
//! `firstWriteStreamingThresholdBytes` (a streaming encoder starting with `{`
//! or a protobuf header) is buffered until the threshold is crossed, so a
//! streamed large list is still compressed while a small one is not.
//!
//! Deviations of expression only: Go's `gzipPool` is not ported (flate2 has no
//! reusable `Reset`; the encoder is created per response), and the tracing
//! span events are `tracing::debug!`. Wiring into the handlers is a separate
//! task (`gzip_response_middleware`, below, wires it into the API chain).

use std::io::{self, Write};

use axum::http::{header, HeaderMap, HeaderValue};
use flate2::write::GzEncoder;
use flate2::Compression;

/// `defaultGzipContentEncodingLevel`: level 1 uses the least CPU for similar
/// ratios (kubernetes/kubernetes#112296).
pub const DEFAULT_GZIP_CONTENT_ENCODING_LEVEL: u32 = 1;
/// `defaultGzipThresholdBytes`: compared to the size of the first write; a
/// smaller one is never gzipped.
pub const DEFAULT_GZIP_THRESHOLD_BYTES: usize = 128 * 1024;
/// `firstWriteStreamingThresholdBytes`: the length of the first write
/// recognises streaming encoders (JSON starts with `{`, protobuf with a
/// 4-byte header).
pub const FIRST_WRITE_STREAMING_THRESHOLD_BYTES: usize = 4;

/// `negotiateContentEncoding`: `"gzip"` when the client asked for it and the
/// `APIResponseCompression` gate is on, else `""`.
pub fn negotiate_content_encoding(headers: &HeaderMap) -> &'static str {
    let Some(encoding) = headers.get(header::ACCEPT_ENCODING) else {
        return "";
    };
    let Ok(encoding) = encoding.to_str() else {
        return "";
    };
    if encoding.is_empty() {
        return "";
    }
    if gate_enabled() {
        for token in encoding.split(',') {
            if token.trim() == "gzip" {
                return "gzip";
            }
        }
    }
    ""
}

fn gate_enabled() -> bool {
    kubernetes_rs_common::feature_gates::gate_enabled("APIResponseCompression").unwrap_or(false)
}

/// The slice of `http.ResponseWriter` the writer needs.
pub trait ResponseWriter {
    fn headers_mut(&mut self) -> &mut HeaderMap;
    fn write_header(&mut self, status_code: u16);
    fn write(&mut self, p: &[u8]) -> io::Result<usize>;
}

enum Out {
    Plain,
    Gzip(Box<GzEncoder<Vec<u8>>>),
}

/// `deferredResponseWriter`.
pub struct DeferredResponseWriter<W: ResponseWriter> {
    media_type: String,
    status_code: u16,
    content_encoding: String,

    has_buffered: bool,
    buffer: Vec<u8>,
    has_written: bool,
    hw: W,
    w: Option<Out>,
}

impl<W: ResponseWriter> DeferredResponseWriter<W> {
    pub fn new(
        hw: W,
        media_type: impl Into<String>,
        status_code: u16,
        content_encoding: impl Into<String>,
    ) -> Self {
        Self {
            media_type: media_type.into(),
            status_code,
            content_encoding: content_encoding.into(),
            has_buffered: false,
            buffer: Vec::new(),
            has_written: false,
            hw,
            w: None,
        }
    }

    /// The wrapped response writer (call after [`Self::close`]).
    pub fn into_inner(self) -> W {
        self.hw
    }

    /// `Write`.
    pub fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        if self.has_written {
            // already written, cannot buffer
            return self.unbuffered_write(p);
        }
        if self.content_encoding != "gzip" {
            // non-gzip, no need to buffer
            return self.unbuffered_write(p);
        }
        if !self.has_buffered && p.len() > DEFAULT_GZIP_THRESHOLD_BYTES {
            // not yet buffered, first write is long enough to trigger gzip
            return self.unbuffered_write(p);
        }
        if !self.has_buffered && p.len() > FIRST_WRITE_STREAMING_THRESHOLD_BYTES {
            // first write is longer than expected for streaming scenarios
            return self.unbuffered_write(p);
        }
        if !self.has_buffered {
            self.has_buffered = true;
            // 80 bytes: the minimum serialized 0-item list.
            self.buffer = Vec::with_capacity(80.max(p.len()));
        }
        self.buffer.extend_from_slice(p);
        if self.buffer.len() > DEFAULT_GZIP_THRESHOLD_BYTES {
            // accumulated enough to trigger gzip, write and clear buffer
            let buf = std::mem::take(&mut self.buffer);
            self.unbuffered_write(&buf)?;
        }
        Ok(p.len())
    }

    /// `unbufferedWrite`.
    fn unbuffered_write(&mut self, p: &[u8]) -> io::Result<usize> {
        if self.has_written {
            return self.out_write(p);
        }
        self.has_written = true;

        if self.content_encoding == "gzip" && p.len() > DEFAULT_GZIP_THRESHOLD_BYTES {
            let h = self.hw.headers_mut();
            h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
            h.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
            self.w = Some(Out::Gzip(Box::new(GzEncoder::new(
                Vec::new(),
                Compression::new(DEFAULT_GZIP_CONTENT_ENCODING_LEVEL),
            ))));
        } else {
            self.w = Some(Out::Plain);
        }
        tracing::debug!(
            writer = if matches!(self.w, Some(Out::Gzip(_))) {
                "gzip"
            } else {
                "plain"
            },
            size = p.len(),
            "About to start writing response"
        );

        let ct = HeaderValue::from_str(&self.media_type)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.hw.headers_mut().insert(header::CONTENT_TYPE, ct);
        self.hw.write_header(self.status_code);
        self.out_write(p)
    }

    fn out_write(&mut self, p: &[u8]) -> io::Result<usize> {
        match self.w.as_mut().expect("writer chosen before write") {
            Out::Plain => self.hw.write(p),
            Out::Gzip(gz) => {
                let n = gz.write(p)?;
                let out = std::mem::take(gz.get_mut());
                if !out.is_empty() {
                    self.hw.write(&out)?;
                }
                Ok(n)
            }
        }
    }

    /// `Close`.
    pub fn close(&mut self) -> io::Result<()> {
        if !self.has_written {
            if !self.has_buffered {
                return Ok(());
            }
            // never reached the threshold: no gzip writer cleanup needed
            let buf = std::mem::take(&mut self.buffer);
            self.unbuffered_write(&buf)?;
            return Ok(());
        }
        if let Some(Out::Gzip(gz)) = self.w.take() {
            let out = gz.finish()?;
            self.hw.write(&out)?;
        }
        Ok(())
    }
}

/// The API serializations `SerializeObject` writes through the deferred
/// writer (JSON, YAML, CBOR and Kubernetes protobuf, incl. `;as=` variants).
fn is_api_media_type(content_type: &str) -> bool {
    [
        "application/json",
        "application/yaml",
        "application/cbor",
        "application/vnd.kubernetes.protobuf",
    ]
    .iter()
    .any(|p| content_type.starts_with(p))
}

/// A buffered axum response as the `http.ResponseWriter` the deferred writer
/// drives.
struct BufferedResponse {
    headers: HeaderMap,
    body: Vec<u8>,
}

impl ResponseWriter for BufferedResponse {
    fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }
    fn write_header(&mut self, _status_code: u16) {}
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.body.extend_from_slice(p);
        Ok(p.len())
    }
}

/// `SerializeObject` (responsewriters/writers.go:92-139): the encoded object
/// goes through a [`DeferredResponseWriter`] whose `contentEncoding` is
/// `negotiateContentEncoding(req)`, so a response above
/// [`DEFAULT_GZIP_THRESHOLD_BYTES`] is gzipped (`Content-Encoding: gzip`,
/// `Vary: Accept-Encoding`) and a smaller one is not.
///
/// Our handlers return the serialized body (already protobuf-wrapped by the
/// content-negotiation middleware when asked for), so this layer sits outside
/// it and feeds the finished body to the writer as its first and only write.
/// Not applied (upstream never passes these through `SerializeObject`):
/// streaming bodies such as watches (no exact size), responses that already
/// carry a `Content-Encoding`, and non-API media types.
pub async fn gzip_response_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::body::{Body, HttpBody};

    let content_encoding = negotiate_content_encoding(req.headers());
    let resp = next.run(req).await;
    if content_encoding != "gzip" || resp.headers().contains_key(header::CONTENT_ENCODING) {
        return resp;
    }
    let is_api_body = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_api_media_type);
    let Some(size) = resp.body().size_hint().exact() else {
        return resp; // streaming
    };
    if !is_api_body || size as usize <= DEFAULT_GZIP_THRESHOLD_BYTES {
        return resp;
    }

    let (mut parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap();
    };
    let media_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let mut w = DeferredResponseWriter::new(
        BufferedResponse {
            headers: std::mem::take(&mut parts.headers),
            body: Vec::new(),
        },
        media_type,
        parts.status.as_u16(),
        content_encoding,
    );
    let written = w.write(&bytes).and_then(|_| w.close());
    let out = w.into_inner();
    parts.headers = out.headers;
    if let Err(e) = written {
        // `apiserver was unable to close cleanly the response writer`
        tracing::error!(%e, "apiserver was unable to write a gzip response");
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap();
    }
    if parts.headers.contains_key(header::CONTENT_ENCODING) {
        // the compressed length replaces the original
        parts.headers.remove(header::CONTENT_LENGTH);
    }
    axum::response::Response::from_parts(parts, Body::from(out.body))
}
