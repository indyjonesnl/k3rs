//! Ported from upstream
//! `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/responsewriters/writers_test.go`:
//! `TestDeferredResponseWriter_Write` (:379) and the gzip decision of
//! `TestStreamingGzipIntegration` (:819), plus `negotiateContentEncoding`.

use std::io::{self, Read};

use axum::http::{header, HeaderMap, HeaderValue};
use flate2::read::GzDecoder;
use kubernetes_rs_middleware::compression::{
    negotiate_content_encoding, DeferredResponseWriter, ResponseWriter,
    DEFAULT_GZIP_THRESHOLD_BYTES,
};

/// `httptest.ResponseRecorder`.
#[derive(Default)]
struct Recorder {
    headers: HeaderMap,
    status: Option<u16>,
    body: Vec<u8>,
}

impl ResponseWriter for Recorder {
    fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }
    fn write_header(&mut self, status_code: u16) {
        self.status.get_or_insert(status_code);
    }
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.body.extend_from_slice(p);
        Ok(p.len())
    }
}

fn run(chunks: &[&[u8]]) -> (Recorder, Vec<u8>) {
    let mut drw = DeferredResponseWriter::new(Recorder::default(), "text/plain", 200, "gzip");
    let mut full = Vec::new();
    for c in chunks {
        let n = drw.write(c).unwrap();
        assert_eq!(n, c.len(), "write is not complete");
        full.extend_from_slice(c);
    }
    drw.close().unwrap();
    (drw.into_inner(), full)
}

fn check(chunks: &[&[u8]], expect_gzip: bool, expect_headers: bool) {
    let (rec, full) = run(chunks);
    if expect_headers {
        assert_eq!(rec.status, Some(200));
        assert_eq!(rec.headers.get(header::CONTENT_TYPE).unwrap(), "text/plain");
    } else {
        assert!(rec.headers.is_empty());
        assert_eq!(rec.status, None);
    }
    let gz = rec.headers.get(header::CONTENT_ENCODING);
    let vary: Vec<_> = rec.headers.get_all(header::VARY).iter().collect();
    if expect_gzip {
        assert_eq!(gz.unwrap(), "gzip");
        assert_eq!(vary, vec!["Accept-Encoding"]);
        let mut out = Vec::new();
        GzDecoder::new(&rec.body[..]).read_to_end(&mut out).unwrap();
        assert!(out == full, "payload mismatch after decompress");
    } else {
        assert!(gz.is_none());
        assert!(vary.is_empty());
        assert!(rec.body == full, "payload mismatch");
    }
}

#[test]
fn gzip_response_deferred_writer_cases() {
    let small = vec![b'b'; DEFAULT_GZIP_THRESHOLD_BYTES - 1];
    let large = vec![b'b'; DEFAULT_GZIP_THRESHOLD_BYTES + 1];
    let (s, l) = (&small[..], &large[..]);
    // (name, chunks, expect_gzip, headers written)
    let cases: Vec<(&str, Vec<&[u8]>, bool, bool)> = vec![
        ("no writes", vec![], false, false),
        ("one empty write", vec![b""], false, true),
        ("one single byte write", vec![b"{"], false, true),
        ("one small chunk write", vec![s], false, true),
        ("two small chunk writes", vec![s, s], false, true),
        (
            "one single byte and one small chunk",
            vec![b"{", s],
            false,
            true,
        ),
        (
            "two single bytes and one small chunk",
            vec![b"{", b"{", s],
            true,
            true,
        ),
        ("one large chunk", vec![l], true, true),
        ("two large chunks", vec![l, l], true, true),
        ("one small and one large chunk", vec![s, l], false, true),
    ];
    for (name, chunks, gzip, hdrs) in cases {
        std::panic::catch_unwind(|| check(&chunks, gzip, hdrs))
            .unwrap_or_else(|_| panic!("case failed: {name}"));
    }
}

#[test]
fn gzip_response_non_gzip_encoding_never_buffers_or_compresses() {
    let large = vec![b'b'; DEFAULT_GZIP_THRESHOLD_BYTES + 1];
    let mut drw = DeferredResponseWriter::new(Recorder::default(), "text/plain", 200, "");
    drw.write(&large).unwrap();
    drw.close().unwrap();
    let rec = drw.into_inner();
    assert!(rec.headers.get(header::CONTENT_ENCODING).is_none());
    assert_eq!(rec.body, large);
}

#[test]
fn gzip_response_negotiate_content_encoding() {
    let h = |v: Option<&'static str>| {
        let mut m = HeaderMap::new();
        if let Some(v) = v {
            m.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(v));
        }
        negotiate_content_encoding(&m)
    };
    assert_eq!(h(None), "");
    assert_eq!(h(Some("")), "");
    assert_eq!(h(Some("identity")), "");
    assert_eq!(h(Some("gzip")), "gzip");
    assert_eq!(h(Some("deflate, gzip")), "gzip");
    assert_eq!(h(Some("br,  gzip ,x")), "gzip");
    assert_eq!(h(Some("gzip;q=0.5")), "");
}
