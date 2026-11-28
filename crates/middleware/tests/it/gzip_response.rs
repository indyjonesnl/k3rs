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

mod layer {
    use std::io::Read;

    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use axum::middleware::from_fn;
    use axum::response::Response;
    use axum::routing::get;
    use axum::Router;
    use flate2::read::GzDecoder;
    use kubernetes_rs_middleware::compression::{
        gzip_response_middleware, DEFAULT_GZIP_THRESHOLD_BYTES,
    };
    use tower::ServiceExt;

    fn json_body(n: usize) -> Vec<u8> {
        let mut v = br#"{"items":["#.to_vec();
        while v.len() < n {
            v.extend_from_slice(br#""aaaaaaaaaaaaaaaaaaaaaaaa","#);
        }
        v.extend_from_slice(br#""x"]}"#);
        v
    }

    fn app(body: Vec<u8>, content_type: &'static str) -> Router {
        Router::new()
            .route(
                "/",
                get(move || {
                    let body = body.clone();
                    async move {
                        Response::builder()
                            .header(header::CONTENT_TYPE, content_type)
                            .header(header::CONTENT_LENGTH, body.len())
                            .body(Body::from(body))
                            .unwrap()
                    }
                }),
            )
            .layer(from_fn(gzip_response_middleware))
    }

    async fn call(app: Router, accept_encoding: Option<&str>) -> Response {
        let mut b = Request::builder().uri("/");
        if let Some(a) = accept_encoding {
            b = b.header(header::ACCEPT_ENCODING, a);
        }
        app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn gzip_response_large_json_is_compressed() {
        let body = json_body(DEFAULT_GZIP_THRESHOLD_BYTES + 1000);
        let resp = call(app(body.clone(), "application/json"), Some("gzip")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(resp.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");
        // the stale uncompressed length is gone; axum sets the new one
        let cl = resp.headers().get(header::CONTENT_LENGTH).cloned();
        let gz = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        if let Some(cl) = cl {
            assert_eq!(cl.to_str().unwrap(), gz.len().to_string());
        }
        assert!(gz.len() < body.len());
        let mut out = Vec::new();
        GzDecoder::new(&gz[..]).read_to_end(&mut out).unwrap();
        assert_eq!(out, body);
    }

    #[tokio::test]
    async fn gzip_response_small_body_is_not_compressed() {
        let body = json_body(1000);
        let resp = call(app(body.clone(), "application/json"), Some("gzip")).await;
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
        assert!(resp.headers().get(header::VARY).is_none());
        let got = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&got[..], &body[..]);
    }

    #[tokio::test]
    async fn gzip_response_not_negotiated_is_plain() {
        let body = json_body(DEFAULT_GZIP_THRESHOLD_BYTES + 1000);
        for ae in [None, Some("identity"), Some("br")] {
            let resp = call(app(body.clone(), "application/json"), ae).await;
            assert!(
                resp.headers().get(header::CONTENT_ENCODING).is_none(),
                "{ae:?}"
            );
            let got = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(got.len(), body.len());
        }
    }

    #[tokio::test]
    async fn gzip_response_protobuf_is_compressed_and_other_types_are_not() {
        let body = json_body(DEFAULT_GZIP_THRESHOLD_BYTES + 1000);
        let resp = call(
            app(body.clone(), "application/vnd.kubernetes.protobuf"),
            Some("deflate, gzip"),
        )
        .await;
        assert_eq!(resp.headers()[header::CONTENT_ENCODING], "gzip");
        let resp = call(app(body, "text/plain"), Some("gzip")).await;
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn gzip_response_streaming_and_encoded_bodies_are_untouched() {
        // a watch: no exact size
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    Response::builder()
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(futures_stream())
                        .unwrap()
                }),
            )
            .layer(from_fn(gzip_response_middleware));
        let resp = call(app, Some("gzip")).await;
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());

        // already encoded
        let big = json_body(DEFAULT_GZIP_THRESHOLD_BYTES + 1000);
        let app = Router::new()
            .route(
                "/",
                get(move || {
                    let big = big.clone();
                    async move {
                        Response::builder()
                            .header(header::CONTENT_TYPE, "application/json")
                            .header(header::CONTENT_ENCODING, "br")
                            .body(Body::from(big))
                            .unwrap()
                    }
                }),
            )
            .layer(from_fn(gzip_response_middleware));
        let resp = call(app, Some("gzip")).await;
        assert_eq!(resp.headers()[header::CONTENT_ENCODING], "br");
    }

    fn futures_stream() -> Body {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(1);
        tokio::spawn(async move {
            let _tx = tx;
            std::future::pending::<()>().await;
        });
        Body::from_stream(futures::stream::poll_fn(move |cx| rx.poll_recv(cx)))
    }
}
