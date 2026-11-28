//! `limitedReadBody` (apiserver/pkg/endpoints/handlers/rest.go:372-390) and the
//! default `MaxRequestBodyBytes` (server/config.go:466) in the middleware.
use axum::body::Body;
use kubernetes_rs_middleware::{limited_read_request_body, MAX_REQUEST_BODY_BYTES};

async fn status_of(resp: axum::response::Response) -> (u16, serde_json::Value) {
    let code = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (code, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn body_limit_mw_constant_is_three_mib() {
    assert_eq!(MAX_REQUEST_BODY_BYTES, 3145728);
}

#[tokio::test]
async fn body_limit_mw_body_over_limit_is_413() {
    let big = vec![0u8; MAX_REQUEST_BODY_BYTES as usize + 1];
    let err = limited_read_request_body(Body::from(big), MAX_REQUEST_BODY_BYTES)
        .await
        .unwrap_err();
    let (code, v) = status_of(err).await;
    assert_eq!(code, 413);
    assert_eq!(v["reason"], "RequestEntityTooLarge");
    assert_eq!(v["message"], "Request entity too large: limit is 3145728");
}

#[tokio::test]
async fn body_limit_mw_body_at_limit_is_read() {
    let ok = vec![7u8; MAX_REQUEST_BODY_BYTES as usize];
    let got = limited_read_request_body(Body::from(ok), MAX_REQUEST_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(got.len(), MAX_REQUEST_BODY_BYTES as usize);
}

#[tokio::test]
async fn body_limit_mw_non_positive_limit_reads_everything() {
    let got = limited_read_request_body(Body::from(vec![1u8; 100]), 0)
        .await
        .unwrap();
    assert_eq!(got.len(), 100);
}

#[tokio::test]
async fn body_limit_mw_stream_is_not_read_past_limit_plus_one() {
    // An endless stream must be refused, not buffered whole.
    let stream = futures::stream::repeat_with(|| Ok::<_, std::io::Error>(vec![0u8; 1024]));
    let err = limited_read_request_body(Body::from_stream(stream), 4096)
        .await
        .unwrap_err();
    assert_eq!(err.status().as_u16(), 413);
}
