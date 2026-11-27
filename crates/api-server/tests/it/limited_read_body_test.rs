//! Port of `TestLimitedReadBody` (endpoints/handlers/rest_test.go:115) for
//! `limited_read_body`, plus the 413 Status shape of
//! `errors.NewRequestEntityTooLargeError("limit is 3145728")`.

use axum::body::Body;
use kubernetes_rs_api_server::endpoints::handlers::rest::{
    check_body_limit, limited_read_body, MAX_REQUEST_BODY_BYTES,
};
use kubernetes_rs_common::Error;

fn status_of(e: Error) -> (u16, String, String) {
    match e {
        Error::Status(s) => (s.code.unwrap(), s.reason.unwrap(), s.message.unwrap()),
        other => panic!("expected a Status error, got {other:?}"),
    }
}

#[tokio::test]
async fn limited_read_body_aaaa_with_limit_1_is_refused() {
    let err = limited_read_body(Body::from("aaaa"), 1).await.unwrap_err();
    let (code, reason, msg) = status_of(err);
    assert_eq!(code, 413);
    assert_eq!(reason, "RequestEntityTooLarge");
    assert_eq!(msg, "Request entity too large: limit is 1");
}

#[tokio::test]
async fn limited_read_body_aaaa_with_limit_5_is_read() {
    let data = limited_read_body(Body::from("aaaa"), 5).await.unwrap();
    assert_eq!(&data[..], b"aaaa");
}

#[tokio::test]
async fn limited_read_body_exactly_at_limit_passes_and_one_over_fails() {
    assert!(limited_read_body(Body::from("aaaa"), 4).await.is_ok());
    assert!(limited_read_body(Body::from("aaaaa"), 4).await.is_err());
}

#[tokio::test]
async fn limited_read_body_non_positive_limit_is_unbounded() {
    let data = limited_read_body(Body::from(vec![b'a'; 4096]), 0)
        .await
        .unwrap();
    assert_eq!(data.len(), 4096);
}

#[tokio::test]
async fn limited_read_body_stops_reading_past_the_limit() {
    // An endless stream must not be buffered whole.
    let endless = futures::stream::repeat_with(|| Ok::<_, std::io::Error>(vec![b'x'; 1024]));
    let err = limited_read_body(Body::from_stream(endless), 3000)
        .await
        .unwrap_err();
    assert_eq!(status_of(err).0, 413);
}

#[test]
fn limited_read_body_default_limit_message_is_3_mib() {
    assert_eq!(MAX_REQUEST_BODY_BYTES, 3145728);
    let big = vec![0u8; MAX_REQUEST_BODY_BYTES as usize + 1];
    let (_, _, msg) = status_of(check_body_limit(&big, MAX_REQUEST_BODY_BYTES).unwrap_err());
    assert_eq!(msg, "Request entity too large: limit is 3145728");
    assert!(check_body_limit(&big[..big.len() - 1], MAX_REQUEST_BODY_BYTES).is_ok());
}
