//! ETag support for aggregated discovery responses.
//!
//! Port of `staging/src/k8s.io/apiserver/pkg/endpoints/discovery/aggregated/etag.go`:
//! `calculateETag` (:90-97) and the header / conditional logic of
//! `ServeHTTPWithETag` (:41-86). Content negotiation and serialization
//! (`responsewriters.WriteObjectNegotiated`) stay with the caller: it passes
//! a closure that builds the 200 response.

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use serde::Serialize;
use sha2::{Digest, Sha512};

/// `calculateETag`: uppercase hex SHA-512 of the JSON serialization
/// (`fmt.Sprintf("%X", sha512.Sum512(serialized))`).
pub fn calculate_etag<T: Serialize>(resources: &T) -> Result<String, serde_json::Error> {
    let serialized = serde_json::to_vec(resources)?;
    let digest = Sha512::digest(&serialized);
    Ok(digest.iter().map(|b| format!("{b:02X}")).collect())
}

/// `ServeHTTPWithETag`: set `ETag` (quoted), `Vary: Accept` and
/// `Cache-Control: public`; reply `304 Not Modified` when `If-None-Match`
/// equals the quoted hash, else build the content with `ok`.
///
/// Like upstream, an empty `hash` is not special-cased in the code path: the
/// `ETag` is then `""`.
pub fn serve_with_etag(
    hash: &str,
    request_headers: &HeaderMap,
    ok: impl FnOnce() -> Response,
) -> Response {
    // ETag must be enclosed in double quotes (strconv.Quote of a hex string).
    let quoted_hash = format!("\"{hash}\"");

    let mut resp = if request_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|client| client == quoted_hash)
    {
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        r
    } else {
        ok()
    };
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&quoted_hash) {
        h.insert(header::ETAG, v);
    }
    h.insert(header::VARY, HeaderValue::from_static("Accept"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    fn ok() -> Response {
        (StatusCode::OK, "body").into_response()
    }

    /// `TestBasicResponse` / `TestEtagConsistency`: the tag is set, is
    /// deterministic and depends only on content.
    #[test]
    fn discovery_etag_is_deterministic_and_content_based() {
        let a = calculate_etag(&serde_json::json!({"a": [1, 2]})).unwrap();
        let b = calculate_etag(&serde_json::json!({"a": [1, 2]})).unwrap();
        let c = calculate_etag(&serde_json::json!({"a": [1, 3]})).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 128);
        assert!(a.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F')));
    }

    #[test]
    fn discovery_etag_known_sha512_vector() {
        // sha512("null"), computed independently (python hashlib).
        let got = calculate_etag(&serde_json::Value::Null).unwrap();
        assert_eq!(
            got,
            "04F8FF2682604862E405BF88DE102ED7710AC45C1205957625E4EE3E5F5A2241E453614ACC451345B91BAFC88F38804019C7492444595674E94E8CF4BE53817F"
        );
    }

    #[test]
    fn discovery_etag_headers_and_200() {
        let r = serve_with_etag("ABC", &HeaderMap::new(), ok);
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::ETAG], "\"ABC\"");
        assert_eq!(r.headers()[header::VARY], "Accept");
        assert_eq!(r.headers()[header::CACHE_CONTROL], "public");
    }

    #[test]
    fn discovery_etag_if_none_match_gives_304() {
        let mut h = HeaderMap::new();
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"ABC\""));
        let r = serve_with_etag("ABC", &h, || panic!("must not build content"));
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
        // headers still set on a 304
        assert_eq!(r.headers()[header::ETAG], "\"ABC\"");

        // unquoted / different tags do not match
        let mut h = HeaderMap::new();
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_static("ABC"));
        assert_eq!(serve_with_etag("ABC", &h, ok).status(), StatusCode::OK);
        let mut h = HeaderMap::new();
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"OLD\""));
        assert_eq!(serve_with_etag("ABC", &h, ok).status(), StatusCode::OK);
    }
}
