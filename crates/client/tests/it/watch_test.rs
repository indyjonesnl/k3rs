use kubernetes_rs_client::watch::{parse_watch_line, WatchEvent};

#[test]
fn parses_added_modified_deleted_bookmark() {
    let added: WatchEvent<serde_json::Value> =
        parse_watch_line(r#"{"type":"ADDED","object":{"metadata":{"name":"a"}}}"#).unwrap();
    assert!(matches!(added, WatchEvent::Added(_)));
    let modified: WatchEvent<serde_json::Value> =
        parse_watch_line(r#"{"type":"MODIFIED","object":{}}"#).unwrap();
    assert!(matches!(modified, WatchEvent::Modified(_)));
    let deleted: WatchEvent<serde_json::Value> =
        parse_watch_line(r#"{"type":"DELETED","object":{}}"#).unwrap();
    assert!(matches!(deleted, WatchEvent::Deleted(_)));
    let bookmark: WatchEvent<serde_json::Value> =
        parse_watch_line(r#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"7"}}}"#)
            .unwrap();
    assert!(matches!(bookmark, WatchEvent::Bookmark(_)));
}

#[test]
fn rejects_garbage_line() {
    assert!(parse_watch_line::<serde_json::Value>("not json").is_err());
}

#[test]
fn error_envelope_surfaces_status_body() {
    // The api-server delivers compacted-RV failures as an in-stream ERROR
    // envelope (HTTP 200): {type:"ERROR", object:Status{code:410,
    // reason:"Expired", message:"too old resource version: X (Y)"}}.
    // parse_watch_line surfaces it as an ApiStatusError (apierrors.FromObject):
    // Display is the Status message (StatusError.Error()), the reason and
    // code are reachable through the api_status predicates.
    let line = r#"{"type":"ERROR","object":{"kind":"Status","status":"Failure","reason":"Expired","message":"too old resource version: 5 (100)","code":410}}"#;
    let err = parse_watch_line::<serde_json::Value>(line).unwrap_err();
    assert!(kubernetes_rs_client::api_status::is_resource_expired(&err));
    assert_eq!(err.to_string(), "too old resource version: 5 (100)");
}
