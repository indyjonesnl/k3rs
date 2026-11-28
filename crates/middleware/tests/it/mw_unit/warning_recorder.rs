//! Ports of `Test_recorder_AddWarning` and `TestTruncation`
//! (staging/src/k8s.io/apiserver/pkg/endpoints/filters/warning_test.go,
//! release-1.35), plus the request-context and layer behaviour.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn;
use axum::routing::get;
use axum::Router;
use kubernetes_rs_middleware::warning::*;
use tower::ServiceExt;

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn warning_recorder_add_warning() {
    type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, Vec<&'a str>);
    let cases: Vec<Case> = vec![
        ("empty", vec![], vec![]),
        ("empty values", vec![("", "")], vec![]),
        (
            "empty agent",
            vec![("", "mytext")],
            vec![r#"299 - "mytext""#],
        ),
        (
            "simple",
            vec![("myagent", "mytext")],
            vec![r#"299 myagent "mytext""#],
        ),
        (
            "duplicate text",
            vec![("myagent", "mytext"), ("myagent2", "mytext")],
            vec![r#"299 myagent "mytext""#],
        ),
        (
            "multiple",
            vec![("", "mytext1"), ("", "mytext2"), ("", "mytext3")],
            vec![
                r#"299 - "mytext1""#,
                r#"299 - "mytext2""#,
                r#"299 - "mytext3""#,
            ],
        ),
        ("invalid agent", vec![("my agent", "mytext")], vec![]),
        ("invalid text", vec![("myagent", "my\ntext")], vec![]),
        (
            "quotes escaped",
            vec![("", r#"say "hi" \o/"#)],
            vec![r#"299 - "say \"hi\" \\o/""#],
        ),
    ];
    for (name, args, expect) in cases {
        let r = WarningRecorder::default();
        for (agent, text) in args {
            r.add_warning(agent, text);
        }
        assert_eq!(r.headers(), strs(&expect), "{name}");
    }
}

#[test]
fn warning_recorder_truncation() {
    let r = WarningRecorder::with_limits(25, 5);
    r.add_warning("", "aaaaaaaaaa"); // long item
    r.add_warning("-", "aaaaaaaaaa"); // duplicate item
    r.add_warning("", "bb");
    r.add_warning("", "ccc");
    r.add_warning("", "Iñtërnâtiô"); // long item
    assert_eq!(
        r.headers(),
        strs(&[
            r#"299 - "aaaaaaaaaa""#,
            r#"299 - "bb""#,
            r#"299 - "ccc""#,
            r#"299 - "Iñtërnâtiô""#
        ])
    );
    // an item exceeding the length triggers truncation, reducing existing items to 15 runes
    r.add_warning("", "e"); // triggering item, 16 total
    r.add_warning("", "ffffffffff"); // truncated, 21 total
    r.add_warning("", "ffffffffff"); // duplicate
    r.add_warning("", "gggggggggg"); // truncated, 26 total
    r.add_warning("", "h"); // ignored: over the limit
    assert_eq!(
        r.headers(),
        strs(&[
            r#"299 - "aaaaa""#,
            r#"299 - "bb""#,
            r#"299 - "ccc""#,
            r#"299 - "Iñtër""#,
            r#"299 - "e""#,
            r#"299 - "fffff""#,
            r#"299 - "ggggg""#,
        ])
    );
}

#[test]
fn warning_recorder_new_warning_header() {
    assert_eq!(new_warning_header(299, "a", "t").unwrap(), r#"299 a "t""#);
    assert_eq!(new_warning_header(5, "", "t").unwrap(), r#"005 - "t""#);
    assert_eq!(
        new_warning_header(1000, "a", "t").unwrap_err(),
        "code must be between 0 and 999"
    );
    assert!(new_warning_header(-1, "a", "t").is_err());
    assert!(new_warning_header(299, "a\"b", "t").is_err());
    assert!(new_warning_header(299, "a\\b", "t").is_err());
}

#[tokio::test]
async fn warning_recorder_layer_writes_headers() {
    let app = Router::new()
        .route(
            "/",
            get(|req: Request<Body>| async move {
                add_warning(req.extensions(), "agent", "first");
                add_warning(req.extensions(), "agent", "first");
                add_warning(req.extensions(), "", "Iñtër");
                StatusCode::OK
            }),
        )
        .layer(from_fn(with_warning_recorder));
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let got: Vec<&[u8]> = resp
        .headers()
        .get_all("warning")
        .iter()
        .map(|v| v.as_bytes())
        .collect();
    assert_eq!(
        got,
        vec![&br#"299 agent "first""#[..], "299 - \"Iñtër\"".as_bytes()]
    );
}

#[test]
fn warning_recorder_no_recorder_is_noop() {
    add_warning(&axum::http::Extensions::new(), "a", "b");
}
