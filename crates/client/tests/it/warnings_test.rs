//! Ports of `apimachinery/pkg/util/net/http_test.go` (TestParseWarningHeader,
//! TestParseWarningHeaders) and `client-go/rest/warnings_test.go`
//! (TestWarningWriter / default handler). Non-UTF-8 byte cases cannot be
//! expressed with `&str` and are not ported.

use kubernetes_rs_client::warnings::*;
use std::sync::{Arc, Mutex};

fn wh(code: i32, text: &str) -> WarningHeader {
    WarningHeader {
        code,
        agent: "-".into(),
        text: text.into(),
    }
}

#[test]
fn warnings_parse_header_errors() {
    let cases = [
        ("", "fewer than 3 segments"),
        ("A B", "fewer than 3 segments"),
        (r#"1 - "text""#, "not 3 digits"),
        (r#"A - "text""#, "not 3 digits"),
        (
            r#"  299 - "text\"\\\a\b\c"  "Tue, 15 Nov 1994 08:12:31 GMT "#,
            "unterminated date segment",
        ),
        (
            r#"  299 - "text\"\\\a\b\c"  "Tue, 15 Nov 1994 08:12:31 GMT" other"#,
            "unexpected token after warn-date",
        ),
        ("  299 agent\u{0}name \"text\"", "invalid agent"),
        ("  299 - \"text\u{0}\"content", "invalid text"),
    ];
    for (h, want) in cases {
        let e = parse_warning_header(h).unwrap_err();
        assert!(e.contains(want), "{h:?}: {e} !~ {want}");
    }
}

#[test]
fn warnings_parse_header_ok() {
    let cases: Vec<(&str, WarningHeader, &str)> = vec![
        (r#"299 - "text""#, wh(299, "text"), ""),
        (r#"299 - "text\"\\\a\b\c""#, wh(299, r#"text"\abc"#), ""),
        (r#"321 - "text""#, wh(321, "text"), ""),
        (
            r#"299 - "=?iso-8859-1?q?this=20is=20some=20text?=""#,
            wh(299, "this is some text"),
            "",
        ),
        (
            r#"299 - "=?UTF-8?B?VGhpcyBpcyBhIGhvcnNleTog8J+Qjg==?= And =?UTF-8?B?VGhpcyBpcyBhIGhvcnNleTog8J+Qjg==?=""#,
            wh(
                299,
                "This is a horsey: \u{1f40e} And This is a horsey: \u{1f40e}",
            ),
            "",
        ),
        (
            r#"299 - "=?UTF-8?Q?This is a \"horsey\": =F0=9F=90=8E?=""#,
            wh(299, "This is a \"horsey\": \u{1f40e}"),
            "",
        ),
        (
            r#"299 - "=?UTF-9?Q?This is a horsey: =F0=9F=90=8E?=""#,
            wh(299, "=?UTF-9?Q?This is a horsey: =F0=9F=90=8E?="),
            "",
        ),
        (r#"  299 - "text\"\\\a\b\c"  "#, wh(299, r#"text"\abc"#), ""),
        (
            r#"  299 - "text\"\\\a\b\c"  "Tue, 15 Nov 1994 08:12:31 GMT" "#,
            wh(299, r#"text"\abc"#),
            "",
        ),
        (
            r#"  299 - "text\"\\\a\b\c"  "Tue, 15 Nov 1994 08:12:31 GMT" , "#,
            wh(299, r#"text"\abc"#),
            "",
        ),
        (
            r#"  299 - "text\"\\\a\b\c"  , "#,
            wh(299, r#"text"\abc"#),
            "",
        ),
        (
            r#"  299 - "text\"\\\a\b\c"  "Tue, 15 Nov 1994 08:12:31 GMT" , remainder "#,
            wh(299, r#"text"\abc"#),
            "remainder",
        ),
        (
            r#"  299 - "text\"\\\a\b\c"  ,remainder text,second remainder"#,
            wh(299, r#"text"\abc"#),
            "remainder text,second remainder",
        ),
        (
            " 299 - \"Test of I\u{f1}t\u{eb}rn\u{e2}ti\u{f4}n\u{e0}liz\u{e6}ti\u{f8}n,\u{1f49d}\" ",
            wh(
                299,
                "Test of I\u{f1}t\u{eb}rn\u{e2}ti\u{f4}n\u{e0}liz\u{e6}ti\u{f8}n,\u{1f49d}",
            ),
            "",
        ),
    ];
    for (h, want, rem) in cases {
        let (got, r) = parse_warning_header(h).unwrap_or_else(|e| panic!("{h:?}: {e}"));
        assert_eq!(got, want, "{h:?}");
        assert_eq!(r, rem, "{h:?}");
    }
}

#[test]
fn warnings_parse_headers_multi_with_error() {
    let (none, errs) = parse_warning_headers(&[]);
    assert!(none.is_empty() && errs.is_empty());
    let headers: Vec<String> = [
        r#"299 - "warning 1.1",299 - "warning 1.2""#,
        r#"299 - "warning 2", 299 - "warning unquoted"#,
        r#" 299 - "warning 3.1" ,  299 - "warning 3.2" "#,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let (got, errs) = parse_warning_headers(&headers);
    assert_eq!(
        got,
        vec![
            wh(299, "warning 1.1"),
            wh(299, "warning 1.2"),
            wh(299, "warning 2"),
            wh(299, "warning 3.1"),
            wh(299, "warning 3.2"),
        ]
    );
    assert_eq!(
        errs,
        vec!["invalid warning header: invalid quoted string: missing closing quote"]
    );
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn warnings_writer_dedupe_color_and_count() {
    let buf = Buf::default();
    let w = WarningWriter::new(
        buf.clone(),
        WarningWriterOptions {
            deduplicate: true,
            color: false,
        },
    );
    w.handle_warning_header(299, "-", "a");
    w.handle_warning_header(299, "-", "a");
    w.handle_warning_header(299, "-", "b");
    w.handle_warning_header(199, "-", "ignored");
    w.handle_warning_header(299, "-", "");
    assert_eq!(w.warning_count(), 2);
    assert_eq!(
        String::from_utf8(buf.0.lock().unwrap().clone()).unwrap(),
        "Warning: a\nWarning: b\n"
    );

    let buf = Buf::default();
    let w = WarningWriter::new(
        buf.clone(),
        WarningWriterOptions {
            deduplicate: false,
            color: true,
        },
    );
    w.handle_warning_header(299, "-", "a");
    w.handle_warning_header(299, "-", "a");
    assert_eq!(w.warning_count(), 2);
    assert_eq!(
        String::from_utf8(buf.0.lock().unwrap().clone()).unwrap(),
        "\u{1b}[33;1mWarning:\u{1b}[0m a\n\u{1b}[33;1mWarning:\u{1b}[0m a\n"
    );
}

#[test]
fn warnings_handle_warnings_feeds_handler() {
    let buf = Buf::default();
    let w = WarningWriter::new(buf.clone(), WarningWriterOptions::default());
    let parsed = handle_warnings(&[r#"299 - "x", 299 - "y""#.to_string()], Some(&w));
    assert_eq!(parsed.len(), 2);
    assert_eq!(w.warning_count(), 2);
    // NoWarnings discards.
    handle_warnings(&[r#"299 - "x""#.to_string()], Some(&NoWarnings));
}

// TestDefaultWarningHandler: a default exists; it can be replaced and cleared.
#[test]
fn warnings_default_handler_set_and_clear() {
    assert!(get_default_warning_handler().is_some());
    let buf = Buf::default();
    let w = Arc::new(WarningWriter::new(
        buf.clone(),
        WarningWriterOptions::default(),
    ));
    set_default_warning_handler(Some(w.clone()));
    handle_warnings(&[r#"299 - "via default""#.to_string()], None);
    assert_eq!(w.warning_count(), 1);
    set_default_warning_handler(None);
    assert!(get_default_warning_handler().is_none());
    set_default_warning_handler(Some(Arc::new(WarningLogger)));
}
