//! Ports of `TestValidPodLogOptions` (pkg/apis/core/validation/validation_test.go:23340)
//! and the query conversion of `Convert_url_Values_To_v1_PodLogOptions`.

use std::collections::HashMap;

use chrono::Utc;
use kubernetes_rs_common::resources::pod::PodLogOptions;
use kubernetes_rs_common::validation::pod_subresource::validate_pod_log_options;

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

#[test]
fn pod_log_options_valid_table() {
    let now = Some(Utc::now());
    let o = PodLogOptions::default;
    #[allow(clippy::type_complexity)]
    let cases: Vec<(PodLogOptions, usize, bool)> = vec![
        (o(), 0, false),
        (
            PodLogOptions {
                previous: true,
                ..o()
            },
            0,
            false,
        ),
        (
            PodLogOptions {
                follow: true,
                ..o()
            },
            0,
            false,
        ),
        (
            PodLogOptions {
                tail_lines: Some(0),
                ..o()
            },
            0,
            false,
        ),
        (
            PodLogOptions {
                tail_lines: Some(-1),
                ..o()
            },
            1,
            false,
        ),
        (
            PodLogOptions {
                tail_lines: Some(1),
                ..o()
            },
            0,
            false,
        ),
        (
            PodLogOptions {
                limit_bytes: Some(0),
                ..o()
            },
            1,
            false,
        ),
        (
            PodLogOptions {
                limit_bytes: Some(-1),
                ..o()
            },
            1,
            false,
        ),
        (
            PodLogOptions {
                limit_bytes: Some(1),
                ..o()
            },
            0,
            false,
        ),
        (
            PodLogOptions {
                since_seconds: Some(-1),
                ..o()
            },
            1,
            false,
        ),
        (
            PodLogOptions {
                since_seconds: Some(1),
                ..o()
            },
            0,
            false,
        ),
        (
            PodLogOptions {
                since_seconds: Some(0),
                ..o()
            },
            1,
            false,
        ),
        (
            PodLogOptions {
                since_time: now,
                ..o()
            },
            0,
            false,
        ),
        (
            PodLogOptions {
                stream: s("Stdout"),
                ..o()
            },
            1,
            false,
        ),
        (
            PodLogOptions {
                stream: s("Stdout"),
                ..o()
            },
            0,
            true,
        ),
        (
            PodLogOptions {
                stream: s("invalid"),
                ..o()
            },
            1,
            true,
        ),
        (
            PodLogOptions {
                stream: s("Stderr"),
                tail_lines: Some(1),
                ..o()
            },
            1,
            true,
        ),
        (
            PodLogOptions {
                stream: s("All"),
                tail_lines: Some(1),
                ..o()
            },
            0,
            true,
        ),
        (
            PodLogOptions {
                stream: s("Stdout"),
                limit_bytes: Some(1),
                since_time: now,
                ..o()
            },
            0,
            true,
        ),
    ];
    for (i, (opt, errs, allow)) in cases.iter().enumerate() {
        let got = validate_pod_log_options(opt, *allow);
        assert_eq!(*errs, got.len(), "case {i}: {got:?}");
    }
}

#[test]
fn pod_log_options_messages() {
    let e = validate_pod_log_options(
        &PodLogOptions {
            since_seconds: Some(1),
            since_time: Some(Utc::now()),
            ..Default::default()
        },
        false,
    );
    assert_eq!(
        e[0].error_body(),
        "Forbidden: at most one of `sinceTime` or `sinceSeconds` may be specified"
    );
    let e = validate_pod_log_options(
        &PodLogOptions {
            limit_bytes: Some(0),
            ..Default::default()
        },
        false,
    );
    assert_eq!(
        e[0].error_body(),
        "Invalid value: 0: must be greater than 0"
    );
    let e = validate_pod_log_options(&PodLogOptions::default(), true);
    assert_eq!(e[0].error_body(), "Required value: must be specified");
}

#[test]
fn pod_log_options_from_query() {
    let q: HashMap<String, String> = [
        ("container", "c"),
        ("follow", "true"),
        ("previous", "false"),
        ("timestamps", "1"),
        ("tailLines", "10"),
        ("limitBytes", "5"),
        ("sinceSeconds", "3"),
        ("insecureSkipTLSVerifyBackend", "true"),
        ("stream", "Stderr"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let o = PodLogOptions::from_query(&q).unwrap();
    assert_eq!(o.container, "c");
    assert!(o.follow && !o.previous && o.timestamps && o.insecure_skip_tls_verify_backend);
    assert_eq!(
        (o.tail_lines, o.limit_bytes, o.since_seconds),
        (Some(10), Some(5), Some(3))
    );
    assert_eq!(o.stream.as_deref(), Some("Stderr"));
    let t: HashMap<String, String> =
        [("sinceTime".to_string(), "2024-01-02T03:04:05Z".to_string())].into();
    assert_eq!(
        PodLogOptions::from_query(&t)
            .unwrap()
            .since_time
            .unwrap()
            .to_rfc3339(),
        "2024-01-02T03:04:05+00:00"
    );
    let bad: HashMap<String, String> = [("tailLines".to_string(), "x".to_string())].into();
    assert!(PodLogOptions::from_query(&bad).is_err());
}
