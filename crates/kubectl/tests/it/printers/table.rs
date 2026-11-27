//! Ports of cli-runtime/pkg/printers/tableprinter_test.go (TestPrintTable_*)
//! plus Table decoding and the Accept header.

use kubernetes_rs_kubectl::printers::table::*;
use serde_json::{json, Value};

fn col(name: &str, ty: &str, priority: i32) -> TableColumnDefinition {
    TableColumnDefinition {
        name: name.into(),
        type_: ty.into(),
        priority,
        ..Default::default()
    }
}

fn cols(retries_prio: i32, age_prio: i32) -> Vec<TableColumnDefinition> {
    vec![
        col("Name", "string", 0),
        col("Ready", "string", 0),
        col("Status", "string", 0),
        col("Retries", "integer", retries_prio),
        col("Age", "string", age_prio),
    ]
}

fn test_pod() -> Value {
    json!({"metadata": {"name": "test-pod-name", "namespace": "test-namespace",
        "labels": {"first-label": "12", "second-label": "label-value"}}})
}

fn row(name: &str, ready: &str, retries: i64, age: &str, obj: Option<Value>) -> TableRow {
    TableRow {
        cells: vec![
            json!(name),
            json!(ready),
            json!("podPhase"),
            json!(retries),
            json!(age),
        ],
        object: obj,
    }
}

fn print(columns: Vec<TableColumnDefinition>, rows: Vec<TableRow>, o: PrintOptions) -> String {
    let t = Table {
        column_definitions: columns,
        rows,
    };
    HumanReadablePrinter::new(o).print_table(t, "").unwrap()
}

#[test]
fn printers_table_missing_columns_rows() {
    assert_eq!(print(vec![], vec![], PrintOptions::default()), "");
    assert_eq!(print(cols(0, 0), vec![], PrintOptions::default()), "");
}

#[test]
fn printers_table_column_priority() {
    let r = vec![row("test1", "1/1", 5, "20h", None)];
    assert_eq!(
        print(cols(1, 1), r.clone(), PrintOptions::default()),
        "NAME    READY   STATUS\ntest1   1/1     podPhase\n"
    );
    let wide = PrintOptions {
        wide: true,
        ..Default::default()
    };
    assert_eq!(
        print(cols(1, 1), r, wide),
        "NAME    READY   STATUS     RETRIES   AGE\ntest1   1/1     podPhase   5         20h\n"
    );
}

#[test]
fn printers_table_column_headers_and_no_headers() {
    let r = vec![row("test1", "1/1", 5, "20h", None)];
    assert_eq!(
        print(cols(0, 0), r.clone(), PrintOptions::default()),
        "NAME    READY   STATUS     RETRIES   AGE\ntest1   1/1     podPhase   5         20h\n"
    );
    let nh = PrintOptions {
        no_headers: true,
        ..Default::default()
    };
    assert_eq!(
        print(cols(0, 0), r, nh),
        "test1   1/1   podPhase   5     20h\n"
    );
}

#[test]
fn printers_table_with_namespace() {
    let o = PrintOptions {
        with_namespace: true,
        ..Default::default()
    };
    assert_eq!(
        print(
            cols(0, 0),
            vec![row("test1", "1/1", 5, "20h", Some(test_pod()))],
            o
        ),
        "NAMESPACE        NAME    READY   STATUS     RETRIES   AGE\ntest-namespace   test1   1/1     podPhase   5         20h\n"
    );
}

#[test]
fn printers_table_with_kind() {
    let mut c = cols(0, 0);
    c[0].format = "name".into();
    let o = PrintOptions {
        with_kind: true,
        kind: Some("Pod".into()),
        ..Default::default()
    };
    assert_eq!(
        print(c, vec![row("test1", "1/1", 5, "20h", None)], o),
        "NAME        READY   STATUS     RETRIES   AGE\npod/test1   1/1     podPhase   5         20h\n"
    );
}

#[test]
fn printers_table_with_labels() {
    let r = vec![row("test1", "1/1", 5, "20h", Some(test_pod()))];
    let show = PrintOptions {
        show_labels: true,
        ..Default::default()
    };
    assert_eq!(
        print(cols(0, 0), r.clone(), show),
        "NAME    READY   STATUS     RETRIES   AGE   LABELS\ntest1   1/1     podPhase   5         20h   first-label=12,second-label=label-value\n"
    );
    let one = PrintOptions {
        column_labels: vec!["second-label".into()],
        ..Default::default()
    };
    assert_eq!(
        print(cols(0, 0), r.clone(), one),
        "NAME    READY   STATUS     RETRIES   AGE   SECOND-LABEL\ntest1   1/1     podPhase   5         20h   label-value\n"
    );
    let two = PrintOptions {
        column_labels: vec!["first-label".into(), "second-label".into()],
        ..Default::default()
    };
    assert_eq!(
        print(cols(0, 0), r, two),
        "NAME    READY   STATUS     RETRIES   AGE   FIRST-LABEL   SECOND-LABEL\ntest1   1/1     podPhase   5         20h   12            label-value\n"
    );
}

#[test]
fn printers_table_watch_events() {
    let t = || Table {
        column_definitions: cols(0, 0),
        rows: vec![row("test1", "1/1", 5, "20h", Some(test_pod()))],
    };
    let out = HumanReadablePrinter::new(PrintOptions::default())
        .print_table(t(), "Added")
        .unwrap();
    assert_eq!(
        out,
        "EVENT   NAME    READY   STATUS     RETRIES   AGE\nAdded   test1   1/1     podPhase   5         20h\n"
    );
    let o = PrintOptions {
        no_headers: true,
        with_namespace: true,
        show_labels: true,
        ..Default::default()
    };
    let out = HumanReadablePrinter::new(o)
        .print_table(t(), "Added")
        .unwrap();
    assert_eq!(
        out,
        "Added   test-namespace   test1   1/1   podPhase   5     20h   first-label=12,second-label=label-value\n"
    );
}

#[test]
fn printers_table_headers_once_and_columnless_watch_rows() {
    let mut p = HumanReadablePrinter::new(PrintOptions::default());
    let first = p
        .print_table(
            Table {
                column_definitions: cols(0, 0),
                rows: vec![row("a", "1/1", 1, "1h", None)],
            },
            "ADDED",
        )
        .unwrap();
    assert!(first.starts_with("EVENT"));
    // A later event without column definitions reuses the last ones, no header.
    let second = p
        .print_table(
            Table {
                column_definitions: vec![],
                rows: vec![row("b", "1/1", 2, "2h", None)],
            },
            "DELETED",
        )
        .unwrap();
    assert_eq!(second, "DELETED    b     1/1   podPhase   2     2h\n");
}

#[test]
fn printers_table_cell_truncation_and_escape() {
    let t = Table {
        column_definitions: vec![col("Name", "string", 0), col("Msg", "string", 0)],
        rows: vec![TableRow {
            cells: vec![json!("n"), json!("line1\nline2\x1b[0m")],
            object: None,
        }],
    };
    let out = HumanReadablePrinter::new(PrintOptions::default())
        .print_table(t, "")
        .unwrap();
    assert_eq!(out, "NAME   MSG\nn      line1...\n");
    let t = Table {
        column_definitions: vec![col("Msg", "string", 0)],
        rows: vec![TableRow {
            cells: vec![json!("a\x1b[0mb")],
            object: None,
        }],
    };
    let out = HumanReadablePrinter::new(PrintOptions::default())
        .print_table(t, "")
        .unwrap();
    assert_eq!(out, "MSG\na^[[0mb\n");
}

#[test]
fn printers_table_extra_cells_are_ignored() {
    // https://issue.k8s.io/66379: more cells than columns must not panic.
    let t = Table {
        column_definitions: vec![col("Name", "string", 0)],
        rows: vec![TableRow {
            cells: vec![json!("x"), json!("extra")],
            object: None,
        }],
    };
    let out = HumanReadablePrinter::new(PrintOptions::default())
        .print_table(t, "")
        .unwrap();
    assert_eq!(out, "NAME\nx\n");
}

#[test]
fn printers_table_decode_and_accept_header() {
    let v = json!({"kind": "Table", "apiVersion": "meta.k8s.io/v1",
        "columnDefinitions": [{"name": "Name", "type": "string", "format": "name", "priority": 0}],
        "rows": [{"cells": ["a"], "object": {"kind": "PartialObjectMetadata"}}]});
    let t = Table::from_value(&v).expect("table");
    assert_eq!(t.rows.len(), 1);
    assert_eq!(t.column_definitions[0].format, "name");
    let mut p = HumanReadablePrinter::new(PrintOptions::default());
    assert_eq!(p.print_value(&v).unwrap(), "NAME\na\n");
    // A plain list (server ignored the Accept header) is not a Table.
    assert!(Table::from_value(&json!({"kind": "PodList", "items": []})).is_none());
    assert!(p.print_value(&json!({"kind": "PodList"})).is_err());
    assert_eq!(
        TABLE_ACCEPT,
        "application/json;as=Table;v=v1;g=meta.k8s.io,application/json;as=Table;v=v1beta1;g=meta.k8s.io,application/json"
    );
}

/// TestPrintTable_NonTable (tableprinter_test.go:473-531).
#[test]
fn printers_table_non_table_fallbacks() {
    let pod = test_pod();
    let status = json!({"kind": "Status", "status": "Failure",
        "reason": "test-status-reason", "message": "test-status-message"});
    let cases: Vec<(Value, PrintOptions, &str)> = vec![
        (
            pod.clone(),
            PrintOptions::default(),
            "NAME            AGE\ntest-pod-name   <unknown>\n",
        ),
        (
            pod.clone(),
            PrintOptions {
                no_headers: true,
                ..Default::default()
            },
            "test-pod-name   <unknown>\n",
        ),
        (
            pod.clone(),
            PrintOptions {
                with_namespace: true,
                ..Default::default()
            },
            "NAMESPACE        NAME            AGE\ntest-namespace   test-pod-name   <unknown>\n",
        ),
        (
            pod.clone(),
            PrintOptions {
                show_labels: true,
                ..Default::default()
            },
            "NAME            AGE         LABELS\ntest-pod-name   <unknown>   first-label=12,second-label=label-value\n",
        ),
        (
            status.clone(),
            PrintOptions::default(),
            "STATUS    REASON               MESSAGE\nFailure   test-status-reason   test-status-message\n",
        ),
        (
            status,
            PrintOptions {
                no_headers: true,
                ..Default::default()
            },
            "Failure   test-status-reason   test-status-message\n",
        ),
    ];
    for (obj, opts, expected) in cases {
        let mut p = HumanReadablePrinter::new(opts);
        assert_eq!(p.print_object(&obj, "").unwrap(), expected);
    }
}

/// `lastType`: a header and a blank line when the handler changes, none when it repeats.
#[test]
fn printers_table_non_table_last_type() {
    let mut p = HumanReadablePrinter::new(PrintOptions::default());
    let pod = test_pod();
    let status = json!({"kind": "Status", "status": "Failure", "reason": "r", "message": "m"});
    let a = p.print_object(&pod, "").unwrap();
    let b = p.print_object(&pod, "").unwrap();
    let c = p.print_object(&status, "").unwrap();
    assert!(a.starts_with("NAME"));
    assert_eq!(b, "test-pod-name   <unknown>\n");
    assert!(c.starts_with("\nSTATUS"));
}

#[test]
fn printers_table_non_table_list_items() {
    let list = json!({"kind": "PodList", "items": [test_pod(), test_pod()]});
    let mut p = HumanReadablePrinter::new(PrintOptions::default());
    assert_eq!(
        p.print_object(&list, "").unwrap(),
        "NAME            AGE\ntest-pod-name   <unknown>\ntest-pod-name   <unknown>\n"
    );
}
