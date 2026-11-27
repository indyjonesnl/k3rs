//! Server-side Table printing for `kubectl get`.
//!
//! Port of k8s.io/cli-runtime/pkg/printers/tableprinter.go (release-1.35):
//! `HumanReadablePrinter.PrintObj` (Table branch), `printTable`, `decorateTable`,
//! `addColumns`, `formatLabelHeaders`, `appendLabelCells`, `formatEventType`;
//! tabwriter.go (`GetNewTabWriter`: minwidth 6, tabwidth 4, padding 3, ' ');
//! terminal.go (`WriteEscaped`); and `labels.FormatLabels`. The `Accept`
//! header is `GetOptions.transformRequests`
//! (staging/src/k8s.io/kubectl/pkg/cmd/get/get.go:424-433).
//!
//! Not ported yet: the non-Table fallbacks (`printObjectMeta`, `printStatus`)
//! and the `get` wiring; see backlog task kubectl-P1-06b.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `Accept` header sent for a human-readable `get` (get.go:429-433).
pub const TABLE_ACCEPT: &str = "application/json;as=Table;v=v1;g=meta.k8s.io,application/json;as=Table;v=v1beta1;g=meta.k8s.io,application/json";

/// tabwriter.go:26-30.
const TABWRITER_MIN_WIDTH: usize = 6;
const TABWRITER_PADDING: usize = 3;

/// `metav1.TableColumnDefinition`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TableColumnDefinition {
    pub name: String,
    #[serde(rename = "type", default)]
    pub type_: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub priority: i32,
}

/// `metav1.TableRow`; `object` is the `RawExtension` (usually
/// PartialObjectMetadata, the whole object with `includeObject=Object`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TableRow {
    #[serde(default)]
    pub cells: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<Value>,
}

/// `metav1.Table`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Table {
    #[serde(rename = "columnDefinitions", default)]
    pub column_definitions: Vec<TableColumnDefinition>,
    #[serde(default)]
    pub rows: Vec<TableRow>,
}

impl Table {
    /// Decode a server response when it is a `meta.k8s.io` Table (the
    /// negotiation succeeded); `None` for any other object (the server
    /// ignored the Accept header).
    pub fn from_value(v: &Value) -> Option<Table> {
        if v.get("kind").and_then(Value::as_str) != Some("Table") {
            return None;
        }
        let api = v.get("apiVersion").and_then(Value::as_str).unwrap_or("");
        if !api.starts_with("meta.k8s.io/") {
            return None;
        }
        serde_json::from_value(v.clone()).ok()
    }
}

/// `printers.PrintOptions` (the fields the Table path reads).
#[derive(Debug, Clone, Default)]
pub struct PrintOptions {
    pub no_headers: bool,
    pub with_namespace: bool,
    pub with_kind: bool,
    pub wide: bool,
    pub show_labels: bool,
    /// `Kind schema.GroupKind` rendered with `.String()` ("Pod", "Deployment.apps").
    pub kind: Option<String>,
    pub column_labels: Vec<String>,
}

/// `formatEventType` / `formattedEventType`.
pub fn format_event_type(event_type: &str) -> String {
    match event_type {
        "ADDED" => "ADDED   ".into(),
        "MODIFIED" => "MODIFIED".into(),
        "DELETED" => "DELETED ".into(),
        "ERROR" => "ERROR   ".into(),
        other => other.into(),
    }
}

/// `labels.FormatLabels`: sorted `k=v` joined with `,`, `<none>` when empty.
pub fn format_labels(labels: &BTreeMap<String, String>) -> String {
    if labels.is_empty() {
        return "<none>".into();
    }
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// `formatLabelHeaders`: last `/` segment, upper-cased.
fn format_label_headers(column_labels: &[String]) -> Vec<String> {
    column_labels
        .iter()
        .map(|l| l.rsplit('/').next().unwrap_or(l).to_uppercase())
        .collect()
}

/// The `meta.Accessor` view of a row object: namespace and labels.
fn accessor(row: &TableRow) -> Option<(String, BTreeMap<String, String>)> {
    let obj = row.object.as_ref()?;
    let meta = obj.get("metadata")?;
    let ns = meta
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let labels = meta
        .get("labels")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    Some((ns, labels))
}

/// `appendLabelCells`.
fn append_label_cells(
    values: &mut Vec<Value>,
    labels: &BTreeMap<String, String>,
    opts: &PrintOptions,
) {
    for key in &opts.column_labels {
        values.push(Value::String(labels.get(key).cloned().unwrap_or_default()));
    }
    if opts.show_labels {
        values.push(Value::String(format_labels(labels)));
    }
}

/// `decorateTable`: namespace column, label columns, `kind/name` prefix.
pub fn decorate_table(table: &mut Table, options: &PrintOptions) {
    let mut width = table.column_definitions.len() + options.column_labels.len();
    if options.with_namespace {
        width += 1;
    }
    if options.show_labels {
        width += 1;
    }

    let mut name_column: Option<usize> = None;
    if options.with_kind && options.kind.as_deref().is_some_and(|k| !k.is_empty()) {
        name_column = table
            .column_definitions
            .iter()
            .position(|c| c.format == "name" && c.type_ == "string");
    }

    if width != table.column_definitions.len() {
        let mut columns = Vec::with_capacity(width);
        let string_col = |name: String| TableColumnDefinition {
            name,
            type_: "string".into(),
            ..Default::default()
        };
        if options.with_namespace {
            columns.push(string_col("Namespace".into()));
        }
        columns.extend(table.column_definitions.iter().cloned());
        for label in format_label_headers(&options.column_labels) {
            columns.push(string_col(label));
        }
        if options.show_labels {
            columns.push(string_col("Labels".into()));
        }
        table.column_definitions = columns;
    }

    let include_labels = !options.column_labels.is_empty() || options.show_labels;
    if include_labels || options.with_namespace || name_column.is_some() {
        for row in &mut table.rows {
            if let Some(nc) = name_column {
                if let Some(cell) = row.cells.get(nc) {
                    let kind = options.kind.as_deref().unwrap_or("").to_lowercase();
                    row.cells[nc] = Value::String(format!("{kind}/{}", cell_string(cell)));
                }
            }
            match accessor(row) {
                // No accessor: pad the row with empty cells.
                None => {
                    if options.with_namespace {
                        row.cells.insert(0, Value::Null);
                    }
                    while row.cells.len() < width {
                        row.cells.push(Value::Null);
                    }
                }
                Some((ns, labels)) => {
                    if options.with_namespace {
                        row.cells.insert(0, Value::String(ns));
                    }
                    if include_labels {
                        append_label_cells(&mut row.cells, &labels, options);
                    }
                }
            }
        }
    }
}

/// `fmt.Sprint(cell)` for a decoded JSON cell.
fn cell_string(cell: &Value) -> String {
    match cell {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `terminal.go` `terminalEscaper`: ESC -> `^[`, CR -> `\r`.
fn write_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '\x1b' => out.push_str("^["),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
}

/// `printTable`: headers (priority 0 columns, all with `wide`) and rows.
pub fn print_table(table: &Table, options: &PrintOptions) -> String {
    let mut out = String::new();
    let cols = &table.column_definitions;
    if !options.no_headers {
        // Avoid printing headers if we have no rows to display.
        if table.rows.is_empty() {
            return out;
        }
        let names: Vec<String> = cols
            .iter()
            .filter(|c| options.wide || c.priority == 0)
            .map(|c| c.name.to_uppercase())
            .collect();
        out.push_str(&names.join("\t"));
        out.push('\n');
    }
    for row in &table.rows {
        let mut first = true;
        for (i, cell) in row.cells.iter().enumerate() {
            // https://issue.k8s.io/66379: ignore cells beyond the columns.
            let Some(column) = cols.get(i) else { break };
            if !options.wide && column.priority != 0 {
                continue;
            }
            if !first {
                out.push('\t');
            }
            first = false;
            match cell {
                Value::Null => {}
                Value::String(val) => {
                    // Truncate at the first newline, carriage return or
                    // formfeed (treated as a newline by tabwriter).
                    match val.find(['\x0c', '\n', '\r']) {
                        Some(i) => {
                            write_escaped(&mut out, &val[..i]);
                            out.push_str("...");
                        }
                        None => write_escaped(&mut out, val),
                    }
                }
                other => write_escaped(&mut out, &cell_string(other)),
            }
        }
        out.push('\n');
    }
    out
}

/// `addColumns` at the beginning (used for the watch `EVENT` column).
fn prepend_column(table: &mut Table, column: TableColumnDefinition, value: &str) {
    for row in &mut table.rows {
        row.cells.insert(0, Value::String(value.to_string()));
    }
    table.column_definitions.insert(0, column);
}

/// The Table branch of `HumanReadablePrinter`: remembers the last columns so
/// watch events that carry no column definitions reuse them and headers are
/// printed once per distinct column set.
#[derive(Debug, Default)]
pub struct HumanReadablePrinter {
    options: PrintOptions,
    last_columns: Vec<TableColumnDefinition>,
    printed_headers: bool,
}

impl HumanReadablePrinter {
    /// `NewTablePrinter`.
    pub fn new(options: PrintOptions) -> Self {
        Self {
            options,
            ..Default::default()
        }
    }

    /// `PrintObj` for a Table (optionally from a watch event of `event_type`).
    /// Returns the tab-aligned text.
    pub fn print_table(&mut self, mut table: Table, event_type: &str) -> Result<String> {
        let mut local = self.options.clone();
        if self.printed_headers
            && (table.column_definitions.is_empty()
                || table.column_definitions == self.last_columns)
        {
            local.no_headers = true;
        }
        if table.column_definitions.is_empty() {
            // Watch events omit the columns to save bandwidth.
            table.column_definitions = self.last_columns.clone();
        } else if table.column_definitions != self.last_columns {
            self.last_columns = table.column_definitions.clone();
            self.printed_headers = false;
        }
        if !table.rows.is_empty() {
            self.printed_headers = true;
        }
        decorate_table(&mut table, &local);
        if !event_type.is_empty() {
            prepend_column(
                &mut table,
                TableColumnDefinition {
                    name: "Event".into(),
                    type_: "string".into(),
                    ..Default::default()
                },
                &format_event_type(event_type),
            );
        }
        Ok(tab_format(&print_table(&table, &local)))
    }

    /// Print a server response that must be a Table.
    pub fn print_value(&mut self, v: &Value) -> Result<String> {
        match Table::from_value(v) {
            Some(t) => self.print_table(t, ""),
            None => bail!("server response is not a meta.k8s.io Table"),
        }
    }
}

/// `GetNewTabWriter` formatting (text/tabwriter semantics: minwidth 6,
/// padding 3, padchar ' '). A cell is tab-terminated; the trailing text of a
/// line is not part of any column. A column block is a run of consecutive
/// lines that have a terminated cell in that column.
pub fn tab_format(input: &str) -> String {
    let lines: Vec<Vec<&str>> = input
        .split_inclusive('\n')
        .map(|l| l.strip_suffix('\n').unwrap_or(l).split('\t').collect())
        .collect();
    let mut widths: Vec<Vec<usize>> = lines.iter().map(|l| vec![0; l.len()]).collect();
    // Terminated cells of a line: all but the last field.
    fn compute(lines: &[Vec<&str>], widths: &mut [Vec<usize>], from: usize, to: usize, col: usize) {
        let mut i = from;
        while i < to {
            if lines[i].len() <= col + 1 {
                i += 1;
                continue;
            }
            let start = i;
            let mut w = 0;
            while i < to && lines[i].len() > col + 1 {
                w = w.max(lines[i][col].chars().count() + TABWRITER_PADDING);
                i += 1;
            }
            let w = w.max(TABWRITER_MIN_WIDTH);
            for wl in widths.iter_mut().take(i).skip(start) {
                wl[col] = w;
            }
            compute(lines, widths, start, i, col + 1);
        }
    }
    compute(&lines, &mut widths, 0, lines.len(), 0);
    let mut out = String::new();
    for (l, line) in lines.iter().enumerate() {
        for (c, cell) in line.iter().enumerate() {
            out.push_str(cell);
            if c + 1 < line.len() {
                for _ in cell.chars().count()..widths[l][c] {
                    out.push(' ');
                }
            }
        }
        out.push('\n');
    }
    out
}
