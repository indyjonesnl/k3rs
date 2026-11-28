//! `cel/validator.go` `homogeneousAggregateLiteralValidator`: the AST
//! validator `cel.HomogeneousAggregateLiterals()` installs
//! (`cel/options.go`), which the Kubernetes environment has from the base
//! options (`environment/base.go:63-69`).
//!
//! It is not part of the type check: `Env.Check` (`cel/env.go:344-385`) runs
//! the validators only on a type-check result without errors, over the final
//! type map (type parameters already substituted, so an unbound `_var0` is
//! `dyn` in its messages), and reports through `Issues.ReportErrorAtID`. The
//! checker itself joins mixed element types to `dyn` (`joinTypes` with
//! `dynElementType`).

use crate::checker::CheckedAst;
use crate::errors::{Errors, Locator};
use crate::types::DType;
use cel::common::ast::{EntryExpr, Expr, IdedExpr, LiteralValue};

/// `ValidatorConfig` for this validator: the functions whose arguments may
/// hold mixed literals (`HomogeneousAggregateLiteralExemptFunctions`, which
/// `ext.Strings` adds `format` to from `StringsVersion(1)`).
#[derive(Clone, Debug, Default)]
pub struct HomogeneousConfig {
    pub exempt_functions: Vec<String>,
}

/// `Type.IsEquivalentType`: the same kind, name and parameters, ignoring the
/// names of type parameters.
fn equivalent(a: &DType, b: &DType) -> bool {
    match (a, b) {
        (DType::Param(_), DType::Param(_)) => true,
        (DType::Type(x), DType::Type(y)) => match (x, y) {
            (Some(x), Some(y)) => equivalent(x, y),
            (None, None) => true,
            _ => false,
        },
        (DType::List(x), DType::List(y)) => equivalent(x, y),
        (DType::Map(k1, v1), DType::Map(k2, v2)) => equivalent(k1, k2) && equivalent(v1, v2),
        (DType::Opaque(n1, p1), DType::Opaque(n2, p2)) => {
            n1 == n2 && p1.len() == p2.len() && p1.iter().zip(p2).all(|(x, y)| equivalent(x, y))
        }
        _ => a == b,
    }
}

/// Runs the validator over `expr`, reporting into `errors`.
pub fn validate_homogeneous_literals(
    expr: &IdedExpr,
    checked: &CheckedAst,
    config: &HomogeneousConfig,
    loc: &dyn Locator,
    errors: &mut Errors,
) {
    let mut lists = Vec::new();
    let mut maps = Vec::new();
    collect(expr, config, false, &mut lists, &mut maps);
    let ty = |id: u64| checked.type_map.get(&id).cloned().unwrap_or(DType::Error);
    let report = |errors: &mut Errors, id: u64, expected: &DType, actual: &DType| {
        errors.type_mismatch(id, loc, expected, actual);
    };
    // `ast.MatchDescendants(root, KindMatcher(ListKind))`, then maps.
    for l in lists {
        let Expr::List(list) = &l.expr else { continue };
        let mut elem: Option<DType> = None;
        for (i, e) in list.elements.iter().enumerate() {
            let mut et = ty(e.id);
            if list.optional_indices.contains(&i) {
                // `et.Parameters()[0]`.
                et = match &et {
                    DType::Opaque(_, ps) if !ps.is_empty() => ps[0].clone(),
                    other => other.clone(),
                };
            }
            match &elem {
                None => elem = Some(et),
                Some(first) => {
                    if !equivalent(first, &et) {
                        report(errors, e.id, first, &et);
                        break;
                    }
                }
            }
        }
    }
    for m in maps {
        let Expr::Map(map) = &m.expr else { continue };
        let mut first: Option<(DType, DType)> = None;
        for entry in &map.entries {
            let EntryExpr::MapEntry(me) = &entry.expr else {
                continue;
            };
            let kt = ty(me.key.id);
            let mut vt = ty(me.value.id);
            if me.optional {
                vt = match &vt {
                    DType::Opaque(_, ps) if !ps.is_empty() => ps[0].clone(),
                    other => other.clone(),
                };
            }
            match &first {
                None => first = Some((kt, vt)),
                Some((fk, fv)) => {
                    if !equivalent(fk, &kt) {
                        report(errors, me.key.id, fk, &kt);
                    }
                    if !equivalent(fv, &vt) {
                        report(errors, me.value.id, fv, &vt);
                    }
                }
            }
        }
    }
}

/// The list and map literals under `e`, in pre-order, leaving out those with
/// an exempt function among their ancestors (`inExemptFunction`).
fn collect<'a>(
    e: &'a IdedExpr,
    config: &HomogeneousConfig,
    exempt: bool,
    lists: &mut Vec<&'a IdedExpr>,
    maps: &mut Vec<&'a IdedExpr>,
) {
    match &e.expr {
        Expr::List(l) => {
            if !exempt {
                lists.push(e);
            }
            for c in &l.elements {
                collect(c, config, exempt, lists, maps);
            }
        }
        Expr::Map(m) => {
            if !exempt {
                maps.push(e);
            }
            for entry in &m.entries {
                if let EntryExpr::MapEntry(me) = &entry.expr {
                    collect(&me.key, config, exempt, lists, maps);
                    collect(&me.value, config, exempt, lists, maps);
                }
            }
        }
        Expr::Call(c) => {
            let exempt = exempt || config.exempt_functions.contains(&c.func_name);
            if let Some(t) = &c.target {
                collect(t, config, exempt, lists, maps);
            }
            for a in &c.args {
                collect(a, config, exempt, lists, maps);
            }
        }
        Expr::Select(s) => collect(&s.operand, config, exempt, lists, maps),
        Expr::Struct(s) => {
            for entry in &s.entries {
                if let EntryExpr::StructField(f) = &entry.expr {
                    collect(&f.value, config, exempt, lists, maps);
                }
            }
        }
        Expr::Comprehension(c) => {
            for part in [
                &c.iter_range,
                &c.accu_init,
                &c.loop_cond,
                &c.loop_step,
                &c.result,
            ] {
                collect(part, config, exempt, lists, maps);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// ValidateDurationLiterals / ValidateTimestampLiterals / ValidateRegexLiterals
// ---------------------------------------------------------------------------

/// `formatValidator.Validate` (cel/validator.go:231-262) for `duration`,
/// `timestamp` and `matches` (`ValidateDurationLiterals`,
/// `ValidateTimestampLiterals`, `ValidateRegexLiterals`, :191-204), in that
/// order: every call of the function whose first argument is a literal is
/// evaluated (regex: compiled) and an invalid one is reported at the literal
/// as `invalid <function> argument`.
///
/// `evalCall` evaluates the `duration(..)` / `timestamp(..)` call itself; a
/// literal can only fail through the string conversions
/// (`types.String.ConvertToType`: `time.ParseDuration`, `time.Parse(RFC3339)`
/// plus the timestamp range) and the int-to-timestamp range, which is what
/// [`duration_literal_ok`] / [`timestamp_literal_ok`] check. `matches`
/// compiles the literal with the `regex` crate for Go's `regexp.Compile`
/// (RE2 syntax; the two accept the same language for patterns users write).
pub fn validate_format_literals(expr: &IdedExpr, loc: &dyn Locator, errors: &mut Errors) {
    type Check = fn(&LiteralValue) -> bool;
    let validators: [(&str, Check); 3] = [
        ("duration", duration_literal_ok),
        ("timestamp", timestamp_literal_ok),
        ("matches", regex_literal_ok),
    ];
    for (func, check) in validators {
        let mut calls = Vec::new();
        collect_calls(expr, func, &mut calls);
        for call in calls {
            let Expr::Call(c) = &call.expr else { continue };
            let Some(arg) = c.args.first() else { continue };
            let Expr::Literal(lit) = &arg.expr else {
                continue;
            };
            if !check(lit) {
                errors.at_id(arg.id, loc, format!("invalid {func} argument"));
            }
        }
    }
}

/// `ast.MatchDescendants(root, ast.FunctionMatcher(name))`: pre-order.
fn collect_calls<'a>(e: &'a IdedExpr, name: &str, out: &mut Vec<&'a IdedExpr>) {
    match &e.expr {
        Expr::Call(c) => {
            if c.func_name == name {
                out.push(e);
            }
            if let Some(t) = &c.target {
                collect_calls(t, name, out);
            }
            for a in &c.args {
                collect_calls(a, name, out);
            }
        }
        Expr::List(l) => {
            for c in &l.elements {
                collect_calls(c, name, out);
            }
        }
        Expr::Map(m) => {
            for entry in &m.entries {
                if let EntryExpr::MapEntry(me) = &entry.expr {
                    collect_calls(&me.key, name, out);
                    collect_calls(&me.value, name, out);
                }
            }
        }
        Expr::Select(s) => collect_calls(&s.operand, name, out),
        Expr::Struct(s) => {
            for entry in &s.entries {
                if let EntryExpr::StructField(f) = &entry.expr {
                    collect_calls(&f.value, name, out);
                }
            }
        }
        Expr::Comprehension(c) => {
            for part in [
                &c.iter_range,
                &c.accu_init,
                &c.loop_cond,
                &c.loop_step,
                &c.result,
            ] {
                collect_calls(part, name, out);
            }
        }
        _ => {}
    }
}

/// `minUnixTime` / `maxUnixTime` (common/types/timestamp.go:50-52): the
/// seconds of `0001-01-01T00:00:00Z` and `9999-12-31T23:59:59Z`.
const MIN_UNIX_TIME: i64 = -62_135_596_800;
const MAX_UNIX_TIME: i64 = 253_402_300_799;

fn duration_literal_ok(lit: &LiteralValue) -> bool {
    match lit {
        LiteralValue::String(s) => go_parse_duration_ok(s.inner()),
        // `Int.ConvertToType(DurationType)` cannot fail.
        _ => true,
    }
}

fn timestamp_literal_ok(lit: &LiteralValue) -> bool {
    match lit {
        LiteralValue::String(s) => go_parse_rfc3339_unix(s.inner())
            .is_some_and(|t| (MIN_UNIX_TIME..=MAX_UNIX_TIME).contains(&t)),
        // `Int.ConvertToType(TimestampType)`: the Unix time must be in range.
        LiteralValue::Int(i) => (MIN_UNIX_TIME..=MAX_UNIX_TIME).contains(i.inner()),
        _ => true,
    }
}

fn regex_literal_ok(lit: &LiteralValue) -> bool {
    match lit {
        LiteralValue::String(s) => regex::Regex::new(s.inner()).is_ok(),
        _ => true,
    }
}

/// Whether Go's `time.ParseDuration` accepts `orig` (time/format.go): an
/// optional sign, then one or more `<number><unit>` terms (`ns us µs μs ms s
/// m h`, the number with an optional fraction), or exactly `0`; the total
/// must fit in an int64 of nanoseconds.
pub(crate) fn go_parse_duration_ok(orig: &str) -> bool {
    const LIMIT: u64 = 1 << 63;
    let mut s = orig;
    let mut neg = false;
    if s.starts_with('-') || s.starts_with('+') {
        neg = s.starts_with('-');
        s = &s[1..];
    }
    if s == "0" {
        return true;
    }
    if s.is_empty() {
        return false;
    }
    let mut d: u64 = 0;
    while !s.is_empty() {
        let b = s.as_bytes();
        if !(b[0] == b'.' || b[0].is_ascii_digit()) {
            return false;
        }
        // leadingInt
        let mut i = 0;
        let mut v: u64 = 0;
        while i < b.len() && b[i].is_ascii_digit() {
            if v > LIMIT / 10 {
                return false;
            }
            v = v * 10 + u64::from(b[i] - b'0');
            if v > LIMIT {
                return false;
            }
            i += 1;
        }
        let pre = i > 0;
        s = &s[i..];
        // optional fraction
        let (mut f, mut scale, mut post) = (0u64, 1f64, false);
        if let Some(rest) = s.strip_prefix('.') {
            let fb = rest.as_bytes();
            let mut j = 0;
            let mut overflow = false;
            while j < fb.len() && fb[j].is_ascii_digit() {
                if !overflow {
                    if f > (LIMIT - 1) / 10 {
                        overflow = true;
                    } else {
                        let y = f * 10 + u64::from(fb[j] - b'0');
                        if y > LIMIT {
                            overflow = true;
                        } else {
                            f = y;
                            scale *= 10.0;
                        }
                    }
                }
                j += 1;
            }
            post = j > 0;
            s = &rest[j..];
        }
        if !pre && !post {
            return false;
        }
        // the unit: everything up to the next '.' or digit
        let end = s
            .find(|c: char| c == '.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if end == 0 {
            return false;
        }
        let unit = match &s[..end] {
            "ns" => 1u64,
            "us" | "\u{00B5}s" | "\u{03BC}s" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 3_600 * 1_000_000_000,
            _ => return false,
        };
        s = &s[end..];
        if v > LIMIT / unit {
            return false;
        }
        v *= unit;
        if f > 0 {
            v += (f as f64 * (unit as f64 / scale)) as u64;
            if v > LIMIT {
                return false;
            }
        }
        d += v;
        if d > LIMIT {
            return false;
        }
    }
    if neg {
        return true;
    }
    d < LIMIT
}

/// `time.Parse(time.RFC3339, s)` (time/format.go) reduced to the Unix time
/// of the result, `None` where Go rejects `s`: `YYYY-MM-DDTHH:MM:SS`, an
/// optional fractional second, then `Z` or `+hh:mm` / `-hh:mm` (hour <= 24,
/// minute <= 60 as Go checks them).
pub(crate) fn go_parse_rfc3339_unix(value: &str) -> Option<i64> {
    fn digits(s: &str, n: usize) -> Option<(i64, &str)> {
        let b = s.as_bytes();
        if b.len() < n || !b[..n].iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some((s[..n].parse().ok()?, &s[n..]))
    }
    fn lit<'a>(s: &'a str, p: &str) -> Option<&'a str> {
        s.strip_prefix(p)
    }
    let (year, r) = digits(value, 4)?;
    let r = lit(r, "-")?;
    let (month, r) = digits(r, 2)?;
    if !(1..=12).contains(&month) {
        return None;
    }
    let r = lit(r, "-")?;
    let (day, r) = digits(r, 2)?;
    let r = lit(r, "T")?;
    let (hour, r) = digits(r, 2)?;
    if hour >= 24 {
        return None;
    }
    let r = lit(r, ":")?;
    let (min, r) = digits(r, 2)?;
    if min >= 60 {
        return None;
    }
    let r = lit(r, ":")?;
    let (sec, mut r) = digits(r, 2)?;
    if sec >= 60 {
        return None;
    }
    // a fractional second is accepted although the layout has none
    let b = r.as_bytes();
    if b.len() >= 2 && (b[0] == b'.' || b[0] == b',') && b[1].is_ascii_digit() {
        let n = 1 + b[1..].iter().take_while(|c| c.is_ascii_digit()).count();
        r = &r[n..];
    }
    let offset: i64 = if let Some(rest) = r.strip_prefix('Z') {
        r = rest;
        0
    } else {
        let b = r.as_bytes();
        if b.len() < 6 || b[3] != b':' || (b[0] != b'+' && b[0] != b'-') {
            return None;
        }
        let (hh, _) = digits(&r[1..], 2)?;
        let (mm, _) = digits(&r[4..], 2)?;
        if hh > 24 || mm > 60 {
            return None;
        }
        let secs = hh * 3600 + mm * 60;
        let signed = if b[0] == b'-' { -secs } else { secs };
        r = &r[6..];
        signed
    };
    if !r.is_empty() {
        return None;
    }
    // day-of-month validity (`day out of range`)
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let dim = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if leap => 29,
        _ => 28,
    };
    if day < 1 || day > dim {
        return None;
    }
    // days since 1970-01-01 (Howard Hinnant's days_from_civil)
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + min * 60 + sec - offset)
}
