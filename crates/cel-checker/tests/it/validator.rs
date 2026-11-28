//! `cel/validator.go` `homogeneousAggregateLiteralValidator`, which the
//! Kubernetes environment installs through `cel.HomogeneousAggregateLiterals()`
//! (`environment/base.go:63-69`): run after a type check without errors, over
//! the final types, with `format` exempted by `ext.Strings`
//! (`ext/formatting.go` `stringFormatValidator.Configure`). The comparison
//! with cel-go is in `goldens.rs`.

use kubernetes_rs_cel_checker::{
    check, Container, EnvSet, EnvType, Features, MapProvider, SourceLocator, Version,
};
use std::sync::Arc;

fn errors(minor: u32, src: &str) -> Vec<String> {
    let set = EnvSet::must_base_env_set(Version::major_minor(1, minor), &Features::default());
    let (expr, info) = set
        .parser(EnvType::NewExpressions)
        .parse_with_source_info(src)
        .unwrap();
    let mut env = set.env(
        EnvType::NewExpressions,
        Container::default(),
        Arc::new(MapProvider::new()),
    );
    let locator = SourceLocator::new(&info, src);
    let (_, errs) = check(&expr, &mut env, &locator);
    errs.errors().iter().map(|e| e.message.clone()).collect()
}

#[test]
fn mixed_literals_are_reported() {
    assert_eq!(
        errors(35, "[1, 'a']"),
        ["expected type 'int' but found 'string'"]
    );
    assert_eq!(
        errors(35, "{1: 'a', 'b': 3}"),
        [
            "expected type 'int' but found 'string'",
            "expected type 'string' but found 'int'"
        ]
    );
    assert!(errors(35, "[1, 2]").is_empty());
    assert!(errors(35, "[1, dyn('a')]").len() == 1);
}

/// The validator runs only on a result without type errors, so the mixed
/// list is not reported next to an undeclared reference.
#[test]
fn only_a_clean_check_is_validated() {
    assert_eq!(
        errors(35, "[1, 'a', undeclared]"),
        ["undeclared reference to 'undeclared' (in container '')"]
    );
}

/// The validator sees the final types: an unbound type parameter is `dyn`.
#[test]
fn messages_use_the_substituted_types() {
    assert_eq!(
        errors(35, "{}.map(c, [c, type(c)])"),
        ["expected type 'dyn' but found 'type(dyn)'"]
    );
}

/// `format` is exempt from `StringsVersion(1)`, which the environment has
/// from 1.29.
#[test]
fn format_arguments_are_exempt() {
    assert!(errors(35, "'%s %d'.format(['a', 1])").is_empty());
}

// ---- cel.ValidateDurationLiterals / ValidateTimestampLiterals /
// ValidateRegexLiterals (cel/validator.go:191-204, `environment/base.go:105-112`).

#[test]
fn cel_literal_validators_duration() {
    assert_eq!(errors(35, "duration('1x')"), ["invalid duration argument"]);
    assert_eq!(errors(35, "duration('')"), ["invalid duration argument"]);
    assert_eq!(errors(35, "duration('1h2')"), ["invalid duration argument"]);
    for ok in [
        "1h", "1h30m", "-1.5s", "+0", "0", "100ms", "1us", ".5s", "3µs",
    ] {
        assert!(errors(35, &format!("duration('{ok}')")).is_empty(), "{ok}");
    }
    // overflowing int64 nanoseconds
    assert_eq!(
        errors(35, "duration('9223372036854775808ns')"),
        ["invalid duration argument"]
    );
    assert!(errors(35, "duration('9223372036854775807ns')").is_empty());
    // a non-literal argument is not checked
    assert!(errors(35, "duration('1' + 'x')").is_empty());
}

#[test]
fn cel_literal_validators_timestamp() {
    assert_eq!(
        errors(35, "timestamp('abc')"),
        ["invalid timestamp argument"]
    );
    assert_eq!(
        errors(35, "timestamp('2023-01-01 00:00:00Z')"),
        ["invalid timestamp argument"]
    );
    assert_eq!(
        errors(35, "timestamp('2023-02-30T00:00:00Z')"),
        ["invalid timestamp argument"]
    );
    for ok in [
        "2023-01-01T00:00:00Z",
        "2023-12-31T23:59:59.123456789Z",
        "2023-01-01T00:00:00+05:30",
        "2024-02-29T00:00:00Z",
    ] {
        assert!(errors(35, &format!("timestamp('{ok}')")).is_empty(), "{ok}");
    }
    // outside 0001-01-01..9999-12-31 after the offset: celErrTimestampOverflow
    assert_eq!(
        errors(35, "timestamp('0001-01-01T00:00:00+01:00')"),
        ["invalid timestamp argument"]
    );
    assert_eq!(
        errors(35, "timestamp('9999-12-31T23:59:59-01:00')"),
        ["invalid timestamp argument"]
    );
    assert!(errors(35, "timestamp('9999-12-31T23:59:59Z')").is_empty());
    // int form: the Unix time must be in range
    assert!(errors(35, "timestamp(0)").is_empty());
    assert_eq!(
        errors(35, "timestamp(253402300800)"),
        ["invalid timestamp argument"]
    );
}

#[test]
fn cel_literal_validators_regex() {
    assert_eq!(errors(35, "'a'.matches('(')"), ["invalid matches argument"]);
    // global form: cel-go checks `args[0]`, which is the subject here
    assert!(errors(35, "matches('a', '[')").is_empty());
    assert!(errors(35, "'abc'.matches('^a.*c$')").is_empty());
    assert!(errors(35, "'abc'.matches('(?i)ABC')").is_empty());
    // no lookahead in RE2
    assert_eq!(
        errors(35, "'a'.matches('(?=a)')"),
        ["invalid matches argument"]
    );
    // a non-literal pattern is not checked
    assert!(errors(35, "'a'.matches('(' + 'x')").is_empty());
    assert_eq!(
        errors(35, "matches('(', 'x')"),
        ["invalid matches argument"]
    );
}

#[test]
fn cel_literal_validators_order_and_scope() {
    // reported in validator order: homogeneous (epoch), then duration, timestamp, matches
    assert_eq!(
        errors(
            35,
            "[duration('x') == duration('1s'), 'a'.matches('('), timestamp('t') == timestamp(0)]"
        ),
        [
            "invalid duration argument",
            "invalid timestamp argument",
            "invalid matches argument"
        ]
    );
    // nested in a macro body
    assert_eq!(
        errors(35, "[1].all(x, duration('1x') > duration('1s'))"),
        ["invalid duration argument"]
    );
    // the validators arrive with 1.29 (environment/base.go:105)
    assert!(errors(28, "duration('1x')").is_empty());
    assert_eq!(errors(29, "duration('1x')"), ["invalid duration argument"]);
}
