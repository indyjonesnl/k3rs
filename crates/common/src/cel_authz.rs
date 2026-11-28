//! The typed CEL environment authorization `matchConditions` are compiled
//! against, and the selector-usage detection of its compiler.
//!
//! Ported from `staging/src/k8s.io/apiserver/pkg/authorization/cel/compile.go`:
//! `mustBuildEnv` / `buildRequestType` / `buildResourceAttributesType` /
//! `buildFieldSelectorType` / `buildLabelSelectorType` /
//! `buildSelectorRequirementType` / `buildNonResourceAttributesType`
//! (:173-268) declare the single variable `request` of object type
//! `kubernetes.SubjectAccessReviewSpec`, and `CompileCELExpression`
//! (:81-171) compiles with it, enforces `ReturnTypes()` (`[bool]`) and walks
//! the AST for `fieldSelector` / `labelSelector` (:128-159).
//!
//! The `cel` crate has no checker (see `cel_env`), so the type inference of
//! cel-go cannot be ported. The declaration half that needs no inference is:
//! identifier resolution (only `request` and the CEL type identifiers), field
//! selection on the declared object types (`undefined field 'x'`), and the
//! output type of a pure select chain over those types. Field types of
//! comprehension variables (`r` in `requirements.exists(r, ...)`) are not
//! checked.

use crate::cel_checker_shadow::checker_env_set;
use crate::cel_policy_types::{DeclType, PolicyCheck};
use crate::cel_versions::{EnvSet, EnvType};
use crate::feature_gates::{self, Feature};
use cel::common::ast::{EntryExpr, Expr, IdedExpr, LiteralValue};
use kubernetes_rs_cel_checker as checker;
use kubernetes_rs_cel_checker::decl::{DeclField, DeclTypeProvider};
use kubernetes_rs_cel_checker::DType;
use std::collections::BTreeMap;
use std::sync::Arc;

/// `subjectAccessReviewRequestVarName` (compile.go:36).
const REQUEST: &str = "request";
/// `fieldSelectorVarName` / `labelSelectorVarName` (compile.go:38-39).
const FIELD_SELECTOR: &str = "fieldSelector";
const LABEL_SELECTOR: &str = "labelSelector";
/// `operators.OptSelect`.
const OPT_SELECT: &str = "_?._";

/// CEL type identifiers every environment declares.
const TYPE_IDENTS: &[&str] = &[
    "int",
    "uint",
    "double",
    "bool",
    "string",
    "bytes",
    "list",
    "map",
    "null_type",
    "type",
    "dyn",
    "optional_type",
];

/// `buildRequestType` (compile.go:207-218).
const REQUEST_FIELDS: &[(&str, &str)] = &[
    ("resourceAttributes", "kubernetes.ResourceAttributes"),
    ("nonResourceAttributes", "kubernetes.NonResourceAttributes"),
    ("user", "string"),
    ("groups", "list(string)"),
    ("extra", "map(string, list(string))"),
    ("uid", "string"),
];

/// `buildResourceAttributesType` (compile.go:222-237), without the selectors.
const RESOURCE_ATTRIBUTES_FIELDS: &[(&str, &str)] = &[
    ("namespace", "string"),
    ("verb", "string"),
    ("group", "string"),
    ("version", "string"),
    ("resource", "string"),
    ("subresource", "string"),
    ("name", "string"),
];

/// `buildFieldSelectorType` / `buildLabelSelectorType` (compile.go:239-251).
const SELECTOR_FIELDS: &[(&str, &str)] = &[
    ("rawSelector", "string"),
    ("requirements", "list(kubernetes.SelectorRequirement)"),
];

/// `buildNonResourceAttributesType` (compile.go:263-268).
const NON_RESOURCE_ATTRIBUTES_FIELDS: &[(&str, &str)] = &[("path", "string"), ("verb", "string")];

/// What a successful compile records (`CompilationResult.UsesFieldSelector` /
/// `UsesLabelSelector`, compile.go:47-51).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelectorUsage {
    pub uses_field_selector: bool,
    pub uses_label_selector: bool,
}

/// The declared fields of a type of the environment, `None` for a type the
/// environment does not model field by field.
fn fields_of(type_name: &str) -> Option<Vec<(&'static str, &'static str)>> {
    match type_name {
        "kubernetes.SubjectAccessReviewSpec" => Some(REQUEST_FIELDS.to_vec()),
        "kubernetes.ResourceAttributes" => {
            let mut f = RESOURCE_ATTRIBUTES_FIELDS.to_vec();
            // compile.go:232-235.
            if feature_gates::enabled(Feature::AuthorizeWithSelectors) {
                f.push((FIELD_SELECTOR, "kubernetes.FieldSelectorAttributes"));
                f.push((LABEL_SELECTOR, "kubernetes.LabelSelectorAttributes"));
            }
            Some(f)
        }
        "kubernetes.NonResourceAttributes" => Some(NON_RESOURCE_ATTRIBUTES_FIELDS.to_vec()),
        "kubernetes.FieldSelectorAttributes" | "kubernetes.LabelSelectorAttributes" => {
            Some(SELECTOR_FIELDS.to_vec())
        }
        _ => None,
    }
}

/// `CompileCELExpression` (compile.go:81-171) for an expression whose
/// `ReturnTypes()` is `[bool]` (`SubjectAccessReviewMatchCondition`,
/// interface.go): the selector usage, or the `Detail` of the compile error.
pub fn compile_authorization_expression(expression: &str) -> Result<SelectorUsage, String> {
    let source = expression.to_string();
    let program = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cel::Program::compile(&source)
    })) {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => return Err(format!("compilation failed: {e}")),
        Err(_) => {
            return Err(format!(
                "compilation failed: invalid CEL expression '{expression}'"
            ))
        }
    };
    let root = program.expression();
    let mut checker = Checker { scope: Vec::new() };
    if let Err(issue) = checker.check(root) {
        return Err(format!("compilation failed: ERROR: <input>: {issue}"));
    }
    if let Some(got) = output_type(root) {
        // compile.go:107-115: `ReturnTypes()` is `[bool]`.
        if got != "bool" && got != "dyn" {
            return Err(format!("must evaluate to bool but got {got}"));
        }
    }
    let mut usage = SelectorUsage::default();
    detect_selector_usage(root, &mut usage);
    Ok(usage)
}

/// The declared type of a pure select chain rooted at `request`, or `None`
/// when it is not one (no inference).
fn chain_type(e: &IdedExpr, scope: &[String]) -> Option<String> {
    match &e.expr {
        Expr::Ident(n) if n == REQUEST && !scope.iter().any(|s| s == REQUEST) => {
            Some("kubernetes.SubjectAccessReviewSpec".to_string())
        }
        Expr::Select(s) if !s.test => {
            let parent = chain_type(&s.operand, scope)?;
            fields_of(&parent)?
                .into_iter()
                .find(|(n, _)| *n == s.field)
                .map(|(_, t)| t.to_string())
        }
        _ => None,
    }
}

/// The output type where it is known without inference: a select chain over
/// the declared types, or the shapes `cel_env::output_type_failure` knows.
fn output_type(root: &IdedExpr) -> Option<String> {
    if let Some(t) = chain_type(root, &[]) {
        return Some(t);
    }
    match &root.expr {
        Expr::Literal(l) => Some(
            match l {
                LiteralValue::Boolean(_) => "bool",
                LiteralValue::Bytes(_) => "bytes",
                LiteralValue::Double(_) => "double",
                LiteralValue::Int(_) => "int",
                LiteralValue::Null => "null_type",
                LiteralValue::String(_) => "string",
                LiteralValue::UInt(_) => "uint",
            }
            .to_string(),
        ),
        Expr::Map(_) => Some("map(dyn, dyn)".to_string()),
        Expr::List(_) => Some("list(dyn)".to_string()),
        Expr::Call(c) if is_bool_operator(&c.func_name) => Some("bool".to_string()),
        _ => None,
    }
}

fn is_bool_operator(name: &str) -> bool {
    matches!(
        name,
        "_<_" | "_<=_" | "_>_" | "_>=_" | "_==_" | "_!=_" | "_&&_" | "_||_" | "!_" | "@in"
    )
}

struct Checker {
    /// Comprehension variables in scope, innermost last.
    scope: Vec<String>,
}

impl Checker {
    fn declared(&self, name: &str) -> bool {
        self.scope.iter().any(|s| s == name) || name == REQUEST || TYPE_IDENTS.contains(&name)
    }

    /// `undefined field` when `field` is not declared on the chain type of
    /// `operand`.
    fn check_field(&self, operand: &IdedExpr, field: &str) -> Result<(), String> {
        if let Some(parent) = chain_type(operand, &self.scope) {
            if let Some(fields) = fields_of(&parent) {
                if !fields.iter().any(|(n, _)| *n == field) {
                    return Err(format!("undefined field '{field}'"));
                }
            }
        }
        Ok(())
    }

    fn check(&mut self, e: &IdedExpr) -> Result<(), String> {
        match &e.expr {
            Expr::Unspecified | Expr::Literal(_) => Ok(()),
            Expr::Ident(name) => {
                if self.declared(name) {
                    Ok(())
                } else {
                    Err(format!(
                        "undeclared reference to '{name}' (in container '')"
                    ))
                }
            }
            Expr::Select(s) => {
                self.check(&s.operand)?;
                self.check_field(&s.operand, &s.field)
            }
            Expr::Call(c) => {
                if let Some(t) = &c.target {
                    self.check(t)?;
                }
                c.args.iter().try_for_each(|a| self.check(a))?;
                // `.?field`: args are [operand, "field"].
                if c.func_name == OPT_SELECT && c.args.len() == 2 {
                    if let Expr::Literal(LiteralValue::String(f)) = &c.args[1].expr {
                        return self.check_field(&c.args[0], f.as_ref());
                    }
                }
                Ok(())
            }
            Expr::List(l) => l.elements.iter().try_for_each(|a| self.check(a)),
            Expr::Map(m) => m.entries.iter().try_for_each(|en| self.check_entry(en)),
            Expr::Struct(s) => Err(format!(
                "undeclared reference to '{}' (in container '')",
                s.type_name
            )),
            Expr::Comprehension(c) => {
                self.check(&c.iter_range)?;
                self.check(&c.accu_init)?;
                let depth = self.scope.len();
                self.scope.push(c.iter_var.clone());
                if let Some(v2) = &c.iter_var2 {
                    self.scope.push(v2.clone());
                }
                self.scope.push(c.accu_var.clone());
                let r = self
                    .check(&c.loop_cond)
                    .and_then(|_| self.check(&c.loop_step))
                    .and_then(|_| self.check(&c.result));
                self.scope.truncate(depth);
                r
            }
        }
    }

    fn check_entry(&mut self, en: &cel::common::ast::IdedEntryExpr) -> Result<(), String> {
        match &en.expr {
            EntryExpr::StructField(f) => self.check(&f.value),
            EntryExpr::MapEntry(m) => self.check(&m.key).and_then(|_| self.check(&m.value)),
        }
    }
}

/// compile.go:128-159: a pre-order visit recording `.fieldSelector` /
/// `.labelSelector` selects and `.?fieldSelector` / `.?labelSelector` optional
/// selects (a call to `_?._` whose second argument is a string literal).
fn detect_selector_usage(e: &IdedExpr, usage: &mut SelectorUsage) {
    // "we already know we use both, no need to inspect more".
    if usage.uses_field_selector && usage.uses_label_selector {
        return;
    }
    let mut field_name: Option<&str> = None;
    match &e.expr {
        Expr::Select(s) => field_name = Some(s.field.as_str()),
        Expr::Call(c) if c.func_name == OPT_SELECT && c.args.len() == 2 => {
            if let Expr::Literal(LiteralValue::String(f)) = &c.args[1].expr {
                field_name = Some(f.as_ref());
            }
        }
        _ => {}
    }
    match field_name {
        Some(FIELD_SELECTOR) => usage.uses_field_selector = true,
        Some(LABEL_SELECTOR) => usage.uses_label_selector = true,
        _ => {}
    }
    match &e.expr {
        Expr::Unspecified | Expr::Literal(_) | Expr::Ident(_) => {}
        Expr::Select(s) => detect_selector_usage(&s.operand, usage),
        Expr::Call(c) => {
            if let Some(t) = &c.target {
                detect_selector_usage(t, usage);
            }
            c.args.iter().for_each(|a| detect_selector_usage(a, usage));
        }
        Expr::List(l) => l
            .elements
            .iter()
            .for_each(|a| detect_selector_usage(a, usage)),
        Expr::Map(m) => m.entries.iter().for_each(|en| match &en.expr {
            EntryExpr::StructField(f) => detect_selector_usage(&f.value, usage),
            EntryExpr::MapEntry(me) => {
                detect_selector_usage(&me.key, usage);
                detect_selector_usage(&me.value, usage);
            }
        }),
        Expr::Struct(s) => s.entries.iter().for_each(|en| match &en.expr {
            EntryExpr::StructField(f) => detect_selector_usage(&f.value, usage),
            EntryExpr::MapEntry(me) => {
                detect_selector_usage(&me.key, usage);
                detect_selector_usage(&me.value, usage);
            }
        }),
        Expr::Comprehension(c) => {
            for part in [
                &c.iter_range,
                &c.accu_init,
                &c.loop_cond,
                &c.loop_step,
                &c.result,
            ] {
                detect_selector_usage(part, usage);
            }
        }
    }
}

// --- The typed environment for the cel-go checker port -----------------------

fn decl_field(name: &str, ty: DeclType) -> (String, DeclField) {
    (
        name.to_string(),
        DeclField {
            name: name.to_string(),
            ty,
            required: false,
        },
    )
}

fn decl_object(name: &str, fields: Vec<(String, DeclField)>) -> DeclType {
    DeclType::object(name, fields.into_iter().collect::<BTreeMap<_, _>>())
}

fn decl_string() -> DeclType {
    DeclType::simple(DType::Str)
}

fn decl_string_list() -> DeclType {
    DeclType::list(decl_string(), -1)
}

/// `buildSelectorRequirementType` (compile.go:253-259).
fn build_selector_requirement_type() -> DeclType {
    decl_object(
        "kubernetes.SelectorRequirement",
        vec![
            decl_field("key", decl_string()),
            decl_field("operator", decl_string()),
            decl_field("values", decl_string_list()),
        ],
    )
}

/// `buildFieldSelectorType` (compile.go:239-244).
fn build_field_selector_type() -> DeclType {
    decl_object(
        "kubernetes.FieldSelectorAttributes",
        vec![
            decl_field("rawSelector", decl_string()),
            decl_field(
                "requirements",
                DeclType::list(build_selector_requirement_type(), -1),
            ),
        ],
    )
}

/// `buildLabelSelectorType` (compile.go:246-251).
fn build_label_selector_type() -> DeclType {
    decl_object(
        "kubernetes.LabelSelectorAttributes",
        vec![
            decl_field("rawSelector", decl_string()),
            decl_field(
                "requirements",
                DeclType::list(build_selector_requirement_type(), -1),
            ),
        ],
    )
}

/// `buildResourceAttributesType` (compile.go:222-237): the selector fields
/// exist only with the `AuthorizeWithSelectors` gate.
pub fn build_resource_attributes_type(authorize_with_selectors: bool) -> DeclType {
    let mut fields = vec![
        decl_field("namespace", decl_string()),
        decl_field("verb", decl_string()),
        decl_field("group", decl_string()),
        decl_field("version", decl_string()),
        decl_field("resource", decl_string()),
        decl_field("subresource", decl_string()),
        decl_field("name", decl_string()),
    ];
    if authorize_with_selectors {
        fields.push(decl_field("fieldSelector", build_field_selector_type()));
        fields.push(decl_field("labelSelector", build_label_selector_type()));
    }
    decl_object("kubernetes.ResourceAttributes", fields)
}

/// `buildNonResourceAttributesType` (compile.go:263-268).
pub fn build_non_resource_attributes_type() -> DeclType {
    decl_object(
        "kubernetes.NonResourceAttributes",
        vec![
            decl_field("path", decl_string()),
            decl_field("verb", decl_string()),
        ],
    )
}

/// `buildRequestType` (compile.go:207-218): `kubernetes.SubjectAccessReviewSpec`,
/// the type of the `request` variable.
pub fn build_request_type(authorize_with_selectors: bool) -> DeclType {
    decl_object(
        "kubernetes.SubjectAccessReviewSpec",
        vec![
            decl_field(
                "resourceAttributes",
                build_resource_attributes_type(authorize_with_selectors),
            ),
            decl_field(
                "nonResourceAttributes",
                build_non_resource_attributes_type(),
            ),
            decl_field("user", decl_string()),
            decl_field("groups", decl_string_list()),
            decl_field("extra", DeclType::map(decl_string_list(), -1)),
            decl_field("uid", decl_string()),
        ],
    )
}

/// `mustBuildEnv` (compile.go:173-205) and the check half of
/// `CompileCELExpression`: the `StoredExpressions` environment of `set` with
/// the single variable `request`, then the checker. `None` when the expression
/// does not parse.
pub fn check_authorization_expression(
    set: &EnvSet,
    authorize_with_selectors: bool,
    expression: &str,
) -> Option<PolicyCheck> {
    let env_type = EnvType::StoredExpressions;
    let (env_set, ct) = checker_env_set(set, env_type);
    let source = expression.to_string();
    // The antlr4rust parser panics on some invalid expressions.
    let (parsed, source_info) =
        std::panic::catch_unwind(|| env_set.parser(ct).parse_with_source_info(&source))
            .ok()?
            .ok()?;
    let request = build_request_type(authorize_with_selectors);
    // Stored expressions keep the keyword escaping of the old environments.
    let provider = DeclTypeProvider::new(
        std::slice::from_ref(&request),
        Arc::new(checker::MapProvider::new()),
        true,
    );
    let mut env = env_set.env(ct, checker::Container::default(), Arc::new(provider));
    env.add_ident(checker::VariableDecl::new(REQUEST, request.dtype()))
        .ok();
    let locator = checker::SourceLocator::new(&source_info, expression);
    let (ast, errs) = checker::check(&parsed, &mut env, &locator);
    let errors: Vec<String> = errs.errors().iter().map(|e| e.message.clone()).collect();
    let output = errors
        .is_empty()
        .then(|| ast.output_type().cloned())
        .flatten();
    Some(PolicyCheck {
        display: errs.to_display_string(Some(expression)),
        errors,
        output,
    })
}

/// `CompileCELExpression` (compile.go:81-115) as far as the checker goes: the
/// compile issues, then the `ReturnTypes()` check (`[bool]`).
pub fn check_authorization_compile(
    set: &EnvSet,
    authorize_with_selectors: bool,
    expression: &str,
) -> Result<(), String> {
    let Some(check) = check_authorization_expression(set, authorize_with_selectors, expression)
    else {
        return Err(format!(
            "compilation failed: Syntax error in '{expression}'"
        ));
    };
    if !check.errors.is_empty() {
        return Err(format!("compilation failed: {}", check.display));
    }
    let output = check.output.unwrap_or(DType::Dyn);
    if output != DType::Bool {
        return Err(format!("must evaluate to bool but got {}", output.name()));
    }
    Ok(())
}
