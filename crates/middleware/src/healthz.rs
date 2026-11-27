//! Shared `/healthz`, `/livez`, `/readyz` handler builder.
//!
//! Ported from `staging/src/k8s.io/apiserver/pkg/server/healthz/healthz.go`
//! (release-1.35): `HealthChecker`, `GroupedHealthChecker`, `PingHealthz`,
//! `NewShutdownHealthz`, `NewInformerSyncHealthz`, `NamedCheck`,
//! `NamedGroupedCheck`, `InstallPathHandlerWithHealthyFunc`,
//! `handleRootHealth`, `adaptCheckToHandler`, `getExcludedChecks`,
//! `formatQuoted`.
//!
//! Deviations: the SLI metrics (`slis.ObserveHealthcheck`) and request
//! instrumentation are not ported; `LogHealthz` is not ported (Rust logging
//! has no flush that can block). Checks do not receive the request.

use crate::lifecycle::LifecycleSignal;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, trace};

pub const DEFAULT_HEALTHZ_PATH: &str = "/healthz";

/// `HealthChecker` (+ `GroupedHealthChecker` through `group_name`).
pub trait HealthChecker: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self) -> Result<(), String>;
    fn group_name(&self) -> Option<&str> {
        None
    }
}

/// `PingHealthz`.
pub struct Ping;

impl HealthChecker for Ping {
    fn name(&self) -> &str {
        "ping"
    }
    fn check(&self) -> Result<(), String> {
        Ok(())
    }
}

type CheckFn = Box<dyn Fn() -> Result<(), String> + Send + Sync>;

/// `healthzCheck` / `groupedHealthzCheck`.
pub struct NamedCheck {
    name: String,
    group: Option<String>,
    check: CheckFn,
}

/// `NamedCheck`.
pub fn named_check(
    name: &str,
    check: impl Fn() -> Result<(), String> + Send + Sync + 'static,
) -> NamedCheck {
    NamedCheck {
        name: name.to_string(),
        group: None,
        check: Box::new(check),
    }
}

/// `NamedGroupedCheck`.
pub fn named_grouped_check(
    name: &str,
    group: &str,
    check: impl Fn() -> Result<(), String> + Send + Sync + 'static,
) -> NamedCheck {
    NamedCheck {
        group: Some(group.to_string()),
        ..named_check(name, check)
    }
}

impl HealthChecker for NamedCheck {
    fn name(&self) -> &str {
        &self.name
    }
    fn check(&self) -> Result<(), String> {
        (self.check)()
    }
    fn group_name(&self) -> Option<&str> {
        self.group.as_deref()
    }
}

/// `NewShutdownHealthz`: fails once the signal (e.g. `ShutdownInitiated`) fires.
pub fn shutdown_healthz(signal: LifecycleSignal) -> NamedCheck {
    named_check("shutdown", move || {
        if signal.is_signaled() {
            Err("process is shutting down".to_string())
        } else {
            Ok(())
        }
    })
}

/// `NewInformerSyncHealthz`: `not_started` returns the names of informers that
/// have not synced (what `WaitForCacheSync` reports as false).
pub fn informer_sync_healthz(
    not_started: impl Fn() -> Vec<String> + Send + Sync + 'static,
) -> NamedCheck {
    named_check("informer-sync", move || {
        let n = not_started();
        if n.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{} informers not started yet: [{}]",
                n.len(),
                n.join(" ")
            ))
        }
    })
}

/// `checkerNames`.
pub fn checker_names(checks: &[Arc<dyn HealthChecker>]) -> Vec<String> {
    checks.iter().map(|c| c.name().to_string()).collect()
}

/// `formatQuoted`.
pub fn format_quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("{n:?}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// `getExcludedChecks`: every `exclude` query value.
pub fn get_excluded_checks(query: Option<&str>) -> BTreeSet<String> {
    url::form_urlencoded::parse(query.unwrap_or("").as_bytes())
        .filter(|(k, _)| k == "exclude")
        .map(|(_, v)| v.into_owned())
        .collect()
}

fn has_query_key(query: Option<&str>, key: &str) -> bool {
    url::form_urlencoded::parse(query.unwrap_or("").as_bytes()).any(|(k, _)| k == key)
}

fn text(status: StatusCode, body: String) -> Response {
    let mut r = (status, body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}

/// `handleRootHealth`.
fn root_health(
    name: &str,
    first_time_healthy: Option<Arc<dyn Fn() + Send + Sync>>,
    checks: &[Arc<dyn HealthChecker>],
    notified: &AtomicBool,
    query: Option<&str>,
) -> Response {
    let excluded = get_excluded_checks(query);
    let mut unknown_excluded = excluded.clone();
    let mut failed_verbose_log = String::new();
    let mut failed_checks: Vec<&str> = Vec::new();
    let mut out = String::new();
    for check in checks {
        if excluded.contains(check.name()) {
            unknown_excluded.remove(check.name());
            out.push_str(&format!("[+]{} excluded: ok\n", check.name()));
            continue;
        }
        if let Some(group) = check.group_name() {
            if excluded.contains(group) {
                unknown_excluded.remove(group);
                out.push_str(&format!(
                    "[+]{} excluded with {}: ok\n",
                    check.name(),
                    group
                ));
                continue;
            }
        }
        match check.check() {
            Err(err) => {
                // Public endpoint: withhold the reason from the response, log it.
                out.push_str(&format!("[-]{} failed: reason withheld\n", check.name()));
                failed_verbose_log.push_str(&format!("[-]{} failed: {}\n", check.name(), err));
                failed_checks.push(check.name());
            }
            Ok(()) => out.push_str(&format!("[+]{} ok\n", check.name())),
        }
    }
    if !unknown_excluded.is_empty() {
        let names: Vec<String> = unknown_excluded.into_iter().collect();
        out.push_str(&format!(
            "warn: some health checks cannot be excluded: no matches for {}\n",
            format_quoted(&names)
        ));
        trace!(
            "cannot exclude some health checks, no health checks are installed matching {}",
            format_quoted(&names)
        );
    }
    // always be verbose on failure
    if !failed_checks.is_empty() {
        debug!(
            "{} check failed: {}\n{}",
            failed_checks.join(","),
            name,
            failed_verbose_log
        );
        // http.Error appends a newline
        return text(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{out}{name} check failed\n"),
        );
    }
    // signal first time this is healthy
    if let Some(f) = &first_time_healthy {
        if !notified.swap(true, Ordering::SeqCst) {
            f();
        }
    }
    let mut r = if has_query_key(query, "verbose") {
        text(StatusCode::OK, format!("{out}{name} check passed\n"))
    } else {
        text(StatusCode::OK, "ok".to_string())
    };
    r.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// `InstallPathHandler`.
pub fn install_path_handler(
    router: Router,
    path: &str,
    checks: Vec<Arc<dyn HealthChecker>>,
) -> Router {
    install_path_handler_with_healthy_func(router, path, None, checks)
}

/// `InstallPathHandlerWithHealthyFunc`: also calls `first_time_healthy` exactly
/// once, when the handler succeeds for the first time. Registering the same
/// path twice panics (axum rejects overlapping routes), as upstream.
pub fn install_path_handler_with_healthy_func(
    mut router: Router,
    path: &str,
    first_time_healthy: Option<Arc<dyn Fn() + Send + Sync>>,
    mut checks: Vec<Arc<dyn HealthChecker>>,
) -> Router {
    if checks.is_empty() {
        debug!("No default health checks specified. Installing the ping handler.");
        checks = vec![Arc::new(Ping)];
    }
    let name = path
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    let notified = Arc::new(AtomicBool::new(false));
    let root_checks = checks.clone();
    router = router.route(
        path,
        any(move |req: Request| {
            let (name, ftf, checks, notified) = (
                name.clone(),
                first_time_healthy.clone(),
                root_checks.clone(),
                notified.clone(),
            );
            async move { root_health(&name, ftf, &checks, &notified, req.uri().query()) }
        }),
    );
    for check in checks {
        router = router.route(
            &format!("{}/{}", path, check.name()),
            any(move || {
                let check = check.clone();
                async move {
                    // adaptCheckToHandler
                    match check.check() {
                        Err(e) => text(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("internal server error: {e}\n"),
                        ),
                        Ok(()) => text(StatusCode::OK, "ok".to_string()),
                    }
                }
            }),
        );
    }
    router
}

/// `InstallHandler` (`/healthz`).
pub fn install_handler(router: Router, checks: Vec<Arc<dyn HealthChecker>>) -> Router {
    install_path_handler(router, DEFAULT_HEALTHZ_PATH, checks)
}

/// `InstallReadyzHandler`.
pub fn install_readyz_handler(router: Router, checks: Vec<Arc<dyn HealthChecker>>) -> Router {
    install_path_handler(router, "/readyz", checks)
}

/// `InstallLivezHandler`.
pub fn install_livez_handler(router: Router, checks: Vec<Arc<dyn HealthChecker>>) -> Router {
    install_path_handler(router, "/livez", checks)
}
