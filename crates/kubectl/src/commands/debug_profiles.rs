//! Port of `staging/src/k8s.io/kubectl/pkg/cmd/debug/profiles.go`
//! (release-1.35): the `kubectl debug --profile` appliers (`legacy`,
//! `general`, `baseline`, `restricted`, `netadmin`, `sysadmin`) that adjust
//! the debug container / pod for each debugging journey (ephemeral container,
//! pod copy, node).
//!
//! Upstream mutates a typed `corev1.Pod`; the rest of this command works on
//! JSON values, so the appliers mutate the pod JSON the same way (a field set
//! to nil upstream is removed here). Tests: `profiles_test.go`.

use serde_json::{json, Map, Value};

pub const PROFILE_LEGACY: &str = "legacy";
pub const PROFILE_GENERAL: &str = "general";
pub const PROFILE_BASELINE: &str = "baseline";
pub const PROFILE_RESTRICTED: &str = "restricted";
pub const PROFILE_NETADMIN: &str = "netadmin";
pub const PROFILE_SYSADMIN: &str = "sysadmin";

/// `debugStyle` (ephemeral / podCopy / node).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DebugStyle {
    Ephemeral,
    PodCopy,
    Node,
}

/// The `target runtime.Object` of `Apply`: what the debug pod is built for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The pod being modified is the target itself (`pod == target`): an
    /// ephemeral container.
    SamePod,
    /// A different `*corev1.Pod`: debugging a copy of it.
    PodCopy,
    /// A `*corev1.Node`.
    Node,
    /// Any other object; the string is its Go type (`%T`).
    Other(String),
}

/// `KeepFlags`: which fields to keep in the copy pod.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeepFlags {
    pub labels: bool,
    pub annotations: bool,
    pub liveness: bool,
    pub readiness: bool,
    pub startup: bool,
    pub init_containers: bool,
}

impl KeepFlags {
    /// `RemoveLabels`.
    pub fn remove_labels(&self, p: &mut Value) {
        if !self.labels {
            if let Some(m) = p.get_mut("metadata") {
                remove_key(m, "labels");
            }
        }
    }

    /// `RemoveAnnotations`.
    pub fn remove_annotations(&self, p: &mut Value) {
        if !self.annotations {
            if let Some(m) = p.get_mut("metadata") {
                remove_key(m, "annotations");
            }
        }
    }

    /// `RemoveProbes`: from the regular containers only.
    pub fn remove_probes(&self, p: &mut Value) {
        if let Some(cs) = p
            .get_mut("spec")
            .and_then(|s| s.get_mut("containers"))
            .and_then(Value::as_array_mut)
        {
            for c in cs {
                if !self.liveness {
                    remove_key(c, "livenessProbe");
                }
                if !self.readiness {
                    remove_key(c, "readinessProbe");
                }
                if !self.startup {
                    remove_key(c, "startupProbe");
                }
            }
        }
    }

    /// `RemoveInitContainers`.
    pub fn remove_init_containers(&self, p: &mut Value) {
        if !self.init_containers {
            if let Some(sp) = p.get_mut("spec") {
                remove_key(sp, "initContainers");
            }
        }
    }
}

/// The profile variants of `NewProfileApplier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    Legacy,
    General,
    Baseline,
    Restricted,
    Netadmin,
    Sysadmin,
}

/// `ProfileApplier`.
#[derive(Debug, Clone, Copy)]
pub struct ProfileApplier {
    profile: Profile,
    kflags: KeepFlags,
}

/// `NewProfileApplier`.
pub fn new_profile_applier(profile: &str, kflags: KeepFlags) -> Result<ProfileApplier, String> {
    let profile = match profile {
        PROFILE_LEGACY => Profile::Legacy,
        PROFILE_GENERAL => Profile::General,
        PROFILE_BASELINE => Profile::Baseline,
        PROFILE_RESTRICTED => Profile::Restricted,
        PROFILE_NETADMIN => Profile::Netadmin,
        PROFILE_SYSADMIN => Profile::Sysadmin,
        other => return Err(format!("unknown profile: {other}")),
    };
    Ok(ProfileApplier { profile, kflags })
}

/// `getDebugStyle`.
fn get_debug_style(target: &Target) -> Result<DebugStyle, String> {
    match target {
        Target::PodCopy => Ok(DebugStyle::PodCopy),
        Target::SamePod => Ok(DebugStyle::Ephemeral),
        Target::Node => Ok(DebugStyle::Node),
        Target::Other(t) => Err(format!("objects of type {t} are not supported")),
    }
}

impl ProfileApplier {
    fn name(&self) -> &'static str {
        match self.profile {
            Profile::Legacy => PROFILE_LEGACY,
            Profile::General => PROFILE_GENERAL,
            Profile::Baseline => PROFILE_BASELINE,
            Profile::Restricted => PROFILE_RESTRICTED,
            Profile::Netadmin => PROFILE_NETADMIN,
            Profile::Sysadmin => PROFILE_SYSADMIN,
        }
    }

    /// `Apply`: applies the profile to the container `container_name` of `pod`.
    pub fn apply(
        &self,
        pod: &mut Value,
        container_name: &str,
        target: &Target,
    ) -> Result<(), String> {
        let style = get_debug_style(target).map_err(|e| format!("{} profile: {e}", self.name()))?;
        let k = self.kflags;
        let copy_cleanup = |pod: &mut Value| {
            k.remove_labels(pod);
            k.remove_annotations(pod);
            k.remove_probes(pod);
            k.remove_init_containers(pod);
            share_process_namespace(pod);
        };
        match self.profile {
            Profile::Legacy => match style {
                DebugStyle::Node => {
                    mount_root_partition(pod, container_name);
                    use_host_namespaces(pod);
                }
                DebugStyle::PodCopy => {
                    // `p.Labels = false; p.RemoveLabels(pod)`: labels always go
                    KeepFlags { labels: false, ..k }.remove_labels(pod);
                }
                DebugStyle::Ephemeral => {}
            },
            Profile::General => match style {
                DebugStyle::Node => {
                    mount_root_partition(pod, container_name);
                    clear_security_context(pod, container_name);
                    use_host_namespaces(pod);
                }
                DebugStyle::PodCopy => {
                    k.remove_labels(pod);
                    k.remove_annotations(pod);
                    k.remove_probes(pod);
                    k.remove_init_containers(pod);
                    allow_process_tracing(pod, container_name);
                    share_process_namespace(pod);
                }
                DebugStyle::Ephemeral => allow_process_tracing(pod, container_name),
            },
            Profile::Baseline => {
                clear_security_context(pod, container_name);
                if style == DebugStyle::PodCopy {
                    copy_cleanup(pod);
                }
            }
            Profile::Restricted => {
                clear_security_context(pod, container_name);
                disallow_root(pod, container_name);
                drop_capabilities(pod, container_name);
                disallow_privilege_escalation(pod, container_name);
                set_seccomp_profile(pod, container_name);
                if style == DebugStyle::PodCopy {
                    copy_cleanup(pod);
                }
            }
            Profile::Netadmin => {
                allow_netadmin_capability(pod, container_name);
                match style {
                    DebugStyle::Node => use_host_namespaces(pod),
                    DebugStyle::PodCopy => copy_cleanup(pod),
                    DebugStyle::Ephemeral => {}
                }
            }
            Profile::Sysadmin => {
                set_privileged(pod, container_name);
                match style {
                    DebugStyle::Node => {
                        use_host_namespaces(pod);
                        mount_root_partition(pod, container_name);
                    }
                    // to mimic general, default and baseline
                    DebugStyle::PodCopy => copy_cleanup(pod),
                    DebugStyle::Ephemeral => {}
                }
            }
        }
        Ok(())
    }
}

fn remove_key(v: &mut Value, key: &str) {
    if let Some(m) = v.as_object_mut() {
        m.remove(key);
    }
}

/// `podutils.VisitContainers(.., AllContainers, ..)` stopping at the first
/// container named `name` (init, regular, then ephemeral containers).
fn with_container(p: &mut Value, name: &str, f: impl FnOnce(&mut Value)) {
    for list in ["initContainers", "containers", "ephemeralContainers"] {
        if let Some(cs) = p
            .get_mut("spec")
            .and_then(|s| s.get_mut(list))
            .and_then(Value::as_array_mut)
        {
            if let Some(c) = cs.iter_mut().find(|c| c["name"] == name) {
                f(c);
                return;
            }
        }
    }
}

fn security_context(c: &mut Value) -> &mut Map<String, Value> {
    if !c["securityContext"].is_object() {
        c["securityContext"] = json!({});
    }
    c["securityContext"].as_object_mut().unwrap()
}

/// `mountRootPartition`: the host's root at `/host` of the (regular)
/// container; the volume is added to the pod.
fn mount_root_partition(p: &mut Value, container_name: &str) {
    const VOLUME_NAME: &str = "host-root";
    if !p["spec"]["volumes"].is_array() {
        p["spec"]["volumes"] = json!([]);
    }
    p["spec"]["volumes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": VOLUME_NAME, "hostPath": {"path": "/"}}));
    // podutils.Containers: regular containers only
    if let Some(c) = p
        .get_mut("spec")
        .and_then(|s| s.get_mut("containers"))
        .and_then(Value::as_array_mut)
        .and_then(|cs| cs.iter_mut().find(|c| c["name"] == container_name))
    {
        if !c["volumeMounts"].is_array() {
            c["volumeMounts"] = json!([]);
        }
        c["volumeMounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"mountPath": "/host", "name": VOLUME_NAME}));
    }
}

/// `useHostNamespaces`.
fn use_host_namespaces(p: &mut Value) {
    p["spec"]["hostNetwork"] = json!(true);
    p["spec"]["hostPID"] = json!(true);
    p["spec"]["hostIPC"] = json!(true);
}

/// `shareProcessNamespace`: only when unset.
fn share_process_namespace(p: &mut Value) {
    if p["spec"]
        .get("shareProcessNamespace")
        .is_none_or(Value::is_null)
    {
        p["spec"]["shareProcessNamespace"] = json!(true);
    }
}

/// `clearSecurityContext`.
fn clear_security_context(p: &mut Value, name: &str) {
    with_container(p, name, |c| remove_key(c, "securityContext"));
}

/// `setPrivileged`.
fn set_privileged(p: &mut Value, name: &str) {
    with_container(p, name, |c| {
        security_context(c).insert("privileged".into(), json!(true));
    });
}

/// `disallowRoot`.
fn disallow_root(p: &mut Value, name: &str) {
    with_container(p, name, |c| {
        security_context(c).insert("runAsNonRoot".into(), json!(true));
    });
}

/// `dropCapabilities`: drop ALL, no adds.
fn drop_capabilities(p: &mut Value, name: &str) {
    with_container(p, name, |c| {
        let sc = security_context(c);
        let caps = sc.entry("capabilities").or_insert_with(|| json!({}));
        if !caps.is_object() {
            *caps = json!({});
        }
        caps["drop"] = json!(["ALL"]);
        remove_key(caps, "add");
    });
}

fn add_capability(c: &mut Value, capability: &str) {
    let sc = security_context(c);
    let caps = sc.entry("capabilities").or_insert_with(|| json!({}));
    if !caps.is_object() {
        *caps = json!({});
    }
    if !caps["add"].is_array() {
        caps["add"] = json!([]);
    }
    caps["add"].as_array_mut().unwrap().push(json!(capability));
}

/// `allowProcessTracing`: SYS_PTRACE.
fn allow_process_tracing(p: &mut Value, name: &str) {
    with_container(p, name, |c| add_capability(c, "SYS_PTRACE"));
}

/// `allowNetadminCapability`: NET_ADMIN and NET_RAW.
fn allow_netadmin_capability(p: &mut Value, name: &str) {
    with_container(p, name, |c| {
        add_capability(c, "NET_ADMIN");
        add_capability(c, "NET_RAW");
    });
}

/// `disallowPrivilegeEscalation`.
fn disallow_privilege_escalation(p: &mut Value, name: &str) {
    with_container(p, name, |c| {
        security_context(c).insert("allowPrivilegeEscalation".into(), json!(false));
    });
}

/// `setSeccompProfile`: RuntimeDefault.
fn set_seccomp_profile(p: &mut Value, name: &str) {
    with_container(p, name, |c| {
        security_context(c).insert("seccompProfile".into(), json!({"type": "RuntimeDefault"}));
    });
}
