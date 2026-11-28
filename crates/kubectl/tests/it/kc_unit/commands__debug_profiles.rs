//! Ported from `kubectl/pkg/cmd/debug/profiles_test.go` (release-1.35):
//! Test{Legacy,General,Baseline,Restricted,NetAdmin,SysAdmin}Profile, each
//! with the bad-input, ephemeral container, pod copy and node cases, over the
//! pod JSON (a field upstream leaves nil is absent here).
use kubernetes_rs_kubectl::commands::debug::profiles::*;
use serde_json::{json, Value};

fn flags() -> KeepFlags {
    KeepFlags {
        init_containers: true,
        ..Default::default()
    }
}

fn run(profile: &str, mut pod: Value, target: Target) -> Value {
    new_profile_applier(profile, flags())
        .unwrap()
        .apply(&mut pod, "dbg", &target)
        .unwrap();
    pod
}

fn ephemeral_pod(sc: Option<Value>) -> Value {
    let mut c = json!({"name": "dbg", "image": "dbgimage"});
    if let Some(sc) = sc {
        c["securityContext"] = sc;
    }
    json!({"metadata": {"name": "pod"}, "spec": {"ephemeralContainers": [c]}})
}

/// The `podcopy` source pod of the upstream tests; `dbg` carries `dbg_sc`.
fn copy_pod(dbg_sc: Option<Value>) -> Value {
    let mut dbg = json!({"name": "dbg", "image": "dbgimage"});
    if let Some(sc) = dbg_sc {
        dbg["securityContext"] = sc;
    }
    json!({
        "metadata": {"name": "podcopy", "labels": {"app": "podcopy"}, "annotations": {"test": "test"}},
        "spec": {
            "initContainers": [{"name": "init-container"}],
            "containers": [
                {"name": "app", "image": "appimage",
                 "livenessProbe": {}, "readinessProbe": {}, "startupProbe": {}},
                dbg
            ]
        }
    })
}

fn node_pod(sc: Option<Value>) -> Value {
    let mut dbg = json!({"name": "dbg", "image": "dbgimage"});
    if let Some(sc) = sc {
        dbg["securityContext"] = sc;
    }
    json!({"metadata": {"name": "pod"}, "spec": {"containers": [dbg]}})
}

fn host_root_node(dbg: Value, namespaces: bool) -> Value {
    let mut dbg = dbg;
    dbg["volumeMounts"] = json!([{"mountPath": "/host", "name": "host-root"}]);
    let mut spec = json!({
        "containers": [dbg],
        "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}]
    });
    if namespaces {
        spec["hostNetwork"] = json!(true);
        spec["hostPID"] = json!(true);
        spec["hostIPC"] = json!(true);
    }
    json!({"metadata": {"name": "pod"}, "spec": spec})
}

fn caps_add(v: &[&str]) -> Value {
    json!({"capabilities": {"add": v}})
}

#[test]
fn debug_profile_bad_inputs_and_unknown_profile() {
    for p in [
        PROFILE_LEGACY,
        PROFILE_GENERAL,
        PROFILE_BASELINE,
        PROFILE_RESTRICTED,
        PROFILE_NETADMIN,
        PROFILE_SYSADMIN,
    ] {
        let a = new_profile_applier(p, flags()).unwrap();
        let err = a
            .apply(&mut json!({}), "dbg", &Target::Other("<nil>".into()))
            .unwrap_err();
        assert_eq!(
            err,
            format!("{p} profile: objects of type <nil> are not supported")
        );
    }
    assert_eq!(
        new_profile_applier("bogus", flags()).unwrap_err(),
        "unknown profile: bogus"
    );
}

#[test]
fn debug_profile_legacy() {
    assert_eq!(
        run(PROFILE_LEGACY, ephemeral_pod(None), Target::SamePod),
        ephemeral_pod(None)
    );
    // pod copy: labels removed even with keep flags empty; annotations/probes kept
    let got = run(
        PROFILE_LEGACY,
        copy_pod(Some(caps_add(&["NET_ADMIN"]))),
        Target::PodCopy,
    );
    let mut want = copy_pod(Some(caps_add(&["NET_ADMIN"])));
    want["metadata"].as_object_mut().unwrap().remove("labels");
    assert_eq!(got, want);
    // node
    let got = run(
        PROFILE_LEGACY,
        node_pod(Some(caps_add(&["NET_ADMIN"]))),
        Target::Node,
    );
    let want = host_root_node(
        json!({"name": "dbg", "image": "dbgimage", "securityContext": caps_add(&["NET_ADMIN"])}),
        true,
    );
    assert_eq!(got, want);
}

#[test]
fn debug_profile_general() {
    let want = ephemeral_pod(Some(caps_add(&["SYS_PTRACE"])));
    assert_eq!(
        run(PROFILE_GENERAL, ephemeral_pod(None), Target::SamePod),
        want
    );

    let got = run(
        PROFILE_GENERAL,
        copy_pod(Some(caps_add(&["NET_ADMIN"]))),
        Target::PodCopy,
    );
    assert_eq!(
        got,
        json!({
            "metadata": {"name": "podcopy"},
            "spec": {
                "initContainers": [{"name": "init-container"}],
                "containers": [
                    {"name": "app", "image": "appimage"},
                    {"name": "dbg", "image": "dbgimage",
                     "securityContext": caps_add(&["NET_ADMIN", "SYS_PTRACE"])}
                ],
                "shareProcessNamespace": true
            }
        })
    );

    // node: security context cleared
    let got = run(
        PROFILE_GENERAL,
        node_pod(Some(caps_add(&["NET_ADMIN"]))),
        Target::Node,
    );
    assert_eq!(
        got,
        host_root_node(json!({"name": "dbg", "image": "dbgimage"}), true)
    );
}

#[test]
fn debug_profile_baseline() {
    // ephemeral: security context cleared
    let got = run(
        PROFILE_BASELINE,
        ephemeral_pod(Some(json!({"privileged": true}))),
        Target::SamePod,
    );
    assert_eq!(got, ephemeral_pod(None));

    let got = run(
        PROFILE_BASELINE,
        copy_pod(Some(caps_add(&["NET_ADMIN"]))),
        Target::PodCopy,
    );
    assert_eq!(
        got,
        json!({
            "metadata": {"name": "podcopy"},
            "spec": {
                "initContainers": [{"name": "init-container"}],
                "containers": [
                    {"name": "app", "image": "appimage"},
                    {"name": "dbg", "image": "dbgimage"}
                ],
                "shareProcessNamespace": true
            }
        })
    );

    // node: only the security context goes (no host namespaces, no mounts)
    let got = run(
        PROFILE_BASELINE,
        node_pod(Some(caps_add(&["NET_ADMIN"]))),
        Target::Node,
    );
    assert_eq!(got, node_pod(None));
}

fn restricted_sc() -> Value {
    json!({
        "runAsNonRoot": true,
        "capabilities": {"drop": ["ALL"]},
        "allowPrivilegeEscalation": false,
        "seccompProfile": {"type": "RuntimeDefault"}
    })
}

#[test]
fn debug_profile_restricted() {
    let got = run(
        PROFILE_RESTRICTED,
        ephemeral_pod(Some(caps_add(&["SYS_PTRACE"]))),
        Target::SamePod,
    );
    assert_eq!(got, ephemeral_pod(Some(restricted_sc())));

    let got = run(PROFILE_RESTRICTED, copy_pod(None), Target::PodCopy);
    assert_eq!(
        got,
        json!({
            "metadata": {"name": "podcopy"},
            "spec": {
                "shareProcessNamespace": true,
                "initContainers": [{"name": "init-container"}],
                "containers": [
                    {"name": "app", "image": "appimage"},
                    {"name": "dbg", "image": "dbgimage", "securityContext": restricted_sc()}
                ]
            }
        })
    );

    // node: an existing `add: [ALL]` is replaced by drop ALL
    let sc = json!({
        "capabilities": {"add": ["ALL"]},
        "allowPrivilegeEscalation": false,
        "seccompProfile": {"type": "RuntimeDefault"}
    });
    let got = run(PROFILE_RESTRICTED, node_pod(Some(sc)), Target::Node);
    assert_eq!(got, node_pod(Some(restricted_sc())));
}

#[test]
fn debug_profile_netadmin() {
    let want = ephemeral_pod(Some(caps_add(&["NET_ADMIN", "NET_RAW"])));
    assert_eq!(
        run(PROFILE_NETADMIN, ephemeral_pod(None), Target::SamePod),
        want
    );

    let got = run(PROFILE_NETADMIN, copy_pod(None), Target::PodCopy);
    assert_eq!(
        got,
        json!({
            "metadata": {"name": "podcopy"},
            "spec": {
                "initContainers": [{"name": "init-container"}],
                "containers": [
                    {"name": "app", "image": "appimage"},
                    {"name": "dbg", "image": "dbgimage",
                     "securityContext": caps_add(&["NET_ADMIN", "NET_RAW"])}
                ],
                "shareProcessNamespace": true
            }
        })
    );

    // node: host namespaces, no root mount
    let got = run(PROFILE_NETADMIN, node_pod(None), Target::Node);
    assert_eq!(
        got,
        json!({"metadata": {"name": "pod"}, "spec": {
            "hostNetwork": true, "hostPID": true, "hostIPC": true,
            "containers": [{"name": "dbg", "image": "dbgimage",
                            "securityContext": caps_add(&["NET_ADMIN", "NET_RAW"])}]}})
    );
}

#[test]
fn debug_profile_sysadmin() {
    let priv_sc = json!({"privileged": true});
    assert_eq!(
        run(PROFILE_SYSADMIN, ephemeral_pod(None), Target::SamePod),
        ephemeral_pod(Some(priv_sc.clone()))
    );

    let got = run(PROFILE_SYSADMIN, copy_pod(None), Target::PodCopy);
    assert_eq!(
        got,
        json!({
            "metadata": {"name": "podcopy"},
            "spec": {
                "initContainers": [{"name": "init-container"}],
                "containers": [
                    {"name": "app", "image": "appimage"},
                    {"name": "dbg", "image": "dbgimage", "securityContext": priv_sc.clone()}
                ],
                "shareProcessNamespace": true
            }
        })
    );

    let got = run(PROFILE_SYSADMIN, node_pod(None), Target::Node);
    assert_eq!(
        got,
        host_root_node(
            json!({"name": "dbg", "image": "dbgimage", "securityContext": priv_sc}),
            true
        )
    );
}

#[test]
fn debug_profile_keep_flags_and_init_containers() {
    let keep = KeepFlags {
        labels: true,
        annotations: true,
        liveness: true,
        readiness: true,
        startup: true,
        init_containers: false,
    };
    let a = new_profile_applier(PROFILE_GENERAL, keep).unwrap();
    let mut pod = copy_pod(None);
    a.apply(&mut pod, "dbg", &Target::PodCopy).unwrap();
    assert_eq!(pod["metadata"]["labels"], json!({"app": "podcopy"}));
    assert_eq!(pod["metadata"]["annotations"], json!({"test": "test"}));
    assert_eq!(pod["spec"]["containers"][0]["livenessProbe"], json!({}));
    assert!(pod["spec"].get("initContainers").is_none());
    // an existing shareProcessNamespace is not overwritten
    let mut pod = copy_pod(None);
    pod["spec"]["shareProcessNamespace"] = json!(false);
    a.apply(&mut pod, "dbg", &Target::PodCopy).unwrap();
    assert_eq!(pod["spec"]["shareProcessNamespace"], json!(false));
}
