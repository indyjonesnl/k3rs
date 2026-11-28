//! Ports of `staging/src/k8s.io/kubectl/pkg/polymorphichelpers/rollout_status_test.go`
//! (TestDeploymentStatusViewerStatus, TestDaemonSetStatusViewerStatus,
//! TestStatefulSetStatusViewerStatus, the wrong-strategy and revision cases).

use kubernetes_rs_kubectl::commands::rollout::rollout_status_message;
use serde_json::{json, Value};

fn deployment(generation: i64, spec_replicas: i64, status: Value) -> Value {
    json!({"metadata": {"name": "foo", "generation": generation},
           "spec": {"replicas": spec_replicas}, "status": status})
}

fn dep(g: i64, spec: i64, obs: i64, rep: i64, upd: i64, avail: i64) -> Value {
    deployment(
        g,
        spec,
        json!({"observedGeneration": obs, "replicas": rep, "updatedReplicas": upd,
               "availableReplicas": avail}),
    )
}

#[test]
fn rollout_status_deployment_viewer() {
    let cases = [
        (dep(0, 1, 1, 1, 0, 1), "Waiting for deployment \"foo\" rollout to finish: 0 out of 1 new replicas have been updated...\n", false),
        (dep(1, 1, 1, 2, 1, 2), "Waiting for deployment \"foo\" rollout to finish: 1 old replicas are pending termination...\n", false),
        (dep(1, 2, 1, 2, 2, 1), "Waiting for deployment \"foo\" rollout to finish: 1 of 2 updated replicas are available...\n", false),
        (dep(1, 2, 1, 2, 2, 2), "deployment \"foo\" successfully rolled out\n", true),
        (dep(2, 2, 1, 2, 2, 2), "Waiting for deployment spec update to be observed...\n", false),
    ];
    for (obj, msg, done) in cases {
        assert_eq!(
            rollout_status_message("Deployment", &obj, 0),
            Ok((msg.to_string(), done))
        );
    }
}

#[test]
fn rollout_status_deployment_revision_and_deadline() {
    let mut d = dep(1, 1, 1, 1, 1, 1);
    d["metadata"]["annotations"] = json!({"deployment.kubernetes.io/revision": "3"});
    assert!(rollout_status_message("Deployment", &d, 3).unwrap().1);
    assert_eq!(
        rollout_status_message("Deployment", &d, 2).unwrap_err(),
        "desired revision (2) is different from the running revision (3)"
    );
    d["metadata"]["annotations"] = json!({"deployment.kubernetes.io/revision": "x"});
    assert!(rollout_status_message("Deployment", &d, 1)
        .unwrap_err()
        .starts_with("cannot get the revision of deployment \"foo\": "));
    let mut d = dep(1, 1, 1, 1, 1, 1);
    d["status"]["conditions"] =
        json!([{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}]);
    assert_eq!(
        rollout_status_message("Deployment", &d, 0).unwrap_err(),
        "deployment \"foo\" exceeded its progress deadline"
    );
}

fn ds(generation: i64, strategy: &str, status: Value) -> Value {
    json!({"metadata": {"name": "foo", "generation": generation},
           "spec": {"updateStrategy": {"type": strategy}}, "status": status})
}

#[test]
fn rollout_status_daemon_set_viewer() {
    let st = |obs, desired, upd, avail| {
        json!({"observedGeneration": obs, "desiredNumberScheduled": desired,
               "updatedNumberScheduled": upd, "numberAvailable": avail})
    };
    let cases = [
        (ds(1, "RollingUpdate", st(1, 1, 0, 0)), "Waiting for daemon set \"foo\" rollout to finish: 0 out of 1 new pods have been updated...\n", false),
        (ds(1, "RollingUpdate", st(1, 2, 2, 1)), "Waiting for daemon set \"foo\" rollout to finish: 1 of 2 updated pods are available...\n", false),
        (ds(1, "RollingUpdate", st(1, 2, 2, 2)), "daemon set \"foo\" successfully rolled out\n", true),
        (ds(2, "RollingUpdate", st(1, 2, 2, 2)), "Waiting for daemon set spec update to be observed...\n", false),
    ];
    for (obj, msg, done) in cases {
        assert_eq!(
            rollout_status_message("DaemonSet", &obj, 0),
            Ok((msg.to_string(), done))
        );
    }
    assert_eq!(
        rollout_status_message("DaemonSet", &ds(1, "OnDelete", json!({})), 0).unwrap_err(),
        "rollout status is only available for RollingUpdate strategy type"
    );
}

fn sts(generation: i64, strategy: Value, status: Value) -> Value {
    json!({"metadata": {"name": "foo", "generation": generation},
           "spec": {"replicas": 3, "updateStrategy": strategy}, "status": status})
}

#[test]
fn rollout_status_stateful_set_viewer() {
    let rolling = |partition: Option<i64>| match partition {
        Some(p) => json!({"type": "RollingUpdate", "rollingUpdate": {"partition": p}}),
        None => json!({"type": "RollingUpdate"}),
    };
    let st = |obs, ready, cur, upd, cur_rev: &str, upd_rev: &str| {
        json!({"observedGeneration": obs, "replicas": 3, "readyReplicas": ready,
               "currentReplicas": cur, "updatedReplicas": upd,
               "currentRevision": cur_rev, "updateRevision": upd_rev})
    };
    assert_eq!(
        rollout_status_message(
            "StatefulSet",
            &sts(1, json!({"type": "OnDelete"}), st(1, 1, 0, 0, "", "")),
            0
        )
        .unwrap_err(),
        "rollout status is only available for RollingUpdate strategy type"
    );
    let cases = [
        (sts(2, rolling(None), st(1, 3, 3, 3, "", "")), "Waiting for statefulset spec update to be observed...\n", false),
        (sts(1, rolling(None), st(1, 2, 3, 3, "", "")), "Waiting for 1 pods to be ready...\n", false),
        (sts(1, rolling(Some(2)), st(2, 3, 2, 1, "", "")), "partitioned roll out complete: 1 new pods have been updated...\n", true),
        (sts(1, rolling(Some(2)), st(2, 3, 3, 0, "", "")), "Waiting for partitioned roll out to finish: 0 out of 1 new pods have been updated...\n", false),
        (sts(1, rolling(None), st(2, 3, 3, 3, "foo", "foo")), "statefulset rolling update complete 3 pods at revision foo...\n", true),
        (sts(1, rolling(None), st(2, 3, 3, 1, "foo", "bar")), "waiting for statefulset rolling update to complete 1 pods at revision bar...\n", false),
    ];
    for (obj, msg, done) in cases {
        assert_eq!(
            rollout_status_message("StatefulSet", &obj, 0),
            Ok((msg.to_string(), done))
        );
    }
}

#[test]
fn rollout_status_unsupported_kind() {
    assert_eq!(
        rollout_status_message("Job", &json!({}), 0).unwrap_err(),
        "no status viewer has been implemented for Job"
    );
}
