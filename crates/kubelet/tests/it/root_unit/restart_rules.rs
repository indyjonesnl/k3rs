//! Port of `TestShouldContainerBeRestarted`
//! (pkg/kubelet/container/helpers_test.go:397, release-1.35) plus the
//! container-level policy and `restartPolicyRules` paths of
//! `podutil.ContainerShouldRestart` (pkg/api/v1/pod/util.go:419).

use chrono::Utc;
use kubernetes_rs_common::resources::pod::{ContainerRestartRule, ContainerRestartRuleOnExitCodes};
use kubernetes_rs_common::resources::{Container, Pod, PodSpec};
use kubernetes_rs_kubelet::lifecycle::{
    should_container_be_restarted, RuntimeContainerState as S, RuntimeContainerStatus,
};

fn st(name: &str, state: S, exit_code: i32) -> RuntimeContainerStatus {
    RuntimeContainerStatus {
        name: name.into(),
        state,
        exit_code,
    }
}

fn container(name: &str) -> Container {
    Container {
        name: name.into(),
        ..Default::default()
    }
}

fn pod(containers: Vec<Container>, policy: &str) -> Pod {
    Pod::new(
        "p",
        PodSpec {
            containers,
            restart_policy: Some(policy.into()),
            ..Default::default()
        },
    )
}

fn statuses() -> Vec<RuntimeContainerStatus> {
    vec![
        st("alive", S::Running, 0),
        st("succeed", S::Exited, 0),
        st("failed", S::Exited, 1),
        st("alive", S::Exited, 2),
        st("unknown", S::Unknown, 0),
        st("failed", S::Exited, 3),
    ]
}

#[test]
fn restart_rules_should_container_be_restarted_policies() {
    let names = ["no-history", "alive", "succeed", "failed", "unknown"];
    let policies = ["Never", "OnFailure", "Always"];
    let expected: [[bool; 3]; 5] = [
        [true, true, true],
        [false, false, false],
        [false, false, true],
        [false, true, true],
        [true, true, true],
    ];
    let containers: Vec<_> = names.iter().map(|n| container(n)).collect();
    for (ci, c) in containers.iter().enumerate() {
        for (pi, policy) in policies.iter().enumerate() {
            let p = pod(containers.clone(), policy);
            assert_eq!(
                should_container_be_restarted(c, &p, &statuses()),
                expected[ci][pi],
                "{} with {policy}",
                c.name
            );
        }
    }
}

#[test]
fn restart_rules_deleted_pod_is_never_restarted() {
    let names = ["no-history", "alive", "succeed", "failed", "unknown"];
    let containers: Vec<_> = names.iter().map(|n| container(n)).collect();
    for policy in ["Never", "OnFailure", "Always"] {
        let mut p = pod(containers.clone(), policy);
        p.metadata.deletion_timestamp = Some(Utc::now());
        for c in &containers {
            assert!(
                !should_container_be_restarted(c, &p, &statuses()),
                "{}",
                c.name
            );
        }
    }
}

#[test]
fn restart_rules_created_state_restarts() {
    let c = container("c");
    let p = pod(vec![c.clone()], "Never");
    assert!(should_container_be_restarted(
        &c,
        &p,
        &[st("c", S::Created, 0)]
    ));
}

fn rule(action: &str, op: &str, values: Vec<i32>) -> ContainerRestartRule {
    ContainerRestartRule {
        action: action.into(),
        exit_codes: Some(ContainerRestartRuleOnExitCodes {
            operator: op.into(),
            values: Some(values),
        }),
    }
}

#[test]
fn restart_rules_container_policy_and_rules() {
    // container policy wins over the pod's
    let mut c = container("c");
    c.restart_policy = Some("Always".into());
    let p = pod(vec![c.clone()], "Never");
    assert!(should_container_be_restarted(
        &c,
        &p,
        &[st("c", S::Exited, 0)]
    ));

    // Never on the container, OnFailure on the pod: container wins
    let mut c = container("c");
    c.restart_policy = Some("Never".into());
    let p = pod(vec![c.clone()], "OnFailure");
    assert!(!should_container_be_restarted(
        &c,
        &p,
        &[st("c", S::Exited, 1)]
    ));

    // rules: In
    let mut c = container("c");
    c.restart_policy = Some("Never".into());
    c.restart_policy_rules = Some(vec![rule("Restart", "In", vec![42, 43])]);
    let p = pod(vec![c.clone()], "Never");
    assert!(should_container_be_restarted(
        &c,
        &p,
        &[st("c", S::Exited, 42)]
    ));
    assert!(!should_container_be_restarted(
        &c,
        &p,
        &[st("c", S::Exited, 1)]
    ));

    // rules: NotIn, first matching rule wins
    let mut c = container("c");
    c.restart_policy = Some("Never".into());
    c.restart_policy_rules = Some(vec![rule("Restart", "NotIn", vec![0])]);
    let p = pod(vec![c.clone()], "Never");
    assert!(should_container_be_restarted(
        &c,
        &p,
        &[st("c", S::Exited, 7)]
    ));
    assert!(!should_container_be_restarted(
        &c,
        &p,
        &[st("c", S::Exited, 0)]
    ));

    // rules are ignored without a container-level restartPolicy
    let mut c = container("c");
    c.restart_policy_rules = Some(vec![rule("Restart", "In", vec![42])]);
    let p = pod(vec![c.clone()], "Never");
    assert!(!should_container_be_restarted(
        &c,
        &p,
        &[st("c", S::Exited, 42)]
    ));
}
