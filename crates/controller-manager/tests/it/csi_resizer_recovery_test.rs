//! Port of `TestExpandAndRecover` (external-resizer
//! `pkg/controller/expand_and_recover_test.go`): the `allocatedResources` /
//! `allocatedResourceStatuses` recovery state machine, with a closure standing
//! in for the mock CSI client.
use chrono::Utc;
use kubernetes_rs_common::quantity::{Format, Quantity};
use kubernetes_rs_common::resources::volume::PersistentVolumeClaim;
use kubernetes_rs_common::resources::PersistentVolume;
use kubernetes_rs_controller_manager::controllers::csi_resizer::*;
use kubernetes_rs_csi::controller_client::ControllerError;
use serde_json::json;

const NS: &str = "default";

fn pvc(spec: &str, status: &str, allocated: &str, resize_status: &str) -> PersistentVolumeClaim {
    let mut st = json!({"phase": "Bound"});
    if !status.is_empty() {
        st["capacity"] = json!({"storage": status});
    }
    if !allocated.is_empty() {
        st["allocatedResources"] = json!({"storage": allocated});
    }
    if !resize_status.is_empty() {
        st["allocatedResourceStatuses"] = json!({"storage": resize_status});
    }
    serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": "claim01", "namespace": NS, "uid": "test-uid"},
        "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": spec}},
                 "volumeName": "test-vol0"},
        "status": st
    }))
    .unwrap()
}

fn pv(gib: i64) -> PersistentVolume {
    serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "PersistentVolume",
        "metadata": {"name": "testPV", "annotations": {}},
        "spec": {"accessModes": ["ReadWriteOnce"], "capacity": {"storage": format!("{gib}Gi")},
                 "csi": {"driver": "foo", "volumeHandle": "foo"}, "volumeMode": "Filesystem",
                 "claimRef": {"namespace": NS, "name": "claim01", "uid": "test-uid"}},
        "status": {"phase": "Bound"}
    }))
    .unwrap()
}

#[derive(Clone, Copy)]
enum Fail {
    None,
    Final,      // FailedPrecondition
    Infeasible, // InvalidArgument
}

struct Case {
    name: &'static str,
    pvc: PersistentVolumeClaim,
    pv: PersistentVolume,
    disable_node_expansion: bool,
    disable_controller_expansion: bool,
    expected_status: &'static str,
    expected_allocated: &'static str,
    expect_not_required_annotation: bool,
    final_errors: bool,
    fail: Fail,
    expect_resize_call: bool,
}

#[allow(clippy::too_many_arguments)]
fn case(
    name: &'static str,
    pvc: PersistentVolumeClaim,
    pv: PersistentVolume,
    expected_status: &'static str,
    expected_allocated: &'static str,
    expect_resize_call: bool,
) -> Case {
    Case {
        name,
        pvc,
        pv,
        disable_node_expansion: false,
        disable_controller_expansion: false,
        expected_status,
        expected_allocated,
        expect_not_required_annotation: false,
        final_errors: false,
        fail: Fail::None,
        expect_resize_call,
    }
}

#[tokio::test]
async fn csi_resizer_recovery_expand_and_recover_table() {
    let p = CLAIM_NODE_RESIZE_PENDING;
    let mut cases = vec![
        case(
            "spec > pv, no status",
            pvc("2G", "1G", "", ""),
            pv(1),
            p,
            "2G",
            true,
        ),
        case(
            "spec = pv, no status",
            pvc("1G", "1G", "", ""),
            pv(1),
            p,
            "1G",
            true,
        ),
        case(
            "spec > pv, controller_expansion_infeasible",
            pvc("5G", "3G", "10G", CLAIM_CONTROLLER_RESIZE_INFEASIBLE),
            pv(3),
            p,
            "5G",
            true,
        ),
        case(
            "spec > pv, controller_expansion_inprogress (final but feasible)",
            pvc("5G", "3G", "10G", CLAIM_CONTROLLER_RESIZE_IN_PROGRESS),
            pv(3),
            p,
            "5G",
            true,
        ),
        case(
            "spec > pv, controller_expansion_inprogress",
            pvc("5G", "3G", "10G", CLAIM_CONTROLLER_RESIZE_IN_PROGRESS),
            pv(3),
            p,
            "10G",
            true,
        ),
        case(
            "spec = pv, node_expansion_pending",
            pvc("1G", "1G", "1G", CLAIM_NODE_RESIZE_PENDING),
            pv(1),
            p,
            "1G",
            false,
        ),
        case(
            "pv >= spec, node_expansion_failed",
            pvc("2G", "1G", "2G", CLAIM_NODE_RESIZE_INFEASIBLE),
            pv(2),
            p,
            "2G",
            true,
        ),
        case(
            "spec > pv, node_expansion_pending",
            pvc("10G", "1G", "3G", CLAIM_NODE_RESIZE_PENDING),
            pv(3),
            p,
            "3G",
            false,
        ),
        case(
            "spec > pv, node_expansion_inprogress",
            pvc("10G", "1G", "3G", CLAIM_NODE_RESIZE_IN_PROGRESS),
            pv(3),
            CLAIM_NODE_RESIZE_IN_PROGRESS,
            "3G",
            false,
        ),
    ];
    cases[3].final_errors = true;
    let mut c = case(
        "final error then retry fails with final error",
        pvc("5G", "3G", "10G", CLAIM_CONTROLLER_RESIZE_IN_PROGRESS),
        pv(3),
        CLAIM_CONTROLLER_RESIZE_IN_PROGRESS,
        "5G",
        true,
    );
    c.final_errors = true;
    c.fail = Fail::Final;
    cases.push(c);
    let mut c = case(
        "final error then retry fails with infeasible error",
        pvc("5G", "3G", "10G", CLAIM_CONTROLLER_RESIZE_IN_PROGRESS),
        pv(3),
        CLAIM_CONTROLLER_RESIZE_INFEASIBLE,
        "5G",
        true,
    );
    c.final_errors = true;
    c.fail = Fail::Infeasible;
    cases.push(c);
    let mut c = case(
        "pv = spec, node_expansion_infeasible, controller expansion disabled",
        pvc("5G", "3G", "10G", CLAIM_NODE_RESIZE_INFEASIBLE),
        pv(10),
        p,
        "5G",
        true,
    );
    c.disable_controller_expansion = true;
    cases.push(c);
    let mut c = case(
        "spec > pv, node expansion disabled",
        pvc("2G", "1G", "", ""),
        pv(1),
        "",
        "2G",
        true,
    );
    c.disable_node_expansion = true;
    c.expect_not_required_annotation = true;
    cases.push(c);

    for c in cases {
        let mut state = ResizeState::default();
        if c.final_errors {
            state.final_error_pvcs.insert(format!("{NS}/claim01"));
        }
        let info = ResizerInfo {
            name: "foo",
            can_support: true,
            driver_supports_control_plane_expansion: !c.disable_controller_expansion,
        };
        let (fail, node_required) = (c.fail, !c.disable_node_expansion);
        let r = expand_and_recover(
            &mut state,
            info,
            &c.pvc,
            &c.pv,
            Utc::now(),
            |_pv, size| async move {
                match fail {
                    Fail::None => Ok(ResizeOutcome {
                        new_size: Quantity::parse(&size.canonical_string()).unwrap(),
                        node_resize_required: node_required,
                    }),
                    Fail::Final => Err(ResizeError::Driver(ControllerError::Grpc(Box::new(
                        tonic::Status::failed_precondition("something broke"),
                    )))),
                    Fail::Infeasible => Err(ResizeError::Driver(ControllerError::Grpc(Box::new(
                        tonic::Status::invalid_argument("something broke"),
                    )))),
                }
            },
        )
        .await;
        let ctx = c.name;
        if matches!(c.fail, Fail::None) {
            assert!(r.error.is_none(), "{ctx}: {:?}", r.error);
        }
        assert_eq!(r.resize_called, c.expect_resize_call, "{ctx}");
        let st = r.pvc.status.as_ref().unwrap();
        let got_status = st
            .allocated_resource_statuses
            .as_ref()
            .and_then(|m| m.get("storage"))
            .map(String::as_str)
            .unwrap_or("");
        assert_eq!(got_status, c.expected_status, "{ctx}");
        let annotated = r
            .pvc
            .metadata
            .annotations
            .as_ref()
            .is_some_and(|a| a.contains_key(NODE_EXPANSION_NOT_REQUIRED));
        assert_eq!(annotated, c.expect_not_required_annotation, "{ctx}");
        let allocated = st
            .allocated_resources
            .as_ref()
            .and_then(|m| m.get("storage"))
            .and_then(|s| Quantity::parse(s).ok())
            .unwrap_or_else(|| Quantity::from_value(0, Format::DecimalSI));
        let want = Quantity::parse(c.expected_allocated).unwrap();
        assert_eq!(
            allocated.cmp_value(&want),
            std::cmp::Ordering::Equal,
            "{ctx}: allocated {allocated}"
        );
    }
}

#[tokio::test]
async fn csi_resizer_recovery_not_bound_or_unsupported_is_a_noop() {
    let mut state = ResizeState::default();
    let p = pvc("2G", "1G", "", "");
    let mut other = pv(1);
    other.spec.claim_ref.as_mut().unwrap().uid = Some("someone-else".into());
    let info = ResizerInfo {
        name: "foo",
        can_support: true,
        driver_supports_control_plane_expansion: true,
    };
    let r = expand_and_recover(&mut state, info, &p, &other, Utc::now(), |_, _| async {
        panic!("resize must not be called")
    })
    .await;
    assert!(!r.resize_called && r.error.is_none());
    let info = ResizerInfo {
        can_support: false,
        ..info
    };
    let r = expand_and_recover(&mut state, info, &p, &pv(1), Utc::now(), |_, _| async {
        panic!("resize must not be called")
    })
    .await;
    assert!(!r.resize_called);
}

#[tokio::test]
async fn csi_resizer_recovery_infeasible_goes_to_slow_set_and_skips_same_size() {
    // markForSlowRetry then "skipping volume expansion" for an infeasible size
    // that was already allocated.
    let mut state = ResizeState::default();
    state.slow_set.insert(format!("{NS}/claim01"));
    let p = pvc("5G", "3G", "5G", CLAIM_CONTROLLER_RESIZE_INFEASIBLE);
    let info = ResizerInfo {
        name: "foo",
        can_support: true,
        driver_supports_control_plane_expansion: true,
    };
    let r = expand_and_recover(&mut state, info, &p, &pv(3), Utc::now(), |_, _| async {
        panic!("resize must not be called")
    })
    .await;
    assert!(!r.resize_called);
    assert_eq!(
        r.error.as_deref(),
        Some("skipping volume expansion for pvc default/claim01, because expansion previously failed with infeasible error")
    );
}

#[test]
fn csi_resizer_recovery_mark_overall_finished_clears_status_and_annotates() {
    let p = pvc("2G", "1G", "2G", CLAIM_NODE_RESIZE_PENDING);
    let (out, ev) = mark_overall_expansion_as_finished(&p, &Quantity::parse("2G").unwrap());
    let st = out.status.unwrap();
    assert!(st.allocated_resource_statuses.is_none());
    assert_eq!(st.capacity.unwrap()["storage"], "2G");
    assert_eq!(
        out.metadata.annotations.unwrap()[NODE_EXPANSION_NOT_REQUIRED],
        "true"
    );
    assert_eq!(ev.reason, EVENT_VOLUME_RESIZE_SUCCESS);
}

#[test]
fn csi_resizer_recovery_update_pv_capacity_annotates_once() {
    let p = pv(1);
    let old = Quantity::parse("1Gi").unwrap();
    let new = Quantity::parse("2Gi").unwrap();
    let a = update_pv_capacity(&p, &old, &new, true);
    assert_eq!(a.spec.capacity["storage"], "2Gi");
    assert_eq!(
        a.metadata.annotations.as_ref().unwrap()[ANN_PRE_RESIZE_CAPACITY],
        "1Gi"
    );
    let b = update_pv_capacity(&a, &new, &Quantity::parse("3Gi").unwrap(), true);
    assert_eq!(
        b.metadata.annotations.unwrap()[ANN_PRE_RESIZE_CAPACITY],
        "1Gi"
    );
    let c = update_pv_capacity(&p, &old, &new, false);
    assert!(!c
        .metadata
        .annotations
        .unwrap()
        .contains_key(ANN_PRE_RESIZE_CAPACITY));
}
