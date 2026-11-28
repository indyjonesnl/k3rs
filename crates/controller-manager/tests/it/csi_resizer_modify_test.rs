//! The VolumeAttributesClass ModifyVolume path of the CSI external-resizer.
//!
//! Upstream: kubernetes-csi/external-resizer `pkg/modifycontroller/
//! modify_volume_test.go` (`TestModify`, `TestModifyUncertain`, `TestCancel`)
//! against in-memory fakes for the driver, the VAC lister and the patches.

use kubernetes_rs_common::resources::csi::VolumeAttributesClass;
use kubernetes_rs_common::resources::volume::PersistentVolumeClaim;
use kubernetes_rs_common::resources::PersistentVolume;
use kubernetes_rs_controller_manager::controllers::csi_resizer::*;
use kubernetes_rs_csi::controller_client::ControllerError;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TEST_VAC: &str = "test-vac";
const TARGET_VAC: &str = "target-vac";

#[derive(Default)]
struct Driver {
    error: Mutex<Option<tonic::Code>>,
    params: Mutex<Option<HashMap<String, String>>>,
}

#[async_trait::async_trait]
impl Modifier for Driver {
    async fn modify(
        &self,
        _pv: &PersistentVolume,
        p: HashMap<String, String>,
    ) -> Result<(), ControllerError> {
        *self.params.lock().unwrap() = Some(p);
        match *self.error.lock().unwrap() {
            Some(c) => Err(ControllerError::Grpc(Box::new(tonic::Status::new(
                c, "boom",
            )))),
            None => Ok(()),
        }
    }
}

#[derive(Default)]
struct Store {
    vacs: Mutex<HashMap<String, VolumeAttributesClass>>,
    events: Mutex<Vec<(String, String)>>,
}

#[async_trait::async_trait]
impl ModifyStore for Store {
    async fn get_vac(&self, name: &str) -> Result<Option<VolumeAttributesClass>, String> {
        Ok(self.vacs.lock().unwrap().get(name).cloned())
    }
    async fn patch_claim(
        &self,
        _old: &PersistentVolumeClaim,
        new: &PersistentVolumeClaim,
        _check: bool,
    ) -> Result<PersistentVolumeClaim, String> {
        Ok(new.clone())
    }
    async fn patch_pv(
        &self,
        _old: &PersistentVolume,
        new: &PersistentVolume,
    ) -> Result<PersistentVolume, String> {
        Ok(new.clone())
    }
    async fn record_event(
        &self,
        _pvc: &PersistentVolumeClaim,
        t: &str,
        reason: &str,
        _msg: String,
    ) {
        self.events.lock().unwrap().push((t.into(), reason.into()));
    }
}

fn vac(name: &str, iops: &str) -> VolumeAttributesClass {
    serde_json::from_value(json!({"metadata":{"name":name},"driverName":"d",
        "parameters":{"iops":iops}}))
    .unwrap()
}

/// `createTestPVC`.
fn pvc(vac: &str, cur: &str, target: &str) -> PersistentVolumeClaim {
    let mut v = json!({"metadata":{"name":"pvc","namespace":"ns"},
        "spec":{"volumeAttributesClassName":vac,"volumeName":"testPV"},
        "status":{"phase":"Bound","currentVolumeAttributesClassName":cur}});
    if !target.is_empty() {
        v["status"]["modifyVolumeStatus"] =
            json!({"targetVolumeAttributesClassName":target,"status":"Infeasible"});
    }
    serde_json::from_value(v).unwrap()
}

fn pv() -> PersistentVolume {
    serde_json::from_value(json!({"metadata":{"name":"testPV"},
        "spec":{"volumeAttributesClassName":TEST_VAC,
        "csi":{"driver":"d","volumeHandle":"vol-1"}}}))
    .unwrap()
}

type Fixture = (
    ModifyController<Arc<Driver>, Arc<Store>>,
    Arc<Driver>,
    Arc<Store>,
);

fn ctrl(target_exists: bool, extra: bool) -> Fixture {
    let d = Arc::new(Driver::default());
    let s = Arc::new(Store::default());
    s.vacs
        .lock()
        .unwrap()
        .insert(TEST_VAC.into(), vac(TEST_VAC, "3000"));
    if target_exists {
        s.vacs
            .lock()
            .unwrap()
            .insert(TARGET_VAC.into(), vac(TARGET_VAC, "4567"));
    }
    (
        ModifyController::new(d.clone(), s.clone(), extra, Duration::from_secs(60)),
        d,
        s,
    )
}

fn status_of(p: &PersistentVolumeClaim) -> Option<(String, String)> {
    p.status.as_ref()?.modify_volume_status.as_ref().map(|m| {
        (
            m.target_volume_attributes_class_name
                .clone()
                .unwrap_or_default(),
            m.status.clone(),
        )
    })
}

fn current(p: &PersistentVolumeClaim) -> Option<String> {
    p.status
        .as_ref()?
        .current_volume_attributes_class_name
        .clone()
}

#[tokio::test]
async fn csi_resizer_modify_nothing_to_modify() {
    let (c, d, _) = ctrl(false, false);
    let (p, v, err, called) = c.modify(pvc(TEST_VAC, TEST_VAC, ""), pv()).await;
    assert!(err.is_none() && !called);
    assert!(d.params.lock().unwrap().is_none());
    assert_eq!(status_of(&p), None);
    assert_eq!(current(&p).as_deref(), Some(TEST_VAC));
    assert_eq!(
        v.spec.volume_attributes_class_name.as_deref(),
        Some(TEST_VAC)
    );
}

#[tokio::test]
async fn csi_resizer_modify_missing_vac_sets_pending() {
    let (c, d, _) = ctrl(false, false);
    let (p, _, err, called) = c.modify(pvc(TARGET_VAC, TEST_VAC, "whatever"), pv()).await;
    assert!(err.is_none() && !called);
    assert!(d.params.lock().unwrap().is_none());
    assert_eq!(status_of(&p), Some(("whatever".into(), "Pending".into())));
    assert_eq!(current(&p).as_deref(), Some(TEST_VAC));
}

#[tokio::test]
async fn csi_resizer_modify_success() {
    let (c, d, s) = ctrl(true, false);
    let (p, v, err, called) = c.modify(pvc(TARGET_VAC, TEST_VAC, TEST_VAC), pv()).await;
    assert!(err.is_none(), "{err:?}");
    assert!(called);
    assert_eq!(status_of(&p), None);
    assert_eq!(current(&p).as_deref(), Some(TARGET_VAC));
    assert_eq!(
        v.spec.volume_attributes_class_name.as_deref(),
        Some(TARGET_VAC)
    );
    assert_eq!(
        d.params.lock().unwrap().clone().unwrap(),
        HashMap::from([("iops".to_string(), "4567".to_string())])
    );
    let reasons: Vec<String> = s
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|e| e.1.clone())
        .collect();
    assert_eq!(reasons, [EVENT_VOLUME_MODIFY, EVENT_VOLUME_MODIFY_SUCCESS]);
}

#[tokio::test]
async fn csi_resizer_modify_success_with_extra_metadata() {
    let (c, d, _) = ctrl(true, true);
    let (_, _, err, called) = c.modify(pvc(TARGET_VAC, TEST_VAC, TEST_VAC), pv()).await;
    assert!(err.is_none() && called);
    assert_eq!(
        d.params.lock().unwrap().clone().unwrap(),
        HashMap::from([
            ("iops".to_string(), "4567".to_string()),
            (PVC_NAME_KEY.to_string(), "pvc".to_string()),
            (PVC_NAMESPACE_KEY.to_string(), "ns".to_string()),
            (PV_NAME_KEY.to_string(), "testPV".to_string()),
        ])
    );
}

#[tokio::test]
async fn csi_resizer_modify_uncertain() {
    let (c, d, _) = ctrl(true, false);
    let mut base = pvc(TARGET_VAC, TEST_VAC, TARGET_VAC);
    base.status
        .as_mut()
        .unwrap()
        .modify_volume_status
        .as_mut()
        .unwrap()
        .status = MODIFY_IN_PROGRESS.into();
    c.init_uncertain_pvcs(std::slice::from_ref(&base));
    assert!(c.is_uncertain("ns/pvc"));

    // A final error clears the uncertain state.
    *d.error.lock().unwrap() = Some(tonic::Code::Internal);
    let (p, v, err, _) = c.modify(base, pv()).await;
    assert!(matches!(err, Some(ModifyError::Driver(_))));
    assert!(!c.is_uncertain("ns/pvc"));

    // A non-final error enters it again.
    *d.error.lock().unwrap() = Some(tonic::Code::Unavailable);
    let (mut p, v, err, _) = c.modify(p, v).await;
    assert!(matches!(err, Some(ModifyError::Driver(_))));
    assert!(c.is_uncertain("ns/pvc"));

    // The target does not change while uncertain.
    p.spec.volume_attributes_class_name = Some("yet-another-vac".into());
    let (p, _, err, _) = c.modify(p, v).await;
    assert!(err.is_some());
    assert_eq!(status_of(&p).unwrap().0, TARGET_VAC);
}

#[tokio::test]
async fn csi_resizer_modify_infeasible_is_slow_retried_then_cancel() {
    let (c, d, s) = ctrl(true, false);
    // `TestCancel`: spec VAC empty, InProgress, ModifyingVolume condition.
    let mut base = pvc("", TEST_VAC, TARGET_VAC);
    base.status
        .as_mut()
        .unwrap()
        .modify_volume_status
        .as_mut()
        .unwrap()
        .status = MODIFY_IN_PROGRESS.into();
    base.status.as_mut().unwrap().conditions = Some(vec![serde_json::from_value(
        json!({"type":"ModifyingVolume","status":"True"}),
    )
    .unwrap()]);
    *d.error.lock().unwrap() = Some(tonic::Code::InvalidArgument);
    // InProgress, so still tried; InvalidArgument makes it Infeasible.
    let (p, v, err, _) = c.modify(base, pv()).await;
    assert!(matches!(err, Some(ModifyError::Driver(_))));
    assert_eq!(status_of(&p).unwrap().1, MODIFY_INFEASIBLE);
    assert!(c.slow_set().contains("ns/pvc"));

    // Infeasible with an empty spec VAC: cancelled, the condition is cleared.
    let (p, _, err, _) = c.modify(p, v).await;
    assert!(err.is_none(), "{err:?}");
    let has = p
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|cs| cs.iter().any(|c| c.r#type == CONDITION_MODIFYING_VOLUME));
    assert!(!has, "{:?}", p.status.as_ref().unwrap().conditions);
    assert!(s
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.1 == EVENT_VOLUME_MODIFY_CANCELLED));
}

#[tokio::test]
async fn csi_resizer_modify_delays_recently_infeasible() {
    let (c, d, _) = ctrl(true, false);
    *d.error.lock().unwrap() = Some(tonic::Code::InvalidArgument);
    let (p, v, err, _) = c.modify(pvc(TARGET_VAC, TEST_VAC, TEST_VAC), pv()).await;
    assert!(err.is_some());
    assert_eq!(status_of(&p).unwrap().1, MODIFY_INFEASIBLE);
    // Same target again: delayed, the driver is not called.
    *d.params.lock().unwrap() = None;
    let (_, _, err, called) = c.modify(p, v).await;
    assert!(err.as_ref().unwrap().is_delay_retry());
    assert!(!called);
    assert!(d.params.lock().unwrap().is_none());
}

#[test]
fn csi_resizer_modify_secret_ref_precedence() {
    let mut v = pv();
    assert_eq!(modify_secret_ref(&v), None);
    v.spec.csi.as_mut().unwrap().controller_expand_secret_ref =
        serde_json::from_value(json!({"name":"exp","namespace":"kube"})).unwrap();
    assert_eq!(modify_secret_ref(&v), Some(("kube".into(), "exp".into())));
    v.metadata.annotations = Some(HashMap::from([
        (MODIFY_SECRET_NAME_ANN.to_string(), "mod".to_string()),
        (MODIFY_SECRET_NAMESPACE_ANN.to_string(), "ns2".to_string()),
    ]));
    assert_eq!(modify_secret_ref(&v), Some(("ns2".into(), "mod".into())));
}

#[test]
fn csi_resizer_modify_slow_set() {
    let s = SlowSet::new(Duration::from_millis(50));
    assert!(s.add("k"));
    assert!(!s.add("k"));
    assert!(s.contains("k"));
    assert!(s.time_remaining("k") > Duration::ZERO);
    std::thread::sleep(Duration::from_millis(60));
    assert!(!s.contains("k"));
    assert!(s.add("k"));
    s.remove("k");
    assert_eq!(s.time_remaining("k"), Duration::ZERO);
}
