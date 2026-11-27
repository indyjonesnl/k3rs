//! The CSI external-resizer driver call, against a fake CSI Controller
//! service on a unix socket.
//!
//! Upstream: kubernetes-csi/external-resizer `pkg/resizer/csi_resizer_test.go`
//! (`TestResizeWithSecret`, `TestGetVolumeCapabilities`, `TestCanSupport`)
//! and `pkg/util/util_test.go` (`TestMergeResizeConditionOnPVC`,
//! `TestIsFinalError`, `TestIsInfeasibleError`).

use kubernetes_rs_common::quantity::{Format, Quantity};
use kubernetes_rs_common::resources::volume::*;
use kubernetes_rs_common::resources::PersistentVolume;
use kubernetes_rs_common::types::ObjectMeta;
use kubernetes_rs_controller_manager::controllers::csi_resizer::*;
use kubernetes_rs_csi::controller_client::{ControllerError, CsiControllerClient};
use kubernetes_rs_csi::proto::controller_server::{Controller, ControllerServer};
use kubernetes_rs_csi::proto::identity_server::{Identity, IdentityServer};
use kubernetes_rs_csi::proto::volume_capability::access_mode::Mode;
use kubernetes_rs_csi::proto::volume_capability::AccessType;
use kubernetes_rs_csi::proto::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

const DRIVER: &str = "csi.example.com";

#[derive(Clone, Default)]
struct Fake {
    expand: Arc<Mutex<Vec<ControllerExpandVolumeRequest>>>,
    node_expansion_required: bool,
    code: Option<tonic::Code>,
    expand_cap: bool,
    single_node_multi_writer: bool,
}

#[tonic::async_trait]
impl Identity for Fake {
    async fn get_plugin_capabilities(
        &self,
        _r: Request<GetPluginCapabilitiesRequest>,
    ) -> Result<Response<GetPluginCapabilitiesResponse>, Status> {
        Ok(Response::new(GetPluginCapabilitiesResponse {
            capabilities: vec![PluginCapability {
                r#type: Some(plugin_capability::Type::Service(
                    plugin_capability::Service {
                        r#type: plugin_capability::service::Type::ControllerService as i32,
                    },
                )),
            }],
        }))
    }
}

#[tonic::async_trait]
impl Controller for Fake {
    async fn create_volume(
        &self,
        _r: Request<CreateVolumeRequest>,
    ) -> Result<Response<CreateVolumeResponse>, Status> {
        Err(Status::unimplemented("not used by the resizer"))
    }
    async fn delete_volume(
        &self,
        _r: Request<DeleteVolumeRequest>,
    ) -> Result<Response<DeleteVolumeResponse>, Status> {
        Err(Status::unimplemented("not used by the resizer"))
    }
    async fn controller_publish_volume(
        &self,
        _r: Request<ControllerPublishVolumeRequest>,
    ) -> Result<Response<ControllerPublishVolumeResponse>, Status> {
        Err(Status::unimplemented("not used by the resizer"))
    }
    async fn controller_unpublish_volume(
        &self,
        _r: Request<ControllerUnpublishVolumeRequest>,
    ) -> Result<Response<ControllerUnpublishVolumeResponse>, Status> {
        Err(Status::unimplemented("not used by the resizer"))
    }
    async fn list_volumes(
        &self,
        _r: Request<ListVolumesRequest>,
    ) -> Result<Response<ListVolumesResponse>, Status> {
        Err(Status::unimplemented("not used by the resizer"))
    }
    async fn get_capacity(
        &self,
        _r: Request<GetCapacityRequest>,
    ) -> Result<Response<GetCapacityResponse>, Status> {
        Err(Status::unimplemented("not used by the resizer"))
    }
    async fn create_snapshot(
        &self,
        _r: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        Err(Status::unimplemented("not used by the resizer"))
    }
    async fn delete_snapshot(
        &self,
        _r: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        Err(Status::unimplemented("not used by the resizer"))
    }
    async fn controller_get_capabilities(
        &self,
        _r: Request<ControllerGetCapabilitiesRequest>,
    ) -> Result<Response<ControllerGetCapabilitiesResponse>, Status> {
        use controller_service_capability::rpc::Type as T;
        let mut types = vec![];
        if self.expand_cap {
            types.push(T::ExpandVolume);
        }
        if self.single_node_multi_writer {
            types.push(T::SingleNodeMultiWriter);
        }
        Ok(Response::new(ControllerGetCapabilitiesResponse {
            capabilities: types
                .into_iter()
                .map(|t| ControllerServiceCapability {
                    r#type: Some(controller_service_capability::Type::Rpc(
                        controller_service_capability::Rpc { r#type: t as i32 },
                    )),
                })
                .collect(),
        }))
    }
    async fn controller_expand_volume(
        &self,
        r: Request<ControllerExpandVolumeRequest>,
    ) -> Result<Response<ControllerExpandVolumeResponse>, Status> {
        let req = r.into_inner();
        self.expand.lock().unwrap().push(req.clone());
        if let Some(code) = self.code {
            return Err(Status::new(code, "boom"));
        }
        Ok(Response::new(ControllerExpandVolumeResponse {
            capacity_bytes: req.capacity_range.map_or(0, |c| c.required_bytes),
            node_expansion_required: self.node_expansion_required,
        }))
    }
}

fn start(
    fake: Fake,
) -> (
    tempfile::TempDir,
    CsiResizer,
    Arc<Mutex<Vec<ControllerExpandVolumeRequest>>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("csi.sock");
    let rec = fake.expand.clone();
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(IdentityServer::new(fake.clone()))
            .add_service(ControllerServer::new(fake))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    let client = Arc::new(CsiControllerClient::with_endpoint(sock));
    (dir, CsiResizer::new(DRIVER, client), rec)
}

fn pv(driver: &str, handle: &str) -> PersistentVolume {
    PersistentVolume {
        metadata: ObjectMeta {
            name: "pv-1".into(),
            ..Default::default()
        },
        type_meta: Default::default(),
        status: None,
        spec: PersistentVolumeSpec {
            access_modes: vec![PersistentVolumeAccessMode::ReadWriteOnce],
            csi: Some(CSIVolumeSource {
                driver: driver.into(),
                volume_handle: Some(handle.into()),
                fs_type: Some("ext4".into()),
                ..Default::default()
            }),
            mount_options: Some(vec!["noatime".into()]),
            ..Default::default()
        },
    }
}

fn gi(n: i64) -> Quantity {
    Quantity::from_value(n << 30, Format::BinarySI)
}

fn cond(t: &str, status: &str, reason: &str, probe: &str) -> PersistentVolumeClaimCondition {
    PersistentVolumeClaimCondition {
        r#type: t.into(),
        status: status.into(),
        reason: Some(reason.into()),
        last_probe_time: Some(probe.into()),
        last_transition_time: None,
        message: None,
    }
}

#[tokio::test]
async fn csi_resizer_can_support_matches_driver_name() {
    let (_d, r, _) = start(Fake::default());
    assert!(r.can_support(&pv(DRIVER, "vol")));
    assert!(!r.can_support(&pv("other.example.com", "vol")));
    let mut in_tree = pv(DRIVER, "vol");
    in_tree.spec.csi = None;
    assert!(!r.can_support(&in_tree));
}

#[tokio::test]
async fn csi_resizer_resize_sends_expand_request() {
    let (_d, r, rec) = start(Fake {
        expand_cap: true,
        node_expansion_required: true,
        ..Default::default()
    });
    let secrets = HashMap::from([("k".to_string(), "v".to_string())]);
    let out = r
        .resize(&pv(DRIVER, "vol-1"), &gi(2), secrets)
        .await
        .unwrap();
    assert_eq!(out.new_size, gi(2));
    assert!(out.node_resize_required);
    let req = rec.lock().unwrap()[0].clone();
    assert_eq!(req.volume_id, "vol-1");
    assert_eq!(req.capacity_range.unwrap().required_bytes, 2 << 30);
    assert_eq!(req.secrets["k"], "v");
    let cap = req.volume_capability.unwrap();
    assert_eq!(cap.access_mode.unwrap().mode, Mode::SingleNodeWriter as i32);
    match cap.access_type.unwrap() {
        AccessType::Mount(m) => {
            assert_eq!(m.fs_type, "ext4");
            assert_eq!(m.mount_flags, vec!["noatime".to_string()]);
        }
        AccessType::Block(_) => panic!("want mount"),
    }
}

#[tokio::test]
async fn csi_resizer_resize_empty_handle_and_non_csi() {
    let (_d, r, rec) = start(Fake {
        expand_cap: true,
        ..Default::default()
    });
    let e = r
        .resize(&pv(DRIVER, ""), &gi(2), HashMap::new())
        .await
        .unwrap_err();
    assert_eq!(e.to_string(), "empty volume handle");
    let mut p = pv(DRIVER, "vol");
    p.spec.csi = None;
    let e = r.resize(&p, &gi(2), HashMap::new()).await.unwrap_err();
    assert_eq!(e.to_string(), "volume pv-1 is not migrated to CSI");
    assert!(rec.lock().unwrap().is_empty());
}

#[tokio::test]
async fn csi_resizer_resize_without_expand_capability_is_not_final() {
    let (_d, r, rec) = start(Fake::default());
    let e = r
        .resize(&pv(DRIVER, "vol"), &gi(2), HashMap::new())
        .await
        .unwrap_err();
    assert!(!e.is_final());
    assert!(rec.lock().unwrap().is_empty());
}

#[tokio::test]
async fn csi_resizer_resize_classifies_driver_errors() {
    for (code, final_, infeasible) in [
        (tonic::Code::InvalidArgument, true, true),
        (tonic::Code::OutOfRange, true, true),
        (tonic::Code::NotFound, true, true),
        (tonic::Code::Internal, true, false),
        (tonic::Code::Unavailable, false, false),
        (tonic::Code::Aborted, false, false),
        (tonic::Code::DeadlineExceeded, false, false),
    ] {
        let (_d, r, _) = start(Fake {
            expand_cap: true,
            code: Some(code),
            ..Default::default()
        });
        let e = r
            .resize(&pv(DRIVER, "vol"), &gi(2), HashMap::new())
            .await
            .unwrap_err();
        assert_eq!(
            (e.is_final(), e.is_infeasible()),
            (final_, infeasible),
            "{code:?}"
        );
    }
}

#[test]
fn csi_resizer_non_grpc_errors_are_not_final() {
    let e = ControllerError::InvalidArgument("x".into());
    assert!(!is_final_error(&e));
    assert!(!is_infeasible_error(&e));
}

#[test]
fn csi_resizer_get_volume_capabilities() {
    let mut spec = pv(DRIVER, "v").spec;
    spec.volume_mode = Some(PersistentVolumeMode::Block);
    spec.access_modes = vec![PersistentVolumeAccessMode::ReadWriteOncePod];
    let c = get_volume_capabilities(&spec, true).unwrap();
    assert!(matches!(c.access_type, Some(AccessType::Block(_))));
    assert_eq!(
        c.access_mode.unwrap().mode,
        Mode::SingleNodeSingleWriter as i32
    );

    spec.access_modes = vec![PersistentVolumeAccessMode::ReadWriteMany];
    let c = get_volume_capabilities(&spec, false).unwrap();
    assert_eq!(
        c.access_mode.unwrap().mode,
        Mode::MultiNodeMultiWriter as i32
    );

    spec.csi = None;
    assert_eq!(
        get_volume_capabilities(&spec, false)
            .unwrap_err()
            .to_string(),
        "CSI volume source was nil"
    );
}

#[test]
fn csi_resizer_merge_resize_conditions_replaces_and_drops() {
    let old = vec![
        cond("Other", "True", "r", "t0"),
        cond(CONDITION_RESIZING, "True", "r", "t0"),
        cond(CONDITION_CONTROLLER_RESIZE_ERROR, "True", "r", "t0"),
    ];
    let new = vec![
        cond(CONDITION_FILE_SYSTEM_RESIZE_PENDING, "True", "n", "t1"),
        cond(CONDITION_RESIZING, "False", "n", "t1"),
    ];
    let m = merge_resize_conditions_of_pvc(&old, &new, false);
    let types: Vec<_> = m.iter().map(|c| c.r#type.as_str()).collect();
    assert_eq!(types, ["Other", "Resizing", "FileSystemResizePending"]);
    assert_eq!(m[1].status, "False");
    let kept = merge_resize_conditions_of_pvc(&old, &new, true);
    assert_eq!(kept.len(), 4);
}

#[test]
fn csi_resizer_merge_pvc_conditions_sets_transition_time() {
    let mut o = cond(CONDITION_RESIZING, "True", "a", "t0");
    o.last_transition_time = Some("t0".into());
    let same = merge_pvc_conditions(&[o.clone()], &[cond(CONDITION_RESIZING, "True", "a", "t1")]);
    assert_eq!(same[0].last_transition_time.as_deref(), Some("t0"));
    let changed = merge_pvc_conditions(&[o], &[cond(CONDITION_RESIZING, "True", "b", "t1")]);
    assert_eq!(changed[0].last_transition_time.as_deref(), Some("t1"));
    let added = merge_pvc_conditions(&[], &[cond(CONDITION_NODE_RESIZE_ERROR, "True", "b", "t2")]);
    assert_eq!(added[0].last_transition_time.as_deref(), Some("t2"));
}
