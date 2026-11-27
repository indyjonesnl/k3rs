//! Snapshot controller driving a real CSI driver (csi-P1-03), against a fake
//! CSI Controller service on a unix socket.
//!
//! Upstream: kubernetes-csi/external-snapshotter
//! `pkg/sidecar-controller/snapshot_controller.go` (`syncContent`,
//! `createSnapshotWrapper`, `deleteCSISnapshotOperation`, `updateSnapshotContentStatus`),
//! `csi_handler.go` (`CreateSnapshot`, `DeleteSnapshot`, `makeSnapshotName`)
//! and `pkg/utils/util.go` (`RemovePrefixedParameters`); the cases follow
//! `TestCreateSnapshotSync` / `TestDeleteSync`.

use kubernetes_rs_common::resources::{VolumeSnapshot, VolumeSnapshotContent};
use kubernetes_rs_controller_manager::controllers::volume_snapshot::{
    make_snapshot_name, remove_prefixed_parameters, VolumeSnapshotController,
};
use kubernetes_rs_csi::controller_client::CsiControllerClient;
use kubernetes_rs_csi::proto::controller_server::{Controller, ControllerServer};
use kubernetes_rs_csi::proto::identity_server::{Identity, IdentityServer};
use kubernetes_rs_csi::proto::*;
use kubernetes_rs_storage::{build_key, memory::MemoryStorage, Storage};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

const DRIVER: &str = "test.csi.example.com";
const VS_UID: &str = "11111111-2222-3333-4444-555555555555";

#[derive(Default)]
struct Recorded {
    create: Vec<CreateSnapshotRequest>,
    delete: Vec<DeleteSnapshotRequest>,
}

#[derive(Clone, Default)]
struct Fake {
    rec: Arc<Mutex<Recorded>>,
    fail_create: bool,
    fail_delete: bool,
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
    async fn controller_get_capabilities(
        &self,
        _r: Request<ControllerGetCapabilitiesRequest>,
    ) -> Result<Response<ControllerGetCapabilitiesResponse>, Status> {
        use controller_service_capability::rpc::Type as T;
        Ok(Response::new(ControllerGetCapabilitiesResponse {
            capabilities: vec![ControllerServiceCapability {
                r#type: Some(controller_service_capability::Type::Rpc(
                    controller_service_capability::Rpc {
                        r#type: T::CreateDeleteSnapshot as i32,
                    },
                )),
            }],
        }))
    }
    async fn controller_publish_volume(
        &self,
        _r: Request<ControllerPublishVolumeRequest>,
    ) -> Result<Response<ControllerPublishVolumeResponse>, Status> {
        Err(Status::unimplemented("snapshot test"))
    }
    async fn controller_unpublish_volume(
        &self,
        _r: Request<ControllerUnpublishVolumeRequest>,
    ) -> Result<Response<ControllerUnpublishVolumeResponse>, Status> {
        Err(Status::unimplemented("snapshot test"))
    }
    async fn get_capacity(
        &self,
        _r: Request<GetCapacityRequest>,
    ) -> Result<Response<GetCapacityResponse>, Status> {
        Err(Status::unimplemented("snapshot test"))
    }
    async fn list_volumes(
        &self,
        _r: Request<ListVolumesRequest>,
    ) -> Result<Response<ListVolumesResponse>, Status> {
        Err(Status::unimplemented("snapshot test"))
    }
    async fn create_volume(
        &self,
        _r: Request<CreateVolumeRequest>,
    ) -> Result<Response<CreateVolumeResponse>, Status> {
        Err(Status::unimplemented("snapshot test"))
    }
    async fn delete_volume(
        &self,
        _r: Request<DeleteVolumeRequest>,
    ) -> Result<Response<DeleteVolumeResponse>, Status> {
        Err(Status::unimplemented("snapshot test"))
    }
    async fn create_snapshot(
        &self,
        r: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        let req = r.into_inner();
        self.rec.lock().unwrap().create.push(req.clone());
        if self.fail_create {
            return Err(Status::new(tonic::Code::Internal, "driver exploded"));
        }
        Ok(Response::new(CreateSnapshotResponse {
            snapshot: Some(Snapshot {
                snapshot_id: "drv-snap-1".into(),
                source_volume_id: req.source_volume_id,
                size_bytes: 1 << 30,
                ready_to_use: true,
                creation_time: Some(prost_types::Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 5,
                }),
                ..Default::default()
            }),
        }))
    }
    async fn delete_snapshot(
        &self,
        r: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        self.rec.lock().unwrap().delete.push(r.into_inner());
        if self.fail_delete {
            return Err(Status::new(tonic::Code::Internal, "delete failed"));
        }
        Ok(Response::new(DeleteSnapshotResponse {}))
    }
    async fn controller_expand_volume(
        &self,
        _r: Request<ControllerExpandVolumeRequest>,
    ) -> Result<Response<ControllerExpandVolumeResponse>, Status> {
        Err(Status::unimplemented("snapshot test"))
    }
    async fn controller_modify_volume(
        &self,
        _r: Request<ControllerModifyVolumeRequest>,
    ) -> Result<Response<ControllerModifyVolumeResponse>, Status> {
        Err(Status::unimplemented("not exercised"))
    }
}

struct Env {
    storage: Arc<MemoryStorage>,
    controller: VolumeSnapshotController<MemoryStorage>,
    rec: Arc<Mutex<Recorded>>,
    _dir: tempfile::TempDir,
}

async fn put(s: &MemoryStorage, res: &str, ns: Option<&str>, name: &str, v: serde_json::Value) {
    s.create(&build_key(res, ns, name), &v).await.unwrap();
}

async fn start(fake: Fake, policy: &str) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("csi.sock");
    let rec = fake.rec.clone();
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
    let storage = Arc::new(MemoryStorage::new());
    put(
        &storage,
        "volumesnapshotclasses",
        None,
        "cls",
        json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshotClass",
            "metadata":{"name":"cls"},"driver":DRIVER,"deletionPolicy":policy,
            "parameters":{"foo":"bar","csi.storage.k8s.io/snapshotter-secret-name":"s"}}),
    )
    .await;
    put(
        &storage,
        "persistentvolumes",
        None,
        "pv1",
        json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"pv1","uid":"pv-uid"},
            "spec":{"accessModes":["ReadWriteOnce"],
                "claimRef":{"name":"pvc1","namespace":"default","uid":"pvc-uid"},
                "csi":{"driver":DRIVER,"volumeHandle":"vol-1"}}}),
    )
    .await;
    put(
        &storage,
        "persistentvolumeclaims",
        Some("default"),
        "pvc1",
        json!({"apiVersion":"v1","kind":"PersistentVolumeClaim",
            "metadata":{"name":"pvc1","namespace":"default","uid":"pvc-uid"},
            "spec":{"volumeName":"pv1","accessModes":["ReadWriteOnce"],
                "resources":{"requests":{"storage":"5Gi"}}},
            "status":{"phase":"Bound"}}),
    )
    .await;
    put(
        &storage,
        "volumesnapshots",
        Some("default"),
        "snap",
        json!({"apiVersion":"snapshot.storage.k8s.io/v1","kind":"VolumeSnapshot",
            "metadata":{"name":"snap","namespace":"default","uid":VS_UID},
            "spec":{"source":{"persistentVolumeClaimName":"pvc1"},"volumeSnapshotClassName":"cls"}}),
    )
    .await;
    let controller = VolumeSnapshotController::new(storage.clone())
        .with_driver_client(DRIVER, CsiControllerClient::with_endpoint(sock));
    Env {
        storage,
        controller,
        rec,
        _dir: dir,
    }
}

const KEY: &str = "volumesnapshots/default/snap";

async fn content(env: &Env) -> VolumeSnapshotContent {
    env.storage
        .get(&build_key(
            "volumesnapshotcontents",
            None,
            "snapcontent-default-snap",
        ))
        .await
        .unwrap()
}

#[tokio::test]
async fn volume_snapshot_driver_create_records_driver_answer() {
    let env = start(Fake::default(), "Delete").await;
    env.controller.process_key(KEY).await.unwrap();

    let reqs = env.rec.lock().unwrap().create.clone();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].name, format!("snapshot-{VS_UID}"));
    assert_eq!(reqs[0].source_volume_id, "vol-1");
    let expect: HashMap<String, String> = [("foo".to_string(), "bar".to_string())].into();
    assert_eq!(reqs[0].parameters, expect);

    let c = content(&env).await;
    assert_eq!(c.spec.source.volume_handle.as_deref(), Some("vol-1"));
    let st = c.status.unwrap();
    assert_eq!(st.snapshot_handle.as_deref(), Some("drv-snap-1"));
    assert_eq!(st.ready_to_use, Some(true));
    assert_eq!(st.restore_size, Some(1 << 30));
    assert_eq!(st.creation_time, Some(1_700_000_000_000_000_005));

    let vs: VolumeSnapshot = env
        .storage
        .get(&build_key("volumesnapshots", Some("default"), "snap"))
        .await
        .unwrap();
    let vst = vs.status.unwrap();
    assert_eq!(
        vst.bound_volume_snapshot_content_name.as_deref(),
        Some("snapcontent-default-snap")
    );
    assert_eq!(vst.ready_to_use, Some(true));
    assert_eq!(vst.restore_size.as_deref(), Some("1073741824"));

    // A ready content is not sent to the driver again (`contentIsReady`).
    env.controller.process_key(KEY).await.unwrap();
    assert_eq!(env.rec.lock().unwrap().create.len(), 1);
}

#[tokio::test]
async fn volume_snapshot_driver_create_failure_sets_error_status() {
    let env = start(
        Fake {
            fail_create: true,
            ..Default::default()
        },
        "Delete",
    )
    .await;
    let err = env.controller.process_key(KEY).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("failed to take snapshot of the volume vol-1"),
        "{err}"
    );
    let st = content(&env).await.status.unwrap();
    assert!(st.snapshot_handle.is_none());
    let msg = st.error.unwrap().message.unwrap();
    assert!(msg.starts_with("Failed to create snapshot: "), "{msg}");
    let vs: VolumeSnapshot = env
        .storage
        .get(&build_key("volumesnapshots", Some("default"), "snap"))
        .await
        .unwrap();
    assert!(vs.status.is_none());
}

#[tokio::test]
async fn volume_snapshot_driver_delete_policy_calls_driver() {
    let env = start(Fake::default(), "Delete").await;
    env.controller.process_key(KEY).await.unwrap();
    env.storage
        .delete(&build_key("volumesnapshots", Some("default"), "snap"))
        .await
        .unwrap();
    env.controller.process_key(KEY).await.unwrap();
    let del = env.rec.lock().unwrap().delete.clone();
    assert_eq!(del.len(), 1);
    assert_eq!(del[0].snapshot_id, "drv-snap-1");
    assert!(env
        .storage
        .get::<VolumeSnapshotContent>(&build_key(
            "volumesnapshotcontents",
            None,
            "snapcontent-default-snap"
        ))
        .await
        .is_err());
}

#[tokio::test]
async fn volume_snapshot_driver_retain_policy_keeps_driver_snapshot() {
    let env = start(Fake::default(), "Retain").await;
    env.controller.process_key(KEY).await.unwrap();
    env.storage
        .delete(&build_key("volumesnapshots", Some("default"), "snap"))
        .await
        .unwrap();
    env.controller.process_key(KEY).await.unwrap();
    assert!(env.rec.lock().unwrap().delete.is_empty());
    assert!(content(&env)
        .await
        .status
        .unwrap()
        .snapshot_handle
        .is_some());
}

#[tokio::test]
async fn volume_snapshot_driver_delete_failure_keeps_content() {
    let env = start(
        Fake {
            fail_delete: true,
            ..Default::default()
        },
        "Delete",
    )
    .await;
    env.controller.process_key(KEY).await.unwrap();
    env.storage
        .delete(&build_key("volumesnapshots", Some("default"), "snap"))
        .await
        .unwrap();
    let err = env.controller.process_key(KEY).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("failed to delete snapshot content snapcontent-default-snap"),
        "{err}"
    );
    assert_eq!(
        content(&env).await.metadata.name,
        "snapcontent-default-snap"
    );
}

#[test]
fn volume_snapshot_driver_parameter_and_name_helpers() {
    let p: HashMap<String, String> = [
        ("a".to_string(), "1".to_string()),
        (
            "csi.storage.k8s.io/snapshotter-secret-name".to_string(),
            "s".to_string(),
        ),
        ("csiDeprecated".to_string(), "2".to_string()),
    ]
    .into();
    let out = remove_prefixed_parameters(&p).unwrap();
    assert_eq!(out.len(), 2);
    let bad: HashMap<String, String> =
        [("csi.storage.k8s.io/nope".to_string(), "x".to_string())].into();
    assert_eq!(
        remove_prefixed_parameters(&bad).unwrap_err().to_string(),
        "found unknown parameter key \"csi.storage.k8s.io/nope\" with reserved namespace csi.storage.k8s.io/"
    );
    assert_eq!(make_snapshot_name("abc").unwrap(), "snapshot-abc");
    assert_eq!(
        make_snapshot_name("").unwrap_err().to_string(),
        "Corrupted snapshot object, it is missing UID"
    );
}
