use crate::controllers::csi_provisioner::resolve_template;
use crate::controllers::worker_pool::spawn_workers;
use anyhow::{Context, Result};
use kubernetes_rs_common::resources::service_account::ObjectReference;
use kubernetes_rs_common::resources::volume::PersistentVolumeClaimPhase;
use kubernetes_rs_common::resources::volume::VolumeSnapshotContentSource;
use kubernetes_rs_common::resources::volume::VolumeSnapshotError;
use kubernetes_rs_common::resources::{
    DeletionPolicy, EventSource, EventType, PersistentVolume, PersistentVolumeClaim, Secret,
    VolumeSnapshot, VolumeSnapshotClass, VolumeSnapshotContent, VolumeSnapshotContentSpec,
    VolumeSnapshotContentStatus, VolumeSnapshotStatus,
};
use kubernetes_rs_common::types::{ObjectMeta, TypeMeta};
use kubernetes_rs_common::validation::metav1::{is_dns1123_label, is_dns1123_subdomain};
use kubernetes_rs_csi::controller_client::{ControllerError, CsiControllerClient};
use kubernetes_rs_csi::proto::{CreateSnapshotRequest, DeleteSnapshotRequest};
use kubernetes_rs_storage::{
    build_key, build_prefix, extract_key, EventRecorder, Storage, WorkQueue,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tracing::{debug, error, info, warn};

/// `IsDefaultSnapshotClassAnnotation` (external-snapshotter
/// `pkg/utils/util.go:94`).
const IS_DEFAULT_SNAPSHOT_CLASS_ANNOTATION: &str =
    "snapshot.storage.kubernetes.io/is-default-class";

/// `threads = flag.Int("worker-threads", 10, "Number of worker threads.")`
/// (external-snapshotter `cmd/snapshot-controller/main.go:70`).
const WORKER_THREADS: usize = 10;

/// `csiParameterPrefix` (external-snapshotter `pkg/utils/util.go`): parameter
/// keys under this prefix are reserved for the controller, not the driver.
const CSI_PARAMETER_PREFIX: &str = "csi.storage.k8s.io/";

/// Well-known reserved keys `RemovePrefixedParameters` accepts and strips
/// (`util.go:553-577`).
const KNOWN_PREFIXED_PARAMETERS: &[&str] = &[
    "csi.storage.k8s.io/snapshotter-secret-name",
    "csi.storage.k8s.io/snapshotter-secret-namespace",
    "csi.storage.k8s.io/snapshotter-list-secret-name",
    "csi.storage.k8s.io/snapshotter-list-secret-namespace",
    "csi.storage.k8s.io/group-snapshotter-get-secret-name",
    "csi.storage.k8s.io/group-snapshotter-get-secret-namespace",
    "csi.storage.k8s.io/group-snapshotter-secret-name",
    "csi.storage.k8s.io/group-snapshotter-secret-namespace",
];

/// `--snapshot-name-prefix` default (`cmd/csi-snapshotter/main.go`).
const SNAPSHOT_NAME_PREFIX: &str = "snapshot";

/// `AnnDeletionSecretRefName` / `AnnDeletionSecretRefNamespace`
/// (external-snapshotter `pkg/utils/util.go:141-142`).
const ANN_DELETION_SECRET_NAME: &str = "snapshot.storage.kubernetes.io/deletion-secret-name";
const ANN_DELETION_SECRET_NAMESPACE: &str =
    "snapshot.storage.kubernetes.io/deletion-secret-namespace";
/// `AnnVolumeSnapshotBeingCreated` (`util.go:116`): set while a CreateSnapshot
/// RPC has not answered with success or a final error.
pub const ANN_VOLUME_SNAPSHOT_BEING_CREATED: &str =
    "snapshot.storage.kubernetes.io/volumesnapshot-being-created";

/// `GetSecretReference` with `SnapshotterSecretParams` (`util.go:307-409`): the
/// secret named by the class parameters `csi.storage.k8s.io/snapshotter-secret-
/// {name,namespace}`, templates resolved against the content and snapshot. No
/// lookup of the secret itself is performed.
///
/// Name tokens: `${volumesnapshotcontent.name}`, `${volumesnapshot.namespace}`,
/// `${volumesnapshot.name}`; namespace tokens: the first two.
pub fn get_snapshotter_secret_reference(
    class_params: &HashMap<String, String>,
    content_name: &str,
    snapshot: Option<&VolumeSnapshot>,
) -> std::result::Result<Option<(String, String)>, String> {
    // verifyAndGetSecretNameAndNamespaceTemplate (`util.go:307-337`).
    let name_t = class_params.get("csi.storage.k8s.io/snapshotter-secret-name");
    let ns_t = class_params.get("csi.storage.k8s.io/snapshotter-secret-namespace");
    let (name_t, ns_t) = match (name_t, ns_t) {
        (None, None) => return Ok(None),
        (Some(n), Some(ns)) => {
            if n.is_empty() || ns.is_empty() {
                return Err("failed to get name and namespace template from params: snapshotter secrets specified in parameters but value of either namespace or name is empty".to_string());
            }
            (n, ns)
        }
        _ => {
            return Err("failed to get name and namespace template from params: either name and namespace for snapshotter secrets specified, Both must be specified".to_string());
        }
    };

    let mut ns_params = HashMap::from([(
        "volumesnapshotcontent.name".to_string(),
        content_name.to_string(),
    )]);
    if let Some(vs) = snapshot {
        ns_params.insert(
            "volumesnapshot.namespace".to_string(),
            vs.metadata.namespace.clone().unwrap_or_default(),
        );
    }
    let namespace = resolve_template(ns_t, &ns_params)
        .map_err(|e| format!("error resolving value {ns_t:?}: {e}"))?;
    if !is_dns1123_label(&namespace).is_empty() {
        return Err(if *ns_t != namespace {
            format!("{ns_t:?} resolved to {namespace:?} which is not a valid namespace name")
        } else {
            format!("{ns_t:?} is not a valid namespace name")
        });
    }

    let mut name_params = ns_params;
    if let Some(vs) = snapshot {
        name_params.insert("volumesnapshot.name".to_string(), vs.metadata.name.clone());
    }
    let name = resolve_template(name_t, &name_params)
        .map_err(|e| format!("error resolving value {name_t:?}: {e}"))?;
    if !is_dns1123_subdomain(&name).is_empty() {
        return Err(if *name_t != name {
            format!("{name_t:?} resolved to {name:?} which is not a valid secret name")
        } else {
            format!("{name_t:?} is not a valid secret name")
        });
    }
    Ok(Some((namespace, name)))
}

/// `isCSIFinalError` (`snapshot_controller.go:889-911`): is the answer proof
/// that no CreateSnapshot is still in progress. Only a gRPC status can say so;
/// anything else is "be on the safe side".
pub fn is_csi_final_error(err: &ControllerError) -> bool {
    use tonic::Code;
    match err.status() {
        None => false,
        Some(st) => !matches!(
            st.code(),
            Code::Cancelled
                | Code::DeadlineExceeded
                | Code::Unavailable
                | Code::ResourceExhausted
                | Code::Aborted
        ),
    }
}

/// `RemovePrefixedParameters` (`pkg/utils/util.go:553`): drop the controller's
/// own well-known `csi.storage.k8s.io/` keys, reject unknown reserved keys, and
/// pass everything else to the driver untouched.
pub fn remove_prefixed_parameters(
    params: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for (k, v) in params {
        if k.starts_with(CSI_PARAMETER_PREFIX) {
            if !KNOWN_PREFIXED_PARAMETERS.contains(&k.as_str()) {
                anyhow::bail!(
                    "found unknown parameter key \"{k}\" with reserved namespace {CSI_PARAMETER_PREFIX}"
                );
            }
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    Ok(out)
}

/// `makeSnapshotName` (`pkg/sidecar-controller/csi_handler.go:138`) with the
/// default `--snapshot-name-uuid-length=-1`: `<prefix>-<snapshot UID>`.
pub fn make_snapshot_name(snapshot_uid: &str) -> Result<String> {
    if snapshot_uid.is_empty() {
        anyhow::bail!("Corrupted snapshot object, it is missing UID");
    }
    Ok(format!("{SNAPSHOT_NAME_PREFIX}-{snapshot_uid}"))
}

pub struct VolumeSnapshotController<S: Storage> {
    storage: Arc<S>,
    recorder: EventRecorder<S>,
    /// CSI driver name -> controller-service client: the external-snapshotter
    /// sidecar's `snapshotter.NewSnapshotter(csiConn)`. A class whose driver
    /// has a client here is driven through CreateSnapshot/DeleteSnapshot; any
    /// other driver keeps the built-in hostpath behaviour.
    driver_clients: HashMap<String, Arc<CsiControllerClient>>,
}

impl<S: Storage + 'static> VolumeSnapshotController<S> {
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            recorder: EventRecorder::new(Arc::clone(&storage)),
            storage,
            driver_clients: HashMap::new(),
        }
    }

    /// Register the CSI controller client for `driver`.
    pub fn with_driver_client(
        mut self,
        driver: impl Into<String>,
        client: CsiControllerClient,
    ) -> Self {
        self.driver_clients.insert(driver.into(), Arc::new(client));
        self
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        use futures::StreamExt;

        info!("Starting Volume Snapshot Controller");

        let queue = WorkQueue::new();

        // N workers drain ONE shared queue; a key in flight is never handed to
        // a second worker (`for i := 0; i < workers; i++ { go wait.Until(ctrl.snapshotWorker, 0, stopCh) }`,
        // `snapshot_controller_base.go:283-285`).
        spawn_workers(WORKER_THREADS, &queue, |worker_queue| {
            let worker_self = Arc::clone(&self);
            async move {
                worker_self.worker(worker_queue).await;
            }
        });

        loop {
            self.enqueue_all(&queue).await;

            let prefix = kubernetes_rs_storage::build_prefix("volumesnapshots", None);
            let watch_result = self.storage.watch(&prefix).await;
            let mut watch = match watch_result {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to establish watch: {}, retrying", e);
                    time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut resync = tokio::time::interval(std::time::Duration::from_secs(30));
            resync.tick().await;

            let mut watch_broken = false;
            while !watch_broken {
                tokio::select! {
                    event = watch.next() => {
                        match event {
                            Some(Ok(ev)) => {
                                let key = extract_key(&ev);
                                queue.add(key).await;
                            }
                            Some(Err(e)) => {
                                warn!("Watch error: {}, reconnecting", e);
                                watch_broken = true;
                            }
                            None => {
                                warn!("Watch stream ended, reconnecting");
                                watch_broken = true;
                            }
                        }
                    }
                    _ = resync.tick() => {
                        self.enqueue_all(&queue).await;
                    }
                }
            }
        }
    }
    async fn worker(&self, queue: WorkQueue) {
        while let Some(key) = queue.get().await {
            match self.process_key(&key).await {
                Ok(()) => queue.forget(&key).await,
                Err(e) => {
                    error!("Failed to sync VolumeSnapshot {}: {}", key, e);
                    queue.requeue_rate_limited(key.clone()).await;
                }
            }
            queue.done(&key).await;
        }
    }

    /// `syncSnapshotByKey` (external-snapshotter
    /// `pkg/common-controller/snapshot_controller_base.go:377`): a key whose
    /// snapshot is gone is the `deleteSnapshot` path (`:585`), scoped to THAT
    /// snapshot's content only, not a sweep of every content.
    pub async fn process_key(&self, key: &str) -> Result<()> {
        let parts: Vec<&str> = key.splitn(3, '/').collect();
        let (ns, name) = match parts.len() {
            3 => (parts[1], parts[2]),
            _ => return Ok(()),
        };
        let storage_key = build_key("volumesnapshots", Some(ns), name);
        match self.storage.get::<VolumeSnapshot>(&storage_key).await {
            Ok(snapshot) => {
                // Only process snapshots that don't have a bound content yet
                if snapshot
                    .status
                    .as_ref()
                    .and_then(|s| s.bound_volume_snapshot_content_name.as_ref())
                    .is_none()
                {
                    self.create_snapshot(&snapshot).await?;
                }
                Ok(())
            }
            Err(_) => self.delete_snapshot(ns, name).await,
        }
    }

    async fn enqueue_all(&self, queue: &WorkQueue) {
        match self
            .storage
            .list::<VolumeSnapshot>("/registry/volumesnapshots/")
            .await
        {
            Ok(items) => {
                for item in &items {
                    let ns = item.metadata.namespace.as_deref().unwrap_or("");
                    let key = format!("volumesnapshots/{}/{}", ns, item.metadata.name);
                    queue.add(key).await;
                }
            }
            Err(e) => {
                error!("Failed to list volumesnapshots for enqueue: {}", e);
            }
        }
        // Resync also covers snapshots deleted while no event was seen (the
        // informer resync in upstream re-lists contents, `syncContentByKey`):
        // enqueue each content's referenced snapshot so a vanished one gets
        // its per-key deletion pass.
        if let Ok(contents) = self
            .storage
            .list::<VolumeSnapshotContent>("/registry/volumesnapshotcontents/")
            .await
        {
            for c in &contents {
                let r = &c.spec.volume_snapshot_ref;
                if let (Some(ns), Some(name)) = (&r.namespace, &r.name) {
                    queue.add(format!("volumesnapshots/{ns}/{name}")).await;
                }
            }
        }
    }

    pub async fn reconcile_all(&self) -> Result<()> {
        // Get all VolumeSnapshots
        let snapshots: Vec<VolumeSnapshot> =
            self.storage.list("/registry/volumesnapshots/").await?;

        for snapshot in snapshots {
            // Only process snapshots that don't have a bound content yet
            if snapshot
                .status
                .as_ref()
                .and_then(|s| s.bound_volume_snapshot_content_name.as_ref())
                .is_none()
            {
                if let Err(e) = self.create_snapshot(&snapshot).await {
                    error!(
                        "Failed to create snapshot for VolumeSnapshot {}/{}: {}",
                        snapshot.metadata.namespace.as_deref().unwrap_or("default"),
                        snapshot.metadata.name,
                        e
                    );
                }
            }
        }

        // Also reconcile snapshot deletions
        self.reconcile_deletions().await?;

        Ok(())
    }

    async fn create_snapshot(&self, vs: &VolumeSnapshot) -> Result<()> {
        let vs_name = &vs.metadata.name;
        let namespace = vs.metadata.namespace.as_deref().unwrap_or("default");

        debug!("Processing VolumeSnapshot {}/{}", namespace, vs_name);

        // Get the VolumeSnapshotClass. `volumeSnapshotClassName` is optional in
        // the external-snapshotter CRD: nil means "use the default
        // VolumeSnapshotClass for this driver", which `SetDefaultSnapshotClass`
        // resolves from the source PVC's PV
        // (`pkg/common-controller/snapshot_controller.go:1466-1526`).
        // `checkAndUpdateSnapshotClass`
        // (`pkg/common-controller/snapshot_controller_base.go:503-521`) is the
        // caller: it emits a `SetDefaultSnapshotClassFailed` warning and gives
        // up on this pass when the lookup fails (#2027).
        let vsc_name = match vs.spec.volume_snapshot_class_name.as_deref() {
            Some(name) => name.to_string(),
            None => match self.set_default_snapshot_class(vs).await {
                Ok(Some(name)) => name,
                // Pre-provisioned: the content names its own driver, so there
                // is no class to find and nothing for this path to do.
                Ok(None) => return Ok(()),
                Err(e) => {
                    let message = format!("Failed to set default snapshot class with error {e}");
                    warn!("VolumeSnapshot {}/{}: {}", namespace, vs_name, message);
                    self.emit(vs, "SetDefaultSnapshotClassFailed", &message)
                        .await;
                    return Err(e);
                }
            },
        };
        let vsc_name = vsc_name.as_str();
        let vsc_key = build_key("volumesnapshotclasses", None, vsc_name);
        let vsc: VolumeSnapshotClass = self
            .storage
            .get(&vsc_key)
            .await
            .with_context(|| format!("VolumeSnapshotClass {} not found", vsc_name))?;

        debug!(
            "Found VolumeSnapshotClass {} with driver {}",
            vsc_name, vsc.driver
        );

        // Check if driver is supported
        let driver_client = self.driver_clients.get(&vsc.driver).cloned();
        if driver_client.is_none() && !self.is_driver_supported(&vsc.driver) {
            warn!(
                "Driver {} is not supported. Skipping VolumeSnapshot {}/{}",
                vsc.driver, namespace, vs_name
            );
            return Ok(());
        }

        // Get the source PVC
        let pvc_name = vs
            .spec
            .source
            .persistent_volume_claim_name
            .as_ref()
            .context("VolumeSnapshot source must specify persistentVolumeClaimName")?;

        let pvc_key = build_key("persistentvolumeclaims", Some(namespace), pvc_name);
        let pvc: PersistentVolumeClaim = self
            .storage
            .get(&pvc_key)
            .await
            .with_context(|| format!("PVC {}/{} not found", namespace, pvc_name))?;

        // Ensure PVC is bound
        let pv_name = pvc
            .spec
            .volume_name
            .as_ref()
            .context("PVC must be bound to a PV before taking a snapshot")?;

        info!(
            "Creating snapshot of PVC {}/{} (bound to PV {})",
            namespace, pvc_name, pv_name
        );

        // Create VolumeSnapshotContent name
        let content_name = format!("snapcontent-{}-{}", namespace, vs_name);

        if let Some(client) = driver_client {
            return self
                .create_snapshot_via_driver(&client, vs, &vsc, &content_name)
                .await;
        }

        // Check if content already exists
        let content_key = build_key("volumesnapshotcontents", None, &content_name);
        if let Ok(_existing_content) = self
            .storage
            .get::<VolumeSnapshotContent>(&content_key)
            .await
        {
            debug!("VolumeSnapshotContent {} already exists", content_name);
            // Update VolumeSnapshot status if needed
            self.update_snapshot_status(vs, &content_name, true).await?;
            return Ok(());
        }

        // Create the snapshot content
        let content = self.create_snapshot_content(&vsc, vs, &content_name, pv_name)?;

        // Store the content
        self.storage
            .create(&content_key, &content)
            .await
            .with_context(|| format!("Failed to create VolumeSnapshotContent {}", content_name))?;

        info!(
            "Successfully created VolumeSnapshotContent {} for VolumeSnapshot {}/{}",
            content_name, namespace, vs_name
        );

        // Update VolumeSnapshot status
        self.update_snapshot_status(vs, &content_name, true).await?;

        Ok(())
    }

    /// `SetDefaultSnapshotClass` (external-snapshotter
    /// `pkg/common-controller/snapshot_controller.go:1466-1526`).
    ///
    /// ```go
    /// for _, class := range list {
    ///     if utils.IsVolumeSnapshotClassDefaultAnnotation(class.ObjectMeta) && pvDriver == class.Driver {
    ///         defaultClasses = append(defaultClasses, class)
    ///     }
    /// }
    /// if len(defaultClasses) == 0 {
    ///     return nil, snapshot, fmt.Errorf("cannot find default snapshot class")
    /// }
    /// if len(defaultClasses) > 1 {
    ///     return nil, snapshot, fmt.Errorf("%d default snapshot classes were found", len(defaultClasses))
    /// }
    /// ```
    ///
    /// "Default" is per **CSI driver**, not per cluster, which is why the
    /// driver has to be resolved from the source PVC's PV first: a cluster may
    /// carry one default class per driver and they do not conflict.
    ///
    /// Upstream then patches `/spec/volumeSnapshotClassName` onto the snapshot,
    /// so the choice is recorded on the object rather than recomputed every
    /// pass; this does the same. `Ok(None)` is upstream's pre-provisioned
    /// no-op.
    ///
    /// Not ported: the `IsVolumeGroupSnapshotMember` short-circuit (`:1475`) —
    /// kubernetes-rs has no VolumeGroupSnapshot.
    async fn set_default_snapshot_class(&self, vs: &VolumeSnapshot) -> Result<Option<String>> {
        if vs.spec.source.volume_snapshot_content_name.is_some() {
            return Ok(None);
        }

        let pv_driver = self.pv_driver_from_snapshot(vs).await?;

        let classes: Vec<VolumeSnapshotClass> = self
            .storage
            .list(&build_prefix("volumesnapshotclasses", None))
            .await
            .context("failed to list VolumeSnapshotClasses")?;

        let defaults: Vec<&VolumeSnapshotClass> = classes
            .iter()
            .filter(|class| {
                class
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get(IS_DEFAULT_SNAPSHOT_CLASS_ANNOTATION))
                    .map(String::as_str)
                    == Some("true")
                    && class.driver == pv_driver
            })
            .collect();

        match defaults.len() {
            0 => anyhow::bail!("cannot find default snapshot class"),
            1 => {}
            n => anyhow::bail!("{n} default snapshot classes were found"),
        }
        let chosen = defaults[0].metadata.name.clone();

        // Upstream's `PatchVolumeSnapshot` with a single `replace` op on
        // `/spec/volumeSnapshotClassName` (`:1517-1524`).
        let namespace = vs.metadata.namespace.as_deref().unwrap_or("default");
        let key = build_key("volumesnapshots", Some(namespace), &vs.metadata.name);
        let mut patched = vs.clone();
        patched.spec.volume_snapshot_class_name = Some(chosen.clone());
        self.storage
            .update(&key, &patched)
            .await
            .with_context(|| format!("failed to record default class on {key}"))?;

        info!(
            "VolumeSnapshot {}/{}: default VolumeSnapshotClass {} selected for driver {}",
            namespace, vs.metadata.name, chosen, pv_driver
        );
        Ok(Some(chosen))
    }

    /// `pvDriverFromSnapshot` (`snapshot_controller.go:1394-1408`) together with
    /// `getVolumeFromVolumeSnapshot` (`:1350-1376`) and
    /// `getClaimFromVolumeSnapshot` (`:1528-1545`), which it is only ever called
    /// through. Every error string is upstream's: they reach the user in the
    /// `SetDefaultSnapshotClassFailed` event.
    async fn pv_driver_from_snapshot(&self, vs: &VolumeSnapshot) -> Result<String> {
        let namespace = vs.metadata.namespace.as_deref().unwrap_or("default");
        let vs_name = &vs.metadata.name;

        let Some(pvc_name) = vs.spec.source.persistent_volume_claim_name.as_deref() else {
            anyhow::bail!("the snapshot source PVC name is not specified");
        };
        if pvc_name.is_empty() {
            anyhow::bail!("the PVC name is not specified in snapshot {namespace}/{vs_name}");
        }

        let pvc: PersistentVolumeClaim = self
            .storage
            .get(&build_key(
                "persistentvolumeclaims",
                Some(namespace),
                pvc_name,
            ))
            .await
            .with_context(|| format!("failed to retrieve PVC {namespace}/{pvc_name}"))?;

        // `getVolumeFromVolumeSnapshot`: the PVC must be Bound before its PV
        // can be read (`:1356-1358`).
        if pvc.status.as_ref().map(|s| s.phase.clone()) != Some(PersistentVolumeClaimPhase::Bound) {
            anyhow::bail!(
                "the PVC {pvc_name} is not yet bound to a PV, will not attempt to take a snapshot"
            );
        }
        let pv_name = pvc.spec.volume_name.as_deref().unwrap_or("");
        let pv: PersistentVolume = self
            .storage
            .get(&build_key("persistentvolumes", None, pv_name))
            .await
            .with_context(|| format!("failed to retrieve PV {pv_name} from the API server"))?;

        // `isVolumeBoundToClaim` (`:1381-1392`): the binding must hold in both
        // directions, or the snapshot would be taken of someone else's volume.
        let claim_ref = pv.spec.claim_ref.as_ref();
        let bound = claim_ref.is_some_and(|r| {
            r.name.as_deref() == Some(pvc.metadata.name.as_str())
                && r.namespace.as_deref() == Some(namespace)
                && r.uid
                    .as_deref()
                    .is_none_or(|uid| uid.is_empty() || uid == pvc.metadata.uid)
        });
        if !bound {
            warn!(
                "binding between PV {} and PVC {} is broken",
                pv_name, pvc.metadata.name
            );
            anyhow::bail!("claim in dataSource not bound or invalid");
        }

        // "supports ONLY CSI volumes" (`:1403-1406`).
        let Some(csi) = pv.spec.csi.as_ref() else {
            anyhow::bail!(
                "snapshotting non-CSI volumes is not supported, snapshot:{namespace}/{vs_name}"
            );
        };
        Ok(csi.driver.clone())
    }

    /// `updateSnapshotErrorStatusWithEvent`'s event half
    /// (`snapshot_controller_base.go:518`). A failure to record the event is
    /// logged and dropped: it must not mask the error it describes.
    async fn emit(&self, vs: &VolumeSnapshot, reason: &str, message: &str) {
        let involved = ObjectReference {
            kind: Some("VolumeSnapshot".to_string()),
            namespace: vs.metadata.namespace.clone(),
            name: Some(vs.metadata.name.clone()),
            uid: Some(vs.metadata.uid.clone()),
            api_version: Some("snapshot.storage.k8s.io/v1".to_string()),
            ..Default::default()
        };
        let source = EventSource {
            component: "snapshot-controller".to_string(),
            host: None,
        };
        if let Err(e) = self
            .recorder
            .event(&involved, &source, EventType::Warning, reason, message)
            .await
        {
            warn!("failed to record {reason} event: {e}");
        }
    }

    pub fn is_driver_supported(&self, driver: &str) -> bool {
        // For now, we only support our own hostpath snapshotter
        matches!(
            driver,
            "kubernetes-rs.io/hostpath-snapshotter" | "hostpath-snapshotter"
        )
    }

    pub fn create_snapshot_content(
        &self,
        vsc: &VolumeSnapshotClass,
        vs: &VolumeSnapshot,
        content_name: &str,
        volume_handle: &str,
    ) -> Result<VolumeSnapshotContent> {
        let namespace = vs.metadata.namespace.as_deref().unwrap_or("default");
        let snapshot_handle = format!(
            "snapshot-{}-{}-{}",
            namespace,
            vs.metadata.name,
            uuid::Uuid::new_v4()
        );

        let content = VolumeSnapshotContent {
            type_meta: TypeMeta {
                kind: "VolumeSnapshotContent".to_string(),
                api_version: "snapshot.storage.k8s.io/v1".to_string(),
            },
            metadata: {
                let mut meta = ObjectMeta::new(content_name);
                meta.uid = uuid::Uuid::new_v4().to_string();
                meta.resource_version = Some("1".to_string());
                meta
            },
            spec: VolumeSnapshotContentSpec {
                source: VolumeSnapshotContentSource {
                    volume_handle: Some(volume_handle.to_string()),
                    snapshot_handle: None, // Will be set by the actual snapshotter
                },
                volume_snapshot_ref: ObjectReference {
                    kind: Some("VolumeSnapshot".to_string()),
                    namespace: Some(namespace.to_string()),
                    name: Some(vs.metadata.name.clone()),
                    uid: Some(vs.metadata.uid.clone()),
                    api_version: Some("snapshot.storage.k8s.io/v1".to_string()),
                    resource_version: vs.metadata.resource_version.clone(),
                    field_path: None,
                },
                volume_snapshot_class_name: Some(vsc.metadata.name.clone()),
                deletion_policy: vsc.deletion_policy.clone(),
                driver: vsc.driver.clone(),
                source_volume_mode: None,
            },
            status: Some(VolumeSnapshotContentStatus {
                snapshot_handle: Some(snapshot_handle.clone()),
                creation_time: Some(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)),
                ready_to_use: Some(true), // Simplified - in real impl, this would be async
                restore_size: None,       // Would be populated by actual snapshotter
                error: None,
            }),
        };

        let mut content = content;
        // `getCreateSnapshotInput` (`:850`) resolves the snapshotter secret and
        // `createSnapshotContent` (`:781-788`) records it in the deletion-secret
        // annotations, which the sidecar reads back for every later RPC.
        let class_params = vsc.parameters.clone().unwrap_or_default();
        if let Some((ns, name)) =
            get_snapshotter_secret_reference(&class_params, content_name, Some(vs))
                .map_err(|e| anyhow::anyhow!(e))?
        {
            let ann = content
                .metadata
                .annotations
                .get_or_insert_with(HashMap::new);
            ann.insert(ANN_DELETION_SECRET_NAME.to_string(), name);
            ann.insert(ANN_DELETION_SECRET_NAMESPACE.to_string(), ns);
        }
        Ok(content)
    }

    /// `GetCredentialsFromAnnotation` (`snapshot_controller.go:728-758`).
    async fn credentials_from_annotation(
        &self,
        content: &VolumeSnapshotContent,
    ) -> Result<HashMap<String, String>> {
        let ann = content.metadata.annotations.as_ref();
        let (Some(name), Some(namespace)) = (
            ann.and_then(|a| a.get(ANN_DELETION_SECRET_NAME)),
            ann.and_then(|a| a.get(ANN_DELETION_SECRET_NAMESPACE)),
        ) else {
            return Ok(HashMap::new());
        };
        if name.is_empty() || namespace.is_empty() {
            anyhow::bail!(
                "cannot retrieve secrets for snapshot content {:?}, err: secret name or namespace not specified",
                content.metadata.name
            );
        }
        // `GetCredentials` (`util.go:483`).
        let secret: Secret = self
            .storage
            .get(&build_key("secrets", Some(namespace), name))
            .await
            .map_err(|e| {
                error!(
                    "Failed to get credentials for snapshot {}: error getting secret {name} in namespace {namespace}: {e}",
                    content.metadata.name
                );
                anyhow::anyhow!("cannot get credentials for snapshot content {:?}", content.metadata.name)
            })?;
        Ok(secret
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, String::from_utf8_lossy(&v).into_owned()))
            .collect())
    }

    /// `setAnnVolumeSnapshotBeingCreated` (`:820`).
    async fn set_being_created(
        &self,
        content: VolumeSnapshotContent,
    ) -> Result<VolumeSnapshotContent> {
        if content
            .metadata
            .annotations
            .as_ref()
            .is_some_and(|a| a.contains_key(ANN_VOLUME_SNAPSHOT_BEING_CREATED))
        {
            return Ok(content);
        }
        let mut updated = content.clone();
        updated
            .metadata
            .annotations
            .get_or_insert_with(HashMap::new)
            .insert(
                ANN_VOLUME_SNAPSHOT_BEING_CREATED.to_string(),
                "yes".to_string(),
            );
        let key = build_key("volumesnapshotcontents", None, &content.metadata.name);
        self.storage
            .update(&key, &updated)
            .await
            .map_err(|e| anyhow::anyhow!("failed to update content {}: {e}", content.metadata.name))
    }

    /// `removeAnnVolumeSnapshotBeingCreated` (`:861`).
    async fn remove_being_created(
        &self,
        content: VolumeSnapshotContent,
    ) -> Result<VolumeSnapshotContent> {
        if !content
            .metadata
            .annotations
            .as_ref()
            .is_some_and(|a| a.contains_key(ANN_VOLUME_SNAPSHOT_BEING_CREATED))
        {
            return Ok(content);
        }
        let mut updated = content.clone();
        if let Some(a) = updated.metadata.annotations.as_mut() {
            a.remove(ANN_VOLUME_SNAPSHOT_BEING_CREATED);
        }
        let key = build_key("volumesnapshotcontents", None, &content.metadata.name);
        self.storage
            .update(&key, &updated)
            .await
            .map_err(|e| anyhow::anyhow!("failed to update content {}: {e}", content.metadata.name))
    }

    /// The external-snapshotter flow for a driver-backed class: the common
    /// controller's dynamic content creation (`createSnapshotContent`,
    /// `snapshot_controller.go`) followed by the sidecar's `syncContent`
    /// (`pkg/sidecar-controller/snapshot_controller.go:61-112`).
    async fn create_snapshot_via_driver(
        &self,
        client: &CsiControllerClient,
        vs: &VolumeSnapshot,
        vsc: &VolumeSnapshotClass,
        content_name: &str,
    ) -> Result<()> {
        let namespace = vs.metadata.namespace.as_deref().unwrap_or("default");
        let pvc_name = vs
            .spec
            .source
            .persistent_volume_claim_name
            .as_deref()
            .context("VolumeSnapshot source must specify persistentVolumeClaimName")?;

        let content_key = build_key("volumesnapshotcontents", None, content_name);
        let mut content = match self
            .storage
            .get::<VolumeSnapshotContent>(&content_key)
            .await
        {
            Ok(c) => c,
            Err(_) => {
                // `spec.source.volumeHandle` is the PV's CSI volume handle
                // (`getVolumeFromVolumeSnapshot` -> `pv.Spec.CSI.VolumeHandle`).
                let pvc: PersistentVolumeClaim = self
                    .storage
                    .get(&build_key(
                        "persistentvolumeclaims",
                        Some(namespace),
                        pvc_name,
                    ))
                    .await
                    .with_context(|| format!("PVC {namespace}/{pvc_name} not found"))?;
                let pv_name = pvc.spec.volume_name.as_deref().unwrap_or("");
                let pv: PersistentVolume = self
                    .storage
                    .get(&build_key("persistentvolumes", None, pv_name))
                    .await
                    .with_context(|| format!("failed to retrieve PV {pv_name}"))?;
                let Some(csi) = pv.spec.csi.as_ref() else {
                    anyhow::bail!(
                        "snapshotting non-CSI volumes is not supported, snapshot:{namespace}/{}",
                        vs.metadata.name
                    );
                };
                let mut c = self.create_snapshot_content(
                    vsc,
                    vs,
                    content_name,
                    csi.volume_handle.as_deref().unwrap_or(""),
                )?;
                // The driver, not the controller, reports the handle.
                c.spec.source.snapshot_handle = None;
                c.status = None;
                // Keep the stored copy: it carries the resourceVersion the
                // annotation updates below are checked against.
                self.storage
                    .create(&content_key, &c)
                    .await
                    .with_context(|| {
                        format!("Failed to create VolumeSnapshotContent {content_name}")
                    })?
            }
        };

        // `contentIsReady`: skip the driver once it reported ready.
        let ready = content
            .status
            .as_ref()
            .and_then(|s| s.ready_to_use)
            .unwrap_or(false);
        if !ready {
            content = match self.create_snapshot_on_driver(client, vsc, &content).await {
                Ok(c) => c,
                Err(e) => {
                    // `updateContentErrorStatusWithEvent` (`:130`).
                    self.record_content_error(&content, &format!("Failed to create snapshot: {e}"))
                        .await;
                    return Err(e);
                }
            };
        }
        self.update_snapshot_status_from_content(vs, &content).await
    }

    /// `createSnapshotWrapper` (`pkg/sidecar-controller/snapshot_controller.go:341`)
    /// and `csiHandler.CreateSnapshot` (`csi_handler.go:75`): returns the
    /// content with the driver's answer recorded in `status`
    /// (`updateSnapshotContentStatus`, `:622`). Not ported: topology.
    async fn create_snapshot_on_driver(
        &self,
        client: &CsiControllerClient,
        vsc: &VolumeSnapshotClass,
        content: &VolumeSnapshotContent,
    ) -> Result<VolumeSnapshotContent> {
        let parameters = remove_prefixed_parameters(&vsc.parameters.clone().unwrap_or_default())
            .map_err(|e| {
                anyhow::anyhow!("failed to remove CSI Parameters of prefixed keys: {e}")
            })?;
        let r = &content.spec.volume_snapshot_ref;
        if r.uid.as_deref().unwrap_or("").is_empty() {
            anyhow::bail!(
                "cannot create snapshot. Snapshot content {} not bound to a snapshot",
                content.metadata.name
            );
        }
        let Some(volume_handle) = content.spec.source.volume_handle.as_deref() else {
            anyhow::bail!(
                "cannot create snapshot. Volume handle not found in snapshot content {}",
                content.metadata.name
            );
        };
        let name = make_snapshot_name(r.uid.as_deref().unwrap_or(""))?;
        // `getCSISnapshotInput` (`:229`): credentials from the annotation.
        let secrets = self
            .credentials_from_annotation(content)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to get input parameters to create snapshot for content {}: {e:?}",
                    content.metadata.name
                )
            })?;
        // Leak protection: the annotation stays on the content if the request
        // times out (`:351-359`).
        let content = &self.set_being_created(content.clone()).await.map_err(|e| {
            anyhow::anyhow!(
                "failed to add VolumeSnapshotBeingCreated annotation on the content {}: {e:?}",
                content.metadata.name
            )
        })?;
        let snap = match client
            .create_snapshot(CreateSnapshotRequest {
                source_volume_id: volume_handle.to_string(),
                name,
                parameters,
                secrets,
            })
            .await
        {
            Ok(s) => s,
            Err(e) => {
                // A final error proves no snapshot is in progress.
                if is_csi_final_error(&e) {
                    self.remove_being_created(content.clone()).await.map_err(|re| {
                        anyhow::anyhow!(
                            "failed to remove VolumeSnapshotBeingCreated annotation from the content {}: {re}",
                            content.metadata.name
                        )
                    })?;
                }
                return Err(anyhow::anyhow!(
                    "failed to take snapshot of the volume {volume_handle}: \"{e}\""
                ));
            }
        };

        // `if creationTime.IsZero() { creationTime = time.Now() }` (`:404`).
        let created_ns = snap
            .creation_time
            .as_ref()
            .filter(|t| t.seconds != 0 || t.nanos != 0)
            .map(|t| t.seconds.saturating_mul(1_000_000_000) + i64::from(t.nanos))
            .unwrap_or_else(|| chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));

        let mut updated = content.clone();
        updated.status = Some(VolumeSnapshotContentStatus {
            snapshot_handle: Some(snap.snapshot_id),
            creation_time: Some(created_ns),
            ready_to_use: Some(snap.ready_to_use),
            // `if size > 0 { newStatus.RestoreSize = &size }`.
            restore_size: (snap.size_bytes > 0).then_some(snap.size_bytes),
            error: None,
        });
        let key = build_key("volumesnapshotcontents", None, &content.metadata.name);
        let updated = self
            .storage
            .update_status(&key, &updated)
            .await
            .with_context(|| {
                format!(
                    "error updating status for volume snapshot content {}",
                    content.metadata.name
                )
            })?;
        // The storage system answered: the request is no longer in flight.
        self.remove_being_created(updated).await.map_err(|e| {
            anyhow::anyhow!(
                "failed to remove VolumeSnapshotBeingCreated annotation on the content {}: {e}",
                content.metadata.name
            )
        })
    }

    /// `updateContentErrorStatusWithEvent`: record the failure on
    /// `content.status.error` and emit a Warning event. Best effort.
    async fn record_content_error(&self, content: &VolumeSnapshotContent, message: &str) {
        let mut updated = content.clone();
        let mut status = updated
            .status
            .take()
            .unwrap_or(VolumeSnapshotContentStatus {
                snapshot_handle: None,
                creation_time: None,
                ready_to_use: None,
                restore_size: None,
                error: None,
            });
        status.error = Some(VolumeSnapshotError {
            time: Some(chrono::Utc::now().to_rfc3339()),
            message: Some(message.to_string()),
        });
        updated.status = Some(status);
        let key = build_key("volumesnapshotcontents", None, &content.metadata.name);
        if let Err(e) = self.storage.update_status(&key, &updated).await {
            warn!(
                "failed to record error on content {}: {e}",
                content.metadata.name
            );
        }
        let involved = ObjectReference {
            kind: Some("VolumeSnapshotContent".to_string()),
            name: Some(content.metadata.name.clone()),
            uid: Some(content.metadata.uid.clone()),
            api_version: Some("snapshot.storage.k8s.io/v1".to_string()),
            ..Default::default()
        };
        let source = EventSource {
            component: "csi-snapshotter".to_string(),
            host: None,
        };
        if let Err(e) = self
            .recorder
            .event(
                &involved,
                &source,
                EventType::Warning,
                "SnapshotCreationFailed",
                message,
            )
            .await
        {
            warn!("failed to record SnapshotCreationFailed event: {e}");
        }
    }

    /// Common controller's `updateSnapshotStatus` from a content's status
    /// (`snapshot_controller.go`): bound name, ready, creation time, size.
    async fn update_snapshot_status_from_content(
        &self,
        vs: &VolumeSnapshot,
        content: &VolumeSnapshotContent,
    ) -> Result<()> {
        let namespace = vs.metadata.namespace.as_deref().unwrap_or("default");
        let vs_key = build_key("volumesnapshots", Some(namespace), &vs.metadata.name);
        let cs = content.status.as_ref();
        let new_status = VolumeSnapshotStatus {
            bound_volume_snapshot_content_name: Some(content.metadata.name.clone()),
            creation_time: cs
                .and_then(|s| s.creation_time)
                .map(|ns| {
                    chrono::DateTime::<chrono::Utc>::from_timestamp(
                        ns.div_euclid(1_000_000_000),
                        ns.rem_euclid(1_000_000_000) as u32,
                    )
                    .unwrap_or_default()
                    .to_rfc3339()
                })
                .or_else(|| vs.status.as_ref().and_then(|s| s.creation_time.clone())),
            ready_to_use: Some(cs.and_then(|s| s.ready_to_use).unwrap_or(false)),
            restore_size: cs.and_then(|s| s.restore_size).map(|b| b.to_string()),
            error: None,
        };
        if serde_json::to_value(vs.status.as_ref()).ok()
            == serde_json::to_value(Some(&new_status)).ok()
        {
            return Ok(());
        }
        let mut updated = vs.clone();
        updated.status = Some(new_status);
        self.storage.update_status(&vs_key, &updated).await?;
        Ok(())
    }

    async fn update_snapshot_status(
        &self,
        vs: &VolumeSnapshot,
        content_name: &str,
        ready: bool,
    ) -> Result<()> {
        let namespace = vs.metadata.namespace.as_deref().unwrap_or("default");
        let vs_key = build_key("volumesnapshots", Some(namespace), &vs.metadata.name);

        // creation_time records when the snapshot was first taken and must
        // NEVER advance once set. Preserve the prior value on every reconcile;
        // otherwise we'd stamp Utc::now() at every interval and emit a
        // MODIFIED watch event per cycle — a controller hot-loop.
        let preserved_creation_time = vs
            .status
            .as_ref()
            .and_then(|s| s.creation_time.clone())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

        let new_status = VolumeSnapshotStatus {
            bound_volume_snapshot_content_name: Some(content_name.to_string()),
            creation_time: Some(preserved_creation_time),
            ready_to_use: Some(ready),
            restore_size: None,
            error: None,
        };

        // Skip the write when nothing actually changed. Compare via canonical
        // JSON since VolumeSnapshotStatus doesn't derive PartialEq.
        let old_v = serde_json::to_value(vs.status.as_ref()).ok();
        let new_v = serde_json::to_value(Some(&new_status)).ok();
        if old_v == new_v {
            return Ok(());
        }

        let mut updated_vs = vs.clone();
        updated_vs.status = Some(new_status);
        // Status subresource write: a full-object PUT strips `.status` (#1723).
        self.storage.update_status(&vs_key, &updated_vs).await?;

        info!(
            "Updated VolumeSnapshot {}/{} status (ready: {})",
            namespace, vs.metadata.name, ready
        );

        Ok(())
    }

    async fn reconcile_deletions(&self) -> Result<()> {
        self.release_contents(None).await
    }

    /// Release the contents bound to the one deleted snapshot `ns/name`.
    async fn delete_snapshot(&self, ns: &str, name: &str) -> Result<()> {
        self.release_contents(Some((ns, name))).await
    }

    /// Apply each content's deletion policy for a snapshot that no longer
    /// exists; `only` restricts the pass to contents referencing that one
    /// snapshot (`None` = full sweep, kept for `reconcile_all`).
    async fn release_contents(&self, only: Option<(&str, &str)>) -> Result<()> {
        // Get all VolumeSnapshotContents
        let contents: Vec<VolumeSnapshotContent> = self
            .storage
            .list("/registry/volumesnapshotcontents/")
            .await?;

        for content in contents {
            // Check if the referenced VolumeSnapshot still exists
            let vs_ref = &content.spec.volume_snapshot_ref;

            if let (Some(namespace), Some(name)) = (&vs_ref.namespace, &vs_ref.name) {
                if only.is_some_and(|(n, m)| n != namespace || m != name) {
                    continue;
                }
                let vs_key = build_key("volumesnapshots", Some(namespace), name);

                // If the VolumeSnapshot is deleted and deletion policy is Delete
                if self.storage.get::<VolumeSnapshot>(&vs_key).await.is_err() {
                    if content.spec.deletion_policy == DeletionPolicy::Delete {
                        // `syncContent` (`pkg/sidecar-controller/snapshot_controller.go:64-79`):
                        // with the Delete policy and a driver snapshot
                        // handle, issue DeleteSnapshot first and keep the
                        // content (retry) when it fails.
                        if let Some(client) = self.driver_clients.get(&content.spec.driver) {
                            if let Some(handle) = content
                                .status
                                .as_ref()
                                .and_then(|s| s.snapshot_handle.clone())
                            {
                                if let Err(e) = client
                                    .delete_snapshot(DeleteSnapshotRequest {
                                        snapshot_id: handle,
                                        ..Default::default()
                                    })
                                    .await
                                {
                                    let msg = format!(
                                        "failed to delete snapshot content {}: \"{e}\"",
                                        content.metadata.name
                                    );
                                    warn!("{msg}");
                                    return Err(anyhow::anyhow!(msg));
                                }
                            }
                        }
                        info!(
                            "VolumeSnapshot {}/{} was deleted. Deleting VolumeSnapshotContent {} (deletion policy: Delete)",
                            namespace, name, content.metadata.name
                        );

                        let content_key =
                            build_key("volumesnapshotcontents", None, &content.metadata.name);
                        self.storage.delete(&content_key).await?;

                        info!("Deleted VolumeSnapshotContent {}", content.metadata.name);
                    } else {
                        info!(
                            "VolumeSnapshot {}/{} was deleted, but VolumeSnapshotContent {} will be retained (deletion policy: Retain)",
                            namespace, name, content.metadata.name
                        );
                    }
                }
            }
        }

        Ok(())
    }
}
