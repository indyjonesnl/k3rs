//! Which identity each controller talks to the api-server as, for
//! `--use-service-account-credentials` mode (k3s always sets it:
//! `pkg/daemons/control/server.go:124`).
//!
//! Upstream builds one client per controller with
//! `controllerContext.ClientBuilder.Client("<name>")` (or `NewClient(name)`),
//! and the `DynamicControllerClientBuilder` authenticates that client as the
//! ServiceAccount `kube-system/<name>`
//! (`staging/src/k8s.io/controller-manager/pkg/clientbuilder/client_builder_dynamic.go`,
//! `cmd/kube-controller-manager/app/controllermanager.go:758-773`). The seeded
//! `system:controller:<name>` ClusterRole is bound to exactly that
//! ServiceAccount (`plugin/pkg/auth/authorizer/rbac/bootstrappolicy/controller_policy.go:34-51`
//! `addControllerRole`; `crates/api-server/src/bootstrap_policy/controller-role-bindings.yaml`).
//!
//! The shared informers and the legacy tokens controller run under the root
//! client, i.e. the controller-manager's own identity
//! (`system:kube-controller-manager`; controllermanager.go:245, :471-472).
//!
//! k3rs-only controllers (no upstream kube-controller-manager equivalent) are
//! [`ControllerIdentity::Unmapped`]: they keep the controller-manager's own
//! identity, exactly as before per-controller identities existed, and get no
//! new grant. Each one says where upstream does that work instead.

/// The identity one controller (by its `storage_for` name in
/// [`crate::spawn_controllers`]) uses for its own API calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerIdentity {
    /// The ServiceAccount `kube-system/<name>` upstream's client builder
    /// uses for this controller; its role is `system:controller:<name>`.
    ServiceAccount(&'static str),
    /// The controller-manager's own identity, as upstream runs this
    /// controller under `rootClientBuilder`.
    ControllerManager,
    /// No upstream kube-controller-manager controller does this work; the
    /// `&str` says where upstream does it. Runs as the controller-manager's
    /// own identity (no grant beyond it).
    Unmapped(&'static str),
}

use ControllerIdentity::{ControllerManager, ServiceAccount, Unmapped};

/// The k3rs-only Events controller's ServiceAccount name (no upstream role;
/// see `CONTROLLER_IDENTITIES` "Events").
pub const EVENT_GC_SERVICE_ACCOUNT: &str = "event-gc-controller";

/// Every `storage_for` name [`crate::spawn_controllers`] can use, with its
/// identity. Client names cite `cmd/kube-controller-manager/app/*.go`.
pub const CONTROLLER_IDENTITIES: &[(&str, ControllerIdentity)] = &[
    (
        "LoadBalancer",
        Unmapped("k3s ServiceLB runs in the k3s cloud-controller-manager as User k3s-cloud-controller-manager (../k3s manifests/ccm.yaml)"),
    ),
    // apps.go:129
    ("Deployment", ServiceAccount("deployment-controller")),
    // core.go:537
    ("ReplicationController", ServiceAccount("replication-controller")),
    // apps.go:103
    ("ReplicaSet", ServiceAccount("replicaset-controller")),
    // apps.go:76
    ("StatefulSet", ServiceAccount("statefulset-controller")),
    // apps.go:44
    ("DaemonSet", ServiceAccount("daemon-set-controller")),
    // batch.go:40
    ("Job", ServiceAccount("job-controller")),
    // batch.go:69
    ("CronJob", ServiceAccount("cronjob-controller")),
    // core.go:327
    ("PVBinder", ServiceAccount("persistent-volume-binder")),
    // core.go:831
    ("PvcProtection", ServiceAccount("pvc-protection-controller")),
    // core.go:444
    ("EphemeralVolume", ServiceAccount("ephemeral-volume-controller")),
    // core.go:860
    ("PvProtection", ServiceAccount("pv-protection-controller")),
    // core.go:886
    (
        "VacProtection",
        ServiceAccount("volumeattributesclass-protection-controller"),
    ),
    // In-tree dynamic provisioning (the hostPath plugin) is part of the PV
    // controller upstream (pkg/controller/volume/persistentvolume/
    // pv_controller.go `provisionClaimOperation`), which uses the binder's
    // client (core.go:327).
    ("DynamicProvisioner", ServiceAccount("persistent-volume-binder")),
    (
        "CSIAttacher",
        Unmapped("the CSI external-attacher sidecar runs under the driver's own ServiceAccount (kubernetes-csi/external-attacher deploy/kubernetes/rbac.yaml)"),
    ),
    // core.go:369
    ("AttachDetach", ServiceAccount("attachdetach-controller")),
    // bootstrap.go:37 (namespaced Role in kube-public)
    ("BootstrapSigner", ServiceAccount("bootstrap-signer")),
    // bootstrap.go:65 (namespaced Role in kube-system)
    ("TokenCleaner", ServiceAccount("token-cleaner")),
    // core.go:1119 (`NewClient(controllerName)`)
    ("SELinuxWarning", ServiceAccount("selinux-warning-controller")),
    (
        "VolumeSnapshot",
        Unmapped("the external snapshot-controller runs under its own ServiceAccount (kubernetes-csi/external-snapshotter deploy/kubernetes/snapshot-controller/rbac-snapshot-controller.yaml)"),
    ),
    // core.go:415
    ("VolumeExpansion", ServiceAccount("expand-controller")),
    (
        "StorageClass",
        Unmapped("no kube-controller-manager equivalent: default-class handling is the DefaultStorageClass admission plugin in the api-server"),
    ),
    // core.go:510
    ("Endpoints", ServiceAccount("endpoint-controller")),
    // discovery.go:39
    ("EndpointSlice", ServiceAccount("endpointslice-controller")),
    // k3rs-only, NO upstream counterpart: upstream has no Events controller
    // (Events are written by the component that observes them and expire by
    // the api-server's etcd lease, `--event-ttl`). This janitor emits pod
    // lifecycle Events and deletes Events older than 1 h. It gets its own
    // ServiceAccount-style identity bound to the k3rs ClusterRole
    // `system:k3rs-event-gc` (crates/k3rs/src/bootstrap.rs `event_gc_rbac`,
    // Events only) instead of a grant on `system:kube-controller-manager`.
    ("Events", ServiceAccount(EVENT_GC_SERVICE_ACCOUNT)),
    // core.go:588-593
    ("ResourceQuota", ServiceAccount("resourcequota-controller")),
    // core.go:760-770
    ("GarbageCollector", ServiceAccount("generic-garbage-collector")),
    // autoscaling.go:44-49
    (
        "HorizontalPodAutoscaler",
        ServiceAccount("horizontal-pod-autoscaler"),
    ),
    (
        "VerticalPodAutoscaler",
        Unmapped("VPA is an addon (kubernetes/autoscaler vertical-pod-autoscaler deploy/vpa-rbac.yaml), not part of kube-controller-manager"),
    ),
    // core.go:916
    ("TTL", ServiceAccount("ttl-after-finished-controller")),
    // policy.go:39-44
    ("PodDisruptionBudget", ServiceAccount("disruption-controller")),
    // The stale-pod-disruption pass is part of the disruption controller
    // upstream (pkg/controller/disruption/disruption.go
    // `stalePodDisruptionQueue`), same client.
    ("StalePodDisruption", ServiceAccount("disruption-controller")),
    (
        "NetworkPolicy",
        Unmapped("NetworkPolicy is enforced by the CNI / k3s's embedded kube-router netpol controller on each agent, not by kube-controller-manager"),
    ),
    (
        "Ingress",
        Unmapped("Ingress is served by an addon (k3s ships traefik, ../k3s manifests/traefik.yaml), not by kube-controller-manager"),
    ),
    // certificates.go:65 (signing/approving)
    (
        "CertificateSigningRequest",
        ServiceAccount("certificate-controller"),
    ),
    // core.go:564
    ("PodGarbageCollector", ServiceAccount("pod-garbage-collector")),
    // core.go:264 (`NewClient(names.DeviceTaintEvictionController)`)
    (
        "DeviceTaintEviction",
        ServiceAccount("device-taint-eviction-controller"),
    ),
    // certificates.go:218
    (
        "CertificateSigningRequestCleaner",
        ServiceAccount("certificate-controller"),
    ),
    // certificates.go:320
    (
        "ClusterTrustBundlePublisher",
        ServiceAccount("kube-apiserver-serving-clustertrustbundle-publisher"),
    ),
    // certificates.go:244
    (
        "PodCertificateRequestCleaner",
        ServiceAccount("podcertificaterequestcleaner"),
    ),
    // validatingadmissionpolicystatus.go:55
    (
        "ValidatingAdmissionPolicyStatus",
        ServiceAccount("validatingadmissionpolicy-status-controller"),
    ),
    // core.go:641 (`ConfigOrDie("namespace-controller")`)
    (
        crate::NAMESPACE_CONTROLLER_CLIENT,
        ServiceAccount("namespace-controller"),
    ),
    // certificates.go:269
    ("RootCACertPublisher", ServiceAccount("root-ca-cert-publisher")),
    // core.go:231-232: "taint-manager uses existing cluster role from
    // node-controller".
    ("TaintEviction", ServiceAccount("node-controller")),
    // rbac.go:35
    (
        "ClusterRoleAggregation",
        ServiceAccount("clusterrole-aggregation-controller"),
    ),
    // k3rs's ServiceAccount controller is upstream's service-account-controller
    // AND the legacy tokens controller (it creates/updates/deletes the
    // token Secrets). Upstream runs the tokens controller under the root
    // client (controllermanager.go:245 `newServiceAccountTokenControllerDescriptor(
    // rootClientBuilder)`, service_accounts.go:65-72), whose role is a superset of
    // system:controller:service-account-controller (create serviceaccounts).
    ("ServiceAccount", ControllerManager),
    // core.go:940
    (
        "LegacyServiceAccountTokenCleaner",
        ServiceAccount("legacy-service-account-token-cleaner"),
    ),
    (
        "Service",
        Unmapped("ClusterIP/NodePort allocation and the default/kubernetes Service are the api-server's job upstream (pkg/registry/core/service, controlplane controller), done with its loopback identity"),
    ),
    // core.go:190 (node lifecycle)
    ("Node", ServiceAccount("node-controller")),
    // core.go:156 (node IPAM)
    ("NodeIPAM", ServiceAccount("node-controller")),
    (
        "PriorityClass",
        Unmapped("system PriorityClasses are created by an api-server post-start hook and pod priority is resolved by the Priority admission plugin, both in the api-server"),
    ),
    (
        "APIServiceAvailability",
        Unmapped("APIService availability is the kube-aggregator's AvailableConditionController inside the api-server"),
    ),
    // networking.go:42
    ("ServiceCIDR", ServiceAccount("service-cidrs-controller")),
    // core.go:1093
    (
        "StorageVersionGC",
        ServiceAccount("storage-version-garbage-collector"),
    ),
];

/// The identity of the controller `storage_for` names `name`, `None` for a
/// name missing from [`CONTROLLER_IDENTITIES`].
pub fn controller_identity(name: &str) -> Option<ControllerIdentity> {
    CONTROLLER_IDENTITIES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, id)| *id)
}

/// The distinct ServiceAccount names of [`CONTROLLER_IDENTITIES`], in table
/// order: one client credential is needed per entry.
pub fn controller_service_accounts() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for (_, id) in CONTROLLER_IDENTITIES {
        if let ServiceAccount(sa) = id {
            if !out.contains(sa) {
                out.push(sa);
            }
        }
    }
    out
}

/// The user name of ServiceAccount `kube-system/<sa>`:
/// `system:serviceaccount:kube-system:<sa>` (`serviceaccount.MakeUsername`,
/// staging/src/k8s.io/apiserver/pkg/authentication/serviceaccount/util.go:55).
pub fn service_account_username(sa: &str) -> String {
    format!("system:serviceaccount:kube-system:{sa}")
}

/// The groups of a `kube-system` ServiceAccount: `system:serviceaccounts`,
/// `system:serviceaccounts:kube-system` (`serviceaccount.MakeGroupNames`,
/// util.go:104). `system:authenticated` is added by the authenticator.
pub const SERVICE_ACCOUNT_GROUPS: &[&str] = &[
    "system:serviceaccounts",
    "system:serviceaccounts:kube-system",
];
