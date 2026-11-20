//! Unit tests moved from `src/lib.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use k3rs_client::http::ApiClient;
    pub use k3rs_controller_manager::controllers::*;
    pub use k3rs_controller_manager::controllers::{
        apiservice::APIServiceAvailabilityController,
        certificate_signing_request::CertificateSigningRequestController,
        clusterrole_aggregation::ClusterRoleAggregationController,
        cronjob::CronJobController,
        daemonset::DaemonSetController,
        deployment::DeploymentController,
        dynamic_provisioner::DynamicProvisionerController,
        endpoints::EndpointsController,
        endpointslice::EndpointSliceController,
        ephemeral_volume::EphemeralVolumeController,
        events::EventsController,
        garbage_collector::GarbageCollector,
        hpa::HorizontalPodAutoscalerController,
        hpa_metrics_client::HttpMetricsConfig,
        ingress::IngressController,
        job::JobController,
        loadbalancer::LoadBalancerController,
        namespace::NamespaceController,
        network_policy::NetworkPolicyController,
        node::NodeController,
        pod_disruption_budget::{PodDisruptionBudgetController, StalePodDisruptionController},
        priorityclass::PriorityClassController,
        pv_binder::PVBinderController,
        pv_protection::PvProtectionController,
        pvc_protection::PvcProtectionController,
        replicaset::ReplicaSetController,
        replicationcontroller::ReplicationControllerController,
        resource_quota::ResourceQuotaController,
        service::ServiceController,
        serviceaccount::ServiceAccountController,
        servicecidr::ServiceCIDRController,
        statefulset::StatefulSetController,
        storage_class::StorageClassController,
        storageversiongc::StorageVersionGCController,
        ttl_after_finished::TTLAfterFinishedController,
        volume_expansion::VolumeExpansionController,
        volume_snapshot::VolumeSnapshotController,
        vpa::VerticalPodAutoscalerController,
    };
    pub use k3rs_storage::api_storage::ApiStorage;
    pub use k3rs_storage::{Storage, StorageBackend};
    pub use std::sync::Arc;
    pub use tracing::{error, info};
}

mod supervisor_tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// #1775: a panicking controller must be restarted, not silently lost.
    ///
    /// The live failure was a `futures` Unfold panic inside the ResourceQuota
    /// controller; `tokio::spawn` swallowed it, the task vanished, and quota
    /// `status.used` was never published again until the process restarted.
    #[tokio::test]
    async fn a_panicking_controller_is_restarted() {
        let attempts = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&attempts);

        k3rs_controller_manager::supervise_controller(
            "test controller",
            Some(3),
            std::time::Duration::ZERO,
            move || {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    panic!("simulated controller crash");
                }
            },
        )
        .await;

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            3,
            "the supervisor must restart a panicking controller up to the attempt limit"
        );
    }

    /// A controller whose run() returns has given up — an infinite reconcile
    /// loop returning at all is a failure, so it is restarted too.
    #[tokio::test]
    async fn a_returning_controller_is_restarted() {
        let attempts = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&attempts);

        k3rs_controller_manager::supervise_controller(
            "test controller",
            Some(2),
            std::time::Duration::ZERO,
            move || {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
            },
        )
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    /// The panic payload must be recoverable for the log — a silent restart
    /// would hide the defect that caused it.
    #[test]
    fn the_panic_payload_is_recovered_for_logging() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(format!("boom {}", 1));
        let as_string = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned());
        assert_eq!(as_string.as_deref(), Some("boom 1"));
    }
}

mod per_controller_client_tests {
    use super::__parent::*;
    use k3rs_controller_manager::*;
    use k3rs_storage::MemoryStorage;
    use std::sync::Mutex;

    /// #1863: the number of controllers started equals the number of clients
    /// (hence limiters) built, one each, and no two share a bucket. Sharing one
    /// limiter across the 35 controllers is what #1856 did and #1862 reverted.
    #[tokio::test]
    async fn every_controller_gets_its_own_client_and_limiter() {
        let skeleton = ApiClient::new("http://127.0.0.1:1", true, None)
            .unwrap()
            .with_rate_limit(20.0, 30.0);
        let built: Mutex<Vec<(&'static str, Arc<ApiClient>)>> = Mutex::new(Vec::new());
        let storage = Arc::new(MemoryStorage::new());

        let handles = spawn_controllers(
            |name| {
                built
                    .lock()
                    .unwrap()
                    .push((name, controller_client(&skeleton, name)));
                storage.clone()
            },
            ControllerManagerConfig {
                sync_interval: 3600,
                pv_recycler: Default::default(),
                metrics_config: None,
                ca_cert_pem: None,
                node_ipam: None,
                legacy_sa_token_clean_up_period:
                    controllers::legacy_serviceaccount_token_cleaner::DEFAULT_CLEAN_UP_PERIOD,
                csi_attachers: Vec::new(),
                attach_detach_controller: false,
                bootstrap_signer_controller: false,
                selinux_warning_controller: false,
                terminated_pod_gc_threshold:
                    controllers::podgc::DEFAULT_TERMINATED_POD_GC_THRESHOLD,
                token_cleaner_controller: false,
                service_cluster_ip_range: String::new(),
            },
        );
        for h in &handles {
            h.abort();
        }

        let built = built.into_inner().unwrap();
        assert!(!handles.is_empty());
        assert_eq!(
            built.len(),
            handles.len(),
            "exactly one client per controller started"
        );

        let mut names: Vec<_> = built.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), built.len(), "controller names are distinct");

        for (i, (na, a)) in built.iter().enumerate() {
            assert!(
                !a.shares_limiter_with(&skeleton),
                "{na} must not share the skeleton's limiter"
            );
            for (nb, b) in &built[i + 1..] {
                assert!(
                    !a.shares_limiter_with(b),
                    "{na} and {nb} must not share a limiter"
                );
            }
        }
    }
}

mod csi_attach_wiring_tests {
    use super::__parent::*;
    use k3rs_controller_manager::*;
    use k3rs_storage::MemoryStorage;

    fn count(csi_attachers: Vec<(String, String)>, attach_detach_controller: bool) -> usize {
        let storage = Arc::new(MemoryStorage::new());
        let handles = spawn_controllers(
            |_| storage.clone(),
            ControllerManagerConfig {
                sync_interval: 3600,
                pv_recycler: Default::default(),
                metrics_config: None,
                ca_cert_pem: None,
                node_ipam: None,
                legacy_sa_token_clean_up_period:
                    controllers::legacy_serviceaccount_token_cleaner::DEFAULT_CLEAN_UP_PERIOD,
                csi_attachers,
                attach_detach_controller,
                bootstrap_signer_controller: false,
                selinux_warning_controller: false,
                terminated_pod_gc_threshold:
                    controllers::podgc::DEFAULT_TERMINATED_POD_GC_THRESHOLD,
                token_cleaner_controller: false,
                service_cluster_ip_range: String::new(),
            },
        );
        for h in &handles {
            h.abort();
        }
        handles.len()
    }

    /// #3128: the all-in-one / API-mode controller set starts the CSI
    /// external-attacher (one per driver) and the AttachDetachController only
    /// when asked, exactly like the standalone binary's `--csi-attacher` /
    /// `--attach-detach-controller` (both opt-in).
    #[tokio::test]
    async fn csi_attacher_and_attach_detach_are_opt_in() {
        let base = count(Vec::new(), false);
        assert_eq!(count(Vec::new(), true), base + 1);
        let one = vec![(
            "hostpath.csi.k8s.io".to_string(),
            "/tmp/csi.sock".to_string(),
        )];
        assert_eq!(count(one.clone(), false), base + 1);
        let two = vec![
            one[0].clone(),
            ("b.csi".to_string(), "/tmp/b.sock".to_string()),
        ];
        assert_eq!(count(two, true), base + 3);
    }
}

mod identity_table_tests {
    use super::__parent::*;
    use k3rs_controller_manager::identities::*;
    use k3rs_controller_manager::*;

    /// Every `storage_for("...")` name in `spawn_controllers` (gated and
    /// opt-in ones included, hence a source scan) has exactly one identity,
    /// and the table names no controller that is never spawned.
    #[test]
    fn identity_table_covers_every_spawned_controller() {
        let src = include_str!("../../../src/lib.rs");
        let body = &src[src.find("pub fn spawn_controllers").unwrap()..];
        let mut spawned: Vec<String> = Vec::new();
        for part in body.split("storage_for(").skip(1) {
            let arg = part.split(')').next().unwrap().trim();
            let name = if arg == "NAMESPACE_CONTROLLER_CLIENT" {
                NAMESPACE_CONTROLLER_CLIENT.to_string()
            } else {
                arg.trim_matches('"').to_string()
            };
            spawned.push(name);
        }
        spawned.sort();
        spawned.dedup();
        assert!(spawned.len() > 40, "scan found {spawned:?}");
        let mut table: Vec<String> = CONTROLLER_IDENTITIES
            .iter()
            .map(|(n, _)| n.to_string())
            .collect();
        table.sort();
        let before = table.len();
        table.dedup();
        assert_eq!(
            before,
            table.len(),
            "duplicate names in CONTROLLER_IDENTITIES"
        );
        assert_eq!(spawned, table);
    }

    #[test]
    fn service_account_identity_matches_upstream_user_info() {
        assert_eq!(
            service_account_username("replicaset-controller"),
            "system:serviceaccount:kube-system:replicaset-controller"
        );
        assert_eq!(
            SERVICE_ACCOUNT_GROUPS,
            [
                "system:serviceaccounts",
                "system:serviceaccounts:kube-system"
            ]
        );
        let sas = controller_service_accounts();
        assert!(sas.contains(&"node-controller"));
        let mut dedup = sas.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), sas.len());
    }

    /// Fail closed: a missing credential is an error, never a silent
    /// fallback to the controller-manager's own identity.
    #[test]
    fn identity_storage_for_requires_every_credential() {
        let root = Arc::new(ApiClient::new("http://127.0.0.1:1", true, None).unwrap());
        let all = || {
            let mut creds = ControllerCredentials::new();
            for sa in controller_service_accounts() {
                creds.insert(
                    sa,
                    ApiClient::new("http://127.0.0.1:1", true, None).unwrap(),
                );
            }
            creds
        };
        assert!(identity_storage_for(Arc::clone(&root), all()).is_ok());
        let mut creds = all();
        creds.remove("replicaset-controller");
        let err = identity_storage_for(root, creds).err().unwrap().to_string();
        assert!(err.contains("replicaset-controller"), "{err}");
    }
}
