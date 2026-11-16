//! Kubelet-side wiring of the pod certificate manager.
//!
//! Ports the parts of `pkg/kubelet/kubelet.go` that surround
//! `podcertificate.IssuingManager`:
//!
//! * construction (`kubelet.go:955-972`): an `IssuingManager` when the
//!   `PodCertificateRequest` gate is on, else a `NoOpManager`;
//! * the `HandlePodAdditions` / `HandlePodRemoves` hooks
//!   (`kubelet.go:2729`, `:2948`) that feed `TrackPod` / `ForgetPod`;
//! * the pod manager the issuing manager reads (`podManager`);
//! * the metrics collector (`metrics/collectors/podcertificate_metrics.go`).

use super::{IssuingManager, Manager, NoOpManager, PodManager, RealClock};
use k3rs_common::feature_gates::{self, Feature};
use k3rs_common::resources::Pod;
use k3rs_storage::{EventRecorder, Storage};
use prometheus::core::{Collector, Desc};
use prometheus::proto::{Gauge, LabelPair, Metric, MetricFamily, MetricType};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tracing::info;

/// `kubelet.podManager` (`pkg/kubelet/pod/pod_manager.go` `basicManager`): a
/// `podByUID` map of pod *pointers* (`Arc<Pod>` here), as far as the pod
/// certificate manager and the volume populator read it. k3rs has no
/// event-driven config source for the whole pod set, so the sync loop's list
/// ([`PodCache::reconcile`]) and the pod watch ([`PodCache::update_pod`]) turn
/// into the `HandlePodAdditions` / `HandlePodUpdates` / `HandlePodRemoves` calls
/// upstream receives as config-source updates.
#[derive(Default)]
pub struct PodCache {
    pods: RwLock<HashMap<String, Arc<Pod>>>,
}

impl PodCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// `basicManager.UpdatePod` (`pod_manager.go`): store the pod under its UID.
    /// Returns whether the UID was already known, and the pointer now held.
    ///
    /// An update carrying the resourceVersion already held is dropped: the
    /// stored pointer stays, so the unchanged pod is neither re-allocated nor
    /// re-cloned on every sync pass (upstream stores the pointer the config
    /// source delivered, and only receives one when the object changed).
    fn upsert(&self, pod: Pod) -> (bool, Arc<Pod>) {
        let mut pods = self.pods.write().unwrap();
        match pods.get(&pod.metadata.uid) {
            Some(held) if held_is_current(held, &pod) => (true, Arc::clone(held)),
            held => {
                let was_known = held.is_some();
                let new = Arc::new(pod);
                pods.insert(new.metadata.uid.clone(), Arc::clone(&new));
                (was_known, new)
            }
        }
    }

    /// The pod called `name` assigned to `node_name`, as the pod workers
    /// (keyed by pod name) look it up. A pointer scan; nothing is cloned.
    pub fn find_node_pod_by_name(&self, name: &str, node_name: &str) -> Option<Arc<Pod>> {
        self.pods
            .read()
            .unwrap()
            .values()
            .find(|p| {
                p.metadata.name == name
                    && p.spec.as_ref().and_then(|s| s.node_name.as_deref()) == Some(node_name)
            })
            .cloned()
    }

    /// `HandlePodAdditions` / `HandlePodUpdates` for one pod
    /// (`kubelet.go:2724-2729`): `UpdatePod`, then `TrackPod` when the pod is
    /// new to the manager -- tracking after the add is what lets
    /// `queueAllProjectionsForPod` find the pod by UID.
    pub fn handle_pod_update(&self, pod: Pod, manager: &dyn Manager) {
        if pod.metadata.uid.is_empty() {
            return;
        }
        let (was_known, held) = self.upsert(pod);
        if !was_known {
            manager.track_pod(&held);
        }
    }

    /// `HandlePodRemoves` for one pod (`kubelet.go:2948-2949`): `ForgetPod`
    /// then `podManager.RemovePod`.
    pub fn handle_pod_remove(&self, uid: &str, manager: &dyn Manager) {
        let held = self.pods.read().unwrap().get(uid).cloned();
        if let Some(pod) = held {
            manager.forget_pod(&pod);
            self.pods.write().unwrap().remove(uid);
        }
    }

    /// Diff `pods` against the cache.
    ///
    /// * Added: `podManager.AddPod(pod)` then `podCertificateManager.TrackPod`
    ///   (`HandlePodAdditions`, `kubelet.go:2724-2729`) -- tracking after the
    ///   add is what lets `queueAllProjectionsForPod` find the pod by UID.
    /// * Removed: `ForgetPod` then `podManager.RemovePod`
    ///   (`HandlePodRemoves`, `kubelet.go:2948-2949`).
    /// * Already present: the cached pod is refreshed (`UpdatePod`), without
    ///   a second `TrackPod`.
    pub fn reconcile(&self, pods: &[Pod], manager: &dyn Manager) {
        let current: HashSet<&str> = pods.iter().map(|p| p.metadata.uid.as_str()).collect();
        let removed: Vec<Arc<Pod>> = self
            .pods
            .read()
            .unwrap()
            .values()
            .filter(|p| !current.contains(p.metadata.uid.as_str()))
            .cloned()
            .collect();
        for pod in &removed {
            manager.forget_pod(pod);
            self.pods.write().unwrap().remove(&pod.metadata.uid);
        }
        for pod in pods {
            if pod.metadata.uid.is_empty() {
                continue;
            }
            // Fast path: an unchanged pod is not cloned at all.
            let unchanged = self
                .pods
                .read()
                .unwrap()
                .get(&pod.metadata.uid)
                .is_some_and(|held| held_is_current(held, pod));
            if unchanged {
                continue;
            }
            self.handle_pod_update(pod.clone(), manager);
        }
    }
}

/// `held` is the same version as `new`, or a newer one. The sync loop's list
/// and the pod watch both feed the cache, so a list taken just before a watch
/// event must not roll the pod back. resourceVersions are opaque, but the
/// storage backends here issue integers, which is all this orders.
fn held_is_current(held: &Pod, new: &Pod) -> bool {
    match (
        &held.metadata.resource_version,
        &new.metadata.resource_version,
    ) {
        (Some(h), Some(n)) => {
            h == n || matches!((h.parse::<u64>(), n.parse::<u64>()), (Ok(h), Ok(n)) if n < h)
        }
        _ => false,
    }
}

impl PodManager for PodCache {
    fn get_pod_by_uid(&self, uid: &str) -> Option<Arc<Pod>> {
        self.pods.read().unwrap().get(uid).cloned()
    }
    fn get_pods(&self) -> Vec<Arc<Pod>> {
        self.pods.read().unwrap().values().cloned().collect()
    }
}

const POD_CERTIFICATE_STATES: &str = "kubelet_podcertificate_states";
const POD_CERTIFICATE_STATES_HELP: &str = "Gauge vector reporting the number of pod certificate projected volume sources, faceted by signer_name and state.";

/// `podCertificateCollector` (`podcertificate_metrics.go:30-62`):
/// `kubelet_podcertificate_states{signer_name,state}`.
pub struct PodCertificateCollector {
    manager: Arc<dyn Manager>,
    desc: Desc,
}

impl PodCertificateCollector {
    /// `PodCertificateCollectorFor`.
    pub fn new(manager: Arc<dyn Manager>) -> Self {
        let desc = Desc::new(
            POD_CERTIFICATE_STATES.to_string(),
            POD_CERTIFICATE_STATES_HELP.to_string(),
            vec!["signer_name".to_string(), "state".to_string()],
            Default::default(),
        )
        .expect("static metric description is valid");
        Self { manager, desc }
    }
}

impl Collector for PodCertificateCollector {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    /// `CollectWithStability`: one gauge per (signer, state) in the report.
    fn collect(&self) -> Vec<MetricFamily> {
        let report = self.manager.metric_report();
        if report.pod_certificate_states.is_empty() {
            return Vec::new();
        }
        let mut family = MetricFamily::default();
        family.set_name(POD_CERTIFICATE_STATES.to_string());
        family.set_help(POD_CERTIFICATE_STATES_HELP.to_string());
        family.set_field_type(MetricType::GAUGE);
        let metrics = report
            .pod_certificate_states
            .iter()
            .map(|(k, count)| {
                let mut metric = Metric::default();
                metric.set_label(
                    [("signer_name", &k.signer_name), ("state", &k.state)]
                        .into_iter()
                        .map(|(n, v)| {
                            let mut lp = LabelPair::default();
                            lp.set_name(n.to_string());
                            lp.set_value(v.clone());
                            lp
                        })
                        .collect::<Vec<_>>(),
                );
                let mut gauge = Gauge::default();
                gauge.set_value(*count as f64);
                metric.set_gauge(gauge);
                metric
            })
            .collect();
        family.set_metric(metrics);
        vec![family]
    }
}

/// `kubelet.go:955-972`: an `IssuingManager` when a client exists and the
/// `PodCertificateRequest` gate is on (the caller then spawns `run`), else a
/// `NoOpManager`. k3rs' kubelet always has a storage client, so only
/// the gate decides.
#[allow(clippy::type_complexity)]
pub fn new_pod_certificate_manager<S: Storage + ?Sized + 'static>(
    storage: Arc<S>,
    pods: Arc<dyn PodManager>,
    node_name: &str,
) -> (Arc<dyn Manager>, Option<Arc<IssuingManager<S>>>) {
    if feature_gates::enabled(Feature::PodCertificateRequest) {
        let issuing = IssuingManager::new(
            storage.clone(),
            pods,
            Some(EventRecorder::new(storage)),
            node_name,
            Arc::new(RealClock),
        );
        (issuing.clone() as Arc<dyn Manager>, Some(issuing))
    } else {
        info!(
            "Not starting PodCertificateRequest manager because the PodCertificateRequest feature gate is disabled"
        );
        (Arc::new(NoOpManager), None)
    }
}
