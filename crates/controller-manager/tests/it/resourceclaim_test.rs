//! Ported from `pkg/controller/resourceclaim/controller_test.go` (release-1.35):
//! `TestSyncHandler`, `TestGetAdminAccessMetricLabel`, `TestEnqueuePodExtendedResourceClaims`
//! and the queue/metric parts of `TestResourceClaimEventHandler`, plus `uid_cache` and a
//! `run()` test that drives the real list+watch -> store -> queue -> sync path against
//! `MemoryStorage`.
//!
//! `TestSyncHandler` runs its cases sequentially in one test, as upstream does ("because of
//! global metrics"): `resourceclaim_controller_creates_total` is process-global.
use async_trait::async_trait;
use kubernetes_rs_client::reflector::StoreEvent;
use kubernetes_rs_common::resources::{Pod, ResourceClaim, ResourceClaimTemplate};
use kubernetes_rs_common::Error;
use kubernetes_rs_controller_manager::controllers::resourceclaim::*;
use kubernetes_rs_storage::memory::MemoryStorage;
use kubernetes_rs_storage::{build_key, build_prefix, Storage, WatchStream};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const NS: &str = "my-namespace";
const OTHER_NS: &str = "not-my-namespace";
const POD_NAME: &str = "test-pod";
const POD_UID: &str = "uidpod1";
const POD_CLAIM: &str = "acme-resource";
const TEMPLATE: &str = "my-template";
const NODE: &str = "worker";
const ADMIN_OFF: &str = "admin access is requested, but the feature is disabled";

// ---------------------------------------------------------------------------
// Fixtures (makePod, makeClaim, makeTemplatedClaim, ...)
// ---------------------------------------------------------------------------

fn pod_json(name: &str, uid: &str, with_resource: bool) -> Value {
    let mut spec = json!({});
    if with_resource {
        spec["resourceClaims"] =
            json!([{"name": POD_CLAIM, "resourceClaimTemplateName": TEMPLATE}]);
    }
    json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NS, "uid": uid},
        "spec": spec,
    })
}

fn test_pod() -> Pod {
    serde_json::from_value(pod_json(POD_NAME, POD_UID, false)).unwrap()
}
fn test_pod_with_resource() -> Pod {
    serde_json::from_value(pod_json(POD_NAME, POD_UID, true)).unwrap()
}
fn other_test_pod() -> Pod {
    serde_json::from_value(pod_json(&format!("{POD_NAME}-II"), "uidpod1-II", false)).unwrap()
}

fn claim_status(claim_name: &str) -> Value {
    json!([{"name": POD_CLAIM, "resourceClaimName": claim_name}])
}

fn templated_name() -> String {
    format!("{POD_NAME}-{POD_CLAIM}-")
}

fn owner(pod: &Pod, controller: bool) -> Value {
    json!({
        "apiVersion": "v1", "kind": "Pod", "name": pod.metadata.name,
        "uid": pod.metadata.uid, "controller": controller,
    })
}

fn make_claim(name: &str, ns: &str, owner: Option<Value>) -> ResourceClaim {
    let mut v = json!({
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceClaim",
        "metadata": {"name": name, "namespace": ns},
    });
    if let Some(o) = owner {
        v["metadata"]["ownerReferences"] = json!([o]);
    }
    serde_json::from_value(v).unwrap()
}

fn admin_spec(admin: bool) -> Value {
    json!({"devices": {"requests": [{"name": "req-0", "exactly": {"deviceClassName": "class", "adminAccess": admin}}]}})
}

/// `makeTemplatedClaim`.
fn make_templated_claim(owner: Option<Value>, admin: Option<bool>) -> ResourceClaim {
    let generate_name = templated_name();
    let mut v = json!({
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceClaim",
        "metadata": {
            "name": format!("{generate_name}1"), "generateName": generate_name,
            "namespace": NS,
            "annotations": {POD_RESOURCE_CLAIM_ANNOTATION: POD_CLAIM},
        },
    });
    if let Some(o) = owner {
        v["metadata"]["ownerReferences"] = json!([o]);
    }
    if let Some(a) = admin {
        v["spec"] = admin_spec(a);
    }
    serde_json::from_value(v).unwrap()
}

/// `makeExtendedResourceClaim`.
fn make_extended_claim(owner: Option<Value>) -> ResourceClaim {
    let generate_name = format!("{POD_NAME}-extended-resources-");
    let mut v = json!({
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceClaim",
        "metadata": {
            "name": format!("{generate_name}1"), "generateName": generate_name,
            "namespace": NS,
            "annotations": {EXTENDED_RESOURCE_CLAIM_ANNOTATION: "true"},
        },
    });
    if let Some(o) = owner {
        v["metadata"]["ownerReferences"] = json!([o]);
    }
    serde_json::from_value(v).unwrap()
}

fn allocate(mut c: ResourceClaim) -> ResourceClaim {
    c.status.get_or_insert_with(Default::default).allocation =
        Some(serde_json::from_value(json!({})).unwrap());
    c
}

fn structured(mut c: ResourceClaim) -> ResourceClaim {
    c.metadata
        .finalizers
        .get_or_insert_with(Vec::new)
        .push(FINALIZER.to_string());
    c
}

fn reserve(mut c: ResourceClaim, pod: &Pod) -> ResourceClaim {
    c.status
        .get_or_insert_with(Default::default)
        .reserved_for
        .push(
            serde_json::from_value(json!({
                "resource": "pods", "name": pod.metadata.name, "uid": pod.metadata.uid,
            }))
            .unwrap(),
        );
    c
}

fn make_template(admin: Option<bool>) -> ResourceClaimTemplate {
    let mut v = json!({
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceClaimTemplate",
        "metadata": {"name": TEMPLATE, "namespace": NS},
    });
    if let Some(a) = admin {
        v["spec"] = json!({"spec": admin_spec(a)});
    }
    serde_json::from_value(v).unwrap()
}

fn pod_with_node_name() -> Pod {
    let mut p = test_pod_with_resource();
    p.spec.as_mut().unwrap().node_name = Some(NODE.to_string());
    p.status = Some(
        serde_json::from_value(json!({
            "resourceClaimStatuses": claim_status(&format!("{}1", templated_name())),
        }))
        .unwrap(),
    );
    p
}

fn pod_with_statuses() -> Pod {
    let mut p = test_pod_with_resource();
    p.status = Some(
        serde_json::from_value(json!({
            "resourceClaimStatuses": claim_status(&format!("{}1", templated_name())),
        }))
        .unwrap(),
    );
    p
}

fn pod_key(p: &Pod) -> String {
    format!(
        "{POD_KEY_PREFIX}{}/{}",
        p.metadata.namespace.as_deref().unwrap(),
        p.metadata.name
    )
}
fn claim_key(c: &ResourceClaim) -> String {
    format!(
        "{CLAIM_KEY_PREFIX}{}/{}",
        c.metadata.namespace.as_deref().unwrap(),
        c.metadata.name
    )
}

/// What `normalizeClaims` + `assert.Equal` compare, minus the generated suffix of
/// `generateName` (the fake clientset upstream numbers them; storage here draws random
/// characters, as the API server does).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct Summary {
    namespace: String,
    name: String,
    generate_name: String,
    owners: Vec<(String, bool)>,
    annotations: Vec<(String, String)>,
    admin_access: bool,
    allocated: bool,
    reserved_for: Vec<String>,
    finalizers: Vec<String>,
}

fn summarize(c: &ResourceClaim) -> Summary {
    let generate_name = c.metadata.generate_name.clone().unwrap_or_default();
    let name = if !generate_name.is_empty() && c.metadata.name.starts_with(&generate_name) {
        format!("{generate_name}*")
    } else {
        c.metadata.name.clone()
    };
    let mut annotations: Vec<(String, String)> = c
        .metadata
        .annotations
        .iter()
        .flatten()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    annotations.sort();
    Summary {
        namespace: c.metadata.namespace.clone().unwrap_or_default(),
        name,
        generate_name,
        owners: c
            .metadata
            .owner_references
            .iter()
            .flatten()
            .map(|o| (o.uid.clone(), o.controller == Some(true)))
            .collect(),
        annotations,
        admin_access: admin_access_metric_label(Some(c)) == "true",
        allocated: c.status.as_ref().is_some_and(|s| s.allocation.is_some()),
        reserved_for: c
            .status
            .iter()
            .flat_map(|s| s.reserved_for.iter().map(|r| r.uid.clone()))
            .collect(),
        finalizers: c.metadata.finalizers.clone().unwrap_or_default(),
    }
}

/// A `Storage` that fails creating ResourceClaims, as the case's
/// `PrependReactor("create", "resourceclaims", ... NewConflict)` does.
struct FailClaimCreate(MemoryStorage);

#[async_trait]
impl Storage for FailClaimCreate {
    async fn create<T>(&self, key: &str, value: &T) -> kubernetes_rs_common::Result<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        if key.contains("resourceclaims") {
            return Err(Error::Conflict(
                "Operation cannot be fulfilled on resourceclaims.resource.k8s.io \"fake name\": fake conflict"
                    .to_string(),
            ));
        }
        self.0.create(key, value).await
    }
    async fn get<T>(&self, key: &str) -> kubernetes_rs_common::Result<T>
    where
        T: DeserializeOwned + Send + Sync,
    {
        self.0.get(key).await
    }
    async fn update<T>(&self, key: &str, value: &T) -> kubernetes_rs_common::Result<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        self.0.update(key, value).await
    }
    async fn update_raw(&self, key: &str, value: &Value) -> kubernetes_rs_common::Result<()> {
        self.0.update_raw(key, value).await
    }
    async fn delete(&self, key: &str) -> kubernetes_rs_common::Result<()> {
        self.0.delete(key).await
    }
    async fn list<T>(&self, prefix: &str) -> kubernetes_rs_common::Result<Vec<T>>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        self.0.list(prefix).await
    }
    async fn watch(&self, prefix: &str) -> kubernetes_rs_common::Result<WatchStream> {
        self.0.watch(prefix).await
    }
    async fn watch_from_revision(
        &self,
        prefix: &str,
        revision: i64,
    ) -> kubernetes_rs_common::Result<WatchStream> {
        self.0.watch_from_revision(prefix, revision).await
    }
    async fn current_revision(&self) -> kubernetes_rs_common::Result<i64> {
        self.0.current_revision().await
    }
    async fn is_revision_compacted(&self, revision: i64) -> kubernetes_rs_common::Result<bool> {
        self.0.is_revision_compacted(revision).await
    }
}

async fn put<S: Storage, T: Serialize + DeserializeOwned + Send + Sync>(
    s: &S,
    resource: &str,
    ns: &str,
    name: &str,
    v: &T,
) {
    s.create(&build_key(resource, Some(ns), name), v)
        .await
        .unwrap();
}

async fn put_pod<S: Storage>(s: &S, p: &Pod) {
    put(s, "pods", NS, &p.metadata.name, p).await;
}
async fn put_claim<S: Storage>(s: &S, c: &ResourceClaim) {
    put(
        s,
        "resourceclaims",
        c.metadata.namespace.as_deref().unwrap(),
        &c.metadata.name,
        c,
    )
    .await;
}

async fn all_claims<S: Storage>(s: &S) -> Vec<ResourceClaim> {
    s.list(&build_prefix("resourceclaims", None)).await.unwrap()
}

/// `expectedMetrics{numCreates, numAdminCreates, numFailures, numAdminFailures}`.
type Metrics = [u64; 4];

fn metrics_now() -> Metrics {
    [
        creates_total("success", "false"),
        creates_total("success", "true"),
        creates_total("failure", "false"),
        creates_total("failure", "true"),
    ]
}

// ---------------------------------------------------------------------------
// TestSyncHandler
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Case {
    name: &'static str,
    key: String,
    admin_access: bool,
    prioritized_list: bool,
    claims: Vec<ResourceClaim>,
    claims_in_cache: Vec<ResourceClaim>,
    pods: Vec<Pod>,
    pods_later: Vec<Pod>,
    templates: Vec<ResourceClaimTemplate>,
    expected_claims: Vec<ResourceClaim>,
    /// pod name -> claim name; `*` stands for the generated templated claim.
    expected_statuses: Vec<(String, String)>,
    expected_error: &'static str,
    expected_metrics: Metrics,
}

fn cases() -> Vec<Case> {
    let pod_res = test_pod_with_resource;
    let owner_ref = || owner(&pod_res(), true);
    let test_claim = || make_claim(&format!("{POD_NAME}-{POD_CLAIM}"), NS, Some(owner_ref()));
    let claim_allocated = || allocate(test_claim());
    let claim_reserved = || reserve(claim_allocated(), &pod_res());
    let claim_reserved_twice = || reserve(claim_reserved(), &other_test_pod());
    let templated = || make_templated_claim(Some(owner_ref()), None);
    let templated_with_admin = || make_templated_claim(Some(owner_ref()), Some(true));
    let templated_allocated = || allocate(templated());
    let templated_reserved = || reserve(templated_allocated(), &pod_res());
    let other_ns_claim = || make_claim(&format!("{POD_NAME}-{POD_CLAIM}"), OTHER_NS, None);
    let conflicting_claim = || make_claim(&format!("{POD_NAME}-{POD_CLAIM}"), NS, None);
    let status_of = |p: &str| (p.to_string(), "*".to_string());
    let succeeded = || {
        let mut p = pod_res();
        p.status = Some(serde_json::from_value(json!({"phase": "Succeeded"})).unwrap());
        p
    };

    vec![
        Case {
            name: "create",
            pods: vec![pod_res()],
            templates: vec![make_template(None)],
            key: pod_key(&pod_res()),
            expected_claims: vec![templated()],
            expected_statuses: vec![status_of(POD_NAME)],
            expected_metrics: [1, 0, 0, 0],
            ..Default::default()
        },
        Case {
            name: "create with admin and feature gate off",
            pods: vec![pod_res()],
            templates: vec![make_template(Some(true))],
            key: pod_key(&pod_res()),
            expected_error: ADMIN_OFF,
            ..Default::default()
        },
        Case {
            name: "create with admin and feature gate on",
            pods: vec![pod_res()],
            templates: vec![make_template(Some(true))],
            key: pod_key(&pod_res()),
            admin_access: true,
            expected_claims: vec![templated_with_admin()],
            expected_statuses: vec![status_of(POD_NAME)],
            expected_metrics: [0, 1, 0, 0],
            ..Default::default()
        },
        Case {
            name: "nop",
            pods: vec![pod_with_statuses()],
            templates: vec![make_template(None)],
            key: pod_key(&pod_res()),
            claims: vec![templated()],
            expected_claims: vec![templated()],
            expected_statuses: vec![(POD_NAME.to_string(), format!("{}1", templated_name()))],
            ..Default::default()
        },
        Case {
            name: "recreate",
            pods: vec![pod_with_statuses()],
            templates: vec![make_template(None)],
            key: pod_key(&pod_res()),
            expected_claims: vec![templated()],
            expected_statuses: vec![status_of(POD_NAME)],
            expected_metrics: [1, 0, 0, 0],
            ..Default::default()
        },
        Case {
            name: "missing-template",
            pods: vec![pod_res()],
            key: pod_key(&pod_res()),
            expected_error: "resource claim template \"my-template\": resourceclaimtemplate.resource.k8s.io \"my-template\" not found",
            ..Default::default()
        },
        Case {
            name: "find-existing-claim-by-label",
            pods: vec![pod_res()],
            key: pod_key(&pod_res()),
            claims: vec![templated()],
            expected_claims: vec![templated()],
            expected_statuses: vec![(POD_NAME.to_string(), format!("{}1", templated_name()))],
            ..Default::default()
        },
        Case {
            name: "find-created-claim-in-cache",
            pods: vec![pod_res()],
            key: pod_key(&pod_res()),
            claims_in_cache: vec![templated()],
            expected_statuses: vec![(POD_NAME.to_string(), format!("{}1", templated_name()))],
            ..Default::default()
        },
        Case {
            name: "no-such-pod",
            key: pod_key(&pod_res()),
            ..Default::default()
        },
        Case {
            name: "pod-deleted",
            pods: {
                let mut p = pod_res();
                p.metadata.deletion_timestamp = Some(chrono::Utc::now());
                vec![p]
            },
            key: pod_key(&pod_res()),
            ..Default::default()
        },
        Case {
            name: "no-volumes",
            pods: vec![test_pod()],
            key: pod_key(&test_pod()),
            ..Default::default()
        },
        Case {
            name: "create-with-other-claim",
            pods: vec![pod_res()],
            templates: vec![make_template(None)],
            key: pod_key(&pod_res()),
            claims: vec![other_ns_claim()],
            expected_claims: vec![other_ns_claim(), templated()],
            expected_statuses: vec![status_of(POD_NAME)],
            expected_metrics: [1, 0, 0, 0],
            ..Default::default()
        },
        Case {
            name: "wrong-claim-owner",
            pods: vec![pod_res()],
            key: pod_key(&pod_res()),
            claims: vec![conflicting_claim()],
            expected_claims: vec![conflicting_claim()],
            expected_error: "resource claim template \"my-template\": resourceclaimtemplate.resource.k8s.io \"my-template\" not found",
            ..Default::default()
        },
        Case {
            name: "stay-reserved-seen",
            pods: vec![pod_res()],
            key: claim_key(&claim_reserved()),
            claims: vec![claim_reserved()],
            expected_claims: vec![claim_reserved()],
            ..Default::default()
        },
        Case {
            name: "stay-reserved-not-seen",
            pods_later: vec![pod_res()],
            key: claim_key(&claim_reserved()),
            claims: vec![claim_reserved()],
            expected_claims: vec![claim_reserved()],
            ..Default::default()
        },
        Case {
            name: "clear-reserved-structured",
            key: claim_key(&claim_reserved()),
            claims: vec![structured(claim_reserved())],
            expected_claims: {
                let mut c = claim_allocated();
                c.metadata.finalizers = Some(vec![]);
                c.status.as_mut().unwrap().allocation = None;
                vec![c]
            },
            ..Default::default()
        },
        Case {
            name: "dont-clear-reserved-structured",
            pods: vec![pod_res()],
            key: claim_key(&claim_reserved()),
            claims: vec![reserve(structured(claim_reserved()), &other_test_pod())],
            expected_claims: vec![structured(claim_reserved())],
            ..Default::default()
        },
        Case {
            name: "clear-reserved-structured-deleted",
            key: claim_key(&claim_reserved()),
            claims: {
                let mut c = structured(claim_reserved());
                c.metadata.deletion_timestamp = Some(chrono::Utc::now());
                vec![c]
            },
            expected_claims: {
                let mut c = structured(claim_allocated());
                c.metadata.deletion_timestamp = Some(chrono::Utc::now());
                c.metadata.finalizers = Some(vec![]);
                c.status.as_mut().unwrap().allocation = None;
                vec![c]
            },
            ..Default::default()
        },
        Case {
            name: "structured-deleted",
            key: claim_key(&claim_reserved()),
            claims: {
                let mut c = structured(claim_allocated());
                c.metadata.deletion_timestamp = Some(chrono::Utc::now());
                vec![c]
            },
            expected_claims: {
                let mut c = structured(claim_allocated());
                c.metadata.deletion_timestamp = Some(chrono::Utc::now());
                c.metadata.finalizers = Some(vec![]);
                c.status.as_mut().unwrap().allocation = None;
                vec![c]
            },
            ..Default::default()
        },
        Case {
            name: "clear-reserved-when-done",
            pods: vec![succeeded()],
            key: claim_key(&claim_reserved()),
            claims: {
                let mut c = claim_reserved();
                c.metadata.owner_references = None;
                vec![c]
            },
            expected_claims: {
                let mut c = claim_allocated();
                c.metadata.owner_references = None;
                vec![c]
            },
            ..Default::default()
        },
        Case {
            name: "remove-reserved",
            pods: vec![test_pod()],
            key: claim_key(&claim_reserved_twice()),
            claims: vec![claim_reserved_twice()],
            expected_claims: vec![claim_reserved()],
            ..Default::default()
        },
        Case {
            name: "delete-claim-when-done",
            pods: vec![succeeded()],
            key: claim_key(&claim_reserved()),
            claims: vec![claim_reserved()],
            expected_claims: vec![],
            ..Default::default()
        },
        Case {
            name: "add-reserved",
            pods: vec![pod_with_node_name()],
            key: pod_key(&pod_with_node_name()),
            templates: vec![make_template(None)],
            claims: vec![templated_allocated()],
            expected_claims: vec![templated_reserved()],
            expected_statuses: vec![(POD_NAME.to_string(), format!("{}1", templated_name()))],
            ..Default::default()
        },
    ]
}

#[tokio::test]
#[serial_test::serial(resourceclaim_metrics)]
async fn test_sync_handler() {
    for tc in cases() {
        let storage = Arc::new(MemoryStorage::new());
        for p in &tc.pods {
            put_pod(&*storage, p).await;
        }
        for c in &tc.claims {
            put_claim(&*storage, c).await;
        }
        for t in &tc.templates {
            put(&*storage, "resourceclaimtemplates", NS, &t.metadata.name, t).await;
        }
        let features = Features {
            admin_access: tc.admin_access,
            prioritized_list: tc.prioritized_list,
        };
        let before = metrics_now();
        let name = tc.name;
        let c = ResourceClaimController::new(storage.clone(), features);
        c.prime_caches().await.unwrap();
        // Add claims that only exist in the mutation cache.
        for claim in &tc.claims_in_cache {
            c.add_mutation(claim);
        }
        // Simulate race: add more pods that the controller doesn't know about.
        for p in &tc.pods_later {
            put_pod(&*storage, p).await;
        }
        let res = c.sync_handler(&tc.key).await;

        if !tc.expected_error.is_empty() {
            let e = res.expect_err(&format!("{name}: expected error"));
            assert!(
                e.to_string().contains(tc.expected_error),
                "{name}: error {e:?} does not contain {:?}",
                tc.expected_error
            );
            continue;
        }
        res.unwrap_or_else(|e| panic!("{name}: unexpected error: {e}"));

        let mut got: Vec<Summary> = all_claims(&*storage).await.iter().map(summarize).collect();
        got.sort();
        let mut want: Vec<Summary> = tc.expected_claims.iter().map(summarize).collect();
        want.sort();
        assert_eq!(want, got, "{name}: claims");

        let pods: Vec<Pod> = storage.list(&build_prefix("pods", None)).await.unwrap();
        let claims = all_claims(&*storage).await;
        let mut statuses: Vec<(String, String)> = Vec::new();
        for p in pods {
            for s in p
                .status
                .iter()
                .flat_map(|s| s.resource_claim_statuses.iter().flatten())
            {
                statuses.push((
                    p.metadata.name.clone(),
                    s.resource_claim_name.clone().unwrap_or_default(),
                ));
            }
        }
        statuses.sort();
        let mut want_statuses = tc.expected_statuses.clone();
        for (_, c) in want_statuses.iter_mut() {
            if c == "*" {
                // The name the controller generated for the one templated claim.
                *c = claims
                    .iter()
                    .find(|x| x.metadata.generate_name.as_deref() == Some(&templated_name()))
                    .map(|x| x.metadata.name.clone())
                    .unwrap_or_default();
            }
        }
        want_statuses.sort();
        assert_eq!(
            want_statuses, statuses,
            "{name}: pod resource claim statuses"
        );

        let after = metrics_now();
        let delta: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
        assert_eq!(tc.expected_metrics.to_vec(), delta, "{name}: metrics");
    }
}

/// `create-conflict`: a failing create is counted and reported as the sync error.
#[tokio::test]
#[serial_test::serial(resourceclaim_metrics)]
async fn test_sync_handler_create_conflict() {
    let s = Arc::new(FailClaimCreate(MemoryStorage::new()));
    put_pod(&*s, &test_pod_with_resource()).await;
    put(
        &*s,
        "resourceclaimtemplates",
        NS,
        TEMPLATE,
        &make_template(None),
    )
    .await;
    let c = ResourceClaimController::new(s, Features::default());
    c.prime_caches().await.unwrap();
    let before = creates_total("failure", "false");
    let e = c
        .sync_handler(&pod_key(&test_pod_with_resource()))
        .await
        .expect_err("create must fail");
    assert!(e.to_string().contains("fake conflict"), "{e}");
    assert!(
        e.to_string().contains("PodResourceClaim acme-resource"),
        "{e}"
    );
    assert!(creates_total("failure", "false") > before);
}

// ---------------------------------------------------------------------------
// Handleclaim details that upstream pins through the lister/indexes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generated_name_is_truncated_like_handle_claim() {
    // handleClaim: > maxBaseLen (57) is cut proportionally, keeping a hyphen.
    let long_pod = "p".repeat(60);
    let n = generate_name_for(&long_pod, "claim");
    assert!(n.len() <= 57 + 1, "{n}");
    assert!(n.contains('-'));
    assert_eq!(generate_name_for("pod", "claim"), "pod-claim-".to_string());
}

#[tokio::test]
#[serial_test::serial(resourceclaim_metrics)]
async fn prioritized_list_needs_feature() {
    let s = Arc::new(MemoryStorage::new());
    put_pod(&*s, &test_pod_with_resource()).await;
    let mut t = make_template(None);
    t.spec.spec = serde_json::from_value(json!({"devices": {"requests": [
        {"name": "r", "firstAvailable": [{"name": "a", "deviceClassName": "class"}]}
    ]}}))
    .unwrap();
    put(&*s, "resourceclaimtemplates", NS, TEMPLATE, &t).await;
    let c = ResourceClaimController::new(s.clone(), Features::default());
    c.prime_caches().await.unwrap();
    let e = c
        .sync_handler(&pod_key(&test_pod_with_resource()))
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains(
            "template includes a prioritized list of subrequests, but the feature is disabled"
        ),
        "{e}"
    );
    // The failure is recorded as a pod event.
    let events: Vec<Value> = s.list(&build_prefix("events", None)).await.unwrap();
    assert!(events
        .iter()
        .any(|e| e["reason"] == "FailedResourceClaimCreation"));
}

// ---------------------------------------------------------------------------
// TestGetAdminAccessMetricLabel
// ---------------------------------------------------------------------------

#[test]
fn test_get_admin_access_metric_label() {
    let with = |requests: Value| -> ResourceClaim {
        serde_json::from_value(json!({
            "metadata": {"name": "c"}, "spec": {"devices": {"requests": requests}},
        }))
        .unwrap()
    };
    assert_eq!(admin_access_metric_label(None), "false");
    assert_eq!(admin_access_metric_label(Some(&with(json!([])))), "false");
    assert_eq!(
        admin_access_metric_label(Some(&with(
            json!([{"name": "r", "exactly": {"deviceClassName": "c"}}])
        ))),
        "false"
    );
    assert_eq!(
        admin_access_metric_label(Some(&with(
            json!([{"name": "r", "exactly": {"deviceClassName": "c", "adminAccess": false}}])
        ))),
        "false"
    );
    assert_eq!(
        admin_access_metric_label(Some(&with(
            json!([{"name": "r", "exactly": {"deviceClassName": "c", "adminAccess": true}}])
        ))),
        "true"
    );
    // A prioritized list has no `exactly`: sub-requests do not have admin access.
    assert_eq!(
        admin_access_metric_label(Some(&with(
            json!([{"name": "r", "firstAvailable": [{"name": "a", "deviceClassName": "c"}]}])
        ))),
        "false"
    );
    assert_eq!(
        admin_access_metric_label(Some(&with(json!([
            {"name": "r1", "exactly": {"deviceClassName": "c", "adminAccess": false}},
            {"name": "r2", "exactly": {"deviceClassName": "c", "adminAccess": true}},
        ])))),
        "true"
    );
    assert_eq!(
        admin_access_metric_label(Some(&with(json!([
            {"name": "r1", "exactly": {"deviceClassName": "c", "adminAccess": false}},
            {"name": "r2", "exactly": {"deviceClassName": "c"}},
        ])))),
        "false"
    );
}

// ---------------------------------------------------------------------------
// TestEnqueuePodExtendedResourceClaims
// ---------------------------------------------------------------------------

async fn drain(c: &ResourceClaimController<MemoryStorage>) -> Vec<String> {
    let mut keys = Vec::new();
    while c.queue().len().await > 0 {
        let k = c.queue().get().await.unwrap();
        c.queue().forget(&k).await;
        c.queue().done(&k).await;
        keys.push(k);
    }
    keys
}

#[tokio::test]
async fn test_enqueue_pod_extended_resource_claims() {
    struct T {
        name: &'static str,
        pod: Value,
        deleted: bool,
        early_return: bool,
        extended_enqueued: bool,
    }
    let ext = json!({"requestMappings": [], "resourceClaimName": "test-extended-claim"});
    let mk = |spec: Value, status: Value| {
        json!({
            "metadata": {"name": "test-pod", "namespace": "default"}, "spec": spec, "status": status,
        })
    };
    let tests = vec![
        T {
            name: "pod with no resource claims",
            pod: mk(json!({}), json!({})),
            deleted: false,
            early_return: true,
            extended_enqueued: false,
        },
        T {
            name: "pod with regular resource claims only",
            pod: mk(
                json!({"resourceClaims": [{"name": "regular-claim"}]}),
                json!({"phase": "Running"}),
            ),
            deleted: false,
            early_return: false,
            extended_enqueued: false,
        },
        T {
            name: "extended, running",
            pod: mk(
                json!({}),
                json!({"phase": "Running", "extendedResourceClaimStatus": ext}),
            ),
            deleted: false,
            early_return: false,
            extended_enqueued: false,
        },
        T {
            name: "extended, completed",
            pod: mk(
                json!({}),
                json!({"phase": "Succeeded", "extendedResourceClaimStatus": ext}),
            ),
            deleted: false,
            early_return: false,
            extended_enqueued: true,
        },
        T {
            name: "extended, failed",
            pod: mk(
                json!({}),
                json!({"phase": "Failed", "extendedResourceClaimStatus": ext}),
            ),
            deleted: false,
            early_return: false,
            extended_enqueued: true,
        },
        T {
            name: "deleted pod with extended resource claim",
            pod: mk(
                json!({}),
                json!({"phase": "Succeeded", "extendedResourceClaimStatus": ext}),
            ),
            deleted: true,
            early_return: false,
            extended_enqueued: true,
        },
        T {
            name: "regular and extended, completed",
            pod: mk(
                json!({"resourceClaims": [{"name": "regular-claim"}]}),
                json!({"phase": "Succeeded", "extendedResourceClaimStatus": ext}),
            ),
            deleted: false,
            early_return: false,
            extended_enqueued: true,
        },
    ];
    for t in tests {
        let c = ResourceClaimController::new(Arc::new(MemoryStorage::new()), Features::default());
        let pod: Pod = serde_json::from_value(t.pod).unwrap();
        c.enqueue_pod(&pod, t.deleted).await;
        let keys = drain(&c).await;
        if t.early_return {
            assert!(keys.is_empty(), "{}: {keys:?}", t.name);
            continue;
        }
        let want = format!("{CLAIM_KEY_PREFIX}default/test-extended-claim");
        assert_eq!(
            keys.contains(&want),
            t.extended_enqueued,
            "{}: keys {keys:?}",
            t.name
        );
    }
}

// ---------------------------------------------------------------------------
// TestResourceClaimEventHandler: queue contents and the claims gauge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_resource_claim_event_handler() {
    use std::collections::BTreeMap;
    let c = ResourceClaimController::new(Arc::new(MemoryStorage::new()), Features::default());
    let key = |l: &str, a: &str, s: &str| (l.to_string(), a.to_string(), s.to_string());
    let claim = make_claim(
        &format!("{POD_NAME}-{POD_CLAIM}"),
        NS,
        Some(owner(&test_pod_with_resource(), true)),
    );
    let claim_key_s = claim_key(&claim);

    // create claim
    c.on_claim_event(&StoreEvent::Added(claim.clone())).await;
    assert_eq!(drain(&c).await, vec![claim_key_s.clone()]);
    assert_eq!(
        count_claims(std::slice::from_ref(&claim)),
        BTreeMap::from([(key("false", "false", ""), 1)])
    );
    // modify claim
    c.on_claim_event(&StoreEvent::Modified(claim.clone())).await;
    assert_eq!(drain(&c).await, vec![claim_key_s.clone()]);
    // allocate claim
    let allocated = allocate(claim.clone());
    c.on_claim_event(&StoreEvent::Modified(allocated.clone()))
        .await;
    assert_eq!(drain(&c).await, vec![claim_key_s.clone()]);
    assert_eq!(
        count_claims(std::slice::from_ref(&allocated)),
        BTreeMap::from([(key("true", "false", ""), 1)])
    );
    // delete deallocated claim: not enqueued
    c.on_claim_event(&StoreEvent::Deleted(claim.clone())).await;
    assert!(drain(&c).await.is_empty());

    // templated claim with admin access, extended resource claim
    let admin = make_templated_claim(None, Some(true));
    let ext = make_extended_claim(None);
    assert_eq!(
        count_claims(&[admin, allocate(ext)]),
        BTreeMap::from([
            (key("false", "true", "resource_claim_template"), 1),
            (key("true", "false", "extended_resource"), 1),
        ])
    );
}

/// A claim event also enqueues the pods that use the claim (`enqueueResourceClaim`
/// through `podResourceClaimIndex`): the pod is queued when it needs to reserve the
/// now allocated claim.
#[tokio::test]
async fn claim_event_enqueues_pods_using_it() {
    let s = Arc::new(MemoryStorage::new());
    put_pod(&*s, &pod_with_node_name()).await;
    let templated = make_templated_claim(Some(owner(&test_pod_with_resource(), true)), None);
    put_claim(&*s, &templated).await;
    let c = ResourceClaimController::new(s, Features::default());
    c.prime_caches().await.unwrap();
    // `prime_caches` does not touch the queue.
    assert!(drain(&c).await.is_empty());

    // The store holds the unallocated claim: the pod has nothing to reserve yet.
    c.on_claim_event(&StoreEvent::Modified(templated.clone()))
        .await;
    let keys = drain(&c).await;
    assert_eq!(keys, vec![claim_key(&templated)]);
}

// ---------------------------------------------------------------------------
// uidCache
// ---------------------------------------------------------------------------

#[test]
fn uid_cache_is_an_lru() {
    let c = UidCache::new(2);
    c.add("a");
    c.add("b");
    assert!(c.has("a")); // a is now the most recently used
    c.add("c"); // evicts b
    assert!(c.has("a"));
    assert!(!c.has("b"));
    assert!(c.has("c"));
}

// ---------------------------------------------------------------------------
// Run path: informers -> queue -> workers -> storage
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial_test::serial(resourceclaim_metrics)]
async fn run_creates_claims_and_reserves_them() {
    let s = Arc::new(MemoryStorage::new());
    put(
        &*s,
        "resourceclaimtemplates",
        NS,
        TEMPLATE,
        &make_template(None),
    )
    .await;
    put_pod(&*s, &test_pod_with_resource()).await;
    let c = Arc::new(ResourceClaimController::new(s.clone(), Features::default()));
    let runner = tokio::spawn({
        let c = c.clone();
        async move { c.run_with_workers(2).await }
    });

    // The pod gets its claim and the status entry.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let claim_name = loop {
        let p: Pod = s.get(&build_key("pods", Some(NS), POD_NAME)).await.unwrap();
        if let Some(n) = p
            .status
            .and_then(|st| st.resource_claim_statuses)
            .and_then(|v| v.into_iter().next())
            .and_then(|v| v.resource_claim_name)
        {
            break n;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pod never got resourceClaimStatuses"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let claim: ResourceClaim = s
        .get(&build_key("resourceclaims", Some(NS), &claim_name))
        .await
        .unwrap();
    assert!(claim.metadata.name.starts_with(&templated_name()));
    assert_eq!(
        claim
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(POD_RESOURCE_CLAIM_ANNOTATION))
            .map(String::as_str),
        Some(POD_CLAIM)
    );

    // The scheduler allocates the claim and binds the pod: the controller reserves it.
    let mut allocated = allocate(claim.clone());
    allocated.metadata.resource_version = claim.metadata.resource_version.clone();
    s.update_status::<ResourceClaim>(
        &build_key("resourceclaims", Some(NS), &claim_name),
        &allocated,
    )
    .await
    .unwrap();
    let mut pod: Pod = s.get(&build_key("pods", Some(NS), POD_NAME)).await.unwrap();
    pod.spec.as_mut().unwrap().node_name = Some(NODE.to_string());
    s.update(&build_key("pods", Some(NS), POD_NAME), &pod)
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let c: ResourceClaim = s
            .get(&build_key("resourceclaims", Some(NS), &claim_name))
            .await
            .unwrap();
        if c.status
            .as_ref()
            .is_some_and(|st| st.reserved_for.iter().any(|r| r.uid == POD_UID))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "claim never got reserved for the pod"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The pod completes: the reservation goes and the generated claim is deleted.
    let mut pod: Pod = s.get(&build_key("pods", Some(NS), POD_NAME)).await.unwrap();
    pod.status.as_mut().unwrap().phase = Some(kubernetes_rs_common::types::Phase::Succeeded);
    s.update_status::<Pod>(&build_key("pods", Some(NS), POD_NAME), &pod)
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if all_claims(&*s).await.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "generated claim was never deleted"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    runner.abort();
}
