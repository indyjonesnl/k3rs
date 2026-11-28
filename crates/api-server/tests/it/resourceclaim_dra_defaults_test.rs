//! `SetDefaults_ExactDeviceRequest` / `SetDefaults_DeviceSubRequest`
//! (`pkg/apis/resource/v1/defaults.go:31-49`) on the ResourceClaim and
//! ResourceClaimTemplate create path.

use kubernetes_rs_storage::{build_key, Storage};
use kubernetes_rs_test_support::harness::TestApiServer;
use serde_json::{json, Value};

fn spec() -> Value {
    json!({ "devices": { "requests": [
        { "name": "req", "exactly": { "deviceClassName": "class" } },
        { "name": "alt", "firstAvailable": [{ "name": "sub", "deviceClassName": "class" }] }
    ] } })
}

fn assert_defaulted(spec: &Value) {
    let reqs = &spec["devices"]["requests"];
    assert_eq!(reqs[0]["exactly"]["allocationMode"], "ExactCount", "{spec}");
    assert_eq!(reqs[0]["exactly"]["count"], 1, "{spec}");
    assert_eq!(
        reqs[1]["firstAvailable"][0]["allocationMode"], "ExactCount",
        "{spec}"
    );
    assert_eq!(reqs[1]["firstAvailable"][0]["count"], 1, "{spec}");
}

#[tokio::test]
async fn dra_defaults_resource_claim_create() {
    let api = TestApiServer::new();
    let (status, body) = api
        .send(
            "POST",
            "/apis/resource.k8s.io/v1/namespaces/default/resourceclaims",
            Some("application/json"),
            Some(&json!({
                "apiVersion": "resource.k8s.io/v1",
                "kind": "ResourceClaim",
                "metadata": { "name": "claim-defaults", "namespace": "default" },
                "spec": spec(),
            })),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
    let body: Value = serde_json::from_str(&body.to_string()).unwrap();
    assert_defaulted(&body["spec"]);
}

#[tokio::test]
async fn dra_defaults_resource_claim_template_create() {
    let api = TestApiServer::new();
    let (status, body) = api
        .send(
            "POST",
            "/apis/resource.k8s.io/v1/namespaces/default/resourceclaimtemplates",
            Some("application/json"),
            Some(&json!({
                "apiVersion": "resource.k8s.io/v1",
                "kind": "ResourceClaimTemplate",
                "metadata": { "name": "tmpl-defaults", "namespace": "default" },
                "spec": { "spec": spec() },
            })),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
    let body: Value = serde_json::from_str(&body.to_string()).unwrap();
    assert_defaulted(&body["spec"]["spec"]);
}

/// The storage codec's scheme defaulter (`SetObjectDefaults_ResourceClaim`,
/// `_ResourceClaimTemplate`, `_ResourceSlice`, zz_generated.defaults.go:46-129)
/// runs on every decode: objects stored without defaults come back defaulted
/// from GET.
#[tokio::test]
async fn dra_defaults_applied_on_read_of_stored_claim_and_template() {
    let api = TestApiServer::new();
    let tol = json!([{ "key": "k", "effect": "NoSchedule" }]);
    let mut spec = spec();
    spec["devices"]["requests"][0]["exactly"]["tolerations"] = tol.clone();
    let claim = json!({
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceClaim",
        "metadata": { "name": "raw", "namespace": "default" },
        "spec": spec.clone(),
        "status": { "allocation": { "devices": { "results": [
            { "request": "req", "driver": "d.example.com", "pool": "p", "device": "x",
              "tolerations": tol }
        ] } } },
    });
    let key = build_key("resourceclaims", Some("default"), "raw");
    api.storage.create(&key, &claim).await.unwrap();
    let (status, got) = api
        .get("/apis/resource.k8s.io/v1/namespaces/default/resourceclaims/raw")
        .await;
    assert!(status.is_success(), "{status} {got}");
    assert_defaulted(&got["spec"]);
    assert_eq!(
        got["spec"]["devices"]["requests"][0]["exactly"]["tolerations"][0]["operator"], "Equal",
        "{got}"
    );
    assert_eq!(
        got["status"]["allocation"]["devices"]["results"][0]["tolerations"][0]["operator"], "Equal",
        "{got}"
    );

    let template = json!({
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceClaimTemplate",
        "metadata": { "name": "raw-t", "namespace": "default" },
        "spec": { "spec": spec },
    });
    let key = build_key("resourceclaimtemplates", Some("default"), "raw-t");
    api.storage.create(&key, &template).await.unwrap();
    let (status, got) = api
        .get("/apis/resource.k8s.io/v1/namespaces/default/resourceclaimtemplates/raw-t")
        .await;
    assert!(status.is_success(), "{status} {got}");
    assert_defaulted(&got["spec"]["spec"]);
}

/// `SetDefaults_DeviceTaint` (defaults.go:51-56) through
/// `SetObjectDefaults_ResourceSlice` (zz_generated.defaults.go:121-129):
/// `timeAdded` is set, truncated to the second, when the stored taint lacks it.
#[tokio::test]
async fn dra_defaults_device_taint_time_added_on_read_of_stored_slice() {
    let api = TestApiServer::new();
    let slice = json!({
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceSlice",
        "metadata": { "name": "raw-slice" },
        "spec": {
            "driver": "d.example.com", "nodeName": "n",
            "pool": { "name": "p", "generation": 1, "resourceSliceCount": 1 },
            "devices": [{ "name": "dev", "taints": [
                { "key": "k", "effect": "NoSchedule" },
                { "key": "k2", "effect": "NoSchedule", "timeAdded": "2024-01-02T03:04:05Z" }
            ] }]
        }
    });
    api.storage
        .create(&build_key("resourceslices", None, "raw-slice"), &slice)
        .await
        .unwrap();
    let (status, got) = api
        .get("/apis/resource.k8s.io/v1/resourceslices/raw-slice")
        .await;
    assert!(status.is_success(), "{status} {got}");
    let taints = &got["spec"]["devices"][0]["taints"];
    let added = taints[0]["timeAdded"].as_str().expect("defaulted");
    assert!(added.ends_with("Z") && !added.contains('.'), "{added}");
    assert_eq!(taints[1]["timeAdded"], "2024-01-02T03:04:05Z", "{got}");
}
