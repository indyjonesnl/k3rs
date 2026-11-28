//! `SetDefaults_ExactDeviceRequest` / `SetDefaults_DeviceSubRequest`
//! (`pkg/apis/resource/v1/defaults.go:31-49`) on the ResourceClaim and
//! ResourceClaimTemplate create path.

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
