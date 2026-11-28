//! Ports of TestDescribeSecret / TestDescribeConfigMap / TestDescribeServiceAccount /
//! TestDescribeResourceQuota / TestDescribeLimitRange / TestDescribePriorityClass
//! (describe_test.go).
use base64::Engine;
use chrono::Utc;
use kubernetes_rs_kubectl::commands::describe::core_a::*;
use serde_json::json;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[test]
fn describe_core_a_secret_sorted_keys_and_no_values() {
    let obj = json!({
        "metadata": {"name": "bar", "namespace": "foo"},
        "data": {"text": b64(b"a3ViZXJuZXRlcwo="), "Text": b64(b"dGhpcyBpcyBhIHRlc3QK"), "tExt": b64(b"d2VpcmQ=")}
    });
    let out = describe_secret(&obj);
    let expected = "Name:         bar\nNamespace:    foo\nLabels:       <none>\nAnnotations:  <none>\n\nType:  \n\nData\n====\nText:  20 bytes\ntExt:  8 bytes\ntext:  16 bytes\n";
    assert_eq!(out, expected);
    assert!(!out.contains("a3ViZXJuZXRlcwo="));
}

#[test]
fn describe_core_a_secret_shows_only_sa_token() {
    let obj = json!({
        "metadata": {"name": "t", "namespace": "ns"},
        "type": "kubernetes.io/service-account-token",
        "data": {"token": b64(b"abc.def"), "ca.crt": b64(b"xx")}
    });
    let out = describe_secret(&obj);
    assert!(out.contains("token:   abc.def"), "{out}");
    assert!(out.contains("ca.crt:  2 bytes"), "{out}");
    let opaque =
        json!({"metadata": {"name": "t"}, "type": "Opaque", "data": {"token": b64(b"abc.def")}});
    assert!(describe_secret(&opaque).contains("token:  7 bytes"));
}

#[test]
fn describe_core_a_config_map() {
    let obj = json!({
        "metadata": {"name": "mycm", "namespace": "foo"},
        "data": {"key1": "value1", "key2": "value2"},
        "binaryData": {"binarykey1": b64(&[0xFF, 0xFE, 0xFD, 0xFC, 0xFB]),
                       "binarykey2": b64(&[0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA])}
    });
    let out = describe_config_map(&obj, Some(&[]), Utc::now());
    let expected = "Name:         mycm\nNamespace:    foo\nLabels:       <none>\nAnnotations:  <none>\n\nData\n====\nkey1:\n----\nvalue1\n\nkey2:\n----\nvalue2\n\n\nBinaryData\n====\nbinarykey1: 5 bytes\nbinarykey2: 6 bytes\n\nEvents:  <none>\n";
    assert_eq!(out, expected);
}

#[test]
fn describe_core_a_service_account() {
    let obj = json!({
        "metadata": {"name": "bar", "namespace": "foo"},
        "secrets": [{"name": "test-objectref"}],
        "imagePullSecrets": [{"name": "test-local-ref"}]
    });
    let out = describe_service_account(&obj, Some(&[]), Utc::now());
    let expected = "Name:                bar\nNamespace:           foo\nLabels:              <none>\nAnnotations:         <none>\nImage pull secrets:  test-local-ref\nEvents:              <none>\n";
    assert_eq!(out, expected);
    let two = json!({"metadata": {"name": "b", "namespace": "f"},
        "imagePullSecrets": [{"name": "a"}, {"name": "b"}]});
    let out = describe_service_account(&two, None, Utc::now());
    assert!(
        out.contains("Image pull secrets:  a\n                     b\n"),
        "{out}"
    );
    let none = json!({"metadata": {"name": "b", "namespace": "f"}});
    assert!(
        describe_service_account(&none, None, Utc::now()).contains("Image pull secrets:  <none>")
    );
}

#[test]
fn describe_core_a_resource_quota() {
    let obj = json!({
        "metadata": {"name": "bar", "namespace": "foo"},
        "spec": {"scopes": ["NotTerminating", "BestEffort"]},
        "status": {
            "hard": {"cpu": "1", "limits.cpu": "2", "limits.memory": "2G", "memory": "1G",
                     "requests.cpu": "1", "requests.memory": "1G"},
            "used": {"cpu": "0", "limits.cpu": "0", "limits.memory": "0G", "memory": "0G",
                     "requests.cpu": "0", "requests.memory": "1000Ki"}
        }
    });
    let out = describe_resource_quota(&obj);
    for want in [
        "limits.cpu",
        "limits.memory",
        "2G",
        "requests.memory",
        "1024k",
        "1G",
    ] {
        assert!(out.contains(want), "missing {want}: {out}");
    }
    // Scopes sorted, one help line each (indented one space).
    assert!(
        out.contains("Scopes:     BestEffort, NotTerminating\n"),
        "{out}"
    );
    assert!(
        out.contains(" * Matches all pods that do not have resource requirements set."),
        "{out}"
    );
    // Resources sorted by name.
    let pos = |s: &str| out.find(s).unwrap();
    assert!(
        pos("cpu ") < pos("limits.cpu")
            && pos("limits.memory") < pos("memory ")
            && pos("memory ") < pos("requests.cpu"),
        "{out}"
    );
}

#[test]
fn describe_core_a_limit_range() {
    let obj = json!({
        "metadata": {"name": "mylr", "namespace": "foo"},
        "spec": {"limits": [
            {"type": "Pod", "max": {"cpu": "100m", "memory": "10000Mi"}, "min": {"cpu": "5m", "memory": "100Mi"},
             "maxLimitRequestRatio": {"cpu": "10"}},
            {"type": "PersistentVolumeClaim", "max": {"storage": "10Gi"}, "min": {"storage": "5Gi"}}
        ]}
    });
    let out = describe_limit_range(&obj);
    let expected = "Name:       mylr\nNamespace:  foo\nType                   Resource  Min   Max      Default Request  Default Limit  Max Limit/Request Ratio\n----                   --------  ---   ---      ---------------  -------------  -----------------------\nPod                    cpu       5m    100m     -                -              10\nPod                    memory    100Mi 10000Mi  -                -              -\nPersistentVolumeClaim  storage   5Gi   10Gi     -                -              -\n";
    // Column widths are the tabwriter's; compare ignoring runs of spaces.
    let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(norm(&out), norm(expected), "{out}");
}

#[test]
fn describe_core_a_priority_class() {
    let obj = json!({
        "metadata": {"name": "bar"},
        "value": 100, "globalDefault": true, "preemptionPolicy": "Never", "description": "test2"
    });
    let out = describe_priority_class(&obj, None, Utc::now());
    let expected = "Name:              bar\nValue:             100\nGlobalDefault:     true\nPreemptionPolicy:  Never\nDescription:       test2\nAnnotations:       <none>\n";
    assert_eq!(out, expected);
    let annotated =
        json!({"metadata": {"name": "b", "annotations": {"b": "2", "a": "1"}}, "value": 1});
    let out = describe_priority_class(&annotated, None, Utc::now());
    assert!(out.contains("Annotations:       a=1,b=2\n"), "{out}");
    assert!(
        out.contains("PreemptionPolicy:  PreemptLowerPriority"),
        "{out}"
    );
}
