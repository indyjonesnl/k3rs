//! Ports of the shared pod-template cases of describe_test.go
//! (TestDescribePodTolerations, TestDescribePodVolumes,
//! TestDescribeTopologySpreadConstraints, TestDescribeContainerPorts) driven
//! through `describeReplicaSet` / `describeReplicationController`, which print
//! the same `DescribePodTemplate` blocks.
use chrono::Utc;
use kubernetes_rs_kubectl::commands::describe::workloads::*;
use serde_json::{json, Value};

/// The tabwriter pads columns, so substring checks compare with whitespace runs collapsed.
fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn rs(template_spec: Value) -> Value {
    json!({
        "metadata": {"name": "bar", "namespace": "foo"},
        "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "x"}},
                 "template": {"metadata": {"labels": {"app": "x"}}, "spec": template_spec}},
        "status": {"replicas": 2}
    })
}

fn out(template_spec: Value) -> String {
    describe_replica_set(&rs(template_spec), None, Ok((1, 2, 3, 4)), Utc::now())
}

#[test]
fn describe_workloads_replica_set_full_output() {
    let mut obj = rs(json!({
        "serviceAccountName": "sa",
        "containers": [{"name": "c", "image": "nginx",
            "ports": [{"containerPort": 80, "protocol": "TCP"}],
            "resources": {"limits": {"cpu": "1", "memory": "1Gi"}, "requests": {"cpu": "500m"}},
            "livenessProbe": {"httpGet": {"path": "/h", "port": 80, "scheme": "HTTP"},
                "initialDelaySeconds": 1, "timeoutSeconds": 2, "periodSeconds": 3,
                "successThreshold": 1, "failureThreshold": 5},
            "env": [{"name": "A", "value": "b"}],
            "volumeMounts": [{"name": "v", "mountPath": "/data"}]}],
        "volumes": [{"name": "v", "emptyDir": {}}]
    }));
    obj["metadata"]["ownerReferences"] =
        json!([{"kind": "Deployment", "name": "dep", "controller": true, "uid": "u"}]);
    obj["status"]["conditions"] =
        json!([{"type": "ReplicaFailure", "status": "True", "reason": "FailedCreate"}]);
    let got = describe_replica_set(&obj, None, Ok((1, 0, 0, 0)), Utc::now());
    let expected = "\
Name:           bar
Namespace:      foo
Selector:       app=x
Labels:         <none>
Annotations:    <none>
Controlled By:  Deployment/dep
Replicas:       2 current / 3 desired
Pods Status:    1 Running / 0 Waiting / 0 Succeeded / 0 Failed
Pod Template:
  Labels:           app=x
  Service Account:  sa
  Containers:
   c:
    Image:      nginx
    Port:       80/TCP
    Host Port:  0/TCP
    Limits:
      cpu:     1
      memory:  1Gi
    Requests:
      cpu:     500m
    Liveness:  http-get http://:80/h delay=1s timeout=2s period=3s #success=1 #failure=5
    Environment:
      A:  b
    Mounts:
      /data from v (rw)
  Volumes:
   v:
    Type:          EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:        
    SizeLimit:     <unset>
  Node-Selectors:  <none>
  Tolerations:     <none>
Conditions:
  Type             Status  Reason
  ----             ------  ------
  ReplicaFailure   True    FailedCreate
";
    assert_eq!(got, expected);
}

#[test]
fn describe_workloads_replication_controller() {
    let rc = json!({
        "metadata": {"name": "rc", "namespace": "ns"},
        "spec": {"replicas": 1, "selector": {"a": "b", "c": "d"},
                 "template": {"spec": {"containers": [{"name": "c", "image": "i"}]}}},
        "status": {"replicas": 1}
    });
    let got = describe_replication_controller(&rc, None, (1, 2, 3, 4), Utc::now());
    assert!(got.contains("Selector:     a=b,c=d\n"), "{got}");
    assert!(
        got.contains("Pods Status:  1 Running / 2 Waiting / 3 Succeeded / 4 Failed\n"),
        "{got}"
    );
    assert!(got.contains("Pod Template:\n  Labels:  <none>\n"), "{got}");
}

#[test]
fn describe_workloads_replica_set_pod_error() {
    let got = describe_replica_set(
        &rs(json!({"containers": []})),
        None,
        Err("boom".into()),
        Utc::now(),
    );
    assert!(
        got.contains("Pods Status:  error in fetching pods: boom\n"),
        "{got}"
    );
    assert!(got.contains("Containers: <none>\n"), "{got}");
}

/// TestDescribePodTolerations.
#[test]
fn describe_workloads_tolerations() {
    let o = out(json!({"containers": [], "tolerations": [
        {"operator": "Exists"},
        {"effect": "NoSchedule", "operator": "Exists"},
        {"key": "key0", "operator": "Exists"},
        {"key": "key1", "value": "value1"},
        {"key": "key2", "operator": "Equal", "value": "value2", "effect": "NoSchedule"},
        {"key": "key3", "value": "value3", "effect": "NoExecute", "tolerationSeconds": 300},
        {"key": "key4", "effect": "NoExecute", "tolerationSeconds": 60}]}));
    for want in [
        "op=Exists\n",
        ":NoSchedule op=Exists\n",
        "key0 op=Exists\n",
        "key1=value1\n",
        "key2=value2:NoSchedule\n",
        "key3=value3:NoExecute for 300s\n",
        "key4:NoExecute for 60s\n",
        "Tolerations:",
    ] {
        assert!(o.contains(want), "missing {want:?} in\n{o}");
    }
}

/// TestDescribePodVolumes (the image volume block).
#[test]
fn describe_workloads_image_volume() {
    let o = out(json!({"containers": [],
        "volumes": [{"name": "image", "image": {"reference": "image", "pullPolicy": "IfNotPresent"}}]}));
    assert!(
        squash(&o).contains(&squash("Volumes:\n image:\n Type: Image (a container image or OCI artifact)\n Reference: image\n PullPolicy: IfNotPresent\n")),
        "{o}"
    );
}

/// TestDescribeTopologySpreadConstraints.
#[test]
fn describe_workloads_topology_spread_constraints() {
    let o = out(json!({"containers": [], "topologySpreadConstraints": [
        {"maxSkew": 3, "topologyKey": "topology.kubernetes.io/test1", "whenUnsatisfiable": "DoNotSchedule",
         "labelSelector": {"matchLabels": {"key1": "val1", "key2": "val2"}}},
        {"maxSkew": 1, "topologyKey": "topology.kubernetes.io/test2", "whenUnsatisfiable": "ScheduleAnyway"}]}));
    assert!(o.contains("topology.kubernetes.io/test1:DoNotSchedule when max skew 3 is exceeded for selector key1=val1,key2=val2\n"), "{o}");
    assert!(
        o.contains("topology.kubernetes.io/test2:ScheduleAnyway when max skew 1 is exceeded\n"),
        "{o}"
    );
}

/// TestDescribeContainerPorts (container and host port strings).
#[test]
fn describe_workloads_container_ports() {
    let o = out(json!({"containers": [{"name": "c", "image": "i", "ports": [
        {"name": "controller", "containerPort": 9093, "hostPort": 9093, "protocol": "TCP"},
        {"containerPort": 9092, "protocol": "TCP"},
        {"name": "interbroker", "containerPort": 9094, "hostPort": 9094, "protocol": "TCP"}]}]}));
    assert!(
        squash(&o).contains("Ports: 9093/TCP (controller), 9092/TCP, 9094/TCP (interbroker)"),
        "{o}"
    );
    assert!(
        squash(&o).contains("Host Ports: 9093/TCP (controller), 0/TCP, 9094/TCP (interbroker)"),
        "{o}"
    );
    let single = out(json!({"containers": [{"name": "c", "image": "i", "ports": [
        {"name": "web", "containerPort": 8080, "hostPort": 8080, "protocol": "TCP"}]}]}));
    assert!(squash(&single).contains("Port: 8080/TCP (web)"), "{single}");
    assert!(
        squash(&single).contains("Host Port: 8080/TCP (web)"),
        "{single}"
    );
}

#[test]
fn describe_workloads_env_probes_and_projected() {
    let o = out(json!({"containers": [{"name": "c", "image": "i",
        "command": ["a\nb"], "args": ["x"],
        "envFrom": [{"configMapRef": {"name": "cm"}}, {"secretRef": {"name": "s", "optional": true}, "prefix": "P_"}],
        "env": [
            {"name": "M", "value": "l1\nl2"},
            {"name": "F", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.name"}}},
            {"name": "R", "valueFrom": {"resourceFieldRef": {"resource": "limits.cpu"}}},
            {"name": "R2", "valueFrom": {"resourceFieldRef": {"resource": "requests.memory",
                "divisor": "1Mi"}}},
            {"name": "S", "valueFrom": {"secretKeyRef": {"name": "sec", "key": "k"}}},
            {"name": "C", "valueFrom": {"configMapKeyRef": {"name": "cm", "key": "k", "optional": true}}}],
        "readinessProbe": {"exec": {"command": ["cat", "/x"]}},
        "startupProbe": {"tcpSocket": {"port": "web"}},
        "resources": {"requests": {"memory": "2Mi"}}}],
        "volumes": [{"name": "p", "projected": {"sources": [
            {"secret": {"name": "s1", "optional": false}}, {"downwardAPI": {}},
            {"configMap": {"name": "c1"}}, {"serviceAccountToken": {"expirationSeconds": 3607}}]}}]}));
    for want in [
        "Command:\n      a\n      b\n",
        "Args:\n      x\n",
        "Environment Variables from:\n      cm\tConfigMap\tOptional: false\n",
        "s\tSecret with prefix 'P_'\tOptional: true\n",
        "M:\tl1\n",
        "\tl2\n",
        "F:\t (v1:metadata.name)\n",
        "R:\tnode allocatable (limits.cpu)\n",
        "R2:\t2 (requests.memory)\n",
        "S:\t<set to the key 'k' in secret 'sec'>\tOptional: false\n",
        "C:\t<set to the key 'k' of config map 'cm'>\tOptional: true\n",
        "Readiness:\texec [cat /x] delay=0s timeout=0s period=0s #success=0 #failure=0\n",
        "Startup:\ttcp-socket :web delay=0s",
        "TokenExpirationSeconds:\t3607\n",
        "DownwardAPI:\ttrue\n",
    ] {
        assert!(
            squash(&o).contains(&squash(want)),
            "missing {want:?} in\n{o}"
        );
    }
}

#[test]
fn describe_workloads_selector_and_pod_status() {
    use kubernetes_rs_kubectl::commands::describe::workloads::format_label_selector;
    let sel = json!({"matchLabels": {"b": "1"}, "matchExpressions": [
        {"key": "a", "operator": "In", "values": ["z", "y"]},
        {"key": "c", "operator": "NotIn", "values": ["q"]},
        {"key": "d", "operator": "Exists"}, {"key": "e", "operator": "DoesNotExist"}]});
    assert_eq!(
        format_label_selector(&sel),
        "a in (y,z),b=1,c notin (q),d,!e"
    );
    assert_eq!(format_label_selector(&json!({})), "<none>");
    assert_eq!(
        format_label_selector(&json!({"matchExpressions": [{"key": "a", "operator": "Bad"}]})),
        "<error>"
    );

    let pod = |phase: &str, uid: &str, ctl: bool| json!({"metadata": {"ownerReferences": [{"uid": uid, "controller": ctl}]}, "status": {"phase": phase}});
    let pods = vec![
        pod("Running", "me", true),
        pod("Pending", "me", true),
        pod("Succeeded", "me", true),
        pod("Failed", "me", true),
        pod("Running", "other", true),
        pod("Running", "me", false),
        json!({"status": {"phase": "Running"}}),
    ];
    assert_eq!(pod_status_for_controller(&pods, "me"), (1, 1, 1, 1));
}
