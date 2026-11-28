//! Ports of `pkg/scheduler/extender_test.go` `TestConvertToMetaVictims` and
//! `TestConvertToVictims`, plus checks of `HTTPExtender.Bind` and
//! `ProcessPreemption` (extender.go:137-247, 362-382).

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use kubernetes_rs_common::resources::binding::{Binding, ObjectReference};
use kubernetes_rs_common::resources::{Node, Pod, PodSpec};
use kubernetes_rs_scheduler::extender::*;
use kubernetes_rs_scheduler::fwk::NodeInfo;

fn pod(name: &str, uid: &str, node: Option<&str>) -> Pod {
    let mut p = Pod::new(
        name,
        PodSpec {
            node_name: node.map(String::from),
            ..Default::default()
        },
    );
    p.metadata.uid = uid.to_string();
    p
}

fn extender(cfg: ExtenderConfig) -> HttpExtender {
    HttpExtender::new(&cfg).unwrap()
}

fn cfg(url: &str) -> ExtenderConfig {
    ExtenderConfig {
        url_prefix: url.to_string(),
        ..Default::default()
    }
}

// TestConvertToMetaVictims (extender_test.go:445)
#[test]
fn extender_convert_to_meta_victims() {
    let mut m = BTreeMap::new();
    m.insert(
        "node1".to_string(),
        Victims {
            pods: vec![pod("pod1", "uid1", None), pod("pod3", "uid3", None)],
            num_pdb_violations: 1,
        },
    );
    m.insert(
        "node2".to_string(),
        Victims {
            pods: vec![pod("pod2", "uid2", None), pod("pod4", "uid4", None)],
            num_pdb_violations: 2,
        },
    );
    let got = convert_to_meta_victims(&m);
    let mv = |uids: &[&str], n| MetaVictims {
        pods: uids
            .iter()
            .map(|u| MetaPod { uid: u.to_string() })
            .collect(),
        num_pdb_violations: n,
    };
    assert_eq!(got["node1"], mv(&["uid1", "uid3"], 1));
    assert_eq!(got["node2"], mv(&["uid2", "uid4"], 2));
    assert_eq!(got.len(), 2);
}

// TestConvertToVictims (extender_test.go:497)
#[test]
fn extender_convert_to_victims() {
    let nodes = [Node::new("node1"), Node::new("node2")];
    let pods = vec![
        pod("pod1", "uid1", Some("node1")),
        pod("pod2", "uid2", Some("node2")),
        pod("pod3", "uid3", Some("node1")),
        pod("pod4", "uid4", Some("node2")),
    ];
    let lister = |name: &str| -> Result<NodeInfo<'_>> {
        nodes
            .iter()
            .find(|n| n.metadata.name == name)
            .map(|n| NodeInfo::new(n, &pods))
            .ok_or_else(|| anyhow!("node {name:?} not found"))
    };
    let mut meta = BTreeMap::new();
    let mp = |uids: &[&str], n| MetaVictims {
        pods: uids
            .iter()
            .map(|u| MetaPod { uid: u.to_string() })
            .collect(),
        num_pdb_violations: n,
    };
    meta.insert("node1".to_string(), mp(&["uid1", "uid3"], 1));
    meta.insert("node2".to_string(), mp(&["uid2", "uid4"], 2));
    let e = extender(cfg("http://x"));
    let got = e.convert_to_victims(&meta, &lister).unwrap();
    let names = |n: &str| -> Vec<String> {
        got[n]
            .pods
            .iter()
            .map(|p| p.metadata.name.clone())
            .collect()
    };
    assert_eq!(names("node1"), ["pod1", "pod3"]);
    assert_eq!(names("node2"), ["pod2", "pod4"]);
    assert_eq!(got["node1"].num_pdb_violations, 1);
    assert_eq!(got["node2"].num_pdb_violations, 2);

    // A pod the node does not hold is a cache inconsistency (extender.go:218).
    meta.insert("node1".to_string(), mp(&["uid2"], 0));
    let err = e.convert_to_victims(&meta, &lister).unwrap_err();
    assert!(err.to_string().contains("claims to preempt pod"), "{err}");
    // An unknown node is the lister's error (extender.go:186).
    meta.insert("node9".to_string(), mp(&[], 0));
    assert!(e.convert_to_victims(&meta, &lister).is_err());
}

#[tokio::test]
async fn extender_bind_requires_bind_verb() {
    let e = extender(cfg("http://x"));
    let b = Binding::new("p", "ns", ObjectReference::default());
    let err = e.bind(&b).await.unwrap_err();
    assert_eq!(err.to_string(), "unexpected empty bindVerb in extender");
}

#[tokio::test]
async fn extender_process_preemption_requires_preempt_verb() {
    let e = extender(cfg("http://x"));
    let lister = |_: &str| -> Result<NodeInfo<'_>> { bail!("unused") };
    let err = e
        .process_preemption(&pod("p", "u", None), &BTreeMap::new(), &lister)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("preempt verb is not defined for extender http://x"));
}

/// One-shot HTTP server replying 200 with `body`; returns the URL and the
/// received request body.
async fn serve(body: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let h = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = s.read(&mut tmp).await.unwrap();
            buf.extend_from_slice(&tmp[..n]);
            let text = String::from_utf8_lossy(&buf).to_string();
            if let Some(i) = text.find("\r\n\r\n") {
                let len: usize = text[..i]
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                if buf.len() >= i + 4 + len {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        s.write_all(resp.as_bytes()).await.unwrap();
        let text = String::from_utf8_lossy(&buf).to_string();
        text.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
    });
    (url, h)
}

#[tokio::test]
async fn extender_bind_sends_binding_args_and_surfaces_error() {
    let (url, req) = serve(r#"{"Error":"boom"}"#).await;
    let mut c = cfg(&url);
    c.bind_verb = "bind".into();
    let e = extender(c);
    let mut b = Binding::new(
        "p",
        "ns",
        ObjectReference {
            name: "node1".into(),
            ..Default::default()
        },
    );
    b.metadata.uid = "u1".into();
    let err = e.bind(&b).await.unwrap_err();
    assert_eq!(err.to_string(), "boom");
    let sent: ExtenderBindingArgs = serde_json::from_str(&req.await.unwrap()).unwrap();
    assert_eq!(
        sent,
        ExtenderBindingArgs {
            pod_name: "p".into(),
            pod_namespace: "ns".into(),
            pod_uid: "u1".into(),
            node: "node1".into()
        }
    );
}

#[tokio::test]
async fn extender_process_preemption_node_cache_capable_sends_meta_victims() {
    let (url, req) = serve(
        r#"{"NodeNameToMetaVictims":{"node1":{"Pods":[{"UID":"uid1"}],"NumPDBViolations":3}}}"#,
    )
    .await;
    let mut c = cfg(&url);
    c.preempt_verb = "preempt".into();
    c.node_cache_capable = true;
    let e = extender(c);
    let nodes = [Node::new("node1")];
    let pods = vec![pod("pod1", "uid1", Some("node1"))];
    let lister = |n: &str| -> Result<NodeInfo<'_>> {
        nodes
            .iter()
            .find(|x| x.metadata.name == n)
            .map(|x| NodeInfo::new(x, &pods))
            .ok_or_else(|| anyhow!("missing"))
    };
    let mut input = BTreeMap::new();
    input.insert(
        "node1".to_string(),
        Victims {
            pods: vec![pods[0].clone()],
            num_pdb_violations: 0,
        },
    );
    let got = e
        .process_preemption(&pod("preemptor", "pu", None), &input, &lister)
        .await
        .unwrap();
    assert_eq!(got["node1"].pods[0].metadata.name, "pod1");
    assert_eq!(got["node1"].num_pdb_violations, 3);
    let sent: ExtenderPreemptionArgs = serde_json::from_str(&req.await.unwrap()).unwrap();
    assert!(sent.node_name_to_victims.is_none());
    assert_eq!(
        sent.node_name_to_meta_victims.unwrap()["node1"].pods[0].uid,
        "uid1"
    );
}
