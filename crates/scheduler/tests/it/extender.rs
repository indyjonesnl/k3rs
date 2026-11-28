//! Ports of `pkg/scheduler/extender_test.go` `TestIsInterested`, plus checks of
//! the `HTTPExtender` transport (`NewHTTPExtender`, `makeTransport`, `send`)
//! and the config / wire JSON of `config.Extender` and `extender/v1`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kubernetes_rs_common::resources::{Container, Pod, PodSpec};
use kubernetes_rs_common::types::ResourceRequirements;
use kubernetes_rs_scheduler::extender::*;

fn managed(names: &[&str]) -> ExtenderConfig {
    ExtenderConfig {
        url_prefix: "http://127.0.0.1:1".into(),
        managed_resources: names
            .iter()
            .map(|n| ExtenderManagedResource {
                name: (*n).into(),
                ignored_by_scheduler: false,
            })
            .collect(),
        ..Default::default()
    }
}

fn container(req: &[&str], lim: &[&str]) -> Container {
    let m = |names: &[&str]| {
        (!names.is_empty()).then(|| {
            names
                .iter()
                .map(|n| ((*n).to_string(), "0".to_string()))
                .collect::<HashMap<_, _>>()
        })
    };
    let mut c: Container = serde_json::from_str(r#"{"name":"app","image":"i"}"#).unwrap();
    c.resources = Some(ResourceRequirements {
        requests: m(req),
        limits: m(lim),
        claims: None,
    });
    c
}

fn pod(containers: Vec<Container>, init: Vec<Container>) -> Pod {
    let mut p: Pod = serde_json::from_str(r#"{"metadata":{"name":"p"}}"#).unwrap();
    let mut spec: PodSpec = serde_json::from_str(r#"{"containers":[]}"#).unwrap();
    spec.containers = containers;
    spec.init_containers = (!init.is_empty()).then_some(init);
    p.spec = Some(spec);
    p
}

/// extender_test.go:386 TestIsInterested.
#[test]
fn extender_is_interested() {
    let empty = HttpExtender::new(&managed(&[])).unwrap();
    assert!(
        empty.is_interested(&serde_json::from_str(r#"{"metadata":{"name":"p"}}"#).unwrap()),
        "Empty managed resources"
    );

    let mem = HttpExtender::new(&managed(&["memory"])).unwrap();
    // Managed memory, empty resources.
    assert!(!mem.is_interested(&pod(vec![container(&[], &[])], vec![])));
    // container memory with Requests.
    assert!(mem.is_interested(&pod(vec![container(&["memory"], &[])], vec![])));
    // container memory with Limits.
    assert!(mem.is_interested(&pod(vec![container(&[], &["memory"])], vec![])));
    // init container memory.
    assert!(mem.is_interested(&pod(
        vec![container(&[], &[])],
        vec![container(&["memory"], &[])]
    )));
    // An unmanaged resource does not interest it.
    assert!(!mem.is_interested(&pod(vec![container(&["cpu"], &[])], vec![])));
}

#[test]
fn extender_predicates_follow_verbs() {
    let none = HttpExtender::new(&ExtenderConfig::default()).unwrap();
    assert!(!none.is_binder() && !none.is_filter() && !none.is_prioritizer());
    assert!(!none.supports_preemption() && !none.is_ignorable());
    let cfg = ExtenderConfig {
        url_prefix: "http://ext/".into(),
        filter_verb: "filter".into(),
        prioritize_verb: "prio".into(),
        bind_verb: "bind".into(),
        preempt_verb: "preempt".into(),
        ignorable: true,
        ..Default::default()
    };
    let e = HttpExtender::new(&cfg).unwrap();
    assert!(e.is_binder() && e.is_filter() && e.is_prioritizer());
    assert!(e.supports_preemption() && e.is_ignorable());
    // Name is the URL prefix, untrimmed (extender.go:127).
    assert_eq!(e.name(), "http://ext/");
}

/// makeTransport + TLSConfigFor: a CA together with `insecure` is rejected.
#[test]
fn extender_tls_ca_with_insecure_is_rejected() {
    let cfg = ExtenderConfig {
        url_prefix: "https://ext".into(),
        tls_config: Some(ExtenderTlsConfig {
            insecure: true,
            ca_data: b"x".to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = HttpExtender::new(&cfg)
        .err()
        .expect("must fail")
        .to_string();
    assert!(
        err.contains("specifying a root certificates file with the insecure flag is not allowed"),
        "{err}"
    );
}

/// makeTransport: `enableHTTPS` without a CA forces insecure, so it builds
/// (and does not read any CA); with garbage CA data it fails to load roots.
#[test]
fn extender_tls_enable_https_and_bad_ca() {
    let cfg = ExtenderConfig {
        url_prefix: "https://ext".into(),
        enable_https: true,
        ..Default::default()
    };
    HttpExtender::new(&cfg).unwrap();
    let bad = ExtenderConfig {
        url_prefix: "https://ext".into(),
        enable_https: true,
        tls_config: Some(ExtenderTlsConfig {
            ca_data: b"not pem".to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = HttpExtender::new(&bad)
        .err()
        .expect("must fail")
        .to_string();
    assert!(err.contains("unable to load root certificates"), "{err}");
    // A missing CA file is a read error, as in dataFromSliceOrFile.
    let missing = ExtenderConfig {
        url_prefix: "https://ext".into(),
        tls_config: Some(ExtenderTlsConfig {
            ca_file: "/nonexistent/ca.pem".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(HttpExtender::new(&missing).is_err());
}

#[test]
fn extender_config_json_roundtrip() {
    let cfg: ExtenderConfig = serde_json::from_str(
        r#"{"urlPrefix":"https://e/x","filterVerb":"f","weight":3,"enableHTTPS":true,
            "tlsConfig":{"insecure":false,"serverName":"s","caData":"aGVsbG8="},
            "httpTimeout":"1m30s","nodeCacheCapable":true,
            "managedResources":[{"name":"example.com/gpu","ignoredByScheduler":true}],
            "ignorable":true}"#,
    )
    .unwrap();
    assert_eq!(cfg.url_prefix, "https://e/x");
    assert_eq!(cfg.weight, 3);
    assert!(cfg.enable_https && cfg.node_cache_capable && cfg.ignorable);
    assert_eq!(cfg.http_timeout, Some(Duration::from_secs(90)));
    let tls = cfg.tls_config.clone().unwrap();
    assert_eq!(tls.ca_data, b"hello");
    assert_eq!(tls.server_name, "s");
    assert!(cfg.managed_resources[0].ignored_by_scheduler);
    let back: ExtenderConfig = serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
    assert_eq!(back, cfg);
}

#[test]
fn extender_wire_types_use_go_field_names() {
    let args = ExtenderBindingArgs {
        pod_name: "p".into(),
        pod_namespace: "ns".into(),
        pod_uid: "u".into(),
        node: "n1".into(),
    };
    let v = serde_json::to_value(&args).unwrap();
    assert_eq!(v["PodName"], "p");
    assert_eq!(v["PodNamespace"], "ns");
    assert_eq!(v["PodUID"], "u");
    assert_eq!(v["Node"], "n1");
    // A null FailedNodes / NodeNames decodes (Go nil map / slice).
    let r: ExtenderFilterResult =
        serde_json::from_str(r#"{"Nodes":null,"NodeNames":["a"],"FailedNodes":null,"Error":""}"#)
            .unwrap();
    assert_eq!(r.node_names, Some(vec!["a".to_string()]));
    assert!(r.failed_nodes.is_empty());
    // Go decodes case-insensitively; the lower-case spelling is accepted.
    let r: ExtenderFilterResult =
        serde_json::from_str(r#"{"nodenames":["b"],"error":"boom"}"#).unwrap();
    assert_eq!(r.node_names, Some(vec!["b".to_string()]));
    assert_eq!(r.error, "boom");
    let hp: HostPriorityList = serde_json::from_str(r#"[{"Host":"n","Score":7}]"#).unwrap();
    assert_eq!(hp[0].score, 7);
    assert_eq!((MIN_EXTENDER_PRIORITY, MAX_EXTENDER_PRIORITY), (0, 10));
}

/// Serve canned replies from a std listener; records `(path, content-type, body)`.
type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

fn serve(status: u16, reply: &'static str) -> (String, Seen) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for stream in l.incoming() {
            let Ok(mut st) = stream else { return };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                let n = st.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(i + 4);
                }
            };
            let Some(he) = head_end else { continue };
            let head = String::from_utf8_lossy(&buf[..he]).to_string();
            let len: usize = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            while buf.len() < he + len {
                let n = st.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
            let ct = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-type:")
                        .map(|v| v.trim().to_string())
                })
                .unwrap_or_default();
            s2.lock().unwrap().push((
                path,
                ct,
                String::from_utf8_lossy(&buf[he..he + len]).to_string(),
            ));
            let resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            let _ = st.write_all(resp.as_bytes());
        }
    });
    (format!("http://{addr}"), seen)
}

/// extender.go:377 `send`: POST JSON to `<prefix trimmed>/<verb>`.
#[tokio::test]
async fn extender_send_posts_json_and_decodes() {
    let (url, seen) = serve(200, r#"{"Error":"nope"}"#);
    let e = HttpExtender::new(&ExtenderConfig {
        url_prefix: format!("{url}//"),
        ..Default::default()
    })
    .unwrap();
    let args = ExtenderBindingArgs {
        pod_name: "p".into(),
        ..Default::default()
    };
    let res: ExtenderBindingResult = e.send("bind", &args).await.unwrap();
    assert_eq!(res.error, "nope");
    let s = seen.lock().unwrap();
    assert_eq!(s[0].0, "/bind");
    assert_eq!(s[0].1, "application/json");
    assert!(s[0].2.contains(r#""PodName":"p""#), "{}", s[0].2);
}

#[tokio::test]
async fn extender_send_non_200_is_an_error() {
    let (url, _) = serve(500, "{}");
    let e = HttpExtender::new(&ExtenderConfig {
        url_prefix: url.clone(),
        ..Default::default()
    })
    .unwrap();
    let err = e
        .send::<_, ExtenderBindingResult>("filter", &ExtenderBindingArgs::default())
        .await
        .err()
        .unwrap()
        .to_string();
    assert_eq!(
        err,
        format!("failed filter with extender at URL {url}/filter, code 500")
    );
}

/// `HTTPTimeout` bounds the request; zero uses the 5s default.
#[tokio::test]
async fn extender_send_honours_http_timeout() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    // Accept and never reply.
    std::thread::spawn(move || {
        let held: Vec<_> = l.incoming().take(1).collect();
        std::thread::sleep(Duration::from_secs(5));
        drop(held);
    });
    let e = HttpExtender::new(&ExtenderConfig {
        url_prefix: url,
        http_timeout: Some(Duration::from_millis(200)),
        ..Default::default()
    })
    .unwrap();
    let start = std::time::Instant::now();
    let r = e
        .send::<_, ExtenderBindingResult>("bind", &ExtenderBindingArgs::default())
        .await;
    assert!(r.is_err());
    assert!(start.elapsed() < Duration::from_secs(3));
}

fn node(name: &str) -> kubernetes_rs_common::resources::Node {
    serde_json::from_str(&format!(r#"{{"metadata":{{"name":"{name}"}}}}"#)).unwrap()
}

fn ext(url: String, f: impl FnOnce(&mut ExtenderConfig)) -> HttpExtender {
    let mut c = ExtenderConfig {
        url_prefix: url,
        ..Default::default()
    };
    f(&mut c);
    HttpExtender::new(&c).unwrap()
}

/// extender.go:222 Filter: no verb passes everything through, no request.
#[tokio::test]
async fn extender_filter_without_verb_passes_all() {
    let (url, seen) = serve(200, "{}");
    let e = ext(url, |_| {});
    let nodes = vec![node("a"), node("b")];
    let out = e.filter(&pod(vec![], vec![]), &nodes).await.unwrap();
    assert_eq!(out.filtered.len(), 2);
    assert!(out.failed_nodes.is_empty());
    assert!(seen.lock().unwrap().is_empty());
}

/// Filter, not nodeCacheCapable: full NodeList is sent, returned Nodes win.
#[tokio::test]
async fn extender_filter_node_list() {
    let (url, seen) = serve(
        200,
        r#"{"Nodes":{"items":[{"metadata":{"name":"b"}}]},"FailedNodes":{"a":"no"},"FailedAndUnresolvableNodes":{"c":"never"}}"#,
    );
    let e = ext(url, |c| c.filter_verb = "filter".into());
    let nodes = vec![node("a"), node("b")];
    let out = e.filter(&pod(vec![], vec![]), &nodes).await.unwrap();
    assert_eq!(out.filtered.len(), 1);
    assert_eq!(out.filtered[0].metadata.name, "b");
    assert_eq!(out.failed_nodes["a"], "no");
    assert_eq!(out.failed_and_unresolvable_nodes["c"], "never");
    let body: serde_json::Value = serde_json::from_str(&seen.lock().unwrap()[0].2).unwrap();
    assert_eq!(body["Nodes"]["items"].as_array().unwrap().len(), 2);
    assert!(body["NodeNames"].is_null());
}

/// Filter, nodeCacheCapable: names are sent and resolved against the input.
#[tokio::test]
async fn extender_filter_node_names() {
    let (url, seen) = serve(200, r#"{"NodeNames":["b"]}"#);
    let e = ext(url, |c| {
        c.filter_verb = "filter".into();
        c.node_cache_capable = true;
    });
    let nodes = vec![node("a"), node("b")];
    let out = e.filter(&pod(vec![], vec![]), &nodes).await.unwrap();
    assert_eq!(out.filtered.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&seen.lock().unwrap()[0].2).unwrap();
    assert_eq!(body["NodeNames"], serde_json::json!(["a", "b"]));
    assert!(body["Nodes"].is_null());

    let (url, _) = serve(200, r#"{"NodeNames":["zzz"]}"#);
    let e = ext(url.clone(), |c| {
        c.filter_verb = "filter".into();
        c.node_cache_capable = true;
    });
    let err = e.filter(&pod(vec![], vec![]), &nodes).await.err().unwrap();
    assert_eq!(
        err.to_string(),
        format!(
            "extender {:?} claims a filtered node \"zzz\" which is not found in the input node list",
            url
        )
    );
}

#[tokio::test]
async fn extender_filter_error_field_is_an_error() {
    let (url, _) = serve(200, r#"{"Error":"boom"}"#);
    let e = ext(url, |c| c.filter_verb = "filter".into());
    let err = e
        .filter(&pod(vec![], vec![]), &[node("a")])
        .await
        .err()
        .unwrap();
    assert_eq!(err.to_string(), "boom");
}

/// extender.go:305 Prioritize.
#[tokio::test]
async fn extender_prioritize() {
    let nodes = vec![node("a"), node("b")];
    // No verb: zero scores, weight 0.
    let e = ext("http://127.0.0.1:1".into(), |c| c.weight = 5);
    let (list, w) = e.prioritize(&pod(vec![], vec![]), &nodes).await.unwrap();
    assert_eq!((list.len(), w), (2, 0));
    assert!(list.iter().all(|h| h.score == 0));
    // With a verb: reply and configured weight.
    let (url, _) = serve(200, r#"[{"Host":"a","Score":3},{"Host":"b","Score":9}]"#);
    let e = ext(url, |c| {
        c.prioritize_verb = "prio".into();
        c.weight = 5;
    });
    let (list, w) = e.prioritize(&pod(vec![], vec![]), &nodes).await.unwrap();
    assert_eq!(w, 5);
    assert_eq!((list[0].host.as_str(), list[1].score), ("a", 9));
}
