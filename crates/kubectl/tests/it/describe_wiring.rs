//! Wiring of `kubectl describe` (`pkg/cmd/describe/describe.go`
//! `DescribeFlags` / `DescriberSettings`): `--show-events` (default true) and
//! `--chunk-size` (default `cmdutil.DefaultChunkSize` = 500) reach the events
//! search, kinds without a dedicated describer use the generic describer
//! (`GenericDescriberFor`), and typed describers get the events block.
//! Driven against an in-process API server.

use kubernetes_rs_client::http::ApiClient;
use kubernetes_rs_kubectl::commands::describe::{
    describe_generic_to_string, events_block, DescriberSettings,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

struct Mock {
    url: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Mock {
    fn paths(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
    fn client(&self) -> ApiClient {
        ApiClient::new(&self.url, false, None).unwrap()
    }
    fn event_requests(&self) -> Vec<String> {
        self.paths()
            .into_iter()
            .filter(|p| p.contains("/events"))
            .collect()
    }
}

fn route(pq: &str) -> Value {
    let path = pq.split('?').next().unwrap();
    match path {
        "/api" => json!({"apiVersion": "apidiscovery.k8s.io/v2", "kind": "APIGroupDiscoveryList",
            "items": [{"metadata": {"name": ""}, "versions": [{"version": "v1", "freshness": "Current",
              "resources": [{"resource": "configmaps", "scope": "Namespaced",
                "responseKind": {"group": "", "version": "v1", "kind": "ConfigMap"},
                "singularResource": "configmap", "verbs": ["get", "list"]}]}]}]}),
        "/apis" => {
            json!({"apiVersion": "apidiscovery.k8s.io/v2", "kind": "APIGroupDiscoveryList", "items": []})
        }
        "/api/v1/namespaces/ns/configmaps/cm1" => json!({"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "cm1", "namespace": "ns", "uid": "u1"}, "data": {"k": "v"}}),
        "/api/v1/namespaces/ns/events" => {
            json!({"kind": "EventList", "apiVersion": "v1", "metadata": {},
            "items": [{"apiVersion": "v1", "kind": "Event",
              "metadata": {"name": "e1", "namespace": "ns"},
              "involvedObject": {"kind": "ConfigMap", "name": "cm1", "namespace": "ns"},
              "type": "Normal", "reason": "Synced", "message": "all good", "count": 1,
              "source": {"component": "ctl"},
              "firstTimestamp": "2024-01-01T00:00:00Z", "lastTimestamp": "2024-01-01T00:00:00Z"}]})
        }
        _ => {
            json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 404, "reason": "NotFound"})
        }
    }
}

async fn start() -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let seen = seen2.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let seen = seen.clone();
                    async move {
                        let pq = req
                            .uri()
                            .path_and_query()
                            .map(|p| p.to_string())
                            .unwrap_or_default();
                        let _ = req.into_body().collect().await;
                        seen.lock().unwrap().push(pq.clone());
                        let v = route(&pq);
                        let code = if v["kind"] == "Status" { 404 } else { 200 };
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(code)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(v.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Mock { url, seen }
}

#[test]
fn describe_wiring_settings_defaults() {
    let s = DescriberSettings::default();
    assert!(s.show_events);
    assert_eq!(s.chunk_size, 500);
}

#[tokio::test]
async fn describe_wiring_generic_fallback_shows_events_with_default_chunk() {
    let m = start().await;
    let out = describe_generic_to_string(
        &m.client(),
        "configmaps",
        "cm1",
        Some("ns"),
        DescriberSettings::default(),
    )
    .await
    .unwrap();
    assert!(out.contains("cm1"), "{out}");
    assert!(out.contains("Events:"), "{out}");
    assert!(out.contains("Synced") && out.contains("all good"), "{out}");
    let ev = m.event_requests();
    assert_eq!(ev.len(), 1);
    assert!(ev[0].contains("limit=500"), "{}", ev[0]);
    assert!(
        ev[0].contains("involvedObject.name%3Dcm1") || ev[0].contains("involvedObject.name=cm1"),
        "{}",
        ev[0]
    );
}

#[tokio::test]
async fn describe_wiring_chunk_size_reaches_the_events_search() {
    let m = start().await;
    let settings = DescriberSettings {
        show_events: true,
        chunk_size: 7,
    };
    describe_generic_to_string(&m.client(), "configmaps", "cm1", Some("ns"), settings)
        .await
        .unwrap();
    assert!(
        m.event_requests()[0].contains("limit=7"),
        "{:?}",
        m.event_requests()
    );
}

#[tokio::test]
async fn describe_wiring_show_events_false_skips_the_search() {
    let m = start().await;
    let settings = DescriberSettings {
        show_events: false,
        chunk_size: 500,
    };
    let out = describe_generic_to_string(&m.client(), "configmaps", "cm1", Some("ns"), settings)
        .await
        .unwrap();
    assert!(!out.contains("Events"), "{out}");
    assert!(m.event_requests().is_empty());
}

#[tokio::test]
async fn describe_wiring_unknown_kind_is_an_error() {
    let m = start().await;
    let err = describe_generic_to_string(
        &m.client(),
        "bogus",
        "x",
        Some("ns"),
        DescriberSettings::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "the server doesn't have a resource type \"bogus\""
    );
}

#[tokio::test]
async fn describe_wiring_typed_describers_get_an_events_block() {
    let m = start().await;
    let pod = json!({"apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "cm1", "namespace": "ns", "uid": "u1"}, "spec": {"containers": []}});
    let block = events_block(&m.client(), "Pod", &pod, DescriberSettings::default()).await;
    assert!(block.contains("Events:"), "{block}");
    assert!(
        m.event_requests()[0].contains("involvedObject.kind"),
        "{:?}",
        m.event_requests()
    );
    // Not requested: nothing printed, nothing fetched.
    let m2 = start().await;
    let off = DescriberSettings {
        show_events: false,
        chunk_size: 500,
    };
    assert_eq!(events_block(&m2.client(), "Pod", &pod, off).await, "");
    assert!(m2.event_requests().is_empty());
    // Typed objects without TypeMeta get the kind filled in.
    let bare = json!({"metadata": {"name": "cm1", "namespace": "ns"}});
    events_block(&m2.client(), "Node", &bare, DescriberSettings::default()).await;
    assert!(
        m2.event_requests()[0].contains("involvedObject.kind"),
        "{:?}",
        m2.event_requests()
    );
}
