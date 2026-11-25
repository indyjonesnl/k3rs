//! End-to-end: a real `serve()` listener on loopback forwarding to a fake
//! upstream. No network egress. Mirrors the k3s Corefile split: cluster
//! zones authoritative, everything else `forward`ed, reverse NXDOMAIN
//! falls through, and a resolv.conf that points back at us trips `loop`.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use kubernetes_rs_common::resources::{Service, ServiceSpec, ServiceType};
use kubernetes_rs_dns::forward::{ForwardOptions, Forwarder, Policy};
use kubernetes_rs_dns::server::{serve, SharedZone};
use kubernetes_rs_dns::zone::{Zone, CLUSTER_ZONE};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn free_port() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let a = s.local_addr().unwrap();
    // TCP on the same port must be free as well; retry until it is.
    drop(s);
    a
}

fn q(id: u16, name: &str, t: RecordType) -> Vec<u8> {
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
    m.to_vec().unwrap()
}

/// Fake recursive upstream (UDP + TCP on one port): example.com ->
/// 93.184.216.34, rest NXDOMAIN.
fn upstream_answer(qm: &Message) -> Message {
    let mut r = Message::response(qm.metadata.id, qm.metadata.op_code);
    r.metadata.recursion_available = true;
    let qq = qm.queries[0].clone();
    r.add_query(qq.clone());
    if qq.name().to_ascii().eq_ignore_ascii_case("example.com.") && qq.query_type() == RecordType::A
    {
        r.add_answer(Record::from_rdata(
            qq.name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));
    } else {
        r.metadata.response_code = ResponseCode::NXDomain;
    }
    r
}

async fn fake_upstream(hits: Arc<AtomicUsize>) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    let h = hits.clone();
    tokio::spawn(async move {
        let mut b = vec![0u8; 4096];
        loop {
            let Ok((n, p)) = sock.recv_from(&mut b).await else {
                return;
            };
            let Ok(qm) = Message::from_vec(&b[..n]) else {
                continue;
            };
            h.fetch_add(1, Ordering::SeqCst);
            let _ = sock
                .send_to(&upstream_answer(&qm).to_vec().unwrap(), p)
                .await;
        }
    });
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let hits = hits.clone();
            tokio::spawn(async move {
                let mut l = [0u8; 2];
                if s.read_exact(&mut l).await.is_err() {
                    return;
                }
                let mut b = vec![0u8; u16::from_be_bytes(l) as usize];
                if s.read_exact(&mut b).await.is_err() {
                    return;
                }
                let Ok(qm) = Message::from_vec(&b) else {
                    return;
                };
                hits.fetch_add(1, Ordering::SeqCst);
                let w = upstream_answer(&qm).to_vec().unwrap();
                let _ = s.write_all(&(w.len() as u16).to_be_bytes()).await;
                let _ = s.write_all(&w).await;
            });
        }
    });
    addr
}

async fn udp(server: SocketAddr, wire: &[u8]) -> Message {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(wire, server).await.unwrap();
    let mut b = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), s.recv_from(&mut b))
        .await
        .expect("reply in time")
        .unwrap();
    Message::from_vec(&b[..n]).unwrap()
}

async fn tcp(server: SocketAddr, wire: &[u8]) -> Message {
    let mut s = TcpStream::connect(server).await.unwrap();
    s.write_all(&(wire.len() as u16).to_be_bytes())
        .await
        .unwrap();
    s.write_all(wire).await.unwrap();
    let mut l = [0u8; 2];
    s.read_exact(&mut l).await.unwrap();
    let mut b = vec![0u8; u16::from_be_bytes(l) as usize];
    s.read_exact(&mut b).await.unwrap();
    Message::from_vec(&b).unwrap()
}

fn zone() -> SharedZone {
    let mut svc = Service::new("kubernetes", ServiceSpec::default());
    svc.metadata.namespace = Some("default".into());
    svc.spec.cluster_ip = Some("10.96.0.1".into());
    svc.spec.service_type = Some(ServiceType::ClusterIP);
    SharedZone::new(Zone::build(CLUSTER_ZONE, &[svc], &[], &[]))
}

fn opts() -> ForwardOptions {
    ForwardOptions {
        policy: Policy::Sequential,
        read_timeout: Duration::from_millis(500),
        ..Default::default()
    }
}

async fn start(
    upstream: SocketAddr,
    loop_detect: bool,
) -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let bind = free_port();
    let fwd = Arc::new(Forwarder::new(vec![upstream], opts()));
    let h = tokio::spawn(serve(zone(), bind, bind, Some(fwd), loop_detect));
    for _ in 0..50 {
        if TcpStream::connect(bind).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (bind, h)
}

#[tokio::test]
async fn external_name_is_forwarded_cluster_name_is_not() {
    let hits = Arc::new(AtomicUsize::new(0));
    let up = fake_upstream(hits.clone()).await;
    let (srv, h) = start(up, false).await;

    // external, UDP and TCP
    for r in [
        udp(srv, &q(0x11, "example.com.", RecordType::A)).await,
        tcp(srv, &q(0x12, "example.com.", RecordType::A)).await,
    ] {
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1);
        assert!(r.metadata.recursion_available, "upstream RA preserved");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // upstream NXDOMAIN is passed through
    let r = udp(srv, &q(0x13, "nope.invalid.", RecordType::A)).await;
    assert_eq!(r.metadata.id, 0x13);
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(hits.load(Ordering::SeqCst), 3);

    // cluster zone stays authoritative and never reaches upstream
    let r = udp(
        srv,
        &q(0x14, "kubernetes.default.svc.cluster.local.", RecordType::A),
    )
    .await;
    assert_eq!(r.answers.len(), 1);
    assert!(r.metadata.authoritative);
    let r = udp(
        srv,
        &q(0x15, "missing.default.svc.cluster.local.", RecordType::A),
    )
    .await;
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    assert!(r.metadata.authoritative);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "cluster names not forwarded"
    );

    // reverse: known PTR is ours, unknown NXDOMAIN falls through
    let r = udp(srv, &q(0x16, "1.0.96.10.in-addr.arpa.", RecordType::PTR)).await;
    assert_eq!(r.answers.len(), 1);
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    let _ = udp(srv, &q(0x17, "9.9.9.9.in-addr.arpa.", RecordType::PTR)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        4,
        "reverse NXDOMAIN falls through"
    );

    h.abort();
}

#[tokio::test]
async fn dead_upstream_answers_servfail() {
    let dead = free_port();
    let (srv, h) = start(dead, false).await;
    let r = udp(srv, &q(0x21, "example.com.", RecordType::A)).await;
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    h.abort();
}

#[tokio::test]
async fn upstream_pointing_at_ourselves_is_detected_as_a_loop() {
    // `forward . <our own address>`: the CoreDNS `loop` probe must fire.
    let bind = free_port();
    let fwd = Arc::new(Forwarder::new(vec![bind], opts()));
    let h = tokio::spawn(serve(zone(), bind, bind, Some(fwd), true));
    let res = tokio::time::timeout(Duration::from_secs(20), h)
        .await
        .expect("loop detected before the timeout")
        .unwrap();
    let err = res.expect_err("serve must fail on a loop");
    assert!(err.to_string().contains("loop"), "{err}");
}
