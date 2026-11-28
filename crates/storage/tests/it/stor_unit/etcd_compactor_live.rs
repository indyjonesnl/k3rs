//! `TestCompact` / `TestCompactConflict` (`etcd3/compact_test.go`) against a
//! real etcd instead of the fake in `etcd_compactor.rs`. Soft-skips when
//! Docker is unavailable, like the other live-etcd tests in `etcd.rs`.
use kubernetes_rs_storage::etcd_compactor::*;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt, TestcontainersError,
};

async fn start() -> Option<(ContainerAsync<GenericImage>, EtcdCompactBackend)> {
    let result = GenericImage::new("quay.io/coreos/etcd", "v3.5.17")
        .with_exposed_port(2379.tcp())
        .with_wait_for(WaitFor::message_on_stderr("ready to serve client requests"))
        .with_cmd([
            "/usr/local/bin/etcd",
            "--name=etcd-test",
            "--data-dir=/etcd-data",
            "--listen-client-urls=http://0.0.0.0:2379",
            "--advertise-client-urls=http://0.0.0.0:2379",
        ])
        .start()
        .await;
    let c = match result {
        Ok(c) => c,
        Err(TestcontainersError::Client(testcontainers::core::client::ClientError::Init(e))) => {
            eprintln!("skipping live etcd compactor test: Docker unavailable ({e})");
            return None;
        }
        Err(e) => panic!("failed to start etcd test container: {e}"),
    };
    let host = c.get_host().await.expect("host");
    let port = c.get_host_port_ipv4(2379).await.expect("port");
    let ep = format!("http://{host}:{port}");
    let client = etcd_client::Client::connect([ep.clone()], None)
        .await
        .expect("connect");
    Some((c, EtcdCompactBackend::new(client, vec![ep])))
}

/// compact_test.go TestCompact: the first compaction wins the CAS and compacts
/// to the given revision; one sharing the compact_rev_key (lost CAS) is not an
/// error, does not compact again, and reports the winner's revision.
#[tokio::test]
async fn etcd_compactor_live_compact_and_conflict() {
    let Some((_c, backend)) = start().await else {
        return;
    };
    // Bootstrap (rev 0): CAS succeeds, version 1, no compaction.
    let out = compact(&backend, 0, 0).await;
    assert_eq!(out.err, None);
    assert_eq!(out.current_version, 1);
    assert_eq!(out.compact_rev, 0);
    let rev = out.current_rev;
    assert!(rev > 0);

    // Second compactor, same view of the key version: wins and compacts.
    let out = compact(&backend, 1, rev).await;
    assert_eq!(out.err, None);
    assert_eq!(out.current_version, 2);
    assert_eq!(out.compact_rev, rev);
    let (val, _) = backend.get_compact_key().await.unwrap();
    assert_eq!(val.as_deref(), Some(rev.to_string().as_bytes()));

    // A compactor with a stale version loses the CAS: no error, reports the
    // winner's version and compact revision, no compaction by itself.
    let out = compact(&backend, 1, rev).await;
    assert_eq!(out.err, None);
    assert_eq!(out.current_version, 2);
    assert_eq!(out.compact_rev, rev);
}
