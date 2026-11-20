//! A failed RestoreAll returns before Healthz.Updated in upstream
//! pkg/proxy/iptables/proxier.go:1497-1506,1521-1522. Retrying identical state
//! must attempt the dataplane again rather than reporting a cached success.
use super::*;
use k3rs_storage::memory::MemoryStorage;
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn failed_sync_is_not_cached() {
    if std::env::var_os("K3RS_TEST_SYNC_FAILURE").is_none() {
        // Run in a child so PATH isolation cannot affect other tests. Both
        // binaries are failing scripts: this test never invokes host iptables.
        let directory = std::env::temp_dir().join(format!("k3rs-3477-sync-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        for binary in ["iptables", "iptables-restore"] {
            let path = directory.join(binary);
            std::fs::write(&path, "#!/bin/sh\nexit 1\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "proxy::failure_tests::failed_sync_is_not_cached",
                "--nocapture",
            ])
            .env("K3RS_TEST_SYNC_FAILURE", "1")
            .env("PATH", &directory)
            .status()
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        assert!(status.success());
        return;
    }
    let storage = Arc::new(MemoryStorage::new());
    let service: Service = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": "s", "namespace": "default"},
        "spec": {"clusterIP": "10.96.0.1", "ports": [{"port": 80}]}
    }))
    .unwrap();
    storage
        .create("/registry/services/default/s", &service)
        .await
        .unwrap();
    let mut proxy = KubeProxy {
        storage,
        iptables: IptablesManager::for_testing(false), // skips initialization/sysctls
        node_name: "n".into(),
        last_sync_hash: 0,
        service_health_server: None,
        host_ports: true,
    };
    assert!(
        proxy.sync().await.is_err(),
        "first failed apply must fail sync"
    );
    assert!(
        proxy.sync().await.is_err(),
        "failed state must never become a cached successful sync"
    );
}

/// Storage that counts (and refuses, as a 403 would) every Pod list, and
/// delegates everything else to a [`MemoryStorage`].
struct PodListCounter {
    inner: MemoryStorage,
    pod_lists: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Storage for PodListCounter {
    async fn create<T>(&self, key: &str, value: &T) -> k3rs_common::Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
    {
        self.inner.create(key, value).await
    }
    async fn get<T>(&self, key: &str) -> k3rs_common::Result<T>
    where
        T: serde::de::DeserializeOwned + Send + Sync,
    {
        self.inner.get(key).await
    }
    async fn update<T>(&self, key: &str, value: &T) -> k3rs_common::Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
    {
        self.inner.update(key, value).await
    }
    async fn update_raw(&self, key: &str, value: &serde_json::Value) -> k3rs_common::Result<()> {
        self.inner.update_raw(key, value).await
    }
    async fn delete(&self, key: &str) -> k3rs_common::Result<()> {
        self.inner.delete(key).await
    }
    async fn list<T>(&self, prefix: &str) -> k3rs_common::Result<Vec<T>>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
    {
        if prefix.starts_with("/registry/pods/") {
            self.pod_lists
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Err(k3rs_common::Error::Forbidden(
                "pods is forbidden: User \"system:kube-proxy\" cannot list resource \"pods\""
                    .into(),
            ));
        }
        self.inner.list(prefix).await
    }
    async fn watch(&self, prefix: &str) -> k3rs_common::Result<k3rs_storage::WatchStream> {
        self.inner.watch(prefix).await
    }
    async fn watch_from_revision(
        &self,
        prefix: &str,
        revision: i64,
    ) -> k3rs_common::Result<k3rs_storage::WatchStream> {
        self.inner.watch_from_revision(prefix, revision).await
    }
    async fn current_revision(&self) -> k3rs_common::Result<i64> {
        self.inner.current_revision().await
    }
    async fn is_revision_compacted(&self, revision: i64) -> k3rs_common::Result<bool> {
        self.inner.is_revision_compacted(revision).await
    }
}

/// Run `test` in a child whose PATH holds only no-op `iptables` /
/// `iptables-restore` scripts (exit 0), so a sync reaches its end without
/// touching host iptables. Returns false in the parent (the caller returns).
fn in_noop_iptables_child(test: &str) -> bool {
    if std::env::var_os("K3RS_TEST_NOOP_IPTABLES").is_some() {
        return true;
    }
    let directory = std::env::temp_dir().join(format!(
        "k3rs-hostports-{}-{}",
        std::process::id(),
        test.rsplit("::").next().unwrap()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    for binary in ["iptables", "iptables-restore"] {
        let path = directory.join(binary);
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("K3RS_TEST_NOOP_IPTABLES", "1")
        .env("PATH", &directory)
        .status()
        .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(status.success(), "{test} failed in the child");
    false
}

fn counting_proxy(host_ports: bool) -> KubeProxy<PodListCounter> {
    KubeProxy {
        storage: Arc::new(PodListCounter {
            inner: MemoryStorage::new(),
            pod_lists: Default::default(),
        }),
        iptables: IptablesManager::for_testing(false),
        node_name: "n".into(),
        last_sync_hash: 0,
        service_health_server: None,
        host_ports,
    }
}

/// k3rs server/agent (`host_ports=false`): the sync never lists Pods, so a
/// Pod list the identity may not make (403 here) cannot fail or slow it.
#[tokio::test]
async fn host_ports_off_never_lists_pods() {
    if !in_noop_iptables_child("proxy::failure_tests::host_ports_off_never_lists_pods") {
        return;
    }
    let mut proxy = counting_proxy(false);
    let _ = proxy.sync().await;
    let _ = proxy.sync().await;
    assert_eq!(
        proxy
            .storage
            .pod_lists
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

/// The default (standalone kube-proxy, bare all-in-one) still lists Pods for
/// KUBE-HOSTPORTS on every sync, exactly as before.
#[tokio::test]
async fn host_ports_default_still_lists_pods() {
    assert!(crate::KubeProxyConfig::default().host_ports);
    if !in_noop_iptables_child("proxy::failure_tests::host_ports_default_still_lists_pods") {
        return;
    }
    let mut proxy = counting_proxy(true);
    let _ = proxy.sync().await;
    assert!(
        proxy
            .storage
            .pod_lists
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1
    );
}
