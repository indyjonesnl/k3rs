//! User namespace manager: allocation and persistence of the per-pod ID range
//! used when a pod sets `spec.hostUsers: false`.
//!
//! Port of `pkg/kubelet/userns/userns_manager.go` (release-1.35):
//! `MakeUserNsManager`, `allocateOne`, `record`, `Release`,
//! `parseUserNsFileAndRecord`, `createUserNs`, `GetOrCreateUserNamespaceMappings`
//! and `CleanupOrphanedPodUsernsAllocations`, plus `parseGetSubIdsOutput` and the
//! default mapping of `Kubelet.getKubeletMappings` (`pkg/kubelet/kubelet_pods.go:95-130`).
//! The interface it needs from the kubelet is `userNsPodsManager`
//! (`pkg/kubelet/userns/types.go`).
//!
//! Deliberate deviations (Rust expression, not mechanism):
//! * `utilfeature.DefaultFeatureGate.Enabled(UserNamespacesSupport)` is an
//!   explicit `feature_enabled` constructor argument (the process-wide gate cannot
//!   be flipped per test); [`user_namespaces_support_enabled`] reads the real gate.
//! * `allocator.AllocationBitmap` (`pkg/registry/core/service/allocator/bitmap.go`,
//!   random-scan strategy) is a small local bitmap; it lives in the api-server crate.
//! * `utilstore.FileStore` is `read_mappings_file`/`write_mappings_file`: temp file
//!   in the pod dir, fsync, rename, fsync of the parent dir.
//! * Not ported here: the `getsubids` exec half of `getKubeletMappings` (wiring).

use kubernetes_rs_cri::v1;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// `mapReInitializeThreshold`.
const MAP_REINITIALIZE_THRESHOLD: usize = 1000;
/// `userNsUnitLength`.
const USER_NS_UNIT_LENGTH: u32 = 65536;
/// `kubeletconfig.DefaultKubeletUserNamespacesIDsPerPod`.
pub const DEFAULT_KUBELET_USER_NAMESPACES_IDS_PER_POD: u32 = 65536;
/// `mappingsFile`: the file the mappings are persisted to, in the pod dir.
const MAPPINGS_FILE: &str = "userns";

/// `features.UserNamespacesSupport`.
pub fn user_namespaces_support_enabled() -> bool {
    kubernetes_rs_common::feature_gates::gate_enabled("UserNamespacesSupport").unwrap_or(false)
}

/// `userNsPodsManager` (`pkg/kubelet/userns/types.go`).
pub trait UserNsPodsManager: Send + Sync {
    fn handler_supports_user_namespaces(&self, runtime_handler: &str) -> Result<bool, String>;
    fn get_pod_dir(&self, pod_uid: &str) -> PathBuf;
    fn list_pods_from_disk(&self) -> std::io::Result<Vec<String>>;
    fn get_kubelet_mappings(&self, ids_per_pod: u32) -> Result<(u32, u32), String>;
    fn get_max_pods(&self) -> usize;
}

/// `idMapping`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdMapping {
    pub host_id: u32,
    pub container_id: u32,
    pub length: u32,
}

/// `userNamespace`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserNamespace {
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,
}

/// `parseGetSubIdsOutput` (`kubelet_pods.go:95-123`): the single
/// `0: kubelet 65536 2147483648` line of `getsubids`, as (first ID, length).
pub fn parse_get_sub_ids_output(input: &str) -> Result<(u32, u32), String> {
    let lines: Vec<&str> = input.trim_matches('\n').split('\n').collect();
    if lines.len() != 1 {
        return Err(format!(
            "error parsing line {input:?}: it must contain only one line"
        ));
    }
    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    if parts.len() != 4 {
        return Err(format!("invalid line {input:?}"));
    }
    let parse = |s: &str| {
        s.parse::<u32>()
            .map_err(|e| format!("error parsing line {input:?}: {e}"))
    };
    Ok((parse(parts[2])?, parse(parts[3])?))
}

/// The default mapping of `getKubeletMappings` (`kubelet_pods.go:130-140`): the
/// whole ID range except the IDs below `ids_per_pod`. Returned when the gate is
/// off, the kubelet user is unknown, or `getsubids` is absent.
pub fn default_kubelet_mappings(ids_per_pod: u32) -> (u32, u32) {
    (ids_per_pod, ((1u64 << 32) - ids_per_pod as u64) as u32)
}

/// `allocator.AllocationBitmap` with the random-scan strategy
/// (`bitmap.go:63-127`, `randomScanStrategy` `:206-225`).
struct Bitmap {
    allocated: Vec<bool>,
    count: usize,
}

impl Bitmap {
    fn new(max: usize) -> Self {
        Self {
            allocated: vec![false; max],
            count: 0,
        }
    }
    fn has(&self, i: usize) -> bool {
        self.allocated.get(i).copied().unwrap_or(false)
    }
    fn allocate_next(&mut self) -> Option<usize> {
        let max = self.allocated.len();
        if self.count >= max {
            return None;
        }
        let offset = rand::rng().random_range(0..max);
        for i in 0..max {
            let at = (offset + i) % max;
            if !self.allocated[at] {
                self.allocated[at] = true;
                self.count += 1;
                return Some(at);
            }
        }
        None
    }
    /// `Allocate`: false when already set.
    fn allocate(&mut self, i: usize) -> bool {
        if i >= self.allocated.len() || self.allocated[i] {
            return false;
        }
        self.allocated[i] = true;
        self.count += 1;
        true
    }
    fn release(&mut self, i: usize) {
        if i < self.allocated.len() && self.allocated[i] {
            self.allocated[i] = false;
            self.count -= 1;
        }
    }
}

struct Inner {
    used: Bitmap,
    /// pod UID -> first host ID of its range.
    used_by: HashMap<String, u32>,
    removed: usize,
}

/// `UsernsManager`.
pub struct UsernsManager {
    off: i64,
    len: i64,
    user_ns_length: u32,
    feature_enabled: bool,
    kl: Arc<dyn UserNsPodsManager>,
    inner: Mutex<Inner>,
}

impl UsernsManager {
    /// `MakeUserNsManager`. `Ok(None)` when the feature is disabled.
    pub fn make(
        kl: Arc<dyn UserNsPodsManager>,
        ids_per_pod: Option<i64>,
        feature_enabled: bool,
    ) -> Result<Option<Self>, String> {
        if !feature_enabled {
            return Ok(None);
        }
        let user_ns_length = ids_per_pod
            .map(|v| v as u32)
            .unwrap_or(DEFAULT_KUBELET_USER_NAMESPACES_IDS_PER_POD);
        let (id, mapping_len) = kl
            .get_kubelet_mappings(user_ns_length)
            .map_err(|e| format!("kubelet mappings: {e}"))?;

        if !user_ns_length.is_multiple_of(USER_NS_UNIT_LENGTH) {
            return Err(format!(
                "kubelet user namespace length {user_ns_length} is not a multiple of {USER_NS_UNIT_LENGTH}"
            ));
        }
        if !id.is_multiple_of(user_ns_length) {
            return Err(format!(
                "kubelet user assigned ID {id} is not a multiple of {user_ns_length}"
            ));
        }
        if id < user_ns_length {
            // We don't allow to map 0, as security is circumvented.
            return Err(format!(
                "kubelet user assigned ID {id} must be greater or equal to {user_ns_length}"
            ));
        }
        if !mapping_len.is_multiple_of(user_ns_length) {
            return Err(format!(
                "kubelet user assigned IDs length {mapping_len} is not a multiple of {user_ns_length}"
            ));
        }
        if ((mapping_len / user_ns_length) as usize) < kl.get_max_pods() {
            return Err(format!(
                "kubelet user assigned IDs are not enough to support {} pods",
                kl.get_max_pods()
            ));
        }
        let off = (id / user_ns_length) as i64;
        let len = (mapping_len / user_ns_length) as i64;
        tracing::trace!(
            offset = off,
            length = len,
            ids_per_pod = user_ns_length,
            "User namespace manager mapping"
        );

        let m = Self {
            off,
            len,
            user_ns_length,
            feature_enabled,
            kl: kl.clone(),
            inner: Mutex::new(Inner {
                used: Bitmap::new(len as usize),
                used_by: HashMap::new(),
                removed: 0,
            }),
        };
        let found = match kl.list_pods_from_disk() {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Some(m)),
            Err(e) => return Err(format!("read pods from disk: {e}")),
        };
        for pod in found {
            m.record_pod_mappings(&pod)
                .map_err(|e| format!("record pod mappings for existing pod {pod:?}: {e}"))?;
        }
        Ok(Some(m))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `writeMappingsToFile`: atomic write, then fsync of the parent dir.
    fn write_mappings_file(&self, pod: &str, user_ns: &UserNamespace) -> Result<(), String> {
        let dir = self.kl.get_pod_dir(pod);
        let data = serde_json::to_vec(user_ns).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&dir).map_err(|e| format!("create user namespace store: {e}"))?;
        let mut tmp = tempfile_in(&dir).map_err(|e| e.to_string())?;
        let res = (|| -> std::io::Result<()> {
            tmp.0.write_all(&data)?;
            tmp.0.sync_all()?;
            std::fs::rename(&tmp.1, dir.join(MAPPINGS_FILE))
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp.1);
        }
        res.map_err(|e| e.to_string())?;
        std::fs::File::open(&dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())
    }

    /// `readMappingsFromFile`: `Ok(None)` is `utilstore.ErrKeyNotFound`.
    fn read_mappings_file(&self, pod: &str) -> Result<Option<Vec<u8>>, String> {
        let dir = self.kl.get_pod_dir(pod);
        std::fs::create_dir_all(&dir).map_err(|e| format!("create user namespace store: {e}"))?;
        match std::fs::read(dir.join(MAPPINGS_FILE)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// `recordPodMappings`.
    fn record_pod_mappings(&self, pod: &str) -> Result<(), String> {
        match self.read_mappings_file(pod)? {
            Some(c) if !c.is_empty() => {
                let mut g = self.lock();
                self.parse_and_record_locked(&mut g, pod, &c).map(|_| ())
            }
            _ => Ok(()),
        }
    }

    fn index(&self, from: u32) -> i64 {
        (from / self.user_ns_length) as i64 - self.off
    }

    /// `isSet`: out-of-range counts as set.
    pub fn is_set(&self, v: u32) -> bool {
        let index = self.index(v);
        if index < 0 || index >= self.len {
            return true;
        }
        self.lock().used.has(index as usize)
    }

    /// `allocateOne`: (first ID, length).
    pub fn allocate_one(&self, pod: &str) -> Result<(u32, u32), String> {
        self.allocate_one_locked(&mut self.lock(), pod)
    }

    fn allocate_one_locked(&self, g: &mut Inner, pod: &str) -> Result<(u32, u32), String> {
        let first_zero = g.used.allocate_next().ok_or_else(|| {
            "could not find an empty slot to allocate a user namespace".to_string()
        })?;
        let first_id = (first_zero as i64 + self.off) as u32 * self.user_ns_length;
        g.used_by.insert(pod.to_string(), first_id);
        Ok((first_id, self.user_ns_length))
    }

    /// `record`: stores the user namespace [from; from+length] for the pod.
    pub fn record(&self, pod: &str, from: u32, length: u32) -> Result<(), String> {
        self.record_locked(&mut self.lock(), pod, from, length)
    }

    fn record_locked(
        &self,
        g: &mut Inner,
        pod: &str,
        from: u32,
        length: u32,
    ) -> Result<(), String> {
        if length != self.user_ns_length {
            return Err(format!("wrong user namespace length {length}"));
        }
        if !from.is_multiple_of(self.user_ns_length) {
            return Err(format!("wrong user namespace offset specified {from}"));
        }
        let prev = g.used_by.get(pod).copied();
        if let Some(p) = prev {
            if p != from {
                return Err(format!(
                    "different user namespace range already used by pod {pod:?}"
                ));
            }
        }
        let index = self.index(from);
        if index < 0 || index >= self.len {
            return Err(format!("id {from} is out of range"));
        }
        // if the pod wasn't found then verify the range is free.
        if prev.is_none() && g.used.has(index as usize) {
            return Err(format!("range picked for pod {pod:?} already taken"));
        }
        // The pod is already registered, nothing to do.
        if prev == Some(from) {
            return Ok(());
        }
        g.used.allocate(index as usize);
        g.used_by.insert(pod.to_string(), from);
        Ok(())
    }

    /// `Release`.
    pub fn release(&self, pod: &str) {
        if !self.feature_enabled {
            return;
        }
        self.release_locked(&mut self.lock(), pod);
    }

    /// `podAllocated`.
    pub fn pod_allocated(&self, pod: &str) -> bool {
        self.feature_enabled && self.lock().used_by.contains_key(pod)
    }

    fn release_locked(&self, g: &mut Inner, pod: &str) {
        let Some(v) = g.used_by.remove(pod) else {
            return;
        };
        g.removed += 1;
        let _ = std::fs::remove_file(self.kl.get_pod_dir(pod).join(MAPPINGS_FILE));
        if g.removed.is_multiple_of(MAP_REINITIALIZE_THRESHOLD) {
            // Go maps never free memory; upstream rebuilds the map here.
            g.used_by.shrink_to_fit();
            g.removed = 0;
        }
        let index = self.index(v);
        if index >= 0 {
            g.used.release(index as usize);
        }
    }

    /// `parseUserNsFileAndRecord`.
    pub fn parse_user_ns_file_and_record(
        &self,
        pod: &str,
        content: &[u8],
    ) -> Result<UserNamespace, String> {
        self.parse_and_record_locked(&mut self.lock(), pod, content)
    }

    fn parse_and_record_locked(
        &self,
        g: &mut Inner,
        pod: &str,
        content: &[u8],
    ) -> Result<UserNamespace, String> {
        let user_ns: UserNamespace = serde_json::from_slice(content)
            .map_err(|e| format!("invalid user namespace mappings file: {e}"))?;
        if user_ns.uid_mappings.len() != 1 {
            return Err(
                "invalid user namespace configuration: no more than one mapping allowed.".into(),
            );
        }
        if user_ns.uid_mappings.len() != user_ns.gid_mappings.len() {
            return Err(
                "invalid user namespace configuration: GID and UID mappings should be identical."
                    .into(),
            );
        }
        if user_ns.uid_mappings[0] != user_ns.gid_mappings[0] {
            return Err(
                "invalid user namespace configuration: GID and UID mapping should be identical"
                    .into(),
            );
        }
        // We don't produce configs without root mapped and some runtimes assume it is mapped.
        if user_ns.uid_mappings[0].container_id != 0 {
            return Err("invalid user namespace configuration: UID 0 must be mapped".into());
        }
        if user_ns.gid_mappings[0].container_id != 0 {
            return Err("invalid user namespace configuration: GID 0 must be mapped".into());
        }
        let m = user_ns.uid_mappings[0];
        self.record_locked(g, pod, m.host_id, m.length)?;
        Ok(user_ns)
    }

    /// `createUserNs`: allocate, persist; release again if persisting fails.
    fn create_user_ns_locked(&self, g: &mut Inner, pod: &str) -> Result<UserNamespace, String> {
        let (first_id, length) = self.allocate_one_locked(g, pod)?;
        let m = IdMapping {
            container_id: 0,
            host_id: first_id,
            length,
        };
        let user_ns = UserNamespace {
            uid_mappings: vec![m],
            gid_mappings: vec![m],
        };
        if let Err(e) = self.write_mappings_file(pod, &user_ns) {
            self.release_locked(g, pod);
            return Err(e);
        }
        Ok(user_ns)
    }

    /// `GetOrCreateUserNamespaceMappings`: the sandbox's `UserNamespace`.
    /// `pod` is `(uid, spec.hostUsers)`; `None` is a nil pod.
    pub fn get_or_create_user_namespace_mappings(
        &self,
        pod: Option<(&str, Option<bool>)>,
        runtime_handler: &str,
    ) -> Result<Option<v1::UserNamespace>, String> {
        let node = || v1::UserNamespace {
            mode: v1::NamespaceMode::Node as i32,
            ..Default::default()
        };
        let Some((uid, host_users)) = pod.and_then(|(u, h)| h.map(|h| (u, h))) else {
            // if the feature is enabled, specify to use the node mode, else don't specify it
            return Ok(self.feature_enabled.then(node));
        };
        if !self.feature_enabled {
            return Err(
                "the feature gate \"UserNamespacesSupport\" is disabled: can't set spec.HostUsers"
                    .into(),
            );
        }
        if host_users {
            return Ok(Some(node()));
        }
        // From here onwards, hostUsers=false and the feature gate is enabled.
        let supported = self.kl.handler_supports_user_namespaces(runtime_handler);
        if !matches!(supported, Ok(true)) {
            let msg = if runtime_handler.is_empty() {
                "can't set `spec.hostUsers: false`, runtime does not support user namespaces"
                    .to_string()
            } else {
                format!("can't set `spec.hostUsers: false`, RuntimeClass handler {runtime_handler:?} does not support user namespaces")
            };
            return Err(match supported {
                Err(e) => format!("{msg}: {e}"),
                _ => msg,
            });
        }

        let mut g = self.lock();
        let user_ns = match self.read_mappings_file(uid)? {
            Some(c) if !c.is_empty() => self
                .parse_and_record_locked(&mut g, uid, &c)
                .map_err(|e| format!("user namespace: {e}"))?,
            _ => self
                .create_user_ns_locked(&mut g, uid)
                .map_err(|e| format!("create user namespace: {e}"))?,
        };
        let conv = |m: &IdMapping| v1::IdMapping {
            host_id: m.host_id,
            container_id: m.container_id,
            length: m.length,
        };
        Ok(Some(v1::UserNamespace {
            mode: v1::NamespaceMode::Pod as i32,
            uids: user_ns.uid_mappings.iter().map(conv).collect(),
            gids: user_ns.gid_mappings.iter().map(conv).collect(),
        }))
    }

    /// `CleanupOrphanedPodUsernsAllocations`: frees the allocations of pods that
    /// are neither in `pods` nor `running_pods` (UIDs), and any allocation whose
    /// pod has no directory on disk.
    pub fn cleanup_orphaned_pod_userns_allocations(
        &self,
        pods: &[String],
        running_pods: &[String],
    ) -> Result<(), String> {
        if !self.feature_enabled {
            return Ok(());
        }
        let mut g = self.lock();
        let all_pods: HashSet<&String> = pods.iter().chain(running_pods).collect();
        let found = self
            .kl
            .list_pods_from_disk()
            .map_err(|e| format!("user namespace: read pods from disk: {e}"))?;
        let all_found: HashSet<&String> = found.iter().collect();
        // Remove all the pods "found" that are not known.
        for pod in &found {
            if !all_pods.contains(pod) {
                self.release_locked(&mut g, pod);
            }
        }
        // Remove any existing allocation for a pod that is not "found".
        let allocated: Vec<String> = g.used_by.keys().cloned().collect();
        for pod in allocated {
            if !all_found.contains(&pod) {
                self.release_locked(&mut g, &pod);
            }
        }
        Ok(())
    }
}

/// `TempFile(dir, ".")` of `utilstore.writeFile`.
fn tempfile_in(dir: &std::path::Path) -> std::io::Result<(std::fs::File, PathBuf)> {
    loop {
        let p = dir.join(format!(".{}", rand::rng().random::<u64>()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
        {
            Ok(f) => return Ok((f, p)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}
