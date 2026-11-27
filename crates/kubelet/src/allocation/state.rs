//! Checkpointed allocated pod resources.
//!
//! Port of pkg/kubelet/allocation/state (state.go `PodResourceInfo`,
//! `PodResourceInfoMap`, `State`; state_mem.go `stateMemory`;
//! state_checkpoint.go `stateCheckpoint`, `noopStateCheckpoint`;
//! checkpoint.go `Checkpoint`) with the pieces of
//! pkg/kubelet/checkpointmanager it sits on (`CheckpointManager`,
//! `checksum.New` = FNV-32a of spew's `%#v` of the data string, i.e.
//! `"(string)" + data`, `CorruptCheckpointError`, `ErrCheckpointNotFound`)
//! and pkg/kubelet/util/store/filestore.go (`FileStore`: validated keys,
//! dot-prefixed temp file, fsync, rename). release-1.35.
//!
//! The kubelet keeps this file as `<root>/allocated_pods_state`
//! (`AllocatedPodsStateFile` in allocation_manager.go). Nothing uses the
//! state yet; the resize flow wiring is a follow-up.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use kubernetes_rs_common::quantity::Quantity;
use serde::{Deserialize, Serialize};

/// `v1.ResourceRequirements`. Quantities are kept as their canonical
/// strings in sorted maps so the serialized form (and so its checksum) is
/// deterministic, like Go's sorted map keys.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceRequirements {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub limits: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub requests: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<serde_json::Value>,
}

impl ResourceRequirements {
    /// Build from quantity strings, canonicalised like a `resource.Quantity`
    /// round trip (`MustParse(..)` then `MarshalJSON`). An unparseable
    /// quantity is kept verbatim.
    pub fn new<'a>(
        requests: impl IntoIterator<Item = (&'a str, &'a str)>,
        limits: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        let canon = |(k, v): (&str, &str)| {
            let v = Quantity::parse(v)
                .map(|q| q.canonical_string())
                .unwrap_or_else(|_| v.to_string());
            (k.to_string(), v)
        };
        Self {
            requests: requests.into_iter().map(canon).collect(),
            limits: limits.into_iter().map(canon).collect(),
            claims: Vec::new(),
        }
    }
}

/// `PodResourceInfo`: field names are the Go field names (no json tags).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PodResourceInfo {
    /// Container name to its resources.
    #[serde(rename = "ContainerResources", default)]
    pub container_resources: BTreeMap<String, ResourceRequirements>,
    #[serde(rename = "PodLevelResources", default)]
    pub pod_level_resources: Option<ResourceRequirements>,
}

/// `PodResourceInfoMap`: pod UID to its info.
pub type PodResourceInfoMap = BTreeMap<String, PodResourceInfo>;

/// `PodResourceCheckpointInfo`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PodResourceCheckpointInfo {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    entries: PodResourceInfoMap,
}

/// `State` (Reader + writer).
pub trait State: Send + Sync {
    fn get_container_resources(
        &self,
        pod_uid: &str,
        container_name: &str,
    ) -> Option<ResourceRequirements>;
    fn get_pod_resource_info_map(&self) -> PodResourceInfoMap;
    fn get_pod_resource_info(&self, pod_uid: &str) -> Option<PodResourceInfo>;
    /// `Some(None)` is a known pod without pod-level resources.
    fn get_pod_level_resources(&self, pod_uid: &str) -> Option<Option<ResourceRequirements>>;
    fn set_container_resources(
        &self,
        pod_uid: &str,
        container_name: &str,
        resources: ResourceRequirements,
    ) -> Result<(), StateError>;
    fn set_pod_resource_info(&self, pod_uid: &str, info: PodResourceInfo)
        -> Result<(), StateError>;
    fn set_pod_level_resources(
        &self,
        pod_uid: &str,
        resources: Option<ResourceRequirements>,
    ) -> Result<(), StateError>;
    fn remove_pod(&self, pod_uid: &str) -> Result<(), StateError>;
    /// Remove the state of every pod not in `remaining_pods`.
    fn remove_orphaned_pods(&self, remaining_pods: &HashSet<String>);
}

/// Errors of the checkpoint layer (checkpointmanager/errors).
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// `ErrCheckpointNotFound`.
    #[error("checkpoint is not found")]
    CheckpointNotFound,
    /// `CorruptCheckpointError` (checksum mismatch).
    #[error("checkpoint is corrupted")]
    CorruptCheckpoint { actual: u64, expected: u64 },
    /// `invalid key: %q` (store.ValidateKey).
    #[error("invalid key: {0:?}")]
    InvalidKey(String),
    #[error("failed to serialize allocations for checkpointing: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to get pod resource information: {0}")]
    Deserialize(serde_json::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// checkpointmanager/checksum
// ---------------------------------------------------------------------------

/// `checksum.New(data)` for a string: `fnv.New32a()` over
/// `dump.ForHash(data)`, which spew renders for `%#v` of a string as
/// `"(string)" + data` (pinned by the golden checksum in
/// state_checkpoint_test.go `Test_stateCheckpoint_formatUpgraded`).
pub fn checksum_of(data: &str) -> u64 {
    let mut h: u32 = 0x811c_9dc5;
    for b in "(string)".bytes().chain(data.bytes()) {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    u64::from(h)
}

/// `Checkpoint` (checkpoint.go): `data` is the serialized
/// `PodResourceCheckpointInfo`.
#[derive(Debug, Serialize, Deserialize)]
struct Checkpoint {
    data: String,
    checksum: u64,
}

impl Checkpoint {
    /// `NewCheckpoint`.
    fn new(info: &PodResourceCheckpointInfo) -> Result<Self, StateError> {
        let data = serde_json::to_string(info).map_err(StateError::Serialize)?;
        let checksum = checksum_of(&data);
        Ok(Self { data, checksum })
    }

    /// `VerifyChecksum`.
    fn verify_checksum(&self) -> Result<(), StateError> {
        let actual = checksum_of(&self.data);
        if actual != self.checksum {
            return Err(StateError::CorruptCheckpoint {
                actual,
                expected: self.checksum,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// util/store FileStore + checkpointmanager
// ---------------------------------------------------------------------------

const TMP_PREFIX: &str = ".";
const KEY_MAX_LENGTH: usize = 250;

/// `store.ValidateKey`.
fn validate_key(key: &str) -> Result<(), StateError> {
    let ok = !key.is_empty()
        && key.len() <= KEY_MAX_LENGTH
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(StateError::InvalidKey(key.to_string()))
    }
}

/// `FileStore` behind `checkpointmanager.CheckpointManager`.
#[derive(Debug)]
struct CheckpointManager {
    dir: PathBuf,
    mutex: Mutex<()>,
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl CheckpointManager {
    /// `NewCheckpointManager` / `NewFileStore`: `MkdirAll(path, 0755)`.
    fn new(dir: &Path) -> Result<Self, StateError> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            mutex: Mutex::new(()),
        })
    }

    /// `CreateCheckpoint`: `writeFile` (temp file, write, fsync, rename).
    fn create_checkpoint(&self, key: &str, cp: &Checkpoint) -> Result<(), StateError> {
        let _g = self.mutex.lock().unwrap();
        validate_key(key)?;
        let blob = serde_json::to_vec(cp).map_err(StateError::Serialize)?;
        fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join(format!(
            "{TMP_PREFIX}{}-{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let write = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&blob)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, self.dir.join(key))
        };
        write().inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
        Ok(())
    }

    /// `GetCheckpoint`: read, unmarshal, verify the checksum.
    fn get_checkpoint(&self, key: &str) -> Result<Checkpoint, StateError> {
        let _g = self.mutex.lock().unwrap();
        validate_key(key)?;
        let blob = match fs::read(self.dir.join(key)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StateError::CheckpointNotFound)
            }
            Err(e) => return Err(e.into()),
        };
        let cp: Checkpoint = serde_json::from_slice(&blob).map_err(StateError::Deserialize)?;
        cp.verify_checksum()?;
        Ok(cp)
    }
}

// ---------------------------------------------------------------------------
// stateMemory
// ---------------------------------------------------------------------------

/// `stateMemory`.
#[derive(Debug, Default)]
pub struct StateMemory {
    pod_resources: RwLock<PodResourceInfoMap>,
}

impl StateMemory {
    /// `NewStateMemory`.
    pub fn new(resources: Option<PodResourceInfoMap>) -> Self {
        Self {
            pod_resources: RwLock::new(resources.unwrap_or_default()),
        }
    }
}

impl State for StateMemory {
    fn get_container_resources(&self, uid: &str, container: &str) -> Option<ResourceRequirements> {
        self.pod_resources
            .read()
            .unwrap()
            .get(uid)?
            .container_resources
            .get(container)
            .cloned()
    }

    fn get_pod_resource_info_map(&self) -> PodResourceInfoMap {
        self.pod_resources.read().unwrap().clone()
    }

    fn get_pod_resource_info(&self, uid: &str) -> Option<PodResourceInfo> {
        self.pod_resources.read().unwrap().get(uid).cloned()
    }

    fn get_pod_level_resources(&self, uid: &str) -> Option<Option<ResourceRequirements>> {
        self.pod_resources
            .read()
            .unwrap()
            .get(uid)
            .map(|p| p.pod_level_resources.clone())
    }

    fn set_container_resources(
        &self,
        uid: &str,
        container: &str,
        resources: ResourceRequirements,
    ) -> Result<(), StateError> {
        self.pod_resources
            .write()
            .unwrap()
            .entry(uid.to_string())
            .or_default()
            .container_resources
            .insert(container.to_string(), resources);
        Ok(())
    }

    fn set_pod_level_resources(
        &self,
        uid: &str,
        resources: Option<ResourceRequirements>,
    ) -> Result<(), StateError> {
        self.pod_resources
            .write()
            .unwrap()
            .entry(uid.to_string())
            .or_default()
            .pod_level_resources = resources;
        Ok(())
    }

    fn set_pod_resource_info(&self, uid: &str, info: PodResourceInfo) -> Result<(), StateError> {
        self.pod_resources
            .write()
            .unwrap()
            .insert(uid.to_string(), info);
        Ok(())
    }

    fn remove_pod(&self, uid: &str) -> Result<(), StateError> {
        self.pod_resources.write().unwrap().remove(uid);
        Ok(())
    }

    fn remove_orphaned_pods(&self, remaining: &HashSet<String>) {
        self.pod_resources
            .write()
            .unwrap()
            .retain(|uid, _| remaining.contains(uid));
    }
}

// ---------------------------------------------------------------------------
// stateCheckpoint
// ---------------------------------------------------------------------------

struct CheckpointInner {
    /// `lastChecksum`.
    last_checksum: u64,
}

/// `stateCheckpoint`: a [`StateMemory`] cache written through to a
/// checkpoint file.
pub struct StateCheckpoint {
    /// Serialises writers like `mux`; readers go to the cache directly (it
    /// has its own lock).
    mux: Mutex<CheckpointInner>,
    cache: StateMemory,
    checkpoint_manager: CheckpointManager,
    checkpoint_name: String,
}

impl StateCheckpoint {
    /// `NewStateCheckpoint(stateDir, checkpointName)`.
    pub fn new(state_dir: &Path, checkpoint_name: &str) -> Result<Self, String> {
        let manager = CheckpointManager::new(state_dir).map_err(|e| {
            format!(
                "failed to initialize checkpoint manager for pod resource information tracking: {e}"
            )
        })?;
        let (pra, last_checksum) = restore_state(&manager, checkpoint_name).map_err(|e| {
            format!(
                "could not restore state from checkpoint: {e}, please drain this node and delete pod resource information checkpoint file {:?} before restarting Kubelet",
                state_dir.join(checkpoint_name).display().to_string()
            )
        })?;
        Ok(Self {
            mux: Mutex::new(CheckpointInner { last_checksum }),
            cache: StateMemory::new(pra),
            checkpoint_manager: manager,
            checkpoint_name: checkpoint_name.to_string(),
        })
    }

    /// `storeState`: skipped when the content did not change.
    fn store_state(&self, inner: &mut CheckpointInner) -> Result<(), StateError> {
        let cp = Checkpoint::new(&PodResourceCheckpointInfo {
            entries: self.cache.get_pod_resource_info_map(),
        })?;
        if cp.checksum == inner.last_checksum {
            // No changes to the checkpoint => no need to re-write it.
            return Ok(());
        }
        self.checkpoint_manager
            .create_checkpoint(&self.checkpoint_name, &cp)?;
        inner.last_checksum = cp.checksum;
        Ok(())
    }
}

/// `restoreState`: a missing checkpoint is an empty state.
fn restore_state(
    manager: &CheckpointManager,
    name: &str,
) -> Result<(Option<PodResourceInfoMap>, u64), StateError> {
    let cp = match manager.get_checkpoint(name) {
        Ok(cp) => cp,
        Err(StateError::CheckpointNotFound) => return Ok((None, 0)),
        Err(e) => return Err(e),
    };
    let info: PodResourceCheckpointInfo =
        serde_json::from_str(&cp.data).map_err(StateError::Deserialize)?;
    Ok((Some(info.entries), cp.checksum))
}

impl State for StateCheckpoint {
    fn get_container_resources(&self, uid: &str, c: &str) -> Option<ResourceRequirements> {
        self.cache.get_container_resources(uid, c)
    }

    fn get_pod_resource_info_map(&self) -> PodResourceInfoMap {
        self.cache.get_pod_resource_info_map()
    }

    fn get_pod_resource_info(&self, uid: &str) -> Option<PodResourceInfo> {
        self.cache.get_pod_resource_info(uid)
    }

    fn get_pod_level_resources(&self, uid: &str) -> Option<Option<ResourceRequirements>> {
        self.cache.get_pod_level_resources(uid)
    }

    fn set_container_resources(
        &self,
        uid: &str,
        c: &str,
        r: ResourceRequirements,
    ) -> Result<(), StateError> {
        let mut g = self.mux.lock().unwrap();
        self.cache.set_container_resources(uid, c, r)?;
        self.store_state(&mut g)
    }

    fn set_pod_level_resources(
        &self,
        uid: &str,
        r: Option<ResourceRequirements>,
    ) -> Result<(), StateError> {
        let mut g = self.mux.lock().unwrap();
        self.cache.set_pod_level_resources(uid, r)?;
        self.store_state(&mut g)
    }

    fn set_pod_resource_info(&self, uid: &str, info: PodResourceInfo) -> Result<(), StateError> {
        let mut g = self.mux.lock().unwrap();
        self.cache.set_pod_resource_info(uid, info)?;
        self.store_state(&mut g)
    }

    /// Skips writing the checkpoint for a pod deletion: there is no side
    /// effect to keeping a deleted pod, and `remove_orphaned_pods` cleans up
    /// eventually (state_checkpoint.go `RemovePod`).
    fn remove_pod(&self, uid: &str) -> Result<(), StateError> {
        let _g = self.mux.lock().unwrap();
        self.cache.remove_pod(uid)
    }

    /// The stored state is not updated; after a restart the orphans are
    /// removed again the next time this runs.
    fn remove_orphaned_pods(&self, remaining: &HashSet<String>) {
        self.cache.remove_orphaned_pods(remaining);
    }
}

/// `noopStateCheckpoint` (`NewNoopStateCheckpoint`): holds nothing.
#[derive(Debug, Default)]
pub struct NoopStateCheckpoint;

impl State for NoopStateCheckpoint {
    fn get_container_resources(&self, _: &str, _: &str) -> Option<ResourceRequirements> {
        None
    }
    fn get_pod_resource_info_map(&self) -> PodResourceInfoMap {
        PodResourceInfoMap::new()
    }
    fn get_pod_resource_info(&self, _: &str) -> Option<PodResourceInfo> {
        None
    }
    fn get_pod_level_resources(&self, _: &str) -> Option<Option<ResourceRequirements>> {
        None
    }
    fn set_container_resources(
        &self,
        _: &str,
        _: &str,
        _: ResourceRequirements,
    ) -> Result<(), StateError> {
        Ok(())
    }
    fn set_pod_resource_info(&self, _: &str, _: PodResourceInfo) -> Result<(), StateError> {
        Ok(())
    }
    fn set_pod_level_resources(
        &self,
        _: &str,
        _: Option<ResourceRequirements>,
    ) -> Result<(), StateError> {
        Ok(())
    }
    fn remove_pod(&self, _: &str) -> Result<(), StateError> {
        Ok(())
    }
    fn remove_orphaned_pods(&self, _: &HashSet<String>) {}
}
