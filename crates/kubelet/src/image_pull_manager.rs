//! Port of the filesystem pull records of
//! `pkg/kubelet/images/pullmanager/fs_pullrecords.go` (release-1.35) and the
//! `PullRecordsAccessor` interface of `interfaces.go`, with the
//! `ImagePullIntent` / `ImagePulledRecord` types of
//! `staging/src/k8s.io/kubelet/config/{v1alpha1,v1beta1}/types.go`.
//!
//! Records live under `<kubelet root>/image_manager/{pulling,pulled}`, one JSON
//! file per record named `sha256-<hex sha256 of image | imageRef>`, written as
//! `kubelet.config.k8s.io/v1beta1` and read from v1alpha1 or v1beta1 (older
//! records are rewritten in place at start, `recordsVersionMigration`).
//! Decoding is strict (unknown fields are rejected), as upstream
//! (`serializer.EnableStrict`).
//!
//! The write-through in-memory cache over any accessor is a port of
//! `mem_pullrecords.go` ([`CachedPullRecordsAccessor`]).
//!
//! Not ported here (tracked as backlog tasks): the pull manager itself
//! (`image_pull_manager.go`: intent ref-counting, `MustAttemptImagePull`) and
//! the metering wrapper (`NewMeteringRecordsAccessor`, metrics.go).

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CACHE_FILES_SHA256_PREFIX: &str = "sha256-";
const TMP_FILES_SUFFIX: &str = ".tmp";

const GROUP: &str = "kubelet.config.k8s.io";
/// `encodeVersion`: `kubeletconfigv1beta1.SchemeGroupVersion`.
const ENCODE_VERSION: &str = "v1beta1";
const ALPHA_VERSION: &str = "v1alpha1";

/// Error of the pull records accessor. Only the message is observable
/// upstream; aggregated errors render as `errors.NewAggregate` does.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);

fn err(msg: impl Into<String>) -> Error {
    Error(msg.into())
}

/// `utilerrors.NewAggregate(errs)`: nothing for an empty list, the message
/// itself for one, otherwise `[a, b]` over de-duplicated messages.
fn aggregate(errs: Vec<Error>) -> Option<Error> {
    let mut seen: Vec<&str> = Vec::new();
    for e in &errs {
        if !seen.contains(&e.0.as_str()) {
            seen.push(&e.0);
        }
    }
    match seen.len() {
        0 => None,
        1 => Some(err(seen[0])),
        _ => Some(err(format!("[{}]", seen.join(", ")))),
    }
}

/// `kubeletconfiginternal.ImagePullSecret`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePullSecret {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    /// SHA-256 of the image pull credentials content of the secret.
    #[serde(rename = "credentialHash")]
    pub credential_hash: String,
}

/// `kubeletconfiginternal.ImagePullServiceAccount`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePullServiceAccount {
    pub uid: String,
    pub namespace: String,
    pub name: String,
}

/// `kubeletconfiginternal.ImagePullCredentials`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePullCredentials {
    #[serde(
        rename = "kubernetesSecrets",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub kubernetes_secrets: Vec<ImagePullSecret>,
    #[serde(
        rename = "kubernetesServiceAccounts",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub kubernetes_service_accounts: Vec<ImagePullServiceAccount>,
    #[serde(
        rename = "nodePodsAccessible",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub node_pods_accessible: bool,
}

/// `kubeletconfiginternal.ImagePullIntent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePullIntent {
    pub image: String,
}

/// `kubeletconfiginternal.ImagePulledRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePulledRecord {
    pub last_updated_time: DateTime<Utc>,
    pub image_ref: String,
    /// `image` without tag/digest -> credentials it was pulled with.
    pub credential_mapping: BTreeMap<String, ImagePullCredentials>,
}

/// On-disk form (TypeMeta inline), field order as Go's struct order.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentWire {
    kind: String,
    #[serde(rename = "apiVersion")]
    api_version: String,
    image: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PulledWire {
    kind: String,
    #[serde(rename = "apiVersion")]
    api_version: String,
    #[serde(rename = "lastUpdatedTime")]
    last_updated_time: String,
    #[serde(rename = "imageRef")]
    image_ref: String,
    #[serde(
        rename = "credentialMapping",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    credential_mapping: BTreeMap<String, ImagePullCredentials>,
}

/// `PullRecordsAccessor` (interfaces.go): unified access to
/// ImagePullIntents/ImagePulledRecords irrespective of the backing database.
pub trait PullRecordsAccessor: Send + Sync {
    /// `ListImagePullIntents`: partial success is possible; the records that
    /// were read are returned together with the aggregated error.
    fn list_image_pull_intents(&self) -> (Vec<ImagePullIntent>, Option<Error>);
    /// `ImagePullIntentExists`: whether a valid intent is present for `image`.
    fn image_pull_intent_exists(&self, image: &str) -> Result<bool, Error>;
    fn write_image_pull_intent(&self, image: &str) -> Result<(), Error>;
    fn delete_image_pull_intent(&self, image: &str) -> Result<(), Error>;
    /// `ListImagePulledRecords`: partial success as for intents.
    fn list_image_pulled_records(&self) -> (Vec<ImagePulledRecord>, Option<Error>);
    /// `GetImagePulledRecord`: `Ok(None)` is `exists=false`. A file that
    /// exists but cannot be decoded is `Err` (upstream: `exists=true` with the
    /// decoding error). A record whose `imageRef` differs from the requested
    /// one is treated as absent.
    fn get_image_pulled_record(&self, image_ref: &str) -> Result<Option<ImagePulledRecord>, Error>;
    fn write_image_pulled_record(&self, record: &ImagePulledRecord) -> Result<(), Error>;
    fn delete_image_pulled_record(&self, image_ref: &str) -> Result<(), Error>;
}

/// `fsPullRecordsAccessor`.
pub struct FsPullRecordsAccessor {
    pulling_dir: PathBuf,
    pulled_dir: PathBuf,
}

impl FsPullRecordsAccessor {
    /// `NewFSPullRecordsAccessor`.
    pub fn new(kubelet_dir: &Path) -> Result<Self, Error> {
        let accessor = Self {
            pulling_dir: kubelet_dir.join("image_manager").join("pulling"),
            pulled_dir: kubelet_dir.join("image_manager").join("pulled"),
        };
        for dir in [&accessor.pulling_dir, &accessor.pulled_dir] {
            create_dir_0700(dir).map_err(|e| err(e.to_string()))?;
        }
        accessor.records_version_migration();
        Ok(accessor)
    }

    /// `recordsVersionMigration`: rewrite records not in the current API
    /// version. Failures are logged, never fatal.
    fn records_version_migration(&self) {
        let r = process_dir_files(&self.pulling_dir, |path, content| {
            let (intent, current) = decode_intent(content).map_err(|e| {
                err(format!(
                    "failed to decode ImagePullIntent from file {path:?}: {e}"
                ))
            })?;
            if !current {
                self.write_image_pull_intent(&intent.image).map_err(|e| {
                    err(format!(
                        "failed to migrate ImagePullIntent for image {:?} to the current version: {e}",
                        intent.image
                    ))
                })?;
            }
            Ok(())
        });
        if let Err(e) = r {
            tracing::error!(err = %e, "Error migrating image pull intents");
        }
        let r = process_dir_files(&self.pulled_dir, |path, content| {
            let (record, current) = decode_pulled_record(content).map_err(|e| {
                err(format!(
                    "failed to decode ImagePulledRecord from file {path:?}: {e}"
                ))
            })?;
            if !current {
                self.write_image_pulled_record(&record).map_err(|e| {
                    err(format!(
                        "failed to migrate ImagePulledRecord for image ref {:?} to the current version: {e}",
                        record.image_ref
                    ))
                })?;
            }
            Ok(())
        });
        if let Err(e) = r {
            tracing::error!(err = %e, "Error migrating image pulled records");
        }
    }

    /// `intentsSize`.
    pub fn intents_size(&self) -> Result<usize, Error> {
        count_cache_files(&self.pulling_dir)
    }

    /// `pulledRecordsSize`.
    pub fn pulled_records_size(&self) -> Result<usize, Error> {
        count_cache_files(&self.pulled_dir)
    }
}

impl PullRecordsAccessor for FsPullRecordsAccessor {
    fn write_image_pull_intent(&self, image: &str) -> Result<(), Error> {
        let wire = IntentWire {
            kind: "ImagePullIntent".into(),
            api_version: format!("{GROUP}/{ENCODE_VERSION}"),
            image: image.to_string(),
        };
        write_file(&self.pulling_dir, &cache_filename(image), &encode(&wire)?)
    }

    fn list_image_pull_intents(&self) -> (Vec<ImagePullIntent>, Option<Error>) {
        let mut intents = Vec::new();
        let r = process_dir_files(&self.pulling_dir, |path, content| {
            let (intent, _) = decode_intent(content).map_err(|e| {
                err(format!(
                    "failed to deserialize content of file {path:?} into ImagePullIntent: {e}"
                ))
            })?;
            intents.push(intent);
            Ok(())
        });
        (intents, r.err())
    }

    fn image_pull_intent_exists(&self, image: &str) -> Result<bool, Error> {
        let path = self.pulling_dir.join(cache_filename(image));
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(err(e.to_string())),
        };
        let (intent, _) = decode_intent(&bytes)?;
        Ok(intent.image == image)
    }

    fn delete_image_pull_intent(&self, image: &str) -> Result<(), Error> {
        remove_ignoring_missing(&self.pulling_dir.join(cache_filename(image)))
    }

    fn get_image_pulled_record(&self, image_ref: &str) -> Result<Option<ImagePulledRecord>, Error> {
        let bytes = match fs::read(self.pulled_dir.join(cache_filename(image_ref))) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(err(e.to_string())),
        };
        let (record, _) = decode_pulled_record(&bytes)?;
        if record.image_ref != image_ref {
            return Ok(None);
        }
        Ok(Some(record))
    }

    fn list_image_pulled_records(&self) -> (Vec<ImagePulledRecord>, Option<Error>) {
        let mut records = Vec::new();
        let r = process_dir_files(&self.pulled_dir, |path, content| {
            let (record, _) = decode_pulled_record(content).map_err(|e| {
                err(format!(
                    "failed to deserialize content of file {path:?} into ImagePulledRecord: {e}"
                ))
            })?;
            records.push(record);
            Ok(())
        });
        (records, r.err())
    }

    fn write_image_pulled_record(&self, record: &ImagePulledRecord) -> Result<(), Error> {
        let wire = PulledWire {
            kind: "ImagePulledRecord".into(),
            api_version: format!("{GROUP}/{ENCODE_VERSION}"),
            last_updated_time: record
                .last_updated_time
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            image_ref: record.image_ref.clone(),
            credential_mapping: record.credential_mapping.clone(),
        };
        let bytes = encode(&wire)
            .map_err(|e| err(format!("failed to serialize ImagePulledRecord: {e}")))?;
        write_file(&self.pulled_dir, &cache_filename(&record.image_ref), &bytes)
    }

    fn delete_image_pulled_record(&self, image_ref: &str) -> Result<(), Error> {
        remove_ignoring_missing(&self.pulled_dir.join(cache_filename(image_ref)))
    }
}

/// JSON serializer `Encode`: compact JSON followed by a newline.
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, Error> {
    let mut b = serde_json::to_vec(v).map_err(|e| err(e.to_string()))?;
    b.push(b'\n');
    Ok(b)
}

fn remove_ignoring_missing(path: &Path) -> Result<(), Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(err(e.to_string())),
    }
}

/// `cacheFilename`: `sha256-<hex>` of the image / imageRef.
pub fn cache_filename(image: &str) -> String {
    format!(
        "{CACHE_FILES_SHA256_PREFIX}{:x}",
        Sha256::digest(image.as_bytes())
    )
}

fn is_valid_cache_file_name(name: &str) -> bool {
    name.starts_with(CACHE_FILES_SHA256_PREFIX) && !name.ends_with(TMP_FILES_SUFFIX)
}

/// `countCacheFiles`.
fn count_cache_files(dir: &Path) -> Result<usize, Error> {
    let rd =
        fs::read_dir(dir).map_err(|e| err(format!("failed to open directory {dir:?}: {e}")))?;
    let mut n = 0;
    for entry in rd {
        let entry = entry.map_err(|e| {
            err(format!(
                "failed to list all entries in directory {dir:?}: {e}"
            ))
        })?;
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir && is_valid_cache_file_name(&entry.file_name().to_string_lossy()) {
            n += 1;
        }
    }
    Ok(n)
}

fn create_dir_0700(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// `writeFile`: atomic write via a `.tmp` sibling and rename.
fn write_file(dir: &Path, filename: &str, content: &[u8]) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;
    create_dir_0700(dir).map_err(|e| err(format!("failed to create directory {dir:?}: {e}")))?;
    let target = dir.join(filename);
    let tmp = dir.join(format!("{filename}{TMP_FILES_SUFFIX}"));
    let written = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(content));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp); // possibly partially written
        return Err(err(format!("failed to create temporary file {tmp:?}: {e}")));
    }
    if let Err(e) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(err(e.to_string()));
    }
    Ok(())
}

/// `processDirFiles`: run `action` on every record file directly inside
/// `dir`, collecting (not stopping at) errors.
fn process_dir_files(
    dir: &Path,
    mut action: impl FnMut(&str, &[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut errors = Vec::new();
    match fs::read_dir(dir) {
        Err(e) => errors.push(err(e.to_string())),
        Ok(rd) => {
            for entry in rd {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        errors.push(err(e.to_string()));
                        continue;
                    }
                };
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                // skip files we didn't write or .tmp files
                if !is_valid_cache_file_name(&entry.file_name().to_string_lossy()) {
                    continue;
                }
                let path = entry.path();
                let content = match fs::read(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        errors.push(err(format!("failed to read {path:?}: {e}")));
                        continue;
                    }
                };
                if let Err(e) = action(&path.to_string_lossy(), &content) {
                    errors.push(e);
                }
            }
        }
    }
    match aggregate(errors) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Checks `kind` and `apiVersion` (kubelet.config.k8s.io/v1alpha1|v1beta1)
/// and reports whether the version is the current one.
fn check_type_meta(kind: &str, want_kind: &str, api_version: &str) -> Result<bool, Error> {
    let version = api_version
        .strip_prefix(GROUP)
        .and_then(|v| v.strip_prefix('/'))
        .filter(|v| *v == ENCODE_VERSION || *v == ALPHA_VERSION)
        .ok_or_else(|| {
            err(format!(
                "no kind {kind:?} is registered for version {api_version:?} in scheme"
            ))
        })?;
    if kind != want_kind {
        return Err(err(format!(
            "failed to convert object to *{want_kind}: kind {kind:?}"
        )));
    }
    Ok(version == ENCODE_VERSION)
}

/// `decodeIntent`: the record and whether it is in the current version.
pub fn decode_intent(bytes: &[u8]) -> Result<(ImagePullIntent, bool), Error> {
    let w: IntentWire = serde_json::from_slice(bytes).map_err(|e| err(e.to_string()))?;
    let current = check_type_meta(&w.kind, "ImagePullIntent", &w.api_version)?;
    Ok((ImagePullIntent { image: w.image }, current))
}

/// `decodePulledRecord`: the record and whether it is in the current version.
pub fn decode_pulled_record(bytes: &[u8]) -> Result<(ImagePulledRecord, bool), Error> {
    let w: PulledWire = serde_json::from_slice(bytes).map_err(|e| err(e.to_string()))?;
    let current = check_type_meta(&w.kind, "ImagePulledRecord", &w.api_version)?;
    let last_updated_time = DateTime::parse_from_rfc3339(&w.last_updated_time)
        .map_err(|e| err(format!("parsing lastUpdatedTime: {e}")))?
        .with_timezone(&Utc);
    Ok((
        ImagePulledRecord {
            last_updated_time,
            image_ref: w.image_ref,
            credential_mapping: w.credential_mapping,
        },
        current,
    ))
}

// ---------------------------------------------------------------------------
// mem_pullrecords.go
// ---------------------------------------------------------------------------

use super::image_pull_policies::StripedLockSet;

struct LruInner<V> {
    /// key -> (value, recency tick)
    map: HashMap<String, (V, u64)>,
    /// recency tick -> key; the first entry is the least recently used.
    order: BTreeMap<u64, String>,
    tick: u64,
}

/// `lruCache` (mem_pullrecords.go) over `k8s.io/utils/lru` (an LRU with an
/// eviction callback that fires for every removed entry).
pub struct LruCache<V> {
    inner: Mutex<LruInner<V>>,
    max_size: usize,
    /// `authoritative`: the cached records can be considered the complete
    /// source. False once the cache evicted a record because it was full, or
    /// after errors during its initialisation.
    authoritative: AtomicBool,
}

impl<V: Clone> LruCache<V> {
    /// `newLRUCache`. A non-positive size is raised to 1.
    pub fn new(size: usize) -> Self {
        Self {
            inner: Mutex::new(LruInner {
                map: HashMap::new(),
                order: BTreeMap::new(),
                tick: 0,
            }),
            max_size: size.max(1),
            authoritative: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LruInner<V>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `Get`: a hit marks the key most recently used.
    pub fn get(&self, key: &str) -> Option<V> {
        let mut g = self.lock();
        let g = &mut *g;
        g.tick += 1;
        let tick = g.tick;
        let (value, old) = g.map.get_mut(key)?;
        let old_tick = std::mem::replace(old, tick);
        g.order.remove(&old_tick);
        g.order.insert(tick, key.to_string());
        Some(value.clone())
    }

    /// `Set` (`lru.Add`): evicting the least recently used entry on overflow
    /// makes the cache non-authoritative (the eviction function).
    pub fn set(&self, key: &str, value: V) {
        let mut g = self.lock();
        let g = &mut *g;
        g.tick += 1;
        let tick = g.tick;
        if let Some((_, old)) = g.map.get(key) {
            g.order.remove(old);
        }
        g.map.insert(key.to_string(), (value, tick));
        g.order.insert(tick, key.to_string());
        if g.map.len() > self.max_size {
            if let Some((_, oldest)) = g.order.pop_first() {
                g.map.remove(&oldest);
                self.authoritative.store(false, Ordering::SeqCst);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `Clear`: every removed entry triggers the eviction function, so a
    /// non-empty clear makes the cache non-authoritative.
    pub fn clear(&self) {
        let mut g = self.lock();
        if !g.map.is_empty() {
            self.authoritative.store(false, Ordering::SeqCst);
        }
        g.map.clear();
        g.order.clear();
    }

    /// `Delete`: an explicit delete does not change the authoritative status.
    /// Must be called with the external lock on `key` held.
    pub fn delete(&self, key: &str) {
        let mut g = self.lock();
        if let Some((_, tick)) = g.map.remove(key) {
            g.order.remove(&tick);
        }
    }

    pub fn is_authoritative(&self) -> bool {
        self.authoritative.load(Ordering::SeqCst)
    }

    pub fn set_authoritative(&self, v: bool) {
        self.authoritative.store(v, Ordering::SeqCst);
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

/// `cachedPullRecordsAccessor`: a write-through cache layer on top of another
/// [`PullRecordsAccessor`].
pub struct CachedPullRecordsAccessor {
    delegate: Arc<dyn PullRecordsAccessor>,
    intents_locks: StripedLockSet,
    intents: LruCache<ImagePullIntent>,
    pulled_records_locks: StripedLockSet,
    pulled_records: LruCache<ImagePulledRecord>,
}

impl CachedPullRecordsAccessor {
    /// `NewCachedPullRecordsAccessor` (without the metering wrapper). Warms
    /// both caches by listing the delegate; a listing error leaves that cache
    /// non-authoritative until a later list succeeds.
    pub fn new(
        delegate: Arc<dyn PullRecordsAccessor>,
        intents_cache_size: i32,
        pulled_records_cache_size: i32,
        striped_locks_size: i32,
    ) -> Self {
        let intents_cache_size = intents_cache_size.clamp(1, 1024) as usize;
        let pulled_records_cache_size = pulled_records_cache_size.clamp(1, 2000) as usize;
        let c = Self {
            delegate,
            intents_locks: StripedLockSet::new(striped_locks_size),
            intents: LruCache::new(intents_cache_size),
            pulled_records_locks: StripedLockSet::new(striped_locks_size),
            pulled_records: LruCache::new(pulled_records_cache_size),
        };
        // warm our caches and set authoritative
        if let (_, Some(e)) = c.list_image_pull_intents() {
            tracing::info!(
                error = %e,
                "there was an error initializing the image pull intents cache, the cache will work in a non-authoritative mode until the intents are listed successfully"
            );
        }
        if let (_, Some(e)) = c.list_image_pulled_records() {
            tracing::info!(
                error = %e,
                "there was an error initializing the image pulled records cache, the cache will work in a non-authoritative mode until the pulled records are listed successfully"
            );
        }
        c
    }

    pub fn intents_authoritative(&self) -> bool {
        self.intents.is_authoritative()
    }

    pub fn pulled_records_authoritative(&self) -> bool {
        self.pulled_records.is_authoritative()
    }

    /// `intentsSize`: percent of the intents cache in use.
    pub fn intents_size(&self) -> usize {
        self.intents.len() * 100 / self.intents.max_size()
    }

    /// `pulledRecordsSize`: percent of the pulled records cache in use.
    pub fn pulled_records_size(&self) -> usize {
        self.pulled_records.len() * 100 / self.pulled_records.max_size()
    }
}

/// `cacheRefreshingList`.
fn cache_refreshing_list<V: Clone>(
    cache: &LruCache<V>,
    delegate_locks: &StripedLockSet,
    list: impl FnOnce() -> (Vec<V>, Option<Error>),
    record_to_key: impl Fn(&V) -> &str,
) -> (Vec<V>, Option<Error>) {
    let was_authoritative = cache.is_authoritative();
    // doing a full list gives us an opportunity to become authoritative if we
    // get back an error-free result that fits in our cache
    let _guards = (!was_authoritative).then(|| delegate_locks.global_lock());

    let (results, err) = list();
    if was_authoritative {
        return (results, err);
    }

    let results_are_authoritative = err.is_none() && results.len() < cache.max_size();
    // populate the cache if that would make our cache authoritative or if the
    // cache is currently empty
    if results_are_authoritative || cache.is_empty() {
        cache.clear();
        for record in results.iter().take(cache.max_size()) {
            cache.set(record_to_key(record), record.clone());
        }
        cache.set_authoritative(results_are_authoritative);
    }
    (results, err)
}

impl PullRecordsAccessor for CachedPullRecordsAccessor {
    fn list_image_pull_intents(&self) -> (Vec<ImagePullIntent>, Option<Error>) {
        cache_refreshing_list(
            &self.intents,
            &self.intents_locks,
            || self.delegate.list_image_pull_intents(),
            |i| i.image.as_str(),
        )
    }

    fn image_pull_intent_exists(&self, image: &str) -> Result<bool, Error> {
        // do the cheap get lock-free
        if self.intents.get(image).is_some() {
            return Ok(true);
        }
        // on a miss, lock on the image
        let _g = self.intents_locks.lock(image);
        // check again under the image lock
        if self.intents.get(image).is_some() {
            return Ok(true);
        }
        // if the cache is authoritative, return false on a miss
        if self.intents.is_authoritative() {
            return Ok(false);
        }
        // fall through to the expensive lookup
        let exists = self.delegate.image_pull_intent_exists(image)?;
        if exists {
            self.intents.set(
                image,
                ImagePullIntent {
                    image: image.to_string(),
                },
            );
        }
        Ok(exists)
    }

    fn write_image_pull_intent(&self, image: &str) -> Result<(), Error> {
        let _g = self.intents_locks.lock(image);
        self.delegate.write_image_pull_intent(image)?;
        self.intents.set(
            image,
            ImagePullIntent {
                image: image.to_string(),
            },
        );
        Ok(())
    }

    fn delete_image_pull_intent(&self, image: &str) -> Result<(), Error> {
        let _g = self.intents_locks.lock(image);
        self.delegate.delete_image_pull_intent(image)?;
        self.intents.delete(image);
        Ok(())
    }

    fn list_image_pulled_records(&self) -> (Vec<ImagePulledRecord>, Option<Error>) {
        cache_refreshing_list(
            &self.pulled_records,
            &self.pulled_records_locks,
            || self.delegate.list_image_pulled_records(),
            |r| r.image_ref.as_str(),
        )
    }

    fn get_image_pulled_record(&self, image_ref: &str) -> Result<Option<ImagePulledRecord>, Error> {
        if let Some(r) = self.pulled_records.get(image_ref) {
            return Ok(Some(r));
        }
        let _g = self.pulled_records_locks.lock(image_ref);
        if let Some(r) = self.pulled_records.get(image_ref) {
            return Ok(Some(r));
        }
        if self.pulled_records.is_authoritative() {
            return Ok(None);
        }
        let rec = self.delegate.get_image_pulled_record(image_ref)?;
        if let Some(r) = &rec {
            self.pulled_records.set(image_ref, r.clone());
        }
        Ok(rec)
    }

    fn write_image_pulled_record(&self, record: &ImagePulledRecord) -> Result<(), Error> {
        let _g = self.pulled_records_locks.lock(&record.image_ref);
        self.delegate.write_image_pulled_record(record)?;
        self.pulled_records.set(&record.image_ref, record.clone());
        Ok(())
    }

    fn delete_image_pulled_record(&self, image_ref: &str) -> Result<(), Error> {
        let _g = self.pulled_records_locks.lock(image_ref);
        self.delegate.delete_image_pulled_record(image_ref)?;
        self.pulled_records.delete(image_ref);
        Ok(())
    }
}
