//! Port of `pkg/kubelet/images/pullmanager/image_pull_manager.go`
//! (release-1.35): `PullManager`, the `ImagePullManager` that tracks images
//! pulled by the kubelet with pull intents (ref-counted in memory) and pulled
//! records, and decides in `MustAttemptImagePull` whether a pod must
//! re-authenticate to use an image that already exists on the node.
//!
//! Security: every failure to read the records makes the answer "must pull"
//! (fail closed), exactly as upstream.
//!
//! Also ported: `NoopImagePullManager` (`noop_pull_manager.go`) and the
//! `ImagePullManager` interface (`interfaces.go`).
//!
//! Not ported here (backlog kubelet-P2-25e): the metrics wrapper
//! (`metrics.go`) and wiring into the image manager. The check result that
//! upstream feeds `recordMustAttemptImagePullResult` is returned by
//! [`PullManager::must_attempt_image_pull_with_result`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use super::image_pull_manager::{
    Error, ImagePullCredentials, ImagePullSecret, ImagePullServiceAccount, ImagePulledRecord,
    PullRecordsAccessor,
};
use super::image_pull_policies::{ImagePullPolicyEnforcer, StripedLockSet};
use crate::credentialprovider::parse_image_repo;
use crate::image_gc::Image;

/// `writeRecordWhileMatchingLimit`: stop writing yet-uncached records found
/// while checking if a pull must be attempted (bounds writes on high
/// namespace turnover).
pub const WRITE_RECORD_WHILE_MATCHING_LIMIT: usize = 100;

/// `mustAttemptImagePullResult` (metrics.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MustAttemptImagePullResult {
    CredentialPolicyAllowed,
    CredentialRecordFound,
    MustAuthenticate,
    Error,
}

impl MustAttemptImagePullResult {
    /// The metric label values of metrics.go:32-35.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CredentialPolicyAllowed => "credentialPolicyAllowed",
            Self::CredentialRecordFound => "credentialRecordFound",
            Self::MustAuthenticate => "mustAuthenticate",
            Self::Error => "error",
        }
    }
}

/// `GetPodCredentials`: the pod's pull secrets / service account, resolved
/// lazily (only when the cached record needs them).
pub type GetPodCredentials<'a> =
    &'a dyn Fn() -> Result<(Vec<ImagePullSecret>, Option<ImagePullServiceAccount>), Error>;

/// `ImagePullManager` (interfaces.go).
pub trait ImagePullManager: Send + Sync {
    fn record_pull_intent(&self, image: &str) -> Result<(), Error>;
    fn record_image_pulled(
        &self,
        image: &str,
        image_ref: &str,
        credentials: Option<&ImagePullCredentials>,
    );
    fn record_image_pull_failed(&self, image: &str);
    fn must_attempt_image_pull(
        &self,
        image: &str,
        image_ref: &str,
        get_pod_credentials: GetPodCredentials<'_>,
    ) -> Result<bool, Error>;
    fn prune_unknown_records(&self, image_list: &[String], until: DateTime<Utc>);
}

/// `NoopImagePullManager` (noop_pull_manager.go): always requires a pull.
pub struct NoopImagePullManager;

impl ImagePullManager for NoopImagePullManager {
    fn record_pull_intent(&self, _image: &str) -> Result<(), Error> {
        Ok(())
    }
    fn record_image_pulled(&self, _: &str, _: &str, _: Option<&ImagePullCredentials>) {}
    fn record_image_pull_failed(&self, _image: &str) {}
    fn must_attempt_image_pull(
        &self,
        _image: &str,
        _image_ref: &str,
        _get_pod_credentials: GetPodCredentials<'_>,
    ) -> Result<bool, Error> {
        Ok(true)
    }
    fn prune_unknown_records(&self, _image_list: &[String], _until: DateTime<Utc>) {}
}

/// `kubecontainer.ImageService.ListImages` as `initialize` uses it.
pub trait ImageLister: Send + Sync {
    fn list_images(&self) -> Result<Vec<Image>, Error>;
}

/// `PullManager`.
pub struct PullManager {
    records_accessor: Arc<dyn PullRecordsAccessor>,
    image_policy_enforcer: Arc<dyn ImagePullPolicyEnforcer>,
    image_service: Arc<dyn ImageLister>,
    /// image -> lock
    intent_accessors: StripedLockSet,
    /// image -> number of current in-flight pulls
    intent_counters: Mutex<HashMap<String, i32>>,
    /// imageRef -> lock
    pulled_accessors: StripedLockSet,
}

impl PullManager {
    /// `NewImagePullManager`: builds the manager and runs `initialize`.
    pub fn new(
        records_accessor: Arc<dyn PullRecordsAccessor>,
        image_policy_enforcer: Arc<dyn ImagePullPolicyEnforcer>,
        image_service: Arc<dyn ImageLister>,
        lock_stripes_num: i32,
    ) -> Self {
        let m = Self {
            records_accessor,
            image_policy_enforcer,
            image_service,
            intent_accessors: StripedLockSet::new(lock_stripes_num),
            intent_counters: Mutex::new(HashMap::new()),
            pulled_accessors: StripedLockSet::new(lock_stripes_num),
        };
        m.initialize();
        m
    }

    /// `RecordPullIntent`.
    pub fn record_pull_intent(&self, image: &str) -> Result<(), Error> {
        let _g = self.intent_accessors.lock(image);
        self.records_accessor
            .write_image_pull_intent(image)
            .map_err(|e| Error(format!("failed to record image pull intent: {e}")))?;
        self.increment_intent_counter_for_image(image);
        Ok(())
    }

    /// `RecordImagePulled`. A write error leaves the intent (and its counter)
    /// dangling on purpose so the pulled image is still considered pulled by
    /// the kubelet; the next start turns the intent into a record.
    pub fn record_image_pulled(
        &self,
        image: &str,
        image_ref: &str,
        credentials: Option<&ImagePullCredentials>,
    ) {
        if let Err(e) = self.write_pulled_record_if_changed(image, image_ref, credentials) {
            tracing::error!(%e, image_ref, "failed to write image pulled record");
            return;
        }
        self.decrement_image_pull_intent(image);
    }

    /// `writePulledRecordIfChanged`. `credentials == None` marks an image
    /// pulled under unknown circumstances: it is tracked, but no credentials
    /// are written so credential verification is forced next time.
    fn write_pulled_record_if_changed(
        &self,
        image: &str,
        image_ref: &str,
        credentials: Option<&ImagePullCredentials>,
    ) -> Result<(), Error> {
        let _g = self.pulled_accessors.lock(image_ref);

        let sanitized_image = trim_image_tag_digest(image)
            .map_err(|e| Error(format!("invalid image name {image:?}: {e}")))?;

        let pulled_record = match self.records_accessor.get_image_pulled_record(image_ref) {
            Ok(r) => r,
            Err(e) => {
                tracing::info!(image, err = %e, "failed to retrieve an ImagePulledRecord");
                None
            }
        };

        let record = match pulled_record {
            None => {
                let mut mapping = BTreeMap::new();
                // The existence of the record alone makes the image
                // kubelet-pulled; with no credential record the kubelet
                // fails safe and requires credential validation.
                if let Some(c) = credentials {
                    mapping.insert(sanitized_image, c.clone());
                }
                ImagePulledRecord {
                    last_updated_time: Utc::now(),
                    image_ref: image_ref.to_string(),
                    credential_mapping: mapping,
                }
            }
            Some(orig) => match pulled_record_merge_new_creds(&orig, &sanitized_image, credentials)
            {
                Some(merged) => merged,
                None => return Ok(()),
            },
        };
        self.records_accessor.write_image_pulled_record(&record)
    }

    /// `RecordImagePullFailed`.
    pub fn record_image_pull_failed(&self, image: &str) {
        self.decrement_image_pull_intent(image);
    }

    /// `decrementImagePullIntent`: drops the intent file once the reference
    /// counter reaches zero.
    fn decrement_image_pull_intent(&self, image: &str) {
        let _g = self.intent_accessors.lock(image);
        if self.get_intent_counter_for_image(image) <= 1 {
            if let Err(e) = self.records_accessor.delete_image_pull_intent(image) {
                tracing::error!(%e, image, "failed to remove image pull intent");
                return;
            }
            // Only delete the counter once the file was deleted, to stay
            // consistent with the records.
            self.intent_counters.lock().unwrap().remove(image);
            return;
        }
        self.decrement_intent_counter_for_image(image);
    }

    /// `MustAttemptImagePull`.
    pub fn must_attempt_image_pull(
        &self,
        image: &str,
        image_ref: &str,
        get_pod_credentials: GetPodCredentials<'_>,
    ) -> Result<bool, Error> {
        self.must_attempt_image_pull_with_result(image, image_ref, get_pod_credentials)
            .0
    }

    /// `MustAttemptImagePull` plus the `resultForMetrics` upstream records in
    /// its deferred func (an empty result is `error`). `None` when upstream
    /// returns before the deferred func is installed (empty `imageRef`).
    pub fn must_attempt_image_pull_with_result(
        &self,
        image: &str,
        image_ref: &str,
        get_pod_credentials: GetPodCredentials<'_>,
    ) -> (Result<bool, Error>, Option<MustAttemptImagePullResult>) {
        use MustAttemptImagePullResult as R;
        if image_ref.is_empty() {
            return (Ok(true), None);
        }

        let pulled_by_kubelet_and_record =
            (|| -> Result<(bool, Option<ImagePulledRecord>), Error> {
                // don't allow changes to the files we're using for our decision
                let _pg = self.pulled_accessors.lock(image_ref);
                let _ig = self.intent_accessors.lock(image);

                match self.records_accessor.get_image_pulled_record(image_ref)? {
                    Some(rec) => Ok((true, Some(rec))),
                    None => {
                        // Optimized check: the counter may be zero only because
                        // the kubelet restarted since the intent was written, so
                        // fall back to the actual records.
                        if self.get_intent_counter_for_image(image) > 0 {
                            return Ok((true, None));
                        }
                        let exists = self
                            .records_accessor
                            .image_pull_intent_exists(image)
                            .map_err(|e| {
                                Error(format!(
                                    "failed to check existence of an image pull intent: {e}"
                                ))
                            })?;
                        Ok((exists, None))
                    }
                }
            })();

        let (image_pulled_by_kubelet, pulled_record) = match pulled_by_kubelet_and_record {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(%e, "Unable to access cache records about image pulls");
                return (Ok(true), Some(R::Error));
            }
        };

        if !self
            .image_policy_enforcer
            .require_credential_verification_for_image(image, image_pulled_by_kubelet)
        {
            return (Ok(false), Some(R::CredentialPolicyAllowed));
        }

        let Some(pulled_record) = pulled_record else {
            // no proper record of a past pull: short-circuit
            return (Ok(true), Some(R::MustAuthenticate));
        };

        let sanitized_image = match trim_image_tag_digest(image) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(%e, image, "failed to parse image name, forcing image credentials reverification");
                return (Ok(true), Some(R::Error));
            }
        };

        let Some(cached_creds) = pulled_record.credential_mapping.get(&sanitized_image) else {
            return (Ok(true), Some(R::MustAuthenticate));
        };

        if cached_creds.node_pods_accessible {
            // anyone on this node can access the image
            return (Ok(false), Some(R::CredentialRecordFound));
        }

        if cached_creds.kubernetes_secrets.is_empty()
            && cached_creds.kubernetes_service_accounts.is_empty()
        {
            return (Ok(true), Some(R::MustAuthenticate));
        }

        let (pod_secrets, pod_service_account) = match get_pod_credentials() {
            Ok(v) => v,
            Err(e) => return (Err(e), Some(R::Error)),
        };

        for pod_secret in &pod_secrets {
            for cached_secret in &cached_creds.kubernetes_secrets {
                // check the hash length in case hashing failed while storing
                // the record in the keyring
                let hashes_match = !cached_secret.credential_hash.is_empty()
                    && pod_secret.credential_hash == cached_secret.credential_hash;
                let coordinates_match = pod_secret.uid == cached_secret.uid
                    && pod_secret.namespace == cached_secret.namespace
                    && pod_secret.name == cached_secret.name;

                if hashes_match {
                    if !coordinates_match
                        && cached_creds.kubernetes_secrets.len() < WRITE_RECORD_WHILE_MATCHING_LIMIT
                    {
                        // Only matching so far: make sure this secret is
                        // considered valid in the future. A no-op when the
                        // secret with this hash is already cached.
                        self.write_matched_secret(image, image_ref, pod_secret);
                    }
                    return (Ok(false), Some(R::CredentialRecordFound));
                }

                if coordinates_match
                    && cached_creds.kubernetes_secrets.len() < WRITE_RECORD_WHILE_MATCHING_LIMIT
                {
                    // Same secret, updated credentials (hashes differ here):
                    // remember the new hash. A no-op if it got updated meanwhile.
                    self.write_matched_secret(image, image_ref, pod_secret);
                    return (Ok(false), Some(R::CredentialRecordFound));
                }
            }
        }

        if let Some(sa) = &pod_service_account {
            if cached_creds.kubernetes_service_accounts.contains(sa) {
                // matching service account, no need to pull the image
                return (Ok(false), Some(R::CredentialRecordFound));
            }
        }

        (Ok(true), Some(R::MustAuthenticate))
    }

    fn write_matched_secret(&self, image: &str, image_ref: &str, secret: &ImagePullSecret) {
        let creds = ImagePullCredentials {
            kubernetes_secrets: vec![secret.clone()],
            ..Default::default()
        };
        if let Err(e) = self.write_pulled_record_if_changed(image, image_ref, Some(&creds)) {
            tracing::error!(%e, image, image_ref, "failed to write an image pulled record");
        }
    }

    /// `PruneUnknownRecords`: delete records of images the GC no longer
    /// knows, unless updated after the GC started (`until`).
    pub fn prune_unknown_records(&self, image_list: &[String], until: DateTime<Utc>) {
        let _g = self.pulled_accessors.global_lock();

        let (pulled_records, err) = self.records_accessor.list_image_pulled_records();
        if let Some(e) = err {
            tracing::error!(%e, "there were errors listing ImagePulledRecords, garbage collection will proceed with incomplete records list");
        }

        let in_use: HashSet<&str> = image_list.iter().map(String::as_str).collect();
        for rec in pulled_records {
            if rec.last_updated_time >= until {
                // only updated after the GC started
                continue;
            }
            if in_use.contains(rec.image_ref.as_str()) {
                continue;
            }
            if let Err(e) = self
                .records_accessor
                .delete_image_pulled_record(&rec.image_ref)
            {
                tracing::error!(%e, image_ref = %rec.image_ref, "failed to remove an ImagePulledRecord");
            }
        }
    }

    /// `initialize`: turn pull intents left by a previous kubelet run into
    /// pulled records when the runtime reports the image as present.
    /// Not thread-safe; called once from `new`.
    fn initialize(&self) {
        let (pull_intents, err) = self.records_accessor.list_image_pull_intents();
        if let Some(e) = err {
            tracing::error!(%e, "there were errors listing ImagePullIntents, continuing with an incomplete records list");
        }
        if pull_intents.is_empty() {
            return;
        }

        let image_objs = match self.image_service.list_images() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(%e, "failed to list images");
                Vec::new()
            }
        };

        let in_flight: HashSet<String> = pull_intents.into_iter().map(|i| i.image).collect();

        // A CRI image can carry several tags and digests; the intent tracks
        // one of them, so go through all.
        for image_obj in &image_objs {
            for image in search_for_existing_tag_digest(&in_flight, image_obj) {
                if let Err(e) = self.write_pulled_record_if_changed(&image, &image_obj.id, None) {
                    tracing::error!(%e, image_ref = %image_obj.id, "failed to write an image pull record");
                    continue;
                }
                if let Err(e) = self.records_accessor.delete_image_pull_intent(&image) {
                    tracing::debug!(image_name = %image, error = %e, "failed to remove image pull intent file");
                }
            }
        }
    }

    fn increment_intent_counter_for_image(&self, image: &str) {
        *self
            .intent_counters
            .lock()
            .unwrap()
            .entry(image.to_string())
            .or_insert(0) += 1;
    }

    fn decrement_intent_counter_for_image(&self, image: &str) {
        let mut m = self.intent_counters.lock().unwrap();
        let v = m.get(image).copied().unwrap_or(0) - 1;
        m.insert(image.to_string(), v);
    }

    /// `getIntentCounterForImage`.
    pub fn get_intent_counter_for_image(&self, image: &str) -> i32 {
        self.intent_counters
            .lock()
            .unwrap()
            .get(image)
            .copied()
            .unwrap_or(0)
    }

    /// Test seam for `intentCounters.Store`.
    pub fn set_intent_counter_for_image(&self, image: &str, n: i32) {
        self.intent_counters
            .lock()
            .unwrap()
            .insert(image.to_string(), n);
    }
}

impl ImagePullManager for PullManager {
    fn record_pull_intent(&self, image: &str) -> Result<(), Error> {
        PullManager::record_pull_intent(self, image)
    }
    fn record_image_pulled(
        &self,
        image: &str,
        image_ref: &str,
        credentials: Option<&ImagePullCredentials>,
    ) {
        PullManager::record_image_pulled(self, image, image_ref, credentials)
    }
    fn record_image_pull_failed(&self, image: &str) {
        PullManager::record_image_pull_failed(self, image)
    }
    fn must_attempt_image_pull(
        &self,
        image: &str,
        image_ref: &str,
        get_pod_credentials: GetPodCredentials<'_>,
    ) -> Result<bool, Error> {
        PullManager::must_attempt_image_pull(self, image, image_ref, get_pod_credentials)
    }
    fn prune_unknown_records(&self, image_list: &[String], until: DateTime<Utc>) {
        PullManager::prune_unknown_records(self, image_list, until)
    }
}

/// `searchForExistingTagDigest`: the `RepoDigests` / `RepoTags` of `image`
/// that appear in `in_flight_pulls`.
pub fn search_for_existing_tag_digest(
    in_flight_pulls: &HashSet<String>,
    image: &Image,
) -> BTreeSet<String> {
    image
        .repo_digests
        .iter()
        .chain(image.repo_tags.iter())
        .filter(|i| in_flight_pulls.contains(*i))
        .cloned()
        .collect()
}

/// `trimImageTagDigest`: the image name without tag and digest.
pub fn trim_image_tag_digest(container_image: &str) -> anyhow::Result<String> {
    parse_image_repo(container_image)
}

/// `pulledRecordMergeNewCreds`: merge `new_creds` into `orig` for
/// `image_no_tag_digest`. `None` means nothing changed (upstream returns
/// `orig, false`); `Some` is the updated copy.
pub fn pulled_record_merge_new_creds(
    orig: &ImagePulledRecord,
    image_no_tag_digest: &str,
    new_creds: Option<&ImagePullCredentials>,
) -> Option<ImagePulledRecord> {
    let new_creds = new_creds?;

    if !new_creds.node_pods_accessible
        && new_creds.kubernetes_secrets.is_empty()
        && new_creds.kubernetes_service_accounts.is_empty()
    {
        // nothing to record
        return None;
    }

    let Some(selected) = orig.credential_mapping.get(image_no_tag_digest) else {
        let mut ret = orig.clone();
        ret.credential_mapping
            .insert(image_no_tag_digest.to_string(), new_creds.clone());
        ret.last_updated_time = Utc::now();
        return Some(ret);
    };
    let mut selected = selected.clone();

    if selected.node_pods_accessible {
        return None;
    }

    if new_creds.node_pods_accessible {
        selected.node_pods_accessible = true;
        selected.kubernetes_secrets = Vec::new();
        selected.kubernetes_service_accounts = Vec::new();
    } else if !new_creds.kubernetes_secrets.is_empty() {
        let (merged, changed) =
            merge_pull_secrets(&selected.kubernetes_secrets, &new_creds.kubernetes_secrets);
        if !changed {
            return None;
        }
        selected.kubernetes_secrets = merged;
    } else if !new_creds.kubernetes_service_accounts.is_empty() {
        let (merged, changed) = merge_pull_service_accounts(
            &selected.kubernetes_service_accounts,
            &new_creds.kubernetes_service_accounts,
        );
        if !changed {
            return None;
        }
        selected.kubernetes_service_accounts = merged;
    }

    let mut ret = orig.clone();
    ret.credential_mapping
        .insert(image_no_tag_digest.to_string(), selected);
    ret.last_updated_time = Utc::now();
    Some(ret)
}

/// `mergePullSecrets`: union keyed by `(Namespace, Name, UID)`; a secret from
/// `new` wins on the hash. Sorted by Namespace, Name, UID. The flag says
/// whether the set changed (then the result is a fresh sorted vec, else a
/// copy of `orig`).
pub fn merge_pull_secrets(
    orig: &[ImagePullSecret],
    new: &[ImagePullSecret],
) -> (Vec<ImagePullSecret>, bool) {
    type Key = (String, String, String);
    let key = |s: &ImagePullSecret| -> Key { (s.namespace.clone(), s.name.clone(), s.uid.clone()) };
    let mut cred_set: BTreeMap<Key, String> = orig
        .iter()
        .map(|s| (key(s), s.credential_hash.clone()))
        .collect();

    let mut changed = false;
    for s in new {
        match cred_set.get(&key(s)) {
            Some(h) if *h == s.credential_hash => {}
            _ => {
                changed = true;
                cred_set.insert(key(s), s.credential_hash.clone());
            }
        }
    }
    if !changed {
        return (orig.to_vec(), false);
    }

    // BTreeMap iteration is the Namespace, Name, UID order of imagePullSecretLess.
    let ret = cred_set
        .into_iter()
        .map(
            |((namespace, name, uid), credential_hash)| ImagePullSecret {
                uid,
                namespace,
                name,
                credential_hash,
            },
        )
        .collect();
    (ret, true)
}

/// `mergePullServiceAccounts`: set union, sorted by Namespace, Name, UID.
pub fn merge_pull_service_accounts(
    orig: &[ImagePullServiceAccount],
    new: &[ImagePullServiceAccount],
) -> (Vec<ImagePullServiceAccount>, bool) {
    type Key = (String, String, String);
    let key = |s: &ImagePullServiceAccount| -> Key {
        (s.namespace.clone(), s.name.clone(), s.uid.clone())
    };
    let mut set: BTreeSet<Key> = orig.iter().map(key).collect();

    let mut changed = false;
    for s in new {
        if set.insert(key(s)) {
            changed = true;
        }
    }
    if !changed {
        return (orig.to_vec(), false);
    }

    let ret = set
        .into_iter()
        .map(|(namespace, name, uid)| ImagePullServiceAccount {
            uid,
            namespace,
            name,
        })
        .collect();
    (ret, true)
}
