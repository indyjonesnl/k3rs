//! Image pull credential verification policies and the striped lock set.
//!
//! Port of `pkg/kubelet/images/pullmanager/image_pull_policies.go`
//! (`ImagePullPolicyEnforcer`, `NewImagePullCredentialVerificationPolicy`,
//! `NeverVerifyImagePullPolicy`, `NeverVerifyPreloadedPullPolicy`,
//! `AlwaysVerifyImagePullPolicy`, `NeverVerifyAllowlistedImages`,
//! `ValidateAllowlistImagesPatterns`, `getAllowlistImagePattern`) and
//! `locks.go` (`StripedLockSet`), release-1.35.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard};

use crate::credentialprovider::parse_image_repo;
use crate::image_manager::parse_image_name;

/// `kubeletconfiginternal.ImagePullCredentialsVerificationPolicy`
/// (pkg/kubelet/apis/config/types.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImagePullCredentialsVerificationPolicy {
    NeverVerify,
    NeverVerifyPreloadedImages,
    NeverVerifyAllowlistedImages,
    AlwaysVerify,
}

impl ImagePullCredentialsVerificationPolicy {
    /// The config string (`"NeverVerify"`, ...).
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "NeverVerify" => Ok(Self::NeverVerify),
            "NeverVerifyPreloadedImages" => Ok(Self::NeverVerifyPreloadedImages),
            "NeverVerifyAllowlistedImages" => Ok(Self::NeverVerifyAllowlistedImages),
            "AlwaysVerify" => Ok(Self::AlwaysVerify),
            other => Err(format!(
                "unknown image pull credential verification policy: {other}"
            )),
        }
    }
}

/// `ImagePullPolicyEnforcer`: whether credential verification is required for
/// `image`; `image_pulled_by_kubelet` says pull intent/record files exist for it.
pub trait ImagePullPolicyEnforcer: Send + Sync {
    fn require_credential_verification_for_image(
        &self,
        image: &str,
        image_pulled_by_kubelet: bool,
    ) -> bool;
}

/// `ImagePullPolicyEnforcerFunc`.
pub struct EnforcerFn<F: Fn(&str, bool) -> bool + Send + Sync>(pub F);

impl<F: Fn(&str, bool) -> bool + Send + Sync> ImagePullPolicyEnforcer for EnforcerFn<F> {
    fn require_credential_verification_for_image(&self, image: &str, pulled: bool) -> bool {
        (self.0)(image, pulled)
    }
}

/// `NewImagePullCredentialVerificationPolicy`.
pub fn new_image_pull_credential_verification_policy(
    policy: ImagePullCredentialsVerificationPolicy,
    image_allow_list: &[String],
) -> Result<Box<dyn ImagePullPolicyEnforcer>, String> {
    use ImagePullCredentialsVerificationPolicy::*;
    Ok(match policy {
        NeverVerify => Box::new(never_verify_image_pull_policy()),
        NeverVerifyPreloadedImages => Box::new(never_verify_preloaded_pull_policy()),
        NeverVerifyAllowlistedImages => {
            Box::new(NeverVerifyAllowlistedImagesPolicy::new(image_allow_list)?)
        }
        AlwaysVerify => Box::new(always_verify_image_pull_policy()),
    })
}

/// `NeverVerifyImagePullPolicy`: never require verification.
pub fn never_verify_image_pull_policy() -> EnforcerFn<impl Fn(&str, bool) -> bool + Send + Sync> {
    EnforcerFn(|_, _| false)
}

/// `NeverVerifyPreloadedPullPolicy`: verify only images the kubelet pulled.
pub fn never_verify_preloaded_pull_policy() -> EnforcerFn<impl Fn(&str, bool) -> bool + Send + Sync>
{
    EnforcerFn(|_, pulled| pulled)
}

/// `AlwaysVerifyImagePullPolicy`: always require verification.
pub fn always_verify_image_pull_policy() -> EnforcerFn<impl Fn(&str, bool) -> bool + Send + Sync> {
    EnforcerFn(|_, _| true)
}

/// `NeverVerifyAllowlistedImages`: no verification for images that match the
/// allowlist; everything else is verified.
#[derive(Debug, Default)]
pub struct NeverVerifyAllowlistedImagesPolicy {
    absolute_urls: HashSet<String>,
    prefixes: Vec<String>,
}

impl NeverVerifyAllowlistedImagesPolicy {
    /// `NewNeverVerifyAllowListedPullPolicy`.
    pub fn new(allow_list: &[String]) -> Result<Self, String> {
        let mut policy = Self::default();
        for pattern in allow_list {
            let (normalized, is_wildcard) = get_allowlist_image_pattern(pattern)?;
            if is_wildcard {
                policy.prefixes.push(normalized);
            } else {
                policy.absolute_urls.insert(normalized);
            }
        }
        Ok(policy)
    }

    /// Number of absolute image URLs in the allowlist.
    pub fn absolute_urls_len(&self) -> usize {
        self.absolute_urls.len()
    }

    /// Number of wildcard prefixes in the allowlist.
    pub fn prefixes_len(&self) -> usize {
        self.prefixes.len()
    }

    fn image_matches(&self, image: &str) -> bool {
        self.absolute_urls.contains(image) || self.prefixes.iter().any(|p| image.starts_with(p))
    }
}

impl ImagePullPolicyEnforcer for NeverVerifyAllowlistedImagesPolicy {
    fn require_credential_verification_for_image(&self, image: &str, _pulled: bool) -> bool {
        !self.image_matches(image)
    }
}

/// `ValidateAllowlistImagesPatterns`.
pub fn validate_allowlist_images_patterns(patterns: &[String]) -> Result<(), String> {
    patterns
        .iter()
        .try_for_each(|p| get_allowlist_image_pattern(p).map(|_| ()))
}

/// `getAllowlistImagePattern`: the pattern with a wildcard's `*` trimmed, and
/// whether it was a wildcard (`registry/*`).
fn get_allowlist_image_pattern(pattern: &str) -> Result<(String, bool), String> {
    if pattern != pattern.trim() {
        return Err(format!(
            "leading/trailing spaces are not allowed: {pattern}"
        ));
    }
    let mut trimmed = pattern;
    let is_wildcard = pattern.ends_with("/*");
    if is_wildcard {
        // strings.TrimSuffix removes exactly one "*".
        trimmed = &pattern[..pattern.len() - 1];
    }
    if trimmed.is_empty() {
        return Err(format!("the supplied pattern is too short: {pattern}"));
    }
    if trimmed.contains('*') {
        return Err(format!(
            "not a valid wildcard pattern, only patterns ending with '/*' are allowed: {pattern}"
        ));
    }
    if is_wildcard {
        if trimmed.len() == 1 {
            return Err("at least registry hostname is required".into());
        }
        return Ok((trimmed.to_string(), true));
    }
    parse_image_name(trimmed).map_err(|e| format!("failed to parse as an image name: {e}"))?;
    // `image.Name()`: the normalised name without tag or digest.
    let name =
        parse_image_repo(trimmed).map_err(|e| format!("failed to parse as an image name: {e}"))?;
    if trimmed != name {
        return Err(format!(
            "neither tag nor digest is accepted in an image reference: {pattern}"
        ));
    }
    Ok((trimmed.to_string(), false))
}

/// `StripedLockSet` (locks.go): context locking by string key over a
/// size-limited set of locks.
pub struct StripedLockSet {
    locks: Vec<Mutex<()>>,
    size: u32,
}

impl StripedLockSet {
    /// `NewStripedLockSet`: `size` is normalised into `[1, 31]` (the doc
    /// comment of `NewStripedLockSet`; upstream sizes the slice that way).
    pub fn new(size: i32) -> Self {
        let size = size.clamp(1, 31) as u32;
        Self {
            locks: (0..size).map(|_| Mutex::new(())).collect(),
            size,
        }
    }

    /// `Lock(key)`: held until the guard drops (`Unlock`).
    pub fn lock(&self, key: &str) -> MutexGuard<'_, ()> {
        self.locks[key_to_id(key, self.size) as usize]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// `GlobalLock()`: every lock, in order; released when dropped.
    pub fn global_lock(&self) -> Vec<MutexGuard<'_, ()>> {
        self.locks
            .iter()
            .map(|l| l.lock().unwrap_or_else(|e| e.into_inner()))
            .collect()
    }
}

/// `keyToID`: `fnv.New32()` (FNV-1, not 1a) of the key modulo the size.
fn key_to_id(key: &str, slice_size: u32) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in key.bytes() {
        h = h.wrapping_mul(0x0100_0193);
        h ^= u32::from(b);
    }
    h % slice_size
}
