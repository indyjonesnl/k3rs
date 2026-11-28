//! Discovery `storageVersionHash` (#3500).
//!
//! Upstream sources (release-1.35):
//! * `staging/src/k8s.io/apiserver/pkg/endpoints/discovery/storageversionhash.go:28-36`
//!   (`StorageVersionHash`)
//! * `staging/src/k8s.io/apiserver/pkg/endpoints/installer.go:488-498` (the
//!   hash is set only when the `StorageVersionHash` gate is on and the storage
//!   is a `rest.StorageVersionProvider`, from the storage versioner's GVK)

use super::{Example, GroupResource, ResourceEncodingConfig};
use crate::resource_encoding::storage_codec_versions;
use base64::Engine;
use sha2::{Digest, Sha256};

/// `discovery.StorageVersionHash`: the first 8 bytes of the SHA-256 of
/// `group/version/kind`, standard base64.
pub fn storage_version_hash(group: &str, version: &str, kind: &str) -> String {
    let gvk = format!("{group}/{version}/{kind}");
    let digest = Sha256::digest(gvk.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(&digest[..8])
}

/// Only `genericregistry.Store` implements `rest.StorageVersionProvider`
/// (staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go:1694).
/// The top-level resources served by a non-Store `rest.Storage` never get a
/// hash: pkg/registry/authentication/{tokenreview,selfsubjectreview},
/// pkg/registry/authorization/{subjectaccessreview,localsubjectaccessreview,
/// selfsubjectaccessreview,selfsubjectrulesreview}, the core
/// `componentstatuses` (pkg/registry/core/componentstatus/rest.go) and
/// `bindings` (pkg/registry/core/rest/storage_core.go:253, `LegacyBindingREST`).
fn is_store_backed(r: &GroupResource) -> bool {
    !matches!(
        (r.group.as_str(), r.resource.as_str()),
        (
            "authentication.k8s.io",
            "tokenreviews" | "selfsubjectreviews"
        ) | (
            "authorization.k8s.io",
            "subjectaccessreviews"
                | "localsubjectaccessreviews"
                | "selfsubjectaccessreviews"
                | "selfsubjectrulesreviews"
        ) | ("", "componentstatuses" | "bindings")
    )
}

/// The hash `installer.go:488-498` stamps on a top-level resource: the GVK of
/// the storage codec's `EncodeVersioner` (`DefaultStorageFactory.NewConfig`,
/// storage_factory.go:247-263), i.e. the *storage* version, not the served
/// one. `None` when the resource is not storage-backed in the scheme
/// (`isStorageVersionProvider` false) or the version cannot be resolved.
pub fn discovery_storage_version_hash(
    config: &dyn ResourceEncodingConfig,
    resource: &GroupResource,
    kind: &str,
) -> Option<String> {
    if !is_store_backed(resource) {
        return None;
    }
    // Groups kube-apiserver's own storage factory does not know. Each is served
    // by a Store-backed API with a single storage version, v1:
    // * apiextensions.k8s.io: apiextensions-apiserver `pkg/apiserver/apiserver.go`
    //   (its own scheme registers only v1, `pkg/apis/apiextensions/install`).
    // * apiregistration.k8s.io: kube-aggregator `pkg/apiserver/apiserver.go`
    //   (`apiGroupInfo` with only the v1 `VersionedResourcesStorageMap`).
    // * snapshot.storage.k8s.io: external-snapshotter CRDs, whose discovery hash
    //   is `discovery.StorageVersionHash(group, storageVersion, kind)`
    //   (apiextensions `pkg/apiserver/customresource_discovery_controller.go`)
    //   with storage version v1.
    if matches!(
        resource.group.as_str(),
        "apiextensions.k8s.io" | "apiregistration.k8s.io" | "snapshot.storage.k8s.io"
    ) {
        return Some(storage_version_hash(&resource.group, "v1", kind));
    }
    let example = Example::new(&resource.group, kind);
    let versions = storage_codec_versions(config, resource, resource, Some(&example)).ok()?;
    let gv = versions.storage_version;
    Some(storage_version_hash(&gv.group, &gv.version, kind))
}
