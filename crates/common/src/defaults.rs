//! Pod-only API defaults.
//!
//! Upstream splits pod defaulting in two, and the split is load-bearing:
//!
//! - `SetDefaults_PodSpec` (`pkg/apis/core/v1/defaults.go:211`) runs for a Pod
//!   **and** for every embedded `PodTemplateSpec` — see the generated
//!   `zz_generated.defaults.go`, where `SetDefaults_PodSpec` is invoked from
//!   `SetObjectDefaults_Deployment`, `_ReplicaSet`, `_Job`, and friends.
//! - `SetDefaults_Pod` (defaults.go:164) runs **only** on a standalone `v1.Pod`
//!   (`zz_generated.defaults.go:208`, inside `SetObjectDefaults_Pod`).
//!
//! This module is the second one. Upstream states the reason inline
//! (defaults.go:165-167):
//!
//! ```text
//! // If limits are specified, but requests are not, default requests to limits
//! // This is done here rather than a more specific defaulting pass on v1.ResourceRequirements
//! // because we only want this defaulting semantic to take place on a v1.Pod and not a v1.PodTemplate
//! ```
//!
//! It lives in `common` rather than in the api-server because the api-server is
//! not the only decoder of a `v1.Pod`. The kubelet reads **static pod**
//! manifests straight off disk, and upstream defaults those too — the manifest
//! goes through `runtime.Decode(legacyscheme.Codecs.UniversalDecoder(), json)`
//! (`pkg/kubelet/config/common.go:122`), and decoding a versioned object runs
//! its defaulters. A static pod that skipped this pass would be the one pod in
//! the cluster whose requests disagree with every other pod's.

use crate::resources::pod::{Container, PodSpec};

/// `SetDefaults_{Secret,ConfigMap,DownwardAPI,Projected}VolumeSource`
/// (`pkg/apis/core/v1/defaults.go`): `defaultMode` is 0644 when unset.
///
/// Pod volumes that never pass through the api-server (static pods) need this
/// applied by the kubelet's decoder, as upstream's `SetObjectDefaults_Pod` does.
pub fn default_volume_source_modes(spec: &mut PodSpec) {
    const DEFAULT_MODE: i32 = 0o644;
    for vol in spec.volumes.iter_mut().flatten() {
        if let Some(s) = vol.secret.as_mut() {
            s.default_mode.get_or_insert(DEFAULT_MODE);
        }
        if let Some(c) = vol.config_map.as_mut() {
            c.default_mode.get_or_insert(DEFAULT_MODE);
        }
        if let Some(d) = vol.downward_api.as_mut() {
            d.default_mode.get_or_insert(DEFAULT_MODE);
        }
        if let Some(p) = vol.projected.as_mut() {
            p.default_mode.get_or_insert(DEFAULT_MODE);
        }
    }
}

/// Default every missing container request from the matching limit, across
/// `spec.containers` and `spec.initContainers`.
///
/// Port of the resource block of upstream `SetDefaults_Pod`
/// (`pkg/apis/core/v1/defaults.go:168-192`), which is two verbatim-identical
/// loops — one over `Spec.Containers`, one over `Spec.InitContainers`.
///
/// Ephemeral containers are deliberately **not** defaulted: upstream has no
/// third loop for them, and they cannot declare resources in the first place.
///
/// Idempotent, so it is safe to run again after mutating webhooks the way
/// upstream re-runs defaulting on the mutated object.
pub fn default_pod_requests_from_limits(spec: &mut PodSpec) {
    for container in spec
        .containers
        .iter_mut()
        .chain(spec.init_containers.iter_mut().flatten())
    {
        default_container_requests_from_limits(container);
    }

    // defaults.go:194-199 - "Pod Requests default values must be applied after
    // container-level default values have been populated."
    if crate::feature_gates::enabled(crate::feature_gates::Feature::PodLevelResources) {
        default_huge_page_pod_limits(spec);
        default_pod_level_requests(spec);
    }
}

/// Port of upstream `defaultPodRequests` (`pkg/apis/core/v1/defaults.go:436-479`).
///
/// Only when pod-level limits are set (`len(Limits) == 0` returns early), a
/// missing pod-level request is defaulted from (1) the aggregated container
/// request, for overcommittable (native, non-hugepage) resources, then (2) the
/// pod-level limit. This is what makes a pod carrying only
/// `spec.resources.limits` Guaranteed.
pub fn default_pod_level_requests(spec: &mut PodSpec) {
    use crate::quota::{aggregate_container_resources, is_supported_pod_level_resource};

    let Some(resources) = spec.resources.as_ref() else {
        return;
    };
    let Some(limits) = resources.limits.clone().filter(|l| !l.is_empty()) else {
        return;
    };
    let mut pod_reqs = resources.requests.clone().unwrap_or_default();

    let pod = crate::resources::Pod::new("", spec.clone());
    for (key, qty) in aggregate_container_resources(&pod, true) {
        // IsOvercommitAllowed = IsNativeResource && !IsHugePageResourceName
        // (pkg/apis/core/v1/helper/helpers.go:130-133).
        if !pod_reqs.contains_key(&key)
            && is_supported_pod_level_resource(&key)
            && crate::quota::is_native_resource_name(&key)
            && !crate::quota::is_hugepage_resource_name(&key)
        {
            pod_reqs.insert(key, qty.to_string());
        }
    }
    for (key, lim) in &limits {
        if !pod_reqs.contains_key(key) && is_supported_pod_level_resource(key) {
            pod_reqs.insert(key.clone(), lim.clone());
        }
    }
    if !pod_reqs.is_empty() {
        if let Some(r) = spec.resources.as_mut() {
            r.requests = Some(pod_reqs);
        }
    }
}

/// Port of upstream `defaultHugePagePodLimits` (`defaults.go:482-526`): when
/// containers set a hugepages limit and the pod-level block (already partly
/// specified) has neither that limit nor a request for it, the pod-level limit
/// defaults to the aggregated container hugepages limit.
pub fn default_huge_page_pod_limits(spec: &mut PodSpec) {
    use crate::quota::{
        aggregate_container_resources, is_hugepage_resource_name, is_supported_pod_level_resource,
    };

    let Some(resources) = spec.resources.as_ref() else {
        return;
    };
    let has = |m: &Option<std::collections::HashMap<String, String>>| {
        m.as_ref().is_some_and(|m| !m.is_empty())
    };
    if !has(&resources.limits) && !has(&resources.requests) {
        return;
    }
    let mut pod_lims = resources.limits.clone().unwrap_or_default();

    let pod = crate::resources::Pod::new("", spec.clone());
    for (key, qty) in aggregate_container_resources(&pod, false) {
        if !is_supported_pod_level_resource(&key) || !is_hugepage_resource_name(&key) {
            continue;
        }
        if resources
            .requests
            .as_ref()
            .is_some_and(|r| r.contains_key(&key))
        {
            continue;
        }
        pod_lims.entry(key).or_insert_with(|| qty.to_string());
    }
    if !pod_lims.is_empty() {
        if let Some(r) = spec.resources.as_mut() {
            r.limits = Some(pod_lims);
        }
    }
}

/// One container's share of [`default_pod_requests_from_limits`].
///
/// Mirrors the loop body at `pkg/apis/core/v1/defaults.go:169-179`:
///
/// ```text
/// if container.Resources.Limits != nil {
///     if container.Resources.Requests == nil {
///         container.Resources.Requests = make(v1.ResourceList)
///     }
///     for key, value := range container.Resources.Limits {
///         if _, exists := container.Resources.Requests[key]; !exists {
///             container.Resources.Requests[key] = value.DeepCopy()
///         }
///     }
/// }
/// ```
///
/// Note the guard is `Limits != nil`, not "limits is non-empty": a container
/// carrying an explicit empty `limits` map gets an empty `requests` map, and
/// serialises with `"requests":{}` exactly as upstream does. An **absent**
/// `limits` leaves `requests` untouched.
///
/// A request that is already present wins — upstream fills only keys for which
/// `!exists` holds, so an explicit `requests.cpu` is never overwritten by a
/// larger `limits.cpu`.
pub fn default_container_requests_from_limits(container: &mut Container) {
    let Some(resources) = container.resources.as_mut() else {
        return;
    };
    let Some(limits) = resources.limits.clone() else {
        return;
    };
    let requests = resources.requests.get_or_insert_with(Default::default);
    for (key, value) in limits {
        requests.entry(key).or_insert(value);
    }
}

/// `SetDefaults_ExactDeviceRequest` / `SetDefaults_DeviceSubRequest`
/// (`pkg/apis/resource/v1/defaults.go:31-49`; the v1beta1/v1beta2 variants are
/// the same): an unset `allocationMode` is `ExactCount`, and an `ExactCount`
/// request with `count` 0 asks for 1 device. Upstream runs this when a
/// ResourceClaim or ResourceClaimTemplate is decoded
/// (`zz_generated.defaults.go`: `SetObjectDefaults_ResourceClaim`,
/// `_ResourceClaimTemplate`).
pub fn default_resource_claim_spec(spec: &mut crate::resources::dra::ResourceClaimSpec) {
    use crate::resources::dra::DeviceAllocationMode;
    fn default_request(mode: &mut Option<DeviceAllocationMode>, count: &mut Option<i64>) {
        if mode.is_none() {
            *mode = Some(DeviceAllocationMode::ExactCount);
        }
        if *mode == Some(DeviceAllocationMode::ExactCount) && count.unwrap_or(0) == 0 {
            *count = Some(1);
        }
    }
    for req in &mut spec.devices.requests {
        if let Some(exactly) = req.exactly.as_mut() {
            default_request(&mut exactly.allocation_mode, &mut exactly.count);
            default_device_tolerations(&mut exactly.tolerations);
        }
        for sub in &mut req.first_available {
            default_request(&mut sub.allocation_mode, &mut sub.count);
            default_device_tolerations(&mut sub.tolerations);
        }
    }
}

/// The toleration default of `SetObjectDefaults_ResourceClaim` /
/// `_ResourceClaimTemplate` (`pkg/apis/resource/v1/zz_generated.defaults.go:46-114`):
/// an empty `operator` is `Equal`.
fn default_device_tolerations(tolerations: &mut [crate::resources::dra::DeviceToleration]) {
    use crate::resources::dra::TolerationOperator;
    for t in tolerations {
        if t.operator.is_none() {
            t.operator = Some(TolerationOperator::Equal);
        }
    }
}

/// `SetObjectDefaults_ResourceClaim` (zz_generated.defaults.go:46-77): the
/// spec defaults, plus the `Equal` operator default on the tolerations the
/// allocation copied into `status.allocation.devices.results`.
pub fn default_resource_claim(claim: &mut crate::resources::dra::ResourceClaim) {
    default_resource_claim_spec(&mut claim.spec);
    if let Some(allocation) = claim.status.as_mut().and_then(|s| s.allocation.as_mut()) {
        for result in &mut allocation.devices.results {
            default_device_tolerations(&mut result.tolerations);
        }
    }
}

/// `SetObjectDefaults_ResourceClaimTemplate` (zz_generated.defaults.go:86-108).
pub fn default_resource_claim_template(
    template: &mut crate::resources::dra::ResourceClaimTemplate,
) {
    default_resource_claim_spec(&mut template.spec.spec);
}

/// `SetDefaults_DeviceTaint` (`pkg/apis/resource/v1/defaults.go:51-56`): an
/// unset `timeAdded` is now, truncated to the second.
pub fn default_device_taint(taint: &mut crate::resources::dra::DeviceTaint) {
    if taint.time_added.is_none() {
        taint.time_added = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0);
    }
}

/// `SetObjectDefaults_ResourceSlice` (zz_generated.defaults.go:121-129):
/// `SetDefaults_DeviceTaint` on every device taint.
pub fn default_resource_slice(slice: &mut crate::resources::ResourceSlice) {
    for device in &mut slice.spec.devices {
        for taint in &mut device.taints {
            default_device_taint(taint);
        }
    }
}
