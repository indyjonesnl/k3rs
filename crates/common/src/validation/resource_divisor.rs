//! Container `resourceFieldRef.divisor` validation.
//!
//! Port of `validateContainerResourceDivisor`
//! (`pkg/apis/core/validation/validation.go:2992-3022`, called from
//! `validateContainerResourceFieldSelector` at `:2915`) and the divisor sets at
//! `:2978-2991`, release-1.35.

use crate::quantity::Quantity;
use crate::validation::field::{Error, ErrorList, Path};

/// `hugepagesRequestsPrefixDownwardAPI` / `hugepagesLimitsPrefixDownwardAPI` (`:2807-2808`).
const HUGEPAGES_REQUESTS_PREFIX_DOWNWARD_API: &str = "requests.hugepages-";
const HUGEPAGES_LIMITS_PREFIX_DOWNWARD_API: &str = "limits.hugepages-";

/// `validContainerResourceDivisorForCPU`.
const VALID_DIVISOR_FOR_CPU: &[&str] = &["1m", "1"];
/// `validContainerResourceDivisorForMemory`, `...ForHugePages` and
/// `...ForEphemeralStorage` are the same set.
const VALID_DIVISOR_FOR_MEMORY_LIKE: &[&str] = &[
    "1", "1k", "1M", "1G", "1T", "1P", "1E", "1Ki", "1Mi", "1Gi", "1Ti", "1Pi", "1Ei",
];

/// `validateContainerResourceDivisor`. A zero (unset) divisor is always valid.
pub fn validate_container_resource_divisor(
    r_name: &str,
    divisor: &Quantity,
    fld_path: &Path,
) -> ErrorList {
    let mut errs = ErrorList::new();
    if divisor.is_zero() {
        return errs;
    }
    let d = divisor.canonical_string();
    let d = d.as_str();
    let path = fld_path.child("divisor");
    match r_name {
        "limits.cpu" | "requests.cpu" if !VALID_DIVISOR_FOR_CPU.contains(&d) => {
            errs.push(Error::invalid(
                &path,
                r_name.to_string(),
                "only divisor's values 1m and 1 are supported with the cpu resource",
            ));
        }
        "limits.memory" | "requests.memory" if !VALID_DIVISOR_FOR_MEMORY_LIKE.contains(&d) => {
            errs.push(Error::invalid(
                    &path,
                    r_name.to_string(),
                    "only divisor's values 1, 1k, 1M, 1G, 1T, 1P, 1E, 1Ki, 1Mi, 1Gi, 1Ti, 1Pi, 1Ei are supported with the memory resource",
                ));
        }
        "limits.ephemeral-storage" | "requests.ephemeral-storage"
            if !VALID_DIVISOR_FOR_MEMORY_LIKE.contains(&d) =>
        {
            errs.push(Error::invalid(
                    &path,
                    r_name.to_string(),
                    "only divisor's values 1, 1k, 1M, 1G, 1T, 1P, 1E, 1Ki, 1Mi, 1Gi, 1Ti, 1Pi, 1Ei are supported with the local ephemeral storage resource",
                ));
        }
        _ => {}
    }
    if (r_name.starts_with(HUGEPAGES_REQUESTS_PREFIX_DOWNWARD_API)
        || r_name.starts_with(HUGEPAGES_LIMITS_PREFIX_DOWNWARD_API))
        && !VALID_DIVISOR_FOR_MEMORY_LIKE.contains(&d)
    {
        errs.push(Error::invalid(
            &path,
            r_name.to_string(),
            "only divisor's values 1, 1k, 1M, 1G, 1T, 1P, 1E, 1Ki, 1Mi, 1Gi, 1Ti, 1Pi, 1Ei are supported with the hugepages resource",
        ));
    }
    errs
}
