//! `validateContainerResourceDivisor` (pkg/apis/core/validation/validation.go:2992).
//! release-1.35 has no dedicated upstream test for it, so these cover every
//! branch of the function: the unset divisor, each resource family, and the
//! exact error text.
use kubernetes_rs_common::quantity::Quantity;
use kubernetes_rs_common::validation::field::Path;
use kubernetes_rs_common::validation::resource_divisor::validate_container_resource_divisor;

fn check(resource: &str, divisor: &str) -> Vec<String> {
    let q = Quantity::parse(divisor).unwrap();
    validate_container_resource_divisor(resource, &q, &Path::new("fieldRef"))
        .iter()
        .map(|e| e.to_string())
        .collect()
}

const MEM_MSG: &str = "only divisor's values 1, 1k, 1M, 1G, 1T, 1P, 1E, 1Ki, 1Mi, 1Gi, 1Ti, 1Pi, 1Ei are supported with the memory resource";

#[test]
fn resource_divisor_unset_is_valid() {
    for r in [
        "limits.cpu",
        "requests.memory",
        "limits.hugepages-2Mi",
        "limits.ephemeral-storage",
    ] {
        assert!(check(r, "0").is_empty(), "{r}");
    }
}

#[test]
fn resource_divisor_cpu() {
    for ok in ["1m", "1", "1000m"] {
        assert!(check("limits.cpu", ok).is_empty(), "{ok}");
        assert!(check("requests.cpu", ok).is_empty(), "{ok}");
    }
    for bad in ["2", "10m", "1k", "500m"] {
        let errs = check("requests.cpu", bad);
        assert_eq!(errs.len(), 1, "{bad}");
        assert!(
            errs[0].contains("only divisor's values 1m and 1 are supported with the cpu resource")
        );
        assert!(errs[0].starts_with("fieldRef.divisor: Invalid value: \"requests.cpu\""));
    }
}

#[test]
fn resource_divisor_memory_and_storage() {
    for ok in [
        "1", "1k", "1M", "1G", "1T", "1P", "1E", "1Ki", "1Mi", "1Gi", "1Ti", "1Pi", "1Ei",
    ] {
        assert!(check("limits.memory", ok).is_empty(), "{ok}");
        assert!(check("requests.ephemeral-storage", ok).is_empty(), "{ok}");
    }
    for bad in ["1m", "2", "10Mi", "1500"] {
        let e = check("requests.memory", bad);
        assert_eq!(e.len(), 1, "{bad}");
        assert!(e[0].contains(MEM_MSG));
        let e = check("limits.ephemeral-storage", bad);
        assert!(e[0].contains("are supported with the local ephemeral storage resource"));
    }
}

#[test]
fn resource_divisor_hugepages_and_unrelated() {
    assert!(check("requests.hugepages-2Mi", "1Mi").is_empty());
    let e = check("limits.hugepages-1Gi", "2");
    assert_eq!(e.len(), 1);
    assert!(e[0].contains("are supported with the hugepages resource"));
    // Resources outside the families carry no divisor rule.
    assert!(check("limits.example.com/foo", "2").is_empty());
}
