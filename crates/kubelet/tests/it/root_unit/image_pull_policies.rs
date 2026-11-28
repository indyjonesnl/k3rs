//! Ports of `pkg/kubelet/images/pullmanager/image_pull_policies_test.go`
//! (TestNeverVerifyPreloadedPullPolicy, TestNewNeverVerifyAllowListedPullPolicy)
//! plus the policy factory and `StripedLockSet` (locks.go).

use kubernetes_rs_kubelet::image_manager::image_pull_policies::*;

fn v(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn image_pull_policies_never_verify_preloaded() {
    let p = never_verify_preloaded_pull_policy();
    assert!(!p.require_credential_verification_for_image("test-image", false));
    assert!(p.require_credential_verification_for_image("test-image", true));
}

#[test]
fn image_pull_policies_never_and_always_verify() {
    for pulled in [false, true] {
        assert!(!never_verify_image_pull_policy()
            .require_credential_verification_for_image("i", pulled));
        assert!(always_verify_image_pull_policy()
            .require_credential_verification_for_image("i", pulled));
    }
}

#[test]
fn image_pull_policies_allowlisted() {
    struct Case {
        name: &'static str,
        allow: Vec<String>,
        absolutes: usize,
        wildcards: usize,
        want: bool,
    }
    let cases = [
        Case {
            name: "not in allowlist",
            allow: v(&[
                "test.io/test/image1",
                "test.io/test/image2",
                "test.io/test/image3",
            ]),
            absolutes: 3,
            wildcards: 0,
            want: true,
        },
        Case {
            name: "duplicates collapse, not in allowlist",
            allow: v(&[
                "test.io/test/image1",
                "test.io/test/image3",
                "test.io/test/image2",
                "test.io/test/image3",
            ]),
            absolutes: 3,
            wildcards: 0,
            want: true,
        },
        Case {
            name: "appears in allowlist",
            allow: v(&[
                "test.io/test/image1",
                "test.io/test/image2",
                "test.io/test/test-image",
                "test.io/test/image3",
            ]),
            absolutes: 4,
            wildcards: 0,
            want: false,
        },
        Case {
            name: "different repo wildcard",
            allow: v(&[
                "test.io/test/image1",
                "test.io/test/image2",
                "different.repo/test/*",
            ]),
            absolutes: 2,
            wildcards: 1,
            want: true,
        },
        Case {
            name: "matches org wildcard",
            allow: v(&[
                "test.io/test/image1",
                "test.io/test/image2",
                "test.io/test/*",
            ]),
            absolutes: 2,
            wildcards: 1,
            want: false,
        },
        Case {
            name: "matches repo wildcard",
            allow: v(&["test.io/test/image1", "test.io/test/image2", "test.io/*"]),
            absolutes: 2,
            wildcards: 1,
            want: false,
        },
    ];
    for c in cases {
        let p = NeverVerifyAllowlistedImagesPolicy::new(&c.allow)
            .unwrap_or_else(|e| panic!("{}: {e}", c.name));
        assert_eq!(p.absolute_urls_len(), c.absolutes, "{}", c.name);
        assert_eq!(p.prefixes_len(), c.wildcards, "{}", c.name);
        // The records flag never changes the allowlist's answer.
        for pulled in [false, true] {
            assert_eq!(
                p.require_credential_verification_for_image("test.io/test/test-image", pulled),
                c.want,
                "{}",
                c.name
            );
        }
    }
}

#[test]
fn image_pull_policies_allowlist_pattern_errors() {
    for bad in [
        "image.repo/pokus*/imagename",
        "image.repo/pokus*",
        "image.repo/*/imagename",
        "/*",
        "image.repo/",
        "",
        "*",
        "test.io/test/image1:tagged",
        "test.io/test/image1@sha256:38a8906435c4dd5f4258899d46621bfd8eea3ad6ff494ee3c2f17ef0321625bd",
        "test.io/test/image1 ",
    ] {
        assert!(
            NeverVerifyAllowlistedImagesPolicy::new(&v(&[bad])).is_err(),
            "{bad:?} must be rejected"
        );
        assert!(validate_allowlist_images_patterns(&v(&[bad])).is_err(), "{bad:?}");
    }
    assert!(validate_allowlist_images_patterns(&v(&["test.io/*", "test.io/a/b"])).is_ok());
}

#[test]
fn image_pull_policies_factory() {
    use ImagePullCredentialsVerificationPolicy::*;
    let allow = v(&["test.io/*"]);
    let never = new_image_pull_credential_verification_policy(NeverVerify, &[]).unwrap();
    assert!(!never.require_credential_verification_for_image("x", true));
    let pre =
        new_image_pull_credential_verification_policy(NeverVerifyPreloadedImages, &[]).unwrap();
    assert!(pre.require_credential_verification_for_image("x", true));
    let al = new_image_pull_credential_verification_policy(NeverVerifyAllowlistedImages, &allow)
        .unwrap();
    assert!(!al.require_credential_verification_for_image("test.io/a", false));
    assert!(al.require_credential_verification_for_image("other.io/a", false));
    let always = new_image_pull_credential_verification_policy(AlwaysVerify, &[]).unwrap();
    assert!(always.require_credential_verification_for_image("x", false));
    assert_eq!(
        ImagePullCredentialsVerificationPolicy::parse("Bogus").unwrap_err(),
        "unknown image pull credential verification policy: Bogus"
    );
    assert_eq!(
        ImagePullCredentialsVerificationPolicy::parse("AlwaysVerify"),
        Ok(AlwaysVerify)
    );
}

/// locks.go: same key serialises, size is normalised into [1, 31].
#[test]
fn image_pull_policies_striped_lock_set() {
    for size in [-5, 0, 1, 31, 100] {
        let s = StripedLockSet::new(size);
        let g = s.lock("a");
        drop(g);
        drop(s.global_lock());
        // Not poisoned / not deadlocked after release.
        drop(s.lock("a"));
    }
    let s = std::sync::Arc::new(StripedLockSet::new(1));
    let g = s.lock("one");
    let s2 = s.clone();
    let h = std::thread::spawn(move || {
        let _g = s2.lock("two"); // one stripe: blocks until "one" is released
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(!h.is_finished());
    drop(g);
    h.join().unwrap();
}
