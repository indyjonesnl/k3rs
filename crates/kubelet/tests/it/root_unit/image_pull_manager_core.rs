//! Ports of `pkg/kubelet/images/pullmanager/image_pull_manager_test.go`
//! (release-1.35) over an in-memory `PullRecordsAccessor` instead of the
//! fs accessor + testdata files: Test_pulledRecordMergeNewCreds,
//! TestFileBasedImagePullManager_{MustAttemptImagePull,RecordPullIntent,
//! RecordImagePulled,initialize,PruneUnknownRecords}, Test_mergePullServiceAccounts.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeZone, Utc};
use kubernetes_rs_kubelet::image_gc::Image;
use kubernetes_rs_kubelet::image_manager::image_pull_manager::*;
use kubernetes_rs_kubelet::image_manager::image_pull_manager_core::*;
use kubernetes_rs_kubelet::image_manager::image_pull_policies::*;

#[derive(Default)]
struct MemAccessor {
    intents: Mutex<HashSet<String>>,
    pulled: Mutex<BTreeMap<String, ImagePulledRecord>>,
    pulled_writes: Mutex<usize>,
    fail_get: Mutex<bool>,
    fail_intent_exists: Mutex<bool>,
    fail_delete_intent: Mutex<bool>,
}

impl PullRecordsAccessor for MemAccessor {
    fn list_image_pull_intents(&self) -> (Vec<ImagePullIntent>, Option<Error>) {
        let mut v: Vec<_> = self.intents.lock().unwrap().iter().cloned().collect();
        v.sort();
        (
            v.into_iter()
                .map(|image| ImagePullIntent { image })
                .collect(),
            None,
        )
    }
    fn image_pull_intent_exists(&self, image: &str) -> Result<bool, Error> {
        if *self.fail_intent_exists.lock().unwrap() {
            return Err(Error("boom".into()));
        }
        Ok(self.intents.lock().unwrap().contains(image))
    }
    fn write_image_pull_intent(&self, image: &str) -> Result<(), Error> {
        self.intents.lock().unwrap().insert(image.to_string());
        Ok(())
    }
    fn delete_image_pull_intent(&self, image: &str) -> Result<(), Error> {
        if *self.fail_delete_intent.lock().unwrap() {
            return Err(Error("boom".into()));
        }
        self.intents.lock().unwrap().remove(image);
        Ok(())
    }
    fn list_image_pulled_records(&self) -> (Vec<ImagePulledRecord>, Option<Error>) {
        (
            self.pulled.lock().unwrap().values().cloned().collect(),
            None,
        )
    }
    fn get_image_pulled_record(&self, r: &str) -> Result<Option<ImagePulledRecord>, Error> {
        if *self.fail_get.lock().unwrap() {
            return Err(Error("boom".into()));
        }
        Ok(self.pulled.lock().unwrap().get(r).cloned())
    }
    fn write_image_pulled_record(&self, rec: &ImagePulledRecord) -> Result<(), Error> {
        *self.pulled_writes.lock().unwrap() += 1;
        self.pulled
            .lock()
            .unwrap()
            .insert(rec.image_ref.clone(), rec.clone());
        Ok(())
    }
    fn delete_image_pulled_record(&self, r: &str) -> Result<(), Error> {
        self.pulled.lock().unwrap().remove(r);
        Ok(())
    }
}

struct Lister(Vec<Image>);
impl ImageLister for Lister {
    fn list_images(&self) -> Result<Vec<Image>, Error> {
        Ok(self.0.clone())
    }
}

fn sec(uid: &str, ns: &str, name: &str, hash: &str) -> ImagePullSecret {
    ImagePullSecret {
        uid: uid.into(),
        namespace: ns.into(),
        name: name.into(),
        credential_hash: hash.into(),
    }
}
fn sa(uid: &str, ns: &str, name: &str) -> ImagePullServiceAccount {
    ImagePullServiceAccount {
        uid: uid.into(),
        namespace: ns.into(),
        name: name.into(),
    }
}
fn secrets(s: Vec<ImagePullSecret>) -> ImagePullCredentials {
    ImagePullCredentials {
        kubernetes_secrets: s,
        ..Default::default()
    }
}
fn rec(image_ref: &str, m: Vec<(&str, ImagePullCredentials)>) -> ImagePulledRecord {
    ImagePulledRecord {
        last_updated_time: Utc.with_ymd_and_hms(2024, 12, 24, 0, 0, 0).unwrap(),
        image_ref: image_ref.into(),
        credential_mapping: m.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
    }
}

#[derive(Clone, Copy)]
enum Pol {
    Preloaded,
    Never,
    Always,
}

fn manager(acc: &Arc<MemAccessor>, policy: Pol, images: Vec<Image>) -> PullManager {
    let policy: Arc<dyn ImagePullPolicyEnforcer> = match policy {
        Pol::Preloaded => Arc::new(never_verify_preloaded_pull_policy()),
        Pol::Never => Arc::new(never_verify_image_pull_policy()),
        Pol::Always => Arc::new(always_verify_image_pull_policy()),
    };
    PullManager::new(acc.clone(), policy, Arc::new(Lister(images)), 10)
}

const IMG: &str = "docker.io/testing/test:latest";
const REPO: &str = "docker.io/testing/test";

fn seeded() -> Arc<MemAccessor> {
    let acc = Arc::new(MemAccessor::default());
    let mut p = acc.pulled.lock().unwrap();
    p.insert(
        "testimageref".into(),
        rec(
            "testimageref",
            vec![(
                REPO,
                secrets(vec![sec(
                    "testsecretuid",
                    "default",
                    "pull-secret",
                    "testsecrethash",
                )]),
            )],
        ),
    );
    p.insert(
        "testemptycredmapping".into(),
        rec("testemptycredmapping", vec![]),
    );
    p.insert(
        "testimage-anonpull".into(),
        rec(
            "testimage-anonpull",
            vec![(
                REPO,
                ImagePullCredentials {
                    node_pods_accessible: true,
                    ..Default::default()
                },
            )],
        ),
    );
    p.insert(
        "test-brokenhash".into(),
        rec(
            "test-brokenhash",
            vec![(
                REPO,
                secrets(vec![sec("testsecretuid", "default", "pull-secret", "")]),
            )],
        ),
    );
    p.insert(
        "testimageref-sa".into(),
        rec(
            "testimageref-sa",
            vec![(
                REPO,
                ImagePullCredentials {
                    kubernetes_service_accounts: vec![sa("test-sa-uid", "default", "test-sa")],
                    ..Default::default()
                },
            )],
        ),
    );
    drop(p);
    acc
}

struct MA {
    name: &'static str,
    policy: Pol,
    secrets: Vec<ImagePullSecret>,
    sa: Option<ImagePullServiceAccount>,
    image: &'static str,
    image_ref: &'static str,
    intent: bool,
    want: bool,
    creds_requested: bool,
    write: bool,
}

const PRELOADED: Pol = Pol::Preloaded;

#[test]
fn image_pull_manager_must_attempt_image_pull() {
    let base = |name| MA {
        name,
        policy: Pol::Preloaded,
        secrets: vec![],
        sa: None,
        image: IMG,
        image_ref: "testimageref",
        intent: false,
        want: true,
        creds_requested: false,
        write: false,
    };
    let s = |ns: &str, uid: &str, hash: &str| vec![sec(uid, ns, "pull-secret", hash)];
    let cases = vec![
        MA {
            secrets: s("default", "testsecretuid", "testsecrethash"),
            want: false,
            creds_requested: true,
            ..base("exact secret")
        },
        MA {
            creds_requested: true,
            ..base("recorded, no pod secrets")
        },
        MA {
            secrets: s("default", "testsecretuid", "differenthash"),
            want: false,
            creds_requested: true,
            write: true,
            ..base("same secret different hash")
        },
        MA {
            secrets: s("default", "different uid", "differenthash"),
            creds_requested: true,
            ..base("different uid")
        },
        MA {
            secrets: s("differentns", "testsecretuid", "differenthash"),
            creds_requested: true,
            ..base("different secret")
        },
        MA {
            secrets: s("differentns", "testsecretuid", "testsecrethash"),
            want: false,
            creds_requested: true,
            write: true,
            ..base("different secret same hash")
        },
        MA {
            secrets: s("default", "testsecretuid", "testsecrethash"),
            image: "docker.io/testing/different:latest",
            ..base("different image name")
        },
        MA {
            image_ref: "testemptycredmapping",
            ..base("empty credential mapping")
        },
        MA {
            image_ref: "",
            ..base("no records")
        },
        MA {
            image_ref: "testexistingref",
            want: false,
            ..base("no records, NeverVerifyPreloaded")
        },
        MA {
            policy: Pol::Always,
            image_ref: "testexistingref",
            ..base("no records, AlwaysVerify")
        },
        MA {
            secrets: s("default", "testsecretuid", "testsecrethash"),
            image_ref: "testexistingref",
            intent: true,
            ..base("intent only")
        },
        MA {
            policy: Pol::Never,
            secrets: s("default", "testsecretuid", "testsecrethash"),
            image_ref: "testexistingref",
            intent: true,
            want: false,
            ..base("intent only, NeverVerify")
        },
        MA {
            image_ref: "testimage-anonpull",
            want: false,
            ..base("node accessible")
        },
        MA {
            secrets: s("default", "testsecretuid", "testsecrethash"),
            image_ref: "testimage-anonpull",
            want: false,
            ..base("node accessible with secrets")
        },
        MA {
            secrets: s("differentns", "testsecretuid", ""),
            image_ref: "test-brokenhash",
            creds_requested: true,
            ..base("empty hash, different secret")
        },
        MA {
            secrets: s("default", "testsecretuid", ""),
            image_ref: "test-brokenhash",
            want: false,
            creds_requested: true,
            ..base("empty hash, same secret")
        },
        MA {
            sa: Some(sa("test-sa-uid", "default", "test-sa")),
            image_ref: "testimageref-sa",
            want: false,
            creds_requested: true,
            ..base("exact sa")
        },
        MA {
            image_ref: "testimageref-sa",
            creds_requested: true,
            ..base("sa recorded, no pod sa")
        },
        MA {
            sa: Some(sa("different-sa-uid", "default", "test-sa")),
            image_ref: "testimageref-sa",
            creds_requested: true,
            ..base("sa different uid")
        },
        MA {
            sa: Some(sa("test-sa-uid", "different-ns", "test-sa")),
            image_ref: "testimageref-sa",
            creds_requested: true,
            ..base("sa different ns")
        },
        MA {
            sa: Some(sa("test-sa-uid", "default", "test-sa")),
            image: "docker.io/testing/different:latest",
            image_ref: "testimageref-sa",
            ..base("sa different image")
        },
        MA {
            sa: Some(sa("test-sa-uid", "default", "test-sa")),
            image_ref: "testexistingref",
            intent: true,
            ..base("sa intent only")
        },
        MA {
            policy: Pol::Never,
            sa: Some(sa("test-sa-uid", "default", "test-sa")),
            image_ref: "testexistingref",
            intent: true,
            want: false,
            ..base("sa intent only, NeverVerify")
        },
        MA {
            sa: Some(sa("test-sa-uid", "default", "test-sa")),
            image_ref: "testimage-anonpull",
            want: false,
            ..base("node accessible with sa")
        },
    ];
    for c in cases {
        let acc = seeded();
        if c.intent {
            acc.intents.lock().unwrap().insert(c.image.to_string());
        }
        let m = manager(&acc, c.policy, vec![]);
        // initialize() with an intent for an unknown image must not touch records
        acc.pulled_writes.lock().unwrap().clone_from(&0);
        let requested = Mutex::new(false);
        let (sec_, sa_) = (c.secrets.clone(), c.sa.clone());
        let got = m
            .must_attempt_image_pull(c.image, c.image_ref, &|| {
                *requested.lock().unwrap() = true;
                Ok((sec_.clone(), sa_.clone()))
            })
            .unwrap();
        assert_eq!(got, c.want, "{}", c.name);
        assert_eq!(
            *requested.lock().unwrap(),
            c.creds_requested,
            "{}: creds lookup",
            c.name
        );
        assert_eq!(
            *acc.pulled_writes.lock().unwrap() != 0,
            c.write,
            "{}: cache write",
            c.name
        );
    }
}

#[test]
fn image_pull_manager_must_attempt_written_record_content() {
    // "same secret different hash" and "different secret same hash" rewrite the record.
    let acc = seeded();
    let m = manager(&acc, PRELOADED, vec![]);
    let pod = vec![sec(
        "testsecretuid",
        "default",
        "pull-secret",
        "differenthash",
    )];
    assert!(!m
        .must_attempt_image_pull(IMG, "testimageref", &|| Ok((pod.clone(), None)))
        .unwrap());
    let got = acc.pulled.lock().unwrap()["testimageref"].clone();
    assert_eq!(
        got.credential_mapping[REPO].kubernetes_secrets,
        vec![sec(
            "testsecretuid",
            "default",
            "pull-secret",
            "differenthash"
        )]
    );

    let acc = seeded();
    let m = manager(&acc, PRELOADED, vec![]);
    let pod = vec![sec(
        "testsecretuid",
        "differentns",
        "pull-secret",
        "testsecrethash",
    )];
    assert!(!m
        .must_attempt_image_pull(IMG, "testimageref", &|| Ok((pod.clone(), None)))
        .unwrap());
    let got = acc.pulled.lock().unwrap()["testimageref"].clone();
    assert_eq!(
        got.credential_mapping[REPO].kubernetes_secrets,
        vec![
            sec("testsecretuid", "default", "pull-secret", "testsecrethash"),
            sec(
                "testsecretuid",
                "differentns",
                "pull-secret",
                "testsecrethash"
            ),
        ]
    );
}

#[test]
fn image_pull_manager_must_attempt_fails_closed() {
    // record read error: must pull, no error surfaced (upstream logs it)
    let acc = seeded();
    let m = manager(&acc, Pol::Never, vec![]);
    *acc.fail_get.lock().unwrap() = true;
    let (r, res) =
        m.must_attempt_image_pull_with_result(IMG, "testimageref", &|| Ok((vec![], None)));
    assert!(r.unwrap());
    assert_eq!(res, Some(MustAttemptImagePullResult::Error));

    // intent existence check error: must pull
    let acc = Arc::new(MemAccessor::default());
    let m = manager(&acc, Pol::Never, vec![]);
    *acc.fail_intent_exists.lock().unwrap() = true;
    assert!(m
        .must_attempt_image_pull(IMG, "ref", &|| Ok((vec![], None)))
        .unwrap());

    // pod credential lookup error: must pull AND error returned
    let acc = seeded();
    let m = manager(&acc, PRELOADED, vec![]);
    let (r, res) =
        m.must_attempt_image_pull_with_result(IMG, "testimageref", &|| Err(Error("nope".into())));
    assert_eq!(r.unwrap_err().0, "nope");
    assert_eq!(res, Some(MustAttemptImagePullResult::Error));

    // unparsable image name with a record present: must pull
    let acc = seeded();
    let m = manager(&acc, PRELOADED, vec![]);
    let (r, res) =
        m.must_attempt_image_pull_with_result("bad image", "testimageref", &|| Ok((vec![], None)));
    assert!(r.unwrap());
    assert_eq!(res, Some(MustAttemptImagePullResult::Error));
}

#[test]
fn image_pull_manager_must_attempt_result_labels() {
    let acc = seeded();
    let m = manager(&acc, PRELOADED, vec![]);
    let (_, r) = m.must_attempt_image_pull_with_result(IMG, "", &|| Ok((vec![], None)));
    assert_eq!(r, None);
    let (_, r) =
        m.must_attempt_image_pull_with_result(IMG, "testimage-anonpull", &|| Ok((vec![], None)));
    assert_eq!(r.unwrap().as_str(), "credentialRecordFound");
    let (_, r) =
        m.must_attempt_image_pull_with_result(IMG, "testemptycredmapping", &|| Ok((vec![], None)));
    assert_eq!(r.unwrap().as_str(), "mustAuthenticate");
    let (_, r) = m.must_attempt_image_pull_with_result(IMG, "unknown-ref", &|| Ok((vec![], None)));
    assert_eq!(r.unwrap().as_str(), "credentialPolicyAllowed");
    let ma = manager(&acc, Pol::Always, vec![]);
    let (_, r) = ma.must_attempt_image_pull_with_result(IMG, "unknown-ref", &|| Ok((vec![], None)));
    assert_eq!(r.unwrap().as_str(), "mustAuthenticate");
    let m2 = manager(&acc, Pol::Never, vec![]);
    let (_, r) = m2.must_attempt_image_pull_with_result(IMG, "unknown-ref", &|| Ok((vec![], None)));
    assert_eq!(r.unwrap().as_str(), "credentialPolicyAllowed");
}

#[test]
fn image_pull_manager_record_pull_intent_counts() {
    for (start, want) in [(0, 1), (1, 2)] {
        let acc = Arc::new(MemAccessor::default());
        let m = manager(&acc, PRELOADED, vec![]);
        let image = "repo.repo/test/test:latest";
        if start > 0 {
            m.set_intent_counter_for_image(image, start);
        }
        m.record_pull_intent(image).unwrap();
        assert!(acc.intents.lock().unwrap().contains(image));
        assert_eq!(m.get_intent_counter_for_image(image), want);
    }
}

#[test]
fn image_pull_manager_intent_refcount_lifecycle() {
    let acc = Arc::new(MemAccessor::default());
    let m = manager(&acc, PRELOADED, vec![]);
    let image = "repo.repo/test/test:latest";
    m.record_pull_intent(image).unwrap();
    m.record_pull_intent(image).unwrap();
    // first failure only decrements; the intent stays while another pull is in flight
    m.record_image_pull_failed(image);
    assert!(acc.intents.lock().unwrap().contains(image));
    assert_eq!(m.get_intent_counter_for_image(image), 1);
    // last one deletes the intent and the counter
    m.record_image_pull_failed(image);
    assert!(!acc.intents.lock().unwrap().contains(image));
    assert_eq!(m.get_intent_counter_for_image(image), 0);

    // delete failure keeps the counter (consistent with the record)
    m.record_pull_intent(image).unwrap();
    *acc.fail_delete_intent.lock().unwrap() = true;
    m.record_image_pull_failed(image);
    assert_eq!(m.get_intent_counter_for_image(image), 1);
}

#[test]
fn image_pull_manager_record_image_pulled() {
    let acc = Arc::new(MemAccessor::default());
    let m = manager(&acc, PRELOADED, vec![]);
    let image = "docker.io/testing/test:latest";
    m.record_pull_intent(image).unwrap();
    let creds = secrets(vec![sec("u", "ns", "n", "h")]);
    m.record_image_pulled(image, "ref1", Some(&creds));
    // record written, intent dropped
    assert!(!acc.intents.lock().unwrap().contains(image));
    let got = acc.pulled.lock().unwrap()["ref1"].clone();
    assert_eq!(got.credential_mapping[REPO], creds);

    // identical credentials again: no new write
    let writes = *acc.pulled_writes.lock().unwrap();
    m.record_image_pulled(image, "ref1", Some(&creds));
    assert_eq!(*acc.pulled_writes.lock().unwrap(), writes);

    // None credentials on a new ref: record exists with empty mapping
    m.record_image_pulled(image, "ref2", None);
    assert!(acc.pulled.lock().unwrap()["ref2"]
        .credential_mapping
        .is_empty());

    // invalid image name: nothing written, intent kept
    m.record_pull_intent("bad image").unwrap();
    m.record_image_pulled("bad image", "ref3", Some(&creds));
    assert!(!acc.pulled.lock().unwrap().contains_key("ref3"));
    assert!(acc.intents.lock().unwrap().contains("bad image"));
}

#[test]
fn image_pull_manager_initialize() {
    let img = |id: &str, tags: &[&str], digests: &[&str]| Image {
        id: id.into(),
        repo_tags: tags.iter().map(|s| s.to_string()).collect(),
        repo_digests: digests.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    let images = vec![
        img(
            "testimageref1",
            &[
                "repo.repo/test/test:docker",
                "docker.io/testing/test:something",
            ],
            &[],
        ),
        img(
            "testimageref2",
            &["repo.repo/test/test:v2"],
            &["repo.repo/test/test@dgst2"],
        ),
        img(
            "testimageref4",
            &[],
            &[
                "repo.repo/test/test@dgst4",
                "repo.repo/test/notatest@dgst44",
            ],
        ),
    ];
    let acc = Arc::new(MemAccessor::default());
    for i in [
        "repo.repo/test/test:docker",
        "repo.repo/test/test@dgst2",
        "repo.repo/test/test@dgst-unknown",
        "repo.repo/test/notatest@dgst44",
    ] {
        acc.intents.lock().unwrap().insert(i.into());
    }
    let _m = manager(&acc, PRELOADED, images);
    // known images become records without credentials, their intents go away
    let pulled = acc.pulled.lock().unwrap();
    assert_eq!(
        pulled.keys().cloned().collect::<Vec<_>>(),
        vec!["testimageref1", "testimageref2", "testimageref4"]
    );
    assert!(pulled.values().all(|r| r.credential_mapping.is_empty()));
    let left: Vec<_> = acc.intents.lock().unwrap().iter().cloned().collect();
    assert_eq!(left, vec!["repo.repo/test/test@dgst-unknown"]);
}

#[test]
fn image_pull_manager_prune_unknown_records() {
    let until: DateTime<Utc> = Utc.with_ymd_and_hms(2024, 12, 25, 0, 1, 0).unwrap();
    let cases: [(&[&str], &[&str]); 4] = [
        (
            &["testimage-anonpull", "testimageref", "testemptycredmapping"],
            &["testemptycredmapping", "testimage-anonpull", "testimageref"],
        ),
        (&[], &[]),
        (&["untracked1", "different-untracked"], &[]),
        (
            &["testimage-anonpull", "untracked1", "testimageref"],
            &["testimage-anonpull", "testimageref"],
        ),
    ];
    for (list, want) in cases {
        let acc = Arc::new(MemAccessor::default());
        for r in ["testimage-anonpull", "testimageref", "testemptycredmapping"] {
            acc.pulled.lock().unwrap().insert(r.into(), rec(r, vec![]));
        }
        let m = manager(&acc, PRELOADED, vec![]);
        let list: Vec<String> = list.iter().map(|s| s.to_string()).collect();
        m.prune_unknown_records(&list, until);
        let left: Vec<_> = acc.pulled.lock().unwrap().keys().cloned().collect();
        let mut want: Vec<_> = want.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(left, want, "{list:?}");
    }

    // records updated after the GC started survive even when unknown
    let acc = Arc::new(MemAccessor::default());
    let mut r = rec("fresh", vec![]);
    r.last_updated_time = until;
    acc.pulled.lock().unwrap().insert("fresh".into(), r);
    manager(&acc, PRELOADED, vec![]).prune_unknown_records(&[], until);
    assert!(acc.pulled.lock().unwrap().contains_key("fresh"));
}

#[test]
fn image_pull_manager_noop() {
    let n = NoopImagePullManager;
    assert!(n.record_pull_intent("x").is_ok());
    assert!(n
        .must_attempt_image_pull("x", "y", &|| Ok((vec![], None)))
        .unwrap());
}

#[test]
fn image_pull_manager_merge_new_creds() {
    let orig = rec(
        "testImageRef",
        vec![
            (
                "test-image1",
                secrets(vec![sec("uid1", "namespace1", "name1", "hash1")]),
            ),
            (
                "test-image-with-sa",
                ImagePullCredentials {
                    kubernetes_service_accounts: vec![sa("sa-uid1", "default", "sa1")],
                    ..Default::default()
                },
            ),
            (
                "test-nodewide",
                ImagePullCredentials {
                    node_pods_accessible: true,
                    ..Default::default()
                },
            ),
        ],
    );
    // nil / empty credentials: no change
    assert!(pulled_record_merge_new_creds(&orig, "x", None).is_none());
    assert!(
        pulled_record_merge_new_creds(&orig, "x", Some(&ImagePullCredentials::default())).is_none()
    );
    // new image: added
    let n = secrets(vec![sec("newuid", "newns", "newname", "newhash")]);
    let got = pulled_record_merge_new_creds(&orig, "new-image", Some(&n)).unwrap();
    assert_eq!(got.credential_mapping["new-image"], n);
    assert!(got.last_updated_time > orig.last_updated_time);
    // merge into existing: sorted by namespace, name, uid
    let got = pulled_record_merge_new_creds(&orig, "test-image1", Some(&n)).unwrap();
    assert_eq!(
        got.credential_mapping["test-image1"].kubernetes_secrets,
        vec![
            sec("uid1", "namespace1", "name1", "hash1"),
            sec("newuid", "newns", "newname", "newhash")
        ]
    );
    // same secret, same hash: unchanged
    let same = secrets(vec![sec("uid1", "namespace1", "name1", "hash1")]);
    assert!(pulled_record_merge_new_creds(&orig, "test-image1", Some(&same)).is_none());
    // same coordinates, new hash: hash replaced
    let rehash = secrets(vec![sec("uid1", "namespace1", "name1", "hash2")]);
    let got = pulled_record_merge_new_creds(&orig, "test-image1", Some(&rehash)).unwrap();
    assert_eq!(
        got.credential_mapping["test-image1"].kubernetes_secrets,
        rehash.kubernetes_secrets
    );
    // existing node-wide access absorbs everything
    assert!(pulled_record_merge_new_creds(&orig, "test-nodewide", Some(&n)).is_none());
    // new node-wide access clears the lists
    let nw = ImagePullCredentials {
        node_pods_accessible: true,
        ..Default::default()
    };
    let got = pulled_record_merge_new_creds(&orig, "test-image1", Some(&nw)).unwrap();
    assert_eq!(got.credential_mapping["test-image1"], nw);
    // service accounts merge
    let new_sa = ImagePullCredentials {
        kubernetes_service_accounts: vec![sa("sa-uid0", "default", "sa0")],
        ..Default::default()
    };
    let got = pulled_record_merge_new_creds(&orig, "test-image-with-sa", Some(&new_sa)).unwrap();
    assert_eq!(
        got.credential_mapping["test-image-with-sa"].kubernetes_service_accounts,
        vec![
            sa("sa-uid0", "default", "sa0"),
            sa("sa-uid1", "default", "sa1")
        ]
    );
}

#[test]
fn image_pull_manager_merge_pull_service_accounts() {
    let a = vec![sa("u2", "ns", "b"), sa("u1", "ns", "a")];
    let (r, changed) = merge_pull_service_accounts(&a, &[sa("u1", "ns", "a")]);
    assert!(!changed);
    assert_eq!(r, a);
    let (r, changed) = merge_pull_service_accounts(&a, &[sa("u0", "ns", "a"), sa("u1", "ns", "a")]);
    assert!(changed);
    assert_eq!(
        r,
        vec![
            sa("u0", "ns", "a"),
            sa("u1", "ns", "a"),
            sa("u2", "ns", "b")
        ]
    );
}
