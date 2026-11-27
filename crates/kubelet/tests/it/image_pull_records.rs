//! Ports `TestNewFSPullRecordsAccessor` (fs_pullrecords_test.go) with the same
//! testdata, plus accessor behaviour from `fs_pullrecords.go` and negative
//! tests for malformed/foreign records (fail closed).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use kubernetes_rs_kubelet::image_manager::image_pull_manager::{
    cache_filename, FsPullRecordsAccessor, ImagePullCredentials, ImagePullSecret,
    ImagePulledRecord, PullRecordsAccessor,
};

fn testdata(kind: &str, name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/it/testdata_image_pull_records")
        .join(kind)
        .join(name);
    fs::read_to_string(p).unwrap()
}

fn tee(dir: &Path, kind: &str, names: &[&str], modify: bool) -> Vec<(String, String)> {
    fs::create_dir_all(dir).unwrap();
    names
        .iter()
        .map(|n| {
            let content = testdata(kind, n);
            fs::write(dir.join(n), &content).unwrap();
            let expected = if modify {
                content.replace(
                    "kubelet.config.k8s.io/v1alpha1",
                    "kubelet.config.k8s.io/v1beta1",
                )
            } else {
                content
            };
            (n.to_string(), expected)
        })
        .collect()
}

const INTENTS: [&str; 4] = [
    "sha256-aef2af226629a35d5f3ef0fdbb29fdbebf038d0acd8850590e8c48e1e283aa56",
    "sha256-6da3dced7eccc7ad0189517c31ec2235b50f730449d738d91525721f7e027fd4",
    "sha256-ee81caca15454863449fb55a1d942904d56d5ed9f9b20a7cb3453944ea2c7e11",
    "sha256-b6e1482bb6cb030924530b918e609fff30bbb07ab6845451d89deb823c3f72a9",
];
const PULLED: [&str; 5] = [
    "sha256-7045bdd498b0e4b3963d50f906793ffbd68dc98686ec46c5b499a0a640a560b2",
    "sha256-38a8906435c4dd5f4258899d46621bfd8eea3ad6ff494ee3c2f17ef0321625bd",
    "sha256-dd1dd8dc6a329b7e1c2e43951302b23a047cb20fd3e10090e4ce7e8396035405",
    "sha256-a2eace2182b24cdbbb730798e47b10709b9ef5e0f0c1624a3bc06c8ca987727a",
    "sha256-f8778b6393eaf39315e767a58cbeacf2c4b270d94b4d6926ee993d9e49444991",
];

#[test]
fn image_pull_records_new_accessor_migrates_alpha_to_beta() {
    let cases: Vec<(&str, bool, Vec<&str>, Vec<&str>)> = vec![
        ("root dir does not exist", false, vec![], vec![]),
        ("root dir exists", true, vec![], vec![]),
        (
            "only alpha intents",
            true,
            INTENTS[1..2]
                .iter()
                .chain(&INTENTS[3..4])
                .copied()
                .collect(),
            vec![],
        ),
        ("alpha and beta intents", true, INTENTS.to_vec(), vec![]),
        (
            "only beta intents",
            true,
            vec![INTENTS[0], INTENTS[2]],
            vec![],
        ),
        (
            "only alpha pulled",
            true,
            vec![],
            vec![PULLED[0], PULLED[2]],
        ),
        ("alpha and beta pulled", true, vec![], PULLED.to_vec()),
        (
            "only beta pulled",
            true,
            vec![],
            vec![PULLED[1], PULLED[3], PULLED[4]],
        ),
        ("everything", true, INTENTS.to_vec(), PULLED.to_vec()),
    ];
    for (name, init_root, intents, pulled) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let root = if init_root {
            tmp.path().to_path_buf()
        } else {
            tmp.path().join("does-not-exist").join("level2dir")
        };
        let pulling_dir = root.join("image_manager/pulling");
        let pulled_dir = root.join("image_manager/pulled");
        let exp_i = tee(&pulling_dir, "pulling", &intents, true);
        let exp_p = tee(&pulled_dir, "pulled", &pulled, true);

        FsPullRecordsAccessor::new(&root).unwrap_or_else(|e| panic!("{name}: {e}"));

        assert!(pulling_dir.is_dir() && pulled_dir.is_dir(), "{name}");
        for (n, want) in exp_i {
            assert_eq!(
                fs::read_to_string(pulling_dir.join(&n)).unwrap(),
                want,
                "{name}: {n}"
            );
        }
        for (n, want) in exp_p {
            assert_eq!(
                fs::read_to_string(pulled_dir.join(&n)).unwrap(),
                want,
                "{name}: {n}"
            );
        }
    }
}

fn record(image_ref: &str) -> ImagePulledRecord {
    ImagePulledRecord {
        last_updated_time: Utc.with_ymd_and_hms(2024, 10, 21, 12, 26, 40).unwrap(),
        image_ref: image_ref.into(),
        credential_mapping: BTreeMap::from([(
            "docker.io/testing/test".to_string(),
            ImagePullCredentials {
                kubernetes_secrets: vec![ImagePullSecret {
                    uid: "testsecretuid".into(),
                    namespace: "default".into(),
                    name: "pull-secret".into(),
                    credential_hash: "testsecrethash".into(),
                }],
                ..Default::default()
            },
        )]),
    }
}

#[test]
fn image_pull_records_intents_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let a = FsPullRecordsAccessor::new(tmp.path()).unwrap();
    assert!(!a.image_pull_intent_exists("docker.io/a:1").unwrap());
    a.write_image_pull_intent("docker.io/a:1").unwrap();
    a.write_image_pull_intent("docker.io/b:1").unwrap();
    assert!(a.image_pull_intent_exists("docker.io/a:1").unwrap());
    assert_eq!(a.intents_size().unwrap(), 2);
    let (mut l, e) = a.list_image_pull_intents();
    assert!(e.is_none());
    l.sort_by(|x, y| x.image.cmp(&y.image));
    assert_eq!(
        l.iter().map(|i| i.image.as_str()).collect::<Vec<_>>(),
        ["docker.io/a:1", "docker.io/b:1"]
    );
    // file name is the sha256 of the image, content is v1beta1 JSON + newline
    let raw = fs::read_to_string(
        tmp.path()
            .join("image_manager/pulling")
            .join(cache_filename("docker.io/a:1")),
    )
    .unwrap();
    assert_eq!(
        raw,
        "{\"kind\":\"ImagePullIntent\",\"apiVersion\":\"kubelet.config.k8s.io/v1beta1\",\"image\":\"docker.io/a:1\"}\n"
    );
    a.delete_image_pull_intent("docker.io/a:1").unwrap();
    a.delete_image_pull_intent("docker.io/a:1").unwrap(); // missing is fine
    assert!(!a.image_pull_intent_exists("docker.io/a:1").unwrap());
}

#[test]
fn image_pull_records_pulled_records_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let a = FsPullRecordsAccessor::new(tmp.path()).unwrap();
    assert_eq!(a.get_image_pulled_record("ref1").unwrap(), None);
    a.write_image_pulled_record(&record("ref1")).unwrap();
    assert_eq!(
        a.get_image_pulled_record("ref1").unwrap(),
        Some(record("ref1"))
    );
    assert_eq!(a.pulled_records_size().unwrap(), 1);
    let (l, e) = a.list_image_pulled_records();
    assert!(e.is_none());
    assert_eq!(l, vec![record("ref1")]);
    a.delete_image_pulled_record("ref1").unwrap();
    a.delete_image_pulled_record("ref1").unwrap();
    assert_eq!(a.get_image_pulled_record("ref1").unwrap(), None);
}

#[test]
fn image_pull_records_get_ignores_record_for_other_image_ref() {
    // A file whose content names a different imageRef than its hash-named
    // path must not grant access (fs_pullrecords.go GetImagePulledRecord).
    let tmp = tempfile::tempdir().unwrap();
    let a = FsPullRecordsAccessor::new(tmp.path()).unwrap();
    a.write_image_pulled_record(&record("other")).unwrap();
    let dir = tmp.path().join("image_manager/pulled");
    fs::rename(
        dir.join(cache_filename("other")),
        dir.join(cache_filename("wanted")),
    )
    .unwrap();
    assert_eq!(a.get_image_pulled_record("wanted").unwrap(), None);
}

#[test]
fn image_pull_records_reject_malformed_records() {
    let tmp = tempfile::tempdir().unwrap();
    let a = FsPullRecordsAccessor::new(tmp.path()).unwrap();
    let pulled = tmp.path().join("image_manager/pulled");
    let pulling = tmp.path().join("image_manager/pulling");

    // unknown field (strict decoding), wrong kind, wrong group, truncated JSON
    let bad = [
        r#"{"kind":"ImagePulledRecord","apiVersion":"kubelet.config.k8s.io/v1beta1","lastUpdatedTime":"2024-10-21T12:26:40Z","imageRef":"x","extra":1}"#,
        r#"{"kind":"ImagePullIntent","apiVersion":"kubelet.config.k8s.io/v1beta1","image":"x"}"#,
        r#"{"kind":"ImagePulledRecord","apiVersion":"other.io/v1beta1","lastUpdatedTime":"2024-10-21T12:26:40Z","imageRef":"x"}"#,
        r#"{"kind":"ImagePulledRecord","apiVersion":"kubelet.config.k8s.io/v1alpha1","imageRef":"x""#,
    ];
    for (i, content) in bad.iter().enumerate() {
        let r = format!("badref{i}");
        fs::write(pulled.join(cache_filename(&r)), content).unwrap();
        assert!(a.get_image_pulled_record(&r).is_err(), "case {i}");
    }
    let (items, e) = a.list_image_pulled_records();
    assert!(items.is_empty());
    assert!(e.is_some());

    fs::write(pulling.join(cache_filename("img")), "not json").unwrap();
    assert!(a.image_pull_intent_exists("img").is_err());
    let (items, e) = a.list_image_pull_intents();
    assert!(items.is_empty() && e.is_some());

    // files we did not write and .tmp files are ignored and not counted
    fs::write(pulling.join("unrelated"), "x").unwrap();
    fs::write(pulling.join(format!("{}.tmp", cache_filename("t"))), "x").unwrap();
    assert_eq!(a.intents_size().unwrap(), 1);
}

#[test]
fn image_pull_records_partial_success_lists_good_records() {
    let tmp = tempfile::tempdir().unwrap();
    let a = FsPullRecordsAccessor::new(tmp.path()).unwrap();
    a.write_image_pull_intent("good").unwrap();
    fs::write(
        tmp.path()
            .join("image_manager/pulling")
            .join(cache_filename("bad")),
        "{",
    )
    .unwrap();
    let (items, e) = a.list_image_pull_intents();
    assert_eq!(items.len(), 1);
    assert!(e
        .unwrap()
        .to_string()
        .contains("failed to deserialize content of file"));
}
