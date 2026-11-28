//! Port of the on-disk part of `TestFSPullRecordsMetrics` and the counter of
//! `pkg/kubelet/images/pullmanager/metrics_test.go` (release-1.35). The
//! in-memory cache usage assertions need the cached accessor (kubelet-P2-25f).

use chrono::Utc;
use kubernetes_rs_kubelet::image_manager::image_pull_manager::*;
use kubernetes_rs_kubelet::image_manager::image_pull_metrics::*;

fn record(image_ref: &str) -> ImagePulledRecord {
    ImagePulledRecord {
        last_updated_time: Utc::now(),
        image_ref: image_ref.into(),
        credential_mapping: Default::default(),
    }
}

#[test]
fn image_pull_metrics_fs_records_size() {
    let dir = tempfile::tempdir().unwrap();
    let m = ImagePullMetrics::new();
    let acc = MeteringRecordsAccessor::new(
        FsPullRecordsAccessor::new(dir.path()).unwrap(),
        m.fs_pull_intents_size.clone(),
        m.fs_pulled_records_size.clone(),
    );
    let intents = || m.fs_pull_intents_size.get() as i64;
    let pulled = || m.fs_pulled_records_size.get() as i64;
    assert_eq!((intents(), pulled()), (0, 0));

    acc.write_image_pull_intent("test-image:latest").unwrap();
    assert_eq!(intents(), 1);
    // writing the same record does not increase the count
    acc.write_image_pull_intent("test-image:latest").unwrap();
    acc.write_image_pull_intent("test-image:latest").unwrap();
    assert_eq!(intents(), 1);
    acc.write_image_pull_intent("test-image:v1").unwrap();
    acc.write_image_pull_intent("test-image:v1.1").unwrap();
    assert_eq!(intents(), 3);

    acc.write_image_pulled_record(&record("latest-ref"))
        .unwrap();
    acc.write_image_pulled_record(&record("latest-ref"))
        .unwrap();
    assert_eq!(pulled(), 1);
    acc.write_image_pulled_record(&record("v1-ref")).unwrap();
    acc.write_image_pulled_record(&record("v1.1-ref")).unwrap();
    acc.write_image_pulled_record(&record("v1.2-ref")).unwrap();
    assert_eq!((intents(), pulled()), (3, 4));

    acc.delete_image_pull_intent("test-image:latest").unwrap();
    acc.delete_image_pull_intent("test-image:latest").unwrap();
    assert_eq!(intents(), 2);
    acc.delete_image_pull_intent("test-image:v1").unwrap();
    acc.delete_image_pull_intent("test-image:v1.1").unwrap();
    assert_eq!((intents(), pulled()), (0, 4));

    acc.delete_image_pulled_record("v1.1-ref").unwrap();
    acc.delete_image_pulled_record("v1.1-ref").unwrap();
    assert_eq!(pulled(), 3);
    for r in ["v1.2-ref", "v1-ref", "latest-ref"] {
        acc.delete_image_pulled_record(r).unwrap();
    }
    assert_eq!(pulled(), 0);

    for i in 0..20 {
        acc.write_image_pull_intent(&format!("test-image-{i}:latest"))
            .unwrap();
        acc.write_image_pulled_record(&record(&format!("test-image-v{i}-ref")))
            .unwrap();
    }
    assert_eq!((intents(), pulled()), (20, 20));
}

#[test]
fn image_pull_metrics_register_and_counter() {
    let m = ImagePullMetrics::new();
    let reg = prometheus::Registry::new();
    m.register(&reg).unwrap();
    m.record_must_attempt_image_pull_result("mustAuthenticate");
    m.record_must_attempt_image_pull_result("mustAuthenticate");
    m.record_must_attempt_image_pull_result("credentialRecordFound");
    let names: Vec<String> = reg.gather().iter().map(|f| f.name().to_string()).collect();
    for n in [
        "kubelet_imagemanager_ondisk_pullintents",
        "kubelet_imagemanager_ondisk_pulledrecords",
        "kubelet_imagemanager_inmemory_pullintents_usage_percent",
        "kubelet_imagemanager_inmemory_pulledrecords_usage_percent",
        "kubelet_imagemanager_image_mustpull_checks_total",
    ] {
        assert!(names.iter().any(|x| x == n), "missing {n}: {names:?}");
    }
    assert_eq!(
        m.must_pull_checks_total
            .with_label_values(&["mustAuthenticate"])
            .get(),
        2
    );
    assert_eq!(
        m.must_pull_checks_total
            .with_label_values(&["credentialRecordFound"])
            .get(),
        1
    );
}
