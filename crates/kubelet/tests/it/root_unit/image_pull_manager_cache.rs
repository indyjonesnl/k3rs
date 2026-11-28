//! Ports of `pkg/kubelet/images/pullmanager/mem_pullrecords_test.go`
//! (TestNewCachedPullRecordsAccessor, Test_cachedPullRecordsAccessor_*) over
//! an in-memory fake delegate (`testPullRecordsAccessor`), plus `lruCache`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{TimeZone, Utc};
use kubernetes_rs_kubelet::image_manager::image_pull_manager::{
    CachedPullRecordsAccessor, Error, ImagePullIntent, ImagePulledRecord, LruCache,
    PullRecordsAccessor,
};

#[derive(Default)]
struct FakeState {
    intents: BTreeMap<String, ImagePullIntent>,
    records: BTreeMap<String, ImagePulledRecord>,
    intents_list_err: Option<String>,
    records_list_err: Option<String>,
    write_err: Option<String>,
    calls: Vec<String>,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<FakeState>>);

impl Fake {
    fn with(intents: usize, records: usize) -> Self {
        let f = Fake::default();
        {
            let mut s = f.0.lock().unwrap();
            for i in 0..intents {
                let n = format!("image-{i:03}");
                s.intents.insert(n.clone(), ImagePullIntent { image: n });
            }
            for i in 0..records {
                let r = rec(&format!("ref-{i:03}"));
                s.records.insert(r.image_ref.clone(), r);
            }
        }
        f
    }
    fn calls(&self) -> Vec<String> {
        self.0.lock().unwrap().calls.clone()
    }
}

fn rec(r: &str) -> ImagePulledRecord {
    ImagePulledRecord {
        last_updated_time: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        image_ref: r.to_string(),
        credential_mapping: BTreeMap::new(),
    }
}

impl PullRecordsAccessor for Fake {
    fn list_image_pull_intents(&self) -> (Vec<ImagePullIntent>, Option<Error>) {
        let mut s = self.0.lock().unwrap();
        s.calls.push("ListImagePullIntents".into());
        (
            s.intents.values().cloned().collect(),
            s.intents_list_err.clone().map(Error),
        )
    }
    fn image_pull_intent_exists(&self, image: &str) -> Result<bool, Error> {
        let mut s = self.0.lock().unwrap();
        s.calls.push("ImagePullIntentExists".into());
        Ok(s.intents.contains_key(image))
    }
    fn write_image_pull_intent(&self, image: &str) -> Result<(), Error> {
        let mut s = self.0.lock().unwrap();
        s.calls.push("WriteImagePullIntent".into());
        if let Some(e) = s.write_err.take() {
            return Err(Error(e));
        }
        s.intents.insert(
            image.into(),
            ImagePullIntent {
                image: image.into(),
            },
        );
        Ok(())
    }
    fn delete_image_pull_intent(&self, image: &str) -> Result<(), Error> {
        let mut s = self.0.lock().unwrap();
        s.calls.push("DeleteImagePullIntent".into());
        if let Some(e) = s.write_err.take() {
            return Err(Error(e));
        }
        s.intents.remove(image);
        Ok(())
    }
    fn list_image_pulled_records(&self) -> (Vec<ImagePulledRecord>, Option<Error>) {
        let mut s = self.0.lock().unwrap();
        s.calls.push("ListImagePulledRecords".into());
        (
            s.records.values().cloned().collect(),
            s.records_list_err.clone().map(Error),
        )
    }
    fn get_image_pulled_record(&self, r: &str) -> Result<Option<ImagePulledRecord>, Error> {
        let mut s = self.0.lock().unwrap();
        s.calls.push("GetImagePulledRecord".into());
        Ok(s.records.get(r).cloned())
    }
    fn write_image_pulled_record(&self, r: &ImagePulledRecord) -> Result<(), Error> {
        let mut s = self.0.lock().unwrap();
        s.calls.push("WriteImagePulledRecord".into());
        if let Some(e) = s.write_err.take() {
            return Err(Error(e));
        }
        s.records.insert(r.image_ref.clone(), r.clone());
        Ok(())
    }
    fn delete_image_pulled_record(&self, r: &str) -> Result<(), Error> {
        let mut s = self.0.lock().unwrap();
        s.calls.push("DeleteImagePulledRecord".into());
        if let Some(e) = s.write_err.take() {
            return Err(Error(e));
        }
        s.records.remove(r);
        Ok(())
    }
}

fn cached(f: &Fake, i: i32, r: i32) -> CachedPullRecordsAccessor {
    CachedPullRecordsAccessor::new(Arc::new(f.clone()), i, r, 10)
}

#[test]
fn image_pull_manager_cache_new_warms_and_is_authoritative() {
    let f = Fake::with(5, 9);
    let c = cached(&f, 100, 100);
    assert!(c.intents_authoritative() && c.pulled_records_authoritative());
    // authoritative: hits and misses never reach the delegate again
    let before = f.calls().len();
    assert!(c.image_pull_intent_exists("image-003").unwrap());
    assert!(!c.image_pull_intent_exists("nope").unwrap());
    assert!(c.get_image_pulled_record("ref-001").unwrap().is_some());
    assert!(c.get_image_pulled_record("nope").unwrap().is_none());
    assert_eq!(f.calls().len(), before);
}

#[test]
fn image_pull_manager_cache_new_list_errors_non_authoritative() {
    let f = Fake::with(5, 9);
    {
        let mut s = f.0.lock().unwrap();
        s.intents_list_err = Some("intentsError".into());
        s.records_list_err = Some("recordsError".into());
    }
    let c = cached(&f, 100, 100);
    assert!(!c.intents_authoritative() && !c.pulled_records_authoritative());
    // cache was empty, so it was populated anyway
    assert_eq!(c.intents_size(), 5);
    assert_eq!(c.pulled_records_size(), 9);
}

#[test]
fn image_pull_manager_cache_new_overflow_non_authoritative() {
    // 51 intents > cache of 50, 101 records > cache of 100
    let f = Fake::with(51, 101);
    let c = cached(&f, 50, 100);
    assert!(!c.intents_authoritative() && !c.pulled_records_authoritative());
    assert_eq!(c.intents_size(), 100);
    assert_eq!(c.pulled_records_size(), 100);
    // a miss now falls through to the delegate (non-authoritative)
    assert!(c.image_pull_intent_exists("image-050").unwrap());
}

#[test]
fn image_pull_manager_cache_list_partial_error_semantics() {
    let f = Fake::with(4, 0);
    let c = cached(&f, 100, 100);
    assert!(c.intents_authoritative());
    // authoritative: list passes through, error and all, and stays so
    f.0.lock().unwrap().intents_list_err = Some("partial".into());
    let (items, err) = c.list_image_pull_intents();
    assert_eq!(items.len(), 4);
    assert_eq!(err.unwrap().0, "partial");
    assert!(c.intents_authoritative());
}

#[test]
fn image_pull_manager_cache_list_recovers_authoritative() {
    let f = Fake::with(4, 0);
    f.0.lock().unwrap().intents_list_err = Some("e".into());
    let c = cached(&f, 100, 100);
    assert!(!c.intents_authoritative());
    f.0.lock().unwrap().intents_list_err = None;
    let (items, err) = c.list_image_pull_intents();
    assert_eq!((items.len(), err), (4, None));
    assert!(c.intents_authoritative());
}

#[test]
fn image_pull_manager_cache_non_authoritative_exists_fills_cache() {
    let f = Fake::with(3, 3);
    f.0.lock().unwrap().intents_list_err = Some("e".into());
    f.0.lock().unwrap().records_list_err = Some("e".into());
    let c = cached(&f, 100, 100);
    // delegate gets a new entry the cache does not know about
    f.0.lock()
        .unwrap()
        .records
        .insert("late".into(), rec("late"));
    assert_eq!(
        c.get_image_pulled_record("late")
            .unwrap()
            .unwrap()
            .image_ref,
        "late"
    );
    let n = f.calls().len();
    assert!(c.get_image_pulled_record("late").unwrap().is_some());
    assert_eq!(f.calls().len(), n, "second get served from cache");
    // not found stays not found, nothing cached
    assert!(c.get_image_pulled_record("none").unwrap().is_none());
}

#[test]
fn image_pull_manager_cache_write_and_delete_write_through() {
    let f = Fake::with(2, 2);
    let c = cached(&f, 100, 100);
    c.write_image_pull_intent("new").unwrap();
    assert!(f.0.lock().unwrap().intents.contains_key("new"));
    assert!(c.image_pull_intent_exists("new").unwrap());
    c.delete_image_pull_intent("new").unwrap();
    assert!(!f.0.lock().unwrap().intents.contains_key("new"));
    assert!(!c.image_pull_intent_exists("new").unwrap());
    // explicit delete keeps the cache authoritative
    assert!(c.intents_authoritative());

    c.write_image_pulled_record(&rec("r-new")).unwrap();
    assert!(c.get_image_pulled_record("r-new").unwrap().is_some());
    c.delete_image_pulled_record("r-new").unwrap();
    assert!(c.get_image_pulled_record("r-new").unwrap().is_none());
    assert!(c.pulled_records_authoritative());
}

#[test]
fn image_pull_manager_cache_delegate_write_error_leaves_cache_untouched() {
    let f = Fake::with(1, 1);
    let c = cached(&f, 100, 100);
    f.0.lock().unwrap().write_err = Some("boom".into());
    assert_eq!(c.write_image_pull_intent("x").unwrap_err().0, "boom");
    assert!(!c.image_pull_intent_exists("x").unwrap());
    f.0.lock().unwrap().write_err = Some("boom".into());
    assert_eq!(
        c.write_image_pulled_record(&rec("x")).unwrap_err().0,
        "boom"
    );
    assert!(c.get_image_pulled_record("x").unwrap().is_none());
    // failed delete keeps the cached record
    f.0.lock().unwrap().write_err = Some("boom".into());
    assert!(c.delete_image_pulled_record("ref-000").is_err());
    assert!(c.get_image_pulled_record("ref-000").unwrap().is_some());
}

#[test]
fn image_pull_manager_lru_cache_eviction() {
    let c: LruCache<u32> = LruCache::new(2);
    c.set_authoritative(true);
    c.set("a", 1);
    c.set("b", 2);
    assert_eq!(c.get("a"), Some(1)); // a is now most recent
    assert!(c.is_authoritative());
    c.set("c", 3); // evicts b
    assert!(!c.is_authoritative());
    assert_eq!(c.get("b"), None);
    assert_eq!((c.get("a"), c.get("c")), (Some(1), Some(3)));
    assert_eq!(c.len(), 2);
    // Delete does not alter authoritative; Clear of a non-empty cache does
    c.set_authoritative(true);
    c.delete("a");
    assert!(c.is_authoritative());
    c.clear();
    assert!(!c.is_authoritative());
    assert!(c.is_empty());
    // overwriting an existing key never evicts
    c.set("x", 1);
    c.set_authoritative(true);
    c.set("x", 2);
    assert!(c.is_authoritative());
    assert_eq!(c.get("x"), Some(2));
}
