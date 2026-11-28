//! Port of `pkg/kubelet/images/pullmanager/metrics.go` (release-1.35): the
//! `kubelet_imagemanager_*` metrics and `meteringRecordsAccessor`, a
//! `PullRecordsAccessor` wrapper that refreshes the on-disk record gauges
//! after every successful write or delete.
//!
//! The in-memory cache usage gauges are defined here
//! (`inmemory_pullintents_usage_percent`, `inmemory_pulledrecords_usage_percent`)
//! and are fed by the cached accessor (kubelet-P2-25f).

use prometheus::{Gauge, IntCounterVec, Opts, Registry};

use super::image_pull_manager::{
    Error, FsPullRecordsAccessor, ImagePullIntent, ImagePulledRecord, PullRecordsAccessor,
};

/// `imageManagerSubsystem = kubeletmetrics.KubeletSubsystem + "_imagemanager"`.
const IMAGE_MANAGER_SUBSYSTEM: &str = "kubelet_imagemanager";

/// `sizeExposedPullRecordsAccessor`: an accessor that can report how many
/// records it stores.
pub trait SizeExposedPullRecordsAccessor: PullRecordsAccessor {
    fn intents_size(&self) -> Result<usize, Error>;
    fn pulled_records_size(&self) -> Result<usize, Error>;
}

impl SizeExposedPullRecordsAccessor for FsPullRecordsAccessor {
    fn intents_size(&self) -> Result<usize, Error> {
        FsPullRecordsAccessor::intents_size(self)
    }
    fn pulled_records_size(&self) -> Result<usize, Error> {
        FsPullRecordsAccessor::pulled_records_size(self)
    }
}

fn gauge(name: &str, help: &str) -> Gauge {
    Gauge::with_opts(Opts::new(name, help).subsystem(IMAGE_MANAGER_SUBSYSTEM))
        .expect("static metric opts are valid")
}

/// The package-level metric vars of metrics.go.
#[derive(Clone)]
pub struct ImagePullMetrics {
    /// `ondisk_pullintents`
    pub fs_pull_intents_size: Gauge,
    /// `ondisk_pulledrecords`
    pub fs_pulled_records_size: Gauge,
    /// `inmemory_pullintents_usage_percent`
    pub in_mem_intents_percent: Gauge,
    /// `inmemory_pulledrecords_usage_percent`
    pub in_mem_pulled_records_percent: Gauge,
    /// `image_mustpull_checks_total{result}`
    pub must_pull_checks_total: IntCounterVec,
}

impl Default for ImagePullMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ImagePullMetrics {
    pub fn new() -> Self {
        Self {
            fs_pull_intents_size: gauge("ondisk_pullintents", "Number of ImagePullIntents stored on disk."),
            fs_pulled_records_size: gauge("ondisk_pulledrecords", "Number of ImagePulledRecords stored on disk."),
            in_mem_intents_percent: gauge(
                "inmemory_pullintents_usage_percent",
                "The ImagePullIntents in-memory cache usage in percent.",
            ),
            in_mem_pulled_records_percent: gauge(
                "inmemory_pulledrecords_usage_percent",
                "The ImagePulledRecords in-memory cache usage in percent.",
            ),
            must_pull_checks_total: IntCounterVec::new(
                Opts::new(
                    "image_mustpull_checks_total",
                    "Counter for how many times kubelet checked whether credentials need to be re-verified to access an image",
                )
                .subsystem(IMAGE_MANAGER_SUBSYSTEM),
                &["result"],
            )
            .expect("static metric opts are valid"),
        }
    }

    /// `init()`: `legacyregistry.MustRegister` of the five collectors.
    pub fn register(&self, registry: &Registry) -> prometheus::Result<()> {
        registry.register(Box::new(self.fs_pull_intents_size.clone()))?;
        registry.register(Box::new(self.fs_pulled_records_size.clone()))?;
        registry.register(Box::new(self.in_mem_intents_percent.clone()))?;
        registry.register(Box::new(self.in_mem_pulled_records_percent.clone()))?;
        registry.register(Box::new(self.must_pull_checks_total.clone()))
    }

    /// `recordMustAttemptImagePullResult`; `result` is one of
    /// `MustAttemptImagePullResult::as_str` of the pull manager.
    pub fn record_must_attempt_image_pull_result(&self, result: &str) {
        self.must_pull_checks_total
            .with_label_values(&[result])
            .inc();
    }
}

/// `meteringRecordsAccessor`: updates the on-disk size gauges on write
/// operations that succeed.
pub struct MeteringRecordsAccessor<A: SizeExposedPullRecordsAccessor> {
    inner: A,
    intents_size: Gauge,
    pulled_records_size: Gauge,
}

impl<A: SizeExposedPullRecordsAccessor> MeteringRecordsAccessor<A> {
    /// `NewMeteringRecordsAccessor`.
    pub fn new(inner: A, intents_size: Gauge, pulled_records_size: Gauge) -> Self {
        Self {
            inner,
            intents_size,
            pulled_records_size,
        }
    }

    fn record_intents_size(&self) {
        match self.inner.intents_size() {
            Ok(n) => self.intents_size.set(n as f64),
            Err(e) => {
                tracing::debug!(%e, "failed to read number of ImagePullIntents, can't update metric")
            }
        }
    }

    fn record_pulled_records_size(&self) {
        match self.inner.pulled_records_size() {
            Ok(n) => self.pulled_records_size.set(n as f64),
            Err(e) => {
                tracing::debug!(%e, "failed to read number of ImagePulledRecords, can't update metric")
            }
        }
    }
}

impl<A: SizeExposedPullRecordsAccessor> PullRecordsAccessor for MeteringRecordsAccessor<A> {
    fn list_image_pull_intents(&self) -> (Vec<ImagePullIntent>, Option<Error>) {
        self.inner.list_image_pull_intents()
    }
    fn image_pull_intent_exists(&self, image: &str) -> Result<bool, Error> {
        self.inner.image_pull_intent_exists(image)
    }
    fn write_image_pull_intent(&self, image: &str) -> Result<(), Error> {
        self.inner.write_image_pull_intent(image)?;
        self.record_intents_size();
        Ok(())
    }
    fn delete_image_pull_intent(&self, image: &str) -> Result<(), Error> {
        self.inner.delete_image_pull_intent(image)?;
        self.record_intents_size();
        Ok(())
    }
    fn list_image_pulled_records(&self) -> (Vec<ImagePulledRecord>, Option<Error>) {
        self.inner.list_image_pulled_records()
    }
    fn get_image_pulled_record(&self, image_ref: &str) -> Result<Option<ImagePulledRecord>, Error> {
        self.inner.get_image_pulled_record(image_ref)
    }
    fn write_image_pulled_record(&self, record: &ImagePulledRecord) -> Result<(), Error> {
        self.inner.write_image_pulled_record(record)?;
        self.record_pulled_records_size();
        Ok(())
    }
    fn delete_image_pulled_record(&self, image_ref: &str) -> Result<(), Error> {
        self.inner.delete_image_pulled_record(image_ref)?;
        self.record_pulled_records_size();
        Ok(())
    }
}
