//! bounded local storage for reports the user has already
//! confirmed (a usage summary or an error report) but that haven't been
//! submitted yet — either because network submission is disabled, the
//! submission attempt failed, or the user asked to export/inspect later
//! instead. Lives at `<config_dir>/reporting/queue/`, outside any linked
//! folder (this data must never sync to peers — nothing
//! in this module ever touches `yadorilink-sync-core` or a linked-folder
//! path).
//!
//! `flush` here means "delete every queued entry": actually retrying
//! submission against a configured endpoint is section 3.5/5's job (the
//! daemon-side retry loop and the HTTPS submission client, neither of
//! which exists yet); this storage layer only owns the bounded on-disk
//! list, not the transport.

use std::path::PathBuf;

use yadorilink_reporting::queue::{QueuedReportMetadata, RetentionPolicy};
use yadorilink_reporting::schema::ReportEnvelope;

use super::entry_store::EntryStore;
use super::error::ReportingResult;

pub struct QueueStore {
    inner: EntryStore,
}

impl QueueStore {
    pub fn new(reporting_dir: impl Into<PathBuf>) -> Self {
        QueueStore::with_policy(reporting_dir, RetentionPolicy::default())
    }

    pub fn with_policy(reporting_dir: impl Into<PathBuf>, policy: RetentionPolicy) -> Self {
        QueueStore { inner: EntryStore::new(reporting_dir.into().join("queue"), policy) }
    }

    pub fn enqueue(&self, envelope: ReportEnvelope) -> ReportingResult<QueuedReportMetadata> {
        self.inner.insert(envelope)
    }

    pub fn list(&self) -> ReportingResult<Vec<QueuedReportMetadata>> {
        self.inner.list()
    }

    pub fn show(&self, report_id: &str) -> ReportingResult<Option<ReportEnvelope>> {
        self.inner.show(report_id)
    }

    pub fn delete(&self, report_id: &str) -> ReportingResult<bool> {
        self.inner.delete(report_id)
    }

    /// bumps `report_id`'s `submit_attempts` after a failed,
    /// retryable submission attempt — used by the queue-retry sweep's
    /// backoff (`retry.rs`) to eventually give up on an entry that keeps
    /// failing rather than retrying it forever.
    pub fn increment_submit_attempts(&self, report_id: &str) -> ReportingResult<Option<u32>> {
        self.inner.increment_submit_attempts(report_id)
    }

    /// Deletes every queued report. See module doc comment for why this
    /// doesn't attempt a submit-then-clear cycle.
    pub fn flush(&self) -> ReportingResult<usize> {
        self.inner.flush()
    }

    pub fn apply_retention(&self) -> ReportingResult<Vec<String>> {
        self.inner.apply_retention()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_reporting::schema::{
        OsFamily, ReportPayload, ReportType, UsagePayload, SCHEMA_VERSION,
    };

    fn sample_envelope() -> ReportEnvelope {
        ReportEnvelope {
            schema_version: SCHEMA_VERSION,
            report_type: ReportType::Usage,
            generated_at: "2026-01-01T00:00:00Z".into(),
            yadorilink_version: "0.1.0".into(),
            os_family: OsFamily::Linux,
            os_version_bucket: "24.04".into(),
            arch: "x86_64".into(),
            install_channel: None,
            anonymous_reporter_id: None,
            payload: ReportPayload::Usage(UsagePayload::default()),
        }
    }

    /// queue deletion (via the public `QueueStore` facade, not
    /// just `EntryStore` directly).
    #[test]
    fn enqueue_list_delete_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let queue = QueueStore::new(dir.path());
        let meta = queue.enqueue(sample_envelope()).unwrap();
        assert_eq!(queue.list().unwrap().len(), 1);
        assert!(queue.delete(&meta.report_id).unwrap());
        assert!(queue.list().unwrap().is_empty());
    }

    #[test]
    fn queue_lives_outside_any_configured_directory_other_than_reporting() {
        let dir = tempfile::tempdir().unwrap();
        let queue = QueueStore::new(dir.path());
        queue.enqueue(sample_envelope()).unwrap();
        assert!(dir.path().join("queue").is_dir());
        // Nothing here ever touches a "linked" or "sync" subpath.
        assert!(!dir.path().join("linked").exists());
    }

    #[test]
    fn flush_clears_the_whole_queue() {
        let dir = tempfile::tempdir().unwrap();
        let queue = QueueStore::new(dir.path());
        queue.enqueue(sample_envelope()).unwrap();
        queue.enqueue(sample_envelope()).unwrap();
        assert_eq!(queue.flush().unwrap(), 2);
        assert!(queue.list().unwrap().is_empty());
    }
}
