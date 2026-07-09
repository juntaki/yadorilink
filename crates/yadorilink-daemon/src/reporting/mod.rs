//! OSS usage/error reporting local storage (openspec change
//! `add-oss-usage-error-reporting`, tasks.md section 2). This module owns
//! everything under `<config_dir>/reporting/` — consent/config state,
//! aggregate usage counters, bounded error-candidate persistence, and the
//! bounded unsent-report queue. It deliberately depends only on
//! `yadorilink-reporting`'s pure types (`ConsentState`, `ReportEnvelope`,
//! `QueuedReportMetadata`, `RetentionPolicy`, ...) plus `std`/`serde_json`
//! — never `yadorilink-sync-core::index::SyncState` or anything else that
//! touches the sync-critical SQLite database, so a reporting-storage bug
//! can never corrupt or block sync (task 2.6).
//!
//! Submodules:
//! - `error`: `ReportingStorageError`/`ReportingResult`, used only within
//!   this module tree — never converted into `crate::error::DaemonError`.
//! - `time`: dependency-free RFC 3339 formatting.
//! - `consent_store`: task 2.1/2.2, `<config_dir>/reporting/consent.json`.
//! - `counters`: task 2.3, `<config_dir>/reporting/counters.json`.
//! - `entry_store`: shared engine behind the next two.
//! - `error_candidates`: task 2.4, `<config_dir>/reporting/error-candidates/`.
//! - `queue`: task 2.5, `<config_dir>/reporting/queue/`.
//!
//! `ReportingStorage` below is the facade that bundles all four stores
//! together and is the type `DaemonState`/section 3's IPC dispatch will
//! actually hold — its `note_*`/`*_best_effort` methods are the
//! infallible surface arbitrary daemon call sites (a command handler, a
//! sync-state transition, an error path) are meant to call directly,
//! satisfying task 2.6 by construction: there is no `Result` for such a
//! call site to mishandle. The individual stores' own `Result`-returning
//! methods remain available (via `ReportingStorage::{consent,queue,error_candidates}`
//! accessors) for reporting-specific code (future CLI/IPC handlers in
//! sections 3/4) that legitimately needs to see and report a failure.

pub mod consent_store;
pub mod counters;
mod entry_store;
pub mod environment;
pub mod error;
pub mod error_candidates;
pub mod hooks;
pub mod queue;
pub mod retry;
pub mod time;

use std::collections::BTreeMap;
use std::path::PathBuf;

use yadorilink_reporting::consent::ConsentState;
use yadorilink_reporting::redact::RedactionSummary;
use yadorilink_reporting::schema::ReportEnvelope;

use consent_store::ConsentStore;
use counters::ReportingCounters;
use error_candidates::ErrorCandidateStore;
use queue::QueueStore;

/// `<config_dir>/reporting` — a sibling of `device.json`/the block store,
/// never inside a linked/synced folder (design.md D3/D7).
pub fn reporting_dir() -> PathBuf {
    crate::device_config::config_dir().join("reporting")
}

pub struct ReportingStorage {
    consent: ConsentStore,
    counters: ReportingCounters,
    error_candidates: ErrorCandidateStore,
    queue: QueueStore,
}

impl ReportingStorage {
    /// Opens (without eagerly writing anything — see `consent_store`'s
    /// doc comment) reporting storage rooted at the daemon's normal
    /// config directory.
    pub fn open_default() -> Self {
        Self::open(reporting_dir())
    }

    pub fn open(reporting_dir: impl Into<PathBuf>) -> Self {
        let dir = reporting_dir.into();
        ReportingStorage {
            consent: ConsentStore::new(&dir),
            counters: ReportingCounters::open(&dir),
            error_candidates: ErrorCandidateStore::new(&dir),
            queue: QueueStore::new(&dir),
        }
    }

    pub fn consent(&self) -> &ConsentStore {
        &self.consent
    }

    pub fn counters(&self) -> &ReportingCounters {
        &self.counters
    }

    pub fn error_candidates(&self) -> &ErrorCandidateStore {
        &self.error_candidates
    }

    pub fn queue(&self) -> &QueueStore {
        &self.queue
    }

    // -- Infallible, "safe for any call site" surface (task 2.6) --------

    /// Best-effort consent read: reporting-disabled default on any
    /// storage failure, for call sites that just need to decide "is
    /// reporting on" without caring why a read might have failed.
    pub fn consent_or_default(&self) -> ConsentState {
        self.consent.load_or_default()
    }

    pub fn note_command_category(&self, category: &str) {
        self.counters.increment_command_category(category);
    }

    pub fn note_sync_state(&self, state: &str) {
        self.counters.record_sync_state(state);
    }

    pub fn note_error_category(&self, category: &str) {
        self.counters.record_error_category(category);
    }

    pub fn note_transfer_bytes(&self, bytes: u64) {
        self.counters.record_transfer_bytes(bytes);
    }

    pub fn note_latency_millis(&self, millis: u64) {
        self.counters.record_latency_millis(millis);
    }

    pub fn note_peer_count(&self, count: u32) {
        self.counters.record_peer_count(count);
    }

    pub fn note_linked_folders(&self, total: u32, policy_counts: BTreeMap<String, u32>) {
        self.counters.record_linked_folder_counts(total, policy_counts);
    }

    pub fn note_feature_flags(&self, flags: Vec<String>) {
        self.counters.record_feature_flags(flags);
    }

    /// Persists a severe-error candidate for later user review. Never
    /// propagates a failure: returns `None` (and logs a warning) instead
    /// of an `Err`, so a real error-hook call site (section 3.3, not yet
    /// wired) can call this from inside its own error-handling path
    /// without needing a nested `Result` of its own.
    pub fn record_error_candidate_best_effort(&self, envelope: ReportEnvelope) -> Option<String> {
        match self.error_candidates.create_candidate(envelope) {
            Ok(meta) => Some(meta.report_id),
            Err(e) => {
                tracing::warn!(error = %e, "reporting: failed to persist error candidate");
                None
            }
        }
    }

    /// Task 3.3/3.4: like `record_error_candidate_best_effort`, but also
    /// persists the redaction summary produced when the candidate's
    /// payload was built, so a later `yadorilink report error --preview`
    /// can show it (see `error_candidates.rs`'s module doc comment).
    pub fn record_error_candidate_with_summary_best_effort(
        &self,
        envelope: ReportEnvelope,
        summary: &RedactionSummary,
    ) -> Option<String> {
        match self.error_candidates.create_candidate_with_summary(envelope, summary) {
            Ok(meta) => Some(meta.report_id),
            Err(e) => {
                tracing::warn!(error = %e, "reporting: failed to persist error candidate");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage() -> (tempfile::TempDir, ReportingStorage) {
        let dir = tempfile::tempdir().unwrap();
        let storage = ReportingStorage::open(dir.path());
        (dir, storage)
    }

    #[test]
    fn opening_storage_does_not_write_any_files_until_something_mutates() {
        let (dir, _storage) = storage();
        // `ReportingCounters::open` reads (best-effort) but must not
        // create the directory just by opening; nothing else does either.
        assert!(!dir.path().exists() || std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn note_methods_never_return_a_result_a_caller_could_mishandle() {
        let (_dir, storage) = storage();
        // This is mostly a compile-time property (see module doc comment)
        // but exercising every "note_*" call site once demonstrates the
        // pattern a real sync/command call site would follow: no `?`, no
        // `.unwrap()`, nothing to propagate.
        storage.note_command_category("link");
        storage.note_sync_state("synced");
        storage.note_error_category("sync_conflict");
        storage.note_transfer_bytes(2048);
        storage.note_latency_millis(120);
        storage.note_peer_count(2);
        storage.note_linked_folders(1, BTreeMap::from([("eager".to_string(), 1)]));
        storage.note_feature_flags(vec!["on-demand-hydration".to_string()]);

        let payload = storage.counters().to_usage_payload();
        assert_eq!(payload.command_category_counts.get("link"), Some(&1));
    }

    /// Task 2.7: reporting-storage failure isolation. Points the
    /// reporting directory at a path that can never be created (a plain
    /// file already sits where the directory needs to go — portable
    /// across Unix and Windows, unlike chmod-based read-only tricks) and
    /// asserts every infallible call still returns normally without
    /// panicking, logging a warning instead of propagating.
    #[test]
    fn reporting_storage_failures_are_logged_and_never_propagate() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct CapturingWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for CapturingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for CapturingWriter {
            type Writer = Self;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let blocked_reporting_dir = dir.path().join("reporting");
        // A plain file sitting where the reporting directory needs to be
        // created makes every `create_dir_all` underneath it fail.
        std::fs::write(&blocked_reporting_dir, b"not a directory").unwrap();

        let writer = CapturingWriter::default();
        let subscriber = tracing_subscriber::fmt().with_writer(writer.clone()).finish();

        tracing::subscriber::with_default(subscriber, || {
            // Constructing storage over an unwritable path must not panic.
            let storage = ReportingStorage::open(&blocked_reporting_dir);

            // A representative sample of the infallible call-site surface:
            // none of these may panic or otherwise abort the "unrelated
            // daemon operation" this simulates being called from.
            storage.note_command_category("link");
            storage.note_error_category("daemon_startup");
            let candidate =
                super::error_candidates::ErrorCandidateStore::new(&blocked_reporting_dir);
            let _ = candidate; // constructing doesn't touch disk either

            let consent = storage.consent_or_default();
            assert_eq!(consent, ConsentState::default(), "falls back to the safe default");

            let candidate_id = storage.record_error_candidate_best_effort(sample_error_envelope());
            assert_eq!(candidate_id, None, "failure is reported as None, not a panic/Err");
        });

        let logs = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
        assert!(
            logs.to_lowercase().contains("warn") && logs.to_lowercase().contains("reporting"),
            "expected a warning-level reporting log, got: {logs}"
        );
    }

    fn sample_error_envelope() -> ReportEnvelope {
        use yadorilink_reporting::builder::{
            build_error_envelope, ErrorPayloadBuilder, ReportEnvironment,
        };
        use yadorilink_reporting::schema::OsFamily;
        let env = ReportEnvironment {
            generated_at: "2026-01-01T00:00:00Z".into(),
            yadorilink_version: "0.1.0".into(),
            os_family: OsFamily::Linux,
            os_version_bucket: "24.04".into(),
            arch: "x86_64".into(),
            install_channel: None,
            anonymous_reporter_id: None,
        };
        build_error_envelope(env, ErrorPayloadBuilder::new("daemon_startup", "control_socket")).0
    }
}
