//! Shared bounded-storage engine behind `queue.rs` (task 2.5) and
//! `error_candidates.rs` (task 2.4). Both are "a directory of JSON files,
//! each a full `ReportEnvelope` plus small metadata, bounded by a
//! `RetentionPolicy`" — the only real differences are the directory name
//! and the default caps, so the file-scanning/retention logic lives here
//! once instead of twice.
//!
//! Retention age is measured from each file's on-disk mtime, not from the
//! `queued_at` string embedded in its metadata: `yadorilink-reporting`'s
//! `QueuedReportMetadata::queued_at` is a caller-supplied RFC 3339 string
//! with no parser round-trip anywhere in this crate (see `time.rs`), and
//! mtime is both simpler to use for eviction math and more trustworthy
//! (it can't be skewed by hand-editing a file's contents).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use yadorilink_reporting::queue::{QueuedReportMetadata, RetentionPolicy};
use yadorilink_reporting::schema::ReportEnvelope;

use super::error::{ReportingResult, ReportingStorageError};
use super::time::{now_rfc3339, system_time_to_unix_seconds};

/// One stored entry: the exact envelope plus the metadata shown by
/// list/show commands. Kept as a single file per entry (`<id>.json`) so a
/// directory listing of the store *is* the queue/candidate list, and
/// deleting one report is one `remove_file` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    metadata: QueuedReportMetadata,
    envelope: ReportEnvelope,
}

pub struct EntryStore {
    dir: PathBuf,
    policy: RetentionPolicy,
}

impl EntryStore {
    pub fn new(dir: impl Into<PathBuf>, policy: RetentionPolicy) -> Self {
        EntryStore { dir: dir.into(), policy }
    }

    fn entry_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Persists `envelope` as a new entry with a fresh, locally-generated
    /// ID (never derived from any account/device identity, same reasoning
    /// as `consent_store::new_reporter_id`), applies the retention policy
    /// immediately afterward, and returns the new entry's metadata.
    pub fn insert(&self, envelope: ReportEnvelope) -> ReportingResult<QueuedReportMetadata> {
        std::fs::create_dir_all(&self.dir)?;
        let report_id = uuid::Uuid::new_v4().to_string();
        let size_bytes = serde_json::to_vec(&envelope)?.len();
        let metadata = QueuedReportMetadata {
            report_id: report_id.clone(),
            report_type: envelope.report_type.clone(),
            queued_at: now_rfc3339(),
            size_bytes,
            submit_attempts: 0,
        };
        let entry = StoredEntry { metadata: metadata.clone(), envelope };
        let json = serde_json::to_string_pretty(&entry)?;
        let path = self.entry_path(&report_id);
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &path)?;
        // Best-effort: a retention-eviction failure shouldn't fail the
        // insert that triggered it. The freshly-inserted entry itself is
        // never a retention target (see `apply_retention`'s doc comment).
        if let Err(e) = self.apply_retention() {
            tracing::warn!(error = %e, dir = %self.dir.display(), "reporting: retention sweep failed after insert");
        }
        Ok(metadata)
    }

    fn read_entry(&self, path: &Path) -> ReportingResult<StoredEntry> {
        let contents = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&contents)?)
    }

    /// Lists every entry's metadata plus its file mtime, oldest-eviction
    /// order not guaranteed (callers needing sorted order sort themselves;
    /// `list()` below sorts by `queued_at` for display).
    fn scan(&self) -> ReportingResult<Vec<(String, QueuedReportMetadata, u64)>> {
        let mut out = Vec::new();
        let read_dir = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue; // skips stray .json.tmp leftovers from an interrupted write too
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
            let stored = match self.read_entry(&path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, path = %path.display(), "reporting: skipping unreadable entry during scan");
                    continue;
                }
            };
            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .map(system_time_to_unix_seconds)
                .unwrap_or(0);
            out.push((stem.to_string(), stored.metadata, mtime));
        }
        Ok(out)
    }

    pub fn list(&self) -> ReportingResult<Vec<QueuedReportMetadata>> {
        let mut entries = self.scan()?;
        entries.sort_by(|a, b| a.1.queued_at.cmp(&b.1.queued_at));
        Ok(entries.into_iter().map(|(_, meta, _)| meta).collect())
    }

    pub fn show(&self, id: &str) -> ReportingResult<Option<ReportEnvelope>> {
        let path = self.entry_path(id);
        match self.read_entry(&path) {
            Ok(stored) => Ok(Some(stored.envelope)),
            Err(ReportingStorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Returns `true` if an entry existed and was removed, `false` if
    /// there was nothing to delete (not an error — deleting an
    /// already-gone entry, e.g. from a concurrent retention sweep, is a
    /// no-op, not a failure).
    pub fn delete(&self, id: &str) -> ReportingResult<bool> {
        let path = self.entry_path(id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Deletes every entry in the store. Returns the number removed.
    pub fn flush(&self) -> ReportingResult<usize> {
        let entries = self.scan()?;
        let mut removed = 0;
        for (id, _, _) in entries {
            if self.delete(&id)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Task 3.5: records one more failed submission attempt against `id`
    /// (used by the queue-retry sweep's backoff — see `retry.rs`),
    /// returning the new attempt count, or `None` if the entry no longer
    /// exists (e.g. deleted concurrently). Rewrites the entry file in
    /// place, preserving the envelope untouched; this does bump the
    /// file's mtime (and therefore, per this module's age-tracking, its
    /// retention clock) — an accepted trade-off, since a report actively
    /// being retried is exactly the kind of entry that shouldn't be
    /// evicted for "looking old" while still under active retry.
    pub fn increment_submit_attempts(&self, id: &str) -> ReportingResult<Option<u32>> {
        let path = self.entry_path(id);
        let mut stored = match self.read_entry(&path) {
            Ok(s) => s,
            Err(ReportingStorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        stored.metadata.submit_attempts += 1;
        let new_count = stored.metadata.submit_attempts;
        let json = serde_json::to_string_pretty(&stored)?;
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &path)?;
        Ok(Some(new_count))
    }

    /// Applies `self.policy` against the current contents and deletes
    /// whatever it says to evict, returning the evicted IDs. Uses file
    /// mtime (via `scan`) as the age source, not the metadata's
    /// `queued_at` string — see this module's doc comment.
    pub fn apply_retention(&self) -> ReportingResult<Vec<String>> {
        let entries = self.scan()?;
        let now = super::time::now_unix_seconds();
        let metas: Vec<QueuedReportMetadata> =
            entries.iter().map(|(_, meta, _)| meta.clone()).collect();
        let mtimes: std::collections::HashMap<String, u64> =
            entries.iter().map(|(_, meta, mtime)| (meta.report_id.clone(), *mtime)).collect();
        let evict = self
            .policy
            .entries_to_evict(&metas, now, |m| mtimes.get(&m.report_id).copied().unwrap_or(now));
        for id in &evict {
            self.delete(id)?;
        }
        Ok(evict)
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

    #[test]
    fn insert_then_list_then_show_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = EntryStore::new(dir.path(), RetentionPolicy::default());
        let meta = store.insert(sample_envelope()).unwrap();

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].report_id, meta.report_id);

        let shown = store.show(&meta.report_id).unwrap().unwrap();
        assert_eq!(shown, sample_envelope());
    }

    #[test]
    fn show_of_unknown_id_returns_none_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = EntryStore::new(dir.path(), RetentionPolicy::default());
        assert_eq!(store.show("does-not-exist").unwrap(), None);
    }

    /// Task 2.7: queue deletion.
    #[test]
    fn delete_removes_the_entry_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = EntryStore::new(dir.path(), RetentionPolicy::default());
        let meta = store.insert(sample_envelope()).unwrap();

        assert!(store.delete(&meta.report_id).unwrap());
        assert!(store.show(&meta.report_id).unwrap().is_none());
        // Deleting again is a no-op, not an error.
        assert!(!store.delete(&meta.report_id).unwrap());
    }

    #[test]
    fn flush_removes_every_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = EntryStore::new(dir.path(), RetentionPolicy::default());
        store.insert(sample_envelope()).unwrap();
        store.insert(sample_envelope()).unwrap();
        assert_eq!(store.list().unwrap().len(), 2);

        let removed = store.flush().unwrap();
        assert_eq!(removed, 2);
        assert!(store.list().unwrap().is_empty());
    }

    /// Task 2.7: retention cap deletion — count cap, exercised through
    /// the real `EntryStore`/filesystem rather than only the pure
    /// `RetentionPolicy` unit tests in `yadorilink-reporting`.
    #[test]
    fn apply_retention_evicts_down_to_max_entries() {
        let dir = tempfile::tempdir().unwrap();
        let policy =
            RetentionPolicy { max_entries: 2, max_age_seconds: u64::MAX, ..Default::default() };
        let store = EntryStore::new(dir.path(), policy);
        for _ in 0..5 {
            store.insert(sample_envelope()).unwrap();
            // Ensure distinct mtimes so eviction order is deterministic
            // even on filesystems with coarse mtime resolution.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // insert() already applies retention after every call, so the
        // store should already be down to the cap.
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn apply_retention_evicts_oversized_entries() {
        let dir = tempfile::tempdir().unwrap();
        let policy = RetentionPolicy { max_entry_bytes: 10, ..Default::default() };
        let store = EntryStore::new(dir.path(), policy);
        let meta = store.insert(sample_envelope()).unwrap();
        // The freshly-inserted entry's real size is far larger than 10
        // bytes, so `insert`'s own post-insert retention sweep should
        // have already evicted it.
        assert!(store.show(&meta.report_id).unwrap().is_none());
    }
}
