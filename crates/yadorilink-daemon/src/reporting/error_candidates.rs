//! bounded local persistence for error-report *candidates*
//! — severe-error snapshots the daemon captures on its own
//! (section 3.3's job to actually create these from real error hooks;
//! this module only owns the storage) before the user has decided
//! whether to preview, export, submit, or discard them. Lives at
//! `<config_dir>/reporting/error-candidates/`, a separate directory from
//! `queue/` because a candidate hasn't been confirmed by the
//! user yet — it's not "queued for submission," it's "waiting for the
//! user to look at it."
//!
//! Default retention (the exact cap is intentionally left unspecified
//! upstream, so these are this module's own reasoned defaults, not a
//! number pulled from a spec):
//! - `max_entries = 20`: candidates are created automatically by daemon
//!   error hooks with no user action, so the cap needs to be tighter than
//!   the user-confirmed queue's 50 — a crash loop must not fill the disk,
//!   and old unconfirmed candidates are the least valuable data this
//!   crate stores (nobody has even looked at them yet).
//! - `max_age_seconds = 14 days`: half the queue's 30-day default. A
//!   candidate nobody has previewed in two weeks is unlikely to still be
//!   useful context for the user, and clearing it bounds worst-case growth
//!   on a machine that never opts in to reporting at all.
//! - `max_entry_bytes`: reuses `yadorilink_reporting::schema::MAX_REPORT_BYTES`
//!   — candidates are full `ReportEnvelope`s subject to the same overall
//!   size contract as every other report.
//!
//! extension: `create_candidate_with_summary`/`show_with_summary`
//! store/retrieve the `RedactionSummary` produced at candidate-creation
//! time (by the `ErrorPayloadBuilder::build()` hook) alongside the
//! entry, as a small sidecar `<id>.redaction.json` file next to the
//! `EntryStore`-managed `<id>.json`. This is deliberately *not* modeled as
//! a change to the shared `EntryStore`/`QueuedReportMetadata` shape (used
//! by the submission queue too, where no such summary exists) — the
//! candidate store already owns its own directory, so a sidecar file next
//! to each entry is a fully additive extension with no risk to
//! `queue.rs`/`entry_store.rs`'s existing contract or tests. Recomputing
//! the summary at preview time instead (by re-running `redact()` over the
//! already-stored, already-redacted payload) was rejected: redaction is
//! idempotent by design (see `redact.rs`'s doc comment), so a fresh pass
//! over already-redacted text always finds nothing — that would silently
//! under-report to the user what was actually stripped when the candidate
//! was created.

use std::path::PathBuf;

use yadorilink_reporting::queue::{QueuedReportMetadata, RetentionPolicy};
use yadorilink_reporting::redact::RedactionSummary;
use yadorilink_reporting::schema::{ReportEnvelope, MAX_REPORT_BYTES};

use super::entry_store::EntryStore;
use super::error::ReportingResult;

pub fn default_retention_policy() -> RetentionPolicy {
    RetentionPolicy {
        max_entries: 20,
        max_age_seconds: 14 * 24 * 60 * 60,
        max_entry_bytes: MAX_REPORT_BYTES,
    }
}

pub struct ErrorCandidateStore {
    dir: PathBuf,
    inner: EntryStore,
}

impl ErrorCandidateStore {
    pub fn new(reporting_dir: impl Into<PathBuf>) -> Self {
        ErrorCandidateStore::with_policy(reporting_dir, default_retention_policy())
    }

    pub fn with_policy(reporting_dir: impl Into<PathBuf>, policy: RetentionPolicy) -> Self {
        let dir = reporting_dir.into().join("error-candidates");
        ErrorCandidateStore { inner: EntryStore::new(dir.clone(), policy), dir }
    }

    pub fn create_candidate(
        &self,
        envelope: ReportEnvelope,
    ) -> ReportingResult<QueuedReportMetadata> {
        self.inner.insert(envelope)
    }

    /// Same as `create_candidate`, but also persists the
    /// redaction summary produced while building `envelope`'s payload, so
    /// a later preview (`show_with_summary`) can show the user exactly
    /// what categories of sensitive data were stripped — see module doc
    /// comment for why this is a sidecar file rather than a shared-type
    /// change.
    pub fn create_candidate_with_summary(
        &self,
        envelope: ReportEnvelope,
        summary: &RedactionSummary,
    ) -> ReportingResult<QueuedReportMetadata> {
        let meta = self.inner.insert(envelope)?;
        self.write_summary(&meta.report_id, summary)?;
        Ok(meta)
    }

    pub fn list(&self) -> ReportingResult<Vec<QueuedReportMetadata>> {
        self.inner.list()
    }

    pub fn show(&self, candidate_id: &str) -> ReportingResult<Option<ReportEnvelope>> {
        self.inner.show(candidate_id)
    }

    /// Like `show`, but also returns the redaction summary captured at
    /// creation time (empty if the candidate was created via the plain
    /// `create_candidate`, or if the sidecar file is missing/unreadable —
    /// a summary read failure must never hide the underlying report
    /// itself).
    pub fn show_with_summary(
        &self,
        candidate_id: &str,
    ) -> ReportingResult<Option<(ReportEnvelope, RedactionSummary)>> {
        let Some(envelope) = self.inner.show(candidate_id)? else { return Ok(None) };
        let summary = self.read_summary(candidate_id);
        Ok(Some((envelope, summary)))
    }

    pub fn delete(&self, candidate_id: &str) -> ReportingResult<bool> {
        let _ = std::fs::remove_file(self.summary_path(candidate_id));
        self.inner.delete(candidate_id)
    }

    pub fn flush(&self) -> ReportingResult<usize> {
        self.inner.flush()
    }

    pub fn apply_retention(&self) -> ReportingResult<Vec<String>> {
        self.inner.apply_retention()
    }

    /// The most recently created candidate, if any — backs
    /// `yadorilink report error --last` (section 4's job to expose over
    /// the CLI; this is the storage-layer primitive it will call).
    pub fn most_recent(&self) -> ReportingResult<Option<QueuedReportMetadata>> {
        Ok(self.list()?.into_iter().last())
    }

    /// Deliberately *not* `.json` — `EntryStore::scan` (the engine behind
    /// `list`/`show`) discovers entries purely by `.json` extension, so a
    /// `<id>.redaction.json` sidecar would otherwise be misdetected as a
    /// candidate entry itself (and then skipped with a logged warning
    /// when it failed to deserialize as a `StoredEntry` — harmless, but
    /// noisy and easy to avoid by construction instead).
    fn summary_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.redaction"))
    }

    fn write_summary(&self, id: &str, summary: &RedactionSummary) -> ReportingResult<()> {
        if summary.is_empty() {
            return Ok(()); // nothing redacted — no sidecar file needed
        }
        std::fs::create_dir_all(&self.dir)?;
        let serializable: Vec<(String, usize)> = summary
            .categories
            .iter()
            .map(|(category, count)| (format!("{category:?}"), *count))
            .collect();
        let json = serde_json::to_string_pretty(&serializable)?;
        std::fs::write(self.summary_path(id), json)?;
        Ok(())
    }

    /// Best-effort: a missing or corrupt sidecar file just means "no
    /// summary available," never a hard error surfaced to the caller.
    fn read_summary(&self, id: &str) -> RedactionSummary {
        let Ok(contents) = std::fs::read_to_string(self.summary_path(id)) else {
            return RedactionSummary::default();
        };
        let Ok(pairs) = serde_json::from_str::<Vec<(String, usize)>>(&contents) else {
            return RedactionSummary::default();
        };
        RedactionSummary {
            categories: pairs.into_iter().map(|(c, n)| (category_from_debug_str(&c), n)).collect(),
        }
    }
}

/// Inverse of the `{category:?}` formatting used in `write_summary` —
/// deliberately falls back to `AbsolutePath` (the most conservative,
/// "something was redacted" category) rather than panicking or discarding
/// the entry on a name it doesn't recognize (e.g. a sidecar file written
/// by a future version of this module with a new category).
fn category_from_debug_str(s: &str) -> yadorilink_reporting::redact::RedactionCategory {
    use yadorilink_reporting::redact::RedactionCategory::*;
    match s {
        "AbsolutePath" => AbsolutePath,
        "HomeDirectory" => HomeDirectory,
        "BearerToken" => BearerToken,
        "PrivateKeyBlock" => PrivateKeyBlock,
        "WireguardKey" => WireguardKey,
        "IpAddress" => IpAddress,
        "CredentialedUrl" => CredentialedUrl,
        "UuidLikeId" => UuidLikeId,
        "EmailAddress" => EmailAddress,
        _ => AbsolutePath,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_reporting::builder::{
        build_error_envelope, ErrorPayloadBuilder, ReportEnvironment,
    };
    use yadorilink_reporting::schema::OsFamily;

    fn sample_error_envelope() -> ReportEnvelope {
        let env = ReportEnvironment {
            generated_at: "2026-01-01T00:00:00Z".into(),
            yadorilink_version: "0.1.0".into(),
            os_family: OsFamily::Macos,
            os_version_bucket: "15.x".into(),
            arch: "aarch64".into(),
            install_channel: None,
            anonymous_reporter_id: None,
        };
        let builder = ErrorPayloadBuilder::new("sync_conflict", "sync-core");
        build_error_envelope(env, builder).0
    }

    #[test]
    fn create_list_show_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = ErrorCandidateStore::new(dir.path());
        let meta = store.create_candidate(sample_error_envelope()).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
        assert_eq!(store.show(&meta.report_id).unwrap().unwrap(), sample_error_envelope());
        assert_eq!(store.most_recent().unwrap().unwrap().report_id, meta.report_id);
    }

    /// retention cap deletion for error candidates specifically
    /// (distinct defaults from the queue).
    #[test]
    fn default_policy_caps_at_twenty_entries() {
        let policy = default_retention_policy();
        assert_eq!(policy.max_entries, 20);
        assert_eq!(policy.max_age_seconds, 14 * 24 * 60 * 60);
    }

    #[test]
    fn delete_removes_a_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let store = ErrorCandidateStore::new(dir.path());
        let meta = store.create_candidate(sample_error_envelope()).unwrap();
        assert!(store.delete(&meta.report_id).unwrap());
        assert!(store.show(&meta.report_id).unwrap().is_none());
    }

    #[test]
    fn candidates_and_queue_are_kept_in_separate_directories() {
        let dir = tempfile::tempdir().unwrap();
        let store = ErrorCandidateStore::new(dir.path());
        store.create_candidate(sample_error_envelope()).unwrap();
        assert!(dir.path().join("error-candidates").is_dir());
        assert!(!dir.path().join("queue").exists());
    }

    /// the redaction summary captured at creation time survives
    /// a round trip through the sidecar file.
    #[test]
    fn create_candidate_with_summary_round_trips_the_summary() {
        let dir = tempfile::tempdir().unwrap();
        let store = ErrorCandidateStore::new(dir.path());
        let builder = ErrorPayloadBuilder::new("sync_conflict", "sync-core")
            .log_lines(vec!["reading /Users/alice/secret failed".to_string()]);
        let env = ReportEnvironment {
            generated_at: "2026-01-01T00:00:00Z".into(),
            yadorilink_version: "0.1.0".into(),
            os_family: OsFamily::Linux,
            os_version_bucket: "24.04".into(),
            arch: "x86_64".into(),
            install_channel: None,
            anonymous_reporter_id: None,
        };
        let (envelope, summary) = build_error_envelope(env, builder);
        assert!(!summary.is_empty());

        let meta = store.create_candidate_with_summary(envelope.clone(), &summary).unwrap();
        let (shown_envelope, shown_summary) =
            store.show_with_summary(&meta.report_id).unwrap().unwrap();
        assert_eq!(shown_envelope, envelope);
        assert_eq!(shown_summary.categories.len(), summary.categories.len());
    }

    /// A plain `create_candidate` (no summary given) shows an empty
    /// summary, not an error.
    #[test]
    fn show_with_summary_of_a_plain_candidate_returns_an_empty_summary() {
        let dir = tempfile::tempdir().unwrap();
        let store = ErrorCandidateStore::new(dir.path());
        let meta = store.create_candidate(sample_error_envelope()).unwrap();
        let (_envelope, summary) = store.show_with_summary(&meta.report_id).unwrap().unwrap();
        assert!(summary.is_empty());
    }

    #[test]
    fn delete_also_removes_the_summary_sidecar_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = ErrorCandidateStore::new(dir.path());
        let builder = ErrorPayloadBuilder::new("sync_conflict", "sync-core")
            .log_lines(vec!["reading /Users/alice/secret failed".to_string()]);
        let env = ReportEnvironment {
            generated_at: "2026-01-01T00:00:00Z".into(),
            yadorilink_version: "0.1.0".into(),
            os_family: OsFamily::Linux,
            os_version_bucket: "24.04".into(),
            arch: "x86_64".into(),
            install_channel: None,
            anonymous_reporter_id: None,
        };
        let (envelope, summary) = build_error_envelope(env, builder);
        let meta = store.create_candidate_with_summary(envelope, &summary).unwrap();
        assert!(store.summary_path(&meta.report_id).exists());
        store.delete(&meta.report_id).unwrap();
        assert!(!store.summary_path(&meta.report_id).exists());
    }
}
