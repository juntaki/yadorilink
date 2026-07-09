//! Task 3.3: severe-error hooks. A "severe error" here means a daemon
//! failure serious enough that a maintainer would want to know about it
//! even without a user filing a GitHub issue — startup failures and an
//! essential supervised task dying (REL-8) are the two real call sites
//! wired up in `main.rs`; this module only owns the capture logic
//! itself, kept separate from `main.rs` so it's independently testable.
//!
//! These hooks only ever *create a local candidate* (design.md D4) — they
//! never submit, queue for submission, or make a network call, regardless
//! of consent state. That's what makes them safe to call from a startup
//! path that runs before consent has even been loaded into `DaemonState`:
//! `record_severe_error` takes a `&ReportingStorage` directly rather than
//! consulting consent first, because *creating a local-only candidate*
//! carries none of the privacy stakes that submitting one would — the
//! user still previews/deletes it later via `yadorilink report error`.

use yadorilink_reporting::builder::ErrorPayloadBuilder;

use super::ReportingStorage;

/// Persists a severe-error candidate for later user review (`yadorilink
/// report error --last`). Infallible from the caller's perspective — logs
/// and swallows any storage failure (task 2.6) rather than returning a
/// `Result` a severe-error call site would have to handle on top of the
/// error it's already handling.
///
/// `category`/`subsystem` are coarse labels (e.g. `"daemon_startup"` /
/// `"sync-state"`, `"essential_task_died"` / `"control-socket"`) — never
/// raw error text, which is what `log_lines` is for (already passed
/// through the D5 redaction pass inside `ErrorPayloadBuilder::build()`).
pub fn record_severe_error(
    storage: &ReportingStorage,
    category: &str,
    subsystem: &str,
    log_lines: Vec<String>,
) -> Option<String> {
    let consent = storage.consent_or_default();
    let env = super::environment::current(&consent);
    let builder = ErrorPayloadBuilder::new(category, subsystem).log_lines(log_lines);
    let (envelope, summary) = yadorilink_reporting::builder::build_error_envelope(env, builder);
    storage.record_error_candidate_with_summary_best_effort(envelope, &summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_severe_error_persists_a_candidate_and_redacts_log_lines() {
        let dir = tempfile::tempdir().unwrap();
        let storage = ReportingStorage::open(dir.path());
        let id = record_severe_error(
            &storage,
            "daemon_startup",
            "sync-state",
            vec!["failed to open /Users/alice/sync-state.sqlite3".to_string()],
        );
        assert!(id.is_some());
        let candidates = storage.error_candidates().list().unwrap();
        assert_eq!(candidates.len(), 1);
        let envelope = storage.error_candidates().show(&candidates[0].report_id).unwrap().unwrap();
        let json = envelope.to_json();
        assert!(!json.contains("alice"));
    }
}
