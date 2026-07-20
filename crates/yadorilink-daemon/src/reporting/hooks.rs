//! severe-error hooks. A "severe error" here means a daemon
//! failure serious enough that a maintainer would want to know about it
//! even without a user filing a GitHub issue — startup failures and an
//! essential supervised task dying are the two real call sites
//! wired up in `main.rs`; this module only owns the capture logic
//! itself, kept separate from `main.rs` so it's independently testable.
//!
//! These hooks only ever *create a local candidate* — they
//! never submit, queue for submission, or make a network call, regardless
//! of consent state. That's what makes them safe to call from a startup
//! path that runs before consent has even been loaded into `DaemonState`:
//! `record_severe_error` takes a `&ReportingStorage` directly rather than
//! consulting consent first, because *creating a local-only candidate*
//! carries none of the privacy stakes that submitting one would — the
//! user still previews/deletes it later via `yadorilink report error`.
//!
//! `record_panic` /
//! `install_panic_hook` extend the same machinery to *automatic* capture. An
//! unhandled panic previously left nothing; now a panic hook produces one
//! bounded, redacted, unsent candidate through this exact path. The hook is
//! deliberately minimal and defensive: it writes at most one bounded local
//! artifact, wraps that work in `catch_unwind` so a fault inside the hook can
//! never escalate to a double-panic/abort, and then calls the previously
//! installed hook so the default print-and-unwind behavior — and therefore
//! shutdown — is entirely unaffected. It shares the reporting storage's
//! isolation from sync (a separate directory, no sync-critical locks), so a
//! panic-time write can never corrupt or block sync state.

use yadorilink_reporting::builder::ErrorPayloadBuilder;

use super::ReportingStorage;

/// Persists a severe-error candidate for later user review (`yadorilink
/// report error --last`). Infallible from the caller's perspective — logs
/// And swallows any storage failure rather than returning a
/// `Result` a severe-error call site would have to handle on top of the
/// error it's already handling.
///
/// `category`/`subsystem` are coarse labels (e.g. `"daemon_startup"` /
/// `"sync-state"`, `"essential_task_died"` / `"control-socket"`) — never
/// raw error text, which is what `log_lines` is for (already passed
/// through the redaction pass inside `ErrorPayloadBuilder::build`).
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

/// Records ONE bounded,
/// redacted, unsent candidate for an unhandled panic. The `message`,
/// `location`, and `backtrace` are free text that may carry paths or other
/// sensitive strings, so they are threaded through `log_lines`/`.backtrace`,
/// both of which `ErrorPayloadBuilder::build` runs through the redaction
/// pass — nothing here bypasses redaction, and no network submission occurs
/// (it is a local candidate, unsent until the user consents). The
/// `"panic"` category is what the intake's triage maps to a `crash` severity.
///
/// Infallible from the caller's perspective (best-effort storage), which is
/// what lets it run safely from inside a panic hook.
pub fn record_panic(
    storage: &ReportingStorage,
    message: &str,
    location: Option<&str>,
    backtrace: &str,
) -> Option<String> {
    let consent = storage.consent_or_default();
    let env = super::environment::current(&consent);
    let mut log_lines = vec![format!("panic: {message}")];
    if let Some(loc) = location {
        log_lines.push(format!("location: {loc}"));
    }
    let builder =
        ErrorPayloadBuilder::new("panic", "daemon").log_lines(log_lines).backtrace(backtrace);
    let (envelope, summary) = yadorilink_reporting::builder::build_error_envelope(env, builder);
    storage.record_error_candidate_with_summary_best_effort(envelope, &summary)
}

/// Installs a process-wide panic hook that captures each unhandled panic as a
/// local candidate via [`record_panic`], then delegates to whatever hook was
/// previously installed so the default print-and-unwind behavior is preserved.
///
/// Safety properties:
/// - It writes AT MOST one bounded local artifact, then returns, so unwinding
///   (and shutdown) proceed exactly as they would without the hook.
/// - The capture is wrapped in `catch_unwind`, so a fault inside the hook can
///   never turn a panic into a double-panic/abort or lose the original panic.
/// - It touches only the reporting storage (isolated from sync), so it can
///   never corrupt sync state.
pub fn install_panic_hook(storage: std::sync::Arc<ReportingStorage>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // AssertUnwindSafe: on the panicking path we only ever *read* the
        // panic info and *append* a bounded artifact; there is no shared
        // invariant a caught unwind here could leave broken.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let payload = info.payload();
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            let location = info.location().map(|l| format!("{}:{}", l.file(), l.line()));
            let backtrace = std::backtrace::Backtrace::force_capture().to_string();
            record_panic(&storage, &message, location.as_deref(), &backtrace);
        }));
        // Preserve the default behavior: we only ADD a bounded local artifact,
        // never replace or block the normal panic path.
        previous(info);
    }));
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

    /// -3.4 "the hook in isolation": `record_panic` -- the exact
    /// function the installed panic hook calls -- must yield a single bounded,
    /// redacted, unsent candidate. The message, location, and backtrace all
    /// carry a home path; none of it may reach disk.
    #[test]
    fn record_panic_yields_a_bounded_redacted_unsent_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let storage = ReportingStorage::open(dir.path());

        let id = record_panic(
            &storage,
            "index corrupt reading /Users/alice/Sync/notes.md",
            Some("crates/yadorilink-daemon/src/foo.rs:42"),
            "0: frame at /Users/alice/secret\n1: more frames",
        );
        assert!(id.is_some());

        // Bounded: exactly one candidate under the error-candidate store's caps.
        let candidates = storage.error_candidates().list().unwrap();
        assert_eq!(candidates.len(), 1);
        // Unsent: nothing was queued for submission -- a candidate is not a
        // submission, and no network path is reachable from record_panic.
        assert!(storage.queue().list().unwrap().is_empty());

        let envelope = storage.error_candidates().show(&candidates[0].report_id).unwrap().unwrap();
        let json = envelope.to_json();
        // Redacted: the home path (and the user file name inside it) is gone,
        // and the redaction pass did run (a redaction marker is present).
        assert!(!json.contains("alice"));
        assert!(!json.contains("notes.md"));
        assert!(json.contains("[REDACTED"));
        // Categorized as a panic, which the intake triages as a crash.
        assert!(json.contains("\"panic\""));
    }

    /// end-to-end: the *installed* hook captures a real
    /// unhandled panic. Serialized against any other test touching the global
    /// panic hook, and the prior hook is restored afterwards so the rest of
    /// the suite is unaffected.
    #[test]
    fn installed_panic_hook_captures_a_real_panic() {
        use std::sync::{Arc, Mutex};
        static HOOK_LOCK: Mutex<()> = Mutex::new(());
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(ReportingStorage::open(dir.path()));

        // Save the pre-existing hook, install ours, trigger a contained panic,
        // then restore -- so this test never leaks a hook into the suite.
        let previous = std::panic::take_hook();
        install_panic_hook(Arc::clone(&storage));
        let result = std::panic::catch_unwind(|| {
            panic!("induced panic at /Users/alice/secret");
        });
        std::panic::set_hook(previous);
        assert!(result.is_err());

        // The panic produced a bounded, redacted candidate.
        let candidates = storage.error_candidates().list().unwrap();
        assert!(!candidates.is_empty());
        let envelope = storage.error_candidates().show(&candidates[0].report_id).unwrap().unwrap();
        assert!(!envelope.to_json().contains("alice"));
    }
}
