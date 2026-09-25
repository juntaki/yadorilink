#![cfg(test)]

use super::{resolve_duplicate_recovery_gate, DuplicateRecoveryOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeError;

impl std::fmt::Display for FakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fake error")
    }
}

// Ordinary startup: nothing pending. The expensive corroboration pass
// must never run -- proven directly (not via timing) by panicking if
// the closure is ever invoked, and `recheck_pending` must likewise
// never be consulted since there was nothing to recheck.
#[test]
fn no_recovery_pending_skips_corroboration_and_completes_immediately() {
    let outcome = resolve_duplicate_recovery_gate::<FakeError>(
        "group",
        Ok(false),
        || panic!("corroborate_and_resolve must not run when nothing is pending"),
        || panic!("recheck_pending must not run when nothing was pending to begin with"),
    );
    assert_eq!(outcome, DuplicateRecoveryOutcome::Complete);
}

// Armed recovery, fully resolved this pass: corroboration runs exactly
// once and, since the durable pending set is now empty, the gate
// reports Complete so suppression may clear.
#[test]
fn pending_recovery_runs_corroboration_once_and_completes_when_pending_clears() {
    let mut corroborate_calls = 0;
    let outcome = resolve_duplicate_recovery_gate(
        "group",
        Ok::<bool, FakeError>(true),
        || corroborate_calls += 1,
        || Ok(false),
    );
    assert_eq!(corroborate_calls, 1);
    assert_eq!(outcome, DuplicateRecoveryOutcome::Complete);
}

// Armed recovery, still unresolved after this pass (some paths were
// not corroborated): suppression must stay armed.
#[test]
fn pending_recovery_stays_pending_when_recheck_still_reports_pending() {
    let mut corroborate_calls = 0;
    let outcome = resolve_duplicate_recovery_gate(
        "group",
        Ok::<bool, FakeError>(true),
        || corroborate_calls += 1,
        || Ok(true),
    );
    assert_eq!(corroborate_calls, 1);
    assert_eq!(outcome, DuplicateRecoveryOutcome::StillPending);
}

// Corroboration ran, but the post-corroboration recheck itself could
// not be read: fail closed exactly like the initial-read failure does,
// not optimistically treated as resolved.
#[test]
fn unreadable_recheck_after_corroboration_fails_closed() {
    let mut corroborate_calls = 0;
    let outcome = resolve_duplicate_recovery_gate(
        "group",
        Ok::<bool, FakeError>(true),
        || corroborate_calls += 1,
        || Err(FakeError),
    );
    assert_eq!(corroborate_calls, 1, "corroboration must still run once pending was true");
    assert_eq!(outcome, DuplicateRecoveryOutcome::UnknownFailClosed);
}

// The durable pending state itself could not be read: fail closed.
// Corroboration must not run against an unknown state, and
// suppression must stay armed rather than being cleared optimistically.
#[test]
fn unreadable_pending_state_fails_closed_without_running_corroboration() {
    let outcome = resolve_duplicate_recovery_gate(
        "group",
        Err(FakeError),
        || panic!("corroborate_and_resolve must not run when pending state is unknown"),
        || -> Result<bool, FakeError> {
            panic!("recheck_pending must not run when the initial read already failed")
        },
    );
    assert_eq!(outcome, DuplicateRecoveryOutcome::UnknownFailClosed);
}
