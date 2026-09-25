#![cfg(test)]

use super::*;

#[test]
fn failover_unlocks_one_additional_rank_per_stable_frontier_window() {
    assert_eq!(eligible_rank_for_elapsed(Duration::ZERO), 0);
    assert_eq!(eligible_rank_for_elapsed(Duration::from_millis(4_999)), 0);
    assert_eq!(eligible_rank_for_elapsed(Duration::from_secs(5)), 1);
    assert_eq!(eligible_rank_for_elapsed(Duration::from_millis(14_999)), 2);
    assert_eq!(eligible_rank_for_elapsed(Duration::from_secs(15)), 3);
}

#[test]
fn only_settled_settles_generation() {
    assert!(settles_generation(&RetirementAttempt::Settled { retired: 0 }));
    assert!(settles_generation(&RetirementAttempt::Settled { retired: 3 }));
    assert!(!settles_generation(&RetirementAttempt::Busy));
    assert!(!settles_generation(&RetirementAttempt::RetryRequired));
}

/// Guard-contention (`Busy`) failure injection: `RetirementWake::
/// complete` must not be called for the claimed generation, so the
/// group stays reported by `pending` for the next wake/backstop.
#[test]
fn busy_outcome_leaves_generation_pending() {
    let wake = crate::sync_runtime::retirement_wake::RetirementWake::new();
    wake.mark_dirty("g1");
    let claimed = *wake.pending().get("g1").unwrap();
    if settles_generation(&RetirementAttempt::Busy) {
        wake.complete("g1", claimed);
    }
    assert_eq!(wake.pending().get("g1"), Some(&1));
}

/// Transient-retry failure injection: a `RetryRequired` outcome (a
/// copy's tombstone materialize hit a transient block/disk condition)
/// must equally not complete the claimed generation.
#[test]
fn retry_required_outcome_leaves_generation_pending() {
    let wake = crate::sync_runtime::retirement_wake::RetirementWake::new();
    wake.mark_dirty("g1");
    let claimed = *wake.pending().get("g1").unwrap();
    if settles_generation(&RetirementAttempt::RetryRequired) {
        wake.complete("g1", claimed);
    }
    assert_eq!(wake.pending().get("g1"), Some(&1));
}

/// The core lost-wakeup regression test: an event landing WHILE a
/// pass is auditing generation 1 must not be swallowed by that pass's
/// own (successful) completion -- it must provoke exactly one
/// follow-up audit, which then settles cleanly with no event left
/// over.
#[test]
fn event_during_audit_provokes_exactly_one_follow_up_audit() {
    let wake = crate::sync_runtime::retirement_wake::RetirementWake::new();
    wake.mark_dirty("g1");
    let claimed_generation_1 = *wake.pending().get("g1").unwrap();
    assert_eq!(claimed_generation_1, 1);

    // A DAG admission (or job completion) lands while the pass that
    // claimed generation 1 is still auditing.
    wake.mark_dirty("g1");

    // That in-flight pass finishes and reports success for the
    // generation it actually claimed, not the new one.
    if settles_generation(&RetirementAttempt::Settled { retired: 1 }) {
        wake.complete("g1", claimed_generation_1);
    }

    // Exactly one follow-up audit's worth of pending work remains --
    // the mid-audit event was not lost.
    let pending = wake.pending();
    assert_eq!(pending.get("g1"), Some(&2));

    let claimed_generation_2 = *pending.get("g1").unwrap();
    if settles_generation(&RetirementAttempt::Settled { retired: 0 }) {
        wake.complete("g1", claimed_generation_2);
    }
    assert!(wake.pending().is_empty());
}
