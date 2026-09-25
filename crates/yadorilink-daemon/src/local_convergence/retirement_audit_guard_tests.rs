#![cfg(test)]

use super::*;
use crate::replica_coordinator::ReplicaCoordinator;

/// The core Commit-4 regression: before `RetirementAuditGuard` existed,
/// `retire_conflict_copies_only` shared `MaterializationAuditGuard`'s
/// key, so a full audit already in flight for a group made every
/// retirement pass against it report `Busy` for the entire duration.
/// A held `MaterializationAuditGuard` must no longer block
/// `RetirementAuditGuard::try_acquire` for the SAME state+group.
#[test]
fn retirement_guard_is_independent_of_a_held_materialization_guard() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let _materialization_guard = MaterializationAuditGuard::try_acquire(&state, "group-a")
        .expect("materialization guard must be free at test start");
    let retirement_guard = RetirementAuditGuard::try_acquire(&state, "group-a");
    assert!(
        retirement_guard.is_some(),
        "a held MaterializationAuditGuard must not block RetirementAuditGuard"
    );
}

/// The reverse must also hold: a held `RetirementAuditGuard` must not
/// block `MaterializationAuditGuard::try_acquire` for the same
/// state+group -- the two key spaces are fully independent, not just
/// independent in one direction.
#[test]
fn materialization_guard_is_independent_of_a_held_retirement_guard() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let _retirement_guard = RetirementAuditGuard::try_acquire(&state, "group-a")
        .expect("retirement guard must be free at test start");
    let materialization_guard = MaterializationAuditGuard::try_acquire(&state, "group-a");
    assert!(
        materialization_guard.is_some(),
        "a held RetirementAuditGuard must not block MaterializationAuditGuard"
    );
}

/// `RetirementAuditGuard` must still single-flight against ITSELF per
/// group -- decoupling from `MaterializationAuditGuard` must not
/// accidentally drop retirement's own single-flight entirely.
#[test]
fn retirement_guard_still_excludes_a_second_retirement_pass_for_the_same_group() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let _first = RetirementAuditGuard::try_acquire(&state, "group-a")
        .expect("first retirement guard must be free at test start");
    assert!(
        RetirementAuditGuard::try_acquire(&state, "group-a").is_none(),
        "two retirement passes for the same group must still contend"
    );
}

/// A different group under the same state must never contend with
/// either guard -- the key is per-(state, group), not per-state alone.
#[test]
fn retirement_guard_does_not_contend_across_different_groups() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let _guard_a = RetirementAuditGuard::try_acquire(&state, "group-a")
        .expect("group-a's retirement guard must be free at test start");
    assert!(
        RetirementAuditGuard::try_acquire(&state, "group-b").is_some(),
        "a held retirement guard for group-a must not block group-b"
    );
}
