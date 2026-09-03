//! PERMANENT diagnostic counters (reclassified 2026-09-01 -- kept rather
//! than removed once their original investigation closed, since a second,
//! unrelated investigation on this same file needed them again days
//! later; see below): instruments `convergence::engine::process_group_via_
//! obligations`.
//!
//! Originally built for the two-arm `startup_scan_block_serving_race`
//! investigation, which showed `wait_ready_first` admitting ~13,795 new
//! historical changes at roughly 15/s while only 339/15,050 target files
//! ever materialized on B. These counters tested the hypothesis that the
//! gap was `process_group_via_obligations`'s own group-wide heads-stability
//! fence (`before == after` on `dag_group_heads`) discarding an ENTIRE
//! `reconcile_paths_directly` attempt's settlements whenever an *unrelated*
//! path's admission moved the group's heads during that same call --
//! confirmed by `unrelated_path_head_movement_must_not_discard_an_already_
//! settled_attempt` (RED against the old gated code, GREEN now that the
//! fence is removed) and `same_path_admission_while_parked_is_
//! independently_rejected_by_generation_cas` (already GREEN, proving the
//! per-path completion CAS decides currency on its own). The fence has
//! since been removed: `reconcile_attempts_heads_changed_mid_attempt`/
//! `paths_settled_with_heads_changed_mid_attempt` are now purely
//! informational (how often an attempt's window saw unrelated head
//! movement), not a count of discarded work.
//!
//! Reused for the decision-9 dual-scheduler cutover: `zero_work_attempted`
//! (added then) backs `zero_work_precheck_examines_at_most_the_path_
//! budget_window_per_tick`, a permanent regression test for the 128-claim/
//! 8-path zero-work-precheck amplification fix. That a second, unrelated
//! investigation reached for this same module rather than re-deriving its
//! own version is the reason this whole module is now classified
//! permanent, not just the one counter it added.
//!
//! Mirrors `yadorilink-peer-session::c4_diag`'s own shape (global atomics,
//! `reset`/`stats`, no per-call-site attribution -- these are fixed call
//! sites in one function).

use std::sync::atomic::{AtomicU64, Ordering};

static OBLIGATIONS_CLAIMED: AtomicU64 = AtomicU64::new(0);
static ZERO_WORK_ATTEMPTED: AtomicU64 = AtomicU64::new(0);
static ZERO_WORK_CLOSED: AtomicU64 = AtomicU64::new(0);

static RECONCILE_ATTEMPTS_STARTED: AtomicU64 = AtomicU64::new(0);
static RECONCILE_ATTEMPTS_WITH_RESULT: AtomicU64 = AtomicU64::new(0);
static RECONCILE_ATTEMPTS_HEADS_STABLE: AtomicU64 = AtomicU64::new(0);
static RECONCILE_ATTEMPTS_HEADS_CHANGED_MID_ATTEMPT: AtomicU64 = AtomicU64::new(0);

static PATHS_SETTLED_BY_RECONCILE: AtomicU64 = AtomicU64::new(0);
/// Informational only (the fence these used to measure the cost of no
/// longer exists): a path this call's own `attempt.settled_with_evidence()`
/// settled, in a `reconcile_paths_directly` call whose `before != after` --
/// i.e. some other, unrelated path's admission moved the group's heads
/// during this attempt's own window. Publishes/completes exactly like any
/// other settled path; nothing here is discarded.
static PATHS_SETTLED_WITH_HEADS_CHANGED_MID_ATTEMPT: AtomicU64 = AtomicU64::new(0);

static COMPLETION_ATTEMPTED: AtomicU64 = AtomicU64::new(0);
static COMPLETION_CLOSED: AtomicU64 = AtomicU64::new(0);
static COMPLETION_CAS_LOST: AtomicU64 = AtomicU64::new(0);

/// Real, growing backoff (`dag_mark_obligation_attempt_failed`) applied to a
/// path a tried candidate examined but did not settle (`RetryRequired`).
static OBLIGATIONS_FAILED: AtomicU64 = AtomicU64::new(0);
/// Real, growing backoff applied because no candidate session shared this
/// group at all this tick (a stable, not transient, condition).
static OBLIGATIONS_BACKED_OFF: AtomicU64 = AtomicU64::new(0);
/// Short, unpenalized reschedule (`dag_defer_obligation_without_penalty`)
/// applied when every tried candidate was skipped (guard contention) or
/// raced a concurrent admission -- nothing was actually learned this tick.
static OBLIGATIONS_DEFERRED: AtomicU64 = AtomicU64::new(0);

pub fn reset() {
    OBLIGATIONS_CLAIMED.store(0, Ordering::Relaxed);
    ZERO_WORK_ATTEMPTED.store(0, Ordering::Relaxed);
    ZERO_WORK_CLOSED.store(0, Ordering::Relaxed);
    RECONCILE_ATTEMPTS_STARTED.store(0, Ordering::Relaxed);
    RECONCILE_ATTEMPTS_WITH_RESULT.store(0, Ordering::Relaxed);
    RECONCILE_ATTEMPTS_HEADS_STABLE.store(0, Ordering::Relaxed);
    RECONCILE_ATTEMPTS_HEADS_CHANGED_MID_ATTEMPT.store(0, Ordering::Relaxed);
    PATHS_SETTLED_BY_RECONCILE.store(0, Ordering::Relaxed);
    PATHS_SETTLED_WITH_HEADS_CHANGED_MID_ATTEMPT.store(0, Ordering::Relaxed);
    COMPLETION_ATTEMPTED.store(0, Ordering::Relaxed);
    COMPLETION_CLOSED.store(0, Ordering::Relaxed);
    COMPLETION_CAS_LOST.store(0, Ordering::Relaxed);
    OBLIGATIONS_FAILED.store(0, Ordering::Relaxed);
    OBLIGATIONS_BACKED_OFF.store(0, Ordering::Relaxed);
    OBLIGATIONS_DEFERRED.store(0, Ordering::Relaxed);
}

pub fn record_obligations_claimed(n: usize) {
    OBLIGATIONS_CLAIMED.fetch_add(n as u64, Ordering::Relaxed);
}

/// How many claimed paths this tick's zero-work pre-check loop actually
/// examined (a real per-path DAG-ancestry walk each) -- bounded to at most
/// `MAX_PATHS_PER_RECONCILE_ATTEMPT`, since walking every claimed path (up
/// to 128) is wasted amplification when at most
/// `MAX_PATHS_PER_RECONCILE_ATTEMPT` could ever reach a real reconcile
/// attempt in the same tick.
pub fn record_zero_work_attempted(n: usize) {
    if n > 0 {
        ZERO_WORK_ATTEMPTED.fetch_add(n as u64, Ordering::Relaxed);
    }
}

pub fn record_zero_work_closed(n: usize) {
    if n > 0 {
        ZERO_WORK_CLOSED.fetch_add(n as u64, Ordering::Relaxed);
    }
}

pub fn record_reconcile_attempt_started() {
    RECONCILE_ATTEMPTS_STARTED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_reconcile_attempt_with_result() {
    RECONCILE_ATTEMPTS_WITH_RESULT.fetch_add(1, Ordering::Relaxed);
}

/// `settled` is `attempt.settled_with_evidence()`'s count for this attempt,
/// for a call whose `heads_before == heads_after`.
pub fn record_reconcile_attempt_heads_stable(settled: usize) {
    RECONCILE_ATTEMPTS_HEADS_STABLE.fetch_add(1, Ordering::Relaxed);
    if settled > 0 {
        PATHS_SETTLED_BY_RECONCILE.fetch_add(settled as u64, Ordering::Relaxed);
    }
}

/// `settled` is `attempt.settled_with_evidence()`'s count for this attempt,
/// for a call whose `heads_before != heads_after` -- these settle exactly
/// like the heads-stable case above; this only records how often an
/// attempt's own window saw unrelated head movement.
pub fn record_reconcile_attempt_heads_changed(settled: usize) {
    RECONCILE_ATTEMPTS_HEADS_CHANGED_MID_ATTEMPT.fetch_add(1, Ordering::Relaxed);
    if settled > 0 {
        PATHS_SETTLED_WITH_HEADS_CHANGED_MID_ATTEMPT.fetch_add(settled as u64, Ordering::Relaxed);
    }
}

pub fn record_completion_attempted() {
    COMPLETION_ATTEMPTED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_completion_closed() {
    COMPLETION_CLOSED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_completion_cas_lost() {
    COMPLETION_CAS_LOST.fetch_add(1, Ordering::Relaxed);
}

pub fn record_obligations_failed(n: usize) {
    if n > 0 {
        OBLIGATIONS_FAILED.fetch_add(n as u64, Ordering::Relaxed);
    }
}

pub fn record_obligations_backed_off(n: usize) {
    if n > 0 {
        OBLIGATIONS_BACKED_OFF.fetch_add(n as u64, Ordering::Relaxed);
    }
}

pub fn record_obligations_deferred(n: usize) {
    if n > 0 {
        OBLIGATIONS_DEFERRED.fetch_add(n as u64, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ObligationEngineStats {
    pub obligations_claimed: u64,
    pub zero_work_attempted: u64,
    pub zero_work_closed: u64,
    pub reconcile_attempts_started: u64,
    pub reconcile_attempts_with_result: u64,
    pub reconcile_attempts_heads_stable: u64,
    pub reconcile_attempts_heads_changed_mid_attempt: u64,
    pub paths_settled_by_reconcile: u64,
    pub paths_settled_with_heads_changed_mid_attempt: u64,
    pub completion_attempted: u64,
    pub completion_closed: u64,
    pub completion_cas_lost: u64,
    pub obligations_failed: u64,
    pub obligations_backed_off: u64,
    pub obligations_deferred: u64,
}

pub fn stats() -> ObligationEngineStats {
    ObligationEngineStats {
        obligations_claimed: OBLIGATIONS_CLAIMED.load(Ordering::Relaxed),
        zero_work_attempted: ZERO_WORK_ATTEMPTED.load(Ordering::Relaxed),
        zero_work_closed: ZERO_WORK_CLOSED.load(Ordering::Relaxed),
        reconcile_attempts_started: RECONCILE_ATTEMPTS_STARTED.load(Ordering::Relaxed),
        reconcile_attempts_with_result: RECONCILE_ATTEMPTS_WITH_RESULT.load(Ordering::Relaxed),
        reconcile_attempts_heads_stable: RECONCILE_ATTEMPTS_HEADS_STABLE.load(Ordering::Relaxed),
        reconcile_attempts_heads_changed_mid_attempt: RECONCILE_ATTEMPTS_HEADS_CHANGED_MID_ATTEMPT
            .load(Ordering::Relaxed),
        paths_settled_by_reconcile: PATHS_SETTLED_BY_RECONCILE.load(Ordering::Relaxed),
        paths_settled_with_heads_changed_mid_attempt: PATHS_SETTLED_WITH_HEADS_CHANGED_MID_ATTEMPT
            .load(Ordering::Relaxed),
        completion_attempted: COMPLETION_ATTEMPTED.load(Ordering::Relaxed),
        completion_closed: COMPLETION_CLOSED.load(Ordering::Relaxed),
        completion_cas_lost: COMPLETION_CAS_LOST.load(Ordering::Relaxed),
        obligations_failed: OBLIGATIONS_FAILED.load(Ordering::Relaxed),
        obligations_backed_off: OBLIGATIONS_BACKED_OFF.load(Ordering::Relaxed),
        obligations_deferred: OBLIGATIONS_DEFERRED.load(Ordering::Relaxed),
    }
}
