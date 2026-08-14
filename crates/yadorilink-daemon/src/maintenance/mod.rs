//! Named job types for this daemon's daemon-wide periodic maintenance
//! tasks (see `maintenance_coordinator.rs`'s own doc comment for the
//! full roster, and `docs/design/phase4-maintenance-inventory.md` for
//! how each job's shape was chosen). Each job is a small struct holding
//! the narrowest real dependency it needs, with its actual sweep/check
//! logic in a `run_once` method -- `maintenance_coordinator::start`
//! retains every job's own loop-shape/interval/supervision strategy
//! unchanged, now calling into `run_once` instead of inlining the sweep
//! body directly in the spawned closure.
//!
//! No shared generic "loop runner" here: these jobs have genuinely
//! different signatures -- some `async` (membership recovery, disk
//! reconcile), one sync-but-blocking-offloaded (retention expiry), some
//! that unify a real startup call with the periodic loop (update-check,
//! retention expiry, membership recovery) and some that must NOT gain
//! one (materialization repair, degraded-link recheck, disk-reconcile
//! backstop, GC idle -- see the inventory's own "no new startup runs"
//! constraint). Forcing all of that through one trait/runner would
//! either hide those real differences or need enough escape hatches to
//! stop being a meaningful abstraction. `LinkRuntimeController` (Phase
//! 3) stayed a plain struct with individual methods for the same
//! reason; this mirrors that pragmatic shape rather than Phase 4's own
//! plan-text assumption of a generic runner.

pub(crate) mod degraded_link_recheck;
pub(crate) mod disk_reconcile_backstop;
pub(crate) mod durability_confirmation;
pub(crate) mod gc_idle;
pub(crate) mod materialization_repair;
pub(crate) mod membership_recovery;
pub(crate) mod retention_expiry;
// The update-check scheduler never spawns under `madsim`/`test` builds
// (see `maintenance_coordinator.rs`'s own spawn site) -- `UpdateCheckJob`
// would otherwise sit unconstructed in every such build, warning as dead
// code.
#[cfg(not(any(madsim, test)))]
pub(crate) mod update_check;

/// Why a particular `run_once` call is happening -- purely informational
/// today (every job's sweep logic is identical regardless of the
/// reason), but keeps the "startup-immediate run and the periodic loop's
/// own run both go through the same `run_once`" unification visible at
/// each call site instead of implicit.
///
/// No `Wake`/`Manual` variant: nothing among this daemon's extracted
/// jobs is triggered by either today (every one of them is either a pure
/// interval loop or an interval loop with one immediate run at startup),
/// and adding unused variants speculatively would be exactly the kind of
/// abstraction-for-its-own-sake this reorganization is meant to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaintenanceTrigger {
    /// The job's own immediate run at daemon startup -- only
    /// `UpdateCheckJob`, `RetentionExpiryJob`, and `MembershipRecoveryJob`
    /// ever see this variant; the other 4 jobs are periodic-only, exactly
    /// as they were before this reorganization.
    Startup,
    /// An ordinary periodic loop tick.
    Interval,
}
