//! The plan/prepare/revalidate/replan loop of design `preimage-capture.md`
//! §6: "a transaction repeatedly plans from the latest verified DAG frontier
//! until the physical tree matches a still-current plan".
//!
//! # Why this module exists
//!
//! Every piece of that sentence already existed and none of it ran.
//! `resolution_planning` built plans, sliced them, filtered out committed
//! work, detected staleness and fenced superseded work; `orchestrator` drove
//! one slice from allocation to release. But `plan_is_stale` had no caller
//! outside its own tests, `replan` was reachable only from a test, and
//! nothing in the crate produced a real `desired_frontier_hash` at all — the
//! plan's captured hash and the "current" hash it was compared against were
//! both invented, per test, to differ. The staleness guarantee was one the
//! planning module *offered*, not one anything *exercised*. This module is
//! the caller that closes it, and it composes those primitives rather than
//! restating any of their rules.
//!
//! # Why the loop is necessary, not a retry convenience
//!
//! §6.1 requires preparation — block fetch, staging, verification, fsync —
//! to hold no canonical-path reservation, because it "may take seconds or
//! minutes". A plan built before that window can therefore be superseded
//! before its commit: a peer's change is admitted, the resolver's answer for
//! one of the plan's paths changes, and the bytes about to be committed are
//! no longer the ones the DAG says belong there. Committing anyway is not a
//! stale-read nuisance, it is the write of a superseded winner over a newer
//! one.
//!
//! So revalidation is per slice, not once per plan: a plan with four slices
//! whose second slice takes a minute must re-check before slices three and
//! four, or the check answers a question about a moment that has passed.
//!
//! ## Where each of the two checks sits, and why there are two
//!
//! [`PlanEnvironment::run_slice`] is one call covering BOTH §6.1
//! preparation and the §6.2 commit window, because
//! [`orchestrator::run_slice`] is — it stages every placement, then acquires
//! the slice's reservations, then commits. This loop's own check therefore
//! sits before preparation begins, and on its own it could never see a
//! frontier that moved *during* that preparation — the very window §6.1
//! says may last minutes.
//!
//! The execution-generation fence does not cover that window either, and the
//! reason is narrower than `yadorilink_sync_sqlite::resolution_planning::plan_is_stale`'s doc used
//! to claim. `dag_store::bump_execution_fence_for_change` IS wired at
//! admission (remote admission, orphan promotion, local emission), and it
//! calls `filesystem_transaction::bump_transactions_for_touched_paths` —
//! but that lookup matches only transactions **holding a reservation** on a
//! touched path, and §6.1 deliberately holds none across preparation. So the
//! window between this loop's check and the slice's `acquire_reservations`
//! was covered by neither signal, while everything after acquisition was
//! covered by the fence.
//!
//! That is now closed where it has to be closed: inside
//! [`orchestrator::run_slice`]'s commit boundary, which acquires the
//! reservations, takes the path locks, revalidates and transitions every
//! epoch as one transaction. This loop supplies the capability
//! ([`orchestrator::SliceFrontierSource`]) and the plan and scope it must be
//! judged against; the orchestrator does the judging, at the one moment when
//! the check and the fence meet with no gap between them.
//!
//! The pre-slice check here is kept, and is not redundant with it: it is
//! cheap, it runs before any preparation is spent, and it catches staleness
//! accrued ACROSS slices. The boundary's check is authoritative and catches
//! staleness accrued WITHIN one slice's preparation, which nothing here can
//! see.
//!
//! ## Why the revalidator is not part of the environment
//!
//! [`drive_plan`] takes `env: &mut dyn PlanEnvironment` and `revalidator:
//! &dyn SliceFrontierSource` as two separate parameters. The obvious
//! alternative — one trait with a `current_frontier` method, passed into
//! `run_slice` — does not compile and cannot be made to: `env.run_slice(..)`
//! takes `&mut env` for the length of the call, and the revalidation the
//! orchestrator performs *inside* that call would need `&env` at the same
//! time. Two mutable borrows of one object, or a mutable and a shared one;
//! either way the borrow checker refuses, and no amount of restructuring
//! inside this module changes that, because the aliasing is inherent to
//! "the callee calls back into its own caller's state".
//!
//! Splitting the two into independently owned objects removes the aliasing
//! entirely rather than working around it. The cost is real and worth
//! naming: a caller now constructs and owns two things instead of one, and
//! `SliceFrontierSource::current_frontier` takes `&self`, so an
//! implementation that wants to cache its DAG reads needs interior
//! mutability where a `&mut self` method would not have. That is the price
//! of the check being able to run at the only place it is worth running.
//!
//! # Two scopes that must be the same scope
//!
//! [`yadorilink_sync_sqlite::resolution_planning::plan_is_stale`] compares a plan's captured
//! frontier hash against "the caller's freshly recomputed hash for exactly
//! this plan's own path scope". Nothing forces those two scopes to agree,
//! and if they do not the comparison is not weaker — it is meaningless in a
//! way that reads as a working check: a recomputation over a subset can
//! never differ for a path outside it (silently never stale), and one over
//! a superset differs the moment any unrelated path moves (permanently
//! stale, replanning without end).
//!
//! This module therefore never accepts a frontier *hash* from its
//! environment. [`PlanEnvironment::build_plan`] returns the frontier it
//! resolved from, [`orchestrator::SliceFrontierSource::current_frontier`] is
//! asked for exactly that path scope and must return exactly it, and the
//! hashing on both sides is done here (and, at the commit boundary, in
//! `orchestrator`) by the single definition in
//! [`yadorilink_replica_engine::resolution_planning::desired_frontier_hash`].
//! A scope disagreement is
//! [`PlanDriverError::FrontierScopeChanged`], not a silent pass.
//!
//! # What this module deliberately does not do
//!
//! It does not open, commit or complete the transaction, and it does not
//! move the saga phase. [`resolution_planning::replan`] moves a stale
//! transaction back to `Planning` itself; every other phase transition
//! belongs to whoever owns the transaction's lifecycle, which is not this
//! loop.
//!
//! It does not build [`orchestrator::PlacementIo`]. That needs open
//! directory handles and live filesystem probes, which is precisely the
//! caller-side knowledge this module has none of — hence
//! [`PlanEnvironment::run_slice`] rather than a `run_slice` call here.
//!
//! It performs no I/O, holds no lock, and reads the DAG only through the
//! environment. Preparation runs inside `run_slice`, outside any path lock,
//! which is what makes the staleness this loop exists to catch possible in
//! the first place.

use rusqlite::Connection;

use crate::sync_error::SyncError;
use yadorilink_sync_sqlite::filesystem_transaction;
use yadorilink_sync_sqlite::commit_window::CommitWindowError;
use super::orchestrator::{
    OrchestratorError, PlacementOutcome, SliceFrontierSource, SliceRevalidation,
};
use yadorilink_sync_sqlite::resolution_planning::{self, FilesystemResolutionPlan};
use yadorilink_replica_engine::resolution_planning::{
    desired_frontier_hash, slice_plan, PathFrontier, PlacementGroup, PlanSlice, SliceBounds,
};

/// What [`PlanEnvironment::build_plan`] returns: the placements a plan
/// wants, together with the frontier they were resolved from.
///
/// The two travel together deliberately. A caller that returned only the
/// groups would leave this module to source the frontier separately, which
/// is the scope split the module doc calls meaningless — the frontier a plan
/// captures must be the one that produced that plan's own placements, read
/// in the same pass.
pub struct PlanBuild {
    pub groups: Vec<PlacementGroup>,
    /// One entry per path the build resolved. May legitimately be larger
    /// than the set of paths that produced placements: a path resolving to
    /// "already correct" plans nothing but is still part of the desired
    /// state this plan is valid against, and a change to it still makes the
    /// plan stale.
    pub frontier: Vec<PathFrontier>,
}

/// Everything the loop cannot do itself: read the DAG, measure staged
/// bytes, and execute a slice against a real filesystem.
pub trait PlanEnvironment {
    /// Resolves the transaction's path scope from the receiver's own latest
    /// verified frontier and returns the placements it implies.
    ///
    /// Called once per plan attempt, including after every replan — a plan
    /// rebuilt after a replan must re-read the DAG, since the whole reason
    /// it is being rebuilt is that the previous read is no longer current.
    /// `plan_revision` and `execution_generation` are the transaction's
    /// current values, passed so an implementation can record them; this
    /// module captures them into the plan regardless.
    fn build_plan(
        &mut self,
        conn: &Connection,
        plan_revision: i64,
        execution_generation: i64,
    ) -> Result<PlanBuild, SyncError>;

    /// The staged-byte cost of one group, for
    /// `yadorilink_replica_engine::resolution_planning::slice_plan`'s bound. `&self`, matching
    /// `slice_plan`'s own `Fn` bound: slicing calls this while walking the
    /// group list, so it must be a pure query, not a step that advances
    /// anything.
    fn group_bytes(&self, group: &PlacementGroup) -> u64;

    /// Prepares and commits one slice — in practice
    /// [`orchestrator::run_slice`], with the [`orchestrator::PlacementIo`]
    /// only the caller can build.
    ///
    /// This is still ONE call covering both §6.1 preparation and the §6.2
    /// commit window, but that is no longer the gap it was: `revalidation`
    /// is threaded straight into [`orchestrator::RunSliceRequest`], and the
    /// orchestrator runs §6.2 step 3 with it at its own commit boundary —
    /// after the slice's reservations exist, before the first epoch leaves
    /// `PreparedArtifact`. An implementation that drops it on the floor
    /// cannot compile: [`orchestrator::RunSliceRequest::revalidation`] is
    /// not optional.
    ///
    /// `expected_execution_generation` is the fence value the plan captured;
    /// passing anything else defeats the fence that makes a replan able to
    /// stop an epoch already in flight under the superseded plan.
    fn run_slice(
        &mut self,
        conn: &mut Connection,
        slice: &PlanSlice,
        expected_execution_generation: i64,
        next_epoch: i64,
        revalidation: SliceRevalidation<'_>,
    ) -> Result<Vec<PlacementOutcome>, OrchestratorError>;
}

/// How the loop is bounded. Neither bound is a correctness property — the
/// fence is what makes a superseded plan unable to commit — they only stop
/// an unbounded loop when desired state keeps moving faster than this
/// transaction can execute it.
#[derive(Debug, Clone, Copy)]
pub struct DriveBounds {
    pub slice_bounds: SliceBounds,
    /// How many attempts that had real work to do this transaction may
    /// spend before [`PlanDriverError::PlanNeverSettled`]. An "attempt" is
    /// a plan that found `resolution_planning::plan_progress` non-empty
    /// and either ran its slices or found the parent `Blocked` — the
    /// mandatory final rebuild that *proves* nothing is left (an empty
    /// `plan_progress`) does not itself consume one, since it does no work
    /// and cannot go stale. `1` therefore means exactly what it says: a
    /// transaction that needs no replan can settle in a single attempt,
    /// including under this bound — a drive that instead needed every
    /// build to count against the bound could never report success for any
    /// non-empty plan even when nothing ever went stale, since settling
    /// unavoidably takes one attempt that does the work plus one rebuild
    /// that proves there is nothing left. The work done so far stays
    /// committed and authored when the bound is reached — nothing is
    /// rolled back, and the next call simply resumes, since
    /// `plan_progress` filters out everything that already landed.
    pub max_plan_attempts: u32,
    /// How many consecutive iterations may be spent losing the
    /// frontier-hash publication CAS before the drive gives up with
    /// [`PlanDriverError::PlanNeverSettled`].
    ///
    /// Separate from [`DriveBounds::max_plan_attempts`] because a lost CAS
    /// is not an attempt at the work: the iteration built a plan, found
    /// someone else had already replanned underneath it, published nothing,
    /// and started over. Charging it to the work budget would make a drive
    /// that merely raced report failure while it still had real attempts
    /// left; leaving it uncharged — the earlier shape — meant a concurrent
    /// replanner moving the revision at a steady rate could hold the drive
    /// loop in build/lose/rebuild with no bound at all, contradicting the
    /// loop's own contract that it always terminates.
    ///
    /// Defaulted well above `max_plan_attempts`: losing this CAS is a
    /// genuine race that a healthy system can hit several times in a row,
    /// so this bound exists to stop an unbounded spin, not to be reached in
    /// normal operation.
    pub max_publication_races: u32,
}

impl Default for DriveBounds {
    fn default() -> Self {
        DriveBounds {
            slice_bounds: SliceBounds::default(),
            max_plan_attempts: 8,
            max_publication_races: 64,
        }
    }
}

#[derive(Debug)]
pub struct DriveOutcome {
    /// Attempts spent that had real work to do, including the one that
    /// finally settled — so `1` means nothing ever went stale. The
    /// mandatory final rebuild that proves nothing is left is not counted
    /// (see [`DriveBounds::max_plan_attempts`]), so this can also be `0`:
    /// a call whose very first build already finds nothing to do.
    pub plan_attempts: u32,
    pub replans: u32,
    pub placements: Vec<PlacementOutcome>,
}

#[derive(Debug)]
pub enum PlanDriverError {
    Sync(SyncError),
    /// [`PlanEnvironment::run_slice`] failed for a reason this loop does not
    /// treat as staleness — an ordinary fault, not a fenced or superseded
    /// plan. `placements` carries every placement, from this slice and
    /// every prior one in this call, that had already committed and been
    /// driven through custody and authoring before the failure —
    /// `DriveOutcome::placements` is otherwise the only channel a caller has
    /// for that, and it is populated only on `Ok` (21.9 / D2).
    Orchestrator {
        error: Box<OrchestratorError>,
        placements: Vec<PlacementOutcome>,
    },
    /// [`PlanEnvironment::current_frontier`] answered about a different set
    /// of paths than the plan's own scope, so its hash and the plan's hash
    /// are not comparable. Refused rather than compared — see the module
    /// doc's "two scopes" section for why a mismatch here is not a weaker
    /// check but a broken one.
    FrontierScopeChanged {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    /// `max_plan_attempts` real attempts were spent — each one either ran
    /// its slices and went stale (a moved frontier, a fenced generation, or
    /// a superseded commit boundary) or found the parent transaction
    /// `Blocked` — without this transaction ever settling. `replans` is how
    /// many of those attempts actually issued a replan; it is reported
    /// separately from `attempts` because the two are not always equal —
    /// an attempt can also be spent on legitimate new work that
    /// [`PlanEnvironment::build_plan`] discovers in a wider scope without
    /// anything having gone stale, and that attempt consumes the bound
    /// without a replan to show for it. A caller comparing the two can tell
    /// "this transaction is genuinely churning" (`replans` close to
    /// `attempts`) from "this transaction is simply bigger than the bound
    /// allows in one call" (`replans` well under `attempts`) — `attempts`
    /// alone cannot distinguish them.
    PlanNeverSettled {
        attempts: u32,
        replans: u32,
        placements: Vec<PlacementOutcome>,
    },
}

impl From<SyncError> for PlanDriverError {
    fn from(e: SyncError) -> Self {
        PlanDriverError::Sync(e)
    }
}

/// See `OrchestratorError`'s identical impl for why this bridges through
/// `SyncError` instead of duplicating the `SyncSqliteError` conversion.
impl From<yadorilink_sync_sqlite::SyncSqliteError> for PlanDriverError {
    fn from(e: yadorilink_sync_sqlite::SyncSqliteError) -> Self {
        PlanDriverError::Sync(SyncError::from(e))
    }
}

/// See `OrchestratorError`'s identical impl for why this bridges through
/// `SyncError` instead of duplicating the `ReplicaEngineError` conversion
/// (needed after 7D-9D moved `resolution_planning::desired_frontier_hash`
/// to `yadorilink-replica-engine`, which returns `ReplicaEngineError`).
impl From<yadorilink_replica_engine::error::ReplicaEngineError> for PlanDriverError {
    fn from(e: yadorilink_replica_engine::error::ReplicaEngineError) -> Self {
        PlanDriverError::Sync(SyncError::from(e))
    }
}

impl From<OrchestratorError> for PlanDriverError {
    fn from(e: OrchestratorError) -> Self {
        PlanDriverError::Orchestrator { error: Box::new(e), placements: Vec::new() }
    }
}

/// Drives `transaction_id` until the tree matches a still-current plan.
/// Gated behind [`filesystem_transaction::EXECUTION_ENABLED`], like every
/// module this composes.
/// `revalidator` is a *separate* object from `env`, not a method on it, and
/// that is deliberate — see the module doc's "why the revalidator is not
/// part of the environment".
pub fn drive_plan(
    conn: &mut Connection,
    transaction_id: &str,
    env: &mut dyn PlanEnvironment,
    revalidator: &dyn SliceFrontierSource,
    bounds: &DriveBounds,
    now_unix_nanos: i64,
) -> Result<DriveOutcome, PlanDriverError> {
    filesystem_transaction::require_execution_enabled()?;
    drive_plan_unchecked(conn, transaction_id, env, revalidator, bounds, now_unix_nanos)
}

/// The ungated core of [`drive_plan`], following the same `_unchecked`
/// convention as every other module here: the primitives it calls are each
/// gated already, so it calls their `_unchecked` seams directly and stays
/// exercisable by its own tests while the gate is closed.
pub(crate) fn drive_plan_unchecked(
    conn: &mut Connection,
    transaction_id: &str,
    env: &mut dyn PlanEnvironment,
    revalidator: &dyn SliceFrontierSource,
    bounds: &DriveBounds,
    now_unix_nanos: i64,
) -> Result<DriveOutcome, PlanDriverError> {
    let mut placements: Vec<PlacementOutcome> = Vec::new();
    let mut plan_attempts: u32 = 0;
    let mut replans: u32 = 0;
    // Iterations spent losing the frontier-hash publication CAS to a
    // concurrent replanner. Counted separately from `plan_attempts` because
    // such an iteration is not an attempt in the sense that bound measures:
    // it built a plan and published nothing, so charging it would make a
    // drive that merely raced report `PlanNeverSettled` while it still had
    // real attempts left. But it cannot be free either -- the `continue`
    // below returns to the top of the loop without touching `plan_attempts`,
    // so another driver moving the revision at a steady rate could hold this
    // loop in build/lose/rebuild indefinitely, and "this loop always
    // terminates under `max_plan_attempts`" would be false. Bounding the
    // churn separately keeps the termination guarantee without charging a
    // race to the work budget.
    let mut publication_races: u32 = 0;

    loop {
        // Re-read rather than carry values across the loop: a replan moved
        // both of these, and the whole point of rebuilding is to plan
        // against what is true now.
        let record =
            filesystem_transaction::lookup_transaction(conn, transaction_id)?.ok_or_else(|| {
                SyncError::NotFound(format!("filesystem transaction {transaction_id}"))
            })?;

        // A `Blocked` parent means exactly what a stale frontier means: this
        // slice needs replanning, not another attempt under the plan that
        // got it here. Unlike the frontier/fence signals below, this one is
        // read directly off the transaction's own phase rather than
        // inferred from an error, because by the time this loop can observe
        // it, the failure that produced it is over: `orchestrator::
        // run_slice_unchecked`'s prepare-failure protocol (and the
        // commit-window's own non-retryable `NotStarted` branch) already
        // returned its error to a previous call, and `TransactionPhase::
        // may_receive_new_epochs` refuses `Blocked` a new epoch -- so on any
        // later call, `allocate_slice_epochs_unchecked` would fail with a
        // plain `SyncError::InvalidInput`, a shape `is_execution_generation_
        // fenced` does not and must not recognise (see that function's own
        // doc on why widening it is unsafe). Checking the phase directly
        // here, before a slice is even attempted, closes both the routes
        // that can produce it -- the prepare loop and the commit-window's
        // `NotStarted` branch both funnel through the same `TransactionPhase::
        // Blocked` -- without this loop needing to know which one happened.
        // `resolution_planning::replan_unchecked` is the only code that
        // moves a transaction out of `Blocked`; it also settles whatever
        // non-terminal epoch the failed attempt left behind (see its own
        // doc), so the parent-completion invariant is not left refusing
        // `Completed` forever once the redone work actually lands.
        //
        // This cannot spin: it is gated by the same `max_plan_attempts`
        // bound as every other branch of this loop that spends a real
        // attempt (see the bound check just below), so a transaction that
        // keeps re-blocking (a genuine, unrecoverable failure, not
        // staleness) still terminates at the bound with `PlanNeverSettled`
        // rather than looping forever -- it does not, and must not, retry
        // the same failing preparation indefinitely on its own. No fresh
        // frontier hash is known at this point (nothing has been read from
        // the DAG yet this iteration), so nothing is folded into this
        // replan's own transaction (D5) -- the next iteration's build below
        // publishes one once it has read the DAG.
        if record.phase == filesystem_transaction::TransactionPhase::Blocked {
            if plan_attempts >= bounds.max_plan_attempts {
                return Err(PlanDriverError::PlanNeverSettled {
                    attempts: plan_attempts,
                    replans,
                    placements,
                });
            }
            plan_attempts += 1;
            resolution_planning::replan_unchecked(conn, transaction_id, None, now_unix_nanos)?;
            replans += 1;
            continue;
        }

        let build = env.build_plan(conn, record.plan_revision, record.execution_generation)?;

        let mut scope: Vec<String> = build.frontier.iter().map(|f| f.path.clone()).collect();
        scope.sort();
        let frontier_hash = desired_frontier_hash(&build.frontier)?;
        let plan = FilesystemResolutionPlan {
            plan_revision: record.plan_revision,
            frontier_hash,
            execution_generation: record.execution_generation,
            groups: build.groups,
        };
        // §6.1 step 2. The row is the durable record of which frontier the
        // current plan belongs to; leaving it at the previous plan's value
        // would make it a second, disagreeing source of the same fact.
        //
        // `record.execution_generation` and `record.plan_revision` are the
        // values just read at the top of this iteration (above,
        // `lookup_transaction`) -- current as of that read, but
        // `env.build_plan` between there and here can take real time, during
        // which a concurrent replan (bumping both columns together, see
        // `resolution_planning::replan_unchecked`) can land. Binding them as
        // the fenced CAS's expectation, rather than writing unconditionally,
        // is exactly what makes that race a refusal instead of a silent
        // overwrite of the newer plan's hash with this stale one.
        if let Err(error) = filesystem_transaction::set_desired_frontier_hash_unchecked(
            conn,
            transaction_id,
            record.execution_generation,
            record.plan_revision,
            plan.frontier_hash,
        ) {
            if matches!(error, yadorilink_sync_sqlite::SyncSqliteError::TransitionRaced { .. }) {
                // Someone else already replanned between our read above and
                // this write, so the plan just built is already superseded
                // -- the same situation `is_execution_generation_fenced`
                // handles for a fence firing inside `run_slice`, just
                // reached earlier in the loop. Loop back and re-read rather
                // than treating this as a terminal failure -- but charge the
                // separate churn budget first, so losing this CAS forever
                // ends the drive instead of spinning it (see
                // `publication_races`' own declaration).
                publication_races += 1;
                if publication_races > bounds.max_publication_races {
                    return Err(PlanDriverError::PlanNeverSettled {
                        attempts: plan_attempts,
                        replans,
                        placements,
                    });
                }
                continue;
            }
            return Err(error.into());
        }

        // Everything this plan wants that is not already on disk under this
        // transaction. Empty means the tree matches a plan built from the
        // current frontier -- which is the loop's only success condition,
        // and the reason the loop always rebuilds once more after executing
        // every slice rather than returning straight from the slice loop.
        let remaining = resolution_planning::plan_progress(conn, transaction_id, &plan.groups)?;
        if remaining.is_empty() {
            return Ok(DriveOutcome { plan_attempts, replans, placements });
        }

        // D1 (24.10): the bound is checked and charged here, once a plan is
        // known to have real work left, not unconditionally at the top of
        // every iteration. The mandatory rebuild above that just proved
        // `remaining` non-empty already returned `Ok` for the case where it
        // proved the opposite -- so every iteration that reaches this line
        // is either about to run slices or about to discover them stale,
        // never a pure verification pass. Charging the bound at the top
        // instead (the earlier shape) meant a drive that needed `r`
        // replans consumed `r + 2` attempts -- the doomed attempts, the one
        // that finally executed everything, AND the proof-of-completion
        // rebuild that found nothing left -- so `max_plan_attempts: 1`
        // could never report success for any non-empty plan, even one that
        // never went stale at all.
        if plan_attempts >= bounds.max_plan_attempts {
            return Err(PlanDriverError::PlanNeverSettled {
                attempts: plan_attempts,
                replans,
                placements,
            });
        }
        plan_attempts += 1;

        let slices = slice_plan(
            plan.plan_revision,
            &remaining,
            &bounds.slice_bounds,
            |group| env.group_bytes(group),
        );

        let mut stale = false;
        for slice in &slices {
            // Per slice, before its preparation. This is no longer the
            // check §6.2 step 3 asks for -- that one now runs inside
            // `orchestrator::run_slice`'s commit boundary, with the slice's
            // reservations held -- it is an early-out that avoids spending
            // minutes preparing a slice already known to be superseded.
            // Keeping both is not redundancy: this one is cheap and catches
            // staleness accrued ACROSS slices before any work is done, the
            // boundary's one is authoritative and catches staleness accrued
            // WITHIN a slice's own preparation, which nothing here can see.
            let current = revalidator.current_frontier(conn, &scope)?;
            let mut actual: Vec<String> = current.iter().map(|f| f.path.clone()).collect();
            actual.sort();
            if actual != scope {
                return Err(PlanDriverError::FrontierScopeChanged { expected: scope, actual });
            }
            let current_hash = desired_frontier_hash(&current)?;
            if resolution_planning::plan_is_stale(conn, transaction_id, &plan, current_hash)? {
                // D5: `current_hash` is already the frontier this replan is
                // responding to, so it is folded straight into
                // `replan_unchecked`'s own transaction -- the durable row
                // never has a chance to show the bumped `plan_revision`
                // without a frontier hash to match it, which a later,
                // separate write (as this used to be) could not promise
                // across a crash between the two.
                resolution_planning::replan_unchecked(
                    conn,
                    transaction_id,
                    Some(current_hash),
                    now_unix_nanos,
                )?;
                replans += 1;
                stale = true;
                break;
            }

            // Allocation order, never reuse: the next number above every
            // epoch this transaction has ever allocated, including epochs
            // from superseded plans -- `allocate_slice_epochs`'s own
            // contract, and what `plan_progress`'s "latest epoch per path"
            // reading depends on.
            let next_epoch = next_epoch_for_transaction(conn, transaction_id)?;
            let revalidation =
                SliceRevalidation { source: revalidator, plan: &plan, scope: &scope };
            match env.run_slice(conn, slice, plan.execution_generation, next_epoch, revalidation) {
                Ok(outcomes) => placements.extend(outcomes),
                Err(error) => {
                    // D2 (21.9): unwrap any placements the failed slice
                    // already committed and drove through custody and
                    // authoring before deciding what the failure MEANS.
                    // Every arm below may replan and continue, or abort the
                    // whole drive -- but none of them may drop the record
                    // of what already landed, since `DriveOutcome::
                    // placements` (or, on abort,
                    // `PlanDriverError::Orchestrator::placements`) is the
                    // only channel a caller has for it.
                    let (error, partial_placements) = match error {
                        OrchestratorError::Partial { error, placements } => (*error, placements),
                        other => (other, Vec::new()),
                    };
                    placements.extend(partial_placements);

                    match error {
                        // The fence firing is this loop's own signal,
                        // arriving by a different route. Something bumped
                        // the generation between the staleness check above
                        // and this slice's transitions, so the epoch
                        // refused to advance under the plan's captured
                        // value -- which is the fence working, not a
                        // fault. Treating it as a terminal error would
                        // abort the one loop whose job is to replan and
                        // continue, and leave forward progress to whoever
                        // happens to call again. Replan and rebuild,
                        // exactly as a `plan_is_stale` yes does.
                        //
                        // Two claims an earlier version of this comment
                        // made, both wrong, corrected here rather than
                        // deleted because the second one is a live gap:
                        //
                        // "the refused slice is a proven no-op" -- it is
                        // not. `orchestrator::run_slice_unchecked` inserts
                        // every epoch row before the first fence-checked
                        // transition, and may have staged and fsynced
                        // artefacts, and may have acquired the slice's
                        // reservations. What is true is only that nothing
                        // already committed is re-executed: `plan_progress`
                        // filters it out of the rebuilt plan.
                        //
                        // "nothing is at risk" -- the reservation half of
                        // that was true when written and is now fixed
                        // (21.6): recovery decides release once per
                        // transaction after walking all of its epochs, so a
                        // fence firing while every epoch is still at
                        // `PreparedArtifact` no longer strands the slice's
                        // reservations. This comment is kept rather than
                        // deleted because its earlier wording outlived the
                        // defect it described and was read by a later
                        // reviewer as evidence the leak was still open --
                        // in a codebase where comments carry the
                        // specification, a stale one is a defect.
                        //
                        // What used to still be true -- that the
                        // `PlacementOutcome`s of any sibling that already
                        // committed were dropped by `run_slice_unchecked`
                        // on its error path -- is fixed above (D2): they
                        // are unwrapped from `OrchestratorError::Partial`
                        // before this match ever runs.
                        _ if is_execution_generation_fenced(&error) => {
                            resolution_planning::replan_unchecked(
                                conn,
                                transaction_id,
                                None,
                                now_unix_nanos,
                            )?;
                            replans += 1;
                            stale = true;
                            break;
                        }
                        // The commit boundary's own §6.2 step 3 refusing.
                        // Same meaning as the fence firing and as
                        // `plan_is_stale` answering yes above -- the plan
                        // is superseded -- reached by the one route that
                        // can see staleness accrued during a slice's own
                        // preparation. Nothing was committed and no
                        // reservation is left held (the boundary is one
                        // transaction), so replanning is the whole
                        // response.
                        OrchestratorError::PlanSuperseded { .. } => {
                            resolution_planning::replan_unchecked(
                                conn,
                                transaction_id,
                                None,
                                now_unix_nanos,
                            )?;
                            replans += 1;
                            stale = true;
                            break;
                        }
                        // Not staleness: the frontier source answered about
                        // a different scope than it was asked about, or
                        // answered something the DAG contradicts. Surfaced
                        // with the same error this module raises for its
                        // own pre-slice check, so a caller sees one shape
                        // for one defect regardless of which of the two
                        // checks caught it.
                        OrchestratorError::FrontierScopeChanged { expected, actual } => {
                            return Err(PlanDriverError::FrontierScopeChanged { expected, actual })
                        }
                        error => {
                            return Err(PlanDriverError::Orchestrator {
                                error: Box::new(error),
                                placements,
                            })
                        }
                    }
                }
            }
        }

        if !stale {
            // Every slice ran. Loop once more so the success condition is
            // "a freshly built plan has nothing left to do", proven against
            // the frontier as of now, rather than "we finished the list we
            // started with" -- which would be a claim about a frontier that
            // may have moved while the list was being executed.
            continue;
        }
    }
}

/// Whether `error` is the execution-generation fence refusing work under a
/// superseded plan.
///
/// Deliberately narrow. It matches only the fence's own
/// `ExecutionGenerationFenced` variant, reached either directly
/// ([`SyncError::ExecutionGenerationFenced`]) or through a commit window
/// that wrapped it (`yadorilink_sync_sqlite::SyncSqliteError::
/// ExecutionGenerationFenced`, 7D-9D ninth pass: `CommitWindowError::Sync`'s
/// payload moved from this crate's own `SyncError` to `SyncSqliteError` when
/// the commit window itself moved to `yadorilink-sync-sqlite`, so the two
/// arms below now match against two distinct types with the same variant
/// name rather than one shared type) — not
/// [`yadorilink_sync_sqlite::commit_window::CommitWindowError::NotStarted`],
/// not `RequiresRecovery`, and not any other `SyncError`/`SyncSqliteError`.
/// Widening it would convert real failures into silent replan-and-retry
/// loops, which is the shape that turns a broken transaction into an
/// infinite one.
///
/// Sees through [`OrchestratorError::Partial`] to the error it wraps — this
/// module's own call site always unwraps `Partial` before matching (D2), so
/// this arm is not reached by that call today, but it keeps the predicate
/// correct for the shape it is actually named after regardless of which
/// layer happens to have peeled the wrapper.
fn is_execution_generation_fenced(error: &OrchestratorError) -> bool {
    match error {
        OrchestratorError::Sync(e) => matches!(e, SyncError::ExecutionGenerationFenced { .. }),
        OrchestratorError::Commit { error: CommitWindowError::Sync(e), .. } => {
            matches!(e, yadorilink_sync_sqlite::SyncSqliteError::ExecutionGenerationFenced { .. })
        }
        OrchestratorError::Partial { error, .. } => is_execution_generation_fenced(error),
        _ => false,
    }
}

/// The transaction's true next-free epoch number: one above the highest it
/// has ever allocated, or `0` if it has none.
///
/// Derived from the epoch journal rather than counted by the caller.
/// `allocate_slice_epochs` documents that an epoch number is never reused,
/// and `plan_progress` reads "the latest epoch per path" as allocation
/// order — both are properties of this number, so it is computed in one
/// place from the record that defines it.
pub(crate) fn next_epoch_for_transaction(
    conn: &Connection,
    transaction_id: &str,
) -> Result<i64, SyncError> {
    let epochs = filesystem_transaction::list_epochs_for_transaction(conn, transaction_id)?;
    Ok(epochs.iter().map(|e| e.epoch + 1).max().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_replica_domain::filesystem_placement::{EpochState, PlacementRole};
    use yadorilink_replica_domain::ids::ChangeHash;
    use yadorilink_sync_sqlite::filesystem_transaction::{
        EpochRecord, EpochUpdate, FilesystemTransactionKind, NewEpoch, NewFilesystemTransaction,
        TransactionCause, TransactionPhase,
    };
    use yadorilink_root_authority::fs_capabilities::DurabilityLevel;
    use yadorilink_root_authority::fs_identity::{DirectoryIdentity, PlatformObjectId, VolumeIdentity};
    use yadorilink_sync_sqlite::file_identity_codec::GenerationId;
    use yadorilink_sync_sqlite::materialized_generation::{
        CausalBasisId, DiskGenerationBasis, MaterializedObjectKind,
    };
    use yadorilink_sync_sqlite::commit_window::CommitWindowOutcome;
    use yadorilink_filesystem_sync::optimistic_placement::PreparationCounters;
    use super::super::orchestrator::CustodyOutcome;
    use yadorilink_replica_engine::resolution_planning::PlannedPlacement;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        yadorilink_sync_sqlite::dag_store::init_dag_schema(&conn).unwrap();
        yadorilink_sync_sqlite::materialized_generation::init_materialized_generation_schema(&conn).unwrap();
        filesystem_transaction::init_filesystem_transaction_schema(&conn).unwrap();
        conn
    }

    fn begin(conn: &Connection) -> String {
        filesystem_transaction::begin_transaction_unchecked(
            conn,
            &NewFilesystemTransaction {
                group_id: "g",
                source_path: "/",
                kind: FilesystemTransactionKind::ObjectResolution,
                cause: TransactionCause::PeerProjection,
                trigger_change_hash: None,
                desired_frontier_hash: [0xEE; 32],
            },
            0,
        )
        .unwrap()
        .transaction_id
    }

    fn dir_identity() -> DirectoryIdentity {
        DirectoryIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: 1 },
            object_id: PlatformObjectId::Unix { inode: 100 },
            generation_or_usn: Some(5),
            birth_or_creation_time: None,
        }
    }

    fn group(path: &str, target: &[u8]) -> PlacementGroup {
        PlacementGroup::new(vec![PlannedPlacement {
            path: path.to_string(),
            role: PlacementRole::CanonicalPath,
            target_generation: target.to_vec(),
        }])
        .unwrap()
    }

    fn frontier(entries: &[(&str, u8)]) -> Vec<PathFrontier> {
        entries
            .iter()
            .map(|(path, head)| PathFrontier {
                path: path.to_string(),
                heads: vec![ChangeHash([*head; 32])],
            })
            .collect()
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeFailure {
        Sync,
        Structural,
    }

    /// A `PlacementOutcome` for `path`, fabricated rather than driven
    /// through the real epoch/commit/custody machinery -- everything this
    /// module's own tests need from it is that it is a real
    /// `PlacementOutcome` value the driver can carry in `DriveOutcome::
    /// placements` / `PlanDriverError::Orchestrator::placements`, not that
    /// its fields describe a placement that actually happened. Used to
    /// stand in for the outcome `orchestrator::run_slice_unchecked` would
    /// have built for a sibling that committed before a later one in the
    /// same slice failed (D2 / 21.9).
    fn fabricated_placement_outcome(path: &str) -> PlacementOutcome {
        let epoch = EpochRecord {
            transaction_id: "synthetic".to_string(),
            epoch: 0,
            plan_revision: 0,
            target_path: path.to_string(),
            placement_role: PlacementRole::CanonicalPath,
            phase: EpochState::Completed,
            displaced_generation_id: None,
            target_generation: b"synthetic".to_vec(),
            parent_directory_identity: dir_identity(),
            displaced_snapshot: None,
            stage_path: None,
            preimage_path: None,
            backup_path: None,
            staged_identity: None,
            displaced_identity: None,
            capability_snapshot: b"caps".to_vec(),
            durability_level: DurabilityLevel::PowerLossSafe,
            classification_result: None,
            captured_change_hash: None,
            unresolved_block_reason: None,
            created_at_unix_nanos: 0,
            updated_at_unix_nanos: 0,
        };
        let commit = CommitWindowOutcome {
            epoch: epoch.clone(),
            generation: DiskGenerationBasis {
                generation_id: GenerationId("synthetic".to_string()),
                causal_basis_id: CausalBasisId("synthetic".to_string()),
                resolved_path_state_hash: [0; 32],
                object_kind: MaterializedObjectKind::RegularFile,
                version: None,
                filesystem_identity: None,
            },
            counters: PreparationCounters::default(),
        };
        PlacementOutcome {
            path: path.to_string(),
            epoch,
            commit,
            custody: CustodyOutcome::NothingDisplaced,
        }
    }

    /// The scripted DAG, shared by the environment and the revalidator.
    ///
    /// It exists as its own object, not as fields on `FakeEnv`, for the
    /// reason the module doc gives: the revalidator is a separate parameter
    /// to [`drive_plan`] because the orchestrator calls it from *inside*
    /// `run_slice`, which already holds the environment mutably. Every field
    /// here is behind a `Cell`/`RefCell` because
    /// [`SliceFrontierSource::current_frontier`] takes `&self` -- the
    /// interior mutability the module doc names as the cost of that split,
    /// paid here in full view.
    ///
    /// `truth` is the frontier the DAG currently holds; `moves` installs a
    /// new truth immediately *before* the Nth `current_frontier` answer,
    /// which is exactly the window §6.1 opens -- a change admitted while
    /// preparation was running.
    struct FakeDag {
        truth: RefCell<Vec<PathFrontier>>,
        moves: RefCell<BTreeMap<usize, Vec<PathFrontier>>>,
        /// Drop a path off the Nth answer, to model a source that answers
        /// about a different scope than it was asked about.
        narrow_answer_on_call: Cell<Option<usize>>,
        current_calls: Cell<usize>,
        /// Every call the driver made, interleaved in real order --
        /// `build`, `check`, or `run:<paths>`. Counting calls cannot
        /// distinguish "revalidate, run, revalidate, run" from "revalidate
        /// three times, then run three times"; the sequence can. Shared, so
        /// the environment's own calls land in the same sequence.
        trace: RefCell<Vec<String>>,
    }

    impl SliceFrontierSource for FakeDag {
        fn current_frontier(
            &self,
            _conn: &Connection,
            _paths: &[String],
        ) -> Result<Vec<PathFrontier>, SyncError> {
            self.current_calls.set(self.current_calls.get() + 1);
            self.trace.borrow_mut().push("check".to_string());
            if let Some(moved) = self.moves.borrow_mut().remove(&self.current_calls.get()) {
                *self.truth.borrow_mut() = moved;
            }
            let mut answer = self.truth.borrow().clone();
            if self.narrow_answer_on_call.get() == Some(self.current_calls.get()) {
                answer.pop();
            }
            Ok(answer)
        }
    }

    /// A scripted environment.
    struct FakeEnv {
        transaction_id: String,
        dag: Rc<FakeDag>,
        groups: Vec<PlacementGroup>,
        /// Bump the transaction's execution generation at the start of the
        /// Nth `run_slice`, so this slice's own transitions meet a fence
        /// that has moved since the driver validated the plan.
        bump_generation_on_run_call: Option<usize>,
        /// Fail the Nth `run_slice` with an ordinary, non-fence error of
        /// this shape.
        fail_on_run_call: Option<(usize, FakeFailure)>,
        /// Fail the Nth `run_slice` the way the orchestrator's own commit
        /// boundary fails when §6.2 step 3 refuses.
        supersede_on_run_call: Option<usize>,
        /// Fail the Nth `run_slice` with `OrchestratorError::Partial`,
        /// carrying one fabricated `PlacementOutcome` for the given path --
        /// standing in for a sibling that committed before this call's own
        /// failure (D2 / 21.9). The wrapped error is always the same
        /// ordinary, non-fence, non-superseded shape
        /// (`OrchestratorError::MissingIo`), so a test using this field is
        /// exercising the *unwrap*, not which failure kind triggered it.
        fail_with_partial_on_run_call: Option<(usize, &'static str)>,
        /// Replan the transaction inside every `build_plan`, standing in for
        /// a concurrent replanner that keeps moving the revision. Because
        /// the driver captured its expectation *before* calling
        /// `build_plan`, its frontier-hash publication CAS then loses every
        /// single time, which is the only way to reach the
        /// `TransitionRaced` branch repeatedly.
        replan_during_every_build: bool,
        run_calls: usize,
        build_calls: usize,
        /// Paths run per `run_slice` call, in call order.
        ran: Vec<Vec<String>>,
        /// Execution generation each `run_slice` was handed.
        ran_generations: Vec<i64>,
        /// The plan's frontier hash and scope as handed to each `run_slice`
        /// through `revalidation`, so a test can prove the driver passes the
        /// plan actually being executed rather than something reconstructed.
        ran_revalidation: Vec<([u8; 32], Vec<String>)>,
        clock: i64,
    }

    impl FakeEnv {
        fn new(
            transaction_id: &str,
            truth: Vec<PathFrontier>,
            groups: Vec<PlacementGroup>,
        ) -> Self {
            FakeEnv {
                transaction_id: transaction_id.to_string(),
                dag: Rc::new(FakeDag {
                    truth: RefCell::new(truth),
                    moves: RefCell::new(BTreeMap::new()),
                    narrow_answer_on_call: Cell::new(None),
                    current_calls: Cell::new(0),
                    trace: RefCell::new(Vec::new()),
                }),
                groups,
                bump_generation_on_run_call: None,
                fail_on_run_call: None,
                supersede_on_run_call: None,
                fail_with_partial_on_run_call: None,
                replan_during_every_build: false,
                run_calls: 0,
                build_calls: 0,
                ran: Vec::new(),
                ran_generations: Vec::new(),
                ran_revalidation: Vec::new(),
                clock: 100,
            }
        }

        fn moves_insert(&self, call: usize, frontier: Vec<PathFrontier>) {
            self.dag.moves.borrow_mut().insert(call, frontier);
        }

        fn set_narrow_answer(&self, call: usize) {
            self.dag.narrow_answer_on_call.set(Some(call));
        }

        fn trace(&self) -> Vec<String> {
            self.dag.trace.borrow().clone()
        }
    }

    impl PlanEnvironment for FakeEnv {
        fn build_plan(
            &mut self,
            conn: &Connection,
            _plan_revision: i64,
            _execution_generation: i64,
        ) -> Result<PlanBuild, SyncError> {
            self.build_calls += 1;
            self.dag.trace.borrow_mut().push("build".to_string());
            if self.replan_during_every_build {
                let transaction_id = self.transaction_id.clone();
                resolution_planning::replan_unchecked(conn, &transaction_id, None, self.clock)?;
            }
            Ok(PlanBuild { groups: self.groups.clone(), frontier: self.dag.truth.borrow().clone() })
        }

        fn group_bytes(&self, _group: &PlacementGroup) -> u64 {
            1
        }

        fn run_slice(
            &mut self,
            conn: &mut Connection,
            slice: &PlanSlice,
            expected_execution_generation: i64,
            next_epoch: i64,
            revalidation: SliceRevalidation<'_>,
        ) -> Result<Vec<PlacementOutcome>, OrchestratorError> {
            self.run_calls += 1;
            let paths: Vec<String> = slice.placements().map(|p| p.path.clone()).collect();
            self.dag.trace.borrow_mut().push(format!("run:{}", paths.join(",")));
            self.ran.push(paths);
            self.ran_generations.push(expected_execution_generation);
            self.ran_revalidation
                .push((revalidation.plan.frontier_hash, revalidation.scope.to_vec()));

            if self.supersede_on_run_call == Some(self.run_calls) {
                // Exactly what `orchestrator::run_slice` returns when its own
                // commit boundary refuses: nothing committed, no reservation
                // left held.
                return Err(OrchestratorError::PlanSuperseded {
                    reason: "test: the commit boundary refused".to_string(),
                });
            }
            if let Some((call, committed_path)) = self.fail_with_partial_on_run_call {
                if call == self.run_calls {
                    return Err(OrchestratorError::Partial {
                        error: Box::new(OrchestratorError::MissingIo {
                            path: "test: a sibling this slice needed".to_string(),
                        }),
                        placements: vec![fabricated_placement_outcome(committed_path)],
                    });
                }
            }
            if let Some((call, kind)) = self.fail_on_run_call {
                if call == self.run_calls {
                    // Two shapes, because `is_execution_generation_fenced`
                    // has two arms to get wrong: a `Sync` error reaches its
                    // inner `SyncError` match, a structural one only its
                    // outer catch-all.
                    return Err(match kind {
                        FakeFailure::Sync => OrchestratorError::Sync(SyncError::NotFound(
                            "a block this slice needed".to_string(),
                        )),
                        FakeFailure::Structural => {
                            OrchestratorError::MissingIo { path: "b.txt".to_string() }
                        }
                    });
                }
            }
            if self.bump_generation_on_run_call == Some(self.run_calls) {
                // Somebody else moved the fence between the driver's
                // staleness check and this slice's first transition. Nothing
                // below is faked: the real fence refuses the real transition
                // and that refusal is what reaches the driver.
                filesystem_transaction::increment_execution_generation_unchecked(
                    conn,
                    &self.transaction_id,
                )
                .unwrap();
            }

            // A real caller moves the saga into its commit window before
            // any epoch transition (design §8.2); after a replan the phase
            // is back at `Planning`, so this re-enters rather than assuming.
            let record = filesystem_transaction::lookup_transaction(conn, &self.transaction_id)
                .unwrap()
                .unwrap();
            if record.phase != TransactionPhase::Committing {
                filesystem_transaction::set_transaction_phase_unchecked(
                    conn,
                    &record.transaction_id,
                    expected_execution_generation,
                    TransactionPhase::Committing,
                    None,
                    self.clock,
                )
                .map_err(|e| OrchestratorError::Sync(SyncError::from(e)))?;
                self.clock += 1;
            }

            yadorilink_sync_sqlite::resolution_planning::allocate_slice_epochs_unchecked(
                conn,
                &record.transaction_id,
                slice,
                next_epoch,
                expected_execution_generation,
                |_| dir_identity(),
                b"caps",
                DurabilityLevel::PowerLossSafe,
                self.clock,
            )
            .map_err(|e| OrchestratorError::Sync(SyncError::from(e)))?;
            self.clock += 1;

            for offset in 0..slice.epoch_count() as i64 {
                for state in [
                    EpochState::Preparing,
                    EpochState::PreparedArtifact,
                    EpochState::AwaitingReservation,
                    EpochState::Prepared,
                    EpochState::Committing,
                    EpochState::Committed,
                ] {
                    filesystem_transaction::transition_epoch_unchecked(
                        conn,
                        &record.transaction_id,
                        next_epoch + offset,
                        expected_execution_generation,
                        state,
                        &EpochUpdate::default(),
                        self.clock,
                    )
                    .map_err(|e| OrchestratorError::Sync(SyncError::from(e)))?;
                    self.clock += 1;
                }
            }
            Ok(Vec::new())
        }
    }

    /// Runs the driver with `env` and `env`'s own DAG as the (separately
    /// owned) revalidator. The `Rc` clone is what makes that possible at
    /// all: `&mut env` and `&env.dag` in one call is the double borrow the
    /// module doc describes.
    macro_rules! drive {
        ($conn:expr, $tx:expr, $env:expr, $bounds:expr, $now:expr) => {{
            let dag = $env.dag.clone();
            drive_plan_unchecked($conn, $tx, &mut $env, dag.as_ref(), $bounds, $now)
        }};
    }

    fn bounds(max_paths_per_slice: usize, max_plan_attempts: u32) -> DriveBounds {
        let slice_bounds = SliceBounds { max_paths_per_slice, ..SliceBounds::default() };
        DriveBounds { slice_bounds, max_plan_attempts, ..DriveBounds::default() }
    }

    #[test]
    fn a_plan_nothing_invalidates_runs_every_slice_once_and_stops() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env = FakeEnv::new(
            &transaction_id,
            frontier(&[("a.txt", 1), ("b.txt", 2)]),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb")],
        );

        let outcome = drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap();

        assert_eq!(env.ran, vec![vec!["a.txt".to_string()], vec!["b.txt".to_string()]]);
        assert_eq!(outcome.replans, 0);
        // One real attempt: it ran every slice without ever going stale.
        // `build_calls` is still 2 (the work, plus the rebuild that proved
        // there was nothing left against a freshly read frontier) -- but
        // that rebuild is a mandatory proof step, not a chargeable attempt
        // (D1 / 24.10): it does no work and cannot itself go stale, so it
        // must not count against `max_plan_attempts`, or a bound of `1`
        // could never report success for any non-empty plan.
        assert_eq!(outcome.plan_attempts, 1);
        assert_eq!(env.build_calls, 2);
    }

    /// The reason this module exists. Preparation for the second slice runs
    /// with no reservation held (§6.1), a peer's change lands in that
    /// window, and the revalidation before that slice's commit is the only
    /// thing standing between the DAG's new answer and a committed write of
    /// the superseded one.
    #[test]
    fn a_frontier_that_moves_mid_plan_replans_instead_of_committing_the_superseded_slice() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env = FakeEnv::new(
            &transaction_id,
            frontier(&[("a.txt", 1), ("b.txt", 2)]),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb")],
        );
        // Call 1 revalidates slice "a.txt" and passes; the move lands
        // before call 2, which revalidates "b.txt".
        env.moves_insert(2, frontier(&[("a.txt", 1), ("b.txt", 0xB2)]));

        let outcome = drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap();

        assert_eq!(outcome.replans, 1);
        // "b.txt" ran only after the replan, never under the plan the move
        // superseded: three run_slice calls, not two, and the second slice
        // of the first plan is absent.
        assert_eq!(
            env.ran,
            vec![
                vec!["a.txt".to_string()],
                vec!["b.txt".to_string()],
                // nothing else: the rebuild found "a.txt" already committed
            ],
            "the superseded slice must not commit; it re-runs under the new plan"
        );
        // The replan bumped the fence, and the slice that ran afterwards
        // was handed the new value -- an epoch still in flight under the
        // old one can no longer commit.
        assert_eq!(env.ran_generations, vec![0, 1]);
        let after =
            filesystem_transaction::lookup_transaction(conn, &transaction_id).unwrap().unwrap();
        assert_eq!(after.plan_revision, 1);
        assert_eq!(after.execution_generation, 1);
    }

    /// §6.2 says every slice revalidates, and a plan with several slices
    /// spends real time between them. Checking once per plan would answer a
    /// question about a moment that has already passed.
    #[test]
    fn the_frontier_is_revalidated_before_every_slice_not_once_per_plan() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env = FakeEnv::new(
            &transaction_id,
            frontier(&[("a.txt", 1), ("b.txt", 2), ("c.txt", 3)]),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb"), group("c.txt", b"gc")],
        );

        drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap();

        // The ORDER, not the count: three checks followed by three runs
        // would satisfy any count-based assertion while checking staleness
        // at a moment that has nothing to do with the slice it guards.
        assert_eq!(
            env.trace(),
            vec![
                "build",
                "check",
                "run:a.txt",
                "check",
                "run:b.txt",
                "check",
                "run:c.txt",
                // the rebuild that finds nothing left
                "build",
            ]
        );
    }

    /// A recomputation over a narrower scope than the plan's can never
    /// differ for a path outside it, so comparing the two hashes would read
    /// as "still current" no matter what happened to the dropped path.
    #[test]
    fn a_frontier_answer_about_a_different_scope_is_refused_rather_than_compared() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env = FakeEnv::new(
            &transaction_id,
            frontier(&[("a.txt", 1), ("b.txt", 2)]),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb")],
        );
        env.set_narrow_answer(1);

        let error = drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap_err();

        match error {
            PlanDriverError::FrontierScopeChanged { expected, actual } => {
                assert_eq!(expected, vec!["a.txt".to_string(), "b.txt".to_string()]);
                assert_eq!(actual, vec!["a.txt".to_string()]);
            }
            other => panic!("expected a refused scope change, got {other:?}"),
        }
        assert!(env.ran.is_empty(), "nothing may commit on an incomparable check");
    }

    /// The fence firing arrives as an error from `run_slice`, not as a
    /// `plan_is_stale` yes -- and it means the same thing. Treating it as
    /// terminal aborts the one loop whose job is to replan, handing forward
    /// progress to whoever happens to call again.
    #[test]
    fn a_fence_that_fires_inside_a_slice_replans_instead_of_aborting_the_loop() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env = FakeEnv::new(
            &transaction_id,
            frontier(&[("a.txt", 1), ("b.txt", 2)]),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb")],
        );
        // The frontier never moves, so `plan_is_stale` says no every time.
        // The only staleness signal in this run is the fence itself.
        env.bump_generation_on_run_call = Some(2);

        let outcome = drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap();

        assert_eq!(outcome.replans, 1, "the fence must be read as staleness, not as a fault");
        // "b.txt" was refused under the superseded generation and then ran
        // under the replanned one; "a.txt" committed before any of it and is
        // not redone.
        assert_eq!(
            env.ran,
            vec![vec!["a.txt".to_string()], vec!["b.txt".to_string()], vec!["b.txt".to_string()],]
        );
        // 0 for the first plan, then the fence bump (1) plus replan's own
        // bump (2).
        assert_eq!(env.ran_generations, vec![0, 0, 2]);
    }

    /// The commit boundary's own §6.2 step 3 refusing is this loop's third
    /// staleness signal, and the only one that can see a frontier that moved
    /// *during* a slice's own preparation. It must replan and continue, not
    /// abort — the same response as the fence firing.
    #[test]
    fn the_commit_boundary_refusing_a_slice_replans_instead_of_aborting_the_loop() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env = FakeEnv::new(
            &transaction_id,
            frontier(&[("a.txt", 1), ("b.txt", 2)]),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb")],
        );
        // The frontier this loop can see never moves; the only staleness
        // signal is the boundary's own refusal, reached inside `run_slice`.
        env.supersede_on_run_call = Some(2);

        let result = drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000);

        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => panic!(
                "a boundary refusal must replan and continue, not abort the drive: {error:?}"
            ),
        };
        assert_eq!(
            outcome.replans, 1,
            "a boundary refusal must be read as staleness, not as a fault"
        );
        assert_eq!(
            env.ran,
            vec![vec!["a.txt".to_string()], vec!["b.txt".to_string()], vec!["b.txt".to_string()]],
            "the refused slice must be redone under the replanned plan"
        );
    }

    /// The plan handed to the boundary must be the plan actually being
    /// executed. A driver that reconstructed it, or passed the previous
    /// attempt's, would give the orchestrator a hash to compare that no
    /// longer describes this slice — the "two scopes that must be the same
    /// scope" defect, moved one layer down.
    #[test]
    fn every_slice_is_handed_the_frontier_hash_and_scope_of_the_plan_it_belongs_to() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let truth = frontier(&[("a.txt", 1), ("b.txt", 2)]);
        let mut env = FakeEnv::new(
            &transaction_id,
            truth.clone(),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb")],
        );

        drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap();

        let expected_hash = desired_frontier_hash(&truth).unwrap();
        let expected_scope = vec!["a.txt".to_string(), "b.txt".to_string()];
        assert_eq!(env.ran_revalidation.len(), 2);
        for (hash, scope) in &env.ran_revalidation {
            assert_eq!(*hash, expected_hash, "the plan's own captured frontier hash, not another");
            assert_eq!(scope, &expected_scope, "the plan's own path scope, ascending");
        }
    }

    /// The counterpart to the fence test above, and the reason the matcher
    /// is narrow. An ordinary failure is not staleness; swallowing it into
    /// "replan and try again" turns a broken transaction into one that
    /// retries the same broken thing until the attempt bound, reporting a
    /// bound exhaustion instead of the actual fault.
    fn assert_slice_failure_aborts(kind: FakeFailure) {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env = FakeEnv::new(
            &transaction_id,
            frontier(&[("a.txt", 1), ("b.txt", 2)]),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb")],
        );
        env.fail_on_run_call = Some((2, kind));

        let error = drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap_err();

        assert!(
            matches!(error, PlanDriverError::Orchestrator { .. }),
            "the real error must reach the caller, got {error:?}"
        );
        let after =
            filesystem_transaction::lookup_transaction(conn, &transaction_id).unwrap().unwrap();
        assert_eq!(after.plan_revision, 0, "an ordinary failure must not replan");
    }

    #[test]
    fn an_ordinary_sync_failure_in_a_slice_aborts_rather_than_being_read_as_staleness() {
        assert_slice_failure_aborts(FakeFailure::Sync);
    }

    #[test]
    fn a_structural_slice_failure_aborts_rather_than_being_read_as_staleness() {
        assert_slice_failure_aborts(FakeFailure::Structural);
    }

    /// D2 (21.9): `run_slice` can fail with `OrchestratorError::Partial`,
    /// carrying the outcome of whatever in the same call already committed
    /// and was driven through custody and authoring. An ordinary (not
    /// fenced, not superseded) failure aborts the drive -- but the
    /// committed sibling's outcome must still reach the caller through
    /// `PlanDriverError::Orchestrator::placements`, not be dropped along
    /// with the error the old code returned bare.
    #[test]
    fn an_ordinary_failure_wrapped_with_a_committed_siblings_outcome_still_reports_that_outcome() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env = FakeEnv::new(
            &transaction_id,
            frontier(&[("a.txt", 1), ("b.txt", 2)]),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb")],
        );
        // The second run_slice call ("b.txt") fails with `Partial`, wrapping
        // a fabricated outcome for "a.txt" -- standing in for a sibling
        // `run_slice_unchecked` had already committed inside that same call
        // before the failure.
        env.fail_with_partial_on_run_call = Some((2, "a.txt"));

        let error = drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap_err();

        match error {
            PlanDriverError::Orchestrator { placements, .. } => {
                assert_eq!(
                    placements.iter().map(|p| p.path.as_str()).collect::<Vec<_>>(),
                    vec!["a.txt"],
                    "the committed sibling's outcome must not be dropped just because the \
                     slice as a whole failed"
                );
            }
            other => panic!("expected an ordinary orchestrator failure, got {other:?}"),
        }
    }

    #[test]
    fn a_frontier_that_keeps_moving_stops_at_the_attempt_bound() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env =
            FakeEnv::new(&transaction_id, frontier(&[("a.txt", 1)]), vec![group("a.txt", b"ga")]);
        for call in 1..=8 {
            env.moves_insert(call, frontier(&[("a.txt", 0x10 + call as u8)]));
        }

        let error = drive!(conn, &transaction_id, env, &bounds(1, 3), 1_000).unwrap_err();

        match error {
            PlanDriverError::PlanNeverSettled { attempts, replans, .. } => {
                assert_eq!(attempts, 3);
                // Every attempt this run spent went stale and replanned --
                // this is the "genuinely churning" case `replans` exists to
                // distinguish from an attempt bound that was simply too low
                // for an otherwise well-behaved transaction (D1 / 24.10).
                assert_eq!(replans, 3);
            }
            other => panic!("expected the attempt bound, got {other:?}"),
        }
        assert!(env.ran.is_empty(), "every attempt went stale before its first slice");
    }

    /// D1 (24.10): the attempt bound used to be charged once per loop
    /// iteration, including the mandatory rebuild that merely *proves*
    /// nothing is left -- so a transaction needing zero replans still spent
    /// two attempts to report success, and `max_plan_attempts: 1` could
    /// never succeed for any non-empty plan. A plan that never goes stale
    /// must be able to settle in exactly one real attempt, even when that
    /// is the entire budget.
    #[test]
    fn max_plan_attempts_of_one_still_succeeds_for_a_plan_that_never_goes_stale() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env = FakeEnv::new(
            &transaction_id,
            frontier(&[("a.txt", 1), ("b.txt", 2)]),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb")],
        );

        let result = drive!(conn, &transaction_id, env, &bounds(1, 1), 1_000);

        match result {
            Ok(outcome) => {
                assert_eq!(outcome.plan_attempts, 1, "one real attempt: nothing went stale");
                assert_eq!(outcome.replans, 0);
            }
            Err(error) => panic!(
                "a plan that never goes stale must be able to succeed even at \
                 max_plan_attempts: 1, got {error:?}"
            ),
        }
        assert_eq!(env.ran, vec![vec!["a.txt".to_string()], vec!["b.txt".to_string()]]);
    }

    /// The loop's contract is that it always terminates. Losing the
    /// frontier-hash publication CAS used to be the one way out of that:
    /// the `TransitionRaced` branch returns to the top of the loop without
    /// charging `max_plan_attempts`, deliberately, because the iteration
    /// published nothing and did no work. But a concurrent replanner that
    /// keeps moving the revision makes that branch fire on every single
    /// iteration, and an uncharged branch that can fire forever is an
    /// unbounded loop -- so it is charged to its own separate budget.
    ///
    /// The environment here replans inside every `build_plan`, which is
    /// exactly the shape that loses the CAS every time: the driver reads
    /// the revision, calls `build_plan`, and by the time it publishes, the
    /// value it captured is stale. Without the churn bound this call does
    /// not return.
    #[test]
    fn losing_the_publication_cas_forever_ends_the_drive_instead_of_spinning() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let mut env =
            FakeEnv::new(&transaction_id, frontier(&[("a.txt", 1)]), vec![group("a.txt", b"ga")]);
        env.replan_during_every_build = true;

        let drive_bounds = DriveBounds { max_publication_races: 3, ..bounds(1, 8) };
        let result = drive!(conn, &transaction_id, env, &drive_bounds, 1_000);

        match result {
            Err(PlanDriverError::PlanNeverSettled { attempts, .. }) => {
                // The work budget is untouched: every iteration was spent
                // losing the race, never running a slice, so charging these
                // to `max_plan_attempts` would have misreported a racing
                // drive as one that exhausted its real attempts.
                assert_eq!(
                    attempts, 0,
                    "a lost publication CAS must not be charged to the work budget"
                );
            }
            other => {
                panic!("a drive that can never publish its plan must end, not spin, got {other:?}")
            }
        }
        // One build per lost race plus the one that exceeded the bound --
        // proof the loop really did go round, rather than exiting early for
        // some unrelated reason.
        assert_eq!(env.build_calls, 4);
        assert!(env.ran.is_empty(), "no slice can run when no plan is ever published");
    }

    /// Reproduces the wedge a mid-slice prepare failure used to leave
    /// behind: `orchestrator::run_slice_unchecked`'s prepare-failure
    /// protocol (and the commit window's own non-retryable `NotStarted`
    /// branch) already returned its error to a previous caller by the time
    /// this loop can ever observe the transaction again, leaving it at
    /// `TransactionPhase::Blocked` with a leftover non-terminal epoch under
    /// it (here built directly, standing in for whichever of those two
    /// routes produced it -- the driver's fix does not care which one did).
    /// Before the fix, this loop had no branch that read the phase at all:
    /// it went straight to `build_plan`, and the first `run_slice` call
    /// would have failed with a plain `SyncError::InvalidInput` from
    /// `TransactionPhase::may_receive_new_epochs` refusing a new epoch --
    /// not the fence shape `is_execution_generation_fenced` matches, so it
    /// would have aborted the loop and left the transaction wedged exactly
    /// where it already was, forever.
    #[test]
    fn a_blocked_parent_is_replanned_instead_of_being_retried_or_left_wedged() {
        let conn = &mut open();
        let transaction_id = begin(conn);

        // Stand in for the leftover state a real prepare failure leaves:
        // one epoch that failed and was correctly settled to `Blocked`
        // already, under a transaction whose phase was moved to `Blocked`
        // with it. No `PreparedArtifact`/`Allocated` sibling is needed here
        // -- this test is about the driver noticing the phase, not about
        // what a replan does to a sibling epoch (that is covered in
        // `resolution_planning`'s own tests).
        filesystem_transaction::insert_epoch_unchecked(
            conn,
            &NewEpoch {
                transaction_id: &transaction_id,
                epoch: 0,
                plan_revision: 0,
                target_path: "a.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"stale",
                parent_directory_identity: &dir_identity(),
                capability_snapshot: b"caps",
                durability_level: DurabilityLevel::PowerLossSafe,
            },
            0,
            0,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            conn,
            &transaction_id,
            0,
            0,
            EpochState::Blocked,
            &EpochUpdate::default(),
            1,
        )
        .unwrap();
        filesystem_transaction::set_transaction_phase_unchecked(
            conn,
            &transaction_id,
            0,
            TransactionPhase::Blocked,
            Some("prepare failed for a.txt"),
            2,
        )
        .unwrap();

        let mut env =
            FakeEnv::new(&transaction_id, frontier(&[("a.txt", 1)]), vec![group("a.txt", b"ga")]);

        let outcome = drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap();

        assert_eq!(
            outcome.replans, 1,
            "a Blocked parent must be replanned, the same as a stale frontier"
        );
        // The blocked epoch is never touched again; a fresh one is planned
        // and actually runs.
        assert_eq!(env.ran, vec![vec!["a.txt".to_string()]]);
        let after =
            filesystem_transaction::lookup_transaction(conn, &transaction_id).unwrap().unwrap();
        assert_eq!(after.phase, TransactionPhase::Committing, "FakeEnv moves it there on its run");
        assert_eq!(after.plan_revision, 1, "replan_unchecked advanced it exactly once");
    }

    /// The durable half of §6.1 step 2. Before this had a writer the column
    /// kept the frontier of whichever plan happened to be the first, so from
    /// the first replan onwards the row named a superseded plan's frontier.
    #[test]
    fn the_transaction_row_records_the_frontier_of_the_plan_actually_being_executed() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        let final_frontier = frontier(&[("a.txt", 0xB2)]);
        let mut env =
            FakeEnv::new(&transaction_id, frontier(&[("a.txt", 1)]), vec![group("a.txt", b"ga")]);
        env.moves_insert(1, final_frontier.clone());

        drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap();

        let after =
            filesystem_transaction::lookup_transaction(conn, &transaction_id).unwrap().unwrap();
        assert_eq!(
            after.desired_frontier_hash,
            desired_frontier_hash(&final_frontier).unwrap(),
            "the row must name the frontier the executed plan was built from"
        );
    }

    #[test]
    fn the_next_epoch_is_one_above_every_epoch_the_transaction_ever_allocated() {
        let conn = &mut open();
        let transaction_id = begin(conn);
        assert_eq!(next_epoch_for_transaction(conn, &transaction_id).unwrap(), 0);

        let mut env = FakeEnv::new(
            &transaction_id,
            frontier(&[("a.txt", 1), ("b.txt", 2)]),
            vec![group("a.txt", b"ga"), group("b.txt", b"gb")],
        );
        env.moves_insert(2, frontier(&[("a.txt", 1), ("b.txt", 0xB2)]));
        drive!(conn, &transaction_id, env, &bounds(1, 8), 1_000).unwrap();

        // Two epochs survive from the superseded plan's own allocation plus
        // the one the replanned slice allocated -- the next number is above
        // all of them, never a reuse of the superseded plan's.
        let epochs =
            filesystem_transaction::list_epochs_for_transaction(conn, &transaction_id).unwrap();
        let highest = epochs.iter().map(|e| e.epoch).max().unwrap();
        assert_eq!(next_epoch_for_transaction(conn, &transaction_id).unwrap(), highest + 1);
    }
}
