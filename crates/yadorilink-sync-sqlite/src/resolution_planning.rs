//! Durable planning: a versioned [`FilesystemResolutionPlan`], split into
//! bounded, all-or-none [`PlanSlice`]s, replanned rather than blindly
//! continued once its captured inputs go stale. See
//! `openspec/design/preimage-capture.md` §6 ("Durable planning and
//! short-commit saga"), §6.4 ("Bounded plan slices"), §11.2 ("multi-path
//! reservation sets and multi-epoch resolver placement") and §17
//! ("Directory subtrees").
//!
//! # Reuse, not a second mechanism
//!
//! This module adds no second planner, no second reservation path and no
//! parallel replanning state machine. It is a thin layer over
//! [`crate::filesystem_transaction`]'s existing tables:
//!
//! - a "plan" is a pure, in-memory value (never its own SQL table); its
//!   durable identity is exactly `filesystem_transactions.plan_revision` /
//!   `.desired_frontier_hash` / `.execution_generation`, all of which
//!   already exist;
//! - "already committed" placements are read back from
//!   `filesystem_transaction_epochs` (`list_epochs_for_transaction`), never
//!   tracked in a second progress table;
//! - replanning is exactly the existing `(Committing, Planning)` /
//!   `(AsyncPreservation, Planning)` / `(Blocked, Planning)` transaction-phase
//!   edges ([`crate::filesystem_transaction::TransactionPhase::can_transition_to`]),
//!   driven through the existing `set_transaction_phase`;
//! - reservations for a slice go through exactly one
//!   [`crate::filesystem_transaction::acquire_reservations`] call, using its
//!   existing all-or-none, sorted-acquisition guarantee.
//!
//! One addition to `filesystem_transaction` itself was needed:
//! `set_plan_revision`/`set_plan_revision_unchecked`, mirroring
//! `increment_execution_generation`'s exact shape. Nothing else in that
//! module changed.
//!
//! # What makes a plan stale
//!
//! Not "the DAG moved" — the DAG moves continuously and most of it is
//! irrelevant to any one plan. A plan is stale exactly when one of the
//! fixed inputs it captured at build time no longer matches the current
//! value:
//!
//! - `desired_frontier_hash` — the resolved head-set for the plan's own
//!   path scope, not the whole DAG;
//! - `execution_generation` — the parent transaction's fence, which
//!   [`crate::filesystem_transaction::TransactionPhase`]'s own doc names as
//!   bumped precisely when "captured writing produce[s] a new local DAG
//!   change" that touches this transaction (design §6.3). *Which* local
//!   changes count is decided at DAG-admission time by whichever caller
//!   authors them (`captured_authoring`, `custody_transfer`, etc.) — outside
//!   this module. This module only trusts the fence, it does not decide who
//!   bumps it;
//! - parent-directory identity, capability snapshot — revalidated at
//!   short-commit-window time by the commit driver, not by this module.
//!
//! A local change to a path *outside* the plan's scope does not invalidate
//! it: nothing here touches `execution_generation` unless the caller that
//! admitted that change decided the transaction's fence applies, or
//! [`replan`] itself bumps it once staleness is already known (see below).
//! Detecting staleness per slice is two independent `O(1)` checks — see
//! [`plan_is_stale`]'s own doc for exactly what each compares, their real
//! costs, and why the `execution_generation` fence alone is not sufficient
//! *for detection*. The fence IS wired at DAG admission — an earlier version
//! of this paragraph claimed it was not, which was simply false:
//! [`crate::dag_store`]'s `bump_execution_fence_for_change` runs on remote
//! admission, on orphan promotion and on local emission, and calls
//! [`crate::filesystem_transaction::bump_transactions_for_touched_paths`].
//! Its limit is narrower, and it is the narrowness, not any missing wiring,
//! that makes the hash comparison load-bearing: that lookup fences only
//! transactions **holding a reservation** on a touched path, and design §6.1
//! deliberately holds no reservation across preparation — so for exactly the
//! preparation window the fence cannot see a change that invalidates the
//! plan. ([`replan`] bumps the fence too, but only as a fencing consequence
//! *after* staleness has already been established some other way, never as a
//! staleness signal.) So [`plan_is_stale`] also compares the plan's captured
//! `desired_frontier_hash` against a freshly recomputed one the caller
//! supplies — that comparison is the authoritative detection signal, it
//! covers the window the fence is blind for, and it must not be dropped in
//! favour of the fence. Recomputing that hash (rerunning
//! [`yadorilink_replica_engine::conflict::resolve_path_heads`] over the plan's own paths) is the
//! expensive part and stays outside this module, which has no DAG access of
//! its own — it is the same walk needed to *build* a plan or a replacement
//! plan in the first place.
//!
//! # Bounded plan slices
//!
//! [`SliceBounds`] carries four independent bounds — paths, epochs, staged
//! bytes and (informationally, for the commit driver to honor) wall time —
//! because no single one of them protects every failure mode design §6.4
//! calls out:
//!
//! - `max_paths_per_slice` / `max_epochs_per_slice` bound how much SQL
//!   journal state and how many directory operations one commit-window
//!   attempt takes on. They differ because one path can become several
//!   epochs (a winning content head plus its conflict copies, see
//!   [`resolution_to_group`]), so a slice that looks small by path count can
//!   still be large by epoch count;
//! - `max_staged_bytes_per_slice` bounds *preparation*, not the commit
//!   window itself (design §6.1 fetches/assembles targets before any lock is
//!   held) — a slice with few paths but huge files can still stall if
//!   nothing bounds bytes;
//! - `max_commit_window` is carried here as the value the actual commit
//!   driver (outside this module — see `optimistic_placement`) must honor
//!   for design §6.2's short commit window; this module never opens a
//!   commit window itself.
//!
//! Too small a bound (single-path slices) makes a large directory operation
//! or conflict set take forever, paying the full plan/reserve/commit/release
//! round trip per object; too large a bound reintroduces the unbounded pass
//! §6.4 exists to avoid. The defaults below are a starting point tuned for
//! neither extreme, deliberately provisional and meant to be measured once a
//! real commit driver exists (see `optimistic_placement`'s own performance
//! notes), not treated as an authoritative SLO.
//!
//! A [`PlacementGroup`] is the smallest unit [`slice_plan`] will ever split
//! across two slices — never a bare path. A winning head and its conflict
//! copies are one group (§11.2: "a single logical change can require
//! several paths at once"); a caller that additionally knows two groups are
//! coupled by an external constraint (for example a rename's source and
//! destination) can fuse them with [`PlacementGroup::merge`] before slicing,
//! so they too are never split. If one group alone exceeds a slice's bounds,
//! it still becomes its own (oversized) slice rather than being torn apart —
//! documented in [`slice_plan`].
//!
//! # Replanning does not lose committed work
//!
//! [`plan_progress`] reuses the epoch machinery directly: a placement counts
//! as already done when the **latest** epoch (by epoch number, a single
//! strictly-increasing, never-reused counter per transaction) this
//! transaction has ever allocated for that exact `target_path` reached
//! [`yadorilink_replica_domain::filesystem_placement::EpochState::Committed`] or a state
//! reachable from it (`CustodyTransferred` through `Completed`; deliberately
//! *not* `Quarantined` / `RequiresPhysicalRecovery` / `Blocked`, which are
//! terminal but not "placed as planned" — see
//! `EpochState::is_terminal`'s own doc on why those three redo under a fresh
//! epoch rather than resuming) *and* names the same `target_generation`
//! bytes — the opaque bytes this module never decodes, same as
//! `filesystem_transaction` itself. Keying on the latest epoch *per path*,
//! not on "any epoch that ever committed this generation," matters: a path
//! can be committed once, then committed again at a different generation by
//! a later epoch (desired content changed and changed back across two
//! replans) — the disk only ever reflects the last successful commit, so an
//! earlier commit of the generation a new plan wants again must not be
//! trusted just because it happened. The match is on content, not on
//! `plan_revision`: if a path's desired content did not change across a
//! replan, the new plan (rebuilt by rerunning `resolve_path_heads`) names
//! the identical target bytes at that path and [`plan_progress`] correctly
//! skips it even though it now belongs to a new `plan_revision` number; if
//! the desired content *did* change, the bytes differ (or an intervening
//! epoch at that path makes the old commit no longer the latest one) and a
//! fresh epoch is planned. No second "progress" table is needed because the
//! epoch journal already is that record.
//!
//! ## "Latest epoch number" is allocation order, not commit order — and why
//! that is still safe
//!
//! Epoch numbers are assigned when an epoch is *allocated*
//! ([`allocate_slice_epochs`]'s `next_epoch`), not when it commits. Nothing
//! in this crate records real commit order directly — no column anywhere
//! (epoch or transaction table) is a sequence bumped only at the moment an
//! epoch reaches `Committed`; `updated_at_unix_nanos` is a wall-clock
//! timestamp set on every transition, not a commit-order counter, and is
//! not used for ordering here. So without an additional guarantee,
//! `plan_progress` picking the highest-numbered epoch per path would be
//! wrong exactly when a lower-numbered epoch is still mid-commit at the
//! moment a higher-numbered one is allocated and finishes first: epoch 0
//! reaches `Committing` and stalls, [`replan`] runs (allocating a new plan
//! but deliberately never touching *epoch* numbers, only `plan_revision`
//! and, as of this fix, `execution_generation`), epoch 1 for the same path
//! is allocated and commits, and epoch 0 then resumes.
//!
//! This is made safe not by ordering epoch numbers correctly but by
//! preventing the stale epoch from ever completing its commit:
//! [`replan`] bumps `execution_generation` before returning, and every
//! epoch's own `Committing` → `Committed` transition is fenced by
//! [`crate::filesystem_transaction::check_execution_generation`] against
//! the *exact* generation value that epoch captured when it began (see
//! `transition_epoch_unchecked`'s own doc in `filesystem_transaction`).
//! Epoch 0's stalled resume therefore fails
//! (`SyncError::ExecutionGenerationFenced`) instead of silently committing
//! after epoch 1 — see
//! `a_stalled_epoch_cannot_commit_after_a_replan_supersedes_it` below. Given
//! that invariant, and that a single transaction's slices commit
//! sequentially (never two slices' epochs racing each other without an
//! intervening replan — see the module doc's deadlock section, which
//! established one `acquire_reservations` call per slice, and slices for
//! one transaction are driven one at a time by the commit driver outside
//! this module), the highest epoch number for a path that ever *actually*
//! reaches `Committed` is guaranteed to be the one the disk currently
//! reflects. "Latest by epoch number" is sound as a consequence of the
//! fence, not as an independent ordering fact — if a future change ever
//! lets two slices' commits interleave without going through [`replan`]'s
//! fence, this reasoning would need revisiting.
//!
//! [`plan_is_stale`] and [`replan`] are driven by
//! yadorilink-daemon's `commit_orchestration::plan_driver::drive_plan`, which owns the re-check loop this
//! module deliberately does not: rebuild from the current frontier,
//! recompute the frontier hash via [`desired_frontier_hash`], call
//! [`plan_is_stale`] before *every* slice's commit, and [`replan`] when it
//! answers yes. That module is also the only producer of a real
//! `desired_frontier_hash` — until it existed, this module's staleness
//! detection was a guarantee it *offered* with nothing exercising it, and
//! the hashes on both sides of the comparison came from test literals.
//!
//! What stays outside this module is unchanged: the DAG walk that produces
//! a frontier is the caller's (see the module doc's "reuse, not a second
//! mechanism" section), which is why `plan_driver` reaches it through an
//! environment rather than this module growing DAG access of its own.
//!
//! # All-or-none across mixed reservation kinds — verified, not assumed
//!
//! [`crate::filesystem_transaction::acquire_reservations`] does every
//! range-conflict check and every insert for a whole batch inside one
//! `BEGIN IMMEDIATE` SQLite transaction, and returns without calling
//! `COMMIT` on the first conflict — so nothing in the batch is ever left
//! held, regardless of whether the batch mixes `Exact` and
//! `SubtreeIntent`/`SubtreeExclusive` requests: they share one range-key
//! derivation and one conflict check
//! ([`yadorilink_replica_domain::filesystem_placement::ReservationScope::conflicts_with`]),
//! there is no kind-specific code path to diverge. `multi_path_acquisition_releases_the_first_path_when_the_second_is_unavailable_across_mixed_kinds`
//! below exercises exactly this — an `Exact` request that would succeed on
//! its own, batched with a `SubtreeExclusive`-blocked request, in one call —
//! and asserts the transaction ends up holding nothing.
//!
//! # Deadlock
//!
//! Two plans needing two paths in opposite orders cannot deadlock, but not
//! because of lock ordering in the classic sense — [`slice_reservation_requests`]
//! deliberately returns the *entire* flattened set for a whole slice so a
//! caller passes it to exactly **one** `acquire_reservations` call. That one
//! call is a single `BEGIN IMMEDIATE` SQLite transaction: it holds SQLite's
//! writer lock for its whole duration and either commits holding everything
//! it asked for, or never commits and holds nothing. A second concurrent
//! caller's `acquire_reservations` call simply blocks on SQLite's writer
//! lock until the first finishes — it cannot begin checking or holding
//! anything until the first is fully resolved one way or the other. Classic
//! two-resource deadlock needs a thread that holds resource A while waiting
//! on resource B that a second thread holds while waiting on A; neither
//! thread here can ever be in a "holding A, waiting on B" state, because
//! holding anything and finishing are the same commit. The internal
//! `path_key` sort inside `acquire_reservations` is therefore not what
//! prevents deadlock (nothing here needs a lock-ordering discipline) — it
//! only makes the batch's own internal iteration order deterministic.
//!
//! This guarantee depends entirely on batching: if a caller instead made
//! separate `acquire_reservations` calls per path or per group within one
//! slice, each call *would* commit and durably hold its own paths before the
//! next call begins, which reopens exactly the classic deadlock (thread A
//! holds path 1 via its first call and blocks acquiring path 2 via its
//! second, while thread B holds path 2 and blocks acquiring path 1). Callers
//! must treat [`slice_reservation_requests`]'s output as one atomic request,
//! never split it.

use rusqlite::Connection;

use yadorilink_replica_domain::filesystem_placement::EpochState;
use yadorilink_replica_engine::resolution_planning::{
    epoch_is_pre_commit_leftover, epoch_is_provably_untouched_by_adapter,
    epoch_reflects_committed_placement, PlacementGroup, PlanSlice, PlannedPlacement,
};
use crate::SyncSqliteError;
use crate::filesystem_transaction::{self, EpochRecord, NewEpoch, TransactionPhase};
use yadorilink_root_authority::fs_capabilities::DurabilityLevel;
use yadorilink_root_authority::fs_identity::DirectoryIdentity;

// `PathFrontier`/`desired_frontier_hash` (sixth pass), and
// `PlannedPlacement`/`ExtraReservation`/`PlacementGroup`/
// `resolution_to_group`, `SliceBounds`/`PlanSlice`/`slice_plan`/
// `slice_reservation_requests`, and the epoch-phase classification group
// (`classify_epoch`/`epoch_reflects_committed_placement`/
// `epoch_is_pre_commit_leftover`/`epoch_is_provably_untouched_by_adapter`)
// (seventh pass) all moved to `yadorilink-replica-engine::
// resolution_planning` (7D-9D). See that module's own top-of-file doc for
// the dependency-cycle history and its resolution (relocating
// `PlacementRole`/`EpochState`/`ReservationRole`/`ReservationScope`/
// `NewReservation` to `yadorilink-replica-domain::filesystem_placement`).
//
// Eighth pass (7D-9D): what used to remain in `yadorilink-sync-core` after
// the seventh pass -- `FilesystemResolutionPlan`, `allocate_slice_epochs[_
// unchecked]`, `plan_progress`, `plan_is_stale`, `replan[_unchecked]` --
// moved here, to `yadorilink-sync-sqlite`, as one mechanical unit (same
// "already-SQL-shaped, no separable pure fragment" pattern as
// `retained_obligation.rs`'s fourth-pass CRUD move and `captured_
// authoring.rs`'s own move): every one of these functions is genuinely
// `&Connection`-typed with no embedded pure-decision logic left to extract
// -- the one decision this file used to make inline (which epochs are
// pre-commit leftovers) was already factored out to the pure
// `epoch_is_pre_commit_leftover` predicate by the seventh pass, so what
// remained was pure SQL orchestration calling straight into
// `filesystem_transaction`/`materialized_generation`, both already owned by
// this crate. `yadorilink-sync-core`'s own `resolution_planning.rs` is gone;
// `plan_driver.rs`/`orchestrator.rs`/`early_physical_recovery.rs` import
// this module directly.

/// A pure, versioned value — never its own SQL row (see the module doc).
/// `execution_generation` is the fence value captured at build time, used
/// by [`plan_is_stale`].
#[derive(Debug, Clone)]
pub struct FilesystemResolutionPlan {
    pub plan_revision: i64,
    pub frontier_hash: [u8; 32],
    pub execution_generation: i64,
    pub groups: Vec<PlacementGroup>,
}

/// Allocates one fresh epoch per placement in `slice`, starting at
/// `next_epoch` (never a reuse of an earlier epoch number, per design §5.4).
/// `next_epoch` is the caller's belief about the transaction's true
/// next-free epoch number, not the source of truth for it -- see
/// [`allocate_slice_epochs_unchecked`]'s own doc for why, and what happens
/// when it disagrees with what the epoch journal actually holds.
/// `expected_execution_generation` is the caller's own fence belief, checked
/// against `transaction_id`'s live `execution_generation` before anything is
/// written -- see [`allocate_slice_epochs_unchecked`]'s own doc for the
/// generation-only staleness source this closes. Gated behind
/// [`crate::filesystem_transaction::EXECUTION_ENABLED`], the same gate every
/// mutating entry point in that module already uses — this module defines no
/// gate of its own.
#[allow(clippy::too_many_arguments)]
pub fn allocate_slice_epochs(
    conn: &Connection,
    transaction_id: &str,
    slice: &PlanSlice,
    next_epoch: i64,
    expected_execution_generation: i64,
    directory_identity_for: impl Fn(&PlannedPlacement) -> DirectoryIdentity,
    capability_snapshot: &[u8],
    durability_level: DurabilityLevel,
    now_unix_nanos: i64,
) -> Result<Vec<EpochRecord>, SyncSqliteError> {
    filesystem_transaction::require_execution_enabled()?;
    allocate_slice_epochs_unchecked(
        conn,
        transaction_id,
        slice,
        next_epoch,
        expected_execution_generation,
        directory_identity_for,
        capability_snapshot,
        durability_level,
        now_unix_nanos,
    )
}

/// `pub`, not `pub(crate)`: `orchestrator.rs`/`plan_driver.rs` (both in
/// `yadorilink-sync-core`, since the eighth pass's move) are composed
/// callers that check [`filesystem_transaction::require_execution_enabled`]
/// exactly once at their own entry point, the same discipline every other
/// `_unchecked` seam in this crate exists for — see those functions' own
/// docs. Exposing this core rather than making those callers go through the
/// gated [`allocate_slice_epochs`] (which would re-check the same gate
/// redundantly, and — while the gate is closed — make their own tests
/// unable to exercise real epoch allocation at all) is that same pattern,
/// one module over.
///
/// The whole slice is allocated inside one SQLite transaction: the true
/// next-free epoch number is derived from the epoch journal itself
/// (`MAX(epoch) + 1`, or `0` if the transaction has none), the parent's
/// `epoch_watermark` is bumped once by the slice's full epoch count, and
/// every placement's row is inserted -- then, and only then, committed. This
/// used to be a loop of independent [`crate::filesystem_transaction::
/// insert_epoch_unchecked`] calls, each opening (and committing) its own
/// transaction: a failure partway through a multi-placement slice left
/// whatever prefix had already been inserted durably committed, with the
/// watermark advanced to match only that prefix, while the remaining
/// placements were simply absent -- neither the all-or-nothing slice this
/// module's own doc promises ("Bounded plan slices" is meant to be an
/// atomic unit of progress) nor a state any recovery path anticipated. It
/// also trusted the caller's `next_epoch` outright: two callers that each
/// independently computed "the next free number" from a stale read (no lock
/// held between reading it and calling this function) could both start
/// numbering from the same value and race each other's inserts.
///
/// `next_epoch` is kept as a parameter -- not derived silently in its place
/// and not dropped -- so `crate::plan_driver`'s existing call site (which
/// this module does not own and must not need to change to keep compiling)
/// keeps working unmodified. It is now used as an assertion of the caller's
/// belief rather than as the value actually written: if it disagrees with
/// what this transaction derives as the true next-free number, that belief
/// was already stale by the time this ran, and the whole call is refused
/// with [`SyncSqliteError::TransitionRaced`] before anything is written, rather
/// than silently substituting the correct number (which would let a caller
/// go on believing a slice succeeded at the epoch numbers it asked for when
/// it did not) or silently numbering under the caller's wrong belief (which
/// is the exact collision this fix exists to prevent).
///
/// `expected_execution_generation` closes a second, narrower staleness
/// source the `next_epoch`/`plan_revision` checks above do not cover: a
/// replan bumps `plan_revision` and `execution_generation` together, so
/// [`filesystem_transaction::insert_epoch_row_unchecked`]'s own
/// `plan_revision` guard already catches a slice built against a superseded
/// plan. But `bump_transactions_for_touched_paths` (DAG admission fencing
/// every transaction holding a touched path) bumps only
/// `execution_generation` -- `plan_revision` never moves. A slice built
/// before that bump, with a still-current `plan_revision`, would sail
/// straight past the `plan_revision` guard and go on to allocate epochs
/// under a fence the caller's belief no longer matches. Checked with
/// [`filesystem_transaction::check_execution_generation`] first, inside the
/// same `BEGIN IMMEDIATE` as everything else this function writes, for the
/// same reason [`filesystem_transaction::insert_epoch_unchecked`] checks it
/// first: a stale caller is refused before either the watermark bump or any
/// row insert, not after.
#[allow(clippy::too_many_arguments)]
pub fn allocate_slice_epochs_unchecked(
    conn: &Connection,
    transaction_id: &str,
    slice: &PlanSlice,
    next_epoch: i64,
    expected_execution_generation: i64,
    directory_identity_for: impl Fn(&PlannedPlacement) -> DirectoryIdentity,
    capability_snapshot: &[u8],
    durability_level: DurabilityLevel,
    now_unix_nanos: i64,
) -> Result<Vec<EpochRecord>, SyncSqliteError> {
    let placements: Vec<&PlannedPlacement> = slice.placements().collect();
    if placements.is_empty() {
        return Ok(Vec::new());
    }
    // `BEGIN IMMEDIATE`, not `DEFERRED`: this derives the true next-free
    // epoch number by reading the journal, then writes based on that read,
    // in the same transaction -- see `filesystem_transaction::
    // with_immediate_transaction`'s own doc for why a transaction with that
    // shape must not be `DEFERRED`.
    filesystem_transaction::with_immediate_transaction(conn, |tx| {
        // Checked first, same reasoning as `insert_epoch_unchecked`'s own
        // fence: a stale caller (its belief about the fence captured before
        // some concurrent bump -- e.g. `bump_transactions_for_touched_paths`
        // moving the generation without touching `plan_revision`, the
        // generation-only staleness source `plan_revision`'s own guard
        // inside `insert_epoch_row_unchecked` cannot see) must be refused
        // before either the watermark bump or any row insert below, not
        // after.
        filesystem_transaction::check_execution_generation(
            tx,
            transaction_id,
            expected_execution_generation,
        )?;

        let true_next_epoch: i64 = tx.query_row(
            "SELECT COALESCE(MAX(epoch) + 1, 0) FROM filesystem_transaction_epochs \
             WHERE transaction_id = ?1",
            [transaction_id],
            |r| r.get(0),
        )?;
        if true_next_epoch != next_epoch {
            return Err(SyncSqliteError::TransitionRaced {
                subject: format!("filesystem transaction {transaction_id} epoch allocation"),
                expected_state: format!("next_epoch {next_epoch}"),
                current_state: format!("next_epoch {true_next_epoch}"),
            });
        }

        filesystem_transaction::bump_epoch_watermark_if_not_completed(
            tx,
            transaction_id,
            placements.len() as i64,
        )?;

        let mut out = Vec::with_capacity(placements.len());
        for (epoch, placement) in (next_epoch..).zip(placements.iter().copied()) {
            let identity = directory_identity_for(placement);
            let record = filesystem_transaction::insert_epoch_row_unchecked(
                tx,
                &NewEpoch {
                    transaction_id,
                    epoch,
                    plan_revision: slice.plan_revision,
                    target_path: &placement.path,
                    placement_role: placement.role,
                    target_generation: &placement.target_generation,
                    parent_directory_identity: &identity,
                    capability_snapshot,
                    durability_level,
                },
                now_unix_nanos,
            )?;
            out.push(record);
        }
        Ok(out)
    })
}


/// Returns the subset of `groups` not yet fully, durably placed — reused
/// directly to build the next slice after a replan.
///
/// A placement counts as done when the **latest** epoch this transaction has
/// ever allocated for that exact `target_path` (any `plan_revision`, highest
/// `epoch` number — epoch numbers are a single strictly-increasing,
/// never-reused counter per transaction, see [`allocate_slice_epochs`])
/// reached a [`epoch_reflects_committed_placement`] state *and* names the
/// same `target_generation` bytes the group wants. Matching on "some epoch
/// ever committed this generation at this path" instead — ignoring whether a
/// later epoch at the same path superseded it — would be wrong: a replan can
/// target a different generation at a path it already committed once (the
/// desired content there changed and changed back), and the disk only ever
/// reflects the *last* successful commit for that path, not every commit
/// that ever happened there. The epoch journal is still the PRIMARY source
/// (`materialized_generation` is not queried at all when the latest epoch's
/// own phase already answers the question), because an epoch in physical
/// recovery reads as attempted in the journal while correctly having no
/// generation row -- `execute_short_commit_window_unchecked` writes a
/// generation in the exact same SQLite transaction as the epoch's own
/// `Committed` transition, so an epoch that never reached `Committed` never
/// has one, and the journal alone still has to be the thing that identifies
/// *which* epoch is the latest per path.
///
/// What the epoch journal alone gets wrong: when the *latest* epoch for a
/// path is [`epoch_is_provably_untouched_by_adapter`] (a `Blocked` epoch
/// from a writer that never reached an adapter call), it can hide an
/// EARLIER epoch at the same path that really did reach `Committed` -- e.g.
/// epoch 10 commits generation A, epoch 11 is later allocated for
/// generation B but fails to prepare and is blocked before any adapter
/// call, and the desired state reverts to A. "Latest epoch number" alone
/// would report A as not-yet-placed even though the disk still holds it,
/// and the driver would re-offer it, `NoOpUnsupported`, and cycle until
/// `PlanNeverSettled`.
/// [`plan_progress`] closes this by falling back to
/// `materialized_generation::lookup_materialized_generation` -- ground
/// truth for what the disk currently reflects -- ONLY when
/// [`epoch_is_provably_untouched_by_adapter`] holds for that latest epoch.
/// `Committing` / `RequiresPhysicalRecovery` / `Quarantined`, and a
/// `Blocked` epoch whose `unresolved_block_reason` is set, all leave "did an
/// adapter call already run" genuinely open, NOT merely "not committed" --
/// consulting `materialized_generation` for those would risk reading a
/// STALE disk record and silently reporting a placement done when the disk
/// may have already moved past it. A `PreCommitLeftover` epoch never
/// touched disk and needs no lookup either way; a `CommittedPlacement`
/// epoch already answers on its own.
///
/// "Highest epoch number" is *allocation* order, not commit order, and is
/// only a safe stand-in for commit order because [`replan`] fences work in
/// flight under a superseded plan — see the module doc's "'Latest epoch
/// number' is allocation order, not commit order" section for the exact
/// race that would otherwise be possible and why the fence closes it. That
/// reasoning is unaffected by the `materialized_generation` fallback above:
/// the fallback only ever answers "is this specific ambiguous epoch's own
/// target already durably on disk", never "which epoch is latest".
///
/// Filters at the placement level, not at the group level: a group whose
/// members are only partially done is returned with just its undone
/// placements, not dropped whole (nothing left to do) or returned whole
/// (re-offering an already-materialized placement). Returning it whole was
/// the earlier behaviour, and it was wrong twice over — it handed
/// `orchestrator::run_slice` a placement `optimistic_placement::
/// prepare_target` will find already correct, which is exactly the
/// `OrchestratorError::NoOpUnsupported` case that error's own doc names
/// this function as "the filter that ordinarily prevents this". This is
/// still `PlacementGroup`'s own §11.2 unit for slicing purposes — a
/// filtered-down group's remaining placements stay one group, and
/// [`slice_plan`] still never splits it across two slices. What changes is
/// only which placements a group carries into that slicing decision, not
/// whether the group can be torn across a slice boundary.
pub fn plan_progress(
    conn: &Connection,
    transaction_id: &str,
    groups: &[PlacementGroup],
) -> Result<Vec<PlacementGroup>, SyncSqliteError> {
    let epochs = filesystem_transaction::list_epochs_for_transaction(conn, transaction_id)?;
    let mut latest_by_path: std::collections::HashMap<&str, &EpochRecord> =
        std::collections::HashMap::new();
    for e in &epochs {
        latest_by_path
            .entry(e.target_path.as_str())
            .and_modify(|cur| {
                if e.epoch > cur.epoch {
                    *cur = e;
                }
            })
            .or_insert(e);
    }
    // A path is unsafe for the `materialized_generation` fallback below if
    // ANY epoch this transaction ever allocated for it -- not just the
    // latest -- is neither a confirmed commit nor provably untouched by an
    // adapter call. Checking only the latest epoch is not enough: a later
    // epoch can be safely `Blocked` (never reached the adapter) while an
    // EARLIER epoch at the same path is stuck `Committing`/
    // `RequiresPhysicalRecovery` -- ambiguous about whether it already
    // moved the disk -- and `replan` deliberately never sweeps those two
    // phases (see `replan_unchecked`'s own doc), so that earlier epoch can
    // sit there indefinitely while newer epochs are allocated over it. The
    // fallback's ground truth is only trustworthy when NOTHING at the path
    // could have mutated it since the row was written, which is a
    // path-wide property, not a per-epoch one.
    let mut path_has_unsafe_epoch: std::collections::HashSet<&str> =
        std::collections::HashSet::new();
    for e in &epochs {
        if !epoch_reflects_committed_placement(e.phase)
            && !epoch_is_provably_untouched_by_adapter(
                e.phase,
                e.unresolved_block_reason.as_deref(),
            )
        {
            path_has_unsafe_epoch.insert(e.target_path.as_str());
        }
    }
    // The latest epoch's own phase cannot always answer whether the disk
    // reflects a placement: a non-committed epoch may still hide an EARLIER
    // epoch at the same path that really did commit, and this epoch, being
    // later, hides that earlier `Committed` row from the "latest by epoch
    // number" rule (see the module doc's "materialized_generation fallback"
    // note). `path_materialized_generations` is consulted as the last
    // engine-recorded materialization for the path -- not literally "the
    // disk right now" (an external mutation the engine never observed would
    // still make it stale; that risk is a pre-existing property of this
    // table, not something this fallback newly introduces) -- only when
    // `epoch_is_provably_untouched_by_adapter` holds for the latest epoch
    // AND no other epoch at that path is unsafe -- never as the primary
    // source, and never when an adapter call may already have run under ANY
    // epoch at the path. The epoch journal stays authoritative whenever it
    // can answer on its own, both for the ordinary committed case and for
    // the ordinary not-yet-attempted case
    // (`PreCommitLeftover`, which never touched disk and needs no lookup).
    let group_id = filesystem_transaction::lookup_transaction(conn, transaction_id)?
        .map(|record| record.group_id);
    let is_done = |p: &PlannedPlacement| -> Result<bool, SyncSqliteError> {
        let Some(e) = latest_by_path.get(p.path.as_str()) else {
            return Ok(false);
        };
        if epoch_reflects_committed_placement(e.phase) {
            return Ok(e.target_generation.as_slice() == p.target_generation.as_slice());
        }
        if !epoch_is_provably_untouched_by_adapter(e.phase, e.unresolved_block_reason.as_deref()) {
            return Ok(false);
        }
        if path_has_unsafe_epoch.contains(p.path.as_str()) {
            return Ok(false);
        }
        let Some(group_id) = group_id.as_deref() else {
            return Ok(false);
        };
        let disk_generation = crate::materialized_generation::lookup_materialized_generation(
            conn, group_id, &p.path,
        )?;
        Ok(disk_generation.is_some_and(|g| {
            g.resolved_path_state_hash.as_slice() == p.target_generation.as_slice()
        }))
    };
    let mut result = Vec::with_capacity(groups.len());
    for g in groups {
        let mut remaining: Vec<PlannedPlacement> = Vec::with_capacity(g.placements().len());
        for p in g.placements() {
            if !is_done(p)? {
                remaining.push(p.clone());
            }
        }
        if remaining.is_empty() {
            // Every placement in this group already landed -- the group is
            // fully done, drop it (the pre-existing behaviour for this
            // case).
            continue;
        }
        if remaining.len() == g.placements().len() {
            // Nothing in this group is done yet -- keep it exactly as
            // given, extra_reservations included, rather than rebuilding an
            // identical value.
            result.push(g.clone());
        } else {
            // Some, not all, of this group's placements already landed.
            // Keep it as one group (§11.2: still never split across a
            // slice boundary) but drop the placements that are already
            // materialized, so `orchestrator::run_slice` is never handed
            // one to re-place. `extra_reservations` travel with the group
            // unconditionally: they are bare subtree markers (design §17),
            // not tied to any one placement, so a partially-done group
            // still needs them reserved alongside whatever placements
            // remain.
            result.push(
                PlacementGroup::new(remaining)
                    .expect("remaining is non-empty and every path is already unique -- checked when the original group was built")
                    .with_extra_reservations(g.extra_reservations().to_vec()),
            );
        }
    }
    Ok(result)
}

/// Per-slice staleness check — see the module doc's "What makes a plan
/// stale" section. `Ok(true)` means either of `plan`'s two captured inputs no
/// longer matches current state and the caller must replan (via [`replan`])
/// before committing another slice; `Ok(false)` means the plan is still
/// current enough to proceed.
///
/// Checks two independent things:
///
/// - `current_frontier_hash` (the caller's freshly recomputed
///   `desired_frontier_hash` for exactly this plan's own path scope) against
///   `plan.frontier_hash` — an `O(1)` byte comparison, done here. This
///   catches every desired-state change that moves the frontier, which is
///   the authoritative signal (see below): a remote or local admission that
///   adds a new head for one of the plan's paths always changes this hash,
///   whether or not anything remembered to fence the transaction for it.
///   Producing a fresh value to compare *against* is the expensive part —
///   the same DAG walk `resolve_path_heads`'s caller already does to build a
///   plan in the first place (see e.g. `store_live_heads_for_path`'s
///   ancestry walk) — and this module has no DAG access of its own to do
///   that walk (see the module doc's "reuse, not a second mechanism"
///   section), so it is always supplied, never recomputed here;
/// - `plan.execution_generation` against the transaction's current fence via
///   [`filesystem_transaction::check_execution_generation`] — also `O(1)`,
///   one indexed row read. This is a cheap, coarser signal *when something
///   bumps it*. An earlier version of this doc said nothing at
///   DAG-*admission* time bumps it. That was wrong.
///   `dag_store::bump_execution_fence_for_change` is called on remote
///   admission, on orphan promotion and on local emission, and it calls
///   [`filesystem_transaction::bump_transactions_for_touched_paths`]. The
///   fence IS admission-wired. Its real limit is narrower and still
///   decisive here: that lookup matches only transactions **holding a
///   reservation** on a touched path, and design §6.1 deliberately holds
///   none across preparation — so the fence is blind for exactly that
///   window. [`replan`]
///   itself *does* bump the fence, but only as a fencing consequence after
///   staleness has already been established some other way (see the
///   module doc's "'Latest epoch number' is allocation order, not commit
///   order" section) — it is not a source `plan_is_stale` can observe to
///   *detect* staleness in the first place, since by the time it runs the
///   caller has already decided to replan. So this half of the check catches
///   only what the admission-time fence could reach — a transaction that
///   held a reservation on the touched path when the change was admitted —
///   and never the preparation window. The frontier-hash comparison above is
///   what detects the rest, and must not be dropped in favour of the fence:
///   the fence is transaction-wide (coarser) and reservation-gated, while
///   the hash is scoped to exactly this plan's paths and is blind to
///   nothing. (This tail sentence used to say "until DAG-admission wiring
///   exists" and "even once the admission-time fence is wired up", left over
///   from the same false premise the paragraph above it already corrects.)
pub fn plan_is_stale(
    conn: &Connection,
    transaction_id: &str,
    plan: &FilesystemResolutionPlan,
    current_frontier_hash: [u8; 32],
) -> Result<bool, SyncSqliteError> {
    if current_frontier_hash != plan.frontier_hash {
        return Ok(true);
    }
    match filesystem_transaction::check_execution_generation(
        conn,
        transaction_id,
        plan.execution_generation,
    ) {
        Ok(()) => Ok(false),
        Err(SyncSqliteError::ExecutionGenerationFenced { .. }) => {
            Ok(true)
        }
        Err(other) => Err(other),
    }
}

/// Returns a stale transaction to `Planning`, advances `plan_revision` so
/// the next plan built for it is durably distinguishable from the one it
/// replaces, and bumps `execution_generation` via
/// [`crate::filesystem_transaction::increment_execution_generation`] so any
/// epoch still mid-commit under the plan being replaced is fenced rather
/// than allowed to land after the plan that supersedes it — see the module
/// doc's "Replanning does not lose committed work" section and
/// `a_stalled_epoch_cannot_commit_after_a_replan_supersedes_it` for exactly
/// the race this closes: an epoch that reached `Committing` and paused
/// before this replan captured the *old* generation value as its own
/// expected fence, so once this function bumps the generation, that
/// stalled epoch's eventual `Committing` → `Committed` attempt fails
/// [`crate::filesystem_transaction::check_execution_generation`] instead of
/// silently succeeding after a newer epoch already committed a different
/// generation at the same path. This does not duplicate whichever other
/// caller's admission of a new local DAG change independently bumped the
/// fence already (design §6.3) — bumping twice is harmless, the fence is
/// monotonic and only ever compared for equality against the value an
/// in-flight epoch captured at its own start. Gated, same gate as
/// everything else in this module.
///
/// If the transaction being replanned is `Blocked`, this also settles every
/// epoch it still has that is a *pre-commit* leftover
/// (`PreparedArtifact`/`Allocated` and their siblings, which a mid-slice
/// prepare or commit failure did not itself touch) to `Blocked` -- see
/// [`epoch_is_pre_commit_leftover`] for the exact allow-list and the
/// settling loop's own comment below for why this, not `orchestrator`, is
/// the right place for that, and why it is safe. An epoch whose placement
/// already committed is never swept: that would retire the row linking the
/// commit to the content it displaced, and would make [`plan_progress`]
/// re-offer a placement whose bytes are already on disk.
///
/// The phase transition, the epoch settling above, the generation bump, the
/// plan_revision advance, and (when the caller supplies one)
/// `new_desired_frontier_hash`'s publication all happen inside one SQLite
/// transaction, so a crash (or any error) partway through leaves none of
/// them applied rather than some subset. Before the first three of these
/// existed, the phase transition, generation bump and plan_revision advance
/// were separate autocommit statements:
/// a crash between them could leave a transaction moved to `Planning` with
/// the *old* generation and `plan_revision` still on it, or moved to
/// `Planning` with the generation bumped but `plan_revision` not advanced --
/// either a durable state this module's own invariants (a plan's identity is
/// exactly `plan_revision`/`desired_frontier_hash`/`execution_generation`
/// together) never anticipated a caller observing. `plan_revision`'s advance
/// is additionally a real compare-and-swap against the value read at the top
/// of this same transaction (see [`crate::filesystem_transaction::
/// set_plan_revision_unchecked`]'s own doc) -- so two callers racing this
/// function (never expected in production, since a single transaction's
/// slices commit sequentially, but not otherwise prevented at this layer)
/// cannot both land `record.plan_revision + 1`; the loser's own read is
/// provably stale by the time its write runs, and it is refused rather than
/// silently duplicating the winner's revision number.
/// `new_desired_frontier_hash`: when the caller already knows the frontier
/// that made the transaction's plan stale (§6.1 step 2 names it
/// `desired_frontier_hash`), passing it here publishes it in the SAME
/// transaction as the `plan_revision`/`execution_generation` bump below —
/// see this function's own doc for why a caller that has to call
/// [`crate::filesystem_transaction::set_desired_frontier_hash`] separately,
/// afterwards, leaves a window where a crash can strand a `plan_revision`
/// no durable frontier hash matches. Pass `None` when no fresher value is
/// known yet (for example [`crate::plan_driver`]'s `Blocked`-parent
/// replan, which precedes any frontier read) — the column is simply left at
/// whatever it already named until a later, separate write catches it up.
pub fn replan(
    conn: &Connection,
    transaction_id: &str,
    new_desired_frontier_hash: Option<[u8; 32]>,
    now_unix_nanos: i64,
) -> Result<i64, SyncSqliteError> {
    filesystem_transaction::require_execution_enabled()?;
    replan_unchecked(conn, transaction_id, new_desired_frontier_hash, now_unix_nanos)
}

pub fn replan_unchecked(
    conn: &Connection,
    transaction_id: &str,
    new_desired_frontier_hash: Option<[u8; 32]>,
    now_unix_nanos: i64,
) -> Result<i64, SyncSqliteError> {
    // `BEGIN IMMEDIATE`, not `DEFERRED`: `record` is read here and then
    // written from, in the same transaction -- see
    // `filesystem_transaction::with_immediate_transaction`'s own doc for why
    // a transaction with that shape must not be `DEFERRED`.
    filesystem_transaction::with_immediate_transaction(conn, |tx| {
        let record =
            filesystem_transaction::lookup_transaction(tx, transaction_id)?.ok_or_else(|| {
                SyncSqliteError::NotFound(format!("filesystem transaction {transaction_id}"))
            })?;
        // A `Blocked` parent can carry epochs `orchestrator::run_slice_
        // unchecked` never settled: the one epoch that actually failed to
        // prepare or commit is already `Blocked` (terminal) by the time the
        // parent reached `Blocked` too, but a sibling that prepared
        // successfully before it (`PreparedArtifact`) or was never even
        // attempted (`Allocated`) is left exactly where that loop put it --
        // deliberately, so a prepared artifact stays available to reuse if
        // this very replan asks for the identical target generation again
        // (design §6.1). Neither state is terminal
        // (`EpochState::is_terminal`), and nothing else in this crate ever
        // revisits them once the transaction leaves `Blocked`: the fresh
        // plan this replan is about to allow always allocates brand-new
        // epoch numbers (`allocate_slice_epochs` never reuses one), so an
        // old `PreparedArtifact`/`Allocated` row is never the one a later
        // slice transitions again. Left alone, either would keep the
        // parent-completion invariant in `set_transaction_phase_unchecked`
        // refusing `Completed` forever, exactly like the `Blocked` sibling
        // would if `EpochState::is_terminal` did not already list it.
        //
        // So this is the one place that settles them: every epoch under this
        // transaction that is still a PRE-COMMIT leftover moves to `Blocked`
        // here, the same "permanently retired, redone under a fresh epoch"
        // destination `EpochState::is_terminal`'s own doc already documents
        // for exactly this situation. This does not touch the artefact a
        // `PreparedArtifact` epoch names -- `early_physical_recovery`'s
        // `mark_owned` protects a `Blocked` epoch's `stage_path`
        // unconditionally, the same as it already does for the sibling
        // `block_unpreparable_epoch` blocks directly -- so nothing physical
        // is lost, only the epoch row's own state, which a fresh epoch
        // number was always going to supersede.
        //
        // The membership test is an explicit allow-list
        // (`epoch_is_pre_commit_leftover`), NOT `!is_terminal()`. That
        // negative test was far wider than this paragraph's claim: only
        // `Quarantined`/`Completed`/`Blocked` are terminal, so it also swept
        // `Committed` and every post-commit state after it -- exactly the
        // set `epoch_reflects_committed_placement` calls "this placement
        // already committed". `can_transition_to` permits any non-terminal
        // epoch to reach `Blocked`, so those sweeps succeeded silently, and
        // `Blocked` has no outgoing edge, so the retained obligation that
        // epoch's `displaced_generation_id`/`displaced_identity`/
        // `classification_result` point at could never be captured. Worse,
        // `plan_progress` then stopped reporting that path as done, so the
        // driver replanned and re-committed a placement whose bytes had
        // already landed -- and the second commit's displaced content is the
        // FIRST commit's output, which loses the user's original bytes for
        // good. Both predicates now derive from the one `classify_epoch`
        // match, so the allow-list and the committed-list cannot drift.
        //
        // `Committing` and `RequiresPhysicalRecovery` are excluded for the
        // same reason as each other: whether the placement landed is an open
        // physical question, and design §14.2 still owes such an epoch a
        // real verdict (roll forward or back) that this generic sweep must
        // not preempt by relabelling it `Blocked`. Note this is a real
        // exclusion, not a vacuous one: a `RequiresPhysicalRecovery` epoch
        // CAN sit under a `Blocked` parent, because
        // `early_physical_recovery::block` blocks the parent per epoch and
        // can do so for epoch B in the very same pass that routed epoch A to
        // `RequiresPhysicalRecovery`. (An earlier version of this comment
        // claimed the combination was impossible because
        // `optimistic_placement::execute_short_commit_window_core` never
        // blocks the parent on that outcome -- true of that one function,
        // but not of the recovery pass, and so not a reason to rely on.)
        if record.phase == TransactionPhase::Blocked {
            let epochs = filesystem_transaction::list_epochs_for_transaction(tx, transaction_id)?;
            for epoch in epochs.iter().filter(|e| epoch_is_pre_commit_leftover(e.phase)) {
                filesystem_transaction::transition_epoch_unchecked(
                    tx,
                    transaction_id,
                    epoch.epoch,
                    record.execution_generation,
                    EpochState::Blocked,
                    &filesystem_transaction::EpochUpdate::default(),
                    now_unix_nanos,
                )?;
            }
        }
        if record.phase != TransactionPhase::Planning {
            filesystem_transaction::set_transaction_phase_unchecked(
                tx,
                transaction_id,
                record.execution_generation,
                TransactionPhase::Planning,
                None,
                now_unix_nanos,
            )?;
        }
        // Fence work in flight under the plan being replaced *before*
        // naming the new plan_revision, so nothing still using the old
        // generation as its expected fence can commit under the new plan's
        // identity.
        let new_generation =
            filesystem_transaction::increment_execution_generation_unchecked(tx, transaction_id)?;
        let new_plan_revision = record.plan_revision + 1;
        filesystem_transaction::set_plan_revision_unchecked(
            tx,
            transaction_id,
            record.plan_revision,
            new_plan_revision,
        )?;
        // A2a / 24.10 (D5): fold the frontier-hash publication into this
        // same transaction when the caller already has the value, rather
        // than leaving it to a later, separate autocommit write. Bound
        // against the generation/revision this transaction just wrote, not
        // the ones `record` captured at its top -- the values a concurrent
        // reader would see the instant this transaction commits, so the
        // write can never race against itself.
        if let Some(hash) = new_desired_frontier_hash {
            filesystem_transaction::set_desired_frontier_hash_unchecked(
                tx,
                transaction_id,
                new_generation,
                new_plan_revision,
                hash,
            )?;
        }
        Ok(new_plan_revision)
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use yadorilink_replica_domain::filesystem_placement::{
        NewReservation, PlacementRole, ReservationRole, ReservationScope,
    };
    use yadorilink_replica_engine::conflict::{self, PathResolution};
    use yadorilink_replica_engine::resolution_planning::{
        resolution_to_group, slice_plan, slice_reservation_requests, SliceBounds,
    };
    use crate::filesystem_transaction::{
        EpochUpdate, FilesystemTransactionKind, NewFilesystemTransaction, TransactionCause,
    };
    use yadorilink_root_authority::fs_identity::{PlatformObjectId, VolumeIdentity};

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::dag_store::init_dag_schema(&conn).unwrap();
        crate::materialized_generation::init_materialized_generation_schema(&conn).unwrap();
        filesystem_transaction::init_filesystem_transaction_schema(&conn).unwrap();
        conn
    }

    fn open_file_backed(path: &std::path::Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        crate::dag_store::init_dag_schema(&conn).unwrap();
        crate::materialized_generation::init_materialized_generation_schema(&conn).unwrap();
        filesystem_transaction::init_filesystem_transaction_schema(&conn).unwrap();
        conn
    }

    fn sample_directory_identity() -> DirectoryIdentity {
        DirectoryIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: 1 },
            object_id: PlatformObjectId::Unix { inode: 100 },
            generation_or_usn: Some(5),
            birth_or_creation_time: None,
        }
    }

    fn begin(conn: &Connection) -> String {
        let record = filesystem_transaction::begin_transaction_unchecked(
            conn,
            &NewFilesystemTransaction {
                group_id: "g",
                source_path: "a.txt",
                kind: FilesystemTransactionKind::ObjectResolution,
                cause: TransactionCause::PeerProjection,
                trigger_change_hash: None,
                desired_frontier_hash: [1; 32],
            },
            0,
        )
        .unwrap();
        record.transaction_id
    }

    fn single(path: &str, role: PlacementRole, target: &[u8]) -> PlacementGroup {
        PlacementGroup::new(vec![PlannedPlacement {
            path: path.to_string(),
            role,
            target_generation: target.to_vec(),
        }])
        .unwrap()
    }

    /// Drives one epoch, in one call each, straight through the legal
    /// sequence up to and including `Committed` — the exact state
    /// [`epoch_reflects_committed_placement`] treats as "durably placed".
    fn drive_epoch_to_committed(
        conn: &Connection,
        transaction_id: &str,
        epoch: i64,
        execution_generation: i64,
        start_at: i64,
    ) {
        for (at, state) in (start_at..).zip([
            EpochState::Preparing,
            EpochState::PreparedArtifact,
            EpochState::AwaitingReservation,
            EpochState::Prepared,
            EpochState::Committing,
            EpochState::Committed,
        ]) {
            filesystem_transaction::transition_epoch_unchecked(
                conn,
                transaction_id,
                epoch,
                execution_generation,
                state,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }
    }

    // `desired_frontier_hash`'s and `PathFrontier`'s own unit tests moved
    // with them to `yadorilink-replica-engine::resolution_planning` (7D-9D)
    // -- see that module's own test block.

    // --- resolution_to_group: §11.2 multi-epoch resolver placement ------

    #[test]
    fn resolution_to_group_turns_a_present_resolution_with_a_conflict_copy_into_one_group() {
        let heads = [
            conflict::PathHead {
                change_hash: [1; 32],
                lamport: 5,
                device_id: "b".to_string(),
                content: Some(conflict::PathHeadContent {
                    version_hash: [0xAA; 32],
                    mtime_unix_nanos: 1,
                }),
            },
            conflict::PathHead {
                change_hash: [2; 32],
                lamport: 5,
                device_id: "a".to_string(),
                content: Some(conflict::PathHeadContent {
                    version_hash: [0xBB; 32],
                    mtime_unix_nanos: 2,
                }),
            },
        ];
        let resolution = conflict::resolve_path_heads("f.txt", &heads);
        let (winner, copies) = match &resolution {
            PathResolution::Present { winner, conflict_copies } => (*winner, conflict_copies),
            other => panic!("expected Present, got {other:?}"),
        };
        assert_eq!(copies.len(), 1, "two distinct concurrent contents must produce one copy");

        let head_targets = vec![b"target-0".to_vec(), b"target-1".to_vec()];
        let group = resolution_to_group("f.txt", &resolution, &head_targets, None)
            .unwrap()
            .expect("a Present resolution always plans something");
        assert_eq!(group.placements().len(), 2, "winner + one conflict copy = two placements");
        assert_eq!(group.placements()[0].path, "f.txt");
        assert_eq!(group.placements()[0].role, PlacementRole::CanonicalPath);
        assert_eq!(group.placements()[0].target_generation, head_targets[winner]);
        assert_eq!(group.placements()[1].role, PlacementRole::ConflictCopy);
        assert_eq!(group.placements()[1].path, copies[0].path);
        assert_eq!(group.placements()[1].target_generation, head_targets[copies[0].head]);
    }

    #[test]
    fn resolution_to_group_plans_nothing_for_an_absent_path_with_no_existing_generation() {
        let resolution = PathResolution::Absent;
        let group = resolution_to_group("gone.txt", &resolution, &[], None).unwrap();
        assert!(group.is_none());
    }

    // --- Bounded slices ---------------------------------------------------

    #[test]
    fn slice_plan_bounds_the_number_of_groups_per_slice_without_splitting_any_group() {
        let groups: Vec<PlacementGroup> = (0..10)
            .map(|i| single(&format!("f{i}.txt"), PlacementRole::CanonicalPath, b"g"))
            .collect();
        let bounds = SliceBounds { max_paths_per_slice: 3, ..SliceBounds::default() };
        let slices = slice_plan(0, &groups, &bounds, |_| 0);

        assert_eq!(slices.len(), 4, "10 single-path groups bounded at 3 per slice -> 4 slices");
        for slice in &slices[..3] {
            assert_eq!(slice.path_count(), 3);
        }
        assert_eq!(slices[3].path_count(), 1);
        let total: usize = slices.iter().map(|s| s.path_count()).sum();
        assert_eq!(total, 10, "every group must appear in exactly one slice");
    }

    #[test]
    fn slice_plan_lets_an_oversized_group_become_its_own_slice_rather_than_splitting_it() {
        let big = PlacementGroup::new(vec![
            PlannedPlacement {
                path: "winner.txt".to_string(),
                role: PlacementRole::CanonicalPath,
                target_generation: b"w".to_vec(),
            },
            PlannedPlacement {
                path: "winner (conflicted copy 1).txt".to_string(),
                role: PlacementRole::ConflictCopy,
                target_generation: b"c1".to_vec(),
            },
            PlannedPlacement {
                path: "winner (conflicted copy 2).txt".to_string(),
                role: PlacementRole::ConflictCopy,
                target_generation: b"c2".to_vec(),
            },
        ])
        .unwrap();
        let small_other = single("other.txt", PlacementRole::CanonicalPath, b"o");
        let bounds = SliceBounds { max_paths_per_slice: 2, ..SliceBounds::default() };
        let slices = slice_plan(0, &[big.clone(), small_other.clone()], &bounds, |_| 0);

        // The 3-placement group alone exceeds the bound of 2 but is never
        // torn apart; the unrelated small group gets its own slice. Slice
        // *order* depends on `PlacementGroup::sort_key`, which this test
        // does not care about -- only that no slice ever splits the
        // 3-placement group.
        assert_eq!(slices.len(), 2);
        let path_counts: Vec<usize> = slices.iter().map(|s| s.path_count()).collect();
        assert!(
            path_counts.contains(&3) && path_counts.contains(&1),
            "expected one 3-path slice (the unsplit oversized group) and one 1-path slice, got \
             {path_counts:?}"
        );
    }

    // --- All-or-none across mixed reservation kinds ------------------------

    #[test]
    fn multi_path_acquisition_releases_the_first_path_when_the_second_is_unavailable_across_mixed_kinds(
    ) {
        let mut conn = open();
        let holder_tx = begin(&conn);
        // Another transaction already holds a subtree_exclusive lock on
        // "dir", excluding every exact mutation below it (already-verified
        // behavior of `acquire_reservations` itself; re-derived here as the
        // blocker for this test, not re-tested).
        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: &holder_tx,
                scope: ReservationScope::SubtreeExclusive,
                path: "dir",
                role: ReservationRole::SubtreeRoot,
            }],
            0,
        )
        .unwrap();

        let planning_tx = begin(&conn);
        let group_a = single("a.txt", PlacementRole::CanonicalPath, b"ga");
        let group_b = single("dir/child.txt", PlacementRole::CanonicalPath, b"gb");
        let slice = PlanSlice { plan_revision: 0, groups: vec![group_a, group_b] };
        let requests = slice_reservation_requests("g", &planning_tx, &slice);
        assert_eq!(requests.len(), 2, "one exact request per placement in the slice");

        let result =
            filesystem_transaction::acquire_reservations_unchecked(&mut conn, &requests, 1);
        assert!(
            matches!(result, Err(SyncSqliteError::ReservationConflict { .. })),
            "the second path must conflict with the held subtree_exclusive lock, got {result:?}"
        );

        let held = filesystem_transaction::list_reservations(&conn, &planning_tx).unwrap();
        assert!(
            held.is_empty(),
            "the first (available) path must not be left held after the batch failed: {held:?}"
        );
    }

    // --- Deadlock: batched acquisition never blocks indefinitely ----------

    #[test]
    fn two_transactions_batch_acquiring_the_same_two_paths_in_opposite_order_never_deadlock() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("slices.sqlite3");

        let conn_a = open_file_backed(&db_path);
        conn_a.busy_timeout(Duration::from_secs(5)).unwrap();
        let tx_a = filesystem_transaction::begin_transaction_unchecked(
            &conn_a,
            &NewFilesystemTransaction {
                group_id: "g",
                source_path: "a.txt",
                kind: FilesystemTransactionKind::ObjectResolution,
                cause: TransactionCause::PeerProjection,
                trigger_change_hash: None,
                desired_frontier_hash: [1; 32],
            },
            0,
        )
        .unwrap()
        .transaction_id;

        let conn_b = open_file_backed(&db_path);
        conn_b.busy_timeout(Duration::from_secs(5)).unwrap();
        let tx_b = filesystem_transaction::begin_transaction_unchecked(
            &conn_b,
            &NewFilesystemTransaction {
                group_id: "g",
                source_path: "b.txt",
                kind: FilesystemTransactionKind::ObjectResolution,
                cause: TransactionCause::PeerProjection,
                trigger_change_hash: None,
                desired_frontier_hash: [2; 32],
            },
            1,
        )
        .unwrap()
        .transaction_id;

        // Thread A requests ["a.txt", "b.txt"]; thread B requests the same
        // two paths in the opposite order. Both are single batched
        // `acquire_reservations` calls -- see the module doc's deadlock
        // section for why the input order is irrelevant to the outcome.
        let slice_a = PlanSlice {
            plan_revision: 0,
            groups: vec![
                single("a.txt", PlacementRole::CanonicalPath, b"a"),
                single("b.txt", PlacementRole::CanonicalPath, b"b"),
            ],
        };
        let slice_b = PlanSlice {
            plan_revision: 0,
            groups: vec![
                single("b.txt", PlacementRole::CanonicalPath, b"b2"),
                single("a.txt", PlacementRole::CanonicalPath, b"a2"),
            ],
        };

        let (tx_result, rx_result) = std::sync::mpsc::channel();
        let tx_result_b = tx_result.clone();
        let handle_a = std::thread::spawn(move || {
            let mut conn_a = conn_a;
            let requests = slice_reservation_requests("g", &tx_a, &slice_a);
            let result =
                filesystem_transaction::acquire_reservations_unchecked(&mut conn_a, &requests, 10);
            tx_result.send(("a", result.is_ok())).unwrap();
        });
        let handle_b = std::thread::spawn(move || {
            let mut conn_b = conn_b;
            let requests = slice_reservation_requests("g", &tx_b, &slice_b);
            let result =
                filesystem_transaction::acquire_reservations_unchecked(&mut conn_b, &requests, 11);
            tx_result_b.send(("b", result.is_ok())).unwrap();
        });

        // A hang here (a real deadlock) fails loudly instead of blocking
        // the test suite forever.
        let first = rx_result.recv_timeout(Duration::from_secs(10)).expect(
            "no reservation batch reported a result within 10s -- this is exactly the deadlock \
             this test exists to rule out",
        );
        let second = rx_result.recv_timeout(Duration::from_secs(10)).expect(
            "the second reservation batch never finished -- the first must have held the \
             writer lock without releasing it",
        );
        handle_a.join().unwrap();
        handle_b.join().unwrap();

        // Exactly one of the two batches wins (they contend for the same
        // two exact paths); the other observes a conflict. Both must
        // resolve -- neither may be left permanently blocked.
        let results = [first, second];
        let ok_count = results.iter().filter(|(_, ok)| *ok).count();
        assert_eq!(
            ok_count, 1,
            "exactly one of the two identical-path batches should succeed, got {results:?}"
        );
    }

    // --- Staleness and replanning without losing committed work -----------

    /// D5 / A2a (24.10): `set_desired_frontier_hash` used to be a separate,
    /// later, autocommit write -- so a crash between `replan_unchecked`
    /// bumping `plan_revision` and that later write landing could leave a
    /// durable row naming a `plan_revision` no `desired_frontier_hash`
    /// actually matches. When the caller already has the new frontier hash
    /// (as `plan_driver` does at the point it decides a plan is stale),
    /// `replan_unchecked` now publishes it in the SAME transaction as the
    /// revision it names, so that window cannot open at all for this call.
    #[test]
    fn replan_unchecked_publishes_a_supplied_frontier_hash_in_the_same_transaction_as_the_revision()
    {
        let conn = open();
        let transaction_id = begin(&conn);
        let new_hash = [0x42; 32];

        let new_revision = replan_unchecked(&conn, &transaction_id, Some(new_hash), 5).unwrap();

        let after =
            filesystem_transaction::lookup_transaction(&conn, &transaction_id).unwrap().unwrap();
        assert_eq!(after.plan_revision, new_revision);
        assert_eq!(
            after.desired_frontier_hash, new_hash,
            "the frontier hash for the newly named revision must already be visible the \
             instant replan_unchecked returns, not only after a later, separate write"
        );
    }

    /// The `None` half of the same call: when no fresher hash is known yet
    /// (the `Blocked`-parent replan, before any frontier has been read),
    /// the column is simply left at whatever it already named -- a later,
    /// separate write (the ordinary per-build-attempt one in `plan_driver`)
    /// catches it up once a frontier is actually known.
    #[test]
    fn replan_unchecked_leaves_the_frontier_hash_untouched_when_none_is_supplied() {
        let conn = open();
        let transaction_id = begin(&conn);
        let before =
            filesystem_transaction::lookup_transaction(&conn, &transaction_id).unwrap().unwrap();

        replan_unchecked(&conn, &transaction_id, None, 5).unwrap();

        let after =
            filesystem_transaction::lookup_transaction(&conn, &transaction_id).unwrap().unwrap();
        assert_eq!(after.desired_frontier_hash, before.desired_frontier_hash);
    }

    #[test]
    fn replan_after_a_genuine_desired_state_change_preserves_already_committed_placements() {
        let conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();

        let group_a = single("a.txt", PlacementRole::CanonicalPath, b"ga");
        let group_b = single("b.txt", PlacementRole::CanonicalPath, b"gb");
        let plan_v0 = FilesystemResolutionPlan {
            plan_revision: 0,
            frontier_hash: [9; 32],
            execution_generation: 0,
            groups: vec![group_a.clone(), group_b.clone()],
        };

        // Move the saga into its short commit window and commit group A's
        // placement all the way through, exactly as design §8.2 sequences
        // it (Committing before any epoch transition).
        filesystem_transaction::set_transaction_phase_unchecked(
            &conn,
            &transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: 0, groups: vec![group_a.clone()] },
            0,
            0,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        )
        .unwrap();
        drive_epoch_to_committed(&conn, &transaction_id, 0, 0, 3);

        assert!(
            !plan_is_stale(&conn, &transaction_id, &plan_v0, plan_v0.frontier_hash).unwrap(),
            "nothing has invalidated the plan yet"
        );

        // The genuine desired-state change: some other part of the system
        // (captured writing, per design §6.3) admits a new local DAG change
        // and bumps the fence. This module does not decide when that
        // happens -- it is simulated directly here, exactly as the design
        // describes the trigger.
        let bumped = filesystem_transaction::increment_execution_generation_unchecked(
            &conn,
            &transaction_id,
        )
        .unwrap();
        assert_eq!(bumped, 1);

        assert!(
            plan_is_stale(&conn, &transaction_id, &plan_v0, plan_v0.frontier_hash).unwrap(),
            "a bumped execution_generation must be observed as staleness"
        );

        let new_plan_revision = replan_unchecked(&conn, &transaction_id, None, 20).unwrap();
        assert_eq!(new_plan_revision, 1);
        let after_replan =
            filesystem_transaction::lookup_transaction(&conn, &transaction_id).unwrap().unwrap();
        assert_eq!(after_replan.phase, TransactionPhase::Planning);
        assert_eq!(after_replan.plan_revision, 1);
        // `replan` now bumps the fence itself (on top of the external bump
        // already simulated above) so any epoch still in flight under the
        // plan being replaced is fenced -- see
        // `a_stalled_epoch_cannot_commit_after_a_replan_supersedes_it`.
        assert_eq!(
            after_replan.execution_generation, 2,
            "replan must advance the fence so in-flight work under the superseded plan is fenced"
        );

        // The replanned plan still wants the identical bytes at "a.txt"
        // (its frontier never moved) plus "b.txt" (never attempted). Only
        // "b.txt" should remain -- group A's committed work is not redone.
        let remaining = plan_progress(&conn, &transaction_id, &[group_a, group_b.clone()]).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].placements()[0].path, "b.txt");

        // Finish the remainder under the new plan revision, at the fence
        // value replan just advanced to.
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: new_plan_revision, groups: remaining },
            1,
            2,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            21,
        )
        .unwrap();
        drive_epoch_to_committed(&conn, &transaction_id, 1, 2, 22);

        let fully_done = plan_progress(&conn, &transaction_id, &[group_b]).unwrap();
        assert!(fully_done.is_empty(), "both placements are now committed");
    }

    /// Data-loss regression. `replan_unchecked`'s epoch sweep used to filter
    /// on `!phase.is_terminal()`, but only `Quarantined`/`Completed`/
    /// `Blocked` are terminal -- so it also retired `Committed` and every
    /// post-commit state after it. `can_transition_to` permits any
    /// non-terminal epoch to reach `Blocked`, so the sweep succeeded
    /// silently; `Blocked` has no outgoing edge, so the retained obligation
    /// the row pointed at could never be captured; and, second-order,
    /// `plan_progress` then stopped seeing the path as done, so the driver
    /// replanned and re-committed a placement whose bytes had already
    /// landed. That second commit's displaced content is the FIRST commit's
    /// output, which destroys the user's original bytes.
    ///
    /// The combination is reachable, and automatic: the driver replans on
    /// ANY `Blocked` parent without inspecting the epochs, and a parent can
    /// be `Blocked` while a post-commit epoch is still non-terminal (see
    /// `early_physical_recovery::block`, which blocks the parent for one
    /// unresolvable epoch while siblings sit at `CustodyTransferred` /
    /// `AwaitingCaptureStorage`).
    #[test]
    fn a_committed_epoch_under_a_blocked_parent_survives_a_replan() {
        let conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();

        let group_a = single("a.txt", PlacementRole::CanonicalPath, b"ga");
        let group_b = single("b.txt", PlacementRole::CanonicalPath, b"gb");

        filesystem_transaction::set_transaction_phase_unchecked(
            &conn,
            &transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: 0, groups: vec![group_a.clone(), group_b.clone()] },
            0,
            0,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        )
        .unwrap();
        // Epoch 0 commits its bytes and moves on into the post-commit
        // sequence, where it carries the durable link to whatever it
        // displaced. Epoch 1 is the ordinary pre-commit leftover the sweep
        // genuinely exists for.
        drive_epoch_to_committed(&conn, &transaction_id, 0, 0, 3);
        filesystem_transaction::transition_epoch_unchecked(
            &conn,
            &transaction_id,
            0,
            0,
            EpochState::CustodyTransferred,
            &EpochUpdate::default(),
            10,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            &conn,
            &transaction_id,
            1,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            11,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            &conn,
            &transaction_id,
            1,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate::default(),
            12,
        )
        .unwrap();

        // Something else blocks the parent -- exactly what early physical
        // recovery does when one epoch's location cannot be observed.
        filesystem_transaction::set_transaction_phase_unchecked(
            &conn,
            &transaction_id,
            0,
            TransactionPhase::Blocked,
            Some("simulated: one epoch could not be observed"),
            13,
        )
        .unwrap();

        replan_unchecked(&conn, &transaction_id, None, 14).unwrap();

        let epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        assert_eq!(
            epochs[0].phase,
            EpochState::CustodyTransferred,
            "an epoch whose placement already committed must SURVIVE the replan sweep: retiring \
             it to Blocked strands the obligation for the content it displaced, because Blocked \
             has no outgoing edge: {:?}",
            epochs[0]
        );
        assert_eq!(
            epochs[1].phase,
            EpochState::Blocked,
            "the pre-commit leftover the sweep exists for must still be settled: {:?}",
            epochs[1]
        );

        // The second-order half, which is where the bytes actually go. If
        // the sweep had retired epoch 0, `plan_progress` would offer
        // "a.txt" again and the driver would commit over its own output.
        let remaining = plan_progress(&conn, &transaction_id, &[group_a, group_b]).unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "only the unplaced path may be re-offered after the replan: {remaining:?}"
        );
        assert_eq!(
            remaining[0].placements()[0].path,
            "b.txt",
            "a.txt's bytes are already on disk; re-offering it makes the next commit displace the \
             previous commit's own output"
        );
    }

    /// High-severity regression: `plan_is_stale` used to check only the
    /// execution-generation fence. This doc used to justify that as "in
    /// production nothing ever bumps that fence", which is false — DAG
    /// admission bumps it via `dag_store::bump_execution_fence_for_change`
    /// (see the module doc). The real gap, and what this test covers, is
    /// that the admission-time bump reaches only transactions holding a
    /// reservation on the touched path, and design §6.1 holds none across
    /// preparation: a desired-state change that moves the frontier during
    /// that window bumps nothing and used to sail straight past
    /// `plan_is_stale` undetected. This reproduces exactly that: no
    /// `increment_execution_generation` call anywhere, only a different
    /// `current_frontier_hash` supplied by the caller, as a real caller
    /// would after rerunning `resolve_path_heads` and finding a new head.
    #[test]
    fn plan_is_stale_detects_a_moved_frontier_even_when_the_generation_never_bumps() {
        let conn = open();
        let transaction_id = begin(&conn);
        let plan = FilesystemResolutionPlan {
            plan_revision: 0,
            frontier_hash: [9; 32],
            execution_generation: 0,
            groups: vec![single("a.txt", PlacementRole::CanonicalPath, b"ga")],
        };

        assert!(
            !plan_is_stale(&conn, &transaction_id, &plan, plan.frontier_hash).unwrap(),
            "the frontier the caller just recomputed matches the plan's captured one"
        );

        // Nothing here touches execution_generation -- it is still 0, the
        // exact value plan.execution_generation captured. Only the caller's
        // freshly recomputed frontier hash differs, exactly as it would
        // after a remote or local admission adds a new head for "a.txt".
        let moved_frontier = [10; 32];
        assert!(
            plan_is_stale(&conn, &transaction_id, &plan, moved_frontier).unwrap(),
            "a moved frontier hash must be observed as staleness even though the generation \
             fence never moved"
        );
    }

    // --- plan_progress filters within a group, not just across groups
    // (D4 / 24.10) ---------------------------------------------------------

    /// A group whose members are only partially committed used to be
    /// returned whole -- handing `orchestrator::run_slice` a placement
    /// `optimistic_placement::prepare_target` finds already correct
    /// (`FastPath::NoOp`), which is exactly the
    /// `OrchestratorError::NoOpUnsupported` case that error's own doc names
    /// `plan_progress` as the filter that ordinarily prevents. The group
    /// must survive as one group (§11.2: never split across a slice
    /// boundary) but with the already-materialized placement dropped from
    /// it.
    #[test]
    fn plan_progress_returns_the_undone_placements_of_a_partially_committed_group_not_the_whole_group(
    ) {
        let conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();

        filesystem_transaction::set_transaction_phase_unchecked(
            &conn,
            &transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();

        // One group naming two placements -- the §11.2 shape a winning head
        // plus its conflict copy takes.
        let group = PlacementGroup::new(vec![
            PlannedPlacement {
                path: "a.txt".to_string(),
                role: PlacementRole::CanonicalPath,
                target_generation: b"ga".to_vec(),
            },
            PlannedPlacement {
                path: "a.txt.conflict".to_string(),
                role: PlacementRole::ConflictCopy,
                target_generation: b"gc".to_vec(),
            },
        ])
        .unwrap();

        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: 0, groups: vec![group.clone()] },
            0,
            0,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        )
        .unwrap();
        // Only "a.txt" (epoch 0) commits; "a.txt.conflict" (epoch 1) is left
        // at `Allocated` -- exactly the shape a fenced/superseded sibling in
        // the same slice leaves behind.
        drive_epoch_to_committed(&conn, &transaction_id, 0, 0, 3);

        let remaining = plan_progress(&conn, &transaction_id, &[group]).unwrap();

        assert_eq!(remaining.len(), 1, "the partially-done group must survive as one group");
        assert_eq!(
            remaining[0].placements().iter().map(|p| p.path.as_str()).collect::<Vec<_>>(),
            vec!["a.txt.conflict"],
            "the already-materialized placement must be dropped from the group, not re-offered \
             whole -- re-offering it is exactly the OrchestratorError::NoOpUnsupported case"
        );
    }

    /// High-severity regression: `plan_progress` used to match on *any*
    /// epoch that ever reached `Committed` for `(target_path,
    /// target_generation)`, regardless of whether a later epoch at the same
    /// path superseded it on disk. This drives a path through two committed
    /// generations under two different epochs, then asserts that a replan
    /// wanting the *first* generation again is correctly seen as not done --
    /// the disk holds the second one.
    #[test]
    fn plan_progress_does_not_skip_a_generation_superseded_by_a_later_epoch_at_the_same_path() {
        let conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();

        // Epoch 0 commits "a.txt" -> g1.
        filesystem_transaction::set_transaction_phase_unchecked(
            &conn,
            &transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();
        let group_g1 = single("a.txt", PlacementRole::CanonicalPath, b"g1");
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: 0, groups: vec![group_g1.clone()] },
            0,
            0,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        )
        .unwrap();
        drive_epoch_to_committed(&conn, &transaction_id, 0, 0, 3);

        // A replan retargets "a.txt" -> g2 under a fresh epoch (1), which
        // also commits. The disk now reflects g2, not g1. `replan` bumps
        // the fence to 1, so epoch 1 is allocated and driven at generation
        // 1, not 0.
        let new_plan_revision = replan_unchecked(&conn, &transaction_id, None, 20).unwrap();
        let group_g2 = single("a.txt", PlacementRole::CanonicalPath, b"g2");
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: new_plan_revision, groups: vec![group_g2] },
            1,
            1,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            21,
        )
        .unwrap();
        drive_epoch_to_committed(&conn, &transaction_id, 1, 1, 22);

        // A third replan wants g1 again (desired state reverted). Epoch 0's
        // Committed record for (a.txt, g1) still exists in history, but
        // epoch 1 -- the latest epoch for "a.txt" -- committed g2 instead.
        // g1 must NOT be reported as already done.
        let remaining = plan_progress(&conn, &transaction_id, &[group_g1]).unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "g1 was superseded on disk by epoch 1's g2 commit and must be replanned, not skipped"
        );
    }

    /// High-severity regression for the exact race the module doc's
    /// "'Latest epoch number' is allocation order, not commit order"
    /// section describes: epoch 0 reaches `Committing` for "a.txt" -> g1
    /// and stalls there (never reaches `Committed`); a replan runs while it
    /// is stalled; epoch 1 for the same path commits "a.txt" -> g2 under
    /// the new plan; epoch 0 then resumes and tries to finish committing
    /// g1. Before this fix, `replan` never bumped `execution_generation`,
    /// so epoch 0's stale commit attempt would pass its fence check (the
    /// generation it captured at allocation time still matched) and land
    /// *after* epoch 1 -- exactly the case `plan_progress`'s "pick the
    /// highest epoch number" rule cannot detect on its own, since epoch 0's
    /// number is still lower than epoch 1's. `replan` now bumps the fence,
    /// so epoch 0's resume must be rejected outright: it never becomes
    /// `Committed`, so `plan_progress` is never given a chance to be
    /// fooled by an older epoch committing after a newer one.
    #[test]
    fn a_stalled_epoch_cannot_commit_after_a_replan_supersedes_it() {
        let conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();

        // Epoch 0 begins committing "a.txt" -> g1 but stalls in
        // `Committing`, never reaching `Committed`.
        filesystem_transaction::set_transaction_phase_unchecked(
            &conn,
            &transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();
        let group_g1 = single("a.txt", PlacementRole::CanonicalPath, b"g1");
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: 0, groups: vec![group_g1.clone()] },
            0,
            0,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        )
        .unwrap();
        for (at, state) in (3..).zip([
            EpochState::Preparing,
            EpochState::PreparedArtifact,
            EpochState::AwaitingReservation,
            EpochState::Prepared,
            EpochState::Committing,
        ]) {
            filesystem_transaction::transition_epoch_unchecked(
                &conn,
                &transaction_id,
                0,
                0,
                state,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }

        // A changed frontier is detected and a replan runs while epoch 0 is
        // still stalled in `Committing`.
        let new_plan_revision = replan_unchecked(&conn, &transaction_id, None, 20).unwrap();
        assert_eq!(new_plan_revision, 1);

        // Epoch 1 commits "a.txt" -> g2 under the new plan and the bumped
        // fence (1).
        let group_g2 = single("a.txt", PlacementRole::CanonicalPath, b"g2");
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: new_plan_revision, groups: vec![group_g2] },
            1,
            1,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            21,
        )
        .unwrap();
        drive_epoch_to_committed(&conn, &transaction_id, 1, 1, 22);

        // Epoch 0 now resumes and tries to finish committing g1 -- the
        // stale-commit-after-a-newer-commit race this test exists to rule
        // out. It still carries the execution_generation (0) it captured
        // when it began, and the fence has since moved to 1, so this must
        // be rejected, not silently accepted.
        let result = filesystem_transaction::transition_epoch_unchecked(
            &conn,
            &transaction_id,
            0,
            0,
            EpochState::Committed,
            &EpochUpdate::default(),
            30,
        );
        assert!(
            matches!(result, Err(SyncSqliteError::ExecutionGenerationFenced { .. })),
            "a stalled epoch must not be able to commit after a replan has superseded it, got \
             {result:?}"
        );

        // The epoch journal now correctly shows only epoch 1's g2 commit
        // for "a.txt" -- plan_progress is never given a chance to see
        // epoch 0 land after epoch 1, so its latest-by-epoch-number rule
        // stays sound.
        let remaining = plan_progress(&conn, &transaction_id, &[group_g1]).unwrap();
        assert_eq!(remaining.len(), 1, "g1 never committed and must still be planned");
    }

    /// A later epoch that never touches disk must not hide an earlier
    /// epoch at the same path that really did commit.
    /// Epoch 0 commits "a.txt" -> gA and reaches `Committed` (and, as the
    /// real commit window would, records a `materialized_generation` row
    /// for it). A replan then wants "a.txt" -> gB under a fresh epoch (1),
    /// which is swept to `Blocked` as a pre-commit leftover without ever
    /// reaching `Committing` -- disk still holds gA. The desired state then
    /// reverts to gA. "Latest epoch number" alone picks epoch 1 (`Blocked`,
    /// not `epoch_reflects_committed_placement`) and would report gA as
    /// still needing placement even though the disk already has it --
    /// exactly the `NoOp` -> `NoOpUnsupported` -> `Blocked` cycle the ledger
    /// entry describes. `plan_progress` must consult `materialized_generation`
    /// for this ambiguous latest-epoch case and recognize gA as already done.
    #[test]
    fn an_uncommitted_later_epoch_must_not_mask_an_earlier_committed_one() {
        let conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();
        let group_id = "g";

        let gen_a = crate::materialized_generation::compute_resolved_path_state_hash(
            group_id,
            "a.txt",
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            None,
        );
        let gen_b = crate::materialized_generation::compute_resolved_path_state_hash(
            group_id,
            "a.txt",
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            Some(&yadorilink_replica_domain::ids::VersionHash([7; 32])),
        );

        // Epoch 0 commits "a.txt" -> gen_a and reaches `Committed`, exactly
        // as `execute_short_commit_window_unchecked` would: the epoch
        // transition and the `materialized_generation` row land together.
        let group_a = single("a.txt", PlacementRole::CanonicalPath, &gen_a);
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: 0, groups: vec![group_a.clone()] },
            0,
            0,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        )
        .unwrap();
        drive_epoch_to_committed(&conn, &transaction_id, 0, 0, 3);
        crate::materialized_generation::record_materialized_generation(
            &conn,
            group_id,
            "a.txt",
            &[],
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            None,
            None,
            9,
        )
        .unwrap();

        // A replan wants "a.txt" -> gen_b under a fresh epoch (1). It never
        // gets past `Preparing`/`PreparedArtifact` before something blocks
        // the parent, so the pre-commit-leftover sweep retires it to
        // `Blocked` -- disk is never touched.
        let new_plan_revision = replan_unchecked(&conn, &transaction_id, None, 20).unwrap();
        let group_b = single("a.txt", PlacementRole::CanonicalPath, &gen_b);
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: new_plan_revision, groups: vec![group_b] },
            1,
            1,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            21,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            &conn,
            &transaction_id,
            1,
            1,
            EpochState::Preparing,
            &EpochUpdate::default(),
            22,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            &conn,
            &transaction_id,
            1,
            1,
            EpochState::Blocked,
            &EpochUpdate::default(),
            23,
        )
        .unwrap();

        // Desired state reverts to gen_a. The disk already has it (epoch
        // 0's commit); it must not be re-offered.
        let remaining = plan_progress(&conn, &transaction_id, &[group_a]).unwrap();
        assert!(
            remaining.is_empty(),
            "gen_a is already durably on disk from epoch 0; the later, uncommitted epoch 1 must \
             not mask it and force a needless re-placement: {remaining:?}"
        );
    }

    /// `Committing` must NOT be treated as "provably never touched disk".
    /// Epoch 0 commits "a.txt" -> gen_a (materialized_generation records
    /// gen_a). A replan wants gen_b under epoch 1; epoch 1 reaches
    /// `Committing` -- meaning the adapter may already have run and the
    /// disk may already be gen_b -- and stalls there (e.g. a journaling
    /// failure after a successful filesystem swap: the `Committing` ->
    /// `Committed` transition, and with it the `materialized_generation`
    /// write for gen_b, never lands). Desired
    /// state then reverts to gen_a. `materialized_generation` still reads
    /// gen_a -- coincidentally matching the reverted target -- but that is
    /// stale, not confirming: the epoch journal cannot tell us the disk
    /// didn't move to gen_b and back. Treating epoch 1's `Committing` state
    /// as safe-to-consult-fallback would report gen_a as done and the path
    /// would never be re-offered, even though the disk may actually hold
    /// gen_b -- a silent, permanent divergence, strictly worse than the
    /// pre-fix behaviour (which at least surfaced as a visible
    /// `PlanNeverSettled`).
    #[test]
    fn a_committing_epoch_must_not_consult_the_stale_materialized_generation_fallback() {
        let conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();
        let group_id = "g";

        let gen_a = crate::materialized_generation::compute_resolved_path_state_hash(
            group_id,
            "a.txt",
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            None,
        );
        let gen_b = crate::materialized_generation::compute_resolved_path_state_hash(
            group_id,
            "a.txt",
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            Some(&yadorilink_replica_domain::ids::VersionHash([7; 32])),
        );

        let group_a = single("a.txt", PlacementRole::CanonicalPath, &gen_a);
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: 0, groups: vec![group_a.clone()] },
            0,
            0,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        )
        .unwrap();
        drive_epoch_to_committed(&conn, &transaction_id, 0, 0, 3);
        crate::materialized_generation::record_materialized_generation(
            &conn,
            group_id,
            "a.txt",
            &[],
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            None,
            None,
            9,
        )
        .unwrap();

        // Epoch 1 targets gen_b and stalls in `Committing`: the adapter may
        // have already swapped the disk to gen_b, but the transition that
        // would confirm it (and update materialized_generation) never
        // completes.
        let new_plan_revision = replan_unchecked(&conn, &transaction_id, None, 20).unwrap();
        let group_b = single("a.txt", PlacementRole::CanonicalPath, &gen_b);
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: new_plan_revision, groups: vec![group_b] },
            1,
            1,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            21,
        )
        .unwrap();
        for (at, state) in (22..).zip([
            EpochState::Preparing,
            EpochState::PreparedArtifact,
            EpochState::AwaitingReservation,
            EpochState::Prepared,
            EpochState::Committing,
        ]) {
            filesystem_transaction::transition_epoch_unchecked(
                &conn,
                &transaction_id,
                1,
                1,
                state,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }

        // Desired state reverts to gen_a. materialized_generation still
        // (staleley) reads gen_a, but epoch 1's `Committing` state means the
        // disk's true content is unknown -- it must NOT be reported done.
        let remaining = plan_progress(&conn, &transaction_id, &[group_a]).unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "epoch 1 is Committing -- whether the disk already moved to gen_b is unknown, so \
             gen_a must not be reported done from a stale materialized_generation read: \
             {remaining:?}"
        );
    }

    /// A `Blocked` epoch with `unresolved_block_reason` set (the
    /// `early_physical_recovery::block` writer -- see
    /// `epoch_is_provably_untouched_by_adapter`'s doc) means physical state
    /// could NOT be determined, not that it was determined to be untouched.
    /// Same setup as the `Committing` case above, except epoch 1 is blocked
    /// with a reason instead of stalling in `Committing`: it must not
    /// consult the (possibly stale) `materialized_generation` fallback
    /// either.
    #[test]
    fn a_blocked_epoch_with_an_unresolved_reason_must_not_consult_the_fallback() {
        let conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();
        let group_id = "g";

        let gen_a = crate::materialized_generation::compute_resolved_path_state_hash(
            group_id,
            "a.txt",
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            None,
        );
        let gen_b = crate::materialized_generation::compute_resolved_path_state_hash(
            group_id,
            "a.txt",
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            Some(&yadorilink_replica_domain::ids::VersionHash([7; 32])),
        );

        let group_a = single("a.txt", PlacementRole::CanonicalPath, &gen_a);
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: 0, groups: vec![group_a.clone()] },
            0,
            0,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        )
        .unwrap();
        drive_epoch_to_committed(&conn, &transaction_id, 0, 0, 3);
        crate::materialized_generation::record_materialized_generation(
            &conn,
            group_id,
            "a.txt",
            &[],
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            None,
            None,
            9,
        )
        .unwrap();

        let new_plan_revision = replan_unchecked(&conn, &transaction_id, None, 20).unwrap();
        let group_b = single("a.txt", PlacementRole::CanonicalPath, &gen_b);
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: new_plan_revision, groups: vec![group_b] },
            1,
            1,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            21,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            &conn,
            &transaction_id,
            1,
            1,
            EpochState::Blocked,
            &EpochUpdate {
                unresolved_block_reason: Some(
                    "simulated: early physical recovery could not \
                                                observe the path",
                ),
                ..EpochUpdate::default()
            },
            22,
        )
        .unwrap();

        let remaining = plan_progress(&conn, &transaction_id, &[group_a]).unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "epoch 1's unresolved_block_reason means physical state is genuinely unknown, not \
             proven untouched, so gen_a must not be reported done from a stale \
             materialized_generation read: {remaining:?}"
        );
    }

    /// Checking only the LATEST epoch's phase is not enough: an earlier,
    /// still-ambiguous epoch at the same path can be hidden behind a later,
    /// safely `Blocked` one. Epoch 0 commits "a.txt" -> gen_a
    /// (materialized_generation records gen_a). Epoch 1 targets gen_b and
    /// stalls in `Committing` (adapter may have already moved the disk to
    /// gen_b; `replan` deliberately never sweeps `Committing`, so it stays
    /// there across replans). A second replan allocates epoch 2, which
    /// targets gen_a again (desired state reverted) and fails to prepare --
    /// safely `Blocked`, no reason. Epoch 2 alone would pass
    /// `epoch_is_provably_untouched_by_adapter`, but epoch 1 is still stuck
    /// ambiguous at the SAME path, so the disk's true state is unknown --
    /// the fallback must refuse to answer for this path at all, not just
    /// look at epoch 2.
    #[test]
    fn a_stuck_ambiguous_epoch_must_poison_the_fallback_for_its_whole_path_even_when_a_later_epoch_is_safely_blocked(
    ) {
        let conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();
        let group_id = "g";

        let gen_a = crate::materialized_generation::compute_resolved_path_state_hash(
            group_id,
            "a.txt",
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            None,
        );
        let gen_b = crate::materialized_generation::compute_resolved_path_state_hash(
            group_id,
            "a.txt",
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            Some(&yadorilink_replica_domain::ids::VersionHash([7; 32])),
        );

        let group_a = single("a.txt", PlacementRole::CanonicalPath, &gen_a);
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: 0, groups: vec![group_a.clone()] },
            0,
            0,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        )
        .unwrap();
        drive_epoch_to_committed(&conn, &transaction_id, 0, 0, 3);
        crate::materialized_generation::record_materialized_generation(
            &conn,
            group_id,
            "a.txt",
            &[],
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            None,
            None,
            9,
        )
        .unwrap();

        // Epoch 1 targets gen_b and stalls in `Committing` -- never settles.
        let plan_revision_1 = replan_unchecked(&conn, &transaction_id, None, 20).unwrap();
        let group_b = single("a.txt", PlacementRole::CanonicalPath, &gen_b);
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: plan_revision_1, groups: vec![group_b] },
            1,
            1,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            21,
        )
        .unwrap();
        for (at, state) in (22..).zip([
            EpochState::Preparing,
            EpochState::PreparedArtifact,
            EpochState::AwaitingReservation,
            EpochState::Prepared,
            EpochState::Committing,
        ]) {
            filesystem_transaction::transition_epoch_unchecked(
                &conn,
                &transaction_id,
                1,
                1,
                state,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }

        // A second replan: epoch 1 is `Committing`, not a pre-commit
        // leftover, so it is NOT swept -- it stays stuck. Desired state
        // reverts to gen_a; epoch 2 is allocated for it and fails to
        // prepare (safely `Blocked`, no reason).
        let plan_revision_2 = replan_unchecked(&conn, &transaction_id, None, 30).unwrap();
        allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &PlanSlice { plan_revision: plan_revision_2, groups: vec![group_a.clone()] },
            2,
            2,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            31,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            &conn,
            &transaction_id,
            2,
            2,
            EpochState::Preparing,
            &EpochUpdate::default(),
            32,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            &conn,
            &transaction_id,
            2,
            2,
            EpochState::Blocked,
            &EpochUpdate::default(),
            33,
        )
        .unwrap();

        let remaining = plan_progress(&conn, &transaction_id, &[group_a]).unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "epoch 1 is still stuck Committing at this path -- whether the disk moved to gen_b \
             is unknown -- so the fact that the LATEST epoch (2) is safely Blocked must not be \
             enough to trust the stale materialized_generation row: {remaining:?}"
        );
    }

    /// The defect this closes: `allocate_slice_epochs_unchecked` used to
    /// call `insert_epoch_unchecked` once per placement in a loop, each
    /// opening (and committing) its own independent SQLite transaction, and
    /// trusted the caller's `next_epoch` outright instead of deriving the
    /// true next-free number from the epoch journal. This reproduces both
    /// halves deterministically, without any threading: an epoch already
    /// occupies the number the *second* placement in a two-placement slice
    /// would have received (as if a second caller had raced ahead and
    /// allocated it first), while the caller's `next_epoch` is still `0`
    /// (its now-stale belief that the transaction has no epochs yet).
    ///
    /// Under the old per-placement-transaction loop, the first placement's
    /// insert at epoch 0 would have succeeded and committed on its own
    /// before the second placement's insert at epoch 1 hit the
    /// already-occupied primary key and failed -- leaving epoch 0 durably
    /// present, the watermark bumped once, and the function returning
    /// `Err`: a partially-applied slice. The fix derives the true next-free
    /// epoch number (2, since epoch 1 already exists) inside one shared
    /// transaction *before* inserting anything, finds it disagrees with the
    /// caller's belief (0), and refuses the whole call up front -- so
    /// nothing from either placement is ever written.
    #[test]
    fn a_mid_slice_failure_leaves_no_partial_epochs_and_an_unchanged_watermark() {
        let conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();

        // Simulates another caller having already raced ahead and allocated
        // epoch 1 for this transaction, while this call still believes the
        // next-free number is 0.
        filesystem_transaction::insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &transaction_id,
                epoch: 1,
                plan_revision: 0,
                target_path: "already-there.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"pre-existing",
                parent_directory_identity: &dir_identity,
                capability_snapshot: b"caps",
                durability_level: DurabilityLevel::PowerLossSafe,
            },
            // `begin` starts the transaction at generation 0 and nothing
            // bumps it before this insert.
            0,
            1,
        )
        .unwrap();
        let watermark_before = filesystem_transaction::lookup_transaction(&conn, &transaction_id)
            .unwrap()
            .unwrap()
            .epoch_watermark;
        assert_eq!(watermark_before, 1);

        let slice = PlanSlice {
            plan_revision: 0,
            groups: vec![
                single("a.txt", PlacementRole::CanonicalPath, b"a"),
                single("b.txt", PlacementRole::CanonicalPath, b"b"),
            ],
        };
        let result = allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &slice,
            0, // stale: the true next-free number is 2, not 0
            0,
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        );
        assert!(
            matches!(result, Err(SyncSqliteError::TransitionRaced { .. })),
            "a caller-supplied next_epoch that disagrees with the journal's true next-free \
             number must be refused, got {result:?}"
        );

        let epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        assert_eq!(
            epochs.len(),
            1,
            "only the pre-existing epoch may remain -- neither of the slice's two placements \
             may have been partially inserted: {epochs:?}"
        );
        assert_eq!(epochs[0].target_path, "already-there.txt");
        let watermark_after = filesystem_transaction::lookup_transaction(&conn, &transaction_id)
            .unwrap()
            .unwrap()
            .epoch_watermark;
        assert_eq!(
            watermark_after, watermark_before,
            "a refused batch allocation must not advance the watermark at all"
        );
    }

    /// The generation-only staleness source `allocate_slice_epochs_unchecked`'s
    /// `expected_execution_generation` fence exists to close:
    /// `filesystem_transaction::bump_transactions_for_touched_paths` (DAG
    /// admission fencing every transaction holding a touched path) bumps
    /// only `execution_generation`, never `plan_revision`. Unlike a replan
    /// (which bumps both together, so the `plan_revision` check inside
    /// [`filesystem_transaction::insert_epoch_row_unchecked`] already
    /// catches it), a slice built with a still-current `plan_revision`
    /// sails straight past that guard. This reproduces exactly that: a
    /// reservation held by the transaction, a touched-path bump against it
    /// with nothing touching `plan_revision`, then a slice allocation still
    /// carrying the pre-bump generation belief.
    #[test]
    fn allocate_slice_epochs_refuses_a_generation_only_bump_that_never_touched_plan_revision() {
        let mut conn = open();
        let transaction_id = begin(&conn);
        let dir_identity = sample_directory_identity();

        // Hold a reservation on the path DAG admission is about to report as
        // touched, so `bump_transactions_for_touched_paths_unchecked` finds
        // this transaction as a holder to bump.
        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: &transaction_id,
                scope: ReservationScope::Exact,
                path: "a.txt",
                role: ReservationRole::CanonicalPath,
            }],
            1,
        )
        .unwrap();

        // The generation-only bump itself: DAG admission for a locally (or
        // peer-) admitted change touching "a.txt", with no replan and no
        // `plan_revision` involved at all.
        let bumped = filesystem_transaction::bump_transactions_for_touched_paths_unchecked(
            &conn,
            "g",
            &["a.txt"],
        )
        .unwrap();
        assert_eq!(bumped, vec![transaction_id.clone()]);

        let after_bump =
            filesystem_transaction::lookup_transaction(&conn, &transaction_id).unwrap().unwrap();
        assert_eq!(after_bump.execution_generation, 1, "the touched-path bump must move the fence");
        assert_eq!(
            after_bump.plan_revision, 0,
            "the defining property of this staleness source: plan_revision must NOT have moved"
        );

        // A slice built before the bump still carries the stale belief that
        // the fence is 0.
        let slice = PlanSlice {
            plan_revision: 0,
            groups: vec![single("b.txt", PlacementRole::CanonicalPath, b"b")],
        };
        let result = allocate_slice_epochs_unchecked(
            &conn,
            &transaction_id,
            &slice,
            0,
            0, // stale: the true fence is now 1
            |_| dir_identity,
            b"caps",
            DurabilityLevel::PowerLossSafe,
            2,
        );
        assert!(
            matches!(
                result,
                Err(SyncSqliteError::ExecutionGenerationFenced { expected: 0, current: 1, .. })
            ),
            "a generation-only bump that never touched plan_revision must still fence a stale \
             slice allocation, got {result:?}"
        );

        let epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        assert!(
            epochs.is_empty(),
            "the refused allocation must not have inserted anything: {epochs:?}"
        );
    }

    /// The defect this closes: `replan_unchecked` used to issue its phase
    /// transition, its `execution_generation` bump and its `plan_revision`
    /// advance as three separate autocommit statements. A concurrent change
    /// to the row between any two of them used to be invisible to the
    /// later ones -- each re-read nothing, they simply trusted the values
    /// captured at the very start. Reproduced with two real connections to
    /// the same on-disk database and actual SQLite write-lock blocking, the
    /// same technique `filesystem_transaction`'s own concurrency tests use:
    /// the racer holds the write lock open, uncommitted, moving the
    /// transaction straight to `Completed` (bypassing the API's own
    /// legality checks with raw SQL, exactly as
    /// `a_child_epoch_inserted_during_completion_is_not_silently_completed_
    /// over` does in `filesystem_transaction.rs`) -- a state `replan`'s own
    /// `(Completed, Planning)` edge does not permit. `replan_unchecked` now
    /// runs its whole body inside one `BEGIN IMMEDIATE` transaction
    /// ([`crate::filesystem_transaction::with_immediate_transaction`]), so
    /// the victim blocks on entry, then reads the parent fresh -- already
    /// `Completed` -- once the racer's commit unblocks it, and refuses the
    /// whole call rather than blindly transitioning from the phase it
    /// captured before the race even started. Nothing it attempted (not
    /// even the phase transition, its very first write) may land.
    #[test]
    fn a_replan_racing_a_concurrent_completion_sees_it_and_refuses_rather_than_partially_applying()
    {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("replan-race.sqlite3");

        let victim_conn = open_file_backed(&db_path);
        victim_conn.busy_timeout(Duration::from_secs(5)).unwrap();
        let tx = filesystem_transaction::begin_transaction_unchecked(
            &victim_conn,
            &NewFilesystemTransaction {
                group_id: "g",
                source_path: "a.txt",
                kind: FilesystemTransactionKind::ObjectResolution,
                cause: TransactionCause::PeerProjection,
                trigger_change_hash: None,
                desired_frontier_hash: [1; 32],
            },
            0,
        )
        .unwrap();
        let transaction_id = tx.transaction_id.clone();
        filesystem_transaction::set_transaction_phase_unchecked(
            &victim_conn,
            &transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();
        // A live transaction the victim believes is `Committing` -- a
        // legal source phase for `replan`'s `(Committing, Planning)` edge.

        let racer_conn = open_file_backed(&db_path);
        racer_conn.busy_timeout(Duration::from_secs(5)).unwrap();
        racer_conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        // Raw SQL, not the real API: moves the transaction straight to
        // `Completed` without going through any legality check, mirroring
        // the technique `filesystem_transaction.rs`'s own racer tests use
        // to force a state the API itself would never let a caller reach
        // this way, while the racer holds the write lock open, uncommitted.
        racer_conn
            .execute(
                "UPDATE filesystem_transactions SET phase = 'completed' WHERE transaction_id = ?1",
                [&transaction_id],
            )
            .unwrap();

        let victim_transaction_id = transaction_id.clone();
        let victim = std::thread::spawn(move || {
            replan_unchecked(&victim_conn, &victim_transaction_id, None, 2)
        });

        // Ample margin for the victim's `replan_unchecked` to reach its own
        // `BEGIN IMMEDIATE` and start blocking on the write lock, before the
        // racer commits.
        std::thread::sleep(std::time::Duration::from_millis(200));
        racer_conn.execute_batch("COMMIT").unwrap();
        drop(racer_conn);

        let result = victim.join().unwrap();
        assert!(
            matches!(result, Err(SyncSqliteError::InvalidInput(_))),
            "a replan that only unblocks after the parent has concurrently completed must read \
             that fresh state and refuse the illegal (Completed, Planning) transition, not \
             transition based on the (Committing) phase it captured before the race even \
             started: got {result:?}"
        );

        let final_conn = open_file_backed(&db_path);
        let after = filesystem_transaction::lookup_transaction(&final_conn, &transaction_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            after.phase,
            TransactionPhase::Completed,
            "the racer's completion must be the only change that landed -- the refused replan's \
             phase transition must not have partially applied"
        );
        assert_eq!(
            after.execution_generation, 0,
            "the refused replan's generation bump must not have applied either, even though it \
             would have been the second of its three writes"
        );
        assert_eq!(
            after.plan_revision, 0,
            "the refused replan's plan_revision advance -- its third and final write -- must \
             not have applied: this is the whole point of running all three in one transaction \
             instead of three separate autocommit statements"
        );
    }
}
