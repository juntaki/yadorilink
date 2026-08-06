//! The short filesystem commit window (§6.2).
//!
//! 7D-9D ninth pass: this whole module -- previously `yadorilink-sync-core::
//! optimistic_placement`'s residual "filesystem execution + SQLite SQL / row
//! mapping" entry, `execute_short_commit_window_core` and its claim/publish
//! machinery -- moved here as one mechanical unit, unsplit. It was left
//! pending through the eighth pass on the theory that the claim/commit/
//! publish sequence is "genuinely I/O-interleaved with a SQL transaction by
//! design" and therefore not portable without breaking its own transactional
//! unity. A fresh read this pass found that framing conflated two different
//! things: the function never actually holds one `rusqlite::Transaction`
//! open across the adapter's filesystem call (see `execute_short_commit_
//! window_core`'s own "Defect 1" comment below -- the `Committing`
//! transaction is deliberately committed *before* the adapter runs, exactly
//! to avoid holding SQLite's single writer lock for an unbounded syscall).
//! The real shape is SQL transaction, then real I/O, then a second SQL
//! transaction -- sequential, not nested -- and every type this sequence
//! touches (`filesystem_transaction`, `materialized_generation`,
//! `FilesystemCommitAdapter`, `durable_flush_directory`) was already
//! reachable from this crate (`yadorilink-sync-sqlite` already depends on
//! `yadorilink-filesystem-sync`, since the eighth pass moved preparation
//! there). So this needed no new port and no cross-crate split at all: the
//! whole orchestrating function simply moves to whichever crate already
//! depends on both halves it coordinates, which is here. `SyncError` became
//! [`crate::error::SyncSqliteError`] (already a superset of every variant
//! this module used) at the one crate-boundary seam that changed; nothing
//! else in the function's logic, sequencing, or transaction shape changed.
//!
//! Before that: this module used to also own preparation
//! ([`prepare_target`]/`prepare_target_unchecked`) -- building a verified
//! stage artefact beside its eventual destination directory. That whole
//! phase was real filesystem I/O with no SQL in it (selecting *which* fast
//! path to use was already pure and had moved to
//! `yadorilink-replica-engine::optimistic_placement` in an earlier pass; what
//! remained here was purely I/O execution of that decision) and moved to
//! `yadorilink-filesystem-sync::optimistic_placement` as one mechanical unit
//! (eighth pass). `PreparationCounters` (shared by both the old preparation
//! phase and this module's own [`CommitWindowOutcome`]) and `durable_flush_
//! directory` (still called once below, inside the same SQLite transaction
//! as the commit's own database write) moved with it; this crate already
//! depends on `yadorilink-filesystem-sync`, so both are reachable unchanged.
//! See that module's own doc for preparation's design.
//!
//! What stays here: [`execute_short_commit_window`] takes an
//! already-prepared artefact and an already-open [`ParentDirHandle`],
//! performs the one atomic platform exchange, flushes what durability
//! requires, and publishes the result to SQLite in one transaction. Its
//! signature is the enforcement mechanism for the "no network fetch, no
//! large-file construction, no displaced-content hashing, no quiescence or
//! policy wait, no captured-change authoring inside this window"
//! requirement: [`CommitWindowRequest`] carries only a
//! [`fs_commit::CommitRequest`] (an already-open directory handle, bare
//! artefact names and a pre-probed capability snapshot), a
//! `SqliteConnection`, and the small set of already-known DAG bookkeeping
//! values the publish step writes. This module never imports
//! `yadorilink_local_storage::BlockStore` or a content hasher. None of the
//! *data* parameters can carry a network client, a policy engine or a
//! quiescence signal — for those, the exclusion is a fact about the
//! argument list rather than a promise about what the body does.
//!
//! The commit adapter is the one exception, and it is a real one. The
//! window takes a `&dyn FilesystemCommitAdapter`, and that trait is public
//! and unsealed, so an implementation is free to open a socket, hash the
//! displaced object or wait on a policy inside the window. Sealing it would
//! defeat its stated purpose — the whole point is that other backends
//! supply their own commit primitive. So for the adapter this is a
//! convention its implementors must honour, enforced by review, not by the
//! type system. Do not read the paragraph above as covering it.
//!
//! Gated behind [`filesystem_transaction::EXECUTION_ENABLED`]; its real
//! caller is `orchestrator.rs`, which checks that gate once at its own entry
//! point (the same discipline every `_unchecked` seam in this crate uses).

use std::ffi::OsStr;
#[cfg(test)]
use std::io;
use std::path::Path;
use std::time::Instant;

use rusqlite::Connection;

use crate::error::SyncSqliteError;
use crate::filesystem_transaction::{self, EpochRecord, EpochUpdate, TransactionPhase};
use crate::materialized_generation::{self, DiskGenerationBasis, MaterializedObjectKind};
#[cfg(test)]
use yadorilink_filesystem_sync::fs_commit::ParentDirHandle;
use yadorilink_filesystem_sync::fs_commit::{
    CommitRequest, FilesystemCommitAdapter, FilesystemCommitOutcome, RecoveryObservation,
    RecoverySnapshot, RetryReason,
};
use yadorilink_replica_domain::filesystem_placement::EpochState;
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
#[cfg(test)]
use yadorilink_root_authority::fs_identity::DirectoryIdentity;
#[cfg(test)]
use yadorilink_root_authority::fs_identity::FileIdentity;
use yadorilink_root_authority::fs_identity::IdentityComparison;
use yadorilink_root_authority::reserved_namespace::{self, ArtefactKind};
// Preparation (`prepare_target` and everything it calls -- fast-path
// selection was already pure and moved to `yadorilink-replica-engine`, but
// everything *executing* a chosen fast path is real filesystem I/O) moved to
// `yadorilink-filesystem-sync::optimistic_placement` (7D-9D eighth pass) --
// see that module's own doc comment. `PreparationCounters` moved with it
// (both `PreparedArtifact` and this module's own `CommitWindowOutcome` carry
// one); `durable_flush_directory` moved with it too, and this module's own
// commit window still calls it (once, inside the same SQLite transaction as
// the commit's own database write) via the path below.
use yadorilink_filesystem_sync::optimistic_placement::{
    durable_flush_directory, PreparationCounters,
};

// =====================================================================
// The short commit window (§6.2) — single-path regular files only
// =====================================================================

/// Everything one commit window needs, and — by construction — nothing
/// more. See the module doc for why this shape is what makes the window's
/// exclusions structural rather than merely intended.
pub struct CommitWindowRequest<'a> {
    pub transaction_id: &'a str,
    pub epoch: i64,
    pub expected_execution_generation: i64,
    pub group_id: &'a str,
    pub path: &'a str,
    pub causal_basis: &'a [ChangeHash],
    pub object_kind: MaterializedObjectKind,
    pub version: Option<&'a VersionHash>,
    /// The already-prepared, already-verified platform commit request —
    /// see [`fs_commit::CommitRequest`]. Its own fields are the only
    /// filesystem-shaped input this window accepts: an open directory
    /// handle, bare artefact names, and a pre-probed capability snapshot.
    pub commit: CommitRequest<'a>,
    /// When the caller acquired the reservations this window is about to
    /// release — the window's own duration alone understates "reservation
    /// hold time" (§18.2), which spans from acquisition through release,
    /// most of which happened in the caller's revalidation step before
    /// this function was ever called.
    pub reservation_held_since: Instant,
}

#[derive(Debug)]
pub enum CommitWindowError {
    /// Nothing was mutated — see [`FilesystemCommitOutcome::NotStarted`].
    /// Safe to retry after addressing the reason (if anything can be done
    /// about it).
    NotStarted(RetryReason),
    /// The filesystem's state at `path` is not known to match what the
    /// database says. Either the platform's commit primitive could not
    /// confirm a clean outcome (see
    /// [`FilesystemCommitOutcome::RequiresRecovery`]), or the mutation
    /// succeeded and this window then failed to journal it (see
    /// `unjournaled_physical_outcome`). Left un-released intentionally:
    /// reservations stay held until a later recovery phase reconciles what
    /// actually happened, rather than this window guessing.
    RequiresRecovery(Box<RecoverySnapshot>),
    /// A refusal raised before `adapter.commit_placement` was reached, so
    /// the filesystem is provably untouched and the epoch is left in a
    /// state that says so (`Prepared`, or whatever it held before this
    /// window claimed it). Every post-mutation failure is reported as
    /// [`CommitWindowError::RequiresRecovery`] instead, so a caller may
    /// treat this variant as "nothing happened on disk".
    Sync(SyncSqliteError),
}

impl std::fmt::Display for CommitWindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitWindowError::NotStarted(reason) => write!(f, "commit did not start: {reason:?}"),
            CommitWindowError::RequiresRecovery(_) => {
                write!(f, "commit outcome requires physical recovery")
            }
            CommitWindowError::Sync(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CommitWindowError {}

#[derive(Debug)]
pub struct CommitWindowOutcome {
    pub epoch: EpochRecord,
    pub generation: DiskGenerationBasis,
    pub counters: PreparationCounters,
}

/// Executes §6.2's short commit window for a single-path regular-file
/// replacement: reserve/lock/revalidate are the caller's job (already done
/// by the time this is called — this function does not itself acquire or
/// check reservations, it only releases them on success); from here it
/// records `Committing`, performs the one platform placement, flushes what
/// durability requires, and publishes the result in one SQLite transaction,
/// releasing reservations immediately after.
///
/// See the module doc for why the exclusions this window promises (no
/// fetch, no large-file construction, no displaced-content hashing, no
/// quiescence/policy wait, no captured-change authoring) are structural:
/// this function's own body never imports a block store, a hasher, a
/// network client or a policy/quiescence signal, and
/// [`CommitWindowRequest`] gives it no parameter through which to reach any
/// of them.
pub fn execute_short_commit_window(
    conn: &mut Connection,
    adapter: &dyn FilesystemCommitAdapter,
    request: &CommitWindowRequest,
    now_unix_nanos: i64,
) -> Result<CommitWindowOutcome, CommitWindowError> {
    filesystem_transaction::require_execution_enabled()
        .map_err(|e| CommitWindowError::Sync(SyncSqliteError::from(e)))?;
    execute_short_commit_window_unchecked(conn, adapter, request, now_unix_nanos)
}

pub(crate) fn execute_short_commit_window_unchecked(
    conn: &mut Connection,
    adapter: &dyn FilesystemCommitAdapter,
    request: &CommitWindowRequest,
    now_unix_nanos: i64,
) -> Result<CommitWindowOutcome, CommitWindowError> {
    execute_short_commit_window_core(conn, adapter, request, now_unix_nanos, true)
}

/// Gated entry point for a multi-path slice orchestrator (`orchestrator.rs`,
/// Phase 12): identical to [`execute_short_commit_window`] except a
/// `Committed` outcome does **not** release `request.transaction_id`'s
/// reservations. See [`execute_short_commit_window_unchecked_keeping_reservations`]
/// for why this exists — `release_reservations_unchecked` deletes every
/// reservation the transaction holds, not only `request.path`'s, so calling
/// the ordinary window for the first of several paths acquired together by
/// one `acquire_reservations` call would drop the others' reservations
/// before their own commit windows ever run.
pub fn execute_short_commit_window_keeping_reservations(
    conn: &mut Connection,
    adapter: &dyn FilesystemCommitAdapter,
    request: &CommitWindowRequest,
    now_unix_nanos: i64,
) -> Result<CommitWindowOutcome, CommitWindowError> {
    filesystem_transaction::require_execution_enabled()
        .map_err(|e| CommitWindowError::Sync(SyncSqliteError::from(e)))?;
    execute_short_commit_window_unchecked_keeping_reservations(
        conn,
        adapter,
        request,
        now_unix_nanos,
    )
}

/// The ungated core of [`execute_short_commit_window_keeping_reservations`].
/// A caller using this seam owns releasing `request.transaction_id`'s
/// reservations itself, exactly once, after every placement in its slice has
/// been driven through its own commit window — see
/// [`crate::filesystem_transaction::release_reservations`].
///
/// `pub`, not `pub(crate)`: 7D-9D ninth pass moved this module out of
/// `yadorilink-sync-core`, but its one real caller (`orchestrator.rs`'s
/// multi-path slice orchestrator) stayed there, so this seam is now reached
/// cross-crate. `orchestrator.rs` still owns checking `EXECUTION_ENABLED`
/// once at its own entry point before reaching this ungated core, the same
/// discipline this crate's other `_unchecked` seams already require of their
/// own callers.
pub fn execute_short_commit_window_unchecked_keeping_reservations(
    conn: &mut Connection,
    adapter: &dyn FilesystemCommitAdapter,
    request: &CommitWindowRequest,
    now_unix_nanos: i64,
) -> Result<CommitWindowOutcome, CommitWindowError> {
    execute_short_commit_window_core(conn, adapter, request, now_unix_nanos, false)
}

/// Shared core [`execute_short_commit_window_unchecked`] and
/// [`execute_short_commit_window_unchecked_keeping_reservations`] both
/// delegate to — identical in every respect except whether a `Committed`
/// outcome releases `request.transaction_id`'s reservations
/// (`release_on_commit`). Every other outcome (`NotStarted`,
/// `RequiresRecovery`) already leaves reservations untouched regardless —
/// see their own branches below for why — so `release_on_commit` only ever
/// changes the `Committed` branch's behaviour.
fn execute_short_commit_window_core(
    conn: &mut Connection,
    adapter: &dyn FilesystemCommitAdapter,
    request: &CommitWindowRequest,
    now_unix_nanos: i64,
    release_on_commit: bool,
) -> Result<CommitWindowOutcome, CommitWindowError> {
    {
        let tx =
            conn.transaction().map_err(|e| CommitWindowError::Sync(SyncSqliteError::Sqlite(e)))?;

        // The bookkeeping this window is about to publish must actually
        // describe the object the adapter is about to mutate, not merely
        // something with the same transaction id/epoch number.
        //
        // Checked inside the same SQL transaction that records
        // `Committing`, and *before* that transition, so a mismatch rolls
        // the whole thing back rather than leaving the epoch durably at
        // `Committing`. That ordering is load-bearing, not cosmetic:
        // durable state alone cannot say whether `adapter.commit_placement`
        // ran, so `early_physical_recovery` routes a `Committing` epoch to
        // `RequiresPhysicalRecovery` unconditionally. A request that never
        // reached the adapter at all must therefore not leave `Committing`
        // behind, or an ordinary caller-side mismatch is converted into
        // "physical state unknown" -- an ambiguity nothing in this phase
        // can subsequently resolve.
        //
        // Nothing is given up by checking here rather than after the
        // transition: every field this guard compares is written at or
        // before `Prepared` and left untouched by the
        // `EpochUpdate::default()` transition below, and the comparison is
        // a pure function of the request and that row -- unlike the
        // pre-mutation fence re-check further down, it is not
        // race-sensitive and gains nothing from running later.
        let prepared_epoch =
            filesystem_transaction::lookup_epoch(&tx, request.transaction_id, request.epoch)
                .map_err(|e| CommitWindowError::Sync(SyncSqliteError::from(e)))?
                .ok_or_else(|| {
                    CommitWindowError::Sync(SyncSqliteError::NotFound(format!(
                        "epoch {}/{}",
                        request.transaction_id, request.epoch
                    )))
                })?;
        require_commit_matches_epoch(request, &prepared_epoch)?;

        filesystem_transaction::transition_epoch_unchecked(
            &tx,
            request.transaction_id,
            request.epoch,
            request.expected_execution_generation,
            EpochState::Committing,
            &EpochUpdate::default(),
            now_unix_nanos,
        )
        .map_err(|e| CommitWindowError::Sync(SyncSqliteError::from(e)))?;
        tx.commit().map_err(|e| CommitWindowError::Sync(SyncSqliteError::Sqlite(e)))?;
    }

    #[cfg(test)]
    fire_pre_mutation_fence_recheck_hook_for_test();

    // Defect 1: `transition_epoch_unchecked` above already checked the
    // execution-generation fence, but that check's protection ended the
    // moment its SQL transaction committed and released the row lock —
    // there is no guarantee the adapter call below runs immediately after,
    // and nothing between here and there re-observes the fence. Per
    // `check_execution_generation`'s own doc, the fence must be checked
    // "the moment immediately before every filesystem commit", not only at
    // each bookkeeping transition, so it is re-checked here, right before
    // the one filesystem mutation this window makes.
    //
    // This check deliberately runs outside any SQL transaction. Folding it
    // into one (i.e. holding the write transaction that set `Committing`
    // open across the adapter call, instead of committing it first) would
    // close the remaining gap completely, but at the cost of holding
    // sqlite's single writer lock for however long the platform's
    // exchange/rename syscall takes — on a slow or wedged volume that is
    // unbounded, and it would stall every other in-flight commit on this
    // connection (a real latency and starvation hazard for unrelated
    // groups/paths, not merely a theoretical one) rather than the narrow,
    // bounded TOCTOU window a plain re-check leaves. That residual window
    // — between this check returning and the adapter's syscall actually
    // landing — is not eliminated by this fix; closing it fully needs an
    // atomic check-and-mutate primitive this module does not have. What
    // this fix does close is the much larger, unbounded gap that existed
    // between the `Committing` transaction's commit and whenever the
    // adapter call happened to actually run.
    //
    // A rejection here proves the plan's execution generation is stale.
    // Returning the epoch to `Prepared` would make the same stale plan
    // retryable forever, because its expected generation can never become
    // current again. Block the epoch and parent transaction instead; a
    // fresh planner must produce a new execution generation.
    if let Err(fence_error) = filesystem_transaction::check_execution_generation(
        conn,
        request.transaction_id,
        request.expected_execution_generation,
    ) {
        block_fenced_epoch(conn, request, now_unix_nanos);
        return Err(CommitWindowError::Sync(SyncSqliteError::from(fence_error)));
    }

    // The one mutating filesystem call this window makes.
    let outcome = adapter.commit_placement(&request.commit);

    match outcome {
        FilesystemCommitOutcome::NotStarted(reason) => {
            // Defect (wiring gap): the `(Committing, Prepared)` retreat the
            // epoch state machine added for a proven no-op adapter outcome
            // had no call site -- this returned immediately, leaving the
            // epoch stuck at `Committing` with nothing recorded, which is
            // exactly the "outcome unknown, route through physical
            // recovery" case that edge exists to avoid for a genuinely
            // known-safe no-op. See `is_notstarted_reason_retryable`'s doc
            // for the retryable/non-retryable classification.
            let tx = conn
                .transaction()
                .map_err(|e| CommitWindowError::Sync(SyncSqliteError::Sqlite(e)))?;
            if is_notstarted_reason_retryable(&reason) {
                filesystem_transaction::transition_epoch_unchecked(
                    &tx,
                    request.transaction_id,
                    request.epoch,
                    request.expected_execution_generation,
                    EpochState::Prepared,
                    &EpochUpdate::default(),
                    now_unix_nanos,
                )
                .map_err(|e| CommitWindowError::Sync(SyncSqliteError::from(e)))?;
            } else {
                // Retrying the identical plan would just fail again --
                // take the pre-existing `(Committing, Blocked)` edge
                // instead, and record why on the parent saga (the epoch
                // table has no `blocked_reason` column of its own; see
                // `EpochState::can_transition_to`'s doc).
                filesystem_transaction::transition_epoch_unchecked(
                    &tx,
                    request.transaction_id,
                    request.epoch,
                    request.expected_execution_generation,
                    EpochState::Blocked,
                    &EpochUpdate::default(),
                    now_unix_nanos,
                )
                .map_err(|e| CommitWindowError::Sync(SyncSqliteError::from(e)))?;
                filesystem_transaction::set_transaction_phase_unchecked(
                    &tx,
                    request.transaction_id,
                    request.expected_execution_generation,
                    TransactionPhase::Blocked,
                    Some(&format!("commit not started: {reason:?}")),
                    now_unix_nanos,
                )
                .map_err(|e| CommitWindowError::Sync(SyncSqliteError::from(e)))?;
            }
            tx.commit().map_err(|e| CommitWindowError::Sync(SyncSqliteError::Sqlite(e)))?;
            Err(CommitWindowError::NotStarted(reason))
        }
        FilesystemCommitOutcome::RequiresRecovery(snapshot) => {
            // The adapter has already reported a physically ambiguous outcome.
            // Persisting that state is best-effort metadata refinement only:
            // a DB begin/write/commit failure must never downgrade the caller's
            // result to ordinary `Sync`, which would erase the one fact that
            // determines whether reservations may be released safely.
            let mut record = || -> Result<(), SyncSqliteError> {
                let tx = conn.transaction()?;
                let generation = current_execution_generation(&tx, request.transaction_id)?;
                filesystem_transaction::transition_epoch_unchecked(
                    &tx,
                    request.transaction_id,
                    request.epoch,
                    generation,
                    EpochState::RequiresPhysicalRecovery,
                    &EpochUpdate::default(),
                    now_unix_nanos,
                )?;
                tx.commit()?;
                Ok(())
            };
            let _ = record();
            Err(CommitWindowError::RequiresRecovery(snapshot))
        }
        FilesystemCommitOutcome::Committed(snapshot) => {
            let mut counters = PreparationCounters::default();
            let flush_start = Instant::now();
            let flush_result = if request.commit.capabilities.durable_directory_flush.is_supported()
            {
                durable_flush_directory(request.commit.parent_dir.path())
            } else {
                Ok(())
            };
            counters.flush_time_nanos = flush_start.elapsed().as_nanos() as u64;

            // A required durable-directory-flush failure must not be
            // swallowed. Symmetric with `finish_staged_file`'s handling
            // of the identical call during preparation, which propagates
            // the error instead of discarding it: publishing `Committed`
            // and a fresh materialized generation after a flush this
            // volume was supposed to guarantee actually failed would let a
            // power loss revert the rename while SQLite still says
            // `Committed`. Routed through physical recovery instead, the
            // same outcome an uncertain platform-level commit gets.
            if let Err(flush_err) = flush_result {
                let _ = flush_err;
                return Err(unjournaled_physical_outcome(
                    conn,
                    adapter,
                    request,
                    &snapshot,
                    now_unix_nanos,
                ));
            }

            // Everything from here on runs *after* the filesystem has
            // already been mutated, so none of it may surface as an
            // ordinary error: see `unjournaled_physical_outcome`'s doc for
            // why every failure below has to reach the caller as
            // `RequiresRecovery` instead. Grouped into one block so there
            // is a single place that can fail and a single conversion, and
            // so a failure part-way through rolls the rest back rather than
            // leaving a half-written journal.
            let journaled: Result<(EpochRecord, DiskGenerationBasis), SyncSqliteError> = (|| {
                let tx = conn.transaction()?;
                let epoch = filesystem_transaction::transition_epoch_unchecked(
                    &tx,
                    request.transaction_id,
                    request.epoch,
                    request.expected_execution_generation,
                    EpochState::Committed,
                    &EpochUpdate {
                        staged_identity: Some(&snapshot.live_identity),
                        displaced_identity: snapshot.preimage_identity.as_ref(),
                        ..Default::default()
                    },
                    now_unix_nanos,
                )?;
                // `snapshot.live_identity` is the adapter's proof of what now
                // exists at `live_name` -- meaningful for every present
                // `MaterializedObjectKind`, but not for `Absent`. A `Committed`
                // outcome through this window today always means "something was
                // exchanged in" (`fs_commit::CommittedSnapshot::live_identity` is
                // a required field, not optional), so no real caller drives this
                // branch with `object_kind: Absent` yet. Still, `object_kind`
                // comes from the caller's `request`, not from `snapshot`, and
                // nothing upstream ties the two together -- so this match keeps
                // the write honest against `materialized_generation`'s own
                // invariant ("an absent generation ... `filesystem_identity` is
                // `None`", see that module's doc) rather than relying on no
                // caller ever mismatching them.
                let filesystem_identity = match request.object_kind {
                    MaterializedObjectKind::Absent => None,
                    MaterializedObjectKind::RegularFile
                    | MaterializedObjectKind::Directory
                    | MaterializedObjectKind::Symlink => Some(&snapshot.live_identity),
                };
                let generation = materialized_generation::record_materialized_generation(
                    &tx,
                    request.group_id,
                    request.path,
                    request.causal_basis,
                    request.object_kind,
                    request.version,
                    filesystem_identity,
                    now_unix_nanos,
                )?;
                if release_on_commit {
                    filesystem_transaction::release_reservations_unchecked(
                        &tx,
                        request.transaction_id,
                    )?;
                }
                tx.commit()?;
                Ok((epoch, generation))
            })(
            );

            let (epoch, generation) = match journaled {
                Ok(journaled) => journaled,
                Err(journal_err) => {
                    let _ = journal_err;
                    return Err(unjournaled_physical_outcome(
                        conn,
                        adapter,
                        request,
                        &snapshot,
                        now_unix_nanos,
                    ));
                }
            };

            counters.reservation_hold_time_nanos =
                request.reservation_held_since.elapsed().as_nanos() as u64;
            Ok(CommitWindowOutcome { epoch, generation, counters })
        }
    }
}

/// Defect 3's guard: refuses a [`CommitWindowRequest`] whose independent
/// `group_id`/`path`/`object_kind`/`version`/`commit` fields disagree with
/// the epoch row `request.transaction_id`/`request.epoch` actually named —
/// nothing upstream of this call otherwise ties them together, so a caller
/// bug (or a stale/mismatched request) could publish a generation for one
/// path while mutating a different one on disk. See this module's part of
/// the independent review for the exact harm shape.
///
/// The checks below fall into two groups:
///
/// - `target_path` / `live_name` / `target_generation` / the parent
///   directory's identity: which canonical path and generation this commit
///   is allowed to publish. Present since this guard was first added.
/// - `commit.stage_name` / `commit.expected_stage_identity` /
///   `commit.backup_name`: which staged artefact this commit is allowed to
///   *read from* and exchange in. Added for the independent review's
///   follow-up: the first group alone lets a caller name the right
///   destination while still pointing at someone else's staged object —
///   the adapter's own identity check only compares the freshly observed
///   stage against whatever `expected_stage_identity` the *caller* passed,
///   so a caller that passes a consistent-but-wrong `(stage_name,
///   expected_stage_identity)` pair for a different object sails through
///   that check too. Binding both to what this epoch's own preparation
///   step actually recorded (`epoch.stage_path` / `epoch.staged_identity`,
///   written at `PreparedArtifact`/`Prepared` respectively — see
///   `filesystem_transaction`'s epoch doc) closes that: the caller no
///   longer gets to assert what was staged, only to prove it matches what
///   this epoch already recorded.
///
/// `commit.backup_name` is bound differently, on purpose: this phase has no
/// producer anywhere that records an expected backup path on the epoch
/// itself (`EpochRecord::backup_path` is never written before `Committing`
/// — grep the crate), so there is no independently-recorded value to check
/// it against yet. Instead it is bound to the same artefact id
/// `epoch.stage_path` already proved belongs to this epoch: the expected
/// backup name is derived as `(ArtefactKind::Backup, id)` from the id
/// parsed out of the (already-verified) stage name, via the same
/// `reserved_namespace` naming protocol that minted the stage name in the
/// first place. A caller can therefore no longer point `backup_name` at an
/// unrelated artefact, even though nothing upstream tracks a `backup_path`
/// of its own yet.
///
/// Two more `commit`/`CommitWindowRequest` fields are deliberately left
/// unbound here, and neither reopens the object-substitution harm this
/// guard exists to close, since neither identifies *which staged object*
/// gets committed:
///
/// - `commit.capabilities`: `epoch.capability_snapshot` is opaque bytes
///   with no decoder anywhere in this phase (see this module's own doc and
///   `filesystem_transaction`'s "What this phase does not model" section)
///   — there is no producer of a canonical encoding to compare
///   `capabilities` against yet, and inventing one here would mean
///   guessing a wire shape with nothing to validate it against, the exact
///   trap that section already calls out. It describes the volume, not the
///   object being committed.
/// - `request.causal_basis`: `EpochRecord` has no causal-basis column at
///   all in this phase — there is nothing recorded to check it against.
///   It flows only into `record_materialized_generation`'s lineage
///   bookkeeping on the `Committed` path, a metadata-correctness concern
///   distinct from which physical object gets exchanged onto disk.
fn require_commit_matches_epoch(
    request: &CommitWindowRequest,
    epoch: &EpochRecord,
) -> Result<(), CommitWindowError> {
    if request.path != epoch.target_path {
        return Err(commit_mismatch(format!(
            "commit window request's path {:?} does not match epoch {}/{}'s target_path {:?}",
            request.path, request.transaction_id, request.epoch, epoch.target_path
        )));
    }
    let expected_final_component = Path::new(epoch.target_path.as_str()).file_name();
    if Some(request.commit.live_name) != expected_final_component {
        return Err(commit_mismatch(format!(
            "commit window request's commit.live_name {:?} does not match epoch {}/{}'s \
             target_path {:?} (final path component {:?})",
            request.commit.live_name,
            request.transaction_id,
            request.epoch,
            epoch.target_path,
            expected_final_component,
        )));
    }
    let expected_generation = materialized_generation::compute_resolved_path_state_hash(
        request.group_id,
        request.path,
        request.object_kind,
        request.version,
    );
    if expected_generation.as_slice() != epoch.target_generation.as_slice() {
        return Err(commit_mismatch(format!(
            "commit window request's (object_kind, version) for {:?} does not resolve to epoch \
             {}/{}'s recorded target_generation",
            request.path, request.transaction_id, request.epoch
        )));
    }
    // Through the held handle, not a fresh path resolution -- `commit`'s
    // own `parent_dir` is already open for the mutation this window is
    // about to make, so observing through it (`ParentDirHandle::identity`)
    // rather than re-resolving `path()` closes the same re-resolution
    // window `early_physical_recovery`'s parent verification closes the
    // same way.
    let observed_parent_identity = request
        .commit
        .parent_dir
        .identity()
        .map_err(|e| CommitWindowError::Sync(SyncSqliteError::Io(e)))?;
    // Only a proven-same directory is accepted. An `Ambiguous` verdict --
    // which on Windows means the object id could not be shown unique, or
    // (now that `DirectoryIdentity` carries a birth time too) a coarse
    // clock with no generation counter that cannot rule out reuse -- fails
    // exactly like a mismatch: this binding exists so the mutation lands
    // in the directory the epoch recorded, and "probably that one" does
    // not establish it. Granularity is measured here, on this same
    // directory, rather than accepted from the caller -- see `fs_commit`'s
    // `check_stage_identity_matches_expected` call sites for the identical
    // reasoning applied to the stage-identity check.
    //
    // Capability-split migration note: AMBIGUOUS on two independent axes.
    // (1) `epoch.parent_directory_identity` is read back from the database,
    // so this comparison spans a restart the same way `stage_identity_
    // verdict` below does. (2) This compares a DIRECTORY, and all three
    // split capability names (`stable_source_identity`, `stable_owned_
    // marker_identity`, `durable_claim_store`) are phrased about files —
    // per D1a/V-D1c a directory has no marker tier (a directory cannot be
    // hard-linked) and needs its own answer, not an assumption that the
    // file case generalises. This is one of the two call sites in this
    // crate that compares a directory (the other is `early_physical_
    // recovery::compare_directory_identity`); together they are the
    // largest single group of overlayfs-affected call sites. Conservative
    // treatment: neither new field is claimed to cover this; it is left
    // exactly as before (`FileIdentity`/`DirectoryIdentity::compare`,
    // unconsulted by any capability field), with the gap recorded here
    // rather than silently assumed away.
    let parent_verdict = observed_parent_identity.compare(
        &epoch.parent_directory_identity,
        yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(
            request.commit.parent_dir.path(),
        ),
    );
    if !matches!(parent_verdict, IdentityComparison::SameObject) {
        return Err(commit_mismatch(format!(
            "commit window request's parent directory does not match epoch {}/{}'s recorded \
             parent_directory_identity ({parent_verdict:?})",
            request.transaction_id, request.epoch
        )));
    }

    // Bind the STAGE to the epoch, not only the destination -- see this
    // function's doc for the harm this closes. `stage_path`/`staged_identity`
    // are required present (`None` is a fail-closed mismatch, not a skipped
    // check): an epoch that never actually recorded what it staged has no
    // business being committed at all.
    let recorded_stage_path = epoch.stage_path.as_deref().ok_or_else(|| {
        commit_mismatch(format!(
            "epoch {}/{} has no recorded stage_path to bind commit.stage_name against \
             (it never reached PreparedArtifact with a staged object)",
            request.transaction_id, request.epoch
        ))
    })?;
    let observed_stage_path = request.commit.parent_dir.path().join(request.commit.stage_name);
    if Path::new(recorded_stage_path) != observed_stage_path {
        return Err(commit_mismatch(format!(
            "commit window request's commit.stage_name resolves to {observed_stage_path:?}, \
             which does not match epoch {}/{}'s recorded stage_path {recorded_stage_path:?}",
            request.transaction_id, request.epoch,
        )));
    }

    let recorded_staged_identity = epoch.staged_identity.as_ref().ok_or_else(|| {
        commit_mismatch(format!(
            "epoch {}/{} has no recorded staged_identity to bind \
             commit.expected_stage_identity against (it never reached Prepared with a \
             verified staged identity)",
            request.transaction_id, request.epoch
        ))
    })?;
    // `FileIdentity::compare`, never a raw field comparison -- for the same
    // reason `fs_commit::check_stage_identity_matches_expected` uses it
    // rather than `==`, and the parent-directory check just above uses
    // `DirectoryIdentity::compare`. `recorded_staged_identity` was decoded
    // from storage (`materialized_generation::decode_file_identity`), which
    // always sets `symlink_target_digest: None` -- deliberately, since that
    // field's own doc explains no decoded row is ever expected to carry it.
    // A raw `!=` against a freshly observed `expected_stage_identity` (whose
    // `symlink_target_digest` is `Some` for every real symlink) would
    // therefore treat "the identical object" as a mismatch for every
    // symlink placement, forever, regardless of what is on disk --
    // `compare`'s ranked ladder only consults that field when *both* sides
    // carry one, so a decoded identity's `None` correctly drops out of the
    // comparison instead of being read as a distinguishing value the way
    // derived `PartialEq` reads it. The same switch also drops `==`'s
    // implicit dependence on `metadata_fingerprint` matching exactly:
    // `compare` never consults it at all, so a chmod, an fsync's ctime
    // bump, or a utimes call between staging and this commit window no
    // longer refuses a commit for a byte-identical object -- this check
    // exists to prove "is the staged object the one preparation verified",
    // and a mode or timestamp change does not make it a different object.
    // `Ambiguous` is treated exactly like `DefinitelyDifferent`, not like a
    // pass, matching every other identity binding in this crate: a
    // comparison that cannot rule out reuse is not proof the staged object
    // is the one this epoch recorded.
    //
    // Capability-split migration note: AMBIGUOUS. `recorded_staged_
    // identity` is decoded from storage (see the paragraph above), so —
    // unlike `fs_commit::check_stage_identity_matches_expected`, whose
    // `expected` never leaves this process — this comparison of the same
    // KIND of object (an engine-written Stage artefact) spans a restart.
    // Engine-owned points at `stable_owned_marker_identity`; restart-
    // spanning is exactly what that field's weaker same-boot predicate
    // (D1b) is documented not to cover. Conservatively treated as
    // depending on `stable_source_identity`, the same choice made at
    // `fs_commit::ParentDirHandle::remove_child_if_identity_matches` for
    // the identical shape of ambiguity.
    let stage_identity_verdict = recorded_staged_identity.compare(
        request.commit.expected_stage_identity,
        yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(
            request.commit.parent_dir.path(),
        ),
    );
    if !matches!(stage_identity_verdict, IdentityComparison::SameObject) {
        return Err(commit_mismatch(format!(
            "commit window request's commit.expected_stage_identity does not match epoch \
             {}/{}'s recorded staged_identity ({stage_identity_verdict:?})",
            request.transaction_id, request.epoch,
        )));
    }

    // Bind `commit.backup_name` to the same artefact id `stage_path` was
    // just proven to belong to this epoch -- see this function's doc for
    // why this is derived rather than compared against a recorded
    // `backup_path` (nothing records one yet).
    let recorded_stage_name = Path::new(recorded_stage_path).file_name().and_then(|n| n.to_str());
    let (stage_kind, artefact_id) = recorded_stage_name
        .and_then(reserved_namespace::parse_artefact_component)
        .ok_or_else(|| {
            commit_mismatch(format!(
                "epoch {}/{}'s recorded stage_path {recorded_stage_path:?} does not parse as a \
                 reserved artefact name",
                request.transaction_id, request.epoch,
            ))
        })?;
    if stage_kind != ArtefactKind::Stage {
        return Err(commit_mismatch(format!(
            "epoch {}/{}'s recorded stage_path {recorded_stage_path:?} names a {stage_kind:?} \
             artefact, not a Stage artefact",
            request.transaction_id, request.epoch,
        )));
    }
    let expected_backup_name =
        reserved_namespace::artefact_component_name(ArtefactKind::Backup, artefact_id).map_err(
            |e| {
                commit_mismatch(format!(
            "epoch {}/{}'s stage artefact id {artefact_id:?} cannot name a Backup artefact: {e}",
            request.transaction_id, request.epoch,
        ))
            },
        )?;
    if request.commit.backup_name != OsStr::new(expected_backup_name.as_str()) {
        return Err(commit_mismatch(format!(
            "commit window request's commit.backup_name {:?} does not match the Backup \
             artefact name {expected_backup_name:?} derived from epoch {}/{}'s recorded stage \
             artefact id {artefact_id:?}",
            request.commit.backup_name, request.transaction_id, request.epoch,
        )));
    }

    Ok(())
}

fn commit_mismatch(msg: String) -> CommitWindowError {
    CommitWindowError::Sync(SyncSqliteError::InvalidInput(msg))
}

/// Whether a [`FilesystemCommitOutcome::NotStarted`] reason earns the
/// epoch state machine's `(Committing, Prepared)` retreat, per that edge's
/// own doc on [`EpochState::can_transition_to`]: only a reason that is a
/// *proven* no-op, where the on-disk state is guaranteed to be exactly
/// what `Prepared` already recorded, qualifies. Fail-closed — a reason
/// this function cannot positively place in that class is treated as
/// non-retryable, per the review's instruction, and routes to `Blocked`
/// instead.
fn is_notstarted_reason_retryable(reason: &RetryReason) -> bool {
    match reason {
        // The one case `RetryReason`'s own doc describes as a timing race
        // rather than a property of the participants: "nothing was
        // touched, try again later" — something else transiently occupied
        // the destination between the pre-move absence check and the move
        // itself. Retrying the identical plan can plausibly succeed once
        // that transient occupant is gone.
        RetryReason::DestinationDidNotStayAbsent => true,

        // Named directly by the state machine's own `(Committing,
        // Prepared)` doc as its two non-retryable examples: an
        // unsupported volume and a kind-changing replacement are both
        // durable facts about this attempt that an identical retry cannot
        // change.
        RetryReason::UnsupportedOnThisVolume | RetryReason::ObjectKindMismatch => false,

        // Permanent properties of the specific objects/path this commit
        // names -- a hardlinked/special object stays ineligible, and
        // `live_name` stays identity-equal to the sync root, no matter how
        // many times the identical plan is retried.
        RetryReason::ReplacementNotEligible(_) | RetryReason::TargetIsSyncRoot => false,

        // Both mean the object `Prepared` actually recorded is no longer
        // what commit_placement observed at `stage_name` -- either absent
        // outright, or present but not provably the same object. The
        // `(Committing, Prepared)` edge's guarantee ("the on-disk state is
        // exactly what `Prepared` already recorded") does not hold in
        // either case, so neither may use it; re-preparation, not a bare
        // retry, is what these actually need.
        RetryReason::StageAbsent | RetryReason::StageIdentityMismatch => false,

        // A bare `io::ErrorKind`, encountered before any mutating syscall.
        // Some kinds (e.g. `Interrupted`) are genuinely transient, but
        // this variant carries no reliable, closed set of "safe to retry"
        // kinds to switch on, and guessing wrong here would let a
        // permanent I/O condition (e.g. a permissions problem) loop back
        // to `Prepared` forever instead of surfacing as blocked. Fail
        // closed.
        RetryReason::Io(_) => false,
    }
}

/// Reads `transaction_id`'s current `execution_generation` — the value a
/// compare-and-swap must name to still be accepted right now.
///
/// Used only by the two post-`Committing` corrections below, both of which
/// have to write in exactly the case where the caller's own
/// `expected_execution_generation` has already been superseded (that is
/// what they are correcting for), so passing the caller's stale value would
/// guarantee the correction is refused. This does not weaken the fence:
/// `transition_epoch_unchecked`'s UPDATE also carries a compare-and-swap on
/// the epoch's *source phase*, so a correction still only applies if the
/// epoch is exactly where this window left it, and both corrections record
/// strictly less claim than leaving the row as it stands.
fn current_execution_generation(
    conn: &Connection,
    transaction_id: &str,
) -> Result<i64, SyncSqliteError> {
    filesystem_transaction::lookup_transaction(conn, transaction_id)?
        .map(|t| t.execution_generation)
        .ok_or_else(|| {
            SyncSqliteError::NotFound(format!("filesystem transaction {transaction_id}"))
        })
}

/// Blocks an epoch whose pre-mutation execution-generation fence failed.
///
/// The adapter has not run, so there is no physical ambiguity. The plan is,
/// however, definitively stale: moving back to `Prepared` would strand an
/// epoch that can only repeat the same rejected generation. The epoch and its
/// parent saga are therefore moved to `Blocked` atomically, using the current
/// generation solely to record the refusal. If this bookkeeping itself fails,
/// the row remains `Committing`, which is conservative and recovery-visible.
fn block_fenced_epoch(conn: &mut Connection, request: &CommitWindowRequest, now_unix_nanos: i64) {
    const REASON: &str =
        "execution generation changed before filesystem commit; the placement must be replanned";
    let mut block = || -> Result<(), SyncSqliteError> {
        let tx = conn.transaction()?;
        let generation = current_execution_generation(&tx, request.transaction_id)?;
        filesystem_transaction::transition_epoch_unchecked(
            &tx,
            request.transaction_id,
            request.epoch,
            generation,
            EpochState::Blocked,
            &EpochUpdate::default(),
            now_unix_nanos,
        )?;
        let transaction = filesystem_transaction::lookup_transaction(&tx, request.transaction_id)?
            .ok_or_else(|| {
                SyncSqliteError::NotFound(format!(
                    "filesystem transaction {}",
                    request.transaction_id
                ))
            })?;
        if transaction.phase != TransactionPhase::Blocked {
            filesystem_transaction::set_transaction_phase_unchecked(
                &tx,
                request.transaction_id,
                generation,
                TransactionPhase::Blocked,
                Some(REASON),
                now_unix_nanos,
            )?;
        }
        tx.commit()?;
        Ok(())
    };
    let _ = block();
}

/// Converts any failure that happens *after* `adapter.commit_placement`
/// reported `Committed` into the one outcome that describes it honestly:
/// the filesystem has been mutated and this window did not manage to
/// journal that fact.
///
/// Every step after the adapter call — the `Committing -> Committed`
/// transition, the materialized-generation write, the reservation release,
/// the SQL commit — can fail (the transition, for one, re-checks the
/// execution-generation fence, which a concurrent bump landing after the
/// pre-mutation re-check will trip). Reported as an ordinary
/// [`CommitWindowError::Sync`], those failures are indistinguishable from
/// the many pre-mutation refusals that share that variant, and a caller
/// deciding on the variant alone (see `orchestrator::run_slice_unchecked`'s
/// reservation release) would drop the path's reservations while the
/// filesystem is mutated and no epoch says so.
///
/// No new durable marker is introduced for this. The epoch is already
/// durably `Committing` at this point, and `early_physical_recovery`
/// already treats `Committing` as "physical outcome unknown", so the
/// crash-recovery answer is correct even if this function's own write is
/// the thing that fails. What is genuinely missing without this is the
/// *in-process* signal, and `CommitWindowError::RequiresRecovery` — already
/// the contract for an uncertain platform commit — is exactly it. The
/// durable `RequiresPhysicalRecovery` transition below is therefore an
/// upgrade in precision (it records the observed identities alongside the
/// state), not the thing correctness rests on, which is why it is
/// best-effort.
fn unjournaled_physical_outcome(
    conn: &mut Connection,
    adapter: &dyn FilesystemCommitAdapter,
    request: &CommitWindowRequest,
    snapshot: &yadorilink_filesystem_sync::fs_commit::CommittedSnapshot,
    now_unix_nanos: i64,
) -> CommitWindowError {
    let live_path = request.commit.parent_dir.path().join(request.commit.live_name);
    let stage_path = request.commit.parent_dir.path().join(request.commit.stage_name);
    let backup_path = request.commit.parent_dir.path().join(request.commit.backup_name);
    let recovery = Box::new(RecoverySnapshot {
        observed_live: Some(observe_for_recovery(adapter, &live_path)),
        observed_stage: Some(observe_for_recovery(adapter, &stage_path)),
        // Mirrors `fs_commit`'s own convention (see its
        // `recovery_snapshot` helper): on Linux/macOS the preimage this
        // commit displaced has no name of its own separate from
        // `stage_path`, so it is not double-reported here.
        // `snapshot.preimage_identity` (already known, not re-observed)
        // still carries it in the `EpochUpdate` below.
        observed_preimage: None,
        observed_backup: Some(observe_for_recovery(adapter, &backup_path)),
    });

    let mut record = || -> Result<(), SyncSqliteError> {
        let tx = conn.transaction()?;
        let generation = current_execution_generation(&tx, request.transaction_id)?;
        filesystem_transaction::transition_epoch_unchecked(
            &tx,
            request.transaction_id,
            request.epoch,
            generation,
            EpochState::RequiresPhysicalRecovery,
            &EpochUpdate {
                staged_identity: Some(&snapshot.live_identity),
                displaced_identity: snapshot.preimage_identity.as_ref(),
                ..Default::default()
            },
            now_unix_nanos,
        )?;
        tx.commit()?;
        Ok(())
    };
    let _ = record();

    CommitWindowError::RequiresRecovery(recovery)
}

/// A fresh, independent observation of one named commit participant for a
/// [`RecoverySnapshot`], via the adapter's own `observe_identity` (never an
/// inference from the flush failure itself) — see [`RecoverySnapshot`]'s
/// doc for why a checked-but-unreadable location must not collapse into
/// "absent".
fn observe_for_recovery(adapter: &dyn FilesystemCommitAdapter, path: &Path) -> RecoveryObservation {
    match adapter.observe_identity(path) {
        Ok(Some(identity)) => RecoveryObservation::Present(identity),
        Ok(None) => RecoveryObservation::Absent,
        Err(e) => RecoveryObservation::Unreadable(e.kind()),
    }
}

#[cfg(test)]
thread_local! {
    static COMMIT_WINDOW_PRE_FENCE_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only seam for [`execute_short_commit_window_unchecked`]'s tests:
/// lets a test run arbitrary code (typically a genuine concurrent
/// `increment_execution_generation` through a second connection to the same
/// database) at the exact point between the `Committing` transition's SQL
/// commit and the pre-mutation fence re-check that fixes Defect 1 — a gap
/// no test can otherwise land code inside of, since nothing else in this
/// synchronous function yields control back to a caller there.
#[cfg(test)]
fn set_pre_mutation_fence_recheck_hook_for_test(hook: impl FnMut() + 'static) {
    COMMIT_WINDOW_PRE_FENCE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn clear_pre_mutation_fence_recheck_hook_for_test() {
    COMMIT_WINDOW_PRE_FENCE_HOOK.with(|h| *h.borrow_mut() = None);
}

#[cfg(test)]
fn fire_pre_mutation_fence_recheck_hook_for_test() {
    COMMIT_WINDOW_PRE_FENCE_HOOK.with(|h| {
        if let Some(hook) = h.borrow_mut().as_mut() {
            hook();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem_transaction::{
        FilesystemTransactionKind, NewEpoch, NewFilesystemTransaction, TransactionCause,
    };
    use yadorilink_filesystem_sync::fs_commit::FakeCommitAdapter;
    use yadorilink_replica_domain::filesystem_placement::PlacementRole;
    use yadorilink_root_authority::fs_capabilities::{
        Capability, DurabilityLevel, FilesystemSafetyCapabilities,
    };

    // ---- Short commit window (§6.2) -------------------------------------

    /// `reflink_or_clone`/`range_clone` are irrelevant to the commit window
    /// (a preparation-phase concern, per `yadorilink-filesystem-sync::
    /// optimistic_placement`'s own `caps()` fixture, which this one used to
    /// share before the 7D-9D eighth pass moved preparation out) -- always
    /// `Supported` here since nothing below selects a fast path.
    fn commit_window_capabilities() -> FilesystemSafetyCapabilities {
        FilesystemSafetyCapabilities {
            atomic_exchange: Capability::Supported,
            durable_file_flush: Capability::Supported,
            durable_directory_flush: Capability::Supported,
            stable_source_identity: Capability::Supported,
            stable_owned_marker_identity: Capability::Supported,
            stale_handle_preservation: Capability::Supported,
            metadata_fidelity: Capability::Supported,
            reflink_or_clone: Capability::Supported,
            range_clone: Capability::Supported,
        }
    }

    /// `durable_directory_flush` claimed only where this platform can
    /// actually deliver it. `fs_capabilities::probe_durable_directory_flush`
    /// reports `Unsupported` on Windows by construction -- opening a
    /// directory handle there does not grant `GENERIC_WRITE`, so
    /// `FlushFileBuffers` on it cannot be performed at all, not merely
    /// undocumented. A fixture that claimed `Supported` regardless of
    /// platform would make the commit window attempt a flush that is
    /// doomed to fail everywhere Windows runs it, which is a defect in the
    /// fixture, not in the commit window it drives.
    fn honestly_supported_durable_directory_flush() -> Capability {
        if cfg!(windows) {
            Capability::Unsupported
        } else {
            Capability::Supported
        }
    }

    /// A `Prepared`-phase transaction+epoch pair whose recorded fields
    /// agree with `group_id`/`path`/`object_kind`/`version`, with
    /// `parent_dir`'s own observed identity, and -- critically for the
    /// stage-binding checks `require_commit_matches_epoch` now makes --
    /// with a real `stage_path`/`staged_identity` recorded via the real
    /// `PreparedArtifact`/`Prepared` transitions, exactly as a genuine
    /// `prepare_target` caller would. Earlier versions of this helper drove
    /// every transition with `EpochUpdate::default()`, leaving those two
    /// fields permanently unset; a check bound against a permanently-unset
    /// field can never observe a mismatch, so that shape would have made
    /// the stage-binding checks vacuous no matter how they were written.
    /// `artefact_id` is the caller's choice of id for the stage/backup
    /// artefact pair this epoch records -- returned as the resulting
    /// `stage_name`/`backup_name` so a test can build a `CommitRequest`
    /// that genuinely agrees with what got recorded (or deliberately
    /// doesn't, to exercise a refusal).
    struct PreparedEpoch {
        transaction_id: String,
        epoch: i64,
        stage_name: String,
        backup_name: String,
        staged_identity: FileIdentity,
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_prepared_epoch(
        conn: &Connection,
        group_id: &str,
        path: &str,
        object_kind: MaterializedObjectKind,
        version: Option<&VersionHash>,
        parent_dir: &ParentDirHandle,
        artefact_id: &str,
    ) -> PreparedEpoch {
        insert_prepared_epoch_with_identity(
            conn,
            group_id,
            path,
            object_kind,
            version,
            parent_dir,
            artefact_id,
            sample_stage_identity(),
        )
    }

    /// Same as [`insert_prepared_epoch`], but lets a caller supply the exact
    /// `FileIdentity` this epoch's `Prepared` transition records as
    /// `staged_identity`, rather than the synthetic `sample_stage_identity`.
    /// Needed by the symlink round-trip tests below: they need a *real*
    /// `FileIdentity::observe_path` observation (with a populated
    /// `symlink_target_digest`) recorded here, so that reading it back out
    /// as `epoch.staged_identity` exercises a genuine decoded row -- one
    /// that lost that field the way `materialized_generation::decode_file_
    /// identity` always does -- rather than a constructed identity that
    /// already had the field absent, which would pass `require_commit_
    /// matches_epoch`'s check for the wrong reason.
    #[allow(clippy::too_many_arguments)]
    fn insert_prepared_epoch_with_identity(
        conn: &Connection,
        group_id: &str,
        path: &str,
        object_kind: MaterializedObjectKind,
        version: Option<&VersionHash>,
        parent_dir: &ParentDirHandle,
        artefact_id: &str,
        staged_identity: FileIdentity,
    ) -> PreparedEpoch {
        let transaction = filesystem_transaction::begin_transaction_unchecked(
            conn,
            &NewFilesystemTransaction {
                group_id,
                source_path: path,
                kind: FilesystemTransactionKind::ObjectResolution,
                cause: TransactionCause::PeerProjection,
                trigger_change_hash: None,
                desired_frontier_hash: [9; 32],
            },
            0,
        )
        .unwrap();

        let parent_directory_identity = DirectoryIdentity::observe_path(parent_dir.path()).unwrap();
        let target_generation = materialized_generation::compute_resolved_path_state_hash(
            group_id,
            path,
            object_kind,
            version,
        );
        let epoch = filesystem_transaction::insert_epoch_unchecked(
            conn,
            &NewEpoch {
                transaction_id: &transaction.transaction_id,
                epoch: 0,
                plan_revision: 0,
                target_path: path,
                placement_role: PlacementRole::CanonicalPath,
                target_generation: &target_generation,
                parent_directory_identity: &parent_directory_identity,
                capability_snapshot: b"opaque",
                durability_level: DurabilityLevel::PowerLossSafe,
            },
            // `transaction` was just freshly begun above at generation 0,
            // and nothing bumps it before this insert.
            0,
            0,
        )
        .unwrap();

        let stage_name =
            reserved_namespace::artefact_component_name(ArtefactKind::Stage, artefact_id).unwrap();
        let backup_name =
            reserved_namespace::artefact_component_name(ArtefactKind::Backup, artefact_id).unwrap();
        let stage_path = parent_dir.path().join(&stage_name);

        // Walk the epoch through its legal sequence up to `Prepared`, the
        // only phase `execute_short_commit_window_unchecked` accepts --
        // recording `stage_path` at `PreparedArtifact` and `staged_identity`
        // at `Prepared`, matching the convention `early_physical_recovery`'s
        // own tests already establish for a genuine staged-artefact epoch.
        filesystem_transaction::transition_epoch_unchecked(
            conn,
            &transaction.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            conn,
            &transaction.transaction_id,
            epoch.epoch,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate { stage_path: Some(stage_path.to_str().unwrap()), ..Default::default() },
            0,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            conn,
            &transaction.transaction_id,
            epoch.epoch,
            0,
            EpochState::AwaitingReservation,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        filesystem_transaction::transition_epoch_unchecked(
            conn,
            &transaction.transaction_id,
            epoch.epoch,
            0,
            EpochState::Prepared,
            &EpochUpdate { staged_identity: Some(&staged_identity), ..Default::default() },
            0,
        )
        .unwrap();

        PreparedEpoch {
            transaction_id: transaction.transaction_id,
            epoch: epoch.epoch,
            stage_name,
            backup_name,
            staged_identity,
        }
    }

    fn open_commit_window_schema(conn: &Connection) {
        crate::dag_store::init_dag_schema(conn).unwrap();
        materialized_generation::init_materialized_generation_schema(conn).unwrap();
        filesystem_transaction::init_filesystem_transaction_schema(conn).unwrap();
    }

    fn sample_sync_root_identity() -> DirectoryIdentity {
        DirectoryIdentity {
            volume_identity: yadorilink_root_authority::fs_identity::VolumeIdentity::Unix {
                device_id: 999,
            },
            object_id: yadorilink_root_authority::fs_identity::PlatformObjectId::Unix {
                inode: 999,
            },
            generation_or_usn: None,
            birth_or_creation_time: None,
        }
    }

    /// A synthetic stage identity for the commit-window tests below, none
    /// of which exercise the real platform `commit_placement` (they drive
    /// `FakeCommitAdapter` or a panic-if-called stub instead) -- so this
    /// only needs to satisfy `CommitRequest`'s now-mandatory
    /// `expected_stage_identity` field, not match anything real on disk.
    /// See `fs_commit`'s own tests for the identity check exercised
    /// end-to-end against a real filesystem.
    ///
    /// It still needs a `generation_or_usn`, though: `FileIdentity::compare`
    /// refuses to conclude `SameObject` for an identity with neither
    /// `generation_or_usn` nor `birth_or_creation_time` present -- with both
    /// absent, comparing it against itself is
    /// `Ambiguous(NoStableGenerationOrUsn)`, not `SameObject`, because
    /// "cannot prove same" is not "same". A fixture with no discriminator
    /// therefore can't even self-compare as itself, which makes every
    /// stage-binding check that calls `compare` on it refuse no matter what
    /// the test is actually exercising. `generation_or_usn` is used here
    /// rather than `birth_or_creation_time` because the generation path
    /// resolves to `SameObject` unconditionally (see `compare`), so this
    /// fixture stays correct independent of whichever timestamp-granularity
    /// capability a given test happens to pass.
    fn sample_stage_identity() -> FileIdentity {
        FileIdentity {
            volume_identity: yadorilink_root_authority::fs_identity::VolumeIdentity::Unix {
                device_id: 1,
            },
            object_id: yadorilink_root_authority::fs_identity::PlatformObjectId::Unix { inode: 7 },
            object_kind: yadorilink_root_authority::fs_identity::ObjectKind::RegularFile,
            generation_or_usn: Some(1),
            birth_or_creation_time: None,
            observed_size: 0,
            metadata_fingerprint: [0; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        }
    }

    // ---- Defect 3: request/epoch agreement ------------------------------

    #[test]
    fn commit_window_refuses_a_request_whose_live_name_names_a_different_path_than_the_epoch() {
        // Recreates the harm from the review: a request whose `path`
        // matches the epoch's `target_path` ("b") but whose
        // `commit.live_name` names a different on-disk object ("a"). Left
        // unchecked, this would mutate "a" on disk while publishing the
        // generation as belonging to "b". Must be refused before the
        // adapter -- configured to panic if reached -- is ever invoked.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "b",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("a"),
            backup_name: OsStr::new("backup"),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &sample_stage_identity(),
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "b",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        struct PanicIfCalled;
        impl FilesystemCommitAdapter for PanicIfCalled {
            fn commit_placement(&self, _request: &CommitRequest) -> FilesystemCommitOutcome {
                panic!("adapter must not be invoked once the request/epoch mismatch is detected");
            }
            fn observe_identity(&self, _path: &Path) -> io::Result<Option<FileIdentity>> {
                Ok(None)
            }
        }

        let result = execute_short_commit_window_unchecked(&mut conn, &PanicIfCalled, &request, 0);
        assert!(matches!(result, Err(CommitWindowError::Sync(SyncSqliteError::InvalidInput(_)))));
    }

    #[test]
    fn commit_window_refuses_a_request_whose_object_kind_or_version_disagrees_with_the_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        // Epoch recorded for a regular file with no version...
        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new("backup"),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &sample_stage_identity(),
        };
        // ...but the request now claims a directory instead.
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::Directory,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        struct PanicIfCalled;
        impl FilesystemCommitAdapter for PanicIfCalled {
            fn commit_placement(&self, _request: &CommitRequest) -> FilesystemCommitOutcome {
                panic!("adapter must not be invoked once the request/epoch mismatch is detected");
            }
            fn observe_identity(&self, _path: &Path) -> io::Result<Option<FileIdentity>> {
                Ok(None)
            }
        }

        let result = execute_short_commit_window_unchecked(&mut conn, &PanicIfCalled, &request, 0);
        assert!(matches!(result, Err(CommitWindowError::Sync(SyncSqliteError::InvalidInput(_)))));
    }

    #[test]
    fn commit_window_accepts_a_request_that_actually_agrees_with_its_epoch() {
        // Not a mutation-restating test on its own -- paired with the two
        // refusal tests above, this confirms `require_commit_matches_epoch`
        // rejects real mismatches without also rejecting the matching case.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let sync_root_identity = sample_sync_root_identity();
        // This test drives an adapter that reports `Committed`, so unlike
        // the `refuses_*` tests above (which are all rejected before the
        // adapter is ever reached), the commit window here goes on to
        // perform a *real* directory flush against `parent_dir`. Claiming
        // `durable_directory_flush: Supported` unconditionally would assert
        // a capability Windows provably does not have (see
        // `honestly_supported_durable_directory_flush`), making that real
        // flush fail and route to recovery for a reason that has nothing
        // to do with what this test checks -- request/epoch agreement.
        let capabilities = FilesystemSafetyCapabilities {
            durable_directory_flush: honestly_supported_durable_directory_flush(),
            ..commit_window_capabilities()
        };
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        let identity = FileIdentity {
            volume_identity: yadorilink_root_authority::fs_identity::VolumeIdentity::Unix {
                device_id: 1,
            },
            object_id: yadorilink_root_authority::fs_identity::PlatformObjectId::Unix { inode: 42 },
            object_kind: yadorilink_root_authority::fs_identity::ObjectKind::RegularFile,
            generation_or_usn: None,
            birth_or_creation_time: None,
            observed_size: 0,
            metadata_fingerprint: [0; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        };
        let adapter = FakeCommitAdapter::returning(FilesystemCommitOutcome::Committed(Box::new(
            yadorilink_filesystem_sync::fs_commit::CommittedSnapshot {
                live_identity: identity,
                preimage_identity: None,
            },
        )));

        let result = execute_short_commit_window_unchecked(&mut conn, &adapter, &request, 0);
        assert!(result.is_ok(), "matching request/epoch must not be refused: {result:?}");
    }

    #[test]
    fn commit_window_refuses_a_request_whose_stage_identity_disagrees_with_the_epoch() {
        // Recreates Gap 1's harm from the review: the request's `path`,
        // `live_name`, generation and parent directory all genuinely agree
        // with the epoch -- only `commit.expected_stage_identity` names a
        // different object than what this epoch's own preparation actually
        // staged and verified (`prepared.staged_identity`). Before this
        // fix, `require_commit_matches_epoch` never looked at the stage at
        // all, so this would have sailed through to the adapter, which
        // would exchange whatever the caller's substituted identity
        // happened to describe.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        // A real, different object's identity -- not the one this epoch's
        // own `Prepared` transition recorded.
        let substituted_identity = FileIdentity {
            volume_identity: yadorilink_root_authority::fs_identity::VolumeIdentity::Unix {
                device_id: 1,
            },
            object_id: yadorilink_root_authority::fs_identity::PlatformObjectId::Unix {
                inode: 999,
            },
            object_kind: yadorilink_root_authority::fs_identity::ObjectKind::RegularFile,
            generation_or_usn: None,
            birth_or_creation_time: None,
            observed_size: 0,
            metadata_fingerprint: [0; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        };
        assert_ne!(substituted_identity, prepared.staged_identity);

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &substituted_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        struct PanicIfCalled;
        impl FilesystemCommitAdapter for PanicIfCalled {
            fn commit_placement(&self, _request: &CommitRequest) -> FilesystemCommitOutcome {
                panic!("adapter must not be invoked once the stage-identity mismatch is detected");
            }
            fn observe_identity(&self, _path: &Path) -> io::Result<Option<FileIdentity>> {
                Ok(None)
            }
        }

        let result = execute_short_commit_window_unchecked(&mut conn, &PanicIfCalled, &request, 0);
        assert!(
            matches!(result, Err(CommitWindowError::Sync(SyncSqliteError::InvalidInput(_)))),
            "a stage identity substituted for the epoch's own recorded one must be refused: \
             {result:?}"
        );
    }

    #[test]
    fn commit_window_accepts_a_genuinely_same_symlink_recorded_only_through_its_decoded_target_digest(
    ) {
        // Regression test for the defect this fix closes. Two things had to
        // change together:
        //
        // 1. `materialized_generation`'s on-disk encoding (bumped to
        //    version 3) now carries `symlink_target_digest` -- previously
        //    omitted on the theory that nothing reading a decoded identity
        //    needed it, which `require_commit_matches_epoch`'s stage
        //    binding falsifies: for a symlink, that digest is the *only*
        //    reuse discriminator available at all (`generation_or_usn` is
        //    never populated for this kind on any platform -- see its own
        //    doc), so a decoded row missing it had no way to reach
        //    `SameObject` on a coarse-clock volume with no birth-time proof
        //    either, regardless of what was actually on disk.
        // 2. `require_commit_matches_epoch` compares through `FileIdentity::
        //    compare`, not a raw `==`/`!=` -- matching the parent-directory
        //    check just above it and `fs_commit::check_stage_identity_
        //    matches_expected`'s identical reasoning.
        //
        // `insert_prepared_epoch_with_identity` records a real `FileIdentity
        // ::observe_path` observation of an actual symlink (not a
        // constructed one that already had every weak field populated,
        // which would pass this check for the wrong reason), so `epoch.
        // staged_identity` here genuinely round-trips through storage and
        // back before this assertion runs.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let link_path = dir.path().join("a-symlink");
        #[cfg(unix)]
        std::os::unix::fs::symlink("target-of-the-link", &link_path).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file("target-of-the-link", &link_path).unwrap();
        let mut live_symlink_identity = FileIdentity::observe_path(&link_path).unwrap();
        assert!(
            live_symlink_identity.symlink_target_digest.is_some(),
            "a live observation of a real symlink must populate symlink_target_digest"
        );
        // `generation_or_usn` is already always `None` for a symlink (the
        // ioctl it comes from is never attempted for this kind -- see
        // `symlink_target_digest`'s own doc). Force `birth_or_creation_
        // time` absent too, regardless of what this test host's filesystem
        // actually reports, so `compare` cannot resolve `SameObject` via
        // that tier either and is driven all the way down to the
        // `symlink_target_digest` tier this test exists to exercise --
        // otherwise a host whose filesystem happens to support birth times
        // would make this test pass without ever reaching that tier, and it
        // would stop being a regression test for the encoding-version-3 fix
        // specifically.
        live_symlink_identity.birth_or_creation_time = None;

        let prepared = insert_prepared_epoch_with_identity(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::Symlink,
            None,
            &parent,
            "ep0",
            live_symlink_identity,
        );
        assert_eq!(
            prepared.staged_identity.symlink_target_digest,
            live_symlink_identity.symlink_target_digest,
            "epoch.staged_identity must survive its own round trip through storage, digest \
             included -- otherwise this test would (again) pass for the wrong reason"
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = FilesystemSafetyCapabilities {
            durable_directory_flush: honestly_supported_durable_directory_flush(),
            ..commit_window_capabilities()
        };
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            // Exactly the shape a genuine caller passes -- `orchestrator`'s
            // real commit-window call site reuses the same in-memory
            // `PreparedArtifact::staged_identity` value for both this field
            // and the `EpochUpdate` that got encoded above, never a fresh
            // observation.
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::Symlink,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        let identity = FileIdentity {
            volume_identity: yadorilink_root_authority::fs_identity::VolumeIdentity::Unix {
                device_id: 1,
            },
            object_id: yadorilink_root_authority::fs_identity::PlatformObjectId::Unix { inode: 42 },
            object_kind: yadorilink_root_authority::fs_identity::ObjectKind::Symlink,
            generation_or_usn: None,
            birth_or_creation_time: None,
            observed_size: 0,
            metadata_fingerprint: [0; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        };
        let adapter = FakeCommitAdapter::returning(FilesystemCommitOutcome::Committed(Box::new(
            yadorilink_filesystem_sync::fs_commit::CommittedSnapshot {
                live_identity: identity,
                preimage_identity: None,
            },
        )));

        let result = execute_short_commit_window_unchecked(&mut conn, &adapter, &request, 0);
        assert!(
            result.is_ok(),
            "a symlink commit whose stage identity genuinely matches the epoch's own recorded \
             observation, with only symlink_target_digest available to prove it, must not be \
             refused: {result:?}"
        );
    }

    #[test]
    fn commit_window_ignores_a_metadata_fingerprint_difference_between_the_recorded_and_live_stage_identity(
    ) {
        // The other half of this fix: `require_commit_matches_epoch` used
        // to compare the whole `FileIdentity` struct by value, which
        // includes `metadata_fingerprint` -- a hash over mtime, ctime and
        // mode. That means any chmod, any ctime bump from an fsync, or any
        // utimes call between the value `Prepared` recorded and this commit
        // window would flip the comparison and refuse a commit for a
        // byte-identical object. This binding asks "is the staged object
        // the one preparation verified", and a mode/timestamp change does
        // not make it a different object -- `FileIdentity::compare` never
        // consults `metadata_fingerprint` at all, so switching to it fixes
        // this for free.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        // Overrides `sample_stage_identity`'s own `generation_or_usn` with a
        // distinct value so this test's `SameObject` outcome is pinned to
        // *this* discriminator matching, independent of the volume's clock
        // granularity and independent of whatever value the shared fixture
        // happens to carry.
        let staged_identity =
            FileIdentity { generation_or_usn: Some(7), ..sample_stage_identity() };
        let prepared = insert_prepared_epoch_with_identity(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
            staged_identity,
        );

        // Same object in every field `compare` actually consults, but a
        // different `metadata_fingerprint` -- standing in for a chmod or an
        // fsync-driven ctime bump landing between `Prepared` and this
        // commit window.
        let live_reobservation_after_a_metadata_change = FileIdentity {
            metadata_fingerprint: {
                let mut fp = prepared.staged_identity.metadata_fingerprint;
                fp[0] ^= 0xff;
                fp
            },
            ..prepared.staged_identity
        };
        assert_ne!(
            live_reobservation_after_a_metadata_change.metadata_fingerprint,
            prepared.staged_identity.metadata_fingerprint
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = FilesystemSafetyCapabilities {
            durable_directory_flush: honestly_supported_durable_directory_flush(),
            ..commit_window_capabilities()
        };
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &live_reobservation_after_a_metadata_change,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        let identity = FileIdentity {
            volume_identity: yadorilink_root_authority::fs_identity::VolumeIdentity::Unix {
                device_id: 1,
            },
            object_id: yadorilink_root_authority::fs_identity::PlatformObjectId::Unix { inode: 42 },
            object_kind: yadorilink_root_authority::fs_identity::ObjectKind::RegularFile,
            generation_or_usn: None,
            birth_or_creation_time: None,
            observed_size: 0,
            metadata_fingerprint: [0; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        };
        let adapter = FakeCommitAdapter::returning(FilesystemCommitOutcome::Committed(Box::new(
            yadorilink_filesystem_sync::fs_commit::CommittedSnapshot {
                live_identity: identity,
                preimage_identity: None,
            },
        )));

        let result = execute_short_commit_window_unchecked(&mut conn, &adapter, &request, 0);
        assert!(
            result.is_ok(),
            "a metadata_fingerprint difference alone must not refuse a commit for the same \
             object: {result:?}"
        );
    }

    #[test]
    fn commit_window_refuses_a_request_whose_stage_name_names_a_different_artefact_than_the_epoch()
    {
        // The other half of Gap 1's harm shape: `commit.stage_name` itself
        // points at a different (but still validly-named) staged artefact
        // than the one this epoch recorded -- `expected_stage_identity` is
        // internally consistent with that other artefact, so a check that
        // only compared identities (and not the name/path too) could in
        // principle miss this. `require_commit_matches_epoch` must catch
        // it via the `stage_path` comparison alone.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );
        let other_stage_name =
            reserved_namespace::artefact_component_name(ArtefactKind::Stage, "not-ep0").unwrap();
        assert_ne!(other_stage_name, prepared.stage_name);

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&other_stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        struct PanicIfCalled;
        impl FilesystemCommitAdapter for PanicIfCalled {
            fn commit_placement(&self, _request: &CommitRequest) -> FilesystemCommitOutcome {
                panic!("adapter must not be invoked once the stage-name mismatch is detected");
            }
            fn observe_identity(&self, _path: &Path) -> io::Result<Option<FileIdentity>> {
                Ok(None)
            }
        }

        let result = execute_short_commit_window_unchecked(&mut conn, &PanicIfCalled, &request, 0);
        assert!(
            matches!(result, Err(CommitWindowError::Sync(SyncSqliteError::InvalidInput(_)))),
            "a stage_name naming a different artefact than the epoch recorded must be refused: \
             {result:?}"
        );
    }

    // ---- Defect 1: fence must hold across the mutation, not just the ----
    // ---- bookkeeping transition -----------------------------------------

    #[test]
    fn commit_window_refuses_to_mutate_when_the_generation_is_bumped_just_before_the_syscall() {
        // Drives a real, independent concurrent increment -- through a
        // second connection to the same on-disk database -- landing
        // exactly in the gap between the `Committing` transition's SQL
        // commit and the pre-mutation fence re-check Defect 1's fix adds.
        // Before that fix, this gap was unguarded and the (panicking, in
        // this test) adapter call below would have been reached with a
        // stale generation.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("commit_window.sqlite");

        let mut conn = Connection::open(&db_path).unwrap();
        open_commit_window_schema(&conn);

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let db_path_for_hook = db_path.clone();
        let transaction_id_for_hook = prepared.transaction_id.clone();
        set_pre_mutation_fence_recheck_hook_for_test(move || {
            let racer = Connection::open(&db_path_for_hook).unwrap();
            filesystem_transaction::increment_execution_generation_unchecked(
                &racer,
                &transaction_id_for_hook,
            )
            .unwrap();
        });

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        struct PanicIfCalled;
        impl FilesystemCommitAdapter for PanicIfCalled {
            fn commit_placement(&self, _request: &CommitRequest) -> FilesystemCommitOutcome {
                panic!(
                    "adapter must not be invoked: the execution-generation fence was already \
                     stale by the time the pre-mutation re-check ran"
                );
            }
            fn observe_identity(&self, _path: &Path) -> io::Result<Option<FileIdentity>> {
                Ok(None)
            }
        }

        let result = execute_short_commit_window_unchecked(&mut conn, &PanicIfCalled, &request, 0);
        clear_pre_mutation_fence_recheck_hook_for_test();

        assert!(matches!(
            result,
            Err(CommitWindowError::Sync(SyncSqliteError::ExecutionGenerationFenced {
                expected: 0,
                current: 1,
                ..
            }))
        ));
    }

    /// A rejection raised before the adapter is reached must not leave the
    /// epoch durably at `Committing`. `early_physical_recovery` cannot tell
    /// from durable state alone whether `commit_placement` ran, so it routes
    /// every `Committing` epoch to `RequiresPhysicalRecovery` -- meaning a
    /// `Committing` row left behind by a request that never touched the
    /// filesystem turns an ordinary caller-side mismatch into a physical
    /// ambiguity nothing in this phase can resolve.
    ///
    /// This covers the deterministic limb: the request/epoch agreement
    /// check, which is a pure comparison and fires on every attempt with a
    /// mismatched request, not only under a race.
    #[test]
    fn a_request_that_disagrees_with_its_epoch_leaves_the_epoch_prepared() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        // Disagrees with the epoch on `path` alone -- every other field is
        // exactly what the epoch recorded, so the refusal below can only
        // come from the agreement check.
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "a-different-path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        struct PanicIfCalled;
        impl FilesystemCommitAdapter for PanicIfCalled {
            fn commit_placement(&self, _request: &CommitRequest) -> FilesystemCommitOutcome {
                panic!("adapter must not be invoked once the path mismatch is detected");
            }
            fn observe_identity(&self, _path: &Path) -> io::Result<Option<FileIdentity>> {
                Ok(None)
            }
        }

        let result = execute_short_commit_window_unchecked(&mut conn, &PanicIfCalled, &request, 0);
        assert!(
            matches!(result, Err(CommitWindowError::Sync(SyncSqliteError::InvalidInput(_)))),
            "a request naming a different path than the epoch recorded must be refused: {result:?}"
        );

        let epoch =
            filesystem_transaction::lookup_epoch(&conn, &prepared.transaction_id, prepared.epoch)
                .unwrap()
                .unwrap();
        assert_eq!(
            epoch.phase,
            EpochState::Prepared,
            "a refusal that never reached the adapter must leave the epoch where it was, not at \
             Committing -- which recovery reads as 'physical outcome unknown'"
        );
    }

    /// The race-dependent limb of the same rule: the pre-mutation fence
    /// re-check fires only when a generation bump lands between the
    /// `Committing` transition's SQL commit and that re-check. The adapter
    /// is still provably untouched, so the epoch must be retreated back to
    /// `Prepared` -- the same `(Committing, Prepared)` edge a proven-no-op
    /// `NotStarted` outcome takes.
    #[test]
    fn a_fence_rejection_just_before_the_syscall_retreats_the_epoch_to_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("commit_window.sqlite");

        let mut conn = Connection::open(&db_path).unwrap();
        open_commit_window_schema(&conn);

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let db_path_for_hook = db_path.clone();
        let transaction_id_for_hook = prepared.transaction_id.clone();
        set_pre_mutation_fence_recheck_hook_for_test(move || {
            let racer = Connection::open(&db_path_for_hook).unwrap();
            filesystem_transaction::increment_execution_generation_unchecked(
                &racer,
                &transaction_id_for_hook,
            )
            .unwrap();
        });

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        struct PanicIfCalled;
        impl FilesystemCommitAdapter for PanicIfCalled {
            fn commit_placement(&self, _request: &CommitRequest) -> FilesystemCommitOutcome {
                panic!("adapter must not be invoked once the fence is known stale");
            }
            fn observe_identity(&self, _path: &Path) -> io::Result<Option<FileIdentity>> {
                Ok(None)
            }
        }

        let result = execute_short_commit_window_unchecked(&mut conn, &PanicIfCalled, &request, 0);
        clear_pre_mutation_fence_recheck_hook_for_test();
        assert!(
            matches!(
                result,
                Err(CommitWindowError::Sync(SyncSqliteError::ExecutionGenerationFenced { .. }))
            ),
            "{result:?}"
        );

        let epoch =
            filesystem_transaction::lookup_epoch(&conn, &prepared.transaction_id, prepared.epoch)
                .unwrap()
                .unwrap();
        assert_eq!(
            epoch.phase,
            EpochState::Blocked,
            "the fence fired before the adapter ran, so the filesystem is provably untouched, but \
             a fenced epoch must not silently return to a schedulable non-terminal state either -- \
             it is left `Blocked` for recovery to reconcile explicitly"
        );
    }

    /// Once `commit_placement` has reported `Committed` the filesystem is
    /// mutated, so no later failure may surface as an ordinary
    /// [`CommitWindowError::Sync`] -- that variant also carries every
    /// pre-mutation refusal, and a caller that decides on the variant alone
    /// (`orchestrator::run_slice_unchecked` releases reservations on it)
    /// would drop the path's exclusion while the epoch still says nothing
    /// happened.
    ///
    /// Driven through the fence: the adapter itself bumps the execution
    /// generation from an independent connection *after* the pre-mutation
    /// re-check has already passed and while reporting a successful commit,
    /// so the `Committing -> Committed` transition is what fails.
    #[test]
    fn a_journaling_failure_after_the_mutation_is_reported_as_requiring_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("commit_window.sqlite");

        let mut conn = Connection::open(&db_path).unwrap();
        open_commit_window_schema(&conn);

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        struct BumpsTheGenerationThenReportsCommitted {
            db_path: std::path::PathBuf,
            transaction_id: String,
        }
        impl FilesystemCommitAdapter for BumpsTheGenerationThenReportsCommitted {
            fn commit_placement(&self, _request: &CommitRequest) -> FilesystemCommitOutcome {
                let racer = Connection::open(&self.db_path).unwrap();
                filesystem_transaction::increment_execution_generation_unchecked(
                    &racer,
                    &self.transaction_id,
                )
                .unwrap();
                FilesystemCommitOutcome::Committed(Box::new(
                    yadorilink_filesystem_sync::fs_commit::CommittedSnapshot {
                        live_identity: FileIdentity {
                            volume_identity:
                                yadorilink_root_authority::fs_identity::VolumeIdentity::Unix {
                                    device_id: 1,
                                },
                            object_id:
                                yadorilink_root_authority::fs_identity::PlatformObjectId::Unix {
                                    inode: 42,
                                },
                            object_kind:
                                yadorilink_root_authority::fs_identity::ObjectKind::RegularFile,
                            generation_or_usn: None,
                            birth_or_creation_time: None,
                            observed_size: 0,
                            metadata_fingerprint: [0; 32],
                            link_count: Some(1),
                            symlink_target_digest: None,
                        },
                        preimage_identity: None,
                    },
                ))
            }
            fn observe_identity(&self, _path: &Path) -> io::Result<Option<FileIdentity>> {
                Ok(None)
            }
        }

        let adapter = BumpsTheGenerationThenReportsCommitted {
            db_path: db_path.clone(),
            transaction_id: prepared.transaction_id.clone(),
        };
        let result = execute_short_commit_window_unchecked(&mut conn, &adapter, &request, 0);
        assert!(
            matches!(result, Err(CommitWindowError::RequiresRecovery(_))),
            "a failure after the filesystem was mutated must be reported as physical ambiguity, \
             not as an ordinary error a caller reads as 'nothing happened': {result:?}"
        );

        // And the durable record must say the same thing, so a restart
        // reaches the same conclusion this process just did.
        let epoch =
            filesystem_transaction::lookup_epoch(&conn, &prepared.transaction_id, prepared.epoch)
                .unwrap()
                .unwrap();
        assert_eq!(epoch.phase, EpochState::RequiresPhysicalRecovery);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM path_materialized_generations WHERE group_id = ?1 AND path = ?2",
                rusqlite::params!["group", "path.txt"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "the journal write failed, so nothing may claim it succeeded");
    }

    // ---- Defect 2: a failed durability flush must not publish a --------
    // ---- generation --------------------------------------------------

    #[test]
    fn commit_window_routes_a_failed_durability_flush_to_recovery_instead_of_publishing() {
        // `durable_directory_flush` is reported `Supported` here
        // unconditionally, including on Windows where that capability is
        // never actually available (see
        // `honestly_supported_durable_directory_flush`, used by the
        // `accepts_a_request_that_actually_agrees_with_its_epoch` test
        // above). That is intentional and different from that test: this
        // one exists specifically to prove a *failed* flush is routed to
        // recovery rather than silently accepted, so it needs the flush
        // attempted on every platform, not merely the platforms where it
        // could otherwise succeed. The parent directory is removed out
        // from under the window right after the (fake) platform commit
        // succeeds, so the required flush itself fails regardless of
        // whether the capability claim was honest. Before the fix, this
        // failure was discarded (`let _ =`) and `Committed` plus a fresh
        // materialized generation were recorded anyway.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        let identity = FileIdentity {
            volume_identity: yadorilink_root_authority::fs_identity::VolumeIdentity::Unix {
                device_id: 1,
            },
            object_id: yadorilink_root_authority::fs_identity::PlatformObjectId::Unix { inode: 42 },
            object_kind: yadorilink_root_authority::fs_identity::ObjectKind::RegularFile,
            generation_or_usn: None,
            birth_or_creation_time: None,
            observed_size: 0,
            metadata_fingerprint: [0; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        };
        let adapter = FakeCommitAdapter::returning(FilesystemCommitOutcome::Committed(Box::new(
            yadorilink_filesystem_sync::fs_commit::CommittedSnapshot {
                live_identity: identity,
                preimage_identity: None,
            },
        )));

        // Remove the parent directory out from under the window so its own
        // durable-directory-flush genuinely fails, rather than the test
        // asserting on a mocked error. Done via the same test-only seam
        // Defect 1's test uses (it fires after Defect 3's own agreement
        // check has already observed the still-live directory, and before
        // the fake platform commit and this window's flush of it), since
        // removing the directory any earlier would make the agreement
        // check itself fail instead of exercising the flush path.
        let dir_path = dir.path().to_path_buf();
        set_pre_mutation_fence_recheck_hook_for_test(move || {
            std::fs::remove_dir(&dir_path).unwrap();
        });

        let result = execute_short_commit_window_unchecked(&mut conn, &adapter, &request, 0);
        clear_pre_mutation_fence_recheck_hook_for_test();
        assert!(
            matches!(result, Err(CommitWindowError::RequiresRecovery(_))),
            "a failed required flush must route to recovery, not publish: {result:?}"
        );

        // And the generation this window would have published must not
        // exist -- the harm a discarded flush error causes is exactly
        // this: a `path_materialized_generations` row implying success.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM path_materialized_generations WHERE group_id = ?1 AND path = ?2",
                rusqlite::params!["group", "path.txt"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "no generation should have been published after a failed flush");
    }

    #[test]
    fn commit_window_leaves_no_generation_when_the_adapter_reports_requires_recovery_directly() {
        // Distinct from the flush-failure test above: there the platform
        // commit itself succeeded and only the follow-up flush failed. Here
        // the adapter's own platform-level commit is what comes back
        // uncertain (`FilesystemCommitOutcome::RequiresRecovery`), never
        // reaching the flush or the generation write at all. Both paths
        // must agree on the outcome that matters: no row implying a
        // placement happened when the engine cannot confirm it did.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        let adapter = FakeCommitAdapter::returning(FilesystemCommitOutcome::RequiresRecovery(
            Box::new(RecoverySnapshot {
                observed_live: None,
                observed_stage: None,
                observed_preimage: None,
                observed_backup: None,
            }),
        ));

        let result = execute_short_commit_window_unchecked(&mut conn, &adapter, &request, 0);
        assert!(
            matches!(result, Err(CommitWindowError::RequiresRecovery(_))),
            "an uncertain platform outcome must surface as RequiresRecovery: {result:?}"
        );

        let epoch =
            filesystem_transaction::lookup_epoch(&conn, &prepared.transaction_id, prepared.epoch)
                .unwrap()
                .unwrap();
        assert_eq!(
            epoch.phase,
            EpochState::RequiresPhysicalRecovery,
            "an uncertain commit outcome must route the epoch to physical recovery"
        );

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM path_materialized_generations WHERE group_id = ?1 AND path = ?2",
                rusqlite::params!["group", "path.txt"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 0,
            "no generation should have been published for an unconfirmed commit outcome"
        );
    }

    #[test]
    fn commit_window_records_an_absent_generation_for_a_deletion_placement() {
        // §4.2/§7's "absence is a generation too": a deletion committed
        // through this window must publish `object_kind: Absent` with no
        // stale `version`/`filesystem_identity` carried over from whatever
        // `fs_commit::CommittedSnapshot::live_identity` the adapter happens
        // to report. `CommittedSnapshot::live_identity` is a required field
        // on that type (nothing in `fs_commit` yet models "the live path
        // ended up absent" as its own outcome shape), so the fake adapter
        // below supplies one anyway, exactly as a real adapter would have
        // to -- proving the window itself discards it for `Absent` rather
        // than relying on every future caller to pass a meaningless one.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::Absent,
            None,
            &parent,
            "ep0",
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = FilesystemSafetyCapabilities {
            durable_directory_flush: honestly_supported_durable_directory_flush(),
            ..commit_window_capabilities()
        };
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::Absent,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        // A non-absent identity the adapter reports anyway (see the test's
        // doc above) -- must not leak into the recorded generation.
        let reported_identity = FileIdentity {
            volume_identity: yadorilink_root_authority::fs_identity::VolumeIdentity::Unix {
                device_id: 1,
            },
            object_id: yadorilink_root_authority::fs_identity::PlatformObjectId::Unix { inode: 42 },
            object_kind: yadorilink_root_authority::fs_identity::ObjectKind::RegularFile,
            generation_or_usn: None,
            birth_or_creation_time: None,
            observed_size: 0,
            metadata_fingerprint: [0; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        };
        let adapter = FakeCommitAdapter::returning(FilesystemCommitOutcome::Committed(Box::new(
            yadorilink_filesystem_sync::fs_commit::CommittedSnapshot {
                live_identity: reported_identity,
                preimage_identity: None,
            },
        )));

        let result = execute_short_commit_window_unchecked(&mut conn, &adapter, &request, 0)
            .expect("a matching Absent request/epoch must commit");
        assert_eq!(result.generation.object_kind, MaterializedObjectKind::Absent);
        assert!(
            result.generation.version.is_none(),
            "an absent generation must not carry a version"
        );
        assert!(
            result.generation.filesystem_identity.is_none(),
            "an absent generation must not carry the adapter's reported live identity"
        );

        let read =
            materialized_generation::lookup_materialized_generation(&conn, "group", "path.txt")
                .unwrap()
                .unwrap();
        assert_eq!(read, result.generation, "the persisted row must match what was returned");
    }

    // ---- Wiring gap: the `(Committing, Prepared)` retreat had no --------
    // ---- production call site --------------------------------------------

    #[test]
    fn commit_window_retreats_the_epoch_to_prepared_on_a_retryable_notstarted_outcome() {
        // Drives a genuine `FilesystemCommitOutcome::NotStarted` through
        // the real window (not the state machine directly, which the
        // review noted an earlier test claiming to cover this actually
        // did instead). `DestinationDidNotStayAbsent` is the one reason
        // the state machine's own doc names as a proven, retryable no-op:
        // "nothing was touched, try again later".
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        let adapter = FakeCommitAdapter::returning(FilesystemCommitOutcome::NotStarted(
            RetryReason::DestinationDidNotStayAbsent,
        ));

        let result = execute_short_commit_window_unchecked(&mut conn, &adapter, &request, 0);
        assert!(matches!(
            result,
            Err(CommitWindowError::NotStarted(RetryReason::DestinationDidNotStayAbsent))
        ));

        let epoch =
            filesystem_transaction::lookup_epoch(&conn, &prepared.transaction_id, prepared.epoch)
                .unwrap()
                .unwrap();
        assert_eq!(
            epoch.phase,
            EpochState::Prepared,
            "a proven no-op NotStarted outcome must retreat the epoch to Prepared, not leave it \
             at Committing"
        );

        let transaction =
            filesystem_transaction::lookup_transaction(&conn, &prepared.transaction_id)
                .unwrap()
                .unwrap();
        assert_ne!(
            transaction.phase,
            crate::filesystem_transaction::TransactionPhase::Blocked,
            "a retryable outcome must not block the parent saga"
        );

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM path_materialized_generations WHERE group_id = ?1 AND path = ?2",
                rusqlite::params!["group", "path.txt"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 0,
            "a NotStarted outcome touched nothing, so it must publish no generation"
        );
    }

    #[test]
    fn commit_window_blocks_the_transaction_on_a_non_retryable_notstarted_outcome() {
        // Same shape as the retryable test above, but with a reason the
        // state machine's own doc names as its non-retryable example
        // (`UnsupportedOnThisVolume`): retrying the identical plan cannot
        // succeed, so this must take the `(Committing, Blocked)` edge and
        // record why on the parent transaction, not retreat to `Prepared`.
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        open_commit_window_schema(&conn);
        let mut conn = conn;

        let prepared = insert_prepared_epoch(
            &conn,
            "group",
            "path.txt",
            MaterializedObjectKind::RegularFile,
            None,
            &parent,
            "ep0",
        );

        let sync_root_identity = sample_sync_root_identity();
        let capabilities = commit_window_capabilities();
        let commit = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new(&prepared.stage_name),
            live_name: OsStr::new("path.txt"),
            backup_name: OsStr::new(&prepared.backup_name),
            capabilities: &capabilities,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &prepared.staged_identity,
        };
        let request = CommitWindowRequest {
            transaction_id: &prepared.transaction_id,
            epoch: prepared.epoch,
            expected_execution_generation: 0,
            group_id: "group",
            path: "path.txt",
            causal_basis: &[],
            object_kind: MaterializedObjectKind::RegularFile,
            version: None,
            commit,
            reservation_held_since: Instant::now(),
        };

        let adapter = FakeCommitAdapter::returning(FilesystemCommitOutcome::NotStarted(
            RetryReason::UnsupportedOnThisVolume,
        ));

        let result = execute_short_commit_window_unchecked(&mut conn, &adapter, &request, 0);
        assert!(matches!(
            result,
            Err(CommitWindowError::NotStarted(RetryReason::UnsupportedOnThisVolume))
        ));

        let epoch =
            filesystem_transaction::lookup_epoch(&conn, &prepared.transaction_id, prepared.epoch)
                .unwrap()
                .unwrap();
        assert_eq!(
            epoch.phase,
            EpochState::Blocked,
            "a non-retryable NotStarted outcome must block the epoch, not retreat it to Prepared \
             (retrying the identical plan would just fail again)"
        );

        let transaction =
            filesystem_transaction::lookup_transaction(&conn, &prepared.transaction_id)
                .unwrap()
                .unwrap();
        assert_eq!(
            transaction.phase,
            crate::filesystem_transaction::TransactionPhase::Blocked,
            "the parent saga must be blocked too, not just the epoch"
        );
        let blocked_reason = transaction.blocked_reason.unwrap();
        assert!(
            blocked_reason.contains("UnsupportedOnThisVolume"),
            "blocked_reason should record why: {blocked_reason:?}"
        );

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM path_materialized_generations WHERE group_id = ?1 AND path = ?2",
                rusqlite::params!["group", "path.txt"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "a refused/blocked commit must publish no generation");
    }
}
