//! The filesystem transaction engine's durable journal: parent sagas
//! (`filesystem_transactions`), hierarchical path reservations
//! (`filesystem_transaction_reservations`) and placement epochs
//! (`filesystem_transaction_epochs`).
//!
//! # Nothing executes yet
//!
//! [`EXECUTION_ENABLED`] is `false` for the whole of this phase. The
//! tables, types and state-transition rules exist so they can be built and
//! tested; every function in this module that would mutate a row calls
//! [`require_execution_enabled`] first and fails closed with
//! `SyncSqliteError::NotImplemented` while the gate is closed. No production
//! caller reaches this module's mutating half yet — the gate is a second,
//! structural line of defense for whenever one is wired up, so a mistake
//! that adds a caller before this phase's execution semantics are reviewed
//! fails loudly instead of quietly starting to run.
//!
//! One exception, and it is read-only: `dag_store`'s admission path
//! ([`bump_transactions_for_touched_paths`]'s callers) now runs
//! unconditionally on every DAG change, peer-received or locally emitted,
//! to look up whether the change touches a path some live transaction
//! holds. Nothing can hold a reservation while the gate is closed --
//! [`acquire_reservations`] is gated too -- so that lookup always comes back
//! empty and this production caller never actually reaches the mutating
//! half described above until the gate opens.
//!
//! # What this phase does not model
//!
//! `target_generation`, `capability_snapshot` and `displaced_snapshot` are
//! stored as opaque bytes here, not decoded or round-tripped through a
//! typed model. Nothing in this phase produces or consumes their contents
//! — that is the preparation/commit machinery of a later phase, which is
//! also the only code positioned to know exactly what a
//! replayable snapshot of a `FilesystemSafetyCapabilities` or a planned
//! target generation needs to contain. Modeling that now, with no producer
//! or consumer to validate the shape against, would be inventing a value
//! rather than recording one — the same trap this crate already avoided
//! once with `path_materialized_generations.hardlink_group_id`.
//!
//! # Reuse, not a second definition
//!
//! `causal_basis_sets`/`intern_causal_basis` (`yadorilink_sync_core::
//! dag_store::causal_basis`, not yet moved to this crate),
//! [`crate::file_identity_codec::GenerationId`] and its
//! [`FileIdentity`]/[`DirectoryIdentity`] blob encodings, and
//! [`yadorilink_root_authority::fs_capabilities::DurabilityLevel`] are all reused as-is. This
//! module adds no second definition of any of them.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use crate::file_identity_codec::{self as materialized_generation, GenerationId};
use yadorilink_replica_domain::filesystem_placement::{
    EpochState, NewReservation, PlacementRole, ReservationRole, ReservationScope,
};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_root_authority::fs_capabilities::DurabilityLevel;
use yadorilink_root_authority::fs_identity::{
    DirectoryIdentity, FileIdentity, PlatformObjectId, Timestamp, VolumeIdentity, WindowsObjectId,
};

/// Whether the filesystem transaction engine is permitted to execute at
/// all. `false` for the whole of this phase — see the module doc.
/// Forward execution remains disabled. The journal and recovery types are
/// merged as foundations, but production `peer_session::materialize` still
/// uses the legacy path and late semantic recovery is not complete. Do not set
/// this to `true` until all remaining execution blockers are closed together:
/// production routing, full recovery-matrix driving, retained-deletion retry
/// scheduling, and platform validation of every commit/custody primitive.
pub const EXECUTION_ENABLED: bool = false;

/// Every mutating entry point in this module calls this first. Returns
/// `SyncSqliteError::NotImplemented` while [`EXECUTION_ENABLED`] is `false`,
/// rather than silently no-opping — a caller that reaches a mutating
/// function here has a bug (nothing should be calling this module in
/// production yet), and a loud, typed refusal is safer than a silent
/// no-op a caller could mistake for "nothing needed doing".
pub fn require_execution_enabled() -> Result<(), SyncSqliteError> {
    if EXECUTION_ENABLED {
        Ok(())
    } else {
        Err(SyncSqliteError::NotImplemented(
            "filesystem transaction execution (behind a disabled gate for this phase)",
        ))
    }
}

pub fn init_filesystem_transaction_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS filesystem_transactions (
            transaction_id          TEXT NOT NULL PRIMARY KEY,
            group_id                TEXT NOT NULL,
            source_path             TEXT NOT NULL,
            transaction_kind        TEXT NOT NULL,
            cause_kind               TEXT NOT NULL,
            trigger_change_hash      BLOB,
            desired_frontier_hash    BLOB NOT NULL,
            plan_revision            INTEGER NOT NULL,
            execution_generation     INTEGER NOT NULL,
            -- Bumped by every `insert_epoch_unchecked` call for this
            -- transaction, in the same atomic unit as the epoch row it
            -- inserts. `set_transaction_phase_unchecked`'s `Completed`
            -- transition reads this alongside its "every epoch is terminal"
            -- check and binds the value it read into the final UPDATE's own
            -- WHERE clause -- see that function's own doc for why a child
            -- epoch inserted between the check and the write must never be
            -- allowed to complete invisibly.
            epoch_watermark          INTEGER NOT NULL DEFAULT 0,
            phase                    TEXT NOT NULL,
            blocked_reason           TEXT,
            created_at_unix_nanos    INTEGER NOT NULL,
            updated_at_unix_nanos    INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS filesystem_transaction_epochs (
            transaction_id            TEXT NOT NULL,
            epoch                     INTEGER NOT NULL,
            plan_revision             INTEGER NOT NULL,
            target_path               TEXT NOT NULL,
            placement_role            TEXT NOT NULL,
            phase                     TEXT NOT NULL,
            displaced_generation_id   TEXT,
            target_generation         BLOB NOT NULL,
            parent_directory_identity BLOB NOT NULL,
            displaced_snapshot        BLOB,
            stage_path                TEXT,
            preimage_path             TEXT,
            backup_path               TEXT,
            staged_identity           BLOB,
            displaced_identity        BLOB,
            capability_snapshot       BLOB NOT NULL,
            durability_level          TEXT NOT NULL,
            classification_result     TEXT,
            captured_change_hash      BLOB,
            -- Set only by the one writer that can produce an *unresolved*
            -- block: `early_physical_recovery::block`, which reaches
            -- `EpochState::Blocked` from "I could not determine anything"
            -- rather than from a settled decision. See `EpochUpdate::
            -- unresolved_block_reason` for why the epoch's bare `phase`
            -- cannot answer that question and this column can.
            unresolved_block_reason   TEXT,
            encoding_version          INTEGER NOT NULL,
            created_at_unix_nanos     INTEGER NOT NULL,
            updated_at_unix_nanos     INTEGER NOT NULL,
            PRIMARY KEY (transaction_id, epoch)
        );

        CREATE TABLE IF NOT EXISTS filesystem_transaction_reservations (
            reservation_id          TEXT NOT NULL PRIMARY KEY,
            group_id                TEXT NOT NULL,
            transaction_id           TEXT NOT NULL,
            scope_kind               TEXT NOT NULL,
            path                     TEXT NOT NULL,
            path_key                 BLOB NOT NULL,
            subtree_end_key          BLOB NOT NULL,
            role                     TEXT NOT NULL,
            created_at_unix_nanos    INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS filesystem_reservation_range
            ON filesystem_transaction_reservations(group_id, path_key, subtree_end_key);
        "#,
    )?;
    Ok(())
}

fn new_id(prefix: &str) -> String {
    let random: [u8; 16] = rand::random();
    format!("{prefix}-{}", hex::encode(random))
}

/// Runs `f` inside a `BEGIN IMMEDIATE` SQLite transaction on `conn`,
/// committing on `Ok` and rolling back on `Err`. `pub(crate)` so
/// `resolution_planning.rs` (one module over) can share it rather than
/// reimplementing the same raw SQL.
///
/// `conn` is `&Connection`, not `&mut Connection`: every caller this exists
/// for ([`insert_epoch_unchecked`], `resolution_planning::
/// allocate_slice_epochs_unchecked`, `resolution_planning::replan_unchecked`)
/// only ever holds a shared connection reference, because their own callers
/// outside this module (`optimistic_placement.rs`, `early_physical_recovery
/// .rs`, `plan_driver.rs`) do too -- widening any of those signatures to
/// `&mut Connection` would ripple into modules this fix does not own.
/// `rusqlite::Connection::transaction_with_behavior` -- the obvious
/// alternative -- cannot be reused for that reason: it requires
/// `&mut Connection` so it can hand back a `Transaction` borrowing the
/// connection uniquely, a guarantee those call sites cannot supply.
///
/// This is not a substitute for `unchecked_transaction()`'s `DEFERRED`
/// default in general -- it exists specifically because `DEFERRED` is wrong
/// for a transaction that reads before it first writes, if it can ever be
/// raced by a concurrent writer: SQLite grants the read no lock at first,
/// so if another connection commits a conflicting change before this one's
/// first write, that write can fail with `SQLITE_BUSY` against a snapshot
/// that is now stale -- retrying the same statement (which is all
/// `busy_timeout` does) fails again identically, because the transaction
/// never re-reads a fresh snapshot. `BEGIN IMMEDIATE` sidesteps this by
/// acquiring the write lock up front, before `f` runs, so there is no
/// snapshot to go stale out from under it.
///
/// Choosing `BEGIN IMMEDIATE` over `unchecked_transaction()` gives up that
/// call's `rusqlite::Transaction`, and with it the `Drop` impl that rolls
/// back automatically on every exit this function does not explicitly
/// commit. [`ImmediateTransactionGuard`] below puts that back: it is
/// created right after `BEGIN IMMEDIATE` succeeds and rolls back on drop
/// unless [`ImmediateTransactionGuard::commit`] ran to completion, so both
/// a failing `COMMIT` (SQLite can return `SQLITE_BUSY`/`SQLITE_IOERR` from
/// `COMMIT` itself, not only from statements inside the transaction) and
/// `f` panicking and unwinding out of this call still end with the
/// transaction terminated -- connections come from a pool, so an
/// unterminated `BEGIN IMMEDIATE` would otherwise outlive this call and
/// break every later `with_immediate_transaction` on that same connection
/// with "cannot start a transaction within a transaction", with every
/// intervening autocommit statement silently joining the orphaned
/// transaction instead of committing on its own.
///
/// Precondition: `conn` must be in autocommit mode when this is called --
/// i.e. not already inside an open transaction. SQLite does not nest
/// `BEGIN`: issuing `BEGIN IMMEDIATE` on a connection that already has one
/// open returns "cannot start a transaction within a transaction" (the
/// error `execute_batch` above surfaces via `?`), it does not silently join
/// the existing transaction or upgrade its locking. A caller that itself
/// needs to run inside its own already-open transaction cannot call this
/// function as-is; it would need this split into an "already inside a
/// caller-owned transaction" core (taking whatever the caller already has
/// open, no `BEGIN`/`COMMIT` of its own) plus this wrapper, which opens the
/// transaction and calls that core. Savepoints do not help here: a
/// savepoint cannot upgrade an already-open `DEFERRED` transaction to
/// `IMMEDIATE`'s up-front write-lock semantics, which is the entire reason
/// this helper exists over `unchecked_transaction()`'s `DEFERRED` default
/// (see below).
///
/// That split now exists for the one helper that needed it:
/// [`acquire_reservations_in_open_transaction`] is the "already inside a
/// caller-owned transaction" core, and [`acquire_reservations_unchecked`] is
/// the thin wrapper that opens one by calling this function. A caller that
/// needs reservation acquisition to be part of a larger atomic unit calls
/// this function itself and calls the core inside the closure.
///
/// Generic over the closure's error type rather than fixed to [`SyncSqliteError`]:
/// the commit boundary in yadorilink-daemon's `commit_orchestration::orchestrator` fails with its own
/// `OrchestratorError` for the revalidation refusals that have no `SyncSqliteError`
/// spelling, and wrapping those in a `SyncSqliteError` just to satisfy this
/// signature would erase exactly the distinction its caller matches on. `E:
/// From<SyncSqliteError>` is what lets the `BEGIN`/`COMMIT` statements below keep
/// `?`-ing their own errors into the caller's type; every pre-existing
/// caller infers `E = SyncSqliteError` and is unchanged.
pub fn with_immediate_transaction<T, E: From<SyncSqliteError>>(
    conn: &Connection,
    f: impl FnOnce(&Connection) -> Result<T, E>,
) -> Result<T, E> {
    conn.execute_batch("BEGIN IMMEDIATE").map_err(SyncSqliteError::from)?;
    let guard = ImmediateTransactionGuard { conn, committed: false };
    let value = f(conn)?;
    guard.commit()?;
    Ok(value)
}

/// RAII half of [`with_immediate_transaction`] -- see that function's own
/// doc for why this exists instead of a manual rollback-on-`Err` branch.
/// Rolls back on drop unless [`Self::commit`] ran to completion, which
/// covers `f` returning `Err` (the `?` in `with_immediate_transaction`
/// drops this guard before `commit` is ever called) and `f` panicking
/// (unwinding drops it the same way) with the exact same code path.
struct ImmediateTransactionGuard<'c> {
    conn: &'c Connection,
    committed: bool,
}

impl ImmediateTransactionGuard<'_> {
    /// Consumes the guard so a later drop cannot roll back a transaction
    /// this call already committed. If `COMMIT` itself fails, `committed`
    /// is never set and the guard is still dropped in place (`self` is
    /// owned by value), so its `Drop` impl attempts the rollback below --
    /// the failed `COMMIT` never leaves `BEGIN IMMEDIATE` open.
    fn commit(mut self) -> Result<(), SyncSqliteError> {
        self.conn.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for ImmediateTransactionGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Best-effort: if the rollback itself fails there is no further
            // recovery this `Drop` impl can attempt, but issuing it is
            // still strictly better than leaving `BEGIN IMMEDIATE` open on
            // a pooled connection for whatever borrows it next.
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}

// =====================================================================
// Parent transactions
// =====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemTransactionKind {
    ObjectResolution,
    SubtreeReplacement,
}

impl FilesystemTransactionKind {
    fn as_db_str(self) -> &'static str {
        match self {
            FilesystemTransactionKind::ObjectResolution => "object_resolution",
            FilesystemTransactionKind::SubtreeReplacement => "subtree_replacement",
        }
    }

    fn from_db_str(value: &str) -> Result<FilesystemTransactionKind, SyncSqliteError> {
        match value {
            "object_resolution" => Ok(FilesystemTransactionKind::ObjectResolution),
            "subtree_replacement" => Ok(FilesystemTransactionKind::SubtreeReplacement),
            other => Err(SyncSqliteError::CorruptState(format!(
                "unknown filesystem_transactions.transaction_kind {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionCause {
    PeerProjection,
    Hydration,
    Repair,
    Restore,
    RemoteDelete,
    Eviction,
    ConflictResolution,
    ConflictCopyRetirement,
}

impl TransactionCause {
    fn as_db_str(self) -> &'static str {
        match self {
            TransactionCause::PeerProjection => "peer_projection",
            TransactionCause::Hydration => "hydration",
            TransactionCause::Repair => "repair",
            TransactionCause::Restore => "restore",
            TransactionCause::RemoteDelete => "remote_delete",
            TransactionCause::Eviction => "eviction",
            TransactionCause::ConflictResolution => "conflict_resolution",
            TransactionCause::ConflictCopyRetirement => "conflict_copy_retirement",
        }
    }

    fn from_db_str(value: &str) -> Result<TransactionCause, SyncSqliteError> {
        match value {
            "peer_projection" => Ok(TransactionCause::PeerProjection),
            "hydration" => Ok(TransactionCause::Hydration),
            "repair" => Ok(TransactionCause::Repair),
            "restore" => Ok(TransactionCause::Restore),
            "remote_delete" => Ok(TransactionCause::RemoteDelete),
            "eviction" => Ok(TransactionCause::Eviction),
            "conflict_resolution" => Ok(TransactionCause::ConflictResolution),
            "conflict_copy_retirement" => Ok(TransactionCause::ConflictCopyRetirement),
            other => Err(SyncSqliteError::CorruptState(format!(
                "unknown filesystem_transactions.cause_kind {other:?}"
            ))),
        }
    }
}

/// The parent saga's own coarse status — deliberately coarser than
/// [`EpochState`], whose states are transcribed verbatim from a fixed,
/// externally-specified list. The `phase` column that holds this value has
/// no such externally-specified list of values, so this enum is this
/// module's own synthesis, not a transcription: `Planning` and `Committing`
/// name preparation and the short commit window as two separate stages,
/// `AsyncPreservation` names independently-scheduled follow-on work that
/// continues after the canonical namespace is released, `Blocked` is
/// implied by the `blocked_reason` column existing at all, and `Completed`
/// is the terminal state once a current plan is fully satisfied. Confirm
/// this breakdown before anything depends on the exact variant boundaries —
/// unlike `EpochState`, this is inferred, not transcribed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionPhase {
    Planning,
    Committing,
    AsyncPreservation,
    Blocked,
    Completed,
}

impl TransactionPhase {
    fn as_db_str(self) -> &'static str {
        match self {
            TransactionPhase::Planning => "planning",
            TransactionPhase::Committing => "committing",
            TransactionPhase::AsyncPreservation => "async_preservation",
            TransactionPhase::Blocked => "blocked",
            TransactionPhase::Completed => "completed",
        }
    }

    fn from_db_str(value: &str) -> Result<TransactionPhase, SyncSqliteError> {
        match value {
            "planning" => Ok(TransactionPhase::Planning),
            "committing" => Ok(TransactionPhase::Committing),
            "async_preservation" => Ok(TransactionPhase::AsyncPreservation),
            "blocked" => Ok(TransactionPhase::Blocked),
            "completed" => Ok(TransactionPhase::Completed),
            other => Err(SyncSqliteError::CorruptState(format!(
                "unknown filesystem_transactions.phase {other:?}"
            ))),
        }
    }

    /// Whether `self -> to` is a legal saga-level transition. `Blocked` is
    /// reachable from every non-terminal phase (an unrelated failure can
    /// stall a saga at any point) and can resume to `Planning` (a new local
    /// change invalidates the current plan and the saga replans from the
    /// new frontier) — every other edge follows the linear planning ->
    /// committing -> async-preservation -> completed order, with no
    /// skipping and no going backwards except through `Blocked`.
    pub fn can_transition_to(self, to: TransactionPhase) -> bool {
        use TransactionPhase::*;
        match (self, to) {
            (Planning, Committing) => true,
            (Committing, AsyncPreservation) => true,
            (AsyncPreservation, Completed) => true,
            // Replanning returns an in-flight saga to Planning.
            (Committing, Planning) => true,
            (AsyncPreservation, Planning) => true,
            (_, Blocked) if self != Completed && self != Blocked => true,
            (Blocked, Planning) => true,
            _ => false,
        }
    }

    /// Whether a transaction currently at `self` may have a brand-new
    /// placement epoch inserted under it.
    ///
    /// `Planning` is legal because that is the state a saga is in the
    /// moment it (or a replan) first decides what to place -- both
    /// [`begin_transaction_unchecked`] and a replan
    /// (`resolution_planning::replan`, which returns the saga here) leave a
    /// transaction at `Planning` with no epochs yet allocated for the
    /// plan it just adopted. `Committing` is legal because §8.2's real
    /// driver loop moves the saga there *before* allocating each slice's
    /// epochs (see `plan_driver`'s and `orchestrator::run_slice_unchecked`'s
    /// own call ordering) -- by the time the first slice's epochs are
    /// inserted in practice, the saga is already `Committing`, not still
    /// `Planning`.
    ///
    /// `AsyncPreservation` is not legal: by design that phase is reached
    /// only after the canonical namespace has been released, and nothing
    /// under this design allocates a new placement -- which always needs a
    /// canonical-path reservation -- once that release has happened.
    /// `Blocked` is not legal either: it is a stall, not a working state: a
    /// stalled saga's only forward edge is back to `Planning` (a replan),
    /// and a fresh epoch belongs to that replanned `Planning` state, never
    /// to the stall itself. `Completed` is not legal for the reason
    /// [`bump_epoch_watermark_for_new_epoch`]'s own doc already gives in
    /// detail: [`list_incomplete_transactions`] never looks at a
    /// `Completed` transaction again, so an epoch inserted under one would
    /// be permanently invisible to startup recovery.
    fn may_receive_new_epochs(self) -> bool {
        // An exhaustive `match`, deliberately with no wildcard arm: a future
        // `TransactionPhase` variant fails to compile here until someone
        // decides, explicitly, whether it may receive a new epoch. A prior
        // version of this used `matches!(self, Planning | Committing)`,
        // which is a `match` with an implicit `_ => false` -- a new variant
        // would silently default to "not legal" instead of forcing a
        // decision, and (see `bump_epoch_watermark_if_not_completed`, whose
        // SQL is derived from this function) a decision that never happens
        // here can never reach that SQL either.
        match self {
            TransactionPhase::Planning => true,
            TransactionPhase::Committing => true,
            TransactionPhase::AsyncPreservation => false,
            TransactionPhase::Blocked => false,
            TransactionPhase::Completed => false,
        }
    }

    /// `self`'s successor in declaration order, or `None` after the last
    /// variant. The only reason this exists is so [`Self::ALL`] can
    /// enumerate every variant without a second hand-written list sitting
    /// next to this one.
    ///
    /// This `match` has no wildcard arm, so a new variant forces its author
    /// to write an arm here. That is weaker than "the new variant is
    /// necessarily in [`Self::ALL`]", and this doc used to claim the
    /// stronger thing: writing `X => None` and never naming `X` as any other
    /// variant's successor compiles cleanly, the walk still terminates, the
    /// array length is unchanged, and `ALL` silently omits `X`. See
    /// [`Self::ALL`] for exactly which drift the compiler does and does not
    /// catch, and for the runtime check that covers the rest.
    const fn successor(self) -> Option<TransactionPhase> {
        match self {
            TransactionPhase::Planning => Some(TransactionPhase::Committing),
            TransactionPhase::Committing => Some(TransactionPhase::AsyncPreservation),
            TransactionPhase::AsyncPreservation => Some(TransactionPhase::Blocked),
            TransactionPhase::Blocked => Some(TransactionPhase::Completed),
            TransactionPhase::Completed => None,
        }
    }

    /// This variant's position in the enum's declaration order.
    ///
    /// Exists only to give [`Self::ALL`] a real variant *count* to check
    /// itself against. An exhaustive `match` with no wildcard arm forces a
    /// new variant's author to assign it an index; the honest assignment for
    /// a variant added to the enum is the next integer, and [`Self::ALL`]'s
    /// coverage check then indexes a fixed-length array by it, so a variant
    /// added without growing `ALL` (and without extending the
    /// [`Self::successor`] walk to reach it) fails const evaluation rather
    /// than being silently omitted.
    const fn declaration_index(self) -> usize {
        match self {
            TransactionPhase::Planning => 0,
            TransactionPhase::Committing => 1,
            TransactionPhase::AsyncPreservation => 2,
            TransactionPhase::Blocked => 3,
            TransactionPhase::Completed => 4,
        }
    }

    /// Every `TransactionPhase` variant, computed once by walking
    /// [`Self::successor`] from `Planning`. [`bump_epoch_watermark_if_not_completed`]
    /// filters this by [`Self::may_receive_new_epochs`] to build its SQL, so
    /// that SQL and the Rust predicate read from the same enumeration
    /// instead of two hand-maintained lists that could disagree.
    ///
    /// What is actually compile-time checked, precisely -- an earlier
    /// version of this doc claimed the guarantee was total, and it was not:
    ///
    /// - A walk *longer* than the array: the write below runs past the last
    ///   index during const evaluation. Compile error.
    /// - A walk *shorter* than the array (a variant dropped out of the
    ///   successor chain, leaving duplicate `Planning` padding): the
    ///   `i == all.len()` assertion below. Compile error.
    /// - A variant that exists but is nowhere in the walk -- the case this
    ///   doc used to miss entirely, since `X => None` in [`Self::successor`]
    ///   plus no other arm naming `X` compiles perfectly well and leaves the
    ///   length unchanged: the `seen` coverage check below indexes a
    ///   fixed-length array by [`Self::declaration_index`], which an
    ///   exhaustive `match` forces the new variant's author to fill in.
    ///   Assigning the next declaration index (5, for a sixth variant)
    ///   indexes past `seen`. Compile error.
    ///
    /// The one residue: an author who both leaves the variant out of the
    /// walk AND gives it a *duplicate* `declaration_index` defeats the
    /// coverage check. Nothing here catches that, and nothing claims to.
    /// The failure it would produce -- the Rust predicate
    /// [`Self::may_receive_new_epochs`] saying `true` for a phase the
    /// generated SQL never lists -- is what
    /// `bump_epoch_watermark_if_not_completed_binds_the_generated_sql` binds
    /// at runtime for the phases that exist today.
    const ALL: [TransactionPhase; 5] = {
        let mut all = [TransactionPhase::Planning; 5];
        let mut seen = [false; 5];
        let mut i = 1;
        let mut cur = TransactionPhase::Planning;
        seen[cur.declaration_index()] = true;
        while let Some(next) = cur.successor() {
            all[i] = next;
            seen[next.declaration_index()] = true;
            cur = next;
            i += 1;
        }
        assert!(
            i == all.len(),
            "TransactionPhase::successor's walk is shorter than ALL: a variant left the chain"
        );
        let mut j = 0;
        while j < seen.len() {
            assert!(
                seen[j],
                "a TransactionPhase variant is not reachable from ALL's successor walk"
            );
            j += 1;
        }
        all
    };
}

#[derive(Debug, Clone, PartialEq)]
pub struct FilesystemTransactionRecord {
    pub transaction_id: String,
    pub group_id: String,
    pub source_path: String,
    pub kind: FilesystemTransactionKind,
    pub cause: TransactionCause,
    pub trigger_change_hash: Option<ChangeHash>,
    pub desired_frontier_hash: [u8; 32],
    pub plan_revision: i64,
    pub execution_generation: i64,
    /// See the `epoch_watermark` column's own doc on
    /// [`init_filesystem_transaction_schema`]'s schema. Not a fence a
    /// caller is meant to compare against directly (unlike
    /// `execution_generation`) -- `set_transaction_phase_unchecked` is the
    /// only reader that needs it, and it re-reads the current value itself
    /// rather than trusting a possibly-stale one on a record a caller
    /// happens to be holding.
    pub epoch_watermark: i64,
    pub phase: TransactionPhase,
    pub blocked_reason: Option<String>,
    pub created_at_unix_nanos: i64,
    pub updated_at_unix_nanos: i64,
}

pub struct NewFilesystemTransaction<'a> {
    pub group_id: &'a str,
    pub source_path: &'a str,
    pub kind: FilesystemTransactionKind,
    pub cause: TransactionCause,
    pub trigger_change_hash: Option<&'a ChangeHash>,
    pub desired_frontier_hash: [u8; 32],
}

/// Begins a new parent saga: `plan_revision` and `execution_generation`
/// both start at `0`, `phase` at [`TransactionPhase::Planning`]. Gated —
/// see the module doc.
pub fn begin_transaction(
    conn: &Connection,
    new: &NewFilesystemTransaction,
    now_unix_nanos: i64,
) -> Result<FilesystemTransactionRecord, SyncSqliteError> {
    require_execution_enabled()?;
    begin_transaction_unchecked(conn, new, now_unix_nanos)
}

/// The gate-free core of [`begin_transaction`]. `pub(crate)` (not private)
/// so this module's own tests can exercise the real logic directly without
/// [`EXECUTION_ENABLED`] flipped on — a `const bool` gate can't be
/// runtime-toggled per-test, and it must not become one just to make
/// testing easier, so the gate check and the work it guards are split
/// instead. Every other gated function in this module follows the same
/// `x` / `x_unchecked` split for the same reason.
pub fn begin_transaction_unchecked(
    conn: &Connection,
    new: &NewFilesystemTransaction,
    now_unix_nanos: i64,
) -> Result<FilesystemTransactionRecord, SyncSqliteError> {
    let transaction_id = new_id("fstx");
    conn.execute(
        "INSERT INTO filesystem_transactions \
            (transaction_id, group_id, source_path, transaction_kind, cause_kind, \
             trigger_change_hash, desired_frontier_hash, plan_revision, execution_generation, \
             epoch_watermark, phase, blocked_reason, created_at_unix_nanos, \
             updated_at_unix_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, 0, ?8, NULL, ?9, ?9)",
        rusqlite::params![
            transaction_id,
            new.group_id,
            new.source_path,
            new.kind.db_str(),
            new.cause.db_str(),
            new.trigger_change_hash.map(|h| &h.0[..]),
            &new.desired_frontier_hash[..],
            TransactionPhase::Planning.db_str(),
            now_unix_nanos,
        ],
    )?;
    Ok(FilesystemTransactionRecord {
        transaction_id,
        group_id: new.group_id.to_string(),
        source_path: new.source_path.to_string(),
        kind: new.kind,
        cause: new.cause,
        trigger_change_hash: new.trigger_change_hash.copied(),
        desired_frontier_hash: new.desired_frontier_hash,
        plan_revision: 0,
        execution_generation: 0,
        epoch_watermark: 0,
        phase: TransactionPhase::Planning,
        blocked_reason: None,
        created_at_unix_nanos: now_unix_nanos,
        updated_at_unix_nanos: now_unix_nanos,
    })
}

#[allow(clippy::type_complexity)]
fn row_to_transaction(
    row: (
        String,
        String,
        String,
        String,
        String,
        Option<Vec<u8>>,
        Vec<u8>,
        i64,
        i64,
        i64,
        String,
        Option<String>,
        i64,
        i64,
    ),
) -> Result<FilesystemTransactionRecord, SyncSqliteError> {
    let (
        transaction_id,
        group_id,
        source_path,
        kind,
        cause,
        trigger_change_hash,
        desired_frontier_hash,
        plan_revision,
        execution_generation,
        epoch_watermark,
        phase,
        blocked_reason,
        created_at_unix_nanos,
        updated_at_unix_nanos,
    ) = row;
    let trigger_change_hash = trigger_change_hash
        .map(|bytes| {
            let hash: [u8; 32] = bytes.try_into().map_err(|_| {
                SyncSqliteError::CorruptState(format!(
                    "invalid trigger_change_hash length for transaction {transaction_id}"
                ))
            })?;
            Ok::<_, SyncSqliteError>(ChangeHash(hash))
        })
        .transpose()?;
    let desired_frontier_hash: [u8; 32] = desired_frontier_hash.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "invalid desired_frontier_hash length for transaction {transaction_id}"
        ))
    })?;
    Ok(FilesystemTransactionRecord {
        kind: FilesystemTransactionKind::from_db_str(&kind)?,
        cause: TransactionCause::from_db_str(&cause)?,
        phase: TransactionPhase::from_db_str(&phase)?,
        transaction_id,
        group_id,
        source_path,
        trigger_change_hash,
        desired_frontier_hash,
        plan_revision,
        execution_generation,
        epoch_watermark,
        blocked_reason,
        created_at_unix_nanos,
        updated_at_unix_nanos,
    })
}

pub fn lookup_transaction(
    conn: &Connection,
    transaction_id: &str,
) -> Result<Option<FilesystemTransactionRecord>, SyncSqliteError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        Option<Vec<u8>>,
        Vec<u8>,
        i64,
        i64,
        i64,
        String,
        Option<String>,
        i64,
        i64,
    )> = conn
        .query_row(
            "SELECT transaction_id, group_id, source_path, transaction_kind, cause_kind, \
                    trigger_change_hash, desired_frontier_hash, plan_revision, \
                    execution_generation, epoch_watermark, phase, blocked_reason, \
                    created_at_unix_nanos, updated_at_unix_nanos \
             FROM filesystem_transactions WHERE transaction_id = ?1",
            [transaction_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                ))
            },
        )
        .optional()?;
    row.map(row_to_transaction).transpose()
}

/// Every transaction whose parent-saga `phase` has not reached
/// [`TransactionPhase::Completed`] — the set early physical recovery
/// (`early_physical_recovery`) must load at startup, per the design's §14.1
/// "load active transactions, epochs and retained obligations". Read-only,
/// so unlike every mutating entry point in this module it is not gated
/// behind [`require_execution_enabled`]: recovery must be able to inspect
/// this journal even while the engine itself is not yet permitted to
/// execute.
pub fn list_incomplete_transactions(
    conn: &Connection,
) -> Result<Vec<FilesystemTransactionRecord>, SyncSqliteError> {
    #[allow(clippy::type_complexity)]
    let mut stmt = conn.prepare(
        "SELECT transaction_id, group_id, source_path, transaction_kind, cause_kind, \
                trigger_change_hash, desired_frontier_hash, plan_revision, \
                execution_generation, epoch_watermark, phase, blocked_reason, \
                created_at_unix_nanos, updated_at_unix_nanos \
         FROM filesystem_transactions WHERE phase != ?1 ORDER BY transaction_id",
    )?;
    let rows = stmt
        .query_map([TransactionPhase::Completed.db_str()], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
                r.get(9)?,
                r.get(10)?,
                r.get(11)?,
                r.get(12)?,
                r.get(13)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(row_to_transaction).collect()
}

/// Checks `transaction_id`'s current `execution_generation` against
/// `expected` — the fencing check every transition and the moment
/// immediately before every filesystem commit must perform. Not gated by
/// [`EXECUTION_ENABLED`]: this is a read-only verification, harmless to
/// call regardless, and tests need it callable on its own.
pub fn check_execution_generation(
    conn: &Connection,
    transaction_id: &str,
    expected: i64,
) -> Result<(), SyncSqliteError> {
    let current: i64 = conn
        .query_row(
            "SELECT execution_generation FROM filesystem_transactions WHERE transaction_id = ?1",
            [transaction_id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| {
            SyncSqliteError::NotFound(format!("filesystem transaction {transaction_id}"))
        })?;
    if current != expected {
        return Err(SyncSqliteError::ExecutionGenerationFenced {
            transaction_id: transaction_id.to_string(),
            expected,
            current,
        });
    }
    Ok(())
}

/// Advances `transaction_id`'s `execution_generation` by one — replanning,
/// cancellation and startup adoption all call this. Gated.
pub fn increment_execution_generation(
    conn: &Connection,
    transaction_id: &str,
) -> Result<i64, SyncSqliteError> {
    require_execution_enabled()?;
    increment_execution_generation_unchecked(conn, transaction_id)
}

pub fn increment_execution_generation_unchecked(
    conn: &Connection,
    transaction_id: &str,
) -> Result<i64, SyncSqliteError> {
    let next: Option<i64> = conn
        .query_row(
            "UPDATE filesystem_transactions SET execution_generation = execution_generation + 1 \
             WHERE transaction_id = ?1 RETURNING execution_generation",
            [transaction_id],
            |r| r.get(0),
        )
        .optional()?;
    next.ok_or_else(|| {
        SyncSqliteError::NotFound(format!("filesystem transaction {transaction_id}"))
    })
}

/// Sets `transaction_id`'s `plan_revision` to `new_plan_revision`, but only
/// if it is still `expected_plan_revision` -- replanning
/// (`resolution_planning::replan`) calls this once it has moved the saga
/// back to [`TransactionPhase::Planning`], passing the value it read
/// `plan_revision` at just before deciding to replan. Deliberately distinct
/// from [`increment_execution_generation`]: `execution_generation` fences
/// stale in-flight work and is bumped by whoever admits a new local DAG
/// change (design §6.3); `plan_revision` merely names which versioned plan
/// a placement epoch (`filesystem_transaction_epochs.plan_revision`)
/// belongs to, and this function is the only writer of it after
/// [`begin_transaction`] sets it to `0`. No legality check against the
/// current phase is performed here -- unlike `execution_generation`, a plan
/// revision has no illegal-jump table of its own to enforce; the caller's
/// own phase transition (already fenced and validated) is what makes a
/// replan legal in the first place.
///
/// `expected_plan_revision` is a genuine compare-and-swap, bound into this
/// `UPDATE`'s own `WHERE` clause rather than checked by a separate read
/// beforehand -- the same reasoning [`transition_epoch_unchecked`]'s own doc
/// gives for why a check whose result is not bound into the statement it
/// authorizes is not a check. Before this parameter existed, two concurrent
/// replans could both read `plan_revision == N`, both compute `N + 1`, and
/// both write it: the second write would silently re-apply the same value
/// over the first's instead of failing, so two different plans could end up
/// sharing one `plan_revision` number that was supposed to distinguish them.
/// With the CAS, only the write that observed the row still at
/// `expected_plan_revision` may apply; the other matches zero rows and the
/// caller learns its view was already stale. Gated.
pub fn set_plan_revision(
    conn: &Connection,
    transaction_id: &str,
    expected_plan_revision: i64,
    new_plan_revision: i64,
) -> Result<(), SyncSqliteError> {
    require_execution_enabled()?;
    set_plan_revision_unchecked(conn, transaction_id, expected_plan_revision, new_plan_revision)
}

pub fn set_plan_revision_unchecked(
    conn: &Connection,
    transaction_id: &str,
    expected_plan_revision: i64,
    new_plan_revision: i64,
) -> Result<(), SyncSqliteError> {
    let rows_changed = conn.execute(
        "UPDATE filesystem_transactions SET plan_revision = ?1 \
         WHERE transaction_id = ?2 AND plan_revision = ?3",
        rusqlite::params![new_plan_revision, transaction_id, expected_plan_revision],
    )?;
    if rows_changed == 0 {
        // Distinguish "the transaction is gone" from "the transaction is
        // still there but plan_revision already moved" -- the same
        // re-derivation pattern `set_transaction_phase_unchecked` and
        // `transition_epoch_unchecked` use after their own CAS misses.
        let current: Option<i64> = conn
            .query_row(
                "SELECT plan_revision FROM filesystem_transactions WHERE transaction_id = ?1",
                [transaction_id],
                |r| r.get(0),
            )
            .optional()?;
        return match current {
            None => {
                Err(SyncSqliteError::NotFound(format!("filesystem transaction {transaction_id}")))
            }
            Some(current_plan_revision) => Err(SyncSqliteError::TransitionRaced {
                subject: format!("filesystem transaction {transaction_id} plan_revision"),
                expected_state: format!("plan_revision {expected_plan_revision}"),
                current_state: format!("plan_revision {current_plan_revision}"),
            }),
        };
    }
    Ok(())
}

/// Records the frontier the transaction's CURRENT plan was built from —
/// design §6.1 step 2, "persist plan_revision and desired_frontier_hash",
/// whose two halves must move together.
///
/// [`begin_transaction`] wrote this column once and nothing updated it
/// afterwards, so from the first replan onwards the row named the frontier
/// of a plan that had already been superseded. Nothing read it for a
/// decision, which is the only reason that was not a live defect: the value
/// `resolution_planning::plan_is_stale` actually compares is the one the
/// in-memory `FilesystemResolutionPlan` captured. A durable field that
/// disagrees with the value the system decides on is worth removing or
/// keeping truthful, not leaving as a plausible-looking second source; the
/// plan driver keeps it truthful by calling this every time it builds a
/// plan.
///
/// No phase check, for the same reason [`set_plan_revision`] has none: this
/// records which plan exists, it does not authorize anything.
///
/// It IS a fenced compare-and-swap, bound into the `UPDATE`'s own `WHERE`
/// clause rather than checked by a separate read beforehand -- the same
/// reasoning [`set_plan_revision`] and [`transition_epoch_unchecked`] give
/// for why a check whose result is not bound into the statement it
/// authorizes is not a check. Without it: worker A reads generation 4 and
/// spends time building a plan whose frontier hash is HA; meanwhile worker B
/// admits a DAG change, replans (which bumps both `execution_generation` and
/// `plan_revision` together -- see `resolution_planning::replan_unchecked`),
/// builds its own plan, and records its frontier hash HB; worker A then
/// resumes and overwrites HB with HA. Allocation is fenced already, so A
/// cannot go on to insert epochs under its stale plan -- but the durable
/// record of which frontier the CURRENT plan belongs to would be left false,
/// silently naming a plan nothing is executing.
///
/// Both `expected_execution_generation` and `expected_plan_revision` are
/// bound, not just the generation. `replan_unchecked` always advances both
/// together today, so a generation-only fence would already refuse the
/// interleaving above. The plan_revision fence is bound anyway because it is
/// the value this column's own doc says the hash describes ("the frontier
/// the transaction's CURRENT plan was built from... whose two halves must
/// move together") -- CAS-ing on the identifier the hash actually describes
/// is the direct guarantee, and it does not depend on staying in sync with
/// whatever `replan_unchecked` happens to do to the generation column on any
/// future refactor.
pub fn set_desired_frontier_hash(
    conn: &Connection,
    transaction_id: &str,
    expected_execution_generation: i64,
    expected_plan_revision: i64,
    desired_frontier_hash: [u8; 32],
) -> Result<(), SyncSqliteError> {
    require_execution_enabled()?;
    set_desired_frontier_hash_unchecked(
        conn,
        transaction_id,
        expected_execution_generation,
        expected_plan_revision,
        desired_frontier_hash,
    )
}

pub fn set_desired_frontier_hash_unchecked(
    conn: &Connection,
    transaction_id: &str,
    expected_execution_generation: i64,
    expected_plan_revision: i64,
    desired_frontier_hash: [u8; 32],
) -> Result<(), SyncSqliteError> {
    let rows_changed = conn.execute(
        "UPDATE filesystem_transactions SET desired_frontier_hash = ?1 \
         WHERE transaction_id = ?2 AND execution_generation = ?3 AND plan_revision = ?4",
        rusqlite::params![
            &desired_frontier_hash[..],
            transaction_id,
            expected_execution_generation,
            expected_plan_revision,
        ],
    )?;
    if rows_changed == 0 {
        // Distinguish "the transaction is gone" from "the transaction is
        // still there but generation and/or plan_revision already moved" --
        // the same re-derivation pattern `set_plan_revision_unchecked`,
        // `set_transaction_phase_unchecked` and `transition_epoch_unchecked`
        // use after their own CAS misses.
        let current: Option<(i64, i64)> = conn
            .query_row(
                "SELECT execution_generation, plan_revision FROM filesystem_transactions \
                 WHERE transaction_id = ?1",
                [transaction_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        return match current {
            None => {
                Err(SyncSqliteError::NotFound(format!("filesystem transaction {transaction_id}")))
            }
            Some((current_generation, current_plan_revision)) => {
                Err(SyncSqliteError::TransitionRaced {
                    subject: format!(
                        "filesystem transaction {transaction_id} desired_frontier_hash"
                    ),
                    expected_state: format!(
                        "execution_generation {expected_execution_generation}, plan_revision \
                     {expected_plan_revision}"
                    ),
                    current_state: format!(
                        "execution_generation {current_generation}, plan_revision \
                     {current_plan_revision}"
                    ),
                })
            }
        };
    }
    Ok(())
}

/// Moves `transaction_id` to phase `to`, after checking the
/// `execution_generation` fence and the phase transition's legality
/// ([`TransactionPhase::can_transition_to`]). Gated.
pub fn set_transaction_phase(
    conn: &Connection,
    transaction_id: &str,
    expected_execution_generation: i64,
    to: TransactionPhase,
    blocked_reason: Option<&str>,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    require_execution_enabled()?;
    set_transaction_phase_unchecked(
        conn,
        transaction_id,
        expected_execution_generation,
        to,
        blocked_reason,
        now_unix_nanos,
    )
}

pub fn set_transaction_phase_unchecked(
    conn: &Connection,
    transaction_id: &str,
    expected_execution_generation: i64,
    to: TransactionPhase,
    blocked_reason: Option<&str>,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    check_execution_generation(conn, transaction_id, expected_execution_generation)?;
    let record = lookup_transaction(conn, transaction_id)?.ok_or_else(|| {
        SyncSqliteError::NotFound(format!("filesystem transaction {transaction_id}"))
    })?;
    if !record.phase.can_transition_to(to) {
        return Err(SyncSqliteError::InvalidInput(format!(
            "filesystem transaction {transaction_id}: {:?} -> {to:?} is not a legal phase transition",
            record.phase
        )));
    }
    // Defect 2: a parent saga must not be allowed to reach `Completed`
    // while any of its placement epochs is still *in flight* -- most
    // importantly not while one is still at `Committing`. Startup
    // recovery's `Committing`-epoch sweep (`early_physical_recovery`) only
    // ever looks at epochs under a transaction `list_incomplete_transactions`
    // returns, i.e. one whose `phase` is not yet `Completed`. If a parent
    // could complete out from under a `Committing` child epoch, a restart
    // after that point would never enumerate that epoch again -- it would
    // sit at `Committing` forever, never physically inspected.
    //
    // The gate is "every epoch is terminal" (`EpochState::is_terminal`),
    // *not* "every epoch reached `Completed`". Two of the three terminal
    // states -- `Quarantined`, `Blocked` -- can never reach `Completed` at
    // all (`can_transition_to` models no outgoing edge from either), each
    // because that state already *is* a settled outcome for that one epoch,
    // not a waypoint to one: `Quarantined` is a legitimate, deliberate
    // outcome for a preserved-but-unresolved object, not a saga failure;
    // `Blocked` is what a saga-level replan (`TransactionPhase::Blocked ->
    // Planning`) leaves behind once it allocates a brand-new epoch (epoch
    // numbers are never reused, so the old one cannot become that
    // replacement) to actually finish the work. Requiring `Completed` from
    // both would make a transaction that ever quarantines or
    // blocks-and-replans permanently unable to complete -- turning a
    // recoverable outcome into a stuck saga.
    //
    // `RequiresPhysicalRecovery` is deliberately *not* one of the terminal
    // states this gate lets slide -- see `EpochState::is_terminal`'s own
    // doc. An epoch sitting there has not yet had its §14.2 verdict
    // (complete forward / roll back / convert to a new capture epoch), so a
    // parent transaction must keep waiting for it exactly like it waits for
    // `Committing`, not be let through on the assumption that nothing is
    // owed to it.
    //
    // Only genuinely in-flight states (everything `is_terminal` says no to,
    // including `Committing` and `RequiresPhysicalRecovery`) still owe
    // recovery a look.
    //
    // Enforcing this here, at the one call site that can ever produce a
    // `Completed` transaction, closes the gap by construction: recovery's
    // existing `list_incomplete_transactions` + `list_epochs_for_transaction`
    // pairing (`early_physical_recovery.rs`) needs no change at all, because
    // once a transaction is excluded from the incomplete set, every epoch
    // under it is provably already terminal -- settled, one way or another.
    // The alternative -- teaching recovery's enumeration to also find
    // `Committing` epochs under completed parents -- would still leave the
    // question of why that state was reachable in the first place, and
    // would need to run on every startup instead of costing one indexed
    // range scan on the one transition that can create the state.
    if to == TransactionPhase::Completed {
        let epochs = list_epochs_for_transaction(conn, transaction_id)?;
        if let Some(unfinished) = epochs.iter().find(|e| !e.phase.is_terminal()) {
            return Err(SyncSqliteError::InvalidInput(format!(
                "filesystem transaction {transaction_id}: cannot complete while epoch {} is at \
                 {:?}, which is still in flight -- every epoch must reach a terminal state \
                 (Completed, Quarantined or Blocked) before its parent can, otherwise an \
                 in-flight epoch under a completed parent would never be found by startup \
                 recovery's incomplete-transaction sweep",
                unfinished.epoch, unfinished.phase
            )));
        }
    }
    // The generation fence must hold on the UPDATE itself, not only on the
    // `check_execution_generation` read above -- otherwise a concurrent
    // `increment_execution_generation` landing between that read and this
    // write would go unnoticed on a plain autocommit `&Connection` (the
    // only case that isn't already protected by the caller's own
    // `IMMEDIATE` transaction plus WAL's `SQLITE_BUSY_SNAPSHOT`). The
    // predicate also carries `phase = ?6`, the exact phase the legality
    // check above validated `to` against -- without it, two siblings that
    // both read the row at the same phase and generation but decided
    // different (both individually legal) destinations could each pass
    // their own `can_transition_to` check, and whichever UPDATE lands
    // second would silently overwrite the first's destination, since
    // `transaction_id` and `execution_generation` alone still match. Naming
    // the source phase in the `WHERE` makes this a genuine compare-and-swap:
    // only the transition that observed the row in the state it is still in
    // may apply.
    //
    // For `to == Completed` specifically, the predicate also carries
    // `epoch_watermark = ?7`, the value `record` (read above, before the
    // "every epoch is terminal" check) already carried. `insert_epoch_
    // unchecked` bumps this same column in the same atomic unit as the
    // epoch row it inserts (see that column's own doc on the schema), so a
    // child epoch inserted by another connection *after* this call's
    // terminal-epoch read but *before* this UPDATE lands changes the
    // watermark this predicate is bound to, and the UPDATE below matches
    // zero rows instead of completing over an epoch it never saw. Without
    // this, the epoch-terminal check above and this UPDATE are two separate
    // statements on a plain autocommit connection with nothing enforcing
    // atomicity between them, and `insert_epoch_unchecked` checks neither
    // this transaction's phase nor its generation before inserting --
    // exactly the gap a sibling connection could exploit to insert a fresh
    // `Allocated` epoch into that window and have it silently excluded from
    // `list_incomplete_transactions` the moment this UPDATE lands, since the
    // parent it belongs to would already read back as `Completed`. Other
    // destinations (`Planning`, `Committing`, `AsyncPreservation`,
    // `Blocked`) have no such hazard -- epochs are ordinarily inserted while
    // a saga is still active, and gating every transition on this column
    // would just make ordinary concurrent epoch allocation spuriously race
    // unrelated phase moves -- so the predicate is scoped to `Completed`
    // alone, the one destination `list_incomplete_transactions` treats as
    // "recovery will never look here again".
    let rows_changed = if to == TransactionPhase::Completed {
        conn.execute(
            "UPDATE filesystem_transactions SET phase = ?1, blocked_reason = ?2, \
             updated_at_unix_nanos = ?3 WHERE transaction_id = ?4 AND execution_generation = ?5 \
             AND phase = ?6 AND epoch_watermark = ?7",
            rusqlite::params![
                to.db_str(),
                blocked_reason,
                now_unix_nanos,
                transaction_id,
                expected_execution_generation,
                record.phase.db_str(),
                record.epoch_watermark,
            ],
        )?
    } else {
        conn.execute(
            "UPDATE filesystem_transactions SET phase = ?1, blocked_reason = ?2, \
             updated_at_unix_nanos = ?3 WHERE transaction_id = ?4 AND execution_generation = ?5 \
             AND phase = ?6",
            rusqlite::params![
                to.db_str(),
                blocked_reason,
                now_unix_nanos,
                transaction_id,
                expected_execution_generation,
                record.phase.db_str(),
            ],
        )?
    };
    if rows_changed == 0 {
        // Re-derive the precise refusal. In order: the generation moved
        // (the original fence's own case), the transaction vanished
        // entirely (also reported by `check_execution_generation`), the
        // generation still matches but the phase itself moved under us (a
        // sibling transition raced this one and won), or -- only reachable
        // for `to == Completed` -- the phase still matches too but a child
        // epoch was inserted in the race window described above. The final
        // fallback only fires if none of those hold, which should not be
        // reachable.
        check_execution_generation(conn, transaction_id, expected_execution_generation)?;
        let current = lookup_transaction(conn, transaction_id)?.ok_or_else(|| {
            SyncSqliteError::NotFound(format!("filesystem transaction {transaction_id}"))
        })?;
        if current.phase != record.phase {
            return Err(SyncSqliteError::TransitionRaced {
                subject: format!("filesystem transaction {transaction_id}"),
                expected_state: record.phase.db_str().to_string(),
                current_state: current.phase.db_str().to_string(),
            });
        }
        if to == TransactionPhase::Completed && current.epoch_watermark != record.epoch_watermark {
            return Err(SyncSqliteError::TransitionRaced {
                subject: format!("filesystem transaction {transaction_id}"),
                expected_state: format!("epoch_watermark {}", record.epoch_watermark),
                current_state: format!("epoch_watermark {}", current.epoch_watermark),
            });
        }
        return Err(SyncSqliteError::ExecutionGenerationFenced {
            transaction_id: transaction_id.to_string(),
            expected: expected_execution_generation,
            current: expected_execution_generation,
        });
    }
    Ok(())
}

// =====================================================================
// Placement epochs
// =====================================================================

// `EpochState` (and its `can_transition_to`/`is_terminal` methods) moved to
// `yadorilink_replica_domain::filesystem_placement` (Phase 7D-9D) -- see
// that module's own doc for why: `yadorilink-sync-core::resolution_
// planning`'s pure functions need it too, and this crate already depends on
// `yadorilink-replica-engine`, so leaving the type defined here would make
// that crate depending on it a straight two-crate cycle. The SQL-string
// codec below stays behind as a local trait (an inherent `impl` needs this
// crate to own the type, which it no longer does) so the exact
// `Result<_, SyncSqliteError>` corrupt-row error path is unchanged.
trait EpochStateDbCodec {
    fn db_str(self) -> &'static str;
    fn from_db_str(value: &str) -> Result<EpochState, SyncSqliteError>;
}

impl EpochStateDbCodec for EpochState {
    fn db_str(self) -> &'static str {
        match self {
            EpochState::Allocated => "allocated",
            EpochState::Preparing => "preparing",
            EpochState::PreparedArtifact => "prepared_artifact",
            EpochState::AwaitingReservation => "awaiting_reservation",
            EpochState::Prepared => "prepared",
            EpochState::Committing => "committing",
            EpochState::Committed => "committed",
            EpochState::Quarantined => "quarantined",
            EpochState::RequiresPhysicalRecovery => "requires_physical_recovery",
            EpochState::CustodyTransferred => "custody_transferred",
            EpochState::AwaitingQuiescence => "awaiting_quiescence",
            EpochState::ClassifiedKnown => "classified_known",
            EpochState::ClassifiedDivergent => "classified_divergent",
            EpochState::AwaitingCaptureStorage => "awaiting_capture_storage",
            EpochState::AwaitingCaptureAuthorization => "awaiting_capture_authorization",
            EpochState::CapturedChangeAuthored => "captured_change_authored",
            EpochState::LocalRecoveryOnly => "local_recovery_only",
            EpochState::Released => "released",
            EpochState::Completed => "completed",
            EpochState::Blocked => "blocked",
        }
    }

    fn from_db_str(value: &str) -> Result<EpochState, SyncSqliteError> {
        Ok(match value {
            "allocated" => EpochState::Allocated,
            "preparing" => EpochState::Preparing,
            "prepared_artifact" => EpochState::PreparedArtifact,
            "awaiting_reservation" => EpochState::AwaitingReservation,
            "prepared" => EpochState::Prepared,
            "committing" => EpochState::Committing,
            "committed" => EpochState::Committed,
            "quarantined" => EpochState::Quarantined,
            "requires_physical_recovery" => EpochState::RequiresPhysicalRecovery,
            "custody_transferred" => EpochState::CustodyTransferred,
            "awaiting_quiescence" => EpochState::AwaitingQuiescence,
            "classified_known" => EpochState::ClassifiedKnown,
            "classified_divergent" => EpochState::ClassifiedDivergent,
            "awaiting_capture_storage" => EpochState::AwaitingCaptureStorage,
            "awaiting_capture_authorization" => EpochState::AwaitingCaptureAuthorization,
            "captured_change_authored" => EpochState::CapturedChangeAuthored,
            "local_recovery_only" => EpochState::LocalRecoveryOnly,
            "released" => EpochState::Released,
            "completed" => EpochState::Completed,
            "blocked" => EpochState::Blocked,
            other => {
                return Err(SyncSqliteError::CorruptState(format!(
                    "unknown filesystem_transaction_epochs.phase {other:?}"
                )))
            }
        })
    }
}

// `PlacementRole` moved to `yadorilink_replica_domain::filesystem_placement`
// alongside `EpochState` (Phase 7D-9D) -- see that module's own doc. Same
// local-trait codec pattern as `EpochStateDbCodec` above.
trait PlacementRoleDbCodec {
    fn db_str(self) -> &'static str;
    fn from_db_str(value: &str) -> Result<PlacementRole, SyncSqliteError>;
}

impl PlacementRoleDbCodec for PlacementRole {
    fn db_str(self) -> &'static str {
        match self {
            PlacementRole::CanonicalPath => "canonical_path",
            PlacementRole::ConflictCopy => "conflict_copy",
            PlacementRole::RetirementTarget => "retirement_target",
        }
    }

    fn from_db_str(value: &str) -> Result<PlacementRole, SyncSqliteError> {
        match value {
            "canonical_path" => Ok(PlacementRole::CanonicalPath),
            "conflict_copy" => Ok(PlacementRole::ConflictCopy),
            "retirement_target" => Ok(PlacementRole::RetirementTarget),
            other => Err(SyncSqliteError::CorruptState(format!(
                "unknown filesystem_transaction_epochs.placement_role {other:?}"
            ))),
        }
    }
}

fn durability_level_as_db_str(level: DurabilityLevel) -> &'static str {
    match level {
        DurabilityLevel::ProcessCrashSafe => "process_crash_safe",
        DurabilityLevel::PowerLossSafe => "power_loss_safe",
        DurabilityLevel::BestEffortRemoteFilesystem => "best_effort_remote_filesystem",
        DurabilityLevel::Unsupported => "unsupported",
    }
}

fn durability_level_from_db_str(value: &str) -> Result<DurabilityLevel, SyncSqliteError> {
    match value {
        "process_crash_safe" => Ok(DurabilityLevel::ProcessCrashSafe),
        "power_loss_safe" => Ok(DurabilityLevel::PowerLossSafe),
        "best_effort_remote_filesystem" => Ok(DurabilityLevel::BestEffortRemoteFilesystem),
        "unsupported" => Ok(DurabilityLevel::Unsupported),
        other => Err(SyncSqliteError::CorruptState(format!(
            "unknown filesystem_transaction_epochs.durability_level {other:?}"
        ))),
    }
}

/// Bumped from 1 to 2 alongside `materialized_generation::
/// MATERIALIZED_GENERATION_ENCODING_VERSION` for the same reason: `Volume
/// Identity::Windows`'s serial number widened from 32 to 64 bits and
/// `PlatformObjectId::Windows` gained the proven/fallback split (see
/// `WindowsObjectId`). No migration -- pre-release, so an old blob fails
/// closed on decode rather than being reinterpreted.
// Bumped 2 -> 3: `DirectoryIdentity` gained `birth_or_creation_time` (see
// its struct doc in `fs_identity.rs` for why the field was missing rather
// than merely absent-on-some-platforms). This project is pre-release —
// no migration is written; a v2-stamped row refuses to decode below
// rather than being silently misread as the new, larger shape.
pub const EPOCH_ENCODING_VERSION: i32 = 3;

/// Encodes a [`DirectoryIdentity`] for `parent_directory_identity` — see
/// the module doc: recording this, rather than re-deriving it, is what
/// lets recovery prove a reopened handle is still the same directory after
/// a parent rename or a mount replacement. Reuses
/// `materialized_generation`'s `Reader` cursor rather than a second one.
///
/// `pub(crate)`, not private: `orchestrator.rs` (Phase 12) needs to encode
/// the same parent-directory identity it already passed into this module's
/// own `NewEpoch::parent_directory_identity` into the byte form
/// `retained_obligation::NewObligation::parent_directory_identity` expects.
/// Reusing this function is what keeps the two modules' encodings from
/// silently drifting apart; it does not change this function's behaviour.
pub fn encode_directory_identity(identity: &DirectoryIdentity) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(EPOCH_ENCODING_VERSION as u8);
    match identity.volume_identity {
        VolumeIdentity::Unix { device_id } => {
            buf.push(0);
            buf.extend_from_slice(&device_id.to_be_bytes());
        }
        VolumeIdentity::Windows { volume_serial_number } => {
            buf.push(1);
            buf.extend_from_slice(&volume_serial_number.to_be_bytes());
        }
    }
    match identity.object_id {
        PlatformObjectId::Unix { inode } => {
            buf.push(0);
            buf.extend_from_slice(&inode.to_be_bytes());
        }
        PlatformObjectId::Windows(w) => {
            buf.push(1);
            match w {
                WindowsObjectId::Fallback { file_index } => {
                    buf.push(0);
                    buf.extend_from_slice(&file_index.to_be_bytes());
                }
                WindowsObjectId::Proven { file_id } => {
                    buf.push(1);
                    buf.extend_from_slice(&file_id);
                }
            }
        }
    }
    match identity.generation_or_usn {
        Some(g) => {
            buf.push(1);
            buf.extend_from_slice(&g.to_be_bytes());
        }
        None => buf.push(0),
    }
    match identity.birth_or_creation_time {
        Some(t) => {
            buf.push(1);
            buf.extend_from_slice(&(t.seconds_since_unix_epoch as u64).to_be_bytes());
            buf.extend_from_slice(&t.subsec_nanos.to_be_bytes());
        }
        None => buf.push(0),
    }
    buf
}

fn decode_directory_identity(blob: &[u8]) -> Result<DirectoryIdentity, SyncSqliteError> {
    let mut r = materialized_generation::Reader::new(blob);
    let encoding_version = r.u8()?;
    if encoding_version != EPOCH_ENCODING_VERSION as u8 {
        return Err(SyncSqliteError::CorruptState(format!(
            "parent_directory_identity blob encoding_version {encoding_version} is not this \
             build's {EPOCH_ENCODING_VERSION}"
        )));
    }
    let volume_identity = match r.u8()? {
        0 => VolumeIdentity::Unix { device_id: r.u64()? },
        1 => VolumeIdentity::Windows { volume_serial_number: r.u64()? },
        other => {
            return Err(SyncSqliteError::CorruptState(format!(
                "unknown VolumeIdentity tag {other} in a stored parent_directory_identity blob"
            )))
        }
    };
    let object_id = match r.u8()? {
        0 => PlatformObjectId::Unix { inode: r.u64()? },
        1 => match r.u8()? {
            0 => PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index: r.u64()? }),
            1 => {
                let file_id: [u8; 16] =
                    r.take(16)?.try_into().expect("Reader::take(16) always returns 16 bytes");
                PlatformObjectId::Windows(WindowsObjectId::Proven { file_id })
            }
            other => {
                return Err(SyncSqliteError::CorruptState(format!(
                    "unknown WindowsObjectId subtag {other} in a stored \
                     parent_directory_identity blob"
                )))
            }
        },
        other => {
            return Err(SyncSqliteError::CorruptState(format!(
                "unknown PlatformObjectId tag {other} in a stored parent_directory_identity blob"
            )))
        }
    };
    let generation_or_usn = if r.bool_flag()? { Some(r.u128()?) } else { None };
    let birth_or_creation_time = if r.bool_flag()? {
        let seconds_since_unix_epoch = r.u64()? as i64;
        let subsec_nanos_bytes: [u8; 4] =
            r.take(4)?.try_into().expect("Reader::take(4) always returns 4 bytes");
        Some(Timestamp {
            seconds_since_unix_epoch,
            subsec_nanos: u32::from_be_bytes(subsec_nanos_bytes),
        })
    } else {
        None
    };
    Ok(DirectoryIdentity { volume_identity, object_id, generation_or_usn, birth_or_creation_time })
}

pub struct NewEpoch<'a> {
    pub transaction_id: &'a str,
    pub epoch: i64,
    pub plan_revision: i64,
    pub target_path: &'a str,
    pub placement_role: PlacementRole,
    pub target_generation: &'a [u8],
    pub parent_directory_identity: &'a DirectoryIdentity,
    pub capability_snapshot: &'a [u8],
    pub durability_level: DurabilityLevel,
}

/// Optional fields an epoch accumulates as it progresses through its
/// protocol sequence, each becoming known at a different point in that
/// sequence. `None` leaves the stored column
/// unchanged; there is no way to *clear* a previously-set field through
/// this struct, matching the module's immutable-once-written posture for
/// anything that has already been observed.
#[derive(Default)]
pub struct EpochUpdate<'a> {
    pub displaced_generation_id: Option<&'a GenerationId>,
    pub displaced_snapshot: Option<&'a [u8]>,
    pub stage_path: Option<&'a str>,
    pub preimage_path: Option<&'a str>,
    pub backup_path: Option<&'a str>,
    pub staged_identity: Option<&'a FileIdentity>,
    pub displaced_identity: Option<&'a FileIdentity>,
    pub classification_result: Option<&'a str>,
    pub captured_change_hash: Option<&'a ChangeHash>,
    /// Why this epoch was blocked *without* the blocker being able to
    /// determine anything about the epoch's physical state.
    ///
    /// Deliberately not derivable from `phase`. `EpochState::Blocked` is a
    /// destination three unrelated writers reach, only one of which leaves a
    /// real open question behind: `early_physical_recovery::block` blocks
    /// because an observation failed or was impossible (see that module's
    /// `BlockReason`), while `orchestrator::block_unpreparable_epoch` blocks
    /// an epoch whose prepare failed with nothing physical outstanding, and
    /// `resolution_planning::replan_unchecked`'s sweep blocks pre-commit
    /// leftovers a replan is about to supersede. Reading a bare `Blocked`
    /// phase as "something is unresolved" therefore over-reads two writers
    /// that have nothing unresolved at all, which is exactly how a
    /// successful replan used to mint epochs that withheld a transaction's
    /// reservations for the rest of its life. Only the writer that genuinely
    /// could not determine anything sets this column, so a writer with
    /// nothing unresolved cannot produce the state that withholds.
    pub unresolved_block_reason: Option<&'a str>,
}

// No `PartialEq`: this embeds a `DirectoryIdentity`, and that type
// deliberately has no equality operator so a caller cannot silently get a
// structural comparison where a same-object judgement is required. Comparing
// whole records is a round-trip-fidelity question, not a same-object one, so
// the one test that needs it compares the fields it cares about.
#[derive(Debug, Clone)]
pub struct EpochRecord {
    pub transaction_id: String,
    pub epoch: i64,
    pub plan_revision: i64,
    pub target_path: String,
    pub placement_role: PlacementRole,
    pub phase: EpochState,
    pub displaced_generation_id: Option<GenerationId>,
    pub target_generation: Vec<u8>,
    pub parent_directory_identity: DirectoryIdentity,
    pub displaced_snapshot: Option<Vec<u8>>,
    pub stage_path: Option<String>,
    pub preimage_path: Option<String>,
    pub backup_path: Option<String>,
    pub staged_identity: Option<FileIdentity>,
    pub displaced_identity: Option<FileIdentity>,
    pub capability_snapshot: Vec<u8>,
    pub durability_level: DurabilityLevel,
    pub classification_result: Option<String>,
    pub captured_change_hash: Option<ChangeHash>,
    /// See [`EpochUpdate::unresolved_block_reason`]. `Some` iff early
    /// physical recovery blocked this epoch on an unanswered physical
    /// question; the durable signal `early_physical_recovery::run` keys its
    /// reservation withholding on.
    pub unresolved_block_reason: Option<String>,
    pub created_at_unix_nanos: i64,
    pub updated_at_unix_nanos: i64,
}

/// Allocates a new epoch — always a fresh `(transaction_id, epoch)` row,
/// never a reuse of an earlier one for the same transaction. Epoch rows are
/// never reused or overwritten by a later resolver placement; a new
/// placement is always a new epoch. Starts at [`EpochState::Allocated`]
/// with every progressive field unset.
///
/// `expected_execution_generation` is the caller's captured belief about
/// `new.transaction_id`'s current `execution_generation`, exactly like
/// every other `expected_execution_generation` parameter in this module
/// (see [`transition_epoch_unchecked`]) -- not a value this call derives,
/// so a caller working from a superseded plan passes a value that no
/// longer matches and is refused with [`SyncSqliteError::ExecutionGenerationFenced`]
/// before anything is written. `new.plan_revision` (already part of
/// [`NewEpoch`]) is the matching belief for `plan_revision`, checked by
/// [`insert_epoch_row_unchecked`]; no second parameter is needed for it. See
/// that function's own doc and [`bump_epoch_watermark_if_not_completed`]'s
/// for the race this closes. Gated.
pub fn insert_epoch(
    conn: &Connection,
    new: &NewEpoch,
    expected_execution_generation: i64,
    now_unix_nanos: i64,
) -> Result<EpochRecord, SyncSqliteError> {
    require_execution_enabled()?;
    insert_epoch_unchecked(conn, new, expected_execution_generation, now_unix_nanos)
}

/// Precondition: `conn` must be in autocommit mode when this is called --
/// same requirement as [`with_immediate_transaction`], which this opens
/// internally, and for the same reason: `BEGIN IMMEDIATE` inside an
/// already-open transaction fails with "cannot start a transaction within a
/// transaction" rather than joining it. A caller that needs to insert an
/// epoch from inside its own already-open transaction cannot call this as-is
/// -- it would need splitting into an "already inside a caller-owned
/// transaction" core plus this wrapper, the same shape
/// [`with_immediate_transaction`]'s own doc describes; a savepoint does not
/// substitute, because it cannot upgrade an already-open transaction to
/// `IMMEDIATE`'s locking semantics.
pub fn insert_epoch_unchecked(
    conn: &Connection,
    new: &NewEpoch,
    expected_execution_generation: i64,
    now_unix_nanos: i64,
) -> Result<EpochRecord, SyncSqliteError> {
    // Bumping the parent's `epoch_watermark` and inserting this epoch row
    // happen inside one SQLite transaction, so no observer -- in particular
    // `set_transaction_phase_unchecked`'s `Completed` compare-and-swap --
    // can ever see the epoch row without the watermark bump or the reverse.
    // See that column's own schema doc and `set_transaction_phase_unchecked`'s
    // own doc on the race this closes. `BEGIN IMMEDIATE`
    // ([`with_immediate_transaction`]), not `DEFERRED`: this reads
    // (indirectly, through the guard's own re-derivation on refusal) and
    // writes in the same transaction, and `with_immediate_transaction`'s own
    // doc explains why `DEFERRED` is the wrong choice for that shape.
    //
    // `check_execution_generation` runs as a plain read here, not a
    // subselect bound into a later `UPDATE`'s own `WHERE` clause the way
    // [`transition_epoch_unchecked`] must -- that function is called
    // standalone, one statement at a time, with no enclosing transaction of
    // its own, so a plain read-then-write would leave a window for a
    // concurrent writer to land between them. This call is different: it
    // already holds `BEGIN IMMEDIATE`'s write lock for the whole closure
    // below, so no other connection can write `execution_generation` (or
    // anything else in this row) between this read and the writes that
    // follow it -- the enclosing transaction is itself the atomic unit, and
    // a plain read inside it is exactly as race-free as a subselect would
    // be. Checked first, before either write, so a stale caller is refused
    // without bumping the watermark or inserting a row that would need
    // rolling back.
    with_immediate_transaction(conn, |tx| {
        check_execution_generation(tx, new.transaction_id, expected_execution_generation)?;
        bump_epoch_watermark_if_not_completed(tx, new.transaction_id, 1)?;
        insert_epoch_row_unchecked(tx, new, now_unix_nanos)
    })
}

/// Refuses to bump `transaction_id`'s `epoch_watermark` -- and by
/// construction, to let a caller go on to insert a new epoch under it --
/// unless the parent is currently in a phase
/// [`TransactionPhase::may_receive_new_epochs`] allows.
///
/// This used to check only that the parent's `phase` was not yet
/// [`TransactionPhase::Completed`], i.e. every other phase was treated as
/// fair game for a new epoch. That is too permissive: `AsyncPreservation`
/// (reached only after the canonical namespace is released; nothing under
/// this design allocates a new placement, which always needs a canonical-path
/// reservation, once that release has happened) and `Blocked` (a stall, not
/// a working state -- its only forward edge is a replan back to `Planning`,
/// and a fresh epoch belongs to that replanned state, not the stall itself)
/// are not phases a new epoch should ever land in. See
/// [`TransactionPhase::may_receive_new_epochs`]'s own doc for the full
/// reasoning, including why `Planning` and `Committing` are the two phases
/// that remain legal.
///
/// The guard is bound directly into this `UPDATE`'s own `WHERE` clause,
/// following [`transition_epoch_unchecked`]'s own reasoning for why a check
/// whose result is not bound into the statement it authorizes is not a
/// check at all: a separate `SELECT phase` followed by this `UPDATE` would
/// leave a window in which a concurrent `set_transaction_phase_unchecked`
/// call could move the transaction to an illegal phase between the two
/// statements, and this `UPDATE` would still go on to match it.
///
/// `by` lets one call cover a whole batch of epochs sharing one shared
/// transaction (`resolution_planning::allocate_slice_epochs_unchecked`)
/// with a single bump, rather than one bump per row -- the column only
/// needs to reflect the total count of epochs ever inserted, not a
/// per-insert audit trail, so the two are equivalent as long as they share
/// one atomic unit with the epoch rows they account for. `conn` is
/// generic over `&Connection` so callers already inside their own open
/// transaction (via Rust's `Deref<Target = Connection>` on
/// `rusqlite::Transaction`) can pass `&tx` directly; this function never
/// opens or commits a transaction of its own.
pub fn bump_epoch_watermark_if_not_completed(
    conn: &Connection,
    transaction_id: &str,
    by: i64,
) -> Result<(), SyncSqliteError> {
    // Built from `TransactionPhase::ALL` (every variant, compile-time
    // checked) filtered through `may_receive_new_epochs` (also an exhaustive
    // match), rather than naming `Planning` and `Committing` a third time
    // here. A previous version of this comment claimed the two "can never
    // drift apart" because of this filtering alone -- that was false: the
    // filtered-through function was `matches!` with an implicit `_ => false`
    // arm, so a new variant would silently fall out of `legal_phases`
    // without a compile error, and separately the placeholder count below
    // was hard-coded to 2 and checked only by a `debug_assert`, so a third
    // legal phase would panic in a debug build and silently bind only the
    // first two `IN (...)` slots in release. Both are now compile-time
    // guarantees instead: see `may_receive_new_epochs`'s and `ALL`'s own
    // docs, and the placeholder list generated below rather than hard-coded.
    let legal_phases: Vec<&'static str> = TransactionPhase::ALL
        .into_iter()
        .filter(|phase| phase.may_receive_new_epochs())
        .map(TransactionPhase::as_db_str)
        .collect();
    // `by` and `transaction_id` occupy ?1 and ?2; the legal-phase list fills
    // ?3 onward, however many there turn out to be.
    let placeholders =
        (0..legal_phases.len()).map(|i| format!("?{}", i + 3)).collect::<Vec<_>>().join(", ");
    let sql = format!(
        "UPDATE filesystem_transactions SET epoch_watermark = epoch_watermark + ?1 \
         WHERE transaction_id = ?2 AND phase IN ({placeholders})"
    );
    let mut params: Vec<&dyn rusqlite::ToSql> = vec![&by, &transaction_id];
    params.extend(legal_phases.iter().map(|p| p as &dyn rusqlite::ToSql));
    let bumped = conn.execute(&sql, params.as_slice())?;
    if bumped == 0 {
        return Err(epoch_allocation_refusal(conn, transaction_id)?);
    }
    Ok(())
}

/// Re-derives why [`bump_epoch_watermark_if_not_completed`]'s guarded
/// `UPDATE` matched no row: either `transaction_id` does not exist, or it
/// exists but its phase is not one [`TransactionPhase::may_receive_new_epochs`]
/// allows. Returning a [`SyncSqliteError`] rather than raising it directly lets
/// both callers of the guard attach it to their own `Err(...)` with the `?`
/// operator.
fn epoch_allocation_refusal(
    conn: &Connection,
    transaction_id: &str,
) -> Result<SyncSqliteError, SyncSqliteError> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT phase FROM filesystem_transactions WHERE transaction_id = ?1",
            [transaction_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(match existing {
        None => SyncSqliteError::NotFound(format!("filesystem transaction {transaction_id}")),
        Some(phase) => SyncSqliteError::InvalidInput(format!(
            "filesystem transaction {transaction_id}: cannot allocate a new epoch while the \
             transaction is {phase} -- only a transaction at planning or committing may receive \
             a new placement epoch; once Completed, startup recovery's \
             list_incomplete_transactions() never looks at this transaction again, so an epoch \
             inserted afterwards would be permanently invisible to it, and async_preservation/\
             blocked are not working states a new placement belongs to either"
        )),
    })
}

/// The row-insert half of epoch allocation, with no watermark bump and no
/// transaction management of its own -- [`insert_epoch_unchecked`] (one
/// epoch, its own transaction) and
/// `resolution_planning::allocate_slice_epochs_unchecked` (a whole slice's
/// epochs sharing one transaction and one
/// [`bump_epoch_watermark_if_not_completed`] call) both build on this.
/// `pub(crate)`, not private, so the latter -- one module over -- can reuse
/// it inside its own open transaction rather than each epoch reopening one.
///
/// The `INSERT` only lands if `new.transaction_id`'s live `plan_revision`
/// still equals `new.plan_revision` -- the belief the caller captured when
/// it built the plan slice this epoch belongs to
/// (`resolution_planning::PlanSlice::plan_revision`, already threaded
/// through to every [`NewEpoch`] this module or `resolution_planning`
/// constructs). Before this, an epoch's own `plan_revision` field was pure
/// metadata: nothing compared it against the parent's actual, current
/// `plan_revision` before writing the row. A worker holding a plan slice
/// built at revision `N` could lose a race with a concurrent replan
/// (`resolution_planning::replan`, which advances `plan_revision` and
/// `execution_generation` together, atomically, and returns the saga to
/// `Planning` -- a phase [`bump_epoch_watermark_if_not_completed`] still
/// treats as legal to receive new epochs) and go on to insert an epoch for
/// a plan revision nothing current recognizes. That epoch is not merely
/// wrong, it is unrecoverable: every later transition on it captures the
/// *new* `execution_generation` as its own fence and immediately fails
/// `check_execution_generation` against the *old* one the stale worker
/// captured, so the epoch sits at `Allocated` forever -- and because it is
/// not terminal, it permanently blocks [`set_transaction_phase_unchecked`]'s
/// `Completed` transition (see that function's own "every epoch is
/// terminal" check) from ever succeeding. Refusing the insert outright,
/// before any row exists to get stuck, is the only place this can be
/// closed: once the row exists, refusing later transitions on it (which
/// [`transition_epoch_unchecked`] already does correctly) only preserves
/// the deadlock instead of avoiding it.
///
/// The guard is an `INSERT ... SELECT ... FROM filesystem_transactions
/// WHERE plan_revision = ?` rather than a `SELECT` followed by a plain
/// `INSERT`, for the same reason [`bump_epoch_watermark_if_not_completed`]
/// binds its own guard into its `UPDATE`'s `WHERE`: a separate read
/// beforehand would leave a window for a concurrent replan to land between
/// the read and the write. Both callers already run this inside their own
/// `BEGIN IMMEDIATE` (see [`insert_epoch_unchecked`] and
/// `resolution_planning::allocate_slice_epochs_unchecked`), so this insert
/// and the watermark bump immediately before it are one atomic unit: if
/// this guard refuses, the whole enclosing transaction rolls back, taking
/// the watermark bump back with it -- there is no state where the watermark
/// moved but the epoch it was meant to account for does not exist.
pub fn insert_epoch_row_unchecked(
    conn: &Connection,
    new: &NewEpoch,
    now_unix_nanos: i64,
) -> Result<EpochRecord, SyncSqliteError> {
    let parent_directory_identity_blob = encode_directory_identity(new.parent_directory_identity);
    let inserted = conn.execute(
        "INSERT INTO filesystem_transaction_epochs \
            (transaction_id, epoch, plan_revision, target_path, placement_role, phase, \
             displaced_generation_id, target_generation, parent_directory_identity, \
             displaced_snapshot, stage_path, preimage_path, backup_path, staged_identity, \
             displaced_identity, capability_snapshot, durability_level, classification_result, \
             captured_change_hash, unresolved_block_reason, encoding_version, \
             created_at_unix_nanos, updated_at_unix_nanos) \
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, NULL, NULL, NULL, NULL, NULL, NULL, ?9, \
                ?10, NULL, NULL, NULL, ?11, ?12, ?12 \
         FROM filesystem_transactions \
         WHERE transaction_id = ?1 AND plan_revision = ?3",
        rusqlite::params![
            new.transaction_id,
            new.epoch,
            new.plan_revision,
            new.target_path,
            new.placement_role.db_str(),
            EpochState::Allocated.db_str(),
            new.target_generation,
            parent_directory_identity_blob,
            new.capability_snapshot,
            durability_level_as_db_str(new.durability_level),
            EPOCH_ENCODING_VERSION,
            now_unix_nanos,
        ],
    )?;
    if inserted == 0 {
        return Err(plan_revision_allocation_refusal(conn, new.transaction_id, new.plan_revision)?);
    }
    Ok(EpochRecord {
        transaction_id: new.transaction_id.to_string(),
        epoch: new.epoch,
        plan_revision: new.plan_revision,
        target_path: new.target_path.to_string(),
        placement_role: new.placement_role,
        phase: EpochState::Allocated,
        displaced_generation_id: None,
        target_generation: new.target_generation.to_vec(),
        parent_directory_identity: *new.parent_directory_identity,
        displaced_snapshot: None,
        stage_path: None,
        preimage_path: None,
        backup_path: None,
        staged_identity: None,
        displaced_identity: None,
        capability_snapshot: new.capability_snapshot.to_vec(),
        durability_level: new.durability_level,
        classification_result: None,
        captured_change_hash: None,
        unresolved_block_reason: None,
        created_at_unix_nanos: now_unix_nanos,
        updated_at_unix_nanos: now_unix_nanos,
    })
}

/// Re-derives why [`insert_epoch_row_unchecked`]'s guarded `INSERT ...
/// SELECT` matched no row: either `transaction_id` does not exist (should
/// not be reachable here in practice --
/// [`bump_epoch_watermark_if_not_completed`] already refuses first for a
/// missing transaction -- but checked for completeness, the same way
/// [`transition_epoch_unchecked`]'s own post-mortem does), or it exists but
/// its `plan_revision` no longer matches `expected_plan_revision`.
/// Returning a [`SyncSqliteError`] rather than raising it directly lets the
/// caller attach it to its own `Err(...)` with the `?` operator.
fn plan_revision_allocation_refusal(
    conn: &Connection,
    transaction_id: &str,
    expected_plan_revision: i64,
) -> Result<SyncSqliteError, SyncSqliteError> {
    let current_plan_revision: Option<i64> = conn
        .query_row(
            "SELECT plan_revision FROM filesystem_transactions WHERE transaction_id = ?1",
            [transaction_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(match current_plan_revision {
        None => SyncSqliteError::NotFound(format!("filesystem transaction {transaction_id}")),
        Some(current) => SyncSqliteError::TransitionRaced {
            subject: format!("filesystem transaction {transaction_id} epoch allocation"),
            expected_state: format!("plan_revision {expected_plan_revision}"),
            current_state: format!("plan_revision {current}"),
        },
    })
}

#[allow(clippy::type_complexity)]
fn row_to_epoch(
    row: (
        String,
        i64,
        i64,
        String,
        String,
        String,
        Option<String>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        String,
        Option<String>,
        Option<Vec<u8>>,
        i64,
        i64,
        Option<String>,
    ),
) -> Result<EpochRecord, SyncSqliteError> {
    let (
        transaction_id,
        epoch,
        plan_revision,
        target_path,
        placement_role,
        phase,
        displaced_generation_id,
        target_generation,
        parent_directory_identity,
        displaced_snapshot,
        stage_path,
        preimage_path,
        backup_path,
        staged_identity,
        displaced_identity,
        capability_snapshot,
        durability_level,
        classification_result,
        captured_change_hash,
        created_at_unix_nanos,
        updated_at_unix_nanos,
        unresolved_block_reason,
    ) = row;
    let captured_change_hash = captured_change_hash
        .map(|bytes| {
            let hash: [u8; 32] = bytes.try_into().map_err(|_| {
                SyncSqliteError::CorruptState(format!(
                    "invalid captured_change_hash length for epoch {transaction_id}/{epoch}"
                ))
            })?;
            Ok::<_, SyncSqliteError>(ChangeHash(hash))
        })
        .transpose()?;
    Ok(EpochRecord {
        placement_role: PlacementRole::from_db_str(&placement_role)?,
        phase: EpochState::from_db_str(&phase)?,
        parent_directory_identity: decode_directory_identity(&parent_directory_identity)?,
        staged_identity: staged_identity
            .map(|b| materialized_generation::decode_file_identity(&b))
            .transpose()?,
        displaced_identity: displaced_identity
            .map(|b| materialized_generation::decode_file_identity(&b))
            .transpose()?,
        durability_level: durability_level_from_db_str(&durability_level)?,
        displaced_generation_id: displaced_generation_id.map(GenerationId),
        transaction_id,
        epoch,
        plan_revision,
        target_path,
        target_generation,
        displaced_snapshot,
        stage_path,
        preimage_path,
        backup_path,
        capability_snapshot,
        classification_result,
        captured_change_hash,
        unresolved_block_reason,
        created_at_unix_nanos,
        updated_at_unix_nanos,
    })
}

pub fn lookup_epoch(
    conn: &Connection,
    transaction_id: &str,
    epoch: i64,
) -> Result<Option<EpochRecord>, SyncSqliteError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        i64,
        i64,
        String,
        String,
        String,
        Option<String>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        String,
        Option<String>,
        Option<Vec<u8>>,
        i64,
        i64,
        Option<String>,
    )> = conn
        .query_row(
            "SELECT transaction_id, epoch, plan_revision, target_path, placement_role, phase, \
                    displaced_generation_id, target_generation, parent_directory_identity, \
                    displaced_snapshot, stage_path, preimage_path, backup_path, staged_identity, \
                    displaced_identity, capability_snapshot, durability_level, \
                    classification_result, captured_change_hash, created_at_unix_nanos, \
                    updated_at_unix_nanos, unresolved_block_reason \
             FROM filesystem_transaction_epochs WHERE transaction_id = ?1 AND epoch = ?2",
            rusqlite::params![transaction_id, epoch],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                    r.get(14)?,
                    r.get(15)?,
                    r.get(16)?,
                    r.get(17)?,
                    r.get(18)?,
                    r.get(19)?,
                    r.get(20)?,
                    r.get(21)?,
                ))
            },
        )
        .optional()?;
    row.map(row_to_epoch).transpose()
}

/// Every placement epoch belonging to `transaction_id`, ordered by `epoch`
/// (oldest first — a later epoch is always a later placement attempt at the
/// same or a different path, never a reuse of an earlier one, per §5.4).
/// Read-only, like [`list_incomplete_transactions`], and not gated behind
/// [`require_execution_enabled`] for the same reason.
pub fn list_epochs_for_transaction(
    conn: &Connection,
    transaction_id: &str,
) -> Result<Vec<EpochRecord>, SyncSqliteError> {
    #[allow(clippy::type_complexity)]
    let mut stmt = conn.prepare(
        "SELECT transaction_id, epoch, plan_revision, target_path, placement_role, phase, \
                displaced_generation_id, target_generation, parent_directory_identity, \
                displaced_snapshot, stage_path, preimage_path, backup_path, staged_identity, \
                displaced_identity, capability_snapshot, durability_level, \
                classification_result, captured_change_hash, created_at_unix_nanos, \
                updated_at_unix_nanos, unresolved_block_reason \
         FROM filesystem_transaction_epochs WHERE transaction_id = ?1 ORDER BY epoch",
    )?;
    let rows = stmt
        .query_map([transaction_id], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
                r.get(9)?,
                r.get(10)?,
                r.get(11)?,
                r.get(12)?,
                r.get(13)?,
                r.get(14)?,
                r.get(15)?,
                r.get(16)?,
                r.get(17)?,
                r.get(18)?,
                r.get(19)?,
                r.get(20)?,
                r.get(21)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(row_to_epoch).collect()
}

/// Moves an epoch to phase `to`, after checking the parent transaction's
/// `execution_generation` fence and the transition's legality
/// ([`EpochState::can_transition_to`]) — both refusals are distinct
/// `SyncSqliteError`s a caller can match on. Also applies any `Some(..)` fields
/// in `update` in the same statement. Gated.
pub fn transition_epoch(
    conn: &Connection,
    transaction_id: &str,
    epoch: i64,
    expected_execution_generation: i64,
    to: EpochState,
    update: &EpochUpdate,
    now_unix_nanos: i64,
) -> Result<EpochRecord, SyncSqliteError> {
    require_execution_enabled()?;
    transition_epoch_unchecked(
        conn,
        transaction_id,
        epoch,
        expected_execution_generation,
        to,
        update,
        now_unix_nanos,
    )
}

pub fn transition_epoch_unchecked(
    conn: &Connection,
    transaction_id: &str,
    epoch: i64,
    expected_execution_generation: i64,
    to: EpochState,
    update: &EpochUpdate,
    now_unix_nanos: i64,
) -> Result<EpochRecord, SyncSqliteError> {
    check_execution_generation(conn, transaction_id, expected_execution_generation)?;
    let current = lookup_epoch(conn, transaction_id, epoch)?
        .ok_or_else(|| SyncSqliteError::NotFound(format!("epoch {transaction_id}/{epoch}")))?;
    if !current.phase.can_transition_to(to) {
        return Err(SyncSqliteError::InvalidInput(format!(
            "epoch {transaction_id}/{epoch}: {:?} -> {to:?} is not a legal transition",
            current.phase
        )));
    }
    // As in `set_transaction_phase_unchecked`, the generation fence must
    // hold on the UPDATE itself. `filesystem_transaction_epochs` has no
    // `execution_generation` column of its own -- the fence lives on the
    // parent `filesystem_transactions` row -- so the check is a subselect
    // against that row rather than a plain equality on this table. The
    // predicate also carries `phase = ?15`, the exact phase the legality
    // check above validated `to` against -- same reasoning as
    // `set_transaction_phase_unchecked`: two siblings sharing one
    // `execution_generation` can each read this epoch at the same phase and
    // legally decide different destinations (e.g. both `Committing` ->
    // `Committed` and `Committing` -> `RequiresPhysicalRecovery` are legal
    // individually); without a phase predicate, whichever UPDATE lands
    // second would silently overwrite the first's destination, because
    // `transaction_id`/`epoch`/`execution_generation` alone still match.
    // Naming the source phase makes this a genuine compare-and-swap: only
    // the transition that observed the epoch in the state it is still in
    // may apply.
    let rows_changed = conn.execute(
        "UPDATE filesystem_transaction_epochs SET \
            phase = ?1, \
            displaced_generation_id = COALESCE(?2, displaced_generation_id), \
            displaced_snapshot = COALESCE(?3, displaced_snapshot), \
            stage_path = COALESCE(?4, stage_path), \
            preimage_path = COALESCE(?5, preimage_path), \
            backup_path = COALESCE(?6, backup_path), \
            staged_identity = COALESCE(?7, staged_identity), \
            displaced_identity = COALESCE(?8, displaced_identity), \
            classification_result = COALESCE(?9, classification_result), \
            captured_change_hash = COALESCE(?10, captured_change_hash), \
            unresolved_block_reason = COALESCE(?11, unresolved_block_reason), \
            updated_at_unix_nanos = ?12 \
         WHERE transaction_id = ?13 AND epoch = ?14 \
           AND ?15 = (SELECT execution_generation FROM filesystem_transactions \
                      WHERE transaction_id = ?13) \
           AND phase = ?16",
        rusqlite::params![
            to.db_str(),
            update.displaced_generation_id.map(|g| g.0.clone()),
            update.displaced_snapshot,
            update.stage_path,
            update.preimage_path,
            update.backup_path,
            update.staged_identity.map(materialized_generation::encode_file_identity),
            update.displaced_identity.map(materialized_generation::encode_file_identity),
            update.classification_result,
            update.captured_change_hash.map(|h| h.0.to_vec()),
            update.unresolved_block_reason,
            now_unix_nanos,
            transaction_id,
            epoch,
            expected_execution_generation,
            current.phase.db_str(),
        ],
    )?;
    if rows_changed == 0 {
        // Re-derive the precise refusal, as above: the generation moved,
        // the transaction vanished (both reported by
        // `check_execution_generation`), the epoch row itself vanished
        // between the `lookup_epoch` above and this UPDATE (not covered by
        // `check_execution_generation`, which only knows about
        // `filesystem_transactions`), or the generation and the epoch both
        // still exist but the epoch's phase moved under us (a sibling
        // transition raced this one and won). The final fallback only
        // fires if none of those hold, which should not be reachable in
        // practice.
        check_execution_generation(conn, transaction_id, expected_execution_generation)?;
        let current_epoch = lookup_epoch(conn, transaction_id, epoch)?
            .ok_or_else(|| SyncSqliteError::NotFound(format!("epoch {transaction_id}/{epoch}")))?;
        if current_epoch.phase != current.phase {
            return Err(SyncSqliteError::TransitionRaced {
                subject: format!("epoch {transaction_id}/{epoch}"),
                expected_state: current.phase.db_str().to_string(),
                current_state: current_epoch.phase.db_str().to_string(),
            });
        }
        return Err(SyncSqliteError::ExecutionGenerationFenced {
            transaction_id: transaction_id.to_string(),
            expected: expected_execution_generation,
            current: expected_execution_generation,
        });
    }
    lookup_epoch(conn, transaction_id, epoch)?
        .ok_or_else(|| SyncSqliteError::NotFound(format!("epoch {transaction_id}/{epoch}")))
}

// =====================================================================
// Hierarchical reservations
// =====================================================================

// `ReservationScope`/`ReservationRole` (and `ReservationScope::
// conflicts_with`) moved to `yadorilink_replica_domain::filesystem_placement`
// alongside `EpochState`/`PlacementRole` (Phase 7D-9D) -- see that module's
// own doc. Same local-trait codec pattern as `EpochStateDbCodec` above.
trait ReservationScopeDbCodec {
    fn db_str(self) -> &'static str;
    fn from_db_str(value: &str) -> Result<ReservationScope, SyncSqliteError>;
}

impl ReservationScopeDbCodec for ReservationScope {
    fn db_str(self) -> &'static str {
        match self {
            ReservationScope::Exact => "exact",
            ReservationScope::SubtreeIntent => "subtree_intent",
            ReservationScope::SubtreeExclusive => "subtree_exclusive",
        }
    }

    fn from_db_str(value: &str) -> Result<ReservationScope, SyncSqliteError> {
        match value {
            "exact" => Ok(ReservationScope::Exact),
            "subtree_intent" => Ok(ReservationScope::SubtreeIntent),
            "subtree_exclusive" => Ok(ReservationScope::SubtreeExclusive),
            other => Err(SyncSqliteError::CorruptState(format!(
                "unknown filesystem_transaction_reservations.scope_kind {other:?}"
            ))),
        }
    }
}

trait ReservationRoleDbCodec {
    fn db_str(self) -> &'static str;
    fn from_db_str(value: &str) -> Result<ReservationRole, SyncSqliteError>;
}

impl ReservationRoleDbCodec for ReservationRole {
    fn db_str(self) -> &'static str {
        match self {
            ReservationRole::CanonicalPath => "canonical_path",
            ReservationRole::ConflictCopy => "conflict_copy",
            ReservationRole::RetirementTarget => "retirement_target",
            ReservationRole::SubtreeRoot => "subtree_root",
        }
    }

    fn from_db_str(value: &str) -> Result<ReservationRole, SyncSqliteError> {
        match value {
            "canonical_path" => Ok(ReservationRole::CanonicalPath),
            "conflict_copy" => Ok(ReservationRole::ConflictCopy),
            "retirement_target" => Ok(ReservationRole::RetirementTarget),
            "subtree_root" => Ok(ReservationRole::SubtreeRoot),
            other => Err(SyncSqliteError::CorruptState(format!(
                "unknown filesystem_transaction_reservations.role {other:?}"
            ))),
        }
    }
}

/// Splits and validates a reservation path into its segments, without yet
/// encoding them into a key. This is the normalization step [`path_key`]
/// needs *before* it turns segments into bytes, so that two different
/// strings naming the same filesystem object are rejected as equal or
/// funnelled into the same segment list rather than silently producing
/// disjoint keys:
///
/// - both `/` and `\` are treated as separators (matching
///   [`crate::change::validate_path`], which already accepts `a\b` as two
///   segments -- `path_key` used to disagree and read it as one);
/// - `.` and `..` segments are refused, matching `validate_path`;
/// - an empty segment (a leading/trailing/doubled separator, e.g. `a//b`,
///   `/a`, `a/`) is refused, since it has no canonical meaning here;
/// - the sync root is spelled `""` and maps to *zero* segments, not one
///   empty segment -- see [`subtree_end_key`] for why that distinction is
///   the whole point.
///
/// What this does **not** do: case-fold on case-insensitive volumes (so
/// `A.txt` and `a.txt` still produce different keys). Whether a volume is
/// case-insensitive is not available to this module -- no caller threads a
/// [`VolumeIdentity`]/capability snapshot into [`NewReservation`], and nothing
/// upstream of `path_key` resolves it either. Folding case here without
/// that input would mean guessing per-volume behavior (or worse, always
/// folding and silently breaking exact-match reservations on case-sensitive
/// volumes). This is a known, documented gap: a caller that later has
/// volume identity in hand at the reservation call site must fold before
/// calling in, or this function must grow a parameter for it -- it must not
/// be guessed here.
fn normalized_reservation_segments(path: &str) -> Result<Vec<&str>, SyncSqliteError> {
    if path.contains('\0') {
        return Err(SyncSqliteError::InvalidInput(format!(
            "path {path:?} contains a NUL byte, which the reservation range encoding reserves \
             as a segment terminator"
        )));
    }
    if path.is_empty() {
        // The sync root: zero segments, not one empty segment.
        return Ok(Vec::new());
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(SyncSqliteError::InvalidInput(format!(
            "path {path:?} must be relative to the sync root, not absolute"
        )));
    }
    let is_sep = |c: char| c == '/' || c == '\\';
    let segments: Vec<&str> = path.split(is_sep).collect();
    for segment in &segments {
        if segment.is_empty() {
            return Err(SyncSqliteError::InvalidInput(format!(
                "path {path:?} contains an empty segment (a leading, trailing, or doubled \
                 separator)"
            )));
        }
        if *segment == "." || *segment == ".." {
            return Err(SyncSqliteError::InvalidInput(format!(
                "path {path:?} contains a '.' or '..' segment"
            )));
        }
    }
    Ok(segments)
}

/// The exact-match key for `path`: each normalized segment (see
/// [`normalized_reservation_segments`]) followed by a `0x00` terminator.
/// The encoding relies on `0x00` never appearing inside a segment's own
/// content to disambiguate "end of segment" from "segment content" -- see
/// [`subtree_end_key`] for why this specific terminator makes the
/// half-open subtree range exact instead of matching unrelated siblings
/// that merely share a string prefix. `path == ""` (the sync root)
/// produces the empty key, not `[0x00]`.
pub fn path_key(path: &str) -> Result<Vec<u8>, SyncSqliteError> {
    let segments = normalized_reservation_segments(path)?;
    let mut buf = Vec::new();
    for segment in segments {
        buf.extend_from_slice(segment.as_bytes());
        buf.push(0);
    }
    Ok(buf)
}

/// The exclusive upper bound of `path`'s subtree range, given its
/// [`path_key`].
///
/// For a non-root key (nonempty, always ending in the `0x00` segment
/// terminator): incrementing that final byte, which never overflows since
/// it is always `0x00` going in. Any key for `path` itself or a proper
/// descendant `path/...` shares `path_key`'s bytes up to and including
/// that terminator position, where it holds `0x00` -- strictly less than
/// the incremented `0x01` here regardless of what follows -- so the
/// half-open range `[path_key, subtree_end_key)` captures exactly `path`
/// and everything under it, and nothing that merely starts with the same
/// characters (e.g. `path` and `pathological` never collide, because
/// `pathological`'s byte at that same position is part of its own segment
/// content, not a `0x00` terminator, and is therefore always `> 0x01` for
/// any legal, NUL-free path).
///
/// For the root key (empty, [`normalized_reservation_segments`]'s
/// zero-segment case): there is no terminator byte to increment, and the
/// half-open range must instead capture *every* real key, not just
/// descendants of some prefix. `path_key` never emits a leading byte
/// higher than `0xF4` (the highest valid UTF-8 lead byte; segment content
/// is always valid UTF-8, and the only other byte a key ever contains is
/// the `0x00` terminator), so `[0xFF]` sorts strictly after every real,
/// nonempty key -- the empty key is a byte-vector prefix of every other
/// key and thus already sorts before all of them -- giving a half-open
/// range `[[], [0xFF])` that contains the whole tree. This is proven by
/// `root_subtree_range_contains_every_descendant_key` below, not just
/// asserted here.
fn subtree_end_key(path_key: &[u8]) -> Vec<u8> {
    if path_key.is_empty() {
        return vec![0xFF];
    }
    let mut end = path_key.to_vec();
    let last = end.last_mut().expect("a non-root path_key always ends with a terminator byte");
    debug_assert_eq!(*last, 0, "path_key's final byte is always the 0x00 terminator");
    *last = 1;
    end
}

fn ranges_overlap(a_start: &[u8], a_end: &[u8], b_start: &[u8], b_end: &[u8]) -> bool {
    a_start < b_end && b_start < a_end
}

// `NewReservation` moved to `yadorilink_replica_domain::filesystem_placement`
// alongside `ReservationScope`/`ReservationRole` (Phase 7D-9D).

/// Acquires every reservation in `requests` for one transaction, or none —
/// the all-or-none rule, enforced by doing every check and every insert
/// inside one `IMMEDIATE` SQLite transaction. Checked in `path_key` order
/// ("acquire in canonical order") against every overlapping reservation in
/// the group that existed *before this call*, using
/// [`ReservationScope::conflicts_with`] — including ones already held by the
/// *requesting* transaction itself. On the first conflict found, the whole
/// batch is rolled back (the `Connection` never commits) and
/// `Err(ReservationConflict)` names it — nothing partial is ever left held.
///
/// "Before this call" is the precise boundary, not a shorthand for "already
/// committed": a batch is checked against a single snapshot taken before its
/// first insert, so the rows this call itself writes never block its own
/// later requests. A slice's request set is allowed to overlap internally —
/// [`yadorilink_sync_core::resolution_planning::slice_reservation_requests`] emits a
/// group's placements and its `extra_reservations` into one list, so a
/// `ReservationScope::SubtreeExclusive` extra reservation arrives alongside
/// the placements inside that subtree — and checking incrementally would
/// make such a slice unacquirable forever rather than merely racy.
///
/// # Why a transaction's own prior reservations are not excluded
///
/// An earlier version of this check excluded rows belonging to the
/// requesting transaction (`transaction_id != ?`), on the reasoning that a
/// transaction's own reservations can never meaningfully conflict with
/// itself. That reasoning does not hold once a single logical transaction
/// can be driven through more than one `acquire_reservations` call —
/// yadorilink-daemon's `commit_orchestration::orchestrator`'s "one acquisition call per slice" rule (see
/// that module's own doc) is a per-*slice* invariant, and a transaction
/// bigger than [`yadorilink_sync_core::resolution_planning::SliceBounds`] is legitimately
/// split into several slices, each with its own call. Two slices of the
/// same transaction driven through two different connections can then both
/// pass the old check for an overlapping path — neither observes the
/// other's reservation, because both are excluded as "the same
/// transaction" — and both proceed to hold it. If each also takes an
/// in-memory path lock across its own physical commit window (see
/// yadorilink-daemon's `commit_orchestration::orchestrator::run_slice_unchecked`'s `commit_path_locks`
/// use) in the opposite order from the other's wait on SQLite's writer
/// lock, the two can invert lock order: one waits on the in-memory path
/// lock the other holds, while the other waits on SQLite's writer lock this
/// call holds — a real (if timeout-bounded, not infinite) deadlock between
/// two slices of one transaction, not between two different transactions.
///
/// Excluding only rows with a *different* role from the request would
/// preserve the same self-exclusion for one specific legitimate shape (a
/// transaction adding a second, differently-purposed reservation on a path
/// it already holds) while still refusing the deadlock-prone shape (an
/// overlapping reservation racing in from elsewhere). But nothing durable
/// distinguishes "a genuinely different, deliberately additive reservation"
/// from "a second slice of this transaction that should never have
/// requested this path at all" — both present as the same transaction
/// asking for an overlapping path a second time, and this function has no
/// slice or acquisition-call identity to tell them apart with. No
/// production caller today asks for the same or an overlapping path twice
/// for one transaction across two different roles either:
/// [`yadorilink_sync_core::resolution_planning::slice_reservation_requests`] gives a
/// conflict's canonical path and its conflict copies *different* paths (see
/// that module's own construction), and `ReservationRole::RetirementTarget`
/// has no production placement constructor at all. Absent a real need and
/// absent a way to prove the safe case, the conservative answer is used:
/// every overlapping reservation is checked against every group-mate
/// including the requester's own, full stop.
pub fn acquire_reservations(
    conn: &mut Connection,
    requests: &[NewReservation],
    now_unix_nanos: i64,
) -> Result<Vec<String>, SyncSqliteError> {
    require_execution_enabled()?;
    acquire_reservations_unchecked(conn, requests, now_unix_nanos)
}

/// The transaction-opening wrapper around
/// [`acquire_reservations_in_open_transaction`]: opens one `BEGIN IMMEDIATE`
/// transaction of its own, runs the core inside it, and commits. Every
/// existing caller wants exactly this, so their call sites are unchanged.
///
/// Precondition: `conn` must be in autocommit mode, inherited verbatim from
/// [`with_immediate_transaction`] — a caller already inside its own
/// transaction must call the core directly instead, which is the whole
/// reason the split exists.
pub fn acquire_reservations_unchecked(
    conn: &mut Connection,
    requests: &[NewReservation],
    now_unix_nanos: i64,
) -> Result<Vec<String>, SyncSqliteError> {
    with_immediate_transaction(conn, |tx| {
        acquire_reservations_in_open_transaction(tx, requests, now_unix_nanos)
    })
}

/// The acquisition core: every conflict check and every insert, in canonical
/// `path_key` order, with no `BEGIN`/`COMMIT` of its own.
///
/// The caller must already have an *`IMMEDIATE`* transaction open on `conn`.
/// That is not a stylistic preference: this function reads
/// (`filesystem_transaction_reservations`) before it writes to the same
/// table, which is precisely the shape [`with_immediate_transaction`]'s doc
/// says must never run under SQLite's `DEFERRED` default. It also cannot
/// open its own: SQLite refuses a nested `BEGIN` outright ("cannot start a
/// transaction within a transaction"), and a savepoint cannot retroactively
/// upgrade an already-open `DEFERRED` transaction to `IMMEDIATE` locking.
///
/// The all-or-none rule is therefore the *caller's* transaction boundary
/// now, not this function's: returning `Err` from here leaves the caller to
/// roll back, which is what makes reservation acquisition composable into a
/// larger unit (see yadorilink-daemon's `commit_orchestration::orchestrator::run_slice`'s commit boundary,
/// where acquisition, the in-memory path locks, revalidation and every
/// epoch transition are one transaction).
pub fn acquire_reservations_in_open_transaction(
    conn: &Connection,
    requests: &[NewReservation],
    now_unix_nanos: i64,
) -> Result<Vec<String>, SyncSqliteError> {
    let mut keyed: Vec<(usize, Vec<u8>, Vec<u8>)> = requests
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let start = path_key(r.path)?;
            let end = subtree_end_key(&start);
            Ok::<_, SyncSqliteError>((i, start, end))
        })
        .collect::<Result<_, _>>()?;
    keyed.sort_by(|a, b| a.1.cmp(&b.1));

    // Snapshotted ONCE, before the first insert, and deliberately not
    // re-read inside the loop. Two properties depend on that:
    //
    //  - correctness of dropping `AND transaction_id != ?2` (above). The
    //    rows this call is about to write are this batch's own, and a batch
    //    is not required to be internally non-overlapping: a group may
    //    legitimately carry a `ReservationScope::Subtree` extra reservation
    //    (see `resolution_planning::PlacementGroup::with_extra_reservations`
    //    and `slice_reservation_requests`, which emits placements and extra
    //    reservations into one request list) together with placements
    //    *inside* that subtree. Re-reading per request would make each
    //    later request conflict with an earlier one from its own batch --
    //    `acquire_reservations_lets_a_subtree_exclusive_block_a_descendant_
    //    exact` is exactly that pairing -- so such a slice could never
    //    acquire, ever, rather than racing. Checking against the
    //    pre-existing rows only keeps intra-batch composition working while
    //    still refusing every reservation anyone (including an earlier
    //    slice of this same transaction) had already committed;
    //  - the snapshot cannot go stale. This runs inside the caller's
    //    `IMMEDIATE` transaction, which holds SQLite's writer lock for its
    //    whole duration, so no other connection can insert a reservation
    //    between this read and the last insert below.
    // Keyed by `group_id` because a reservation only ever excludes another
    // in the same group -- the per-request `WHERE group_id = ?` this
    // replaces. `requests` is not required to be single-group, so every
    // group named by any request is snapshotted and each request is
    // compared only against its own group's rows.
    #[allow(clippy::type_complexity)]
    let preexisting: Vec<(String, String, ReservationScope, Vec<u8>, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT group_id, transaction_id, scope_kind, path_key, subtree_end_key \
             FROM filesystem_transaction_reservations \
             WHERE group_id = ?1",
        )?;
        let mut groups: Vec<&str> = requests.iter().map(|r| r.group_id).collect();
        groups.sort_unstable();
        groups.dedup();
        let mut out = Vec::new();
        for group_id in groups {
            let rows = stmt.query_map(rusqlite::params![group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                ))
            })?;
            for row in rows {
                let (group_id, transaction_id, scope, start, end) = row?;
                out.push((
                    group_id,
                    transaction_id,
                    ReservationScope::from_db_str(&scope)?,
                    start,
                    end,
                ));
            }
        }
        out
    };

    let mut ids = vec![String::new(); requests.len()];
    for (i, start, end) in &keyed {
        let request = &requests[*i];
        for (other_group, other_transaction_id, other_scope, other_start, other_end) in &preexisting
        {
            if other_group == request.group_id
                && ranges_overlap(start, end, other_start, other_end)
                && request.scope.conflicts_with(*other_scope)
            {
                return Err(SyncSqliteError::ReservationConflict {
                    transaction_id: request.transaction_id.to_string(),
                    path: request.path.to_string(),
                    blocking_transaction_id: other_transaction_id.clone(),
                });
            }
        }
        let reservation_id = new_id("fsres");
        conn.execute(
            "INSERT INTO filesystem_transaction_reservations \
                (reservation_id, group_id, transaction_id, scope_kind, path, path_key, \
                 subtree_end_key, role, created_at_unix_nanos) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                reservation_id,
                request.group_id,
                request.transaction_id,
                request.scope.db_str(),
                request.path,
                start,
                end,
                request.role.db_str(),
                now_unix_nanos,
            ],
        )?;
        ids[*i] = reservation_id;
    }
    Ok(ids)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationRecord {
    pub reservation_id: String,
    pub group_id: String,
    pub transaction_id: String,
    pub scope: ReservationScope,
    pub path: String,
    pub role: ReservationRole,
    pub created_at_unix_nanos: i64,
}

/// Every reservation `transaction_id` currently holds, in no particular
/// order.
pub fn list_reservations(
    conn: &Connection,
    transaction_id: &str,
) -> Result<Vec<ReservationRecord>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT reservation_id, group_id, transaction_id, scope_kind, path, role, \
                created_at_unix_nanos \
         FROM filesystem_transaction_reservations WHERE transaction_id = ?1",
    )?;
    let rows = stmt.query_map([transaction_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, i64>(6)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (reservation_id, group_id, transaction_id, scope, path, role, created_at_unix_nanos) =
            row?;
        out.push(ReservationRecord {
            reservation_id,
            group_id,
            transaction_id,
            scope: ReservationScope::from_db_str(&scope)?,
            path,
            role: ReservationRole::from_db_str(&role)?,
            created_at_unix_nanos,
        });
    }
    Ok(out)
}

/// Releases every reservation `transaction_id` holds — canonical locks and
/// reservations are released immediately after a commit. Gated.
pub fn release_reservations(
    conn: &Connection,
    transaction_id: &str,
) -> Result<(), SyncSqliteError> {
    require_execution_enabled()?;
    release_reservations_unchecked(conn, transaction_id)
}

pub fn release_reservations_unchecked(
    conn: &Connection,
    transaction_id: &str,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "DELETE FROM filesystem_transaction_reservations WHERE transaction_id = ?1",
        [transaction_id],
    )?;
    Ok(())
}

// =====================================================================
// Fence bump at DAG admission
// =====================================================================
//
// `execution_generation` is the fence every phase transition and every
// pre-commit check (`check_execution_generation`) verifies against — but
// until now the only writer of it was `increment_execution_generation`
// itself, called by replanning, cancellation and startup adoption. Nothing
// moved it at the moment a DAG change actually lands: a change admitted
// locally or from a peer can move the desired state under a path a live
// transaction has already planned against, and without a bump here that
// stale plan would sail through its own fence check unchallenged.
//
// The mapping this needs -- "which live transaction, if any, does this path
// belong to" -- is exactly what `filesystem_transaction_reservations`
// already answers; a reservation range already IS a claim of ownership over
// a path (or a subtree of paths) by exactly one transaction at a time (two
// overlapping, conflicting reservations can never coexist -- see
// `acquire_reservations`'s all-or-none rule and `ReservationScope::
// conflicts_with`). No second index is needed or added here.
//
// A subtree reservation's stored range already extends past its own path
// down to every descendant -- `acquire_reservations` computes
// `subtree_end_key` the same way for every scope, `Exact` included, so a
// path inside a subtree that a transaction holds falls inside that
// transaction's range exactly as if it had reserved that path directly.
// `transactions_holding_touched_paths` below reuses that range as-is for
// that direction; it does not need to special-case subtree scopes to get
// this right.
//
// That is only one of the two containment directions this needs, though
// (previously recorded as an open gap and closed here). A
// touched path can also be an ANCESTOR of a held reservation -- a
// transaction reserves `a/b`, and the admitted change touches `a` itself
// (e.g. a delete or a move of `a`). `a`'s own key is never inside `a/b`'s
// stored range (that range only covers `a/b` and its descendants), so the
// ancestor-or-exact direction above alone misses it, and a stale plan
// built against `a/b`'s pre-admission state would sail through its fence
// unchallenged -- exactly the failure this module exists to prevent.
//
// Closing it needs no second index or second notion of containment: a
// touched path's own subtree range -- `[path_key(touched),
// subtree_end_key(path_key(touched)))` -- is computed the exact same way
// `acquire_reservations` computes it for a hold at that path. A
// reservation is "nested under" a touched path exactly when that
// reservation's own `path_key` falls inside the touched path's subtree
// range. `transactions_holding_touched_paths` below ORs that condition
// into the same indexed lookup, one query per touched path, so a bulk
// admission's cost stays one indexed lookup per touched path -- never a
// scan per held reservation.
//
// Because a reservation's stored range is shape-identical for `Exact` and
// `Subtree` holds (see above), this one query catches both: an `Exact`
// hold on `a/b` occupies the same range an equivalent `Subtree` hold on
// `a/b` would, so nothing here needs to distinguish scope kinds to find
// it.
//
// This cannot, from the touched paths alone, distinguish an ancestor
// change that structurally invalidates what is nested beneath it (a
// delete or a move of `a`) from one that only touches `a`'s own metadata
// (a `Put` that leaves `a` a directory and does not disturb `a/b`).
// `op_touched_paths` in `dag_store` only ever hands this module bare
// paths, not the `Op` they came from, and plumbing the op kind through
// would grow a second notion of what "touched" means for this fence to
// track. Fencing every ancestor change, unconditionally, is the safe
// default: a spurious bump forces an otherwise-unnecessary replan
// (expensive, but always safe -- `check_execution_generation` just
// refuses the stale phase transition and the caller replans from current
// state), while a missed bump is the exact bug this section exists to
// close. Over-fencing costs a replan; under-fencing costs a wrong commit.

/// Every distinct `transaction_id` currently holding a reservation whose
/// range covers at least one of `touched_paths`, for `group_id` — the
/// read-only lookup [`bump_transactions_for_touched_paths`] performs before
/// deciding whether it has anything gated to do at all. Order is
/// unspecified; duplicates across multiple touched paths mapping to the
/// same transaction are collapsed to one entry, since a single admitted
/// change must bump a transaction it displaces exactly once, not once per
/// path it happens to touch under that transaction.
///
/// Covers both containment directions (see the section doc above): a
/// touched path that falls inside a held reservation's own range (the
/// touched path is the reserved path itself or a descendant of it), and a
/// held reservation that falls inside the touched path's own subtree range
/// (the reservation is nested under the touched path).
///
/// Read-only, like [`list_incomplete_transactions`]/
/// [`check_execution_generation`], and for the same reason not gated behind
/// [`require_execution_enabled`]: while the gate is closed,
/// [`acquire_reservations`] can never have inserted a row for this to find
/// (it is gated itself), so this always returns empty and a caller that
/// runs it unconditionally on every DAG admission never actually reaches
/// this module's mutating half until the gate opens.
fn transactions_holding_touched_paths(
    conn: &Connection,
    group_id: &str,
    touched_paths: &[&str],
) -> Result<Vec<String>, SyncSqliteError> {
    let mut holders: Vec<String> = Vec::new();
    for path in touched_paths {
        let start = path_key(path)?;
        let end = subtree_end_key(&start);
        // `?2`/`?3` are the touched path's own `[path_key, subtree_end_key)`
        // range -- the same pair `acquire_reservations` would compute for a
        // hold at this exact path.
        //
        //  - `path_key <= ?2 AND subtree_end_key > ?2`: the touched path
        //    falls inside a held reservation's range (reservation is this
        //    path or an ancestor of it).
        //  - `path_key >= ?2 AND path_key < ?3`: a held reservation's own
        //    path falls inside the touched path's subtree range
        //    (reservation is nested under this path).
        //
        // Both arms are satisfiable from the
        // `(group_id, path_key, subtree_end_key)` index already declared
        // for this table; this stays one indexed lookup per touched path,
        // not a scan per held reservation.
        let mut stmt = conn.prepare(
            "SELECT DISTINCT transaction_id FROM filesystem_transaction_reservations \
             WHERE group_id = ?1 \
               AND ((path_key <= ?2 AND subtree_end_key > ?2) \
                 OR (path_key >= ?2 AND path_key < ?3))",
        )?;
        let rows =
            stmt.query_map(rusqlite::params![group_id, start, end], |r| r.get::<_, String>(0))?;
        for row in rows {
            let transaction_id = row?;
            if !holders.contains(&transaction_id) {
                holders.push(transaction_id);
            }
        }
    }
    Ok(holders)
}

fn bump_holders_unchecked(conn: &Connection, holders: &[String]) -> Result<(), SyncSqliteError> {
    for transaction_id in holders {
        increment_execution_generation_unchecked(conn, transaction_id)?;
    }
    Ok(())
}

/// Bumps the `execution_generation` fence of every live transaction whose
/// held reservation range covers one of `touched_paths` — the call every
/// DAG admission site (a locally emitted change, a peer change applied
/// directly, or a buffered orphan promoted once its ancestry completes)
/// makes for the paths the just-admitted change's ops touch, so that a plan
/// built against the pre-admission state is fenced out the next time it is
/// checked. One increment per distinctly held transaction, regardless of
/// how many of `touched_paths` that transaction's range covers.
///
/// Returns the transaction_ids bumped, mainly so a caller can log or test
/// against it; production callers otherwise ignore it.
///
/// When no touched path is held by anything (the overwhelmingly common
/// case, and the only case reachable at all while [`EXECUTION_ENABLED`] is
/// `false`, since nothing can hold a reservation before then), this costs
/// one indexed range lookup per touched path and no write, and does not
/// even reach [`require_execution_enabled`] — see this section's module doc.
/// Gated for the write it performs when there IS something to bump.
pub fn bump_transactions_for_touched_paths(
    conn: &Connection,
    group_id: &str,
    touched_paths: &[&str],
) -> Result<Vec<String>, SyncSqliteError> {
    let holders = transactions_holding_touched_paths(conn, group_id, touched_paths)?;
    if holders.is_empty() {
        return Ok(holders);
    }
    require_execution_enabled()?;
    bump_holders_unchecked(conn, &holders)?;
    Ok(holders)
}

/// `resolution_planning.rs`'s own test module (`yadorilink-sync-core`) calls
/// this directly to exercise the touched-path bump without the production
/// `EXECUTION_ENABLED` gate in the way, so this is exposed through the
/// `test-support` feature (like every other cross-crate test-only helper in
/// this crate), not left `#[cfg(test)]`-only the way it could be back when
/// its only caller was in the same crate.
#[cfg(any(test, feature = "test-support"))]
pub fn bump_transactions_for_touched_paths_unchecked(
    conn: &Connection,
    group_id: &str,
    touched_paths: &[&str],
) -> Result<Vec<String>, SyncSqliteError> {
    let holders = transactions_holding_touched_paths(conn, group_id, touched_paths)?;
    bump_holders_unchecked(conn, &holders)?;
    Ok(holders)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_root_authority::fs_identity::{ObjectKind, Timestamp};

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::dag_store::init_dag_schema(&conn).unwrap();
        crate::materialized_generation::init_materialized_generation_schema(&conn).unwrap();
        init_filesystem_transaction_schema(&conn).unwrap();
        conn
    }

    /// Like [`open`], but backed by a real file so a second [`Connection`]
    /// to the same path shares the same database -- needed to drive a
    /// genuine cross-connection race, which two `:memory:` connections
    /// can never see each other's writes for.
    fn open_file_backed(path: &std::path::Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        crate::dag_store::init_dag_schema(&conn).unwrap();
        crate::materialized_generation::init_materialized_generation_schema(&conn).unwrap();
        init_filesystem_transaction_schema(&conn).unwrap();
        conn
    }

    fn sample_new_transaction<'a>(trigger: Option<&'a ChangeHash>) -> NewFilesystemTransaction<'a> {
        NewFilesystemTransaction {
            group_id: "g",
            source_path: "a.txt",
            kind: FilesystemTransactionKind::ObjectResolution,
            cause: TransactionCause::PeerProjection,
            trigger_change_hash: trigger,
            desired_frontier_hash: [7; 32],
        }
    }

    fn sample_directory_identity() -> DirectoryIdentity {
        DirectoryIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: 1 },
            object_id: PlatformObjectId::Unix { inode: 100 },
            generation_or_usn: Some(5),
            birth_or_creation_time: None,
        }
    }

    fn sample_file_identity() -> FileIdentity {
        FileIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: 1 },
            object_id: PlatformObjectId::Unix { inode: 200 },
            object_kind: ObjectKind::RegularFile,
            generation_or_usn: None,
            birth_or_creation_time: Some(Timestamp {
                seconds_since_unix_epoch: 1_700_000_000,
                subsec_nanos: 0,
            }),
            observed_size: 4,
            metadata_fingerprint: [3; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        }
    }

    // --- Execution gate -------------------------------------------------

    #[test]
    fn every_mutating_entry_point_refuses_while_the_gate_is_closed() {
        // This test's premise is `EXECUTION_ENABLED == false`; mutation
        // check performed by hand -- flipping it to `true` and re-running
        // this test makes it fail on its first assertion below (confirmed,
        // then reverted).
        let conn = open();
        let hash = ChangeHash([1; 32]);
        let new_tx = sample_new_transaction(Some(&hash));
        assert!(matches!(
            begin_transaction(&conn, &new_tx, 0),
            Err(SyncSqliteError::NotImplemented(_))
        ));
        assert!(matches!(
            increment_execution_generation(&conn, "whatever"),
            Err(SyncSqliteError::NotImplemented(_))
        ));
        assert!(matches!(
            set_transaction_phase(&conn, "whatever", 0, TransactionPhase::Committing, None, 0),
            Err(SyncSqliteError::NotImplemented(_))
        ));
        let identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: "whatever",
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"opaque",
            parent_directory_identity: &identity,
            capability_snapshot: b"opaque",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        assert!(matches!(
            insert_epoch(&conn, &new_epoch, 0, 0),
            Err(SyncSqliteError::NotImplemented(_))
        ));
        assert!(matches!(
            transition_epoch(
                &conn,
                "whatever",
                0,
                0,
                EpochState::Preparing,
                &EpochUpdate::default(),
                0
            ),
            Err(SyncSqliteError::NotImplemented(_))
        ));
        let mut conn = conn;
        let requests = [NewReservation {
            group_id: "g",
            transaction_id: "whatever",
            scope: ReservationScope::Exact,
            path: "a.txt",
            role: ReservationRole::CanonicalPath,
        }];
        assert!(matches!(
            acquire_reservations(&mut conn, &requests, 0),
            Err(SyncSqliteError::NotImplemented(_))
        ));
        assert!(matches!(
            release_reservations(&conn, "whatever"),
            Err(SyncSqliteError::NotImplemented(_))
        ));
    }

    // --- Parent transactions --------------------------------------------

    #[test]
    fn begin_transaction_starts_at_planning_with_zeroed_counters() {
        let conn = open();
        let hash = ChangeHash([1; 32]);
        let new_tx = sample_new_transaction(Some(&hash));
        let record = begin_transaction_unchecked(&conn, &new_tx, 1000).unwrap();
        assert_eq!(record.phase, TransactionPhase::Planning);
        assert_eq!(record.plan_revision, 0);
        assert_eq!(record.execution_generation, 0);
        assert_eq!(record.trigger_change_hash, Some(hash));

        let read_back = lookup_transaction(&conn, &record.transaction_id).unwrap().unwrap();
        assert_eq!(read_back, record);
    }

    #[test]
    fn lookup_of_an_unknown_transaction_is_none() {
        let conn = open();
        assert!(lookup_transaction(&conn, "nope").unwrap().is_none());
    }

    #[test]
    fn check_execution_generation_matches_or_fences() {
        let conn = open();
        let new_tx = sample_new_transaction(None);
        let record = begin_transaction_unchecked(&conn, &new_tx, 0).unwrap();
        assert!(check_execution_generation(&conn, &record.transaction_id, 0).is_ok());
        let fenced = check_execution_generation(&conn, &record.transaction_id, 5);
        assert!(matches!(
            fenced,
            Err(SyncSqliteError::ExecutionGenerationFenced { expected: 5, current: 0, .. })
        ));
    }

    #[test]
    fn increment_execution_generation_advances_and_is_reflected_in_the_fence() {
        let conn = open();
        let record = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let next = increment_execution_generation_unchecked(&conn, &record.transaction_id).unwrap();
        assert_eq!(next, 1);
        assert!(check_execution_generation(&conn, &record.transaction_id, 1).is_ok());
        assert!(check_execution_generation(&conn, &record.transaction_id, 0).is_err());
    }

    #[test]
    fn set_transaction_phase_follows_the_legal_saga_sequence() {
        let conn = open();
        let record = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        set_transaction_phase_unchecked(
            &conn,
            &record.transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();
        set_transaction_phase_unchecked(
            &conn,
            &record.transaction_id,
            0,
            TransactionPhase::AsyncPreservation,
            None,
            2,
        )
        .unwrap();
        set_transaction_phase_unchecked(
            &conn,
            &record.transaction_id,
            0,
            TransactionPhase::Completed,
            None,
            3,
        )
        .unwrap();
        let read_back = lookup_transaction(&conn, &record.transaction_id).unwrap().unwrap();
        assert_eq!(read_back.phase, TransactionPhase::Completed);
    }

    #[test]
    fn set_transaction_phase_refuses_an_illegal_jump() {
        let conn = open();
        let record = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        // Planning -> Completed skips the whole saga; must be refused.
        let result = set_transaction_phase_unchecked(
            &conn,
            &record.transaction_id,
            0,
            TransactionPhase::Completed,
            None,
            1,
        );
        assert!(matches!(result, Err(SyncSqliteError::InvalidInput(_))));
        // Nothing was touched by the refused call.
        let read_back = lookup_transaction(&conn, &record.transaction_id).unwrap().unwrap();
        assert_eq!(read_back.phase, TransactionPhase::Planning);
    }

    #[test]
    fn set_transaction_phase_refuses_on_a_stale_execution_generation() {
        let conn = open();
        let record = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        increment_execution_generation_unchecked(&conn, &record.transaction_id).unwrap();
        let result = set_transaction_phase_unchecked(
            &conn,
            &record.transaction_id,
            0, // stale: the real generation is now 1
            TransactionPhase::Committing,
            None,
            1,
        );
        assert!(matches!(result, Err(SyncSqliteError::ExecutionGenerationFenced { .. })));
    }

    #[test]
    fn set_transaction_phase_fences_the_update_itself_against_a_generation_bump_landing_after_the_check(
    ) {
        // Defect 2: `check_execution_generation` (a standalone SELECT) and
        // the phase UPDATE used to be two separate autocommit statements,
        // and the UPDATE's `WHERE` named only `transaction_id` -- no
        // generation predicate. On a plain autocommit `&Connection` (no
        // wrapping `conn.transaction()`), a concurrent
        // `increment_execution_generation` landing strictly between those
        // two statements went unnoticed: the UPDATE still matched on
        // `transaction_id` alone and silently applied a phase transition
        // decided against a generation that no longer held.
        //
        // Reproduced with two real connections to the same on-disk
        // database and actual SQLite write-lock blocking, not a timing
        // guess: the racer holds an uncommitted write lock (`BEGIN
        // IMMEDIATE`, no `COMMIT` yet) across the whole window, so the
        // victim's SELECT-based check is guaranteed to observe the
        // pre-bump generation (the racer's write is invisible until it
        // commits), and the victim's UPDATE is guaranteed to block on that
        // lock until the racer commits -- so it always evaluates its
        // `WHERE` clause against the post-bump row. If the fix's
        // `AND execution_generation = ?` predicate were reverted, this
        // UPDATE would match on `transaction_id` alone and succeed, and
        // the assertion below would fail.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("fence.sqlite3");

        let victim_conn = open_file_backed(&db_path);
        victim_conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        let record =
            begin_transaction_unchecked(&victim_conn, &sample_new_transaction(None), 0).unwrap();
        let transaction_id = record.transaction_id.clone();

        let racer_conn = open_file_backed(&db_path);
        racer_conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        racer_conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        racer_conn
            .execute(
                "UPDATE filesystem_transactions SET execution_generation = \
                 execution_generation + 1 WHERE transaction_id = ?1",
                [&transaction_id],
            )
            .unwrap();
        // Uncommitted: the row's committed generation is still 0, and the
        // racer now holds the database's write lock.

        let victim_transaction_id = transaction_id.clone();
        let victim = std::thread::spawn(move || {
            set_transaction_phase_unchecked(
                &victim_conn,
                &victim_transaction_id,
                0, // matches the still-committed generation at check time
                TransactionPhase::Committing,
                None,
                1,
            )
        });

        // Ample margin for the victim's SELECT-based check (microsecond
        // scale) to run and for the thread to then start blocking on the
        // write lock its UPDATE needs, before the racer commits.
        std::thread::sleep(std::time::Duration::from_millis(200));
        racer_conn.execute_batch("COMMIT").unwrap();
        drop(racer_conn);

        let result = victim.join().unwrap();
        assert!(
            matches!(result, Err(SyncSqliteError::ExecutionGenerationFenced { .. })),
            "the UPDATE must re-check the fence itself once unblocked, got {result:?}"
        );

        let read_back =
            lookup_transaction(&open_file_backed(&db_path), &transaction_id).unwrap().unwrap();
        assert_eq!(
            read_back.phase,
            TransactionPhase::Planning,
            "the phase must be untouched by the fenced update"
        );
    }

    /// The child-insertion race: completing a parent checks every epoch is
    /// terminal, then updates the parent to `Completed` -- two separate
    /// statements. Between them, another connection can insert a fresh
    /// `Allocated` epoch: `insert_epoch_unchecked` used to check neither the
    /// parent's phase nor its generation, so nothing stopped it, and the
    /// completion `UPDATE`'s own predicate (`transaction_id`,
    /// `execution_generation`, `phase`) says nothing about the epoch set
    /// either, so it would still match and complete right over the new
    /// child. Once the parent reads back `Completed`,
    /// `list_incomplete_transactions` never looks at it again, and the new
    /// epoch is invisible to startup recovery forever.
    ///
    /// Reproduced with two real connections to the same on-disk database and
    /// actual SQLite write-lock blocking, the same technique as
    /// `set_transaction_phase_fences_the_update_itself_against_a_generation_bump_landing_after_the_check`
    /// above: the racer's `BEGIN IMMEDIATE` insert is held open, uncommitted,
    /// across the whole window, so the victim's own epoch-terminal read is
    /// guaranteed to run before the racer's insert is visible, and the
    /// victim's completion `UPDATE` is guaranteed to block on the write lock
    /// until the racer commits -- so it always evaluates its `WHERE` clause
    /// against the post-insert `epoch_watermark`. If the fix's
    /// `AND epoch_watermark = ?` predicate (and `insert_epoch_unchecked`'s
    /// own atomic bump of that same column) were reverted, this `UPDATE`
    /// would match and complete anyway, and the assertions below would fail.
    #[test]
    fn a_child_epoch_inserted_during_completion_is_not_silently_completed_over() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("child-race.sqlite3");

        let victim_conn = open_file_backed(&db_path);
        victim_conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        let record =
            begin_transaction_unchecked(&victim_conn, &sample_new_transaction(None), 0).unwrap();
        let transaction_id = record.transaction_id.clone();

        // One epoch, driven straight to the terminal `Blocked` state, so the
        // "every epoch is terminal" check this test targets would otherwise
        // legitimately let the parent complete.
        insert_epoch_unchecked(
            &victim_conn,
            &NewEpoch {
                transaction_id: &transaction_id,
                epoch: 0,
                plan_revision: 0,
                target_path: "a.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"opaque",
                parent_directory_identity: &sample_directory_identity(),
                capability_snapshot: b"opaque",
                durability_level: DurabilityLevel::ProcessCrashSafe,
            },
            0,
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &victim_conn,
            &transaction_id,
            0,
            0,
            EpochState::Blocked,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        set_transaction_phase_unchecked(
            &victim_conn,
            &transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            0,
        )
        .unwrap();
        set_transaction_phase_unchecked(
            &victim_conn,
            &transaction_id,
            0,
            TransactionPhase::AsyncPreservation,
            None,
            0,
        )
        .unwrap();

        let racer_conn = open_file_backed(&db_path);
        racer_conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        racer_conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        // Mirrors `insert_epoch_unchecked`'s own two statements exactly --
        // the real shape a second connection racing this call would produce
        // -- rather than calling that function itself, which would try to
        // open its own transaction on a connection already inside one.
        racer_conn
            .execute(
                "UPDATE filesystem_transactions SET epoch_watermark = epoch_watermark + 1 \
                 WHERE transaction_id = ?1",
                [&transaction_id],
            )
            .unwrap();
        racer_conn
            .execute(
                "INSERT INTO filesystem_transaction_epochs \
                    (transaction_id, epoch, plan_revision, target_path, placement_role, phase, \
                     displaced_generation_id, target_generation, parent_directory_identity, \
                     displaced_snapshot, stage_path, preimage_path, backup_path, \
                     staged_identity, displaced_identity, capability_snapshot, \
                     durability_level, classification_result, captured_change_hash, \
                     encoding_version, created_at_unix_nanos, updated_at_unix_nanos) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, NULL, NULL, NULL, NULL, NULL, \
                         NULL, ?9, ?10, NULL, NULL, ?11, ?12, ?12)",
                rusqlite::params![
                    transaction_id,
                    1_i64,
                    0_i64,
                    "b.txt",
                    PlacementRole::CanonicalPath.db_str(),
                    EpochState::Allocated.db_str(),
                    b"opaque".to_vec(),
                    encode_directory_identity(&sample_directory_identity()),
                    b"opaque".to_vec(),
                    durability_level_as_db_str(DurabilityLevel::ProcessCrashSafe),
                    EPOCH_ENCODING_VERSION,
                    0_i64,
                ],
            )
            .unwrap();
        // Uncommitted: the committed epoch set is still just the one
        // `Blocked` epoch, and the racer now holds the database's write
        // lock.

        let victim_transaction_id = transaction_id.clone();
        let victim = std::thread::spawn(move || {
            set_transaction_phase_unchecked(
                &victim_conn,
                &victim_transaction_id,
                0,
                TransactionPhase::Completed,
                None,
                1,
            )
        });

        // Ample margin for the victim's epoch-terminal check (microsecond
        // scale) to run and for the thread to then start blocking on the
        // write lock its `UPDATE` needs, before the racer commits.
        std::thread::sleep(std::time::Duration::from_millis(200));
        racer_conn.execute_batch("COMMIT").unwrap();
        drop(racer_conn);

        let result = victim.join().unwrap();
        assert!(
            matches!(result, Err(SyncSqliteError::TransitionRaced { .. })),
            "a child epoch inserted between the terminal check and the completion UPDATE must \
             refuse the completion, not silently complete over it: got {result:?}"
        );

        let final_conn = open_file_backed(&db_path);
        let read_back = lookup_transaction(&final_conn, &transaction_id).unwrap().unwrap();
        assert_eq!(
            read_back.phase,
            TransactionPhase::AsyncPreservation,
            "the phase must be untouched by the refused completion"
        );
        // Starts at 1 after the setup epoch's own insert bumps it once; the
        // racer's insert bumps it a second time.
        assert_eq!(
            read_back.epoch_watermark, 2,
            "the racer's insert itself must still have landed"
        );
        let epochs = list_epochs_for_transaction(&final_conn, &transaction_id).unwrap();
        assert_eq!(
            epochs.len(),
            2,
            "the child epoch the racer inserted must still be there, not rolled back -- this is \
             the parent's completion refusing, not the child's insertion"
        );
    }

    /// The defect this closes: `insert_epoch_unchecked` used to key its
    /// atomic bump-and-insert purely on `transaction_id`, never on the
    /// parent's own `phase` -- so an epoch could be inserted under a
    /// transaction already `Completed`. `list_incomplete_transactions`
    /// enumerates only non-`Completed` transactions, so that epoch would be
    /// permanently invisible to every future startup recovery pass.
    #[test]
    fn insert_epoch_into_a_completed_transaction_is_refused() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        // Zero epochs, so the "every epoch is terminal" check each phase
        // move performs along the way passes trivially -- this test targets
        // the insert-side guard, not the completion-side one already
        // covered above.
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::AsyncPreservation,
            None,
            2,
        )
        .unwrap();
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Completed,
            None,
            3,
        )
        .unwrap();

        let identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        let result = insert_epoch_unchecked(&conn, &new_epoch, 0, 4);
        assert!(
            matches!(result, Err(SyncSqliteError::InvalidInput(_))),
            "inserting an epoch into a Completed transaction must be refused, got {result:?}"
        );

        let after = lookup_transaction(&conn, &tx.transaction_id).unwrap().unwrap();
        assert_eq!(after.epoch_watermark, 0, "a refused insert must not bump the watermark either");
        assert!(
            list_epochs_for_transaction(&conn, &tx.transaction_id).unwrap().is_empty(),
            "no epoch row may exist after a refused insert"
        );
    }

    /// The defect this closes: before this, an epoch insert checked only
    /// that the parent was not yet `Completed`, never its
    /// `execution_generation`. A worker holding a plan built at generation
    /// `0` that loses a race with a concurrent generation bump (here
    /// reproduced directly with `increment_execution_generation_unchecked`,
    /// the same primitive a real admission-time fence or replan calls) must
    /// be refused before either the watermark or the epoch row is touched --
    /// not merely allowed through and left to fail on its epoch's first
    /// transition, which is the shape that leaves a permanently-`Allocated`,
    /// non-terminal epoch blocking the parent from ever completing.
    #[test]
    fn insert_epoch_refuses_a_stale_execution_generation() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        increment_execution_generation_unchecked(&conn, &tx.transaction_id).unwrap();

        let identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        // Still believes generation 0, but the transaction is now at 1.
        let result = insert_epoch_unchecked(&conn, &new_epoch, 0, 1);
        assert!(
            matches!(
                result,
                Err(SyncSqliteError::ExecutionGenerationFenced { expected: 0, current: 1, .. })
            ),
            "an insert whose captured generation no longer matches must be refused before \
             anything is written, got {result:?}"
        );

        let after = lookup_transaction(&conn, &tx.transaction_id).unwrap().unwrap();
        assert_eq!(
            after.epoch_watermark, 0,
            "a refused insert must not bump the watermark, generation fence included"
        );
        assert!(
            list_epochs_for_transaction(&conn, &tx.transaction_id).unwrap().is_empty(),
            "no epoch row may exist after a refused insert, generation fence included"
        );
    }

    /// The defect this closes -- the exact race the parent ticket describes:
    /// a worker holds a plan slice built at `plan_revision` 0, a concurrent
    /// replan advances the transaction to `plan_revision` 1 (here
    /// reproduced directly with `set_plan_revision_unchecked`, the same
    /// primitive `resolution_planning::replan` calls) and returns the saga
    /// to `Planning` -- still a phase legal to receive new epochs. The
    /// stale worker's insert, still carrying `plan_revision` 0, must be
    /// refused rather than landing an epoch for a plan revision nothing
    /// current recognizes: every later transition on such an epoch would
    /// capture the *new* generation as its fence (see
    /// `insert_epoch_refuses_a_stale_execution_generation` for that half)
    /// and the epoch would sit at `Allocated` forever, permanently blocking
    /// the parent's completion.
    #[test]
    fn insert_epoch_refuses_a_stale_plan_revision() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        set_plan_revision_unchecked(&conn, &tx.transaction_id, 0, 1).unwrap();

        let identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            // Still believes plan_revision 0, but the transaction is now at 1.
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        let result = insert_epoch_unchecked(&conn, &new_epoch, 0, 1);
        assert!(
            matches!(result, Err(SyncSqliteError::TransitionRaced { .. })),
            "an insert whose captured plan_revision no longer matches must be refused before \
             anything is written, got {result:?}"
        );

        let after = lookup_transaction(&conn, &tx.transaction_id).unwrap().unwrap();
        assert_eq!(
            after.epoch_watermark, 0,
            "a refused insert must not bump the watermark, plan_revision fence included"
        );
        assert!(
            list_epochs_for_transaction(&conn, &tx.transaction_id).unwrap().is_empty(),
            "no epoch row may exist after a refused insert, plan_revision fence included"
        );
    }

    /// The defect this closes: before this, the only phase an epoch insert
    /// refused was `Completed`. `AsyncPreservation` and `Blocked` are not
    /// working states either -- see `TransactionPhase::may_receive_new_
    /// epochs`'s own doc -- and an insert that reached either of them
    /// through this guard alone (both are legal `can_transition_to`
    /// destinations, so a caller cannot tell from the phase transition
    /// table alone that they are illegal for a *new* epoch) used to
    /// succeed. Exercises both phases in one test since they share the same
    /// refusal path and the same reasoning.
    #[test]
    fn insert_epoch_refuses_async_preservation_and_blocked_phases() {
        let conn = open();
        let identity = sample_directory_identity();

        let async_tx =
            begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        set_transaction_phase_unchecked(
            &conn,
            &async_tx.transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();
        set_transaction_phase_unchecked(
            &conn,
            &async_tx.transaction_id,
            0,
            TransactionPhase::AsyncPreservation,
            None,
            2,
        )
        .unwrap();
        let async_epoch = NewEpoch {
            transaction_id: &async_tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        let async_result = insert_epoch_unchecked(&conn, &async_epoch, 0, 3);
        assert!(
            matches!(async_result, Err(SyncSqliteError::InvalidInput(_))),
            "an insert while the parent is at AsyncPreservation must be refused, got \
             {async_result:?}"
        );
        let async_after = lookup_transaction(&conn, &async_tx.transaction_id).unwrap().unwrap();
        assert_eq!(async_after.epoch_watermark, 0);
        assert!(list_epochs_for_transaction(&conn, &async_tx.transaction_id).unwrap().is_empty());

        let blocked_tx =
            begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        set_transaction_phase_unchecked(
            &conn,
            &blocked_tx.transaction_id,
            0,
            TransactionPhase::Blocked,
            Some("stalled"),
            1,
        )
        .unwrap();
        let blocked_epoch = NewEpoch {
            transaction_id: &blocked_tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "b.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        let blocked_result = insert_epoch_unchecked(&conn, &blocked_epoch, 0, 2);
        assert!(
            matches!(blocked_result, Err(SyncSqliteError::InvalidInput(_))),
            "an insert while the parent is Blocked must be refused, got {blocked_result:?}"
        );
        let blocked_after = lookup_transaction(&conn, &blocked_tx.transaction_id).unwrap().unwrap();
        assert_eq!(blocked_after.epoch_watermark, 0);
        assert!(list_epochs_for_transaction(&conn, &blocked_tx.transaction_id).unwrap().is_empty());
    }

    /// End-to-end: the deadlock the parent ticket describes never gets a
    /// chance to form. A stale worker (superseded generation *and*
    /// plan_revision, exactly what a real replan advances together) is
    /// refused at allocation time -- not merely at its epoch's first
    /// transition -- so no non-terminal epoch is ever created to block
    /// completion. The transaction that actually replanned is then driven,
    /// through its own fresh epoch, all the way to `Completed`.
    #[test]
    fn a_stale_worker_refused_at_allocation_never_blocks_the_parent_from_completing() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();

        // Worker A's stale belief, captured before the replan below: still
        // generation 0, plan_revision 0.
        let stale_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"stale",
            parent_directory_identity: &dir_identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };

        // Worker B's replan: advances plan_revision and execution_generation
        // together, exactly as `resolution_planning::replan_unchecked` does,
        // and leaves the saga at `Planning` -- not `Completed`, so the old,
        // phase-only guard would have let worker A's insert through.
        increment_execution_generation_unchecked(&conn, &tx.transaction_id).unwrap();
        set_plan_revision_unchecked(&conn, &tx.transaction_id, 0, 1).unwrap();

        // Worker A allocates its now-stale slice and is refused, not
        // silently admitted.
        let stale_result = insert_epoch_unchecked(&conn, &stale_epoch, 0, 1);
        assert!(
            matches!(
                stale_result,
                Err(SyncSqliteError::ExecutionGenerationFenced { .. })
                    | Err(SyncSqliteError::TransitionRaced { .. })
            ),
            "the stale worker's allocation must be refused, got {stale_result:?}"
        );
        assert!(
            list_epochs_for_transaction(&conn, &tx.transaction_id).unwrap().is_empty(),
            "the refused, stale epoch must never exist -- if it did, it could never leave \
             Allocated (every later transition would fail the generation fence it captured) \
             and would block the parent from Completed forever"
        );

        // The transaction that actually replanned allocates its own fresh
        // epoch, at the live generation and plan_revision, and drives it to
        // completion -- proving nothing the refused insert left behind
        // stands in the way.
        let fresh_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 1,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"fresh",
            parent_directory_identity: &dir_identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        insert_epoch_unchecked(&conn, &fresh_epoch, 1, 2).unwrap();

        for (state, at) in [
            (EpochState::Preparing, 3),
            (EpochState::PreparedArtifact, 4),
            (EpochState::AwaitingReservation, 5),
            (EpochState::Prepared, 6),
            (EpochState::Committing, 7),
            (EpochState::Committed, 8),
            (EpochState::CustodyTransferred, 9),
            (EpochState::AwaitingQuiescence, 10),
            (EpochState::ClassifiedKnown, 11),
            (EpochState::Released, 12),
            (EpochState::Completed, 13),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                0,
                1,
                state,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }
        for (state, at) in
            [(TransactionPhase::Committing, 14), (TransactionPhase::AsyncPreservation, 15)]
        {
            set_transaction_phase_unchecked(&conn, &tx.transaction_id, 1, state, None, at).unwrap();
        }
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            1,
            TransactionPhase::Completed,
            None,
            16,
        )
        .expect(
            "nothing the refused, stale allocation left behind may block the replanned \
             transaction from completing",
        );
    }

    /// The defect this closes: `set_plan_revision_unchecked` used to take no
    /// `expected_plan_revision` at all -- it just wrote whatever the caller
    /// computed, unconditionally. Two callers that both read
    /// `plan_revision == 0` (exactly what two concurrent
    /// `resolution_planning::replan` calls would each do) would both go on
    /// to compute `1` and both succeed at writing it: the second write is
    /// silently indistinguishable from the first, even though only one of
    /// them was actually racing a still-current read. Modeled directly here
    /// rather than through `replan_unchecked` itself, since that function
    /// now runs inside one `BEGIN IMMEDIATE` transaction and two real
    /// concurrent calls to it are therefore already serialized by SQLite's
    /// own write lock before either one's read can go stale -- this test
    /// instead exercises the primitive's own compare-and-swap directly, the
    /// exact mechanism that makes that serialization actually matter instead
    /// of merely trusting that no caller ever bypasses it.
    #[test]
    fn set_plan_revision_is_a_genuine_compare_and_swap_not_an_unconditional_write() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();

        // Two callers that both read plan_revision == 0 before either one
        // writes -- exactly what two concurrent replans, each unaware of
        // the other, would each have observed.
        set_plan_revision_unchecked(&conn, &tx.transaction_id, 0, 1).unwrap();
        let second = set_plan_revision_unchecked(&conn, &tx.transaction_id, 0, 1);
        assert!(
            matches!(second, Err(SyncSqliteError::TransitionRaced { .. })),
            "a second writer whose own expected_plan_revision (0) no longer matches the row \
             (already 1) must be refused, not silently re-apply the same value as if it had \
             won too: got {second:?}"
        );

        let after = lookup_transaction(&conn, &tx.transaction_id).unwrap().unwrap();
        assert_eq!(after.plan_revision, 1, "only the first writer's revision may land");
    }

    /// The defect this closes: `set_desired_frontier_hash_unchecked` used to
    /// take no fence at all -- an unconditional `UPDATE ... WHERE
    /// transaction_id = ?`. A stale worker (one that read the transaction
    /// before a replan bumped `execution_generation` and `plan_revision`
    /// together) could overwrite a fresher worker's already-recorded
    /// frontier hash with its own stale one, leaving the durable
    /// `desired_frontier_hash` column naming a plan nothing is executing
    /// anymore, even though allocation itself was already fenced elsewhere.
    #[test]
    fn set_desired_frontier_hash_is_a_genuine_compare_and_swap_not_an_unconditional_write() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();

        // Worker A's read: generation 0, plan_revision 0 -- the transaction's
        // starting state.
        let stale_generation = 0;
        let stale_plan_revision = 0;
        let stale_hash = [0xAA; 32];

        // Worker B replans first: bumps both columns together, exactly as
        // `resolution_planning::replan_unchecked` does, then records the
        // fresh frontier hash for the plan it just built.
        increment_execution_generation_unchecked(&conn, &tx.transaction_id).unwrap();
        set_plan_revision_unchecked(&conn, &tx.transaction_id, 0, 1).unwrap();
        let fresh_hash = [0xBB; 32];
        set_desired_frontier_hash_unchecked(&conn, &tx.transaction_id, 1, 1, fresh_hash).unwrap();

        // Worker A resumes and tries to record its own (now stale) hash
        // using the generation and plan_revision it originally read.
        let stale_write = set_desired_frontier_hash_unchecked(
            &conn,
            &tx.transaction_id,
            stale_generation,
            stale_plan_revision,
            stale_hash,
        );
        assert!(
            matches!(stale_write, Err(SyncSqliteError::TransitionRaced { .. })),
            "a stale writer whose expected (generation, plan_revision) no longer matches the row \
             must be refused, not silently overwrite the newer hash: got {stale_write:?}"
        );

        let after = lookup_transaction(&conn, &tx.transaction_id).unwrap().unwrap();
        assert_eq!(
            after.desired_frontier_hash, fresh_hash,
            "the newer worker's frontier hash must survive the stale worker's overwrite attempt"
        );
    }

    /// The defect this closes: the SQL `bump_epoch_watermark_if_not_completed`
    /// builds used to be derived from a hand-written five-variant array
    /// filtered by `TransactionPhase::may_receive_new_epochs`, which was
    /// itself a `matches!` with an implicit `_ => false` arm -- a new
    /// variant would silently fall out of the legal-phase list rather than
    /// forcing a compile error, and the query's placeholder count was
    /// separately hard-coded to 2, checked only by a `debug_assert`. Neither
    /// half is meaningfully testable at runtime: a `#[test]` cannot add a
    /// `TransactionPhase` variant and observe a compile failure. What IS
    /// testable, and is asserted here, is that the actual runtime output of
    /// that derivation -- the set of phases the SQL will match -- is exactly
    /// {Planning, Committing} right now, so a regression that silently
    /// changes the *computed* legal set (as opposed to one only reachable by
    /// adding a variant) is still caught. The compile-time half of the
    /// guarantee lives in `TransactionPhase::may_receive_new_epochs` and
    /// `TransactionPhase::successor` themselves: both are exhaustive
    /// `match`es with no wildcard arm, so `cargo check` -- not this test --
    /// is what refuses to build once a new variant is added without an
    /// explicit decision in each.
    #[test]
    fn legal_phases_for_new_epochs_is_exactly_planning_and_committing() {
        let legal: Vec<TransactionPhase> = TransactionPhase::ALL
            .into_iter()
            .filter(|phase| phase.may_receive_new_epochs())
            .collect();
        assert_eq!(
            legal,
            vec![TransactionPhase::Planning, TransactionPhase::Committing],
            "bump_epoch_watermark_if_not_completed's SQL is built from exactly this list"
        );
    }

    /// The assertion the test above cannot make. That one reads the `Vec`
    /// the derivation produces, which stays green under the only thing that
    /// derivation actually changed at runtime: the dynamically generated
    /// placeholder list. A list of two phases with a mis-generated
    /// `IN (...)` clause -- the previous hard-coded-to-2 placeholder count,
    /// or an off-by-one in the `?{i + 3}` numbering -- binds the wrong
    /// parameters or none, and the `Vec` assertion notices nothing. So this
    /// runs the real statement: a `Planning` transaction must be allowed a
    /// new epoch, and an `AsyncPreservation` one must be refused, both
    /// decided by the generated SQL's own `WHERE` rather than by any Rust
    /// predicate a test can read directly.
    #[test]
    fn bump_epoch_watermark_if_not_completed_binds_the_generated_sql() {
        let conn = open();
        let planning =
            begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        assert!(
            bump_epoch_watermark_if_not_completed(&conn, &planning.transaction_id, 1).is_ok(),
            "a transaction at Planning may receive a new epoch, and the generated IN (...) must \
             actually bind that phase"
        );
        assert_eq!(
            lookup_transaction(&conn, &planning.transaction_id).unwrap().unwrap().epoch_watermark,
            planning.epoch_watermark + 1,
            "the guarded UPDATE must have matched the row it authorized"
        );

        let preserving =
            begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        for (phase, at) in
            [(TransactionPhase::Committing, 1), (TransactionPhase::AsyncPreservation, 2)]
        {
            set_transaction_phase_unchecked(&conn, &preserving.transaction_id, 0, phase, None, at)
                .unwrap();
        }
        let refused = bump_epoch_watermark_if_not_completed(&conn, &preserving.transaction_id, 1);
        assert!(
            matches!(refused, Err(SyncSqliteError::InvalidInput(_))),
            "AsyncPreservation is not a phase that may receive a new epoch, and it is the \
             generated SQL's own WHERE that must refuse it: {refused:?}"
        );
        assert_eq!(
            lookup_transaction(&conn, &preserving.transaction_id).unwrap().unwrap().epoch_watermark,
            preserving.epoch_watermark,
            "a refused allocation must not have moved the watermark"
        );
    }

    #[test]
    fn transaction_phase_transition_table_matches_the_synthesized_sequence() {
        use TransactionPhase::*;
        assert!(Planning.can_transition_to(Committing));
        assert!(Committing.can_transition_to(AsyncPreservation));
        assert!(AsyncPreservation.can_transition_to(Completed));
        assert!(Committing.can_transition_to(Planning), "replanning returns to Planning");
        assert!(Blocked.can_transition_to(Planning), "unblocked resumes at Planning");
        assert!(Planning.can_transition_to(Blocked));
        assert!(!Completed.can_transition_to(Blocked), "a completed saga cannot be blocked");
        assert!(!Blocked.can_transition_to(Blocked), "no self-transition");
        assert!(!Planning.can_transition_to(Completed), "no skipping the sequence");
        assert!(!Completed.can_transition_to(Planning), "terminal, no resurrection");
    }

    // --- Epochs -----------------------------------------------------------

    #[test]
    fn insert_epoch_round_trips_every_field_including_identities() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"opaque-target",
            parent_directory_identity: &dir_identity,
            capability_snapshot: b"opaque-caps",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        let written = insert_epoch_unchecked(&conn, &new_epoch, 0, 1000).unwrap();
        assert_eq!(written.phase, EpochState::Allocated);
        let read_back = lookup_epoch(&conn, &tx.transaction_id, 0).unwrap().unwrap();
        assert_eq!(read_back.transaction_id, written.transaction_id);
        assert_eq!(read_back.epoch, written.epoch);
        assert_eq!(read_back.target_path, written.target_path);
        assert_eq!(read_back.placement_role, written.placement_role);
        assert_eq!(read_back.phase, written.phase);
        assert_eq!(read_back.stage_path, written.stage_path);
        assert_eq!(read_back.staged_identity, written.staged_identity);
        assert_eq!(read_back.displaced_identity, written.displaced_identity);
        // Field-by-field rather than through `DirectoryIdentity::compare`:
        // this asserts the row round-tripped byte-for-byte, which is a
        // different question from whether two observations name one object --
        // a `Fallback` id round-trips perfectly and still compares ambiguous.
        assert_eq!(
            read_back.parent_directory_identity.volume_identity,
            dir_identity.volume_identity
        );
        assert_eq!(read_back.parent_directory_identity.object_id, dir_identity.object_id);
        assert_eq!(
            read_back.parent_directory_identity.generation_or_usn,
            dir_identity.generation_or_usn
        );
        assert_eq!(read_back.target_generation, b"opaque-target");
        assert_eq!(read_back.capability_snapshot, b"opaque-caps");
        assert_eq!(read_back.durability_level, DurabilityLevel::PowerLossSafe);
        assert!(read_back.staged_identity.is_none());
    }

    #[test]
    fn epoch_rows_are_never_reused_a_second_epoch_number_is_a_new_row() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();
        for epoch in [0, 1] {
            let new_epoch = NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch,
                plan_revision: 0,
                target_path: "a.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"g",
                parent_directory_identity: &dir_identity,
                capability_snapshot: b"c",
                durability_level: DurabilityLevel::PowerLossSafe,
            };
            insert_epoch_unchecked(&conn, &new_epoch, 0, 0).unwrap();
        }
        assert!(lookup_epoch(&conn, &tx.transaction_id, 0).unwrap().is_some());
        assert!(lookup_epoch(&conn, &tx.transaction_id, 1).unwrap().is_some());
    }

    #[test]
    fn transition_epoch_follows_the_committed_path_and_records_progressive_fields() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &dir_identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        insert_epoch_unchecked(&conn, &new_epoch, 0, 0).unwrap();

        let staged = sample_file_identity();
        let after_prep = transition_epoch_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            0,
            EpochState::Preparing,
            &EpochUpdate {
                stage_path: Some(".yadorilink-v1-stage.abc"),
                staged_identity: Some(&staged),
                ..Default::default()
            },
            1,
        )
        .unwrap();
        assert_eq!(after_prep.phase, EpochState::Preparing);
        assert_eq!(after_prep.stage_path.as_deref(), Some(".yadorilink-v1-stage.abc"));
        assert_eq!(after_prep.staged_identity, Some(staged));

        for (state, at) in [
            (EpochState::PreparedArtifact, 2),
            (EpochState::AwaitingReservation, 3),
            (EpochState::Prepared, 4),
            (EpochState::Committing, 5),
            (EpochState::Committed, 6),
            (EpochState::CustodyTransferred, 7),
            (EpochState::AwaitingQuiescence, 8),
            (EpochState::ClassifiedKnown, 9),
            (EpochState::Released, 10),
            (EpochState::Completed, 11),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                0,
                0,
                state,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }
        let final_state = lookup_epoch(&conn, &tx.transaction_id, 0).unwrap().unwrap();
        assert_eq!(final_state.phase, EpochState::Completed);
        // Fields set earlier in the lifecycle must still be there --
        // `EpochUpdate::default()` (all `None`) must never clear them.
        assert_eq!(final_state.stage_path.as_deref(), Some(".yadorilink-v1-stage.abc"));
        assert_eq!(final_state.staged_identity, Some(staged));
    }

    #[test]
    fn transition_epoch_refuses_an_illegal_jump() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &dir_identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        insert_epoch_unchecked(&conn, &new_epoch, 0, 0).unwrap();
        // Allocated -> Committed skips the whole preparation sequence.
        let result = transition_epoch_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            0,
            EpochState::Committed,
            &EpochUpdate::default(),
            1,
        );
        assert!(matches!(result, Err(SyncSqliteError::InvalidInput(_))));
        let read_back = lookup_epoch(&conn, &tx.transaction_id, 0).unwrap().unwrap();
        assert_eq!(
            read_back.phase,
            EpochState::Allocated,
            "the refused call must not have moved it"
        );
    }

    #[test]
    fn transition_epoch_refuses_on_a_stale_execution_generation() {
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        increment_execution_generation_unchecked(&conn, &tx.transaction_id).unwrap();
        let dir_identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &dir_identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        // The generation was already bumped above, so the insert must be
        // told the live generation (1), not a stale 0 -- this test's own
        // point is that a *later transition's* stale belief is refused, not
        // the insert's.
        insert_epoch_unchecked(&conn, &new_epoch, 1, 0).unwrap();
        let result = transition_epoch_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            0, // stale
            EpochState::Preparing,
            &EpochUpdate::default(),
            1,
        );
        assert!(matches!(result, Err(SyncSqliteError::ExecutionGenerationFenced { .. })));
    }

    #[test]
    fn transition_epoch_fences_the_update_itself_against_a_generation_bump_landing_after_the_check()
    {
        // Same defect as
        // `set_transaction_phase_fences_the_update_itself_against_a_generation_bump_landing_after_the_check`,
        // for the other entry point: `filesystem_transaction_epochs` has
        // no `execution_generation` column of its own (the fence lives on
        // the parent `filesystem_transactions` row), so the fix is a
        // subselect in the `WHERE` clause rather than a plain equality --
        // this proves that subselect is load-bearing under the same real
        // cross-connection race, not merely well-formed SQL.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("fence.sqlite3");

        let victim_conn = open_file_backed(&db_path);
        victim_conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        let tx =
            begin_transaction_unchecked(&victim_conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &dir_identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        insert_epoch_unchecked(&victim_conn, &new_epoch, 0, 0).unwrap();
        let transaction_id = tx.transaction_id.clone();

        let racer_conn = open_file_backed(&db_path);
        racer_conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        racer_conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        racer_conn
            .execute(
                "UPDATE filesystem_transactions SET execution_generation = \
                 execution_generation + 1 WHERE transaction_id = ?1",
                [&transaction_id],
            )
            .unwrap();
        // Uncommitted: the parent transaction's committed generation is
        // still 0, and the racer now holds the database's write lock.

        let victim_transaction_id = transaction_id.clone();
        let victim = std::thread::spawn(move || {
            transition_epoch_unchecked(
                &victim_conn,
                &victim_transaction_id,
                0,
                0, // matches the still-committed generation at check time
                EpochState::Preparing,
                &EpochUpdate::default(),
                1,
            )
        });

        std::thread::sleep(std::time::Duration::from_millis(200));
        racer_conn.execute_batch("COMMIT").unwrap();
        drop(racer_conn);

        let result = victim.join().unwrap();
        assert!(
            matches!(result, Err(SyncSqliteError::ExecutionGenerationFenced { .. })),
            "the UPDATE must re-check the fence itself once unblocked, got {result:?}"
        );

        let final_conn = open_file_backed(&db_path);
        let read_back = lookup_epoch(&final_conn, &transaction_id, 0).unwrap().unwrap();
        assert_eq!(
            read_back.phase,
            EpochState::Allocated,
            "the epoch phase must be untouched by the fenced update"
        );
    }

    #[test]
    fn transition_epoch_refuses_a_sibling_that_raced_it_to_the_same_source_phase() {
        // Defect 1's exact harm scenario: two workers share one
        // `execution_generation` and both read the same epoch at
        // `Committing`. One decides `RequiresPhysicalRecovery`, the other
        // decides `Committed` -- both individually legal destinations from
        // `Committing`. The `execution_generation` fence alone does not
        // serialize them: neither worker bumped the generation, so it
        // still matches for both. Before the fix, the UPDATE's `WHERE`
        // named the transaction id, the epoch and the generation, but not
        // the phase the legality check actually validated against -- so
        // whichever transition landed second would silently overwrite the
        // first's decision, turning `RequiresPhysicalRecovery` back into
        // `Committed`: an illegal transition performed through the legal
        // API.
        //
        // Reproduced with two real connections to one on-disk database and
        // actual SQLite write-lock blocking, not a timing guess, following
        // the same `BEGIN IMMEDIATE` pattern as
        // `transition_epoch_fences_the_update_itself_against_a_generation_bump_landing_after_the_check`:
        // the racer holds an uncommitted write lock across the whole
        // window, so the victim's SELECT-based legality check is
        // guaranteed to still observe `Committing` (the racer's write is
        // invisible until it commits), and the victim's UPDATE is
        // guaranteed to block on that lock until the racer commits -- so it
        // always evaluates its `WHERE` clause against the post-racer row.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("sibling-race.sqlite3");

        let victim_conn = open_file_backed(&db_path);
        victim_conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        let tx =
            begin_transaction_unchecked(&victim_conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &dir_identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        insert_epoch_unchecked(&victim_conn, &new_epoch, 0, 0).unwrap();
        // Drive the epoch to `Committing` before the race starts, exactly
        // as `transition_epoch_follows_the_committed_path...` does.
        for (state, at) in [
            (EpochState::Preparing, 1),
            (EpochState::PreparedArtifact, 2),
            (EpochState::AwaitingReservation, 3),
            (EpochState::Prepared, 4),
            (EpochState::Committing, 5),
        ] {
            transition_epoch_unchecked(
                &victim_conn,
                &tx.transaction_id,
                0,
                0,
                state,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }
        let transaction_id = tx.transaction_id.clone();

        // The racer plays the worker that decides `RequiresPhysicalRecovery`
        // and lands first, using the module's real transition SQL shape
        // (not a shortcut) so the test exercises the same statement the
        // victim will race against.
        let racer_conn = open_file_backed(&db_path);
        racer_conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        racer_conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        racer_conn
            .execute(
                "UPDATE filesystem_transaction_epochs SET phase = ?1, updated_at_unix_nanos = ?2 \
                 WHERE transaction_id = ?3 AND epoch = 0 AND phase = ?4",
                rusqlite::params![
                    EpochState::RequiresPhysicalRecovery.db_str(),
                    6i64,
                    &transaction_id,
                    EpochState::Committing.db_str(),
                ],
            )
            .unwrap();
        // Uncommitted: the epoch's committed phase is still `Committing`,
        // and the racer now holds the database's write lock.

        // The victim plays the worker that decides `Committed` and reads
        // the epoch before the racer's write is visible, so its own
        // `can_transition_to` legality check also passes.
        let victim_transaction_id = transaction_id.clone();
        let victim = std::thread::spawn(move || {
            transition_epoch_unchecked(
                &victim_conn,
                &victim_transaction_id,
                0,
                0, // the execution_generation neither worker touched
                EpochState::Committed,
                &EpochUpdate::default(),
                6,
            )
        });

        // Ample margin for the victim's SELECT-based check to run and the
        // thread to start blocking on the write lock its UPDATE needs,
        // before the racer commits.
        std::thread::sleep(std::time::Duration::from_millis(200));
        racer_conn.execute_batch("COMMIT").unwrap();
        drop(racer_conn);

        let result = victim.join().unwrap();
        assert!(
            matches!(result, Err(SyncSqliteError::TransitionRaced { .. })),
            "the UPDATE must re-check the source phase itself once unblocked, got {result:?}"
        );
        if let Err(SyncSqliteError::TransitionRaced { expected_state, current_state, .. }) = &result
        {
            assert_eq!(expected_state, EpochState::Committing.db_str());
            assert_eq!(current_state, EpochState::RequiresPhysicalRecovery.db_str());
        }

        let final_conn = open_file_backed(&db_path);
        let read_back = lookup_epoch(&final_conn, &transaction_id, 0).unwrap().unwrap();
        assert_eq!(
            read_back.phase,
            EpochState::RequiresPhysicalRecovery,
            "the racer's decision must not be silently overwritten by the victim's stale-phase \
             UPDATE"
        );
    }

    #[test]
    fn set_transaction_phase_refuses_a_sibling_that_raced_it_to_the_same_source_phase() {
        // The transaction-phase analogue of
        // `transition_epoch_refuses_a_sibling_that_raced_it_to_the_same_source_phase`:
        // two individually-legal destinations from the same source phase
        // (`Committing` -> `AsyncPreservation` and `Committing` ->
        // `Planning`, a replan) raced on one `execution_generation`.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("tx-sibling-race.sqlite3");

        let victim_conn = open_file_backed(&db_path);
        victim_conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        let tx =
            begin_transaction_unchecked(&victim_conn, &sample_new_transaction(None), 0).unwrap();
        set_transaction_phase_unchecked(
            &victim_conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();
        let transaction_id = tx.transaction_id.clone();

        let racer_conn = open_file_backed(&db_path);
        racer_conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        racer_conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        racer_conn
            .execute(
                "UPDATE filesystem_transactions SET phase = ?1, updated_at_unix_nanos = ?2 \
                 WHERE transaction_id = ?3 AND phase = ?4",
                rusqlite::params![
                    TransactionPhase::Planning.db_str(),
                    2i64,
                    &transaction_id,
                    TransactionPhase::Committing.db_str(),
                ],
            )
            .unwrap();

        let victim_transaction_id = transaction_id.clone();
        let victim = std::thread::spawn(move || {
            set_transaction_phase_unchecked(
                &victim_conn,
                &victim_transaction_id,
                0,
                TransactionPhase::AsyncPreservation,
                None,
                2,
            )
        });

        std::thread::sleep(std::time::Duration::from_millis(200));
        racer_conn.execute_batch("COMMIT").unwrap();
        drop(racer_conn);

        let result = victim.join().unwrap();
        assert!(matches!(result, Err(SyncSqliteError::TransitionRaced { .. })), "got {result:?}");

        let final_conn = open_file_backed(&db_path);
        let read_back = lookup_transaction(&final_conn, &transaction_id).unwrap().unwrap();
        assert_eq!(
            read_back.phase,
            TransactionPhase::Planning,
            "the racer's decision must not be silently overwritten"
        );
    }

    #[test]
    fn set_transaction_phase_refuses_to_complete_while_an_epoch_is_not_yet_completed() {
        // Defect 2: a parent saga must not reach `Completed` while a child
        // epoch is still in flight (not `EpochState::is_terminal`) -- most
        // of all not while `Committing`, since that is exactly the state
        // startup recovery's physical-inspection sweep must never miss. See
        // the invariant's comment at its call site in
        // `set_transaction_phase_unchecked` for why this is enforced here
        // rather than by widening recovery's enumeration, and
        // `set_transaction_phase_completes_around_epochs_settled_at_a_non_completed_terminal_state`
        // for the complementary case: a terminal-but-not-`Completed` epoch
        // must *not* block completion.
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();
        insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch: 0,
                plan_revision: 0,
                target_path: "a.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"g",
                parent_directory_identity: &dir_identity,
                capability_snapshot: b"c",
                durability_level: DurabilityLevel::PowerLossSafe,
            },
            0,
            0,
        )
        .unwrap();
        for (state, at) in [
            (EpochState::Preparing, 1),
            (EpochState::PreparedArtifact, 2),
            (EpochState::AwaitingReservation, 3),
            (EpochState::Prepared, 4),
            (EpochState::Committing, 5),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                0,
                0,
                state,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }

        for (state, at) in
            [(TransactionPhase::Committing, 6), (TransactionPhase::AsyncPreservation, 7)]
        {
            set_transaction_phase_unchecked(&conn, &tx.transaction_id, 0, state, None, at).unwrap();
        }
        let result = set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Completed,
            None,
            8,
        );
        assert!(matches!(result, Err(SyncSqliteError::InvalidInput(_))), "got {result:?}");
        let read_back = lookup_transaction(&conn, &tx.transaction_id).unwrap().unwrap();
        assert_eq!(
            read_back.phase,
            TransactionPhase::AsyncPreservation,
            "the refused completion must not have moved the parent"
        );

        // Once the epoch actually reaches `Completed`, the same completion
        // succeeds.
        for (state, at) in [
            (EpochState::Committed, 9),
            (EpochState::CustodyTransferred, 10),
            (EpochState::AwaitingQuiescence, 11),
            (EpochState::ClassifiedKnown, 12),
            (EpochState::Released, 13),
            (EpochState::Completed, 14),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                0,
                0,
                state,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Completed,
            None,
            15,
        )
        .unwrap();
    }

    #[test]
    fn set_transaction_phase_completes_around_epochs_settled_at_a_non_completed_terminal_state() {
        // The complementary case to
        // `set_transaction_phase_refuses_to_complete_while_an_epoch_is_not_yet_completed`:
        // `Quarantined` and `Blocked` are both terminal per
        // `EpochState::is_terminal` -- `can_transition_to` models no
        // outgoing edge from either, so requiring `EpochState::Completed`
        // specifically would make a transaction with an epoch in either
        // state permanently unable to complete. `RequiresPhysicalRecovery`
        // is deliberately NOT exercised here -- see
        // `set_transaction_phase_refuses_to_complete_while_an_epoch_is_at_requires_physical_recovery`,
        // its opposite: that state is still in flight (its §14.2 verdict is
        // not yet in), so it must keep blocking completion, not be let
        // through by this invariant. Two epochs, one settled at each of
        // `Quarantined`/`Blocked`, plus a third actually `Completed`, must
        // not block the parent.
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();

        // epoch 1: driven straight to Quarantined -- a preserved-but-
        // unresolved object, a legitimate outcome, not a saga failure.
        insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch: 1,
                plan_revision: 0,
                target_path: "b.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"g",
                parent_directory_identity: &dir_identity,
                capability_snapshot: b"c",
                durability_level: DurabilityLevel::PowerLossSafe,
            },
            0,
            0,
        )
        .unwrap();
        for (state, at) in [
            (EpochState::Preparing, 1),
            (EpochState::PreparedArtifact, 2),
            (EpochState::AwaitingReservation, 3),
            (EpochState::Prepared, 4),
            (EpochState::Committing, 5),
            (EpochState::Quarantined, 6),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                1,
                0,
                state,
                &Default::default(),
                at,
            )
            .unwrap();
        }

        // epoch 2: Blocked straight from Allocated -- the `(_, Blocked)`
        // edge is reachable from any non-terminal state.
        insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch: 2,
                plan_revision: 0,
                target_path: "c.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"g",
                parent_directory_identity: &dir_identity,
                capability_snapshot: b"c",
                durability_level: DurabilityLevel::PowerLossSafe,
            },
            0,
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &tx.transaction_id,
            2,
            0,
            EpochState::Blocked,
            &EpochUpdate::default(),
            1,
        )
        .unwrap();

        // epoch 3: driven all the way to Completed.
        insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch: 3,
                plan_revision: 0,
                target_path: "d.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"g",
                parent_directory_identity: &dir_identity,
                capability_snapshot: b"c",
                durability_level: DurabilityLevel::PowerLossSafe,
            },
            0,
            0,
        )
        .unwrap();
        for (state, at) in [
            (EpochState::Preparing, 1),
            (EpochState::PreparedArtifact, 2),
            (EpochState::AwaitingReservation, 3),
            (EpochState::Prepared, 4),
            (EpochState::Committing, 5),
            (EpochState::Committed, 6),
            (EpochState::CustodyTransferred, 7),
            (EpochState::AwaitingQuiescence, 8),
            (EpochState::ClassifiedKnown, 9),
            (EpochState::Released, 10),
            (EpochState::Completed, 11),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                3,
                0,
                state,
                &Default::default(),
                at,
            )
            .unwrap();
        }

        for (state, at) in
            [(TransactionPhase::Committing, 20), (TransactionPhase::AsyncPreservation, 21)]
        {
            set_transaction_phase_unchecked(&conn, &tx.transaction_id, 0, state, None, at).unwrap();
        }
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Completed,
            None,
            22,
        )
        .expect(
            "Quarantined/Blocked epochs are settled outcomes and must not block the parent from \
             completing",
        );
    }

    #[test]
    fn set_transaction_phase_refuses_to_complete_while_an_epoch_is_at_requires_physical_recovery() {
        // The mirror image of
        // `set_transaction_phase_completes_around_epochs_settled_at_a_non_completed_terminal_state`:
        // unlike `Quarantined`/`Blocked`, `RequiresPhysicalRecovery` is not
        // in `EpochState::is_terminal` -- design §14.2 still owes this epoch
        // a verdict (complete forward / roll back / convert to a new
        // capture epoch), so its parent must keep waiting exactly as it
        // would for a `Committing` epoch, not be waved through on the old
        // "nothing is owed to it" assumption.
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();
        insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch: 0,
                plan_revision: 0,
                target_path: "a.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"g",
                parent_directory_identity: &dir_identity,
                capability_snapshot: b"c",
                durability_level: DurabilityLevel::PowerLossSafe,
            },
            0,
            0,
        )
        .unwrap();
        for (state, at) in [
            (EpochState::Preparing, 1),
            (EpochState::PreparedArtifact, 2),
            (EpochState::AwaitingReservation, 3),
            (EpochState::Prepared, 4),
            (EpochState::Committing, 5),
            (EpochState::RequiresPhysicalRecovery, 6),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                0,
                0,
                state,
                &Default::default(),
                at,
            )
            .unwrap();
        }

        for (state, at) in
            [(TransactionPhase::Committing, 7), (TransactionPhase::AsyncPreservation, 8)]
        {
            set_transaction_phase_unchecked(&conn, &tx.transaction_id, 0, state, None, at).unwrap();
        }
        let result = set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Completed,
            None,
            9,
        );
        assert!(matches!(result, Err(SyncSqliteError::InvalidInput(_))), "got {result:?}");
        let read_back = lookup_transaction(&conn, &tx.transaction_id).unwrap().unwrap();
        assert_eq!(
            read_back.phase,
            TransactionPhase::AsyncPreservation,
            "the refused completion must not have moved the parent"
        );

        // Once late semantic recovery's "complete forward" verdict lands,
        // the same epoch resumes the ordinary post-commit pipeline and the
        // parent can complete.
        for (state, at) in [
            (EpochState::Committed, 10),
            (EpochState::CustodyTransferred, 11),
            (EpochState::AwaitingQuiescence, 12),
            (EpochState::ClassifiedKnown, 13),
            (EpochState::Released, 14),
            (EpochState::Completed, 15),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                0,
                0,
                state,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Completed,
            None,
            16,
        )
        .expect("the epoch reached Completed, so the parent may too");
    }

    #[test]
    fn set_transaction_phase_completes_after_a_blocked_epoch_is_replanned_into_a_fresh_one() {
        // The exact replan flow: an epoch blocks, the saga blocks and
        // replans back to `Planning`, and a brand-new epoch (never a reuse
        // of the blocked one's number) actually finishes the work. The
        // blocked epoch is never touched again -- it stays `Blocked`
        // forever -- and that must not prevent the saga from eventually
        // completing.
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();

        insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch: 0,
                plan_revision: 0,
                target_path: "a.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"g",
                parent_directory_identity: &dir_identity,
                capability_snapshot: b"c",
                durability_level: DurabilityLevel::PowerLossSafe,
            },
            0,
            0,
        )
        .unwrap();
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Committing,
            None,
            1,
        )
        .unwrap();
        for (state, at) in [
            (EpochState::Preparing, 2),
            (EpochState::PreparedArtifact, 3),
            (EpochState::AwaitingReservation, 4),
            (EpochState::Prepared, 5),
            (EpochState::Committing, 6),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                0,
                0,
                state,
                &Default::default(),
                at,
            )
            .unwrap();
        }
        // A non-retryable outcome blocks epoch 0 and, through it, the saga.
        transition_epoch_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            0,
            EpochState::Blocked,
            &EpochUpdate::default(),
            7,
        )
        .unwrap();
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Blocked,
            Some("epoch 0 is non-retryable"),
            8,
        )
        .unwrap();
        // Replan: back to Planning. Epoch 0 is left behind at `Blocked`,
        // untouched from here on.
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Planning,
            None,
            9,
        )
        .unwrap();
        // A real replan also advances plan_revision (`resolution_planning::
        // replan_unchecked` bumps it in the same atomic transaction as the
        // phase move above) -- reproduced explicitly here because this test
        // drives phase transitions directly rather than through `replan`,
        // and the fresh epoch below now needs the parent's live
        // plan_revision to actually match its own for
        // `bump_epoch_watermark_for_new_epoch`'s compare-and-swap to admit
        // it.
        set_plan_revision_unchecked(&conn, &tx.transaction_id, 0, 1).unwrap();

        // A fresh epoch -- number 1, never a reuse of 0 -- actually
        // completes the placement.
        insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch: 1,
                plan_revision: 1,
                target_path: "a.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"g2",
                parent_directory_identity: &dir_identity,
                capability_snapshot: b"c",
                durability_level: DurabilityLevel::PowerLossSafe,
            },
            0,
            10,
        )
        .unwrap();
        for (state, at) in [
            (EpochState::Preparing, 11),
            (EpochState::PreparedArtifact, 12),
            (EpochState::AwaitingReservation, 13),
            (EpochState::Prepared, 14),
            (EpochState::Committing, 15),
            (EpochState::Committed, 16),
            (EpochState::CustodyTransferred, 17),
            (EpochState::AwaitingQuiescence, 18),
            (EpochState::ClassifiedKnown, 19),
            (EpochState::Released, 20),
            (EpochState::Completed, 21),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                1,
                0,
                state,
                &Default::default(),
                at,
            )
            .unwrap();
        }

        for (state, at) in
            [(TransactionPhase::Committing, 22), (TransactionPhase::AsyncPreservation, 23)]
        {
            set_transaction_phase_unchecked(&conn, &tx.transaction_id, 0, state, None, at).unwrap();
        }
        set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Completed,
            None,
            24,
        )
        .expect(
            "a replanned saga must be able to complete even though the epoch it replanned away \
             from is permanently stuck at Blocked",
        );

        let blocked_epoch = lookup_epoch(&conn, &tx.transaction_id, 0).unwrap().unwrap();
        assert_eq!(
            blocked_epoch.phase,
            EpochState::Blocked,
            "the replanned-away epoch must be left exactly where it was, not retroactively \
             touched"
        );
    }

    #[test]
    fn epoch_state_committing_can_retreat_to_prepared_after_a_provably_no_op_outcome() {
        // Mirrors a real commit-window retry: Prepared -> Committing (the
        // syscall attempt) -> back to Prepared (the adapter reported
        // `NotStarted`, so nothing on disk changed) -> Committing again ->
        // Committed. Every hop uses the real gated core, not just the
        // transition-legality predicate, so the retry loop is proven at the
        // storage layer, not merely in the state matrix.
        let conn = open();
        let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let dir_identity = sample_directory_identity();
        let new_epoch = NewEpoch {
            transaction_id: &tx.transaction_id,
            epoch: 0,
            plan_revision: 0,
            target_path: "a.txt",
            placement_role: PlacementRole::CanonicalPath,
            target_generation: b"g",
            parent_directory_identity: &dir_identity,
            capability_snapshot: b"c",
            durability_level: DurabilityLevel::PowerLossSafe,
        };
        insert_epoch_unchecked(&conn, &new_epoch, 0, 0).unwrap();

        for (at, to) in [
            (1, EpochState::Preparing),
            (2, EpochState::PreparedArtifact),
            (3, EpochState::AwaitingReservation),
            (4, EpochState::Prepared),
            (5, EpochState::Committing),
        ] {
            transition_epoch_unchecked(
                &conn,
                &tx.transaction_id,
                0,
                0,
                to,
                &EpochUpdate::default(),
                at,
            )
            .unwrap();
        }

        // The adapter reported `NotStarted`: retreat to `Prepared`, the same
        // recorded snapshot, no new preparation needed.
        let retried = transition_epoch_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            0,
            EpochState::Prepared,
            &EpochUpdate::default(),
            6,
        )
        .unwrap();
        assert_eq!(retried.phase, EpochState::Prepared);

        // The retry attempt itself: Prepared -> Committing -> Committed.
        transition_epoch_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            0,
            EpochState::Committing,
            &EpochUpdate::default(),
            7,
        )
        .unwrap();
        let committed = transition_epoch_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            0,
            EpochState::Committed,
            &EpochUpdate::default(),
            8,
        )
        .unwrap();
        assert_eq!(committed.phase, EpochState::Committed);
    }

    #[test]
    fn epoch_state_committing_can_still_block_for_a_non_retryable_not_started_reason() {
        // A `NotStarted` reason that will fail identically on retry (e.g. an
        // unsupported volume) does not use `(Committing, Prepared)` — the
        // caller takes the pre-existing `(Committing, Blocked)` edge instead
        // and blocks the parent saga, since this transition table has no
        // idea what a `RetryReason` even is (that type belongs to a
        // different module and phase).
        assert!(EpochState::Committing.can_transition_to(EpochState::Blocked));
    }

    // --- Reservations -------------------------------------------------
    //
    // `reservation_scope_conflict_matrix` moved to
    // `yadorilink_replica_domain::filesystem_placement`'s own test module
    // (Phase 7D-9D) along with `ReservationScope::conflicts_with` itself.

    #[test]
    fn path_key_captures_the_exact_path_and_every_descendant() {
        let root = path_key("ab").unwrap();
        let end = subtree_end_key(&root);
        let exact = path_key("ab").unwrap();
        let child = path_key("ab/child").unwrap();
        let grandchild = path_key("ab/cd/ef").unwrap();
        assert!(ranges_overlap(&root, &end, &exact, &subtree_end_key(&exact)));
        assert!(exact >= root && exact < end);
        assert!(child >= root && child < end, "a direct child must be captured");
        assert!(
            grandchild >= root && grandchild < end,
            "a multi-level descendant must be captured"
        );
    }

    #[test]
    fn path_key_does_not_falsely_capture_an_unrelated_sibling_sharing_a_string_prefix() {
        // The exact case a naive byte-prefix range gets wrong: "ab" must
        // not accidentally capture "abc" or "ab!" (a byte value below the
        // '/' separator), since neither is "ab" or a child of "ab".
        let root = path_key("ab").unwrap();
        let end = subtree_end_key(&root);
        for sibling in ["abc", "ab!", "ab depths", "ab.txt"] {
            let key = path_key(sibling).unwrap();
            assert!(
                !(key >= root && key < end),
                "{sibling:?} must not be captured by \"ab\"'s subtree range"
            );
        }
    }

    #[test]
    fn path_key_refuses_a_nul_byte() {
        // Mutation check performed by hand: with the NUL guard in
        // `path_key` temporarily removed, this assertion fails (the call
        // "succeeds" and produces a key instead of refusing) -- confirming
        // the guard is load-bearing for the terminator-boundary safety
        // property the sibling test above depends on. Reverted afterward.
        let result = path_key("a\0b");
        assert!(matches!(result, Err(SyncSqliteError::InvalidInput(_))));
    }

    #[test]
    fn path_key_rejects_dot_dotdot_and_empty_segments() {
        for bad in ["a/./b", "a/../b", "a//b", "/a", "a/", "."] {
            let result = path_key(bad);
            assert!(result.is_err(), "{bad:?} should have been refused, got {result:?}");
        }
    }

    #[test]
    fn path_key_treats_backslash_as_a_separator_like_a_forward_slash() {
        // `a\b` and `a/b` name the same object; they must now produce the
        // same key so `ranges_overlap` actually catches the alias.
        assert_eq!(path_key("a\\b").unwrap(), path_key("a/b").unwrap());
    }

    #[test]
    fn path_key_backslash_alias_collapses_to_the_same_key_as_its_forward_slash_form() {
        // `a\b` names the same object as `a/b`. Before normalization,
        // `path_key` produced a distinct, non-conflicting key for it.
        assert_eq!(path_key("a\\b").unwrap(), path_key("a/b").unwrap());
    }

    #[test]
    fn path_key_refuses_dot_and_dotdot_aliases_rather_than_resolving_them() {
        // `a/./b` and `a/x/../b` also name `a/b`, but resolving `.`/`..`
        // segments here would need to know the surrounding tree shape (is
        // `x` really a directory?) that this module doesn't have. Matching
        // `crate::change::validate_path`, these are refused outright
        // rather than silently resolved into a possibly-wrong key.
        for alias in ["a/./b", "a/x/../b"] {
            let result = path_key(alias);
            assert!(
                matches!(result, Err(SyncSqliteError::InvalidInput(_))),
                "{alias:?} -> {result:?}"
            );
        }
    }

    #[test]
    fn root_subtree_range_contains_every_descendant_key() {
        // Proof, not assertion: the empty key's subtree range must contain
        // every real key this encoding can produce, including a `path`
        // whose first byte is close to the `0xFF` upper bound and a
        // multi-segment descendant.
        let root = path_key("").unwrap();
        assert!(root.is_empty(), "the sync root's path_key must be the empty key");
        let end = subtree_end_key(&root);
        assert_eq!(end, vec![0xFF]);
        for descendant in
            ["a", "z", "dir/child.txt", "dir/sub/grandchild", "\u{f4}\u{8f}\u{bf}\u{bf}"]
        {
            let key = path_key(descendant).unwrap();
            assert!(
                ranges_overlap(&root, &end, &key, &subtree_end_key(&key)),
                "{descendant:?}'s key must fall inside the root subtree range"
            );
        }
    }

    #[test]
    fn acquire_reservations_lets_a_root_subtree_exclusive_block_every_descendant() {
        // The bug as measured: a `SubtreeExclusive` reservation on `""`
        // used to conflict with nothing, because `path_key("")` produced
        // `[0x00]` and its `subtree_end_key` produced `[0x01]`, which
        // sorts *below* any real child key. It must now block a descendant
        // exact reservation from a different transaction.
        let mut conn = open();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::SubtreeExclusive,
                path: "",
                role: ReservationRole::SubtreeRoot,
            }],
            0,
        )
        .unwrap();
        let result = acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-b",
                scope: ReservationScope::Exact,
                path: "anything.txt",
                role: ReservationRole::CanonicalPath,
            }],
            1,
        );
        assert!(
            matches!(result, Err(SyncSqliteError::ReservationConflict { .. })),
            "a root subtree_exclusive reservation must block every descendant, got {result:?}"
        );
    }

    #[test]
    fn acquire_reservations_treats_a_backslash_alias_as_a_conflict() {
        let mut conn = open();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::Exact,
                path: "a/b",
                role: ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();
        let result = acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-b",
                scope: ReservationScope::Exact,
                path: "a\\b",
                role: ReservationRole::CanonicalPath,
            }],
            1,
        );
        assert!(
            matches!(result, Err(SyncSqliteError::ReservationConflict { .. })),
            "\"a\\\\b\" must conflict with an existing reservation on \"a/b\", got {result:?}"
        );
    }

    #[test]
    fn acquire_reservations_grants_non_overlapping_requests_from_different_transactions() {
        let mut conn = open();
        let requests = [
            NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::Exact,
                path: "a.txt",
                role: ReservationRole::CanonicalPath,
            },
            NewReservation {
                group_id: "g",
                transaction_id: "tx-b",
                scope: ReservationScope::Exact,
                path: "b.txt",
                role: ReservationRole::CanonicalPath,
            },
        ];
        for request in &requests {
            let ids = acquire_reservations_unchecked(&mut conn, std::slice::from_ref(request), 0)
                .unwrap();
            assert_eq!(ids.len(), 1);
        }
        assert_eq!(list_reservations(&conn, "tx-a").unwrap().len(), 1);
        assert_eq!(list_reservations(&conn, "tx-b").unwrap().len(), 1);
    }

    #[test]
    fn acquire_reservations_is_all_or_none_on_conflict() {
        let mut conn = open();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::Exact,
                path: "shared.txt",
                role: ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        let batch = [
            NewReservation {
                group_id: "g",
                transaction_id: "tx-b",
                scope: ReservationScope::Exact,
                path: "unrelated.txt",
                role: ReservationRole::CanonicalPath,
            },
            NewReservation {
                group_id: "g",
                transaction_id: "tx-b",
                scope: ReservationScope::Exact,
                path: "shared.txt",
                role: ReservationRole::CanonicalPath,
            },
        ];
        let result = acquire_reservations_unchecked(&mut conn, &batch, 1);
        assert!(matches!(result, Err(SyncSqliteError::ReservationConflict { .. })));
        // All-or-none: `tx-b` must hold NEITHER reservation, not just the
        // one that conflicted.
        assert!(
            list_reservations(&conn, "tx-b").unwrap().is_empty(),
            "a partially-acquired batch must never be left holding a subset"
        );
    }

    /// The point of the core/wrapper split: acquisition's all-or-none
    /// boundary becomes the *caller's* transaction, so a caller that rolls
    /// back for a reason of its own (the commit boundary's revalidation
    /// refusing, say) leaves no reservation behind. Before the split this
    /// was impossible to express at all -- `acquire_reservations_unchecked`
    /// committed its own transaction before returning, so every caller was
    /// left holding rows it then had to remember to release by hand.
    #[test]
    fn a_caller_owned_rollback_undoes_reservations_acquired_inside_it() {
        let conn = open();
        let batch = [
            NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::Exact,
                path: "a.txt",
                role: ReservationRole::CanonicalPath,
            },
            NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::Exact,
                path: "b.txt",
                role: ReservationRole::CanonicalPath,
            },
        ];

        let outcome: Result<(), SyncSqliteError> = with_immediate_transaction(&conn, |tx| {
            let ids = acquire_reservations_in_open_transaction(tx, &batch, 0)?;
            assert_eq!(ids.len(), 2);
            // Visible inside the caller's own transaction...
            assert_eq!(list_reservations(tx, "tx-a").unwrap().len(), 2);
            Err(SyncSqliteError::NotImplemented("test: caller aborts after acquiring"))
        });
        assert!(matches!(outcome, Err(SyncSqliteError::NotImplemented(_))));

        // ...and gone once the caller's transaction rolled back.
        assert!(
            list_reservations(&conn, "tx-a").unwrap().is_empty(),
            "a reservation acquired inside a caller-owned transaction must not survive that \
             transaction's rollback"
        );
    }

    // This test used to be named `acquire_reservations_never_conflicts_
    // with_its_own_transactions_prior_reservations` and asserted
    // `result.is_ok()` here: a same-transaction, overlapping-path
    // reservation across two separate `acquire_reservations` calls was
    // deliberately exempted from the conflict check. That encoded the
    // wrong behaviour -- see `acquire_reservations`'s own doc, "Why a
    // transaction's own prior reservations are not excluded", for the
    // deadlock this exemption enabled between two slices of one
    // transaction. No production caller ever relies on reserving an
    // overlapping path twice for one transaction (every real request set
    // -- `resolution_planning::slice_reservation_requests` -- gives a
    // canonical path and its conflict copies distinct paths), so the
    // conservative fix is used instead: this now pins the corrected
    // behaviour, a `ReservationConflict` naming the transaction's own
    // earlier reservation as the blocker.
    #[test]
    fn acquire_reservations_conflicts_with_its_own_transactions_prior_reservation_on_an_overlapping_path(
    ) {
        let mut conn = open();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::Exact,
                path: "a.txt",
                role: ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();
        // A later, separate acquisition call for the same transaction on an
        // overlapping path -- e.g. a second slice of the same logical
        // transaction -- must now be refused, not silently granted.
        let result = acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::Exact,
                path: "a.txt",
                role: ReservationRole::ConflictCopy,
            }],
            1,
        );
        assert!(
            matches!(
                &result,
                Err(SyncSqliteError::ReservationConflict { blocking_transaction_id, .. })
                    if blocking_transaction_id == "tx-a"
            ),
            "an overlapping reservation for the same transaction must now conflict against \
             its own prior reservation, got {result:?}"
        );
        // All-or-none still holds: the refused batch left nothing new
        // behind, so the transaction still holds exactly its first
        // reservation.
        assert_eq!(list_reservations(&conn, "tx-a").unwrap().len(), 1);
    }

    /// The defect this pins (independent review): two slices of the *same*
    /// transaction, driven through two different connections, could both
    /// pass the old same-transaction exclusion for an overlapping path and
    /// both end up holding a reservation on it. In `orchestrator::
    /// run_slice_unchecked`, reservation acquisition (step 1) runs strictly
    /// before the in-memory path lock is taken (step 2, `commit_path_locks::
    /// lock_slice_paths`) inside the very same commit-boundary transaction —
    /// so if slice B's acquisition here is refused, B never reaches the
    /// path-lock step at all, and there is no lock order for it to invert
    /// against slice A's own path-lock hold. This test uses two real,
    /// file-backed connections (a `:memory:` pair cannot see each other's
    /// writes) to prove the cross-connection case specifically, not just the
    /// single-connection shape the test above already covers.
    #[test]
    fn a_second_slice_of_one_transaction_on_a_different_connection_cannot_acquire_an_overlapping_path(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("slices.sqlite3");

        // Slice A: acquires and, in the real orchestrator, goes on to hold
        // its in-memory path lock across a physical commit window -- this
        // call returning `Ok` and committing is the durable half of that.
        let mut conn_a = open_file_backed(&db_path);
        acquire_reservations_unchecked(
            &mut conn_a,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-shared",
                scope: ReservationScope::Exact,
                path: "shared.txt",
                role: ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        // Slice B: same transaction_id, a different connection, requesting
        // an overlapping path with a different role -- exactly the shape
        // the review named. Must be refused outright, before this call ever
        // has anything to hand to a path-lock step.
        let mut conn_b = open_file_backed(&db_path);
        let result = acquire_reservations_unchecked(
            &mut conn_b,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-shared",
                scope: ReservationScope::Exact,
                path: "shared.txt",
                role: ReservationRole::ConflictCopy,
            }],
            1,
        );
        assert!(
            matches!(
                &result,
                Err(SyncSqliteError::ReservationConflict { blocking_transaction_id, .. })
                    if blocking_transaction_id == "tx-shared"
            ),
            "a second slice of the same transaction, on a different connection, must not be \
             able to acquire an overlapping reservation, got {result:?}"
        );

        // Slice A's own reservation is the only one that exists anywhere --
        // visible from either connection, since they share one file-backed
        // database. Slice B never held anything, even momentarily, so
        // there was never a path lock for it to have taken and no lock
        // order for it to invert.
        assert_eq!(list_reservations(&conn_a, "tx-shared").unwrap().len(), 1);
        assert_eq!(list_reservations(&conn_b, "tx-shared").unwrap().len(), 1);
    }

    #[test]
    fn acquire_reservations_lets_a_subtree_exclusive_block_a_descendant_exact() {
        let mut conn = open();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::SubtreeExclusive,
                path: "dir",
                role: ReservationRole::SubtreeRoot,
            }],
            0,
        )
        .unwrap();
        let result = acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-b",
                scope: ReservationScope::Exact,
                path: "dir/child.txt",
                role: ReservationRole::CanonicalPath,
            }],
            1,
        );
        assert!(matches!(result, Err(SyncSqliteError::ReservationConflict { .. })));
    }

    /// The composition the same-transaction exclusion used to hide. Dropping
    /// `AND transaction_id != ?` (see `acquire_reservations`'s own doc) makes
    /// a transaction's own rows visible to its conflict check -- which is the
    /// point -- but a *batch* is allowed to be internally overlapping:
    /// `resolution_planning::slice_reservation_requests` emits a group's
    /// placements and its `extra_reservations` into one request list, so a
    /// group carrying a `SubtreeExclusive` extra reservation together with
    /// placements inside that subtree arrives here as exactly the pairing the
    /// test above proves is a conflict.
    ///
    /// If the conflict check re-read the table per request instead of
    /// snapshotting once before the first insert, the subtree row this call
    /// itself just wrote would block this call's own descendant -- so such a
    /// slice could never acquire, under any timing, forever. That is a hard
    /// wedge rather than a race, which is why it is pinned here.
    #[test]
    fn one_batch_may_hold_a_subtree_and_a_placement_inside_it() {
        let mut conn = open();
        let ids = acquire_reservations_unchecked(
            &mut conn,
            &[
                NewReservation {
                    group_id: "g",
                    transaction_id: "tx-a",
                    scope: ReservationScope::SubtreeExclusive,
                    path: "dir",
                    role: ReservationRole::SubtreeRoot,
                },
                NewReservation {
                    group_id: "g",
                    transaction_id: "tx-a",
                    scope: ReservationScope::Exact,
                    path: "dir/child.txt",
                    role: ReservationRole::CanonicalPath,
                },
            ],
            0,
        )
        .expect(
            "a group's subtree reservation and a placement inside it are one slice's request \
             set, and must be acquirable together",
        );
        assert_eq!(ids.len(), 2);
        assert_eq!(list_reservations(&conn, "tx-a").unwrap().len(), 2);

        // ...and the exclusion the batch just established still binds
        // everyone else, so allowing the intra-batch pair did not weaken it.
        let other = acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-b",
                scope: ReservationScope::Exact,
                path: "dir/child.txt",
                role: ReservationRole::CanonicalPath,
            }],
            1,
        );
        assert!(
            matches!(other, Err(SyncSqliteError::ReservationConflict { .. })),
            "a different transaction must still be blocked, got {other:?}"
        );
    }

    #[test]
    fn acquire_reservations_allows_two_subtree_intents_on_the_same_path() {
        let mut conn = open();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::SubtreeIntent,
                path: "dir",
                role: ReservationRole::SubtreeRoot,
            }],
            0,
        )
        .unwrap();
        let result = acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-b",
                scope: ReservationScope::SubtreeIntent,
                path: "dir",
                role: ReservationRole::SubtreeRoot,
            }],
            1,
        );
        assert!(result.is_ok(), "two intents on the same subtree do not conflict");
    }

    #[test]
    fn release_reservations_frees_the_namespace_for_a_later_conflicting_request() {
        let mut conn = open();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-a",
                scope: ReservationScope::Exact,
                path: "a.txt",
                role: ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();
        release_reservations_unchecked(&conn, "tx-a").unwrap();
        assert!(list_reservations(&conn, "tx-a").unwrap().is_empty());
        let result = acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: "tx-b",
                scope: ReservationScope::Exact,
                path: "a.txt",
                role: ReservationRole::CanonicalPath,
            }],
            1,
        );
        assert!(result.is_ok(), "the released path must now be free");
    }

    // --- Fence bump at DAG admission ------------------------------------

    #[test]
    fn bump_touches_only_the_transaction_holding_the_exact_path() {
        let mut conn = open();
        let tx_a = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        let tx_b = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: &tx_a.transaction_id,
                scope: ReservationScope::Exact,
                path: "held/path.txt",
                role: ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        let bumped =
            bump_transactions_for_touched_paths_unchecked(&conn, "g", &["held/path.txt"]).unwrap();
        assert_eq!(bumped, vec![tx_a.transaction_id.clone()]);

        let a_after = lookup_transaction(&conn, &tx_a.transaction_id).unwrap().unwrap();
        assert_eq!(a_after.execution_generation, 1, "the holder's fence must advance");
        let b_after = lookup_transaction(&conn, &tx_b.transaction_id).unwrap().unwrap();
        assert_eq!(b_after.execution_generation, 0, "an uninvolved transaction must not move");
    }

    #[test]
    fn bump_on_an_unheld_path_bumps_nothing() {
        let conn = open();
        let tx_a = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();

        let bumped =
            bump_transactions_for_touched_paths_unchecked(&conn, "g", &["nobody/holds/this.txt"])
                .unwrap();
        assert!(bumped.is_empty(), "nothing is reserved, so nothing should be reported bumped");

        let a_after = lookup_transaction(&conn, &tx_a.transaction_id).unwrap().unwrap();
        assert_eq!(a_after.execution_generation, 0, "an unheld path must cost the fence nothing");
    }

    #[test]
    fn bump_on_a_path_inside_a_held_subtree_bumps_the_subtree_holder() {
        let mut conn = open();
        let tx_a = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: &tx_a.transaction_id,
                scope: ReservationScope::SubtreeExclusive,
                path: "dir",
                role: ReservationRole::SubtreeRoot,
            }],
            0,
        )
        .unwrap();

        let bumped =
            bump_transactions_for_touched_paths_unchecked(&conn, "g", &["dir/nested/child.txt"])
                .unwrap();
        assert_eq!(bumped, vec![tx_a.transaction_id.clone()]);

        let a_after = lookup_transaction(&conn, &tx_a.transaction_id).unwrap().unwrap();
        assert_eq!(a_after.execution_generation, 1, "a change under the held subtree must bump it");
    }

    #[test]
    fn bump_on_an_ancestor_of_a_held_reservation_bumps_the_nested_holder() {
        // The direction 20.46 recorded as an open gap: a transaction holds
        // a reservation on `a/b`; the admitted change touches `a` itself
        // (e.g. a delete or a move of `a`), not `a/b`. `a`'s key is never
        // inside `a/b`'s own stored range, so this only passes if the bump
        // also checks the other containment direction -- the held
        // reservation nested inside the touched path's own subtree range.
        let mut conn = open();
        let tx_a = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: &tx_a.transaction_id,
                scope: ReservationScope::Exact,
                path: "a/b",
                role: ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        let bumped = bump_transactions_for_touched_paths_unchecked(&conn, "g", &["a"]).unwrap();
        assert_eq!(bumped, vec![tx_a.transaction_id.clone()]);

        let a_after = lookup_transaction(&conn, &tx_a.transaction_id).unwrap().unwrap();
        assert_eq!(
            a_after.execution_generation, 1,
            "a change at an ancestor of a held reservation must bump its holder"
        );
    }

    #[test]
    fn bump_on_an_unrelated_sibling_does_not_bump_a_nested_holder_elsewhere() {
        // Companion to the ancestor case above: touching a path that is
        // neither an ancestor nor a descendant of the held reservation must
        // still bump nothing, so the new nested-containment arm does not
        // over-match unrelated paths that merely share a common ancestor.
        let mut conn = open();
        let tx_a = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: &tx_a.transaction_id,
                scope: ReservationScope::Exact,
                path: "a/b",
                role: ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        let bumped = bump_transactions_for_touched_paths_unchecked(&conn, "g", &["c"]).unwrap();
        assert!(bumped.is_empty(), "an unrelated sibling path must bump nothing");

        let a_after = lookup_transaction(&conn, &tx_a.transaction_id).unwrap().unwrap();
        assert_eq!(a_after.execution_generation, 0, "the unrelated holder must not move");
    }

    #[test]
    fn touched_path_lookup_uses_the_reservation_range_index_for_both_directions() {
        // Cost-shape proof, not just a correctness assertion: with many
        // reservations held, the query the bump performs for one touched
        // path must resolve via the `filesystem_reservation_range` index on
        // both its OR arms, not fall back to a full table scan -- otherwise
        // a bulk admission touching many paths degrades into a scan per
        // held reservation, which the module doc promises it never does.
        let mut conn = open();
        for i in 0..50 {
            let tx = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
            acquire_reservations_unchecked(
                &mut conn,
                &[NewReservation {
                    group_id: "g",
                    transaction_id: &tx.transaction_id,
                    scope: ReservationScope::Exact,
                    path: &format!("dir{i}/leaf.txt"),
                    role: ReservationRole::CanonicalPath,
                }],
                0,
            )
            .unwrap();
        }

        let plan: Vec<String> = conn
            .prepare(
                "EXPLAIN QUERY PLAN \
                 SELECT DISTINCT transaction_id FROM filesystem_transaction_reservations \
                 WHERE group_id = ?1 \
                   AND ((path_key <= ?2 AND subtree_end_key > ?2) \
                     OR (path_key >= ?2 AND path_key < ?3))",
            )
            .unwrap()
            .query_map(
                rusqlite::params![
                    "g",
                    b"dir0\0leaf.txt\0".to_vec(),
                    b"dir0\0leaf.txt\x01".to_vec()
                ],
                |r| r.get::<_, String>(3),
            )
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let plan = plan.join(" | ");
        assert!(
            plan.contains("filesystem_reservation_range"),
            "expected both OR arms to use the range index, got plan: {plan}"
        );
        assert!(
            !plan.contains("SCAN"),
            "expected an indexed search, not a table scan, got plan: {plan}"
        );
    }

    #[test]
    fn bump_touching_the_same_holder_through_two_paths_in_one_change_bumps_it_once() {
        let mut conn = open();
        let tx_a = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: &tx_a.transaction_id,
                scope: ReservationScope::SubtreeExclusive,
                path: "dir",
                role: ReservationRole::SubtreeRoot,
            }],
            0,
        )
        .unwrap();

        // A single change (e.g. a `Move`) can touch two paths that both fall
        // under the same held subtree; that must still be one bump, not two.
        let bumped =
            bump_transactions_for_touched_paths_unchecked(&conn, "g", &["dir/a.txt", "dir/b.txt"])
                .unwrap();
        assert_eq!(bumped, vec![tx_a.transaction_id.clone()]);

        let a_after = lookup_transaction(&conn, &tx_a.transaction_id).unwrap().unwrap();
        assert_eq!(a_after.execution_generation, 1);
    }

    #[test]
    fn a_plan_built_before_admission_is_fenced_out_after_the_bump() {
        let mut conn = open();
        let tx_a = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: &tx_a.transaction_id,
                scope: ReservationScope::Exact,
                path: "held/path.txt",
                role: ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        // A plan built at this point observed generation 0 and would present
        // it back at commit time.
        let plan_generation = tx_a.execution_generation;
        assert!(check_execution_generation(&conn, &tx_a.transaction_id, plan_generation).is_ok());

        // A DAG change is admitted on the reserved path.
        bump_transactions_for_touched_paths_unchecked(&conn, "g", &["held/path.txt"]).unwrap();

        // The old plan's generation no longer matches -- it is fenced.
        assert!(matches!(
            check_execution_generation(&conn, &tx_a.transaction_id, plan_generation),
            Err(SyncSqliteError::ExecutionGenerationFenced { .. })
        ));
        // The transaction's new, current generation is still checkable and
        // passes -- this is a fence, not a permanent wedge.
        assert!(
            check_execution_generation(&conn, &tx_a.transaction_id, plan_generation + 1).is_ok()
        );
    }

    #[test]
    fn bump_gated_public_entry_point_refuses_while_the_gate_is_closed_when_there_is_something_to_bump(
    ) {
        // This test's premise is `EXECUTION_ENABLED == false`; mutation
        // checked by hand as in `every_mutating_entry_point_refuses_while_the_gate_is_closed`.
        let mut conn = open();
        let tx_a = begin_transaction_unchecked(&conn, &sample_new_transaction(None), 0).unwrap();
        acquire_reservations_unchecked(
            &mut conn,
            &[NewReservation {
                group_id: "g",
                transaction_id: &tx_a.transaction_id,
                scope: ReservationScope::Exact,
                path: "held/path.txt",
                role: ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        assert!(matches!(
            bump_transactions_for_touched_paths(&conn, "g", &["held/path.txt"]),
            Err(SyncSqliteError::NotImplemented(_))
        ));
    }

    #[test]
    fn bump_gated_public_entry_point_is_a_true_no_op_on_an_unheld_path_while_the_gate_is_closed() {
        // The read-only lookup finds nothing to bump (nothing can be held
        // while the gate is closed -- `acquire_reservations` is itself
        // gated), so this must succeed with an empty result instead of
        // reaching `require_execution_enabled` at all.
        let conn = open();
        let bumped = bump_transactions_for_touched_paths(&conn, "g", &["whatever.txt"]).unwrap();
        assert!(bumped.is_empty());
    }

    // --- with_immediate_transaction: the RAII guard must terminate the
    //     transaction on every exit, not only `f` returning `Ok`/`Err` -----

    /// A `COMMIT` that itself fails (as opposed to a statement inside `f`
    /// failing) used to leave the connection sitting inside an
    /// unterminated `BEGIN IMMEDIATE`, because the old code's `Ok` arm had
    /// no rollback path at all. Forced here by holding an uncommitted read
    /// transaction open on a second, file-backed connection to the same
    /// database with `busy_timeout` at zero on the connection under test:
    /// `BEGIN IMMEDIATE` still succeeds (a `RESERVED` lock is compatible
    /// with the racer's `SHARED` one), `f`'s own write still succeeds for
    /// the same reason, but `COMMIT` needs to upgrade to `EXCLUSIVE` and
    /// cannot while the racer's `SHARED` lock is held -- with
    /// `busy_timeout` at zero that fails immediately with `SQLITE_BUSY`
    /// instead of blocking.
    #[test]
    fn commit_failure_still_terminates_the_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("commit-failure.sqlite3");

        let conn = open_file_backed(&db_path);
        conn.busy_timeout(std::time::Duration::from_millis(0)).unwrap();
        let hash = ChangeHash([4; 32]);
        let record =
            begin_transaction_unchecked(&conn, &sample_new_transaction(Some(&hash)), 0).unwrap();
        let transaction_id = record.transaction_id.clone();

        // A second connection holds an open read transaction across the
        // whole window below -- enough to block the first connection's
        // COMMIT without blocking its BEGIN IMMEDIATE or its write.
        let reader = open_file_backed(&db_path);
        reader.execute_batch("BEGIN; SELECT count(*) FROM filesystem_transactions;").unwrap();

        let result = with_immediate_transaction::<(), SyncSqliteError>(&conn, |c| {
            c.execute(
                "UPDATE filesystem_transactions SET plan_revision = 999 WHERE transaction_id = \
                 ?1",
                [&transaction_id],
            )?;
            Ok(())
        });
        assert!(
            result.is_err(),
            "COMMIT must fail while the reader holds its SHARED lock, got {result:?}"
        );

        // Release the reader's lock, then confirm the guard rolled the
        // failed COMMIT back rather than leaving BEGIN IMMEDIATE open: a
        // fresh `with_immediate_transaction` call on the same connection
        // must succeed, and the row must show the pre-mutation value, not
        // the one `f` wrote before COMMIT failed.
        reader.execute_batch("COMMIT").unwrap();
        drop(reader);

        let after = with_immediate_transaction::<(), SyncSqliteError>(&conn, |_| Ok(()));
        assert!(
            after.is_ok(),
            "the connection must still accept a fresh BEGIN IMMEDIATE after a failed COMMIT, \
             got {after:?}"
        );

        let reloaded = lookup_transaction(&conn, &transaction_id).unwrap().unwrap();
        assert_eq!(
            reloaded.plan_revision, 0,
            "the update made before the failed COMMIT must not have survived"
        );
    }

    /// `f` panicking must unwind through the guard the same way an `Err`
    /// does -- the guard's `Drop` impl runs during unwind exactly as it
    /// would on a normal early return, with no `catch_unwind` of its own
    /// needed inside `with_immediate_transaction`.
    #[test]
    fn panic_inside_f_still_terminates_the_transaction() {
        let conn = open();
        let hash = ChangeHash([5; 32]);
        let record =
            begin_transaction_unchecked(&conn, &sample_new_transaction(Some(&hash)), 0).unwrap();
        let transaction_id = record.transaction_id.clone();

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_immediate_transaction(&conn, |c| -> Result<(), SyncSqliteError> {
                c.execute(
                    "UPDATE filesystem_transactions SET plan_revision = 999 WHERE \
                     transaction_id = ?1",
                    [&transaction_id],
                )
                .unwrap();
                panic!("simulated failure inside f, before COMMIT ever runs");
            })
        }));
        assert!(
            outcome.is_err(),
            "expected the panic to propagate out of with_immediate_transaction"
        );

        // The guard must have rolled back on unwind: the connection is
        // usable again, and the mutation made before the panic did not
        // survive.
        let after = with_immediate_transaction::<(), SyncSqliteError>(&conn, |_| Ok(()));
        assert!(
            after.is_ok(),
            "the connection must still accept a fresh BEGIN IMMEDIATE after a panic inside f, \
             got {after:?}"
        );

        let reloaded = lookup_transaction(&conn, &transaction_id).unwrap().unwrap();
        assert_eq!(
            reloaded.plan_revision, 0,
            "the update made before the panic must not have survived"
        );
    }
}
