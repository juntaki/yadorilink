//! Early physical recovery — design `openspec/design/preimage-capture.md`
//! §14.1. The pass that runs at daemon startup, under
//! [`yadorilink_root_authority::sync_root_lock::SyncRootLock`], before signing keys or verified
//! policy exist (§14.3 step 3, well before step 7's "construct
//! `DaemonState`, signing and policy providers"). It performs no semantic
//! DAG authoring and never deletes an ambiguous artefact.
//!
//! Moved from `yadorilink-sync-core::early_physical_recovery` (Phase 7D-9E)
//! as one cohesive unit, not the three-way replica-engine/sync-sqlite/daemon
//! split an earlier pass's ledger entry proposed. That split does not match
//! this module's actual shape: [`run`] is a single, synchronous,
//! `&Connection`-driven sweep whose SQL reads/writes, physical-observation
//! decisions and one filesystem mutation ([`cleanup_unstarted_artefact`])
//! are woven through one control-flow function by function, not separable
//! at any clean boundary without rewriting the crash-recovery logic itself.
//! It has no daemon-specific content at all — no async, no signing/policy
//! provider, nothing from `yadorilink-daemon` — by the same enforced
//! constraint this doc already describes ("[`run`] takes only a
//! `&Connection`"), so `yadorilink-daemon` was never a real destination for
//! any of it. Its two real dependencies beyond this crate's own SQL
//! (`filesystem_transaction`, `retained_obligation`) are
//! `yadorilink_root_authority` and `yadorilink_filesystem_sync::fs_commit::ParentDirHandle`
//! — both already production dependencies of `yadorilink-sync-sqlite` — so
//! this crate is the correct common-ancestor destination. As of this move,
//! [`run`] has no production caller anywhere in the workspace (only a test
//! in `yadorilink-sync-core::orchestrator`'s own suite exercises it
//! directly); wiring the daemon-startup call site remains a real, still-open
//! gap this module's own doc already flagged below, not something this move
//! changes.
//!
//! # What "early" forbids, and how that is enforced
//!
//! Before signing keys and policy exist, this phase cannot: author a
//! captured change (needs a signing key), classify a displaced object as
//! known-vs-divergent (§11's classification is content-model work the
//! design assigns to late semantic recovery, §14.2), decide whether a path
//! is permitted at all (needs verified policy/auth), or replan a
//! transaction against a new frontier (needs the current DAG frontier and
//! the group's admission policy). The enforcement is not a comment: [`run`]
//! takes only a `&Connection`. There is no signing-key parameter, no policy
//! or auth-provider parameter, and no group-gate handle for a caller to pass
//! one through even by mistake, and nothing in this module imports a
//! signing type, an auth-provider type, or anything that authors a
//! [`yadorilink_replica_domain::ids::ChangeHash`]. The only mutations this module performs
//! are: (a) epoch/transaction phase bookkeeping through the already-gated
//! internal (`_unchecked`) entry points in [`filesystem_transaction`]
//! (state-machine legality only, no content), and (b) removing an
//! *unstarted* artefact this same row itself named, per the identity-proven
//! cleanup case below.
//!
//! # The settled `Committing` rule
//!
//! An epoch found at [`EpochState::Committing`] always routes to
//! [`EpochState::RequiresPhysicalRecovery`], regardless of what physical
//! inspection concludes. See
//! [`EpochState::can_transition_to`][yadorilink_replica_domain::filesystem_placement::EpochState::can_transition_to]'s
//! own doc on the `(Committing, Prepared)` edge: that edge exists only for a
//! caller that *itself*, in the same process, observed
//! `FilesystemCommitOutcome::NotStarted` in memory. A crash between the
//! commit adapter call and the SQL transaction that would have recorded the
//! outcome leaves no durable trace of which branch fired, so recovery
//! restarting cold can never legitimately reach that state even when
//! physical inspection makes the "nothing happened" or "it fully landed"
//! story look obvious — recovery still only ever has physical evidence,
//! never the live guarantee the design reserves for the in-process case.
//! This module physically inspects every location anyway (§14.1: "record
//! observed topology and any blocked ambiguity") and hands the raw
//! four-location observation to whatever later phase processes
//! `RequiresPhysicalRecovery` epochs — it does not itself decide "complete
//! forward" vs "roll back" vs "convert into a new capture epoch" (the
//! design's §14.4 recovery matrix), because each of those needs plan and
//! frontier context this phase does not have.
//!
//! # The recovery matrix principle (§14.4), and what this module covers
//!
//! §14.4 says every observed identity tuple must resolve to one of: complete
//! forward; roll back from a persisted snapshot (only if no newly observed
//! live object would be overwritten); convert a newly observed live object
//! into another capture epoch; or retain all artefacts and block. This
//! module implements only the last of those four for any state it cannot
//! trivially resolve on physical grounds alone (a `Committing` epoch, or any
//! epoch whose parent-directory identity cannot be reconfirmed) — it defers
//! "complete forward" and "roll back"/"convert" to late semantic recovery,
//! which has the plan/frontier/policy context those decisions actually
//! need. The one case this module *does* resolve unassisted is physically
//! trivial by construction: an epoch that never progressed past creating an
//! unreserved stage artefact (`Preparing`/`PreparedArtifact`/
//! `AwaitingReservation`), where "complete forward" and "roll back" are the
//! same action (there is nothing to roll back to or forward from — no
//! canonical path was ever touched). So: **partially** satisfied. The two
//! matrix branches this module does not implement are real gaps, not
//! silently skipped; every unresolved case is reported through
//! [`EarlyRecoveryAction::RoutedToPhysicalRecovery`] or
//! [`EarlyRecoveryAction::Blocked`], never dropped on the floor.
//!
//! # What this module deliberately does not load
//!
//! §14.1 also says to "load active transactions, epochs and retained
//! obligations". `retained_obligation` now owns the `retained_preimages`
//! table (§5.5) and its lifecycle — including the exact "still needs
//! captured authoring" fact §16 assigns to `AwaitingCaptureAuthorization`
//! for the epoch that created a retained object: a `Divergent` obligation
//! with no `last_captured_change_hash` recorded is, in that table's own
//! vocabulary, still waiting (`RetentionReason::NoCapturedChange`), findable
//! later via its `originating_transaction_id`/`source_epoch` columns. This
//! module still does not load or protect those rows, though — that half of
//! §14.1 is a real, still-open gap against the design text, not a decision.
//! Whichever change wires the retry that obligation is waiting for must also
//! extend this module (or give it a sibling) to load `retained_preimages`
//! rows and mark their `custody_path` owned the same way this one already
//! protects epoch artefacts, so a retained object surviving its originating
//! epoch is not left exposed to generic cleanup across a cold start.
//!
//! # Directory-relative discipline
//!
//! Parent-directory identity is reconfirmed before touching anything under
//! it (§9.1), and the one destructive action this module takes (removing an
//! unstarted stage artefact) goes through
//! [`yadorilink_filesystem_sync::fs_commit::ParentDirHandle::remove_child_if_identity_matches`]
//! — a directory-handle-relative, identity-checked removal added alongside
//! this module, symmetric with
//! [`yadorilink_filesystem_sync::fs_commit::ParentDirHandle::create_artefact`] — rather than a
//! plain path-string remove. On Unix this closes the TOCTOU window between
//! the parent-directory check above and the removal itself: both the
//! existence/kind/identity check and the unlink resolve through the same
//! directory file descriptor the check just verified, so nothing can
//! redirect the removal to a different directory that happens to reoccupy
//! the same path string in between. Windows has no directory-fd-relative
//! removal primitive at the Win32 level — the same limitation
//! [`yadorilink_filesystem_sync::fs_commit::ParentDirHandle`]'s own struct doc already states for
//! `ReplaceFileW`/`MoveFileExW` — so that branch remains a path-string
//! check-then-remove pair with a real, narrow residual window; this is the
//! platform's limitation, stated plainly rather than papered over, not a
//! choice made in this module.
//!
//! `remove_child_if_identity_matches` also refuses to remove anything but a
//! plain regular file (never a directory, never a symlink regardless of its
//! target, never an object it could not conclusively classify), so a
//! recorded `stage_path` that has somehow stopped being a plain file is
//! left untouched rather than acted on with a guess — and, on top of that
//! kind check, refuses to remove a plain regular file that does not itself
//! compare [`yadorilink_root_authority::fs_identity::IdentityComparison::SameObject`] against
//! `epoch.staged_identity` (see [`cleanup_unstarted_artefact`]'s own doc for
//! why a kind check alone was never proof of *which* regular file this row
//! actually named, and for the defined, fail-closed answer when
//! `staged_identity` was never recorded at all).

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::error::SyncSqliteError;
use crate::file_identity_codec;
use crate::filesystem_transaction::{self};
use crate::filesystem_transaction::{
    encode_directory_identity, list_epochs_for_transaction, list_incomplete_transactions,
    lookup_transaction, release_reservations_unchecked, set_transaction_phase_unchecked,
    transition_epoch_unchecked, EpochRecord, EpochUpdate, FilesystemTransactionRecord,
    TransactionPhase,
};
use crate::retained_obligation::{self, NewObligation, RetainedObligationError};
use yadorilink_filesystem_sync::fs_commit::{
    ParentDirHandle, RecoveryObservation, RemoveChildIdentityError,
};
use yadorilink_replica_domain::filesystem_placement::EpochState;
use yadorilink_root_authority::fs_identity::{DirectoryIdentity, FileIdentity, IdentityComparison};
use yadorilink_root_authority::reserved_namespace::{self, ArtefactKind};

/// Everything one call to [`run`] found and did.
#[derive(Debug, Default)]
pub struct EarlyRecoveryReport {
    /// Every path (`target_path`/`stage_path`/`preimage_path`/`backup_path`)
    /// belonging to an epoch this pass considered in-flight — for generic
    /// cleanup, hydration, eviction and audit to skip (§14.1: "mark
    /// operation-owned paths"). This report is the marking mechanism itself;
    /// wiring those other subsystems to consult it is not part of this
    /// change.
    pub owned_paths: HashSet<PathBuf>,
    pub epochs: Vec<EpochRecoveryOutcome>,
}

#[derive(Debug)]
pub struct EpochRecoveryOutcome {
    pub transaction_id: String,
    pub epoch: i64,
    pub action: EarlyRecoveryAction,
}

#[derive(Debug)]
pub enum EarlyRecoveryAction {
    /// Nothing for this phase to do. Covers several different reasons, none
    /// of which involve this phase producing new information:
    /// `Completed`/`Released` (fully resolved, nothing left to protect —
    /// `mark_owned` does not even run for these, see `recover_epoch`);
    /// `Quarantined`/`Blocked` (settled outcomes whose own state already
    /// records what a later phase needs — see `recover_epoch`'s doc on why
    /// these are not the same defect as
    /// [`PersistedRequiresPhysicalRecovery`][Self::PersistedRequiresPhysicalRecovery] —
    /// but whose artefacts *are* still marked owned); or a state this phase
    /// leaves for late semantic recovery to continue without any physical
    /// ambiguity to reconcile first (e.g. `Prepared`: nothing destructive
    /// was ever attempted). `EpochState::Allocated` also resolves to
    /// `NoAction` in principle (see `recover_epoch`'s own match arm), but is
    /// *not* a live example of this today: reaching that arm at all requires
    /// `target_path` to be absolute, and production's group-relative sync
    /// path never is, so an `Allocated` epoch's parent-directory resolution
    /// blocks first with [`BlockReason::ParentDirectoryUnresolvable`] before
    /// this arm is ever reached — see that variant's own doc and
    /// `recover_epoch`'s `parent_dir` derivation above the final match.
    NoAction,
    /// An unstarted stage artefact — recorded by this exact epoch row,
    /// never reserved, so nothing else could depend on it — was physically
    /// present and has been removed.
    UnstartedArtefactRemoved { removed_path: PathBuf },
    /// A `Committing` epoch's outcome could not be trusted from memory (see
    /// the module doc's "settled `Committing` rule"). *This call* moved it
    /// to `RequiresPhysicalRecovery`; carries the raw four-location physical
    /// observation for whatever later phase reconciles it. If a later cold
    /// start finds this same epoch still sitting at
    /// `RequiresPhysicalRecovery`, it is reported through
    /// [`PersistedRequiresPhysicalRecovery`][Self::PersistedRequiresPhysicalRecovery]
    /// instead, never this variant again — the two are kept distinguishable
    /// on purpose, since only this one represents a transition this call
    /// itself just made.
    RoutedToPhysicalRecovery(Box<PhysicalObservation>),
    /// An epoch found *already* at `RequiresPhysicalRecovery` when this pass
    /// began — not one this call transitioned into that state (that case is
    /// [`RoutedToPhysicalRecovery`][Self::RoutedToPhysicalRecovery]).
    /// Nothing durable ever carried forward whatever
    /// `PhysicalObservation`/`RecoverySnapshot` the process that reached
    /// this state built — it lived only in that process's memory and is
    /// gone once it crashed or exited. What this variant carries is a
    /// **freshly re-derived** observation: a plain, idempotent re-read of
    /// the same four locations, safe to redo on every cold start because it
    /// does not depend on anything the earlier process knew.
    ///
    /// Cost and exit condition, stated plainly rather than implied: this
    /// re-observation is bounded per epoch (a handful of `stat`-equivalent
    /// calls, same order as the pre-existing `Committing` sweep), so one
    /// startup's cost is proportional to how many epochs are currently
    /// stuck here — not to repository size. `EpochState::can_transition_to`
    /// now models the two edges §14.2 needs out of `RequiresPhysicalRecovery`
    /// (`-> Committed` for "complete forward", `-> Blocked` for "roll back"
    /// or "convert to a new capture epoch" — see that function's own doc),
    /// and `EpochState::is_terminal` no longer counts this state as settled,
    /// so a parent transaction can no longer complete out from under an
    /// epoch stuck here. But no *caller* in this crate yet drives either
    /// edge — §14.2 late semantic recovery itself is still unimplemented —
    /// so this variant is, today, still produced again on every single
    /// startup for as long as an epoch sits here. What changed is that the
    /// state table no longer forecloses the exit; what has not changed is
    /// that nothing yet takes it.
    PersistedRequiresPhysicalRecovery(Box<PhysicalObservation>),
    /// This epoch's recorded parent-directory identity could not be
    /// reconfirmed — reuse or replacement of the parent cannot be excluded,
    /// or the directory itself could not even be observed. Nothing under it
    /// was touched; the epoch and its parent transaction were both moved to
    /// `Blocked`.
    Blocked(BlockReason),
    /// An epoch at `EpochState::CustodyTransferred` or later, with a
    /// recorded `displaced_identity`, had no matching `retained_preimages`
    /// row — the crash window `orchestrator.rs`'s module doc names between
    /// custody transfer's rename and `retained_obligation::create`'s own
    /// commit (see [`recover_orphaned_custody_obligation`]). The missing
    /// obligation has been recreated from this epoch row's own durable
    /// fields, so the retained artefact is no longer exposed to generic
    /// cleanup with no owner.
    OrphanedCustodyObligationRecovered { retained_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// The parent directory was observed, but its identity does not
    /// provably match what this epoch recorded (or reuse cannot be
    /// excluded).
    ParentDirectoryUnverifiable,
    /// The parent directory could not be observed at all (a real I/O
    /// failure, not a confirmed absence) — an unreadable location is never
    /// evidence of anything, per the same fail-closed convention
    /// [`RecoveryObservation::Unreadable`] documents.
    ParentDirectoryUnreadable,
    /// A `Committed` epoch's derived custody artefact location could not be
    /// observed (a real I/O failure, not a confirmed absence) while checking
    /// whether [`recover_committed_custody_transfer`]'s crash window applies
    /// — same fail-closed reasoning as `ParentDirectoryUnreadable`: an
    /// unreadable location proves nothing either way, so this refuses to
    /// guess whether the retained artefact is there.
    RetainedArtefactUnreadable,
    /// A retained custody name existed, but the object at that name was not
    /// provably the displaced object this epoch recorded. Presence and a
    /// matching shape are not ownership proof; mismatched and ambiguous
    /// identity comparisons both block recovery.
    RetainedArtefactIdentityUnverifiable,
    /// This epoch has no physical location this module can honestly resolve
    /// a parent directory from at all: no stage artefact has been recorded
    /// yet (see [`physical_parent_dir`]'s own doc), and `target_path` is not
    /// itself an absolute path this process's own filesystem view can
    /// resolve — the ordinary case for a group-relative sync path before a
    /// stage artefact exists. Deliberately distinct from
    /// `ParentDirectoryUnverifiable` (a directory *was* observed and did not
    /// match) and `ParentDirectoryUnreadable` (a real I/O failure trying to
    /// observe one this module *did* know how to open): neither of those is
    /// true here — nothing was opened, because nothing durable names where
    /// to look. "Could not check" and "checked and it was wrong" are
    /// different findings, and only the latter is evidence the directory
    /// changed; conflating them under an existing variant would make every
    /// consumer of this report unable to tell which one actually happened.
    /// Still resolved as a block, the same fail-closed answer this pass
    /// gives every other case it cannot prove — see
    /// [`crate::early_physical_recovery`]'s own module doc on why an
    /// unresolvable location is never treated as "nothing to protect".
    ParentDirectoryUnresolvable,
}

/// The raw physical state found at every location a `Committing` epoch
/// names, one independent observation per location. Deliberately not
/// interpreted here — see the module doc.
#[derive(Debug)]
pub struct PhysicalObservation {
    pub live: RecoveryObservation,
    pub stage: Option<RecoveryObservation>,
    pub preimage: Option<RecoveryObservation>,
    pub backup: Option<RecoveryObservation>,
}

/// Runs early physical recovery over every transaction and epoch this
/// connection's journal currently holds. Must run under a held
/// [`yadorilink_root_authority::sync_root_lock::SyncRootLock`] for whichever root(s) the loaded
/// epochs' paths live under — this function does not acquire that lock
/// itself, since a process recovering more than one sync root takes the
/// lock per root before calling in, not once globally.
///
/// Precondition: `conn` must be in autocommit mode — i.e. not already inside
/// an open transaction — checked first, before any read or mutation. This is
/// the same precondition [`filesystem_transaction::with_immediate_transaction`]
/// documents on itself, but this function cannot simply inherit that
/// function's own enforcement: it processes epochs one at a time, mutating
/// rows as it goes (`transition_epoch_unchecked`, `release_reservations_
/// unchecked`, `cleanup_unstarted_artefact`'s removal) between the several
/// `BEGIN IMMEDIATE` transactions those helpers open internally, rather than
/// wrapping the whole pass in one. `rusqlite::Transaction` derefs to
/// `Connection`, so `run(&tx)` type-checks even though this module's own doc
/// never grants a caller a transaction to pass — a caller already holding
/// one and calling in anyway would see this pass mutate state under that
/// caller's transaction until an epoch it cannot resolve reaches `block`,
/// whose `with_immediate_transaction` call then fails outright on SQLite's
/// "cannot start a transaction within a transaction", leaving the caller
/// holding a transaction that is already partly mutated with no indication
/// this function was ever responsible for committing or rolling it back.
/// Refusing up front, before the first read, means a caller that violates
/// this never observes any of that: either every epoch this pass would have
/// touched is still exactly as found, or `run` was never called with an open
/// transaction in the first place.
///
/// Considered and rejected: splitting this function into a "caller-owned
/// transaction" core (taking whatever the caller already has open, no
/// `BEGIN`/`COMMIT` of its own) plus this autocommit-checking wrapper, the
/// same shape [`filesystem_transaction::acquire_reservations_in_open_transaction`]
/// uses. That split only works when the core's every internal transaction
/// can be folded into the caller's without changing its locking mode — here
/// it cannot: `block`'s `with_immediate_transaction` call specifically needs
/// `BEGIN IMMEDIATE`'s up-front write-lock semantics (see that function's own
/// doc for why `unchecked_transaction()`'s `DEFERRED` default is not enough),
/// and rusqlite gives no API to inspect what kind of transaction a caller
/// already has open — a caller-owned `DEFERRED` or plain `unchecked_
/// transaction()` cannot be upgraded to `IMMEDIATE` after the fact, and this
/// function has no way to even detect that mismatch to refuse it. Exposing a
/// caller-owned-transaction core would therefore silently accept a caller's
/// weaker transaction and run every internal recovery step under it,
/// including `block`'s own `BEGIN IMMEDIATE`, which would itself immediately
/// fail with the exact same nested-transaction error this precondition
/// exists to avoid — the split does not remove the problem, it just moves
/// where the failure happens back inside the pass instead of before it. If a
/// future rusqlite version exposes a way to prove a caller's open
/// transaction is already `IMMEDIATE` (or stronger), that would remove this
/// objection and the split becomes viable; no such API exists today.
pub fn run(conn: &Connection) -> Result<EarlyRecoveryReport, SyncSqliteError> {
    if !conn.is_autocommit() {
        return Err(SyncSqliteError::InvalidInput(
            "early_physical_recovery::run requires a connection in autocommit mode (no \
             transaction already open) -- it opens and commits several of its own internal \
             transactions as it walks epochs, and cannot join a transaction the caller already \
             holds. A caller must not pass an rusqlite::Transaction (which derefs to \
             Connection and would otherwise compile) or any &Connection with BEGIN already \
             issued on it. Call this before opening any transaction of your own."
                .to_string(),
        ));
    }
    let mut report = EarlyRecoveryReport::default();
    for transaction in list_incomplete_transactions(conn)? {
        // `orchestrator::run_slice_unchecked` acquires a whole slice's
        // reservations in exactly ONE call, before any epoch in that slice
        // has moved off `PreparedArtifact` (see the module doc's own note on
        // `physical_parent_dir` and `run_slice_unchecked`'s "revalidate into
        // `AwaitingReservation`" comment). A crash between that acquisition
        // and the first per-epoch transition therefore leaves every epoch of
        // the transaction sitting at `PreparedArtifact` while the
        // transaction as a whole still holds every reservation the slice
        // requested — nothing about any *single* epoch proves whether a
        // sibling epoch elsewhere in the same transaction is still relying
        // on that same reservation set. Whether it is safe to release can
        // therefore only be decided once, per transaction, after every one
        // of its epochs has been walked this pass — never from one epoch in
        // isolation, and never more than once from inside the per-epoch
        // dispatch (`release_reservations_unchecked` deletes the whole
        // transaction's reservation rows, not one epoch's).
        //
        // The rule: a transaction's reservations may be released once every
        // one of its epochs has been resolved by this pass to something
        // other than `RequiresPhysicalRecovery` — whether found already
        // there (`PersistedRequiresPhysicalRecovery`) or just routed there
        // from `Committing` by this same call (`RoutedToPhysicalRecovery`).
        // That state is the one the design (`orchestrator.rs`'s module doc,
        // "left un-released intentionally") deliberately leaves holding its
        // reservation across a restart, because it is the one genuine
        // physical ambiguity late semantic recovery still needs the
        // exclusion for. A `Blocked` epoch withholds too, for reasons
        // stated per `BlockReason` below — the enumeration this comment
        // used to give of states that "have nothing left to protect" was
        // both incomplete (every fully-resolved terminal state and every
        // unresumed `Prepared`/`Allocated`-adjacent state also reaches this
        // release, not just the three it named) and, for `Blocked`, wrong:
        // some `Blocked` reasons are themselves an unresolved physical
        // question, not a settled one.
        //
        // Every `BlockReason` this module currently produces (`block`'s own
        // call sites) is examined below, because whether a given reason may
        // release is a judgement call this comment makes explicit rather
        // than leaving implicit in a `matches!` arm:
        //
        // - `ParentDirectoryUnreadable` and `RetainedArtefactUnreadable`:
        //   both are a real I/O failure observing a location, not a
        //   confirmed absence — see each variant's own doc, which already
        //   says outright that an unreadable location "proves nothing
        //   either way". Releasing the reservation here would treat a
        //   failed `stat` the same as a confirmed "nothing left to
        //   protect", which is exactly the guess those docs refuse to make.
        //   Must withhold.
        // - `ParentDirectoryUnverifiable`: the parent directory *was*
        //   observed, but its identity does not provably match what the
        //   epoch recorded — reuse or replacement cannot be excluded. That
        //   is evidence of an open question about the very location this
        //   epoch's reservation exists to guard, not evidence the question
        //   is settled. Must withhold.
        // - `ParentDirectoryUnresolvable`: nothing was ever opened, because
        //   nothing durable said where to look (no stage artefact yet, and
        //   `target_path` is a group-relative sync path this module has no
        //   resolver for — see this variant's own doc, "could not check"
        //   vs. "checked, and it was wrong"). "Could not check" is not
        //   "confirmed nothing to protect" either. Must withhold.
        //
        // In short: every `BlockReason` this module currently has is an "I
        // could not determine anything" answer, never a confirmed-absence
        // one, so every `Blocked` outcome THIS MODULE produces withholds.
        // `release_reservations_unchecked` is always safe to call even when
        // the orchestrator already released (it is a `DELETE ... WHERE
        // transaction_id = ?`, idempotent on an empty set), so this does not
        // need to track whether release already ran on the branch that does
        // call it.
        //
        // "this module produces" is load-bearing, and is why the durable
        // signal below is `unresolved_block_reason` rather than the epoch's
        // bare `phase`. `EpochState::Blocked` is a destination two other
        // writers also reach, with nothing physically unresolved:
        // `orchestrator::block_unpreparable_epoch` (a prepare that failed
        // before touching the target; its own doc says `Blocked` there "is
        // not a judgement call, it is the epoch state machine's only
        // option") and `resolution_planning::replan_unchecked`'s sweep of
        // pre-commit leftovers a replan is about to supersede. Keying on the
        // phase alone made an ordinary SUCCESSFUL replan mint epochs that
        // withheld this transaction's reservations for the rest of its life:
        // prepare failure -> parent `Blocked` -> replan (leaving `Blocked`
        // rows behind) -> new slice acquires reservations -> crash before
        // release, and from then on every boot saw the stale `Blocked` rows,
        // withheld, and nothing ever reclaimed the crashed slice's
        // reservations.
        let mut must_withhold_reservations = false;
        for epoch in list_epochs_for_transaction(conn, &transaction.transaction_id)? {
            // The withholding decision cannot rely on `action` alone: an
            // epoch already sitting at `Blocked` when this pass began
            // produces `EarlyRecoveryAction::NoAction` from `recover_epoch`
            // (see that function's own doc on why a settled
            // `Blocked`/`Quarantined` epoch is left exactly as found,
            // never re-transitioned), so `action` only ever carries
            // `Blocked(_)` on the one pass that makes the transition
            // itself -- every later cold start would otherwise see
            // `NoAction` and wrongly conclude nothing here still needs
            // withholding. The durable source of truth for "does this epoch
            // still need its reservation withheld" is the epoch's own
            // `unresolved_block_reason`, read fresh every pass from
            // `list_epochs_for_transaction` above: `block` (below) is the
            // only writer in this crate that sets it, and it sets it on
            // exactly the transition this comment's long counterpart above
            // argues can never be a confirmed absence. Re-deriving the
            // verdict from a per-epoch record of *why* means a writer that
            // has nothing unresolved cannot produce the withholding state at
            // all -- it would have to write this column, and only the
            // "could not determine anything" path does.
            //
            // Deliberately not sourced from the transaction-level
            // `blocked_reason` column instead: that column records only the
            // *first* `BlockReason` to hit this transaction across all of
            // its epochs (see `block`'s own guard below), so it cannot
            // answer "is *this* epoch still blocked" once a transaction has
            // more than one blocked epoch -- and it is written for
            // orchestrator-sourced blocks too. The epoch column can answer,
            // unambiguously, per epoch, and only for this module's blocks.
            //
            // Also deliberately not "exclude epochs from a superseded
            // `plan_revision`", the other candidate fix: that would silently
            // stop withholding for a *genuinely* undetermined epoch as soon
            // as any replan advanced the revision past it, turning a real
            // open physical question into a released reservation. The
            // question this module asks is about physical evidence, not
            // about which plan an epoch belonged to.
            let has_unresolved_block = epoch.unresolved_block_reason.is_some();
            let action = recover_epoch(conn, &transaction, &epoch, &mut report)?;
            if has_unresolved_block
                || matches!(
                    action,
                    EarlyRecoveryAction::RoutedToPhysicalRecovery(_)
                        | EarlyRecoveryAction::PersistedRequiresPhysicalRecovery(_)
                        | EarlyRecoveryAction::Blocked(_)
                )
            {
                must_withhold_reservations = true;
            }
            report.epochs.push(EpochRecoveryOutcome {
                transaction_id: epoch.transaction_id.clone(),
                epoch: epoch.epoch,
                action,
            });
        }
        if !must_withhold_reservations {
            release_reservations_unchecked(conn, &transaction.transaction_id)?;
        }
    }
    Ok(report)
}

fn recover_epoch(
    conn: &Connection,
    transaction: &FilesystemTransactionRecord,
    epoch: &EpochRecord,
    report: &mut EarlyRecoveryReport,
) -> Result<EarlyRecoveryAction, SyncSqliteError> {
    // `Completed` and `Released` are the only two states where nothing of
    // this epoch's own is left to protect: by the time an epoch reaches
    // either, custody of whatever it once displaced has already moved to an
    // independent, separately-tracked obligation (`CustodyTransferred` is
    // exactly the design's own line for "canonical-path exclusion is no
    // longer required", §8.3), and `target_path` is just an ordinary
    // materialized file again — marking it "owned" here would wrongly tell
    // generic cleanup/hydration/eviction to skip a perfectly normal path.
    // Nothing for this phase to inspect either. This is the only pair that
    // may return before `mark_owned` runs.
    if matches!(epoch.phase, EpochState::Completed | EpochState::Released) {
        return Ok(EarlyRecoveryAction::NoAction);
    }

    mark_owned(report, epoch)?;

    // `Quarantined` and `Blocked` are settled outcomes this phase does not
    // itself produce new information for — a `Blocked` epoch's reason is
    // already durable on the parent transaction's `blocked_reason` column,
    // and a `Quarantined` epoch (currently unreachable in this crate: no
    // production call site transitions any epoch to it yet, only
    // `(Committing, Quarantined)` is modeled — see
    // `filesystem_transaction::EpochState::can_transition_to`) is, per the
    // design, a deliberate preserved-but-unresolved outcome, not one that
    // discarded an observation the way a bare `RequiresPhysicalRecovery`
    // row does. Unlike the bug below, nothing about either state is *lost*
    // by leaving it exactly as found. What was genuinely missing — and is
    // fixed by moving `mark_owned` above this check — is that their
    // artefacts (a `Blocked` epoch in particular can easily still have a
    // real `stage_path` on disk; see `block`'s own doc: "nothing under it
    // was touched") were previously left unprotected from generic cleanup
    // on every single restart, for as long as the parent transaction stays
    // incomplete (see `set_transaction_phase_unchecked`'s own comment: a
    // transaction with a terminal-but-unresolved epoch does not have to
    // reach `Completed`, so this can persist indefinitely).
    if matches!(epoch.phase, EpochState::Quarantined | EpochState::Blocked) {
        return Ok(EarlyRecoveryAction::NoAction);
    }

    // `RequiresPhysicalRecovery` found already persisted at the start of
    // this pass (as opposed to one this same call transitions into that
    // state below, via `route_committing_to_physical_recovery`) is the one
    // real gap this module previously had: a crash between the process
    // that wrote this row (whether the `Committing` sweep below, on an
    // earlier boot, or `optimistic_placement`'s own durability-flush-failure
    // path) and whatever later phase was meant to consume the
    // `PhysicalObservation`/`RecoverySnapshot` it produced loses that value
    // completely — it only ever existed in that crashed process's memory,
    // nothing durable carries it forward. The fix is not to recover a lost
    // value (it cannot be), but to accept that observing is a pure,
    // idempotent read of whatever is on disk right now and simply redo it,
    // every cold start, for as long as this row exists. Reported through a
    // distinct variant from `RoutedToPhysicalRecovery` on purpose: a
    // consumer must be able to tell "this pass itself just made the
    // Committing -> RequiresPhysicalRecovery decision" (a one-time event)
    // apart from "this was already sitting here, possibly re-derived on
    // every boot for a long time" (see [`EarlyRecoveryAction::PersistedRequiresPhysicalRecovery`]'s
    // own doc for the cost/exit-condition honesty this implies).
    if epoch.phase == EpochState::RequiresPhysicalRecovery {
        return Ok(EarlyRecoveryAction::PersistedRequiresPhysicalRecovery(Box::new(observe_all(
            epoch,
        ))));
    }

    // `Committing` always routes to `RequiresPhysicalRecovery` regardless of
    // what physical inspection concludes (see the module doc's "settled
    // `Committing` rule") — it must never be gated behind the
    // parent-directory verification below, which exists only to protect a
    // mutation this pass might make (`cleanup_unstarted_artefact`) or a
    // durable custody-row reconstruction, neither of which this branch
    // performs. `route_committing_to_physical_recovery` reads only the raw
    // recorded paths (`observe_all`) and needs no verified parent handle, so
    // it is dispatched before that verification can ever refuse it.
    if epoch.phase == EpochState::Committing {
        return route_committing_to_physical_recovery(conn, transaction, epoch);
    }

    // The physical parent directory to verify and, for the states below
    // that mutate, act through. Preferred source: this epoch's own stage
    // artefact, which forward execution always records as the full path
    // already joined through the real `ParentDirHandle` it was created with
    // (see `orchestrator::run_slice_unchecked`'s own `stage_path =
    // io.parent_dir.path().join(&stage_name)`) -- see `physical_parent_dir`'s
    // own doc for why this, never `epoch.target_path`, is the one place this
    // module can get a physical directory from without inventing a decoder
    // for the group-relative sync path's own separator/portable-name
    // encoding, an encoding this module (like `orchestrator::PlacementIo`
    // before it) has no opinion on.
    //
    // Only recorded once an epoch reaches `PreparedArtifact`, though: an
    // `Allocated` epoch, or a `Preparing` one that crashed before that
    // transition, has no physical footprint yet for this module to derive a
    // directory from at all.
    //
    // For exactly those two states, `target_path`'s own parent is used only
    // when `target_path` is itself already absolute -- i.e. only when it is
    // honestly a physical path this process's own filesystem view can
    // resolve, not the group-relative sync path production actually stores
    // there. When it is not absolute, this module has no durable location to
    // check at all: no stage artefact was ever recorded, and there is no
    // sync-root-relative resolver in this crate to translate `target_path`
    // with (a `ParentDirHandle` this module never held cannot be
    // reconstructed from an identity blob alone). That is not the same
    // finding as "a directory was observed and did not match" -- it is "no
    // directory was ever opened, because nothing durable said where to look"
    // -- so it is reported as its own [`BlockReason::ParentDirectoryUnresolvable`]
    // rather than folded into `ParentDirectoryUnverifiable`/
    // `ParentDirectoryUnreadable`, both of which imply an open was actually
    // attempted. Still resolved as a block either way -- the fail-closed
    // answer this pass gives every other case it cannot prove -- but a
    // consumer of this report can now tell "could not check" apart from
    // "checked, and it was wrong". Once execution wires a sync-root-relative
    // resolver into this crate, this is the one branch that should call it.
    let parent_dir = match physical_parent_dir(epoch) {
        Some(dir) => dir.to_path_buf(),
        None if Path::new(&epoch.target_path).is_absolute() => {
            match Path::new(&epoch.target_path).parent() {
                Some(dir) => dir.to_path_buf(),
                None => {
                    return block(
                        conn,
                        transaction,
                        epoch,
                        BlockReason::ParentDirectoryUnresolvable,
                    )
                }
            }
        }
        None => return block(conn, transaction, epoch, BlockReason::ParentDirectoryUnresolvable),
    };
    // Opened once and held for both the identity check below and any
    // mutation this call makes (`cleanup_unstarted_artefact`) — not
    // re-resolved by path a second time for the mutation. A verify-by-
    // path-then-act-by-path shape leaves a re-resolution window between
    // the two in which the directory at `parent_dir` could be replaced
    // after this check passes and before the mutation runs; holding one
    // handle across both removes that window entirely for this in-process
    // case (see `ParentDirHandle::identity`'s doc).
    let parent_handle = match ParentDirHandle::open(&parent_dir) {
        Ok(handle) => handle,
        Err(_) => return block(conn, transaction, epoch, BlockReason::ParentDirectoryUnreadable),
    };
    match verify_parent_directory(&parent_handle, &epoch.parent_directory_identity) {
        Ok(true) => {}
        Ok(false) => {
            return block(conn, transaction, epoch, BlockReason::ParentDirectoryUnverifiable);
        }
        Err(_) => return block(conn, transaction, epoch, BlockReason::ParentDirectoryUnreadable),
    }

    match epoch.phase {
        // Dead in production, not merely redundant: reaching this arm at
        // all requires the `parent_dir` derivation above to have resolved a
        // directory, which for `Allocated` (no `stage_path` recorded yet)
        // only happens when `target_path` is itself absolute — the `None if
        // ... .is_absolute()` branch a few lines up. Production always
        // stores a group-relative sync path (see this module's own doc and
        // every `BlockReason::ParentDirectoryUnresolvable` test below), so
        // a real `Allocated` epoch blocks there instead and never reaches
        // here. Left in rather than folded into the `_` arm below so this
        // comment has an exact, named line to attach the finding to.
        EpochState::Allocated => Ok(EarlyRecoveryAction::NoAction),
        EpochState::AwaitingReservation => {
            // `orchestrator::run_slice_unchecked` acquires the whole
            // slice's reservations in one call, before any epoch in the
            // slice leaves `PreparedArtifact` — so an epoch sitting here
            // proves nothing on its own about whether the transaction's
            // reservation set is still needed by a sibling epoch elsewhere
            // in the same transaction. Releasing is therefore not this
            // per-epoch arm's decision: `run` makes that call exactly once,
            // per transaction, after walking every one of its epochs — see
            // `run`'s own doc for the rule. This arm only cleans up the
            // stage artefact, the same as `Preparing`/`PreparedArtifact`.
            cleanup_unstarted_artefact(epoch, &parent_handle)
        }
        EpochState::Preparing | EpochState::PreparedArtifact => {
            cleanup_unstarted_artefact(epoch, &parent_handle)
        }
        EpochState::Committed if epoch.displaced_identity.is_some() => {
            recover_committed_custody_transfer(conn, transaction, epoch)
        }
        EpochState::CustodyTransferred
        | EpochState::AwaitingQuiescence
        | EpochState::ClassifiedKnown
        | EpochState::ClassifiedDivergent
        | EpochState::AwaitingCaptureStorage
        | EpochState::AwaitingCaptureAuthorization
        | EpochState::CapturedChangeAuthored
        | EpochState::LocalRecoveryOnly
            if epoch.displaced_identity.is_some() =>
        {
            recover_orphaned_custody_obligation(conn, transaction, epoch)
        }
        _ => Ok(EarlyRecoveryAction::NoAction),
    }
}

/// The physical parent directory an epoch's own stage artefact was created
/// in — the one durable, absolute location any epoch row carries once it
/// has reached `PreparedArtifact` or later. See [`recover_epoch`]'s own doc
/// for why this, and never `epoch.target_path`, is what every physical-path
/// derivation in this module must start from.
fn physical_parent_dir(epoch: &EpochRecord) -> Option<&Path> {
    epoch.stage_path.as_deref().map(Path::new).and_then(Path::parent)
}

/// Closes the other half of the same crash window
/// [`recover_orphaned_custody_obligation`] handles below — see that
/// function's own doc for the `CustodyTransferred`-or-later half, where
/// reaching that phase at all is already proof the rename ran.
///
/// `Committed` gives no such proof either way: every ordinary commit sits at
/// `Committed`, with `displaced_identity` already recorded, before
/// `drive_captured_placement` even starts, and a crash *before*
/// `custody_transfer::transfer_to_custody`'s rename leaves exactly the same
/// fields on the row a crash *after* it does. So this physically checks for
/// the retained artefact at the one location `mark_owned`'s stage/preimage/
/// backup derivation does not already cover — the exact custody name
/// `orchestrator.rs` derives — before treating this as the crash window at
/// all:
///
/// - Absent: the rename never ran. The displaced object, if any, is still at
///   whatever stage/preimage/backup location `mark_owned` already protects
///   for a `Committed` epoch. `NoAction`.
/// - Present: the rename landed but the epoch transition that would have
///   recorded it durably did not — this *is*
///   [`recover_orphaned_custody_obligation`]'s crash window, just caught one
///   phase earlier than its own guard checks for. This brings the durable
///   record in line with the physical fact it already caused
///   (`CustodyTransferred`) before delegating to that function for the rest,
///   the same order `drive_captured_placement` itself follows.
///
/// An I/O error observing the custody location (as opposed to a confirmed
/// absence) is never evidence of anything either way, so it blocks rather
/// than guesses — see [`BlockReason::RetainedArtefactUnreadable`].
fn recover_committed_custody_transfer(
    conn: &Connection,
    transaction: &FilesystemTransactionRecord,
    epoch: &EpochRecord,
) -> Result<EarlyRecoveryAction, SyncSqliteError> {
    let retained_id = format!("{}-ep{}", epoch.transaction_id, epoch.epoch);
    // See [`physical_parent_dir`]'s own doc — `epoch.target_path` is the
    // group-relative sync path, never a physical directory to join against.
    let parent_dir = physical_parent_dir(epoch).unwrap_or_else(|| Path::new(""));
    let custody_name =
        reserved_namespace::artefact_component_name(ArtefactKind::Retained, &retained_id)
            .map_err(|e| SyncSqliteError::InvalidInput(e.to_string()))?;
    let custody_path = parent_dir.join(&custody_name);

    let observed = match observe_optional(&custody_path) {
        Ok(None) => return Ok(EarlyRecoveryAction::NoAction),
        Err(_) => {
            return block(conn, transaction, epoch, BlockReason::RetainedArtefactUnreadable);
        }
        Ok(Some(observed)) => observed,
    };
    let Some(expected) = epoch.displaced_identity.as_ref() else {
        return block(conn, transaction, epoch, BlockReason::RetainedArtefactIdentityUnverifiable);
    };
    let granularity =
        yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(parent_dir);
    if !matches!(observed.compare(expected, granularity), IdentityComparison::SameObject) {
        return block(conn, transaction, epoch, BlockReason::RetainedArtefactIdentityUnverifiable);
    }

    // Durable intent now matches the physical fact this observation just
    // confirmed, for exactly the reason `drive_captured_placement` itself
    // writes this transition before `retained_obligation::create` runs —
    // see that function's own doc.
    transition_epoch_unchecked(
        conn,
        &epoch.transaction_id,
        epoch.epoch,
        transaction.execution_generation,
        EpochState::CustodyTransferred,
        &EpochUpdate::default(),
        now_unix_nanos(),
    )?;

    recover_orphaned_custody_obligation(conn, transaction, epoch)
}

/// §14.1's still-open gap this module's own doc names ("What this module
/// deliberately does not load"): a crash between `custody_transfer::
/// transfer_to_custody`'s rename and `retained_obligation::create`'s own
/// commit leaves a retained artefact on disk with no obligation row naming
/// it at all — not merely a retention root racing its owner (the ordinary
/// "obligation before retention root" ordering `orchestrator.rs` already
/// gets right), but no owner ever recorded.
///
/// An epoch at `EpochState::CustodyTransferred` or later, with a recorded
/// `displaced_identity` (something really was displaced), is exactly this
/// crash's signature: `orchestrator.rs`'s `drive_captured_placement`
/// durably transitions the epoch to `CustodyTransferred` — the durable
/// intent — *before* calling `retained_obligation::create`, so a missing
/// obligation found at this phase or later can only mean that create never
/// committed. [`recover_committed_custody_transfer`] above handles the one
/// phase earlier than this guard: a `Committed` epoch whose rename already
/// landed physically but whose `CustodyTransferred` transition did not.
///
/// Every field this reconstructs comes from the epoch row itself, written
/// durably well before the crash window even opens: `displaced_generation_id`
/// (the causal basis a captured change authors against) is recorded at
/// `Prepared` time, long before the commit that displaces anything;
/// `target_path` and `parent_directory_identity` are original epoch fields.
/// This performs no signing, classification or authoring — exactly the
/// early-phase restriction this module's own doc states — it only recreates
/// the bookkeeping row `retained_obligation::create` is itself idempotent
/// on, so a later ordinary `create` call for the same `retained_id` (from a
/// resumed slice, or a later recovery pass) is a safe no-op, not a conflict.
///
/// If `displaced_generation_id` was never recorded (an epoch written before
/// this recovery step existed, or some other malformed row), this cannot
/// safely reconstruct `original_parent_basis_id` and leaves the row exactly
/// as found — `NoAction` — rather than guessing at a causal basis nothing
/// durable actually names.
///
/// # What proves an existing row is *this* reconstruction repeating
///
/// `retained_id` is derived deterministically from `(transaction_id,
/// epoch)`, so a row already sitting under this exact id can only
/// legitimately be a repeat of this same call — there is no other object
/// this crate's own derivation could ever produce that id for. That is
/// exactly why finding one is not enough by itself to call this a safe
/// no-op: `retained_id` and `group_id` matching only proves the row is
/// *addressed* the same, not that it *is* the same obligation. This checks
/// every field this call would itself have written — `original_path`,
/// `custody_path`, `parent_directory_identity`, `original_parent_basis_id`,
/// `source_epoch` and `originating_transaction_id` — before treating the
/// existing row as done. That set is exactly [`NewObligation`]'s own
/// identity-relevant fields (everything but the two capture-pipeline
/// columns [`retained_obligation::create`] never sets and the derived
/// `retained_id` already used to look the row up); matching all of them is
/// sufficient because they are precisely the fields this call itself
/// computes from the epoch row before writing, so an existing row
/// disagreeing on any one of them was not produced by this same
/// reconstruction from this same epoch — a genuine identity collision, not
/// a legitimate retry, and worth surfacing loudly rather than silently
/// accepting (the failure mode the review named: a row with the right id
/// but the wrong basis being treated as already handled).
fn recover_orphaned_custody_obligation(
    conn: &Connection,
    transaction: &FilesystemTransactionRecord,
    epoch: &EpochRecord,
) -> Result<EarlyRecoveryAction, SyncSqliteError> {
    let retained_id = format!("{}-ep{}", epoch.transaction_id, epoch.epoch);
    let Some(displaced_generation_id) = &epoch.displaced_generation_id else {
        return Ok(EarlyRecoveryAction::NoAction);
    };

    // See [`physical_parent_dir`]'s own doc — `epoch.target_path` is the
    // group-relative sync path, never a physical directory to join against.
    let parent_dir = physical_parent_dir(epoch).unwrap_or_else(|| Path::new(""));
    let custody_name =
        reserved_namespace::artefact_component_name(ArtefactKind::Retained, &retained_id)
            .map_err(|e| SyncSqliteError::InvalidInput(e.to_string()))?;
    let custody_path = parent_dir.join(&custody_name);
    let parent_directory_identity = encode_directory_identity(&epoch.parent_directory_identity);
    let Some(expected_identity) = epoch.displaced_identity.as_ref() else {
        return block(conn, transaction, epoch, BlockReason::RetainedArtefactIdentityUnverifiable);
    };
    let observed_identity = match observe_optional(&custody_path) {
        Ok(Some(identity)) => identity,
        Ok(None) | Err(_) => {
            return block(
                conn,
                transaction,
                epoch,
                BlockReason::RetainedArtefactIdentityUnverifiable,
            );
        }
    };
    let granularity =
        yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(parent_dir);
    if !matches!(
        observed_identity.compare(expected_identity, granularity),
        IdentityComparison::SameObject
    ) {
        return block(conn, transaction, epoch, BlockReason::RetainedArtefactIdentityUnverifiable);
    }
    let filesystem_identity = file_identity_codec::encode_file_identity(&observed_identity);

    if let Some(existing) = retained_obligation::get(conn, &transaction.group_id, &retained_id)? {
        let matches = existing.group_id == transaction.group_id
            && existing.original_path == epoch.target_path
            && existing.custody_path == custody_path.to_string_lossy()
            && existing.parent_directory_identity == parent_directory_identity
            && existing.filesystem_identity.as_deref() == Some(filesystem_identity.as_slice())
            && existing.original_parent_basis_id == displaced_generation_id.0
            && existing.source_epoch == Some(epoch.epoch)
            && existing.originating_transaction_id.as_deref()
                == Some(epoch.transaction_id.as_str());
        if matches {
            return Ok(EarlyRecoveryAction::NoAction);
        }
        return Err(SyncSqliteError::CorruptState(format!(
            "recovering orphaned custody obligation for {retained_id:?}: an existing \
             retained_preimages row does not match what this epoch's own recorded fields \
             reconstruct -- retained_id is derived deterministically from (transaction_id, \
             epoch), so this can only be a genuine identity collision, not a legitimate repeat \
             of this same recovery"
        )));
    }

    retained_obligation::create(
        conn,
        &NewObligation {
            retained_id: &retained_id,
            originating_transaction_id: Some(&epoch.transaction_id),
            source_epoch: Some(epoch.epoch),
            group_id: &transaction.group_id,
            original_path: &epoch.target_path,
            custody_path: &custody_path.to_string_lossy(),
            parent_directory_identity: &parent_directory_identity,
            filesystem_identity: Some(&filesystem_identity),
            original_parent_basis_id: &displaced_generation_id.0,
        },
        now_unix_nanos(),
    )
    .map_err(|error| match error {
        RetainedObligationError::Sync(e) => e,
        // The `get`-and-compare check above already handles a byte-for-byte
        // repeat, so this call only ever reaches `create` when no row
        // exists at all -- a genuine `ObligationIdentityConflict` here means
        // `create`'s own, narrower identity check (`group_id`/
        // `original_path`/`custody_path`) disagrees with something *else*
        // that raced this call between the `get` above and this insert, an
        // invariant break worth surfacing loudly rather than silently
        // swallowing.
        other => SyncSqliteError::CorruptState(format!(
            "recovering orphaned custody obligation for {retained_id:?}: {other:?}"
        )),
    })?;

    Ok(EarlyRecoveryAction::OrphanedCustodyObligationRecovered { retained_id })
}

fn mark_owned(
    report: &mut EarlyRecoveryReport,
    epoch: &EpochRecord,
) -> Result<(), SyncSqliteError> {
    report.owned_paths.insert(PathBuf::from(&epoch.target_path));
    for path in [&epoch.stage_path, &epoch.preimage_path, &epoch.backup_path].into_iter().flatten()
    {
        report.owned_paths.insert(PathBuf::from(path));
    }
    // `epoch.backup_path` above is `epoch.backup_path` the *persisted
    // column* — never written by anything upstream in this crate today
    // (see `expected_backup_path`'s own doc), so the loop above never
    // actually inserts a Backup artefact name on its own. On Windows, once
    // a commit has actually run, the real displaced object — the sole
    // surviving copy of whatever this epoch's commit exchanged out of the
    // live path — sits at exactly the name `expected_backup_path` derives,
    // not at the persisted (always-`None`) column. Without this, that
    // object is invisible to `owned_paths` for every epoch this function
    // is reached for (`Committed`, `Committing`,
    // `RequiresPhysicalRecovery` included), even though it is the one
    // artefact `owned_paths` most needs to protect. Derived here the same
    // way `observe_all` already derives it for physical observation, so
    // the two never disagree on where it is.
    //
    // On Unix this name is never a real location: `renameat2(RENAME_
    // EXCHANGE)`/`renamex_np(RENAME_SWAP)` leave the displaced preimage at
    // the stage name itself, already covered by `stage_path` above (see
    // `expected_backup_path`'s own doc for the platform split this
    // mirrors) — inserting the derived name there as well would just mark
    // a path nothing is ever placed at, so it is skipped rather than
    // harmlessly duplicated.
    #[cfg(windows)]
    if let Some(backup_path) = expected_backup_path(epoch) {
        report.owned_paths.insert(backup_path);
    }

    // `displaced_identity` is written only once a commit has actually
    // displaced an object. From that point onward a crash may have moved the
    // preimage to its deterministic retained-custody name even if the epoch
    // transition or obligation insert did not commit. Mark that derived name
    // as operation-owned before any identity validation or early return, so a
    // generic reserved-artefact cleanup pass can never delete the sole
    // surviving preimage merely because recovery correctly blocked on an
    // identity mismatch.
    if epoch.displaced_identity.is_some() {
        if let Some(parent_dir) = physical_parent_dir(epoch) {
            let retained_id = format!("{}-ep{}", epoch.transaction_id, epoch.epoch);
            let custody_name =
                reserved_namespace::artefact_component_name(ArtefactKind::Retained, &retained_id)
                    .map_err(|error| SyncSqliteError::InvalidInput(error.to_string()))?;
            report.owned_paths.insert(parent_dir.join(custody_name));
        }
    }

    Ok(())
}

/// Whether a freshly observed directory is provably the one an epoch
/// recorded.
///
/// This used to be structural equality, argued for on the grounds that
/// `DirectoryIdentity` has no third field to build an "ambiguous" state
/// from. That argument was wrong in one specific way that matters here: on
/// Windows a fallback object id is a 64-bit file index, which Microsoft
/// does not guarantee unique on ReFS, so two DISTINCT directories on one
/// volume can carry equal fields. Parent-directory verification is exactly
/// where that must not be read as proof, because what follows it is a
/// deletion. [`DirectoryIdentity::compare`] now expresses that, and only
/// `SameObject` is accepted — an ambiguous verdict is treated exactly like
/// a mismatch, which is this pass's rule everywhere else.
// Capability-split migration note: AMBIGUOUS, the same shape as
// `optimistic_placement::require_commit_matches_epoch`'s `parent_verdict`
// (see that call site's own note — this is the other of the two directory
// comparisons in this crate). This module IS the crash-recovery pass, so
// `expected` (an `EpochRecord`'s persisted `parent_directory_identity`) is
// always restart-spanning here, and `DirectoryIdentity` has no marker tier
// under any of the three split capability names. Left exactly as before.
fn compare_directory_identity(
    observed: &DirectoryIdentity,
    expected: &DirectoryIdentity,
    birth_time_granularity: yadorilink_root_authority::fs_identity::TimestampGranularity,
) -> bool {
    matches!(observed.compare(expected, birth_time_granularity), IdentityComparison::SameObject)
}

/// Verifies `handle`'s directory against `expected`, deriving this volume's
/// real birth-time granularity itself rather than accepting one as a
/// parameter — there is no existing probed-capability input this module
/// receives (`run` intentionally takes only a `&Connection`, see the module
/// doc), and a caller-supplied granularity is exactly the shape that has
/// gone wrong elsewhere in this crate: every hardcoded `TimestampGranularity::
/// Fine` this codebase has had to fix was a caller assuming a value instead
/// of measuring it. Folding the probe into the one function that performs
/// the comparison makes it structurally impossible to reach that comparison
/// without it, rather than documenting an obligation callers must remember.
fn verify_parent_directory(
    handle: &ParentDirHandle,
    expected: &DirectoryIdentity,
) -> io::Result<bool> {
    let observed = handle.identity()?;
    let granularity =
        yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(handle.path());
    Ok(compare_directory_identity(&observed, expected, granularity))
}

/// Moves both the epoch and its parent transaction to `Blocked`, then
/// reports it. The transaction may already be `Blocked` by an earlier
/// sibling epoch in this same pass, so whether `set_transaction_phase_
/// unchecked` needs calling at all is checked first, against the
/// transaction's *current* database phase — read fresh right here with its
/// own `lookup_transaction` call, never against the `transaction` parameter.
/// That parameter is the snapshot `run`'s outer loop loaded once, before any
/// epoch of this transaction had been walked; `run` never refreshes it, and
/// two placements blocking in the same slice is the ordinary case in
/// production (a group-relative `target_path` makes `physical_parent_dir`
/// resolve to `None` for every `Allocated` epoch, so every epoch in a
/// multi-placement slice blocks with `ParentDirectoryUnresolvable` — see
/// [`BlockReason::ParentDirectoryUnresolvable`]'s own doc). Deciding
/// legality from the stale snapshot would read `transaction.phase` as
/// whatever it was before this pass started (e.g. `Planning`) even after an
/// earlier sibling epoch in this same loop already moved the row to
/// `Blocked` in the database, attempt `set_transaction_phase_unchecked`
/// anyway, and have that call's own fresh read of the transaction find
/// `Blocked` already there — `TransactionPhase::Blocked.can_transition_to
/// (Blocked)` is `false`, so that call would raise "not a legal phase
/// transition", aborting the rest of this pass: every remaining epoch, every
/// remaining transaction, and every reservation release. Reading fresh here
/// closes that: this call sees the same `Blocked` the failed attempt would
/// have found, skips the redundant transition instead of attempting one that
/// cannot succeed, and every other epoch in this pass keeps being walked.
///
/// The epoch transition, the fresh phase read and the (conditional)
/// transaction transition all run inside one `BEGIN IMMEDIATE`, for the same
/// reasons `orchestrator::block_unpreparable_epoch` (the identical write
/// pair, reached from a prepare failure rather than from a failed
/// observation) already gives: a crash between the two writes would
/// otherwise leave the epoch `Blocked` under a parent that still looks like
/// nothing happened, and the read-then-write shape here -- read the parent's
/// phase, then write it -- is exactly what `with_immediate_transaction`'s own
/// doc says must not run `DEFERRED`. This function used to run its two
/// writes as separate autocommit statements with a bare `lookup_transaction`
/// between them; there is no property of this call site that makes the
/// atomicity its sibling insists on unnecessary here, so the difference was
/// an inconsistency rather than a decision.
///
/// The epoch write also records `unresolved_block_reason`. This is the one
/// place in the crate that writes that column, which is what lets [`run`]'s
/// reservation withholding key on "early physical recovery could not
/// determine anything" instead of on the bare `Blocked` phase two other
/// writers reach with nothing unresolved. See [`run`]'s own loop comment.
fn block(
    conn: &Connection,
    transaction: &FilesystemTransactionRecord,
    epoch: &EpochRecord,
    reason: BlockReason,
) -> Result<EarlyRecoveryAction, SyncSqliteError> {
    let reason_text = format!("early physical recovery: {reason:?}");
    filesystem_transaction::with_immediate_transaction(conn, |tx| {
        transition_epoch_unchecked(
            tx,
            &epoch.transaction_id,
            epoch.epoch,
            transaction.execution_generation,
            EpochState::Blocked,
            &EpochUpdate { unresolved_block_reason: Some(&reason_text), ..EpochUpdate::default() },
            now_unix_nanos(),
        )?;
        let current_transaction_phase = lookup_transaction(tx, &transaction.transaction_id)?
            .ok_or_else(|| {
                SyncSqliteError::NotFound(format!(
                    "filesystem transaction {}",
                    transaction.transaction_id
                ))
            })?
            .phase;
        if current_transaction_phase != TransactionPhase::Blocked {
            set_transaction_phase_unchecked(
                tx,
                &transaction.transaction_id,
                transaction.execution_generation,
                TransactionPhase::Blocked,
                Some(&reason_text),
                now_unix_nanos(),
            )?;
        }
        // Annotated because `with_immediate_transaction` is generic over the
        // closure's error type (so a caller can return its own error without
        // laundering it through `SyncSqliteError`), and every statement in this
        // closure produces `SyncSqliteError` via `?` rather than naming it — so
        // nothing here fixes `E` and inference has more than one candidate.
        Ok::<(), SyncSqliteError>(())
    })?;
    Ok(EarlyRecoveryAction::Blocked(reason))
}

fn route_committing_to_physical_recovery(
    conn: &Connection,
    transaction: &FilesystemTransactionRecord,
    epoch: &EpochRecord,
) -> Result<EarlyRecoveryAction, SyncSqliteError> {
    let observation = observe_all(epoch);
    transition_epoch_unchecked(
        conn,
        &epoch.transaction_id,
        epoch.epoch,
        transaction.execution_generation,
        EpochState::RequiresPhysicalRecovery,
        &EpochUpdate::default(),
        now_unix_nanos(),
    )?;
    Ok(EarlyRecoveryAction::RoutedToPhysicalRecovery(Box::new(observation)))
}

fn observe_all(epoch: &EpochRecord) -> PhysicalObservation {
    PhysicalObservation {
        live: observe_one(Path::new(&epoch.target_path)),
        stage: epoch.stage_path.as_deref().map(Path::new).map(observe_one),
        preimage: epoch.preimage_path.as_deref().map(Path::new).map(observe_one),
        backup: expected_backup_path(epoch).as_deref().map(observe_one),
    }
}

/// Where this epoch's Backup artefact would be, if a real commit ever
/// exchanged into it. `fs_commit`'s module doc records the per-platform
/// split this exists to cover: on Windows, `ReplaceFileW` leaves the
/// displaced preimage at an explicit backup path distinct from the stage
/// name it exchanged with, where Unix's `renameat2(RENAME_EXCHANGE)` /
/// `renamex_np(RENAME_SWAP)` leave it at the stage name itself (already
/// covered by `PhysicalObservation::stage` above, so this deliberately
/// does not double-report it).
///
/// `EpochRecord::backup_path` itself is never written before `Committing`
/// -- see `optimistic_placement::require_commit_matches_epoch`'s own doc:
/// nothing upstream in this crate tracks one, since the commit-window
/// phase binds `commit.backup_name` by deriving it fresh from the
/// already-verified stage artefact id rather than comparing it against a
/// recorded value. An epoch reaching this crash-recovery sweep therefore
/// has no recorded backup location to read on `epoch.backup_path` at all
/// -- on Windows that would silently lose the one place a real commit
/// could have left the preimage, not merely fail to double-check it. This
/// mirrors that same binding's derivation instead of trusting the
/// (never-populated) column: the expected Backup artefact name comes from
/// the same artefact id already embedded in `epoch.stage_path`'s Stage
/// artefact name.
fn expected_backup_path(epoch: &EpochRecord) -> Option<PathBuf> {
    if let Some(backup_path) = &epoch.backup_path {
        return Some(PathBuf::from(backup_path));
    }
    let stage_path = Path::new(epoch.stage_path.as_deref()?);
    let parent = stage_path.parent()?;
    let stage_name = stage_path.file_name()?.to_str()?;
    let (kind, artefact_id) = reserved_namespace::parse_artefact_component(stage_name)?;
    if kind != ArtefactKind::Stage {
        return None;
    }
    let backup_name =
        reserved_namespace::artefact_component_name(ArtefactKind::Backup, artefact_id).ok()?;
    Some(parent.join(backup_name))
}

fn observe_one(path: &Path) -> RecoveryObservation {
    match observe_optional(path) {
        Ok(Some(identity)) => RecoveryObservation::Present(identity),
        Ok(None) => RecoveryObservation::Absent,
        Err(e) => RecoveryObservation::Unreadable(e.kind()),
    }
}

fn observe_optional(path: &Path) -> io::Result<Option<FileIdentity>> {
    match FileIdentity::observe_path(path) {
        Ok(identity) => Ok(Some(identity)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// An epoch this row itself named as its stage artefact, found physically
/// present *and provably the object this row recorded*, is removed — see
/// the module doc's "one case this module does resolve unassisted". A path
/// recorded as `None` (never reached this far before the crash) is left
/// exactly as-is: this function never scans the parent directory for a
/// same-shaped stray file to associate with the epoch, since doing so would
/// be the naming-based ownership guess §10 forbids, not the identity-based
/// proof this row's own recorded path provides.
///
/// "Provably the object this row recorded" means `epoch.staged_identity`
/// compares [`yadorilink_root_authority::fs_identity::IdentityComparison::SameObject`] against
/// whatever is physically present at `stage_path` right now — a plain
/// regular-file kind check alone (what this function used to rely on)
/// proves only that *something* of the right shape sits at that name, never
/// that it is the same something this row created. Between the crash this
/// row survived and this pass running, the original object could have been
/// removed or renamed away and an unrelated regular file placed at the same
/// name by something else entirely; deleting on the strength of the name
/// alone would delete that unrelated object's bytes, not this epoch's own.
///
/// `epoch.staged_identity` can itself be `None` — nothing upstream in this
/// crate records it before the `Prepared` transition, strictly *after*
/// every phase this function is called for (`AwaitingReservation`,
/// `Preparing`, `PreparedArtifact`), so an epoch that crashed before
/// reaching this far has no recorded identity to prove anything with. That
/// is not a corner case to special-case around: it is treated exactly like
/// every other unprovable case in this module — the object is left
/// untouched rather than guessed at, the same fail-closed answer an
/// [`yadorilink_root_authority::fs_identity::IdentityComparison::Ambiguous`] comparison gets
/// below. Once a caller upstream of this recovery pass records identity
/// earlier (e.g. right after `prepare_target` creates the stage object),
/// this same check starts authorizing removal for those epochs with no
/// further change required here. That value already exists today —
/// [`crate::optimistic_placement::PreparedArtifact::verified_identity`] is
/// exactly it, documented at its own definition as the value a future
/// `PreparedArtifact`-transition caller must persist as
/// `epoch.staged_identity` — only the caller that would attach
/// it to that transition is unwritten.
fn cleanup_unstarted_artefact(
    epoch: &EpochRecord,
    parent_handle: &ParentDirHandle,
) -> Result<EarlyRecoveryAction, SyncSqliteError> {
    let Some(stage_path) = &epoch.stage_path else {
        return Ok(EarlyRecoveryAction::NoAction);
    };
    let stage_path = Path::new(stage_path);
    // Defensive: §10 puts every artefact directly beside its target, so a
    // recorded stage path's parent should always be exactly the directory
    // already reconfirmed by the caller. If it somehow is not, this row is
    // not what this function's ownership proof assumes — leave it alone
    // rather than open a different directory handle than the one whose
    // identity was actually checked.
    if stage_path.parent() != Some(parent_handle.path()) {
        return Ok(EarlyRecoveryAction::NoAction);
    }
    let Some(file_name) = stage_path.file_name() else {
        return Ok(EarlyRecoveryAction::NoAction);
    };
    let Some(expected_identity) = &epoch.staged_identity else {
        return Ok(EarlyRecoveryAction::NoAction);
    };
    let granularity = yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(
        parent_handle.path(),
    );
    // Directory-handle-relative, not a path-string remove, and through the
    // exact same handle `recover_epoch` already verified the identity of
    // — not a second, freshly reopened one. Reopening by path here would
    // reintroduce the re-resolution window `recover_epoch` holding this
    // handle across both steps exists to close (see `ParentDirHandle::
    // identity`'s doc); resolving the removal through the caller's own
    // already-proven handle is what keeps this the same directory that
    // check just proved, all the way through to the actual identity read
    // and unlink — see `ParentDirHandle::remove_child_if_identity_matches`'s
    // own doc for the handle-relative rationale and its own, narrower,
    // residual window between that read and the unlink itself.
    match parent_handle.remove_child_if_identity_matches(file_name, expected_identity, granularity)
    {
        Ok(()) => Ok(EarlyRecoveryAction::UnstartedArtefactRemoved {
            removed_path: stage_path.to_path_buf(),
        }),
        Err(RemoveChildIdentityError::Absent) => Ok(EarlyRecoveryAction::NoAction),
        // Recorded as this epoch's stage artefact, but not what a stage
        // artefact should ever physically be — do not guess, and do not
        // report cleanup as having happened.
        Err(RemoveChildIdentityError::NotARegularFile) => Ok(EarlyRecoveryAction::NoAction),
        // Present, a plain regular file, but not provably the object this
        // row named — the exact case this function's own doc describes.
        // Left untouched, byte for byte.
        Err(RemoveChildIdentityError::IdentityMismatch) => Ok(EarlyRecoveryAction::NoAction),
        Err(RemoveChildIdentityError::Io(e)) => Err(SyncSqliteError::Io(e)),
    }
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use rusqlite::Connection;

    use super::*;
    use crate::filesystem_transaction::{
        begin_transaction_unchecked, insert_epoch_unchecked, transition_epoch_unchecked,
        FilesystemTransactionKind, NewEpoch, NewFilesystemTransaction, TransactionCause,
    };
    use crate::{dag_store, materialized_generation, resolution_planning};
    use yadorilink_filesystem_sync::fs_commit::{
        CommitRequest, FilesystemCommitAdapter, NativeCommitAdapter, ParentDirHandle,
    };
    use yadorilink_replica_domain::filesystem_placement::PlacementRole;
    use yadorilink_root_authority::fs_capabilities::{Capability, FilesystemSafetyCapabilities};
    use yadorilink_root_authority::reserved_namespace::{artefact_component_name, ArtefactKind};

    fn open_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&conn).unwrap();
        materialized_generation::init_materialized_generation_schema(&conn).unwrap();
        filesystem_transaction::init_filesystem_transaction_schema(&conn).unwrap();
        conn
    }

    fn all_supported_capabilities() -> FilesystemSafetyCapabilities {
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

    fn begin_sample_transaction(conn: &Connection) -> FilesystemTransactionRecord {
        begin_transaction_unchecked(
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
        .unwrap()
    }

    fn insert_sample_epoch(
        conn: &Connection,
        transaction_id: &str,
        target_path: &str,
        parent_directory_identity: &DirectoryIdentity,
    ) -> EpochRecord {
        insert_epoch_unchecked(
            conn,
            &NewEpoch {
                transaction_id,
                epoch: 0,
                plan_revision: 0,
                target_path,
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"opaque",
                parent_directory_identity,
                capability_snapshot: b"opaque",
                durability_level:
                    yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            },
            // `begin_sample_transaction` never bumps `execution_generation`
            // past the `0` it starts `begin_transaction_unchecked` at, and
            // no test in this module bumps it either -- the fence stays 0.
            0,
            0,
        )
        .unwrap()
    }

    // --- Allocated: nothing was ever created, nothing to do -------------

    #[test]
    fn allocated_epoch_is_left_untouched() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );

        let report = run(&conn).unwrap();

        assert_eq!(report.epochs.len(), 1);
        assert!(matches!(report.epochs[0].action, EarlyRecoveryAction::NoAction));
        assert!(report.owned_paths.contains(&dir.path().join("a.txt")));
    }

    // --- Preparing/PreparedArtifact: identity-proven unstarted cleanup ---

    #[test]
    fn unstarted_stage_artefact_with_no_reservation_is_removed() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );

        // Drive the epoch to `PreparedArtifact` the way a real crash would:
        // through the real transitions, with a real stage file created on
        // disk in between.
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"half-written stage content").unwrap();
        // A real caller records the staged object's own identity as soon
        // as it creates it -- see `optimistic_placement::PreparedArtifact::
        // verified_identity`. This test records it at the same
        // `PreparedArtifact` transition to match that, since deletion is
        // now conditional on this row proving it is the same object
        // physically present (see `cleanup_unstarted_artefact`'s own doc).
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate {
                stage_path: Some(stage_path.to_str().unwrap()),
                staged_identity: Some(&staged_identity),
                ..Default::default()
            },
            0,
        )
        .unwrap();

        // A stray, unrelated artefact-shaped file with no owning row at
        // all: must survive untouched no matter what this epoch's own
        // cleanup does.
        let stray_name = artefact_component_name(ArtefactKind::Stage, "unowned").unwrap();
        let stray_path = dir.path().join(&stray_name);
        std::fs::write(&stray_path, b"nobody's row names this").unwrap();

        let report = run(&conn).unwrap();

        assert!(!stage_path.exists(), "the unstarted, unreserved stage artefact must be removed");
        assert_eq!(
            std::fs::read(&stray_path).unwrap(),
            b"nobody's row names this",
            "an artefact with no owning row must never be touched"
        );
        assert_eq!(report.epochs.len(), 1);
        assert!(matches!(
            report.epochs[0].action,
            EarlyRecoveryAction::UnstartedArtefactRemoved { .. }
        ));
    }

    // --- Precondition: refuse a connection already inside a transaction -

    /// The defect this pins: `rusqlite::Transaction` derefs to
    /// `Connection`, so `run(&tx)` type-checks even though nothing in this
    /// module's contract grants a caller a transaction to pass. Before the
    /// autocommit check at the top of `run`, this would process epochs --
    /// mutating rows under the caller's own open transaction -- until it
    /// reached one `block` could not resolve, whose `with_immediate_
    /// transaction` then failed outright on SQLite's "cannot start a
    /// transaction within a transaction", leaving the caller holding a
    /// transaction that was already partly mutated. This test sets up
    /// exactly that shape (an unresolvable `PreparedArtifact` epoch with a
    /// real stage artefact on disk, ready to be deleted by the same
    /// `cleanup_unstarted_artefact` path the test above exercises), calls
    /// `run` against an open transaction on the same connection, and
    /// asserts not merely that the call fails, but that the stage artefact
    /// and the epoch's durable phase are both still exactly as found --
    /// i.e. refused before the first mutation, not merely refused
    /// eventually.
    #[test]
    fn run_against_an_open_transaction_is_refused_before_any_mutation() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );

        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"half-written stage content").unwrap();
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate {
                stage_path: Some(stage_path.to_str().unwrap()),
                staged_identity: Some(&staged_identity),
                ..Default::default()
            },
            0,
        )
        .unwrap();

        // `unchecked_transaction` is rusqlite's own escape hatch that opens
        // a real `BEGIN` without requiring a `&mut Connection` -- the exact
        // shape that lets an ordinary `rusqlite::Transaction` compile as the
        // `&Connection` argument `run` takes.
        let open_tx = conn.unchecked_transaction().unwrap();

        let result = run(&open_tx);
        assert!(
            matches!(&result, Err(SyncSqliteError::InvalidInput(msg)) if msg.contains("autocommit")),
            "run against an already-open transaction must be refused with InvalidInput naming \
             the autocommit precondition, got {result:?}"
        );

        drop(open_tx);

        assert!(
            stage_path.exists(),
            "run must refuse before mutating anything -- the stage artefact this pass would \
             otherwise have deleted must still be on disk"
        );
        assert_eq!(
            std::fs::read(&stage_path).unwrap(),
            b"half-written stage content",
            "the stage artefact's contents must be untouched"
        );
        let reloaded = list_epochs_for_transaction(&conn, &epoch.transaction_id).unwrap().remove(0);
        assert_eq!(
            reloaded.phase,
            EpochState::PreparedArtifact,
            "the epoch's durable phase must be exactly as found -- run must not have \
             transitioned it before refusing"
        );
    }

    // --- Regression: deletion must be conditional on proven object
    //     identity, never on the recorded name alone -------------------

    /// The defect this pins: before this fix, `cleanup_unstarted_artefact`
    /// removed whatever plain regular file currently sat at `stage_path`,
    /// proving only that it was *some* regular file, never that it was
    /// *this epoch's own* regular file. Here the original stage object is
    /// replaced with an entirely different file before recovery ever runs
    /// — the crash-then-substitution sequence the review named. Recovery
    /// must leave the substituted file exactly as found, byte for byte,
    /// not delete it on the strength of the name it happens to occupy.
    #[test]
    fn a_substituted_stage_object_survives_byte_for_byte_instead_of_being_deleted_by_name() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );

        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"the real stage object this epoch created").unwrap();
        // Recorded exactly as a real caller would: the identity of the
        // object actually created for this epoch, at the moment it was
        // created.
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate {
                stage_path: Some(stage_path.to_str().unwrap()),
                staged_identity: Some(&staged_identity),
                ..Default::default()
            },
            0,
        )
        .unwrap();

        // The substitution: the original stage object is removed, and a
        // different file — same name, same reserved-namespace shape, same
        // "plain regular file" kind — takes its place. Nothing about a
        // kind check alone can tell these two apart.
        std::fs::remove_file(&stage_path).unwrap();
        std::fs::write(&stage_path, b"an unrelated file that now occupies the same name").unwrap();

        let report = run(&conn).unwrap();

        assert_eq!(
            std::fs::read(&stage_path).unwrap(),
            b"an unrelated file that now occupies the same name",
            "a substituted object must survive untouched, byte for byte -- it is not the object \
             this epoch's row recorded, no matter what name it occupies"
        );
        assert_eq!(report.epochs.len(), 1);
        assert!(
            matches!(report.epochs[0].action, EarlyRecoveryAction::NoAction),
            "an unprovable identity must never authorize deletion, got {:?}",
            report.epochs[0].action
        );
    }

    /// The other half of the same defect: an epoch that crashed before
    /// `staged_identity` was ever recorded (still the normal case in this
    /// crate today -- nothing upstream writes it before the `Prepared`
    /// transition, strictly after every phase `cleanup_unstarted_artefact`
    /// handles) has no proof to offer at all. The safe, defined answer is
    /// the same one every other unprovable case in this module gets: leave
    /// the object untouched rather than guess, never delete on the
    /// strength of the recorded path string alone.
    #[test]
    fn missing_recorded_identity_leaves_the_stage_object_untouched() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );

        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"half-written stage content, identity never recorded")
            .unwrap();
        // No `staged_identity` supplied -- the crash-before-recorded case.
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate { stage_path: Some(stage_path.to_str().unwrap()), ..Default::default() },
            0,
        )
        .unwrap();

        let report = run(&conn).unwrap();

        assert_eq!(
            std::fs::read(&stage_path).unwrap(),
            b"half-written stage content, identity never recorded",
            "with no recorded identity to prove anything against, the object must be left \
             untouched rather than deleted on a guess"
        );
        assert_eq!(report.epochs.len(), 1);
        assert!(
            matches!(report.epochs[0].action, EarlyRecoveryAction::NoAction),
            "got {:?}",
            report.epochs[0].action
        );
        // Still protected from generic cleanup while it sits here
        // unresolved, exactly like every other in-flight epoch.
        assert!(report.owned_paths.contains(&stage_path));
    }

    #[test]
    fn awaiting_reservation_releases_the_reservation_before_cleanup() {
        let mut conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"staged").unwrap();
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();

        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate {
                stage_path: Some(stage_path.to_str().unwrap()),
                staged_identity: Some(&staged_identity),
                ..Default::default()
            },
            0,
        )
        .unwrap();
        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[yadorilink_replica_domain::filesystem_placement::NewReservation {
                group_id: "g",
                transaction_id: &tx.transaction_id,
                scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                path: "a.txt",
                role:
                    yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::AwaitingReservation,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();

        let report = run(&conn).unwrap();

        assert!(!stage_path.exists());
        assert!(
            filesystem_transaction::list_reservations(&conn, &tx.transaction_id)
                .unwrap()
                .is_empty(),
            "the stale reservation must be released, not left dangling on an abandoned epoch"
        );
        assert!(matches!(
            report.epochs[0].action,
            EarlyRecoveryAction::UnstartedArtefactRemoved { .. }
        ));
    }

    // --- Prepared: nothing destructive was attempted, nothing to do -----

    #[test]
    fn prepared_epoch_with_stage_present_and_live_absent_is_left_alone() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let live_path = dir.path().join("a.txt");
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            live_path.to_str().unwrap(),
            &parent_identity,
        );
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"new content").unwrap();

        for to in [EpochState::Preparing, EpochState::PreparedArtifact] {
            transition_epoch_unchecked(
                &conn,
                &epoch.transaction_id,
                epoch.epoch,
                0,
                to,
                &EpochUpdate {
                    stage_path: Some(stage_path.to_str().unwrap()),
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        }
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::AwaitingReservation,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Prepared,
            &EpochUpdate { staged_identity: Some(&staged_identity), ..Default::default() },
            0,
        )
        .unwrap();

        let report = run(&conn).unwrap();

        assert!(stage_path.exists(), "Prepared is a legitimately resumable state, not ambiguous");
        assert!(!live_path.exists());
        assert!(matches!(report.epochs[0].action, EarlyRecoveryAction::NoAction));
    }

    // --- Committing: the crash-after-commit-before-publication case -----

    #[test]
    fn committing_epoch_after_a_real_commit_is_routed_to_physical_recovery() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let live_path = dir.path().join("a.txt");
        std::fs::write(&live_path, b"old content").unwrap();
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            live_path.to_str().unwrap(),
            &parent_identity,
        );

        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"new content").unwrap();
        let displaced_identity = FileIdentity::observe_path(&live_path).unwrap();
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();

        for to in [EpochState::Preparing, EpochState::PreparedArtifact] {
            transition_epoch_unchecked(
                &conn,
                &epoch.transaction_id,
                epoch.epoch,
                0,
                to,
                &EpochUpdate {
                    stage_path: Some(stage_path.to_str().unwrap()),
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        }
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::AwaitingReservation,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Prepared,
            &EpochUpdate {
                staged_identity: Some(&staged_identity),
                displaced_identity: Some(&displaced_identity),
                ..Default::default()
            },
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Committing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();

        // The real filesystem commit: an actual atomic exchange through the
        // real platform adapter, not a hand-constructed end state.
        let parent_handle = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        // `backup_name` must be the artefact name `require_commit_matches_epoch`
        // (optimistic_placement.rs) derives from the *same* stage artefact
        // id and always enforces on a real commit-window caller -- a
        // literal like `"backup"` is not a name any production commit
        // could ever carry, so a test that used one was not exercising a
        // production-shaped commit at all. On Windows, where the real
        // preimage lands at exactly `parent_dir.join(backup_name)` (see
        // `fs_commit`'s Windows `commit_placement`), an arbitrary literal
        // here would put the real backup file somewhere recovery's own
        // (equally derived) expectation does not look.
        let backup_name = artefact_component_name(ArtefactKind::Backup, "ep0").unwrap();
        let request = CommitRequest {
            parent_dir: &parent_handle,
            stage_name: OsStr::new(&stage_name),
            live_name: OsStr::new("a.txt"),
            backup_name: OsStr::new(&backup_name),
            capabilities: &caps,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &staged_identity,
        };
        let outcome = NativeCommitAdapter.commit_placement(&request);
        assert!(
            matches!(
                outcome,
                yadorilink_filesystem_sync::fs_commit::FilesystemCommitOutcome::Committed(_)
            ),
            "the real commit must actually succeed for this scenario to test anything: {outcome:?}"
        );
        // The crash: no epoch/generation-publication transaction ever runs.
        assert_eq!(std::fs::read(&live_path).unwrap(), b"new content");

        let report = run(&conn).unwrap();

        let reloaded =
            filesystem_transaction::lookup_epoch(&conn, &epoch.transaction_id, 0).unwrap().unwrap();
        assert_eq!(reloaded.phase, EpochState::RequiresPhysicalRecovery);
        match &report.epochs[0].action {
            EarlyRecoveryAction::RoutedToPhysicalRecovery(observation) => {
                assert!(
                    matches!(observation.live, RecoveryObservation::Present(_)),
                    "live must be observed present after a real successful commit"
                );
                // Where the real platform commit adapter leaves the
                // displaced preimage differs by platform -- see
                // `fs_commit`'s module doc. On Linux/macOS,
                // `renameat2(RENAME_EXCHANGE)` / `renamex_np(RENAME_SWAP)`
                // leave it at the stage name itself (there is no separate
                // backup name on those platforms), so `observation.stage`
                // is where a real crash-recovery caller must look. On
                // Windows, `ReplaceFileW` leaves it at the distinct backup
                // path instead, and the stage artefact it exchanged away is
                // gone -- so this asserts each platform's own convention
                // rather than assuming the Unix one everywhere.
                #[cfg(not(windows))]
                match &observation.stage {
                    Some(RecoveryObservation::Present(id)) => {
                        assert_eq!(id.observed_size, b"old content".len() as u64);
                    }
                    other => panic!("expected the preimage back at the stage name, got {other:?}"),
                }
                #[cfg(windows)]
                {
                    assert!(
                        matches!(observation.stage, Some(RecoveryObservation::Absent)),
                        "Windows exchanges away the stage artefact itself; expected it gone, \
                         got {:?}",
                        observation.stage
                    );
                    match &observation.backup {
                        Some(RecoveryObservation::Present(id)) => {
                            assert_eq!(id.observed_size, b"old content".len() as u64);
                        }
                        other => {
                            panic!("expected the preimage back at the backup name, got {other:?}")
                        }
                    }
                }
            }
            other => panic!("expected RoutedToPhysicalRecovery, got {other:?}"),
        }
    }

    // --- Committed: epoch phase and materialized generation are one
    //     atomic SQLite transaction, so there is no separate persisted
    //     "Committed but ungenerated" state to crash into --------------

    /// The task brief names a crash point "after the epoch row says
    /// `Committed`, before the materialized generation is recorded" as one
    /// to cut into. Reading `commit_window::execute_short_commit_window_unchecked`'s
    /// `Committed` arm shows that cut point does not exist as a distinct
    /// persisted state: `transition_epoch_unchecked(.., EpochState::Committed, ..)`
    /// and `materialized_generation::record_materialized_generation` run
    /// inside the same `rusqlite::Transaction`, committed once, together
    /// (see that module around its `EpochState::Committed` transition and
    /// the `record_materialized_generation` call immediately after it, both
    /// inside one `conn.transaction()` block). A crash before that one
    /// SQLite transaction commits leaves the epoch at `Committing` — the
    /// case the test above already covers — never at `Committed` with no
    /// generation row. This test reproduces the only state a crash can
    /// actually leave once that transaction *has* committed: `Committed`
    /// and the generation both durable, together. It documents that early
    /// recovery correctly leaves this alone (there is no ambiguity to
    /// resolve), not that a gap was found here.
    #[test]
    fn committed_epoch_and_its_generation_are_persisted_atomically_and_left_alone() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let live_path = dir.path().join("a.txt");
        std::fs::write(&live_path, b"old content").unwrap();
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            live_path.to_str().unwrap(),
            &parent_identity,
        );

        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"new content").unwrap();
        let displaced_identity = FileIdentity::observe_path(&live_path).unwrap();
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();

        for to in [EpochState::Preparing, EpochState::PreparedArtifact] {
            transition_epoch_unchecked(
                &conn,
                &epoch.transaction_id,
                epoch.epoch,
                0,
                to,
                &EpochUpdate {
                    stage_path: Some(stage_path.to_str().unwrap()),
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        }
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::AwaitingReservation,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Prepared,
            &EpochUpdate {
                staged_identity: Some(&staged_identity),
                displaced_identity: Some(&displaced_identity),
                ..Default::default()
            },
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Committing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();

        // The real filesystem commit.
        let parent_handle = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent_handle,
            stage_name: OsStr::new(&stage_name),
            live_name: OsStr::new("a.txt"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &staged_identity,
        };
        let outcome = NativeCommitAdapter.commit_placement(&request);
        assert!(matches!(
            outcome,
            yadorilink_filesystem_sync::fs_commit::FilesystemCommitOutcome::Committed(_)
        ));
        let live_identity = FileIdentity::observe_path(&live_path).unwrap();

        // The one durable transaction production code performs after a
        // `Committed` outcome: epoch phase and the materialized generation
        // land together, then the process crashes (nothing else runs).
        {
            let db_tx = conn.unchecked_transaction().unwrap();
            transition_epoch_unchecked(
                &db_tx,
                &epoch.transaction_id,
                epoch.epoch,
                0,
                EpochState::Committed,
                &EpochUpdate {
                    staged_identity: Some(&live_identity),
                    displaced_identity: Some(&displaced_identity),
                    ..Default::default()
                },
                0,
            )
            .unwrap();
            materialized_generation::record_materialized_generation(
                &db_tx,
                "g",
                "a.txt",
                &[],
                materialized_generation::MaterializedObjectKind::RegularFile,
                None,
                Some(&live_identity),
                0,
            )
            .unwrap();
            db_tx.commit().unwrap();
        }

        let report = run(&conn).unwrap();

        assert!(matches!(report.epochs[0].action, EarlyRecoveryAction::NoAction));
        assert_eq!(
            std::fs::read(&live_path).unwrap(),
            b"new content",
            "recovery must not touch it"
        );
        let reloaded =
            filesystem_transaction::lookup_epoch(&conn, &epoch.transaction_id, 0).unwrap().unwrap();
        assert_eq!(
            reloaded.phase,
            EpochState::Committed,
            "early recovery has nothing to resolve here and must not advance the phase itself"
        );
        assert!(
            materialized_generation::lookup_materialized_generation(&conn, "g", "a.txt")
                .unwrap()
                .is_some(),
            "the generation this test's setup wrote atomically with Committed must still be there"
        );
    }

    // --- RequiresPhysicalRecovery already on disk at startup: re-observed
    //     and re-marked owned on every cold start, not skipped as terminal --

    /// Regression test for the gap the task brief named. `Committing` ->
    /// `RequiresPhysicalRecovery` is exactly what
    /// `commit_window::execute_short_commit_window_unchecked` does
    /// itself when a required durability flush fails after a successful
    /// platform commit (see its `Committed` arm's `flush_result` handling)
    /// — this test drives the epoch through that identical transition with
    /// the identical function, then "crashes" (drops everything) before any
    /// consumer processes the `CommitWindowError::RequiresRecovery` value
    /// that call would have returned in memory. That in-memory value was the
    /// *only* place the four-location observation ever existed — nothing
    /// persists it to the database, and it cannot be recovered. What
    /// `recover_epoch` does instead is treat observation as a pure,
    /// idempotent re-read of current disk state and simply redo it, every
    /// cold start, reporting a fresh
    /// [`EarlyRecoveryAction::PersistedRequiresPhysicalRecovery`] (not the
    /// `RoutedToPhysicalRecovery` this same module produces when *it*
    /// performs the transition) and marking every one of this epoch's paths
    /// owned, exactly like every other in-flight state.
    #[test]
    fn requires_physical_recovery_persisted_before_a_crash_is_reobserved_and_kept_owned() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let live_path = dir.path().join("a.txt");
        std::fs::write(&live_path, b"old content").unwrap();
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            live_path.to_str().unwrap(),
            &parent_identity,
        );

        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"new content").unwrap();
        let displaced_identity = FileIdentity::observe_path(&live_path).unwrap();
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();

        for to in [EpochState::Preparing, EpochState::PreparedArtifact] {
            transition_epoch_unchecked(
                &conn,
                &epoch.transaction_id,
                epoch.epoch,
                0,
                to,
                &EpochUpdate {
                    stage_path: Some(stage_path.to_str().unwrap()),
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        }
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::AwaitingReservation,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Prepared,
            &EpochUpdate {
                staged_identity: Some(&staged_identity),
                displaced_identity: Some(&displaced_identity),
                ..Default::default()
            },
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Committing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();

        // The real filesystem commit succeeds...
        let parent_handle = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent_handle,
            stage_name: OsStr::new(&stage_name),
            live_name: OsStr::new("a.txt"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &staged_identity,
        };
        let outcome = NativeCommitAdapter.commit_placement(&request);
        assert!(matches!(
            outcome,
            yadorilink_filesystem_sync::fs_commit::FilesystemCommitOutcome::Committed(_)
        ));
        let live_identity = FileIdentity::observe_path(&live_path).unwrap();

        // ...but the durability flush that must run before publishing
        // `Committed` fails, so production code takes exactly this
        // transition instead (see `execute_short_commit_window_unchecked`'s
        // `flush_result` error arm). No generation is ever recorded on this
        // path. Then the process crashes: nothing consumes the
        // `CommitWindowError::RequiresRecovery` this would have returned.
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::RequiresPhysicalRecovery,
            &EpochUpdate {
                staged_identity: Some(&live_identity),
                displaced_identity: Some(&displaced_identity),
                ..Default::default()
            },
            0,
        )
        .unwrap();

        // Cold restart: only `run` sees this row, nothing else.
        let report = run(&conn).unwrap();

        match &report.epochs[0].action {
            EarlyRecoveryAction::PersistedRequiresPhysicalRecovery(observation) => {
                assert!(
                    matches!(observation.live, RecoveryObservation::Present(_)),
                    "live must be freshly observed present, re-derived from disk, not carried \
                     over from anything the crashed process saw"
                );
            }
            other => panic!("expected PersistedRequiresPhysicalRecovery, got {other:?}"),
        }
        // Fixed: this path is now marked owned exactly like every other
        // in-flight epoch, so generic cleanup/hydration/eviction will not
        // touch it while it sits here unresolved.
        assert!(
            report.owned_paths.contains(&live_path),
            "a RequiresPhysicalRecovery epoch's paths must stay protected on every cold start, \
             not only the pass that first reached this state"
        );
        let reloaded =
            filesystem_transaction::lookup_epoch(&conn, &epoch.transaction_id, 0).unwrap().unwrap();
        assert_eq!(
            reloaded.phase,
            EpochState::RequiresPhysicalRecovery,
            "early recovery re-observes but still does not itself resolve this state -- that is \
             late semantic recovery's job, once it exists"
        );
        assert!(
            materialized_generation::lookup_materialized_generation(&conn, "g", "a.txt")
                .unwrap()
                .is_none(),
            "no generation was ever recorded on the durability-flush-failure path"
        );
        // The new content is durably on disk (the platform commit really
        // happened); the re-derived observation above is what makes that
        // fact visible to whatever later phase reconciles it, instead of
        // being silently lost.
        assert_eq!(std::fs::read(&live_path).unwrap(), b"new content");
    }

    /// A second cold start after the first one already re-observed the same
    /// `RequiresPhysicalRecovery` epoch: still re-observed again, not
    /// treated as settled just because a previous pass already reported it.
    /// This is the "no exit condition today" half of
    /// [`EarlyRecoveryAction::PersistedRequiresPhysicalRecovery`]'s doc,
    /// pinned as a test rather than left as an assertion in prose.
    #[test]
    fn requires_physical_recovery_is_reobserved_again_on_a_second_cold_start() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let live_path = dir.path().join("a.txt");
        std::fs::write(&live_path, b"already committed content").unwrap();
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            live_path.to_str().unwrap(),
            &parent_identity,
        );
        let live_identity = FileIdentity::observe_path(&live_path).unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        // Jump straight to `RequiresPhysicalRecovery` -- the exact
        // production edge is exercised by the test above; this one only
        // needs a row already sitting there across two separate `run` calls.
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::AwaitingReservation,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Prepared,
            &EpochUpdate { staged_identity: Some(&live_identity), ..Default::default() },
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Committing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::RequiresPhysicalRecovery,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();

        let first = run(&conn).unwrap();
        assert!(matches!(
            first.epochs[0].action,
            EarlyRecoveryAction::PersistedRequiresPhysicalRecovery(_)
        ));

        // Second cold start: nothing about the row changed in between
        // (exactly what "no exit condition" means -- there is no code path
        // in this crate yet that would have changed it).
        let second = run(&conn).unwrap();
        assert!(
            matches!(
                second.epochs[0].action,
                EarlyRecoveryAction::PersistedRequiresPhysicalRecovery(_)
            ),
            "still re-observed, not treated as settled merely because a previous pass saw it"
        );
        assert!(second.owned_paths.contains(&live_path));
    }

    // --- Blocked / Quarantined: settled, but their artefacts must still be
    //     marked owned on every cold start, not only the pass that first
    //     reached the state ------------------------------------------------

    /// The same `mark_owned`-ordering defect the two tests above fix for
    /// `RequiresPhysicalRecovery` applied equally to `Blocked`: this drives
    /// an epoch to `Blocked` through this module's own `block` path (a
    /// parent-directory that cannot be reconfirmed), confirms the first
    /// pass reports `Blocked` and marks the path owned (already exercised by
    /// `a_replaced_parent_directory_blocks_instead_of_guessing`), then runs
    /// a *second* cold start against the now-`Blocked` row to confirm the
    /// path stays marked owned indefinitely, not only on the pass that
    /// produced the block.
    #[test]
    fn blocked_epoch_stays_marked_owned_on_a_later_cold_start() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();

        // Replace the parent directory so the first `run` blocks it, same
        // setup as `a_replaced_parent_directory_blocks_instead_of_guessing`.
        std::fs::remove_dir(dir.path()).unwrap();
        std::fs::create_dir(dir.path()).unwrap();

        let first = run(&conn).unwrap();
        assert!(matches!(
            first.epochs[0].action,
            EarlyRecoveryAction::Blocked(BlockReason::ParentDirectoryUnverifiable)
        ));
        assert!(first.owned_paths.contains(&dir.path().join("a.txt")));

        // Second cold start: the epoch is now `Blocked` (a terminal state),
        // and must still be reported as owned, not silently dropped from
        // `owned_paths` the moment it becomes terminal.
        let second = run(&conn).unwrap();
        assert!(matches!(second.epochs[0].action, EarlyRecoveryAction::NoAction));
        assert!(
            second.owned_paths.contains(&dir.path().join("a.txt")),
            "a Blocked epoch's path must stay protected from generic cleanup indefinitely, not \
             only on the pass that first blocked it"
        );
    }

    // --- An artefact with no owning row anywhere: never touched ---------

    #[test]
    fn artefact_with_no_owning_transaction_at_all_is_left_untouched() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        // No transaction, no epoch -- an entirely orphaned reserved-looking
        // file, e.g. left behind by a version of the daemon that no longer
        // runs, or from a transaction whose row was already fully retired.
        let stage_name = artefact_component_name(ArtefactKind::Stage, "orphan").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"nobody's row, anywhere, names this").unwrap();

        let report = run(&conn).unwrap();

        assert!(report.epochs.is_empty());
        assert!(report.owned_paths.is_empty());
        assert_eq!(std::fs::read(&stage_path).unwrap(), b"nobody's row, anywhere, names this");
    }

    // --- A reserved-looking artefact recovery cannot even identify: must
    //     survive byte-for-byte no matter what else this pass does --------

    #[test]
    fn unparseable_reserved_looking_artefact_survives_a_cleanup_pass_byte_for_byte() {
        // `cleanup_unstarted_artefact` only ever acts on the exact path an
        // epoch row recorded as its own `stage_path` -- it never lists the
        // parent directory looking for anything reserved-namespace-shaped,
        // so a file that merely *looks* like it could be an artefact (same
        // reserved prefix) but does not even parse as a valid artefact name
        // is never a candidate for removal, identified or not. This test
        // makes that explicit with a garbage suffix that
        // `reserved_namespace` cannot parse back into an `ArtefactKind`/id
        // pair, sitting right next to a real cleanup happening in the same
        // pass.
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"half-written stage content").unwrap();
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate {
                stage_path: Some(stage_path.to_str().unwrap()),
                staged_identity: Some(&staged_identity),
                ..Default::default()
            },
            0,
        )
        .unwrap();

        // Same reserved prefix, but not a shape `reserved_namespace` can
        // parse back into a kind/id at all.
        let garbage_name = format!(
            "{}not-a-real-artefact-suffix",
            stage_name.strip_suffix("ep0").unwrap_or(&stage_name)
        );
        let garbage_path = dir.path().join(&garbage_name);
        std::fs::write(&garbage_path, b"reserved-looking but unparseable, untouched").unwrap();

        let report = run(&conn).unwrap();

        assert!(!stage_path.exists(), "the genuinely owned, unstarted artefact is still removed");
        assert_eq!(
            std::fs::read(&garbage_path).unwrap(),
            b"reserved-looking but unparseable, untouched",
            "an unidentifiable reserved-looking artefact must survive untouched, byte for byte"
        );
        assert!(matches!(
            report.epochs[0].action,
            EarlyRecoveryAction::UnstartedArtefactRemoved { .. }
        ));
    }

    // --- Windows-only: the derived backup name must be marked owned too --

    /// Regression test for the second defect the review found:
    /// `epoch.backup_path` (the *persisted* column) is never written by
    /// anything upstream in this crate, so the old `mark_owned` never
    /// actually protected the Windows Backup artefact — the sole surviving
    /// copy of whatever a real commit displaced on that platform. This
    /// only exercises `mark_owned`'s own derivation-and-insertion logic
    /// (no real commit is run; nothing here needs `NativeCommitAdapter`),
    /// so it stays deterministic without a Windows filesystem. It is
    /// `#[cfg(windows)]` because the behavior it checks is itself
    /// `#[cfg(windows)]` (see `mark_owned`'s own doc for why deriving this
    /// name on Unix would just mark a path nothing is ever placed at).
    /// UNVERIFIED beyond compilation on this host — no Windows host was
    /// available to actually run it; it will run for real on CI/a Windows
    /// host.
    #[cfg(windows)]
    #[test]
    fn windows_derived_backup_path_is_marked_owned() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );

        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"staged").unwrap();
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate {
                stage_path: Some(stage_path.to_str().unwrap()),
                staged_identity: Some(&staged_identity),
                ..Default::default()
            },
            0,
        )
        .unwrap();

        let report = run(&conn).unwrap();

        // Derived independently here, exactly the way `expected_backup_path`
        // derives it from the same Stage artefact id embedded in
        // `stage_name` -- not by calling that private function directly,
        // so this test also proves the *name itself* is right, not just
        // that some path got inserted.
        let backup_name = artefact_component_name(ArtefactKind::Backup, "ep0").unwrap();
        let expected_backup_path = dir.path().join(&backup_name);
        assert!(
            report.owned_paths.contains(&expected_backup_path),
            "the derived Windows backup name -- the real location of the object a commit would \
             have displaced -- must be marked owned, not only the never-written persisted column"
        );
    }

    // --- Parent-directory identity cannot be reconfirmed: fail closed ---

    #[test]
    fn a_replaced_parent_directory_blocks_instead_of_guessing() {
        let conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let live_path = dir.path().join("a.txt");
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            live_path.to_str().unwrap(),
            &parent_identity,
        );
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();

        // Replace the parent directory itself with a fresh one at the same
        // path (a different underlying object with the same name) --
        // exactly the reuse/replacement case §9.1 requires blocking on.
        std::fs::remove_dir(dir.path()).unwrap();
        std::fs::create_dir(dir.path()).unwrap();

        let report = run(&conn).unwrap();

        assert!(matches!(
            report.epochs[0].action,
            EarlyRecoveryAction::Blocked(BlockReason::ParentDirectoryUnverifiable)
        ));
        let reloaded_tx =
            filesystem_transaction::lookup_transaction(&conn, &tx.transaction_id).unwrap().unwrap();
        assert_eq!(reloaded_tx.phase, TransactionPhase::Blocked);
    }

    // --- CustodyTransferred / later: orphaned custody obligation ---------

    fn open_db_with_obligations() -> Connection {
        let conn = open_db();
        retained_obligation::init_retained_obligations_schema(&conn).unwrap();
        conn
    }

    #[allow(clippy::too_many_arguments)]
    fn drive_epoch_to_committed(
        conn: &Connection,
        epoch: &EpochRecord,
        stage_path: &std::path::Path,
        displaced_generation_id: &file_identity_codec::GenerationId,
        displaced_identity: &FileIdentity,
    ) {
        // Mirrors `orchestrator.rs`'s own real transitions up through the
        // commit window: `stage_path` recorded at `PreparedArtifact` as the
        // full path joined through the real `ParentDirHandle` (see
        // `orchestrator::run_slice_unchecked`'s own `stage_path =
        // io.parent_dir.path().join(&stage_name)`) -- the one durable,
        // absolute physical location this row carries, distinct from
        // `target_path`'s group-relative sync path; `displaced_generation_id`
        // recorded at `Prepared`, well before commit; `displaced_identity`
        // recorded at `Committed` -- exactly where a crash before
        // `custody_transfer::transfer_to_custody`'s rename ever runs would
        // leave it.
        transition_epoch_unchecked(
            conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Preparing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::PreparedArtifact,
            &EpochUpdate { stage_path: Some(&stage_path.to_string_lossy()), ..Default::default() },
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::AwaitingReservation,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Prepared,
            &EpochUpdate {
                displaced_generation_id: Some(displaced_generation_id),
                ..Default::default()
            },
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Committing,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Committed,
            &EpochUpdate { displaced_identity: Some(displaced_identity), ..Default::default() },
            0,
        )
        .unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn drive_epoch_to_custody_transferred(
        conn: &Connection,
        epoch: &EpochRecord,
        stage_path: &std::path::Path,
        displaced_generation_id: &file_identity_codec::GenerationId,
        displaced_identity: &FileIdentity,
    ) {
        drive_epoch_to_committed(
            conn,
            epoch,
            stage_path,
            displaced_generation_id,
            displaced_identity,
        );
        // Then straight to `CustodyTransferred` -- exactly where a crash
        // before `retained_obligation::create` runs would leave it.
        transition_epoch_unchecked(
            conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::CustodyTransferred,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
    }

    /// The crash window `orchestrator.rs`'s module doc names: custody
    /// transfer's rename landed (this epoch reached `CustodyTransferred`,
    /// with a real `displaced_identity` recorded) but the process crashed
    /// before `retained_obligation::create` ever committed. Recovery must
    /// recreate the missing obligation from this epoch row's own durable
    /// fields, not leave the retained artefact owned by nothing.
    #[test]
    fn an_epoch_at_custody_transferred_with_no_obligation_gets_one_recreated() {
        let conn = open_db_with_obligations();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let target_path = dir.path().join("a.txt");
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            target_path.to_str().unwrap(),
            &parent_identity,
        );

        std::fs::write(&target_path, b"new content").unwrap();
        let displaced_identity = FileIdentity::observe_path(&target_path).unwrap();
        let displaced_generation_id = file_identity_codec::GenerationId("basis-123".to_string());
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        drive_epoch_to_custody_transferred(
            &conn,
            &epoch,
            &stage_path,
            &displaced_generation_id,
            &displaced_identity,
        );

        let retained_id = format!("{}-ep{}", epoch.transaction_id, epoch.epoch);
        // The rename `custody_transfer::transfer_to_custody` performs
        // already landed physically by `CustodyTransferred` -- simulated
        // directly here since this test drives the epoch state machine
        // without a real commit. Recovery verifies the object at
        // `custody_path` is the SAME object `displaced_identity` was
        // observed from, so only a rename (not a fresh write) preserves the
        // identity it checks.
        let custody_name =
            reserved_namespace::artefact_component_name(ArtefactKind::Retained, &retained_id)
                .unwrap();
        std::fs::rename(&target_path, dir.path().join(&custody_name)).unwrap();
        assert!(retained_obligation::get(&conn, "g", &retained_id).unwrap().is_none());

        let report = run(&conn).unwrap();

        assert_eq!(report.epochs.len(), 1);
        match &report.epochs[0].action {
            EarlyRecoveryAction::OrphanedCustodyObligationRecovered { retained_id: r } => {
                assert_eq!(*r, retained_id)
            }
            other => panic!("expected OrphanedCustodyObligationRecovered, got {other:?}"),
        }

        let obligation = retained_obligation::get(&conn, "g", &retained_id).unwrap().unwrap();
        assert_eq!(obligation.original_path, target_path.to_str().unwrap());
        assert_eq!(obligation.original_parent_basis_id, "basis-123");
    }

    /// The production shape the review named: `target_path` is a
    /// group-relative sync path (it may contain separators, per
    /// `resolution_planning::PlannedPlacement::path`'s own doc), never a
    /// physical filename `Path::parent()` can be taken of directly. Every
    /// other test in this module happens to use an *absolute* `target_path`
    /// (a real temp-directory path), which makes a buggy
    /// `target_path.parent()` derivation accidentally resolve to the right
    /// directory anyway -- exactly the masking the review named. This one
    /// uses a real relative, multi-component sync path under a real sync
    /// root, so only deriving the physical directory from `stage_path` (see
    /// [`physical_parent_dir`]'s own doc), never from `target_path`, can make
    /// it pass: the old code would have resolved `sub/.yadorilink-...`
    /// relative to the test process's own working directory instead of
    /// under the sync root.
    #[test]
    fn a_rebuilt_custody_path_uses_the_real_physical_directory_for_a_group_relative_target_path() {
        let conn = open_db_with_obligations();
        let sync_root = tempfile::tempdir().unwrap();
        let physical_dir = sync_root.path().join("sub");
        std::fs::create_dir(&physical_dir).unwrap();
        let parent_identity = DirectoryIdentity::observe_path(&physical_dir).unwrap();
        let tx = begin_sample_transaction(&conn);
        // Group-relative, not physical -- `PlannedPlacement::path`'s own
        // shape, never joined against `sync_root` by this row itself.
        let target_path = "sub/a.txt";
        let epoch = insert_sample_epoch(&conn, &tx.transaction_id, target_path, &parent_identity);

        let live_path = physical_dir.join("a.txt");
        std::fs::write(&live_path, b"new content").unwrap();
        let displaced_identity = FileIdentity::observe_path(&live_path).unwrap();
        let displaced_generation_id = file_identity_codec::GenerationId("basis-123".to_string());
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        // The one durable, absolute physical location this row carries --
        // joined through the real directory, exactly as
        // `orchestrator::run_slice_unchecked` records it, never derived from
        // `target_path`.
        let stage_path = physical_dir.join(&stage_name);
        drive_epoch_to_custody_transferred(
            &conn,
            &epoch,
            &stage_path,
            &displaced_generation_id,
            &displaced_identity,
        );

        let retained_id = format!("{}-ep{}", epoch.transaction_id, epoch.epoch);
        // Same physical rename as the other tests in this module: recovery
        // now verifies the object at `custody_path` is the SAME object
        // `displaced_identity` was observed from.
        let custody_name =
            reserved_namespace::artefact_component_name(ArtefactKind::Retained, &retained_id)
                .unwrap();
        std::fs::rename(&live_path, physical_dir.join(&custody_name)).unwrap();

        let report = run(&conn).unwrap();

        assert_eq!(report.epochs.len(), 1);
        assert!(matches!(
            report.epochs[0].action,
            EarlyRecoveryAction::OrphanedCustodyObligationRecovered { .. }
        ));

        let obligation = retained_obligation::get(&conn, "g", &retained_id).unwrap().unwrap();
        let custody_path = std::path::PathBuf::from(&obligation.custody_path);
        assert_eq!(
            custody_path.parent(),
            Some(physical_dir.as_path()),
            "the custody artefact must be rebuilt under the real physical directory the stage \
             artefact was created in, not resolved from the group-relative `target_path` \
             relative to the process's own working directory: got {custody_path:?}"
        );
        assert_eq!(obligation.original_path, target_path);
    }

    /// The review's second finding on this reconstruction: an existing
    /// `retained_preimages` row under this exact `retained_id` must not be
    /// treated as "already recovered" on the strength of the id alone.
    /// Because `retained_id` is derived deterministically from
    /// `(transaction_id, epoch)`, a row that disagrees with what this
    /// epoch's own fields would reconstruct -- here, a different
    /// `original_parent_basis_id`, with everything else matching -- can only
    /// be a genuine identity collision, and recovery must say so loudly
    /// rather than silently accepting the wrong basis as done.
    #[test]
    fn an_existing_row_with_a_mismatched_basis_is_not_silently_accepted() {
        let conn = open_db_with_obligations();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let target_path = dir.path().join("a.txt");
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            target_path.to_str().unwrap(),
            &parent_identity,
        );

        std::fs::write(&target_path, b"new content").unwrap();
        let displaced_identity = FileIdentity::observe_path(&target_path).unwrap();
        let displaced_generation_id = file_identity_codec::GenerationId("basis-123".to_string());
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        drive_epoch_to_custody_transferred(
            &conn,
            &epoch,
            &stage_path,
            &displaced_generation_id,
            &displaced_identity,
        );

        let retained_id = format!("{}-ep{}", epoch.transaction_id, epoch.epoch);
        let custody_name =
            reserved_namespace::artefact_component_name(ArtefactKind::Retained, &retained_id)
                .unwrap();
        // The rename `custody_transfer::transfer_to_custody` performs
        // already landed physically -- recovery must reach the existing-row
        // basis comparison this test exercises, which requires first
        // passing its own identity check against the object actually at
        // `custody_path`.
        std::fs::rename(&target_path, dir.path().join(&custody_name)).unwrap();
        // Everything but the basis matches what recovery would itself
        // reconstruct -- a row this precise can only be a stale write
        // against the same id under a different causal basis, not a
        // legitimate repeat of this same recovery.
        retained_obligation::create(
            &conn,
            &NewObligation {
                retained_id: &retained_id,
                originating_transaction_id: Some(&epoch.transaction_id),
                source_epoch: Some(epoch.epoch),
                group_id: "g",
                original_path: target_path.to_str().unwrap(),
                custody_path: &dir.path().join(&custody_name).to_string_lossy(),
                parent_directory_identity: &encode_directory_identity(&parent_identity),
                filesystem_identity: None,
                original_parent_basis_id: "a-different-basis",
            },
            0,
        )
        .unwrap();

        let error = run(&conn).unwrap_err();
        assert!(
            matches!(error, SyncSqliteError::CorruptState(_)),
            "a row with the right id but the wrong basis must be surfaced loudly, not silently \
             treated as already recovered: got {error:?}"
        );

        // The mismatched row itself is left exactly as found -- this is a
        // refusal, not a repair.
        let obligation = retained_obligation::get(&conn, "g", &retained_id).unwrap().unwrap();
        assert_eq!(obligation.original_parent_basis_id, "a-different-basis");
    }

    /// The ordinary case -- the obligation was already durably created by an
    /// earlier recovery pass over the same still-incomplete transaction (no
    /// further crash in between) -- must be a no-op on a second pass:
    /// recovery must not attempt to recreate (and, since `create` is
    /// idempotent, would not corrupt) a row that is already there, and must
    /// not misreport an already-resolved epoch as having just recovered
    /// something. Rebuilding the existing row from a real first recovery
    /// pass, rather than hand-crafting one, is what proves this: a
    /// hand-crafted row with fields recovery would never itself produce
    /// (e.g. a `custody_path` recovery could not have derived) would only
    /// prove the *old*, weaker "any row with this id" check, not that the
    /// row recovery finds is actually byte-for-byte what it would have
    /// written itself -- see [`recover_orphaned_custody_obligation`]'s own
    /// doc on why that distinction matters.
    #[test]
    fn an_epoch_at_custody_transferred_with_an_existing_obligation_is_left_alone() {
        let conn = open_db_with_obligations();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let target_path = dir.path().join("a.txt");
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            target_path.to_str().unwrap(),
            &parent_identity,
        );

        std::fs::write(&target_path, b"new content").unwrap();
        let displaced_identity = FileIdentity::observe_path(&target_path).unwrap();
        let displaced_generation_id = file_identity_codec::GenerationId("basis-123".to_string());
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        drive_epoch_to_custody_transferred(
            &conn,
            &epoch,
            &stage_path,
            &displaced_generation_id,
            &displaced_identity,
        );

        let retained_id = format!("{}-ep{}", epoch.transaction_id, epoch.epoch);
        // The rename `custody_transfer::transfer_to_custody` performs
        // already landed physically -- recovery verifies the object at
        // `custody_path` is the SAME object `displaced_identity` was
        // observed from.
        let custody_name =
            reserved_namespace::artefact_component_name(ArtefactKind::Retained, &retained_id)
                .unwrap();
        std::fs::rename(&target_path, dir.path().join(&custody_name)).unwrap();

        // First pass: the crash-recovery case already covered above,
        // recreating the obligation for real.
        let first = run(&conn).unwrap();
        assert!(matches!(
            first.epochs[0].action,
            EarlyRecoveryAction::OrphanedCustodyObligationRecovered { .. }
        ));
        let obligation_after_first =
            retained_obligation::get(&conn, "g", &retained_id).unwrap().unwrap();

        // Second pass over the same still-incomplete transaction: the
        // ordinary case this test targets. Nothing on the epoch or
        // obligation row changed in between, so this must be a pure no-op.
        let second = run(&conn).unwrap();

        assert_eq!(second.epochs.len(), 1);
        assert!(matches!(second.epochs[0].action, EarlyRecoveryAction::NoAction));

        let obligation_after_second =
            retained_obligation::get(&conn, "g", &retained_id).unwrap().unwrap();
        assert_eq!(
            obligation_after_second.custody_path, obligation_after_first.custody_path,
            "an existing, matching obligation must not be overwritten or rederived"
        );
    }

    // --- Committed: rename-landed-before-transition crash window ---------

    /// The crash window `recover_committed_custody_transfer` exists for,
    /// one phase earlier than the `CustodyTransferred` case above:
    /// `custody_transfer::transfer_to_custody`'s rename is a plain
    /// filesystem call, durable the instant it returns, but
    /// `drive_captured_placement` only writes the `CustodyTransferred`
    /// transition *after* that call returns. A crash in between leaves the
    /// retained artefact already at its custody name on disk while the
    /// epoch row still reads `Committed`. Recovery must find it there,
    /// bring the epoch's durable state in line with the physical fact
    /// (`CustodyTransferred`), and recreate the missing obligation --
    /// otherwise the artefact is invisible to `owned_paths` and exposed to
    /// generic cleanup for as long as the row sits at `Committed`.
    #[test]
    fn a_committed_epoch_whose_rename_already_landed_gets_recovered() {
        let conn = open_db_with_obligations();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let target_path = dir.path().join("a.txt");
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            target_path.to_str().unwrap(),
            &parent_identity,
        );

        std::fs::write(&target_path, b"new content").unwrap();
        let displaced_identity = FileIdentity::observe_path(&target_path).unwrap();
        let displaced_generation_id = file_identity_codec::GenerationId("basis-123".to_string());
        let stage_path = dir.path().join("stage-a.txt");
        drive_epoch_to_committed(
            &conn,
            &epoch,
            &stage_path,
            &displaced_generation_id,
            &displaced_identity,
        );

        let retained_id = format!("{}-ep{}", epoch.transaction_id, epoch.epoch);
        let custody_name =
            reserved_namespace::artefact_component_name(ArtefactKind::Retained, &retained_id)
                .unwrap();
        let custody_path = dir.path().join(&custody_name);
        // The rename `custody_transfer::transfer_to_custody` performs
        // already landed physically -- simulated directly here, since this
        // test drives the epoch state machine without running a real
        // commit -- but the epoch row is left at `Committed`, exactly the
        // crash shape this recovers. A real rename (not a fresh write)
        // matters: recovery now verifies the object at `custody_path` is
        // the SAME object `displaced_identity` was observed from (inode
        // identity, not mere existence), and only a rename preserves that.
        std::fs::rename(&target_path, &custody_path).unwrap();

        assert!(retained_obligation::get(&conn, "g", &retained_id).unwrap().is_none());

        let report = run(&conn).unwrap();

        assert_eq!(report.epochs.len(), 1);
        match &report.epochs[0].action {
            EarlyRecoveryAction::OrphanedCustodyObligationRecovered { retained_id: r } => {
                assert_eq!(*r, retained_id)
            }
            other => panic!("expected OrphanedCustodyObligationRecovered, got {other:?}"),
        }

        let obligation = retained_obligation::get(&conn, "g", &retained_id).unwrap().unwrap();
        assert_eq!(obligation.original_path, target_path.to_str().unwrap());
        assert_eq!(obligation.original_parent_basis_id, "basis-123");
        assert_eq!(obligation.custody_path, custody_path.to_string_lossy());

        // The durable record now matches the physical fact recovery found:
        // no longer stranded at the non-terminal `Committed` with an
        // invisible, unowned retained artefact.
        let epochs = list_epochs_for_transaction(&conn, &epoch.transaction_id).unwrap();
        let reloaded = epochs.iter().find(|e| e.epoch == epoch.epoch).unwrap();
        assert_eq!(reloaded.phase, EpochState::CustodyTransferred);
    }

    /// The ordinary case for a `Committed` epoch: the rename never ran (no
    /// artefact at the derived custody location), whether because the
    /// commit displaced nothing durable enough to reach this window or
    /// because the crash happened before `custody_transfer::
    /// transfer_to_custody` itself. Nothing here is this crash's signature,
    /// so recovery must leave the row exactly as found rather than guessing
    /// a custody transfer happened that never did.
    #[test]
    fn a_committed_epoch_whose_rename_never_ran_is_left_alone() {
        let conn = open_db_with_obligations();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        let target_path = dir.path().join("a.txt");
        let epoch = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            target_path.to_str().unwrap(),
            &parent_identity,
        );

        std::fs::write(&target_path, b"new content").unwrap();
        let displaced_identity = FileIdentity::observe_path(&target_path).unwrap();
        let displaced_generation_id = file_identity_codec::GenerationId("basis-123".to_string());
        let stage_path = dir.path().join("stage-a.txt");
        drive_epoch_to_committed(
            &conn,
            &epoch,
            &stage_path,
            &displaced_generation_id,
            &displaced_identity,
        );

        // Deliberately no file written at the derived custody location.
        let retained_id = format!("{}-ep{}", epoch.transaction_id, epoch.epoch);

        let report = run(&conn).unwrap();

        assert_eq!(report.epochs.len(), 1);
        assert!(matches!(report.epochs[0].action, EarlyRecoveryAction::NoAction));
        assert!(retained_obligation::get(&conn, "g", &retained_id).unwrap().is_none());

        let epochs = list_epochs_for_transaction(&conn, &epoch.transaction_id).unwrap();
        let reloaded = epochs.iter().find(|e| e.epoch == epoch.epoch).unwrap();
        assert_eq!(
            reloaded.phase,
            EpochState::Committed,
            "no custody transfer happened, so the epoch must not be advanced"
        );
    }

    // --- Regression: a slice-wide reservation leaked across every epoch
    //     still sitting at `PreparedArtifact` must be released ------------

    /// Reproduces exactly what `orchestrator::run_slice_unchecked` really
    /// produces on a crash right after its one, whole-slice
    /// `acquire_reservations_unchecked` call and before the loop that
    /// transitions individual epochs even starts: every epoch in the
    /// transaction is still at `PreparedArtifact`, and the transaction as a
    /// whole holds every reservation the slice requested. Before this fix,
    /// the per-epoch dispatch only ever released a reservation from the
    /// `AwaitingReservation` arm -- a state none of these epochs ever
    /// reached -- so the reservation survived this pass untouched and would
    /// have gone on blocking every other transaction on these paths, and
    /// fencing every future DAG admission that touched them, forever.
    #[test]
    fn slice_wide_reservation_acquired_before_any_epoch_left_prepared_artifact_is_released() {
        let mut conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);

        let epoch_a = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );
        let epoch_b = insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch: 1,
                plan_revision: 0,
                target_path: dir.path().join("b.txt").to_str().unwrap(),
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"opaque",
                parent_directory_identity: &parent_identity,
                capability_snapshot: b"opaque",
                durability_level:
                    yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            },
            // `tx` (from `begin_sample_transaction`) is still at its
            // starting generation 0 here -- nothing bumps it before this.
            0,
            0,
        )
        .unwrap();

        // Drive both epochs to `PreparedArtifact` -- no stage artefact
        // recorded, matching an epoch whose `prepare_target` step never
        // reached far enough to write one; this test is about the
        // reservation, not stage cleanup.
        for epoch in [&epoch_a, &epoch_b] {
            transition_epoch_unchecked(
                &conn,
                &epoch.transaction_id,
                epoch.epoch,
                0,
                EpochState::Preparing,
                &EpochUpdate::default(),
                0,
            )
            .unwrap();
            transition_epoch_unchecked(
                &conn,
                &epoch.transaction_id,
                epoch.epoch,
                0,
                EpochState::PreparedArtifact,
                &EpochUpdate::default(),
                0,
            )
            .unwrap();
        }

        // The one, whole-slice acquisition `run_slice_unchecked` performs
        // before either epoch moves to `AwaitingReservation`.
        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[
                yadorilink_replica_domain::filesystem_placement::NewReservation {
                    group_id: "g",
                    transaction_id: &tx.transaction_id,
                    scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                    path: "a.txt",
                    role: yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
                },
                yadorilink_replica_domain::filesystem_placement::NewReservation {
                    group_id: "g",
                    transaction_id: &tx.transaction_id,
                    scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                    path: "b.txt",
                    role: yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
                },
            ],
            0,
        )
        .unwrap();

        let report = run(&conn).unwrap();

        assert!(
            filesystem_transaction::list_reservations(&conn, &tx.transaction_id)
                .unwrap()
                .is_empty(),
            "a slice-wide reservation acquired before any epoch left PreparedArtifact must not \
             survive this pass -- it has nothing left to protect and nothing else will ever \
             release it"
        );
        assert_eq!(report.epochs.len(), 2);
        for outcome in &report.epochs {
            assert!(
                matches!(outcome.action, EarlyRecoveryAction::NoAction),
                "got {:?}",
                outcome.action
            );
        }
    }

    /// The case the fix above must not break: when one epoch of the
    /// transaction is (or is routed to, by this same pass) `Requires
    /// PhysicalRecovery`, the reservation is deliberately left held for
    /// late semantic recovery -- see `orchestrator.rs`'s module doc, "left
    /// un-released intentionally" -- even though a *sibling* epoch in the
    /// same transaction is sitting untouched at `PreparedArtifact` and
    /// would, on its own, look exactly like the leak the test above pins.
    #[test]
    fn reservation_stays_held_when_a_sibling_epoch_requires_physical_recovery() {
        let mut conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);

        // Epoch 0: driven all the way to `Committing`, the state that
        // always routes to `RequiresPhysicalRecovery` regardless of what
        // physical inspection finds (the module's "settled `Committing`
        // rule").
        let epoch_committing = insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );
        for to in [
            EpochState::Preparing,
            EpochState::PreparedArtifact,
            EpochState::AwaitingReservation,
            EpochState::Prepared,
            EpochState::Committing,
        ] {
            transition_epoch_unchecked(
                &conn,
                &epoch_committing.transaction_id,
                epoch_committing.epoch,
                0,
                to,
                &EpochUpdate::default(),
                0,
            )
            .unwrap();
        }

        // Epoch 1: a sibling still sitting untouched at `PreparedArtifact`,
        // as if the crash happened partway through the slice's per-epoch
        // loop, after epoch 0 reached its commit window but before epoch 1
        // was ever reached.
        let epoch_untouched = insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch: 1,
                plan_revision: 0,
                target_path: dir.path().join("b.txt").to_str().unwrap(),
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"opaque",
                parent_directory_identity: &parent_identity,
                capability_snapshot: b"opaque",
                durability_level:
                    yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            },
            // Every transition on `epoch_committing` above used expected
            // generation 0, and nothing bumps the fence in this test.
            0,
            0,
        )
        .unwrap();
        for to in [EpochState::Preparing, EpochState::PreparedArtifact] {
            transition_epoch_unchecked(
                &conn,
                &epoch_untouched.transaction_id,
                epoch_untouched.epoch,
                0,
                to,
                &EpochUpdate::default(),
                0,
            )
            .unwrap();
        }

        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[
                yadorilink_replica_domain::filesystem_placement::NewReservation {
                    group_id: "g",
                    transaction_id: &tx.transaction_id,
                    scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                    path: "a.txt",
                    role: yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
                },
                yadorilink_replica_domain::filesystem_placement::NewReservation {
                    group_id: "g",
                    transaction_id: &tx.transaction_id,
                    scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                    path: "b.txt",
                    role: yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
                },
            ],
            0,
        )
        .unwrap();

        let report = run(&conn).unwrap();

        assert_eq!(
            filesystem_transaction::list_reservations(&conn, &tx.transaction_id).unwrap().len(),
            2,
            "an epoch requiring physical recovery anywhere in the transaction must keep every \
             reservation held, even though a sibling epoch looks -- on its own -- exactly like \
             the abandoned-slice case that must release"
        );
        let committing_action =
            &report.epochs.iter().find(|o| o.epoch == epoch_committing.epoch).unwrap().action;
        assert!(
            matches!(committing_action, EarlyRecoveryAction::RoutedToPhysicalRecovery(_)),
            "got {:?}",
            committing_action
        );
        let untouched_action =
            &report.epochs.iter().find(|o| o.epoch == epoch_untouched.epoch).unwrap().action;
        assert!(
            matches!(untouched_action, EarlyRecoveryAction::NoAction),
            "got {:?}",
            untouched_action
        );
    }

    // --- Regression: `Blocked` proves nothing, so it must not release
    //     the reservation the way a settled/resolved outcome does --------

    /// An ordinary, non-`Blocked` outcome must still release: pins the
    /// polarity the two tests below are contrasted against.
    ///
    /// This used to drive the epoch only to `Allocated` with an *absolute*
    /// `target_path`. Both were wrong for what this test claims to pin:
    /// production always stores a group-relative sync path (see this
    /// module's own doc), and under a group-relative `target_path` an
    /// `Allocated` epoch never reaches `recover_epoch`'s `NoAction` arm at
    /// all -- `physical_parent_dir` returns `None` (no `stage_path` yet)
    /// and `target_path` is not absolute, so it blocks with
    /// `BlockReason::ParentDirectoryUnresolvable` instead (see that arm's
    /// own comment). A test that reached `NoAction` only by giving
    /// `target_path` a shape production never produces was pinning a
    /// release branch that is dead code for the one state it exercised --
    /// it would have stayed green even if `Allocated`'s `NoAction` arm were
    /// deleted outright.
    ///
    /// The release branch itself is very much alive in production, just not
    /// via `Allocated`: `Prepared` is a real, drives-through-a-real-commit
    /// state that reaches `recover_epoch`'s `_ => NoAction` catch-all after
    /// resolving its parent directory from the epoch's own (always
    /// absolute) `stage_path` -- never from `target_path` at all once a
    /// stage artefact has been recorded (see `physical_parent_dir`'s own
    /// doc). This drives a group-relative `target_path` all the way through
    /// the real transitions to `Prepared`, so it pins the release polarity
    /// against a state and a `target_path` shape production can actually
    /// reach at the same time.
    #[test]
    fn an_ordinary_unblocked_epoch_releases_the_reservation() {
        let mut conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        // Group-relative, exactly as production stores it -- see
        // `blocked_epoch_with_a_group_relative_target_path_keeps_the_reservation_held`
        // for the same convention. `physical_parent_dir` never looks at
        // this once a `stage_path` is recorded below, so its shape cannot
        // affect parent-directory resolution here.
        let epoch = insert_sample_epoch(&conn, &tx.transaction_id, "a.txt", &parent_identity);
        let stage_name = artefact_component_name(ArtefactKind::Stage, "ep0").unwrap();
        let stage_path = dir.path().join(&stage_name);
        std::fs::write(&stage_path, b"staged").unwrap();
        let staged_identity = FileIdentity::observe_path(&stage_path).unwrap();

        for to in [EpochState::Preparing, EpochState::PreparedArtifact] {
            transition_epoch_unchecked(
                &conn,
                &epoch.transaction_id,
                epoch.epoch,
                0,
                to,
                &EpochUpdate {
                    stage_path: Some(stage_path.to_str().unwrap()),
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        }
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::AwaitingReservation,
            &EpochUpdate::default(),
            0,
        )
        .unwrap();
        transition_epoch_unchecked(
            &conn,
            &epoch.transaction_id,
            epoch.epoch,
            0,
            EpochState::Prepared,
            &EpochUpdate { staged_identity: Some(&staged_identity), ..Default::default() },
            0,
        )
        .unwrap();
        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[yadorilink_replica_domain::filesystem_placement::NewReservation {
                group_id: "g",
                transaction_id: &tx.transaction_id,
                scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                path: "a.txt",
                role:
                    yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        let report = run(&conn).unwrap();

        assert!(matches!(report.epochs[0].action, EarlyRecoveryAction::NoAction));
        assert!(
            filesystem_transaction::list_reservations(&conn, &tx.transaction_id)
                .unwrap()
                .is_empty(),
            "an ordinary resolved outcome must still release -- this pins the release polarity \
             the withhold tests below are contrasted against"
        );
    }

    /// The concrete break the fix closes: a real I/O failure observing the
    /// parent directory (`BlockReason::ParentDirectoryUnreadable`) is a
    /// "could not check" outcome, never a confirmed absence -- see that
    /// variant's own doc. Before the fix, `run` treated any outcome other
    /// than `RoutedToPhysicalRecovery`/`PersistedRequiresPhysicalRecovery`
    /// as "nothing left to protect" and released the reservation anyway.
    #[cfg(unix)]
    #[test]
    fn blocked_epoch_with_an_unreadable_parent_directory_keeps_the_reservation_held() {
        use std::os::unix::fs::PermissionsExt;

        struct RestorePerms(std::path::PathBuf);
        impl Drop for RestorePerms {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
        }

        let mut conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        insert_sample_epoch(
            &conn,
            &tx.transaction_id,
            dir.path().join("a.txt").to_str().unwrap(),
            &parent_identity,
        );
        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[yadorilink_replica_domain::filesystem_placement::NewReservation {
                group_id: "g",
                transaction_id: &tx.transaction_id,
                scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                path: "a.txt",
                role:
                    yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        // Deny even search access to the parent directory, so
        // `ParentDirHandle::open` fails with a real `io::Error` rather
        // than this pass observing (and being able to conclude) anything.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
        // Restored on every exit from here, including a failed assertion
        // below, so the tempdir's own `Drop` can still remove it.
        let _restore = RestorePerms(dir.path().to_path_buf());

        let report = run(&conn).unwrap();

        assert!(
            matches!(
                report.epochs[0].action,
                EarlyRecoveryAction::Blocked(BlockReason::ParentDirectoryUnreadable)
            ),
            "got {:?}",
            report.epochs[0].action
        );
        assert_eq!(
            filesystem_transaction::list_reservations(&conn, &tx.transaction_id).unwrap().len(),
            1,
            "an unreadable parent directory proves nothing either way -- the reservation must \
             stay held, not be released as though this pass had confirmed nothing was left to \
             protect"
        );
    }

    /// Production stores group-relative sync paths, never the absolute
    /// paths every other test in this file uses for `target_path` (a test
    /// convenience, so `DirectoryIdentity::observe_path` has a real
    /// directory to observe). A relative `target_path` with no recorded
    /// `stage_path` -- the ordinary shape for an epoch that crashed before
    /// `PreparedArtifact` -- has no physical location this module can
    /// resolve at all: [`physical_parent_dir`] returns `None` and
    /// `target_path` is not absolute, so `recover_epoch` never even
    /// attempts to open a directory. That is `BlockReason::
    /// ParentDirectoryUnresolvable`, resolved as a block for the same
    /// fail-closed reason as the unreadable case above -- "no directory was
    /// ever opened, because nothing durable said where to look" is not
    /// evidence the reservation has nothing left to protect either.
    #[test]
    fn blocked_epoch_with_a_group_relative_target_path_keeps_the_reservation_held() {
        let mut conn = open_db();
        // Never opened by this test -- `recover_epoch` must never reach for
        // it either, since `target_path` below is relative and there is no
        // recorded `stage_path` to derive a directory from. Only its
        // identity blob is used, as the (unverified) value this epoch row
        // recorded before the crash.
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        // Group-relative, exactly as production `dag_store`/`resolution_planning`
        // rows store it -- never joined against any real directory in this
        // test, which is the point: nothing durable says where to look.
        insert_sample_epoch(&conn, &tx.transaction_id, "a.txt", &parent_identity);
        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[yadorilink_replica_domain::filesystem_placement::NewReservation {
                group_id: "g",
                transaction_id: &tx.transaction_id,
                scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                path: "a.txt",
                role:
                    yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        let report = run(&conn).unwrap();

        assert!(
            matches!(
                report.epochs[0].action,
                EarlyRecoveryAction::Blocked(BlockReason::ParentDirectoryUnresolvable)
            ),
            "got {:?}",
            report.epochs[0].action
        );
        assert_eq!(
            filesystem_transaction::list_reservations(&conn, &tx.transaction_id).unwrap().len(),
            1,
            "a group-relative target_path with no stage_path is a 'could not check' outcome, \
             not a confirmed absence -- the reservation must stay held"
        );
    }

    // --- Regression: two epochs of one transaction both blocking in the
    //     same pass must not abort recovery -------------------------------

    /// The concrete break defect 2 named: `block`'s legality check used to
    /// read `transaction.phase` from the snapshot `run`'s outer loop loaded
    /// once, before either epoch had been walked. Production stores
    /// group-relative sync paths, so `physical_parent_dir` returning `None`
    /// (no `stage_path` recorded) for an `Allocated` epoch is the ordinary
    /// case, not exotic -- and two placements in one slice, both blocking
    /// the same way, is the ordinary shape a real multi-file transaction
    /// takes. Before the fix, the second epoch's `block()` call would see
    /// the stale (pre-pass) `transaction.phase`, decide it must still call
    /// `set_transaction_phase_unchecked`, and have that call's own fresh
    /// read find the transaction already `Blocked` -- `(Blocked, Blocked)`
    /// is not a legal `TransactionPhase` transition, so that call would
    /// return `SyncSqliteError::InvalidInput`, propagating out of `run` and
    /// skipping every remaining epoch, every remaining transaction, and
    /// every reservation release in the same call. This test's central
    /// assertion is simply that `run` returns `Ok` at all with two blocking
    /// siblings -- everything else here confirms the *rest* of the pass
    /// still completed normally around that.
    #[test]
    fn two_sibling_epochs_blocking_in_the_same_pass_does_not_abort_recovery() {
        let mut conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);

        // Both group-relative, exactly as production stores them, and both
        // left at `Allocated` -- no `stage_path` recorded for either, so
        // `physical_parent_dir` returns `None` and `target_path` is not
        // absolute for both, and both block with
        // `BlockReason::ParentDirectoryUnresolvable`.
        let epoch_a = insert_sample_epoch(&conn, &tx.transaction_id, "a.txt", &parent_identity);
        let epoch_b = insert_epoch_unchecked(
            &conn,
            &NewEpoch {
                transaction_id: &tx.transaction_id,
                epoch: 1,
                plan_revision: 0,
                target_path: "b.txt",
                placement_role: PlacementRole::CanonicalPath,
                target_generation: b"opaque",
                parent_directory_identity: &parent_identity,
                capability_snapshot: b"opaque",
                durability_level:
                    yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            },
            0,
            0,
        )
        .unwrap();
        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[
                yadorilink_replica_domain::filesystem_placement::NewReservation {
                    group_id: "g",
                    transaction_id: &tx.transaction_id,
                    scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                    path: "a.txt",
                    role: yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
                },
                yadorilink_replica_domain::filesystem_placement::NewReservation {
                    group_id: "g",
                    transaction_id: &tx.transaction_id,
                    scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                    path: "b.txt",
                    role: yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
                },
            ],
            0,
        )
        .unwrap();

        let report = run(&conn).expect(
            "two sibling epochs both blocking in the same pass must not abort recovery with an \
             illegal-transition error",
        );

        assert_eq!(report.epochs.len(), 2);
        for outcome in &report.epochs {
            assert!(
                matches!(
                    outcome.action,
                    EarlyRecoveryAction::Blocked(BlockReason::ParentDirectoryUnresolvable)
                ),
                "got {:?}",
                outcome.action
            );
        }
        let reloaded_a = filesystem_transaction::lookup_epoch(&conn, &epoch_a.transaction_id, 0)
            .unwrap()
            .unwrap();
        let reloaded_b = filesystem_transaction::lookup_epoch(&conn, &epoch_b.transaction_id, 1)
            .unwrap()
            .unwrap();
        assert_eq!(reloaded_a.phase, EpochState::Blocked);
        assert_eq!(reloaded_b.phase, EpochState::Blocked);
        let reloaded_tx =
            filesystem_transaction::lookup_transaction(&conn, &tx.transaction_id).unwrap().unwrap();
        assert_eq!(reloaded_tx.phase, TransactionPhase::Blocked);
        assert_eq!(
            filesystem_transaction::list_reservations(&conn, &tx.transaction_id).unwrap().len(),
            2,
            "neither reservation has anything confirmed resolved about it -- both must stay held"
        );
    }

    // --- Regression: withholding must survive every pass, not only the
    //     first one that produces the block -------------------------------

    /// The concrete break defect 1 named: `recover_epoch` deliberately
    /// short-circuits an already-`Blocked` epoch straight to `NoAction`
    /// (see that function's own doc on the settled-`Blocked` case) without
    /// re-deriving a `BlockReason`, so on a *second* cold start `run`'s
    /// withholding decision used to see only `NoAction` from every epoch of
    /// this transaction and release its reservation -- even though nothing
    /// physically resolved the open question a `BlockReason` represents in
    /// between the two starts. This drives one epoch to `Blocked`, runs
    /// once (pinning the ordinary first-pass behavior), then runs a
    /// *second* time against the now-settled row and asserts the
    /// reservation is still held.
    #[test]
    fn a_blocked_epoch_keeps_its_reservation_held_on_a_second_cold_start() {
        let mut conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        // Group-relative, as production stores it -- no `stage_path` ever
        // recorded, so this blocks with `ParentDirectoryUnresolvable`.
        insert_sample_epoch(&conn, &tx.transaction_id, "a.txt", &parent_identity);
        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[yadorilink_replica_domain::filesystem_placement::NewReservation {
                group_id: "g",
                transaction_id: &tx.transaction_id,
                scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                path: "a.txt",
                role:
                    yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
            }],
            0,
        )
        .unwrap();

        let first = run(&conn).unwrap();
        assert!(matches!(
            first.epochs[0].action,
            EarlyRecoveryAction::Blocked(BlockReason::ParentDirectoryUnresolvable)
        ));
        assert_eq!(
            filesystem_transaction::list_reservations(&conn, &tx.transaction_id).unwrap().len(),
            1,
            "the first pass that produces the block must withhold, same as every other Blocked \
             case in this file"
        );

        // Second cold start: the epoch is now settled at `Blocked` --
        // `recover_epoch` reports `NoAction` for it (nothing new to
        // observe), but that must not be read as "nothing left to
        // protect".
        let second = run(&conn).unwrap();
        assert!(matches!(second.epochs[0].action, EarlyRecoveryAction::NoAction));
        assert_eq!(
            filesystem_transaction::list_reservations(&conn, &tx.transaction_id).unwrap().len(),
            1,
            "a Blocked epoch's reservation must stay held on every pass, not only the one that \
             first produced the block -- nothing physically resolved the open BlockReason \
             question in between"
        );
    }

    /// The complement of the test above, and a leak regression in its own
    /// right. Withholding used to key on the bare `EpochState::Blocked`
    /// phase, which is terminal -- so once ANY epoch of a transaction was
    /// `Blocked`, every later pass withheld for the rest of that
    /// transaction's life. That predicate matched two writers with nothing
    /// physically unresolved: `orchestrator::block_unpreparable_epoch`, and
    /// `resolution_planning::replan_unchecked`'s sweep of pre-commit
    /// leftovers. So an ordinary SUCCESSFUL replan minted permanently
    /// withholding epochs: prepare failure -> parent `Blocked` -> replan
    /// (leaving `Blocked` rows) -> new slice acquires reservations -> crash
    /// before the release, and from then on every boot saw the stale rows,
    /// withheld, and nothing ever reclaimed the crashed slice's
    /// reservations.
    ///
    /// This drives exactly that sequence and requires the release.
    #[test]
    fn a_replan_swept_blocked_epoch_does_not_withhold_reservations_forever() {
        let mut conn = open_db();
        let dir = tempfile::tempdir().unwrap();
        let parent_identity = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let tx = begin_sample_transaction(&conn);
        insert_sample_epoch(&conn, &tx.transaction_id, "a.txt", &parent_identity);

        // A prepare failure blocks the parent, and the driver replans. The
        // replan sweeps the leftover `Allocated` epoch to `Blocked` -- a
        // settled bookkeeping outcome, with nothing physical outstanding.
        filesystem_transaction::set_transaction_phase_unchecked(
            &conn,
            &tx.transaction_id,
            0,
            TransactionPhase::Blocked,
            Some("simulated prepare failure"),
            1,
        )
        .unwrap();
        resolution_planning::replan_unchecked(&conn, &tx.transaction_id, None, 2).unwrap();
        let swept = list_epochs_for_transaction(&conn, &tx.transaction_id).unwrap();
        assert_eq!(swept[0].phase, EpochState::Blocked);
        assert!(
            swept[0].unresolved_block_reason.is_none(),
            "a replan's sweep has nothing physically unresolved to record, so it must not write \
             the column withholding keys on: {:?}",
            swept[0]
        );

        // The replanned slice acquires its reservations, then the process
        // crashes before releasing them.
        filesystem_transaction::acquire_reservations_unchecked(
            &mut conn,
            &[yadorilink_replica_domain::filesystem_placement::NewReservation {
                group_id: "g",
                transaction_id: &tx.transaction_id,
                scope: yadorilink_replica_domain::filesystem_placement::ReservationScope::Exact,
                path: "a.txt",
                role:
                    yadorilink_replica_domain::filesystem_placement::ReservationRole::CanonicalPath,
            }],
            3,
        )
        .unwrap();

        run(&conn).unwrap();
        assert_eq!(
            filesystem_transaction::list_reservations(&conn, &tx.transaction_id).unwrap().len(),
            0,
            "a stale `Blocked` row left behind by a SUCCESSFUL replan must not withhold: nothing \
             about it is physically unresolved, and nothing else ever reclaims the crashed \
             slice's reservations"
        );
    }
}
