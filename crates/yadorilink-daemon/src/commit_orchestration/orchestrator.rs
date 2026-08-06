//! Filesystem transaction orchestrator: drives one already-built
//! [`PlanSlice`] from epoch allocation through release,
//! and — for every placement that actually displaced something — through
//! custody transfer, classification and captured authoring.
//!
//! # Composition, not new mechanism
//!
//! Every step below is an existing, independently tested primitive from
//! `resolution_planning`, `filesystem_transaction`, `optimistic_placement`,
//! `custody_transfer`, `single_pass_capture`, `captured_authoring` and
//! `retained_obligation`. This module adds no new state machine, no new
//! table and no new reservation or fencing rule — it only calls the
//! existing ones in the order design §8.2 names:
//!
//! ```text
//! 1. allocate one epoch per placement (resolution_planning)
//! 2. prepare every placement's staged artefact (optimistic_placement) --
//!    no canonical-path reservation yet (§6.1)
//! 3. acquire every path in the slice in ONE call (filesystem_transaction) --
//!    see "one acquisition call" below
//! 4. run each placement's short commit window, keeping the slice's
//!    reservations held across every placement (commit_window)
//! 5. release the slice's reservations once, after every placement in it
//!    has been driven through its own commit window
//! 6. for every placement that actually displaced something: custody
//!    transfer, classify, author the capture, record the retained
//!    obligation (custody_transfer, single_pass_capture,
//!    captured_authoring, retained_obligation)
//! ```
//!
//! # One acquisition call per slice (20.35)
//!
//! [`resolution_planning::slice_reservation_requests`]'s own doc proves
//! deadlock freedom is contingent on exactly one
//! [`filesystem_transaction::acquire_reservations`] call per slice — a
//! caller that instead acquired per path or per group would durably commit
//! each before starting the next and reopen ordinary two-resource
//! deadlock. [`run_slice`] calls it exactly once, for the whole slice, and
//! nothing in this module calls `acquire_reservations` anywhere else.
//!
//! # Reservations survive every placement in the slice, not just the first
//!
//! [`commit_window::execute_short_commit_window`]'s `Committed`
//! branch calls `filesystem_transaction::release_reservations_unchecked`,
//! which deletes *every* reservation `transaction_id` holds — not only the
//! one path that just committed. For a slice with more than one path, that
//! is a real seam gap: driving placement 1 through the ordinary
//! [`commit_window::execute_short_commit_window`] would release
//! placement 2's still-unreserved reservation before placement 2's own
//! commit window ever runs, silently reopening the exact race the
//! reservation existed to close, with nothing downstream re-checking that
//! the reservation is still held before placement 2 mutates the
//! filesystem.
//!
//! This module closes that gap with a narrow, additive change to
//! `commit_window.rs`:
//! [`commit_window::execute_short_commit_window_keeping_reservations`],
//! which behaves identically to `execute_short_commit_window` except a
//! `Committed` outcome does not release anything. [`run_slice`] uses this
//! variant for every placement, then calls
//! [`filesystem_transaction::release_reservations`] itself exactly once,
//! after every placement in the slice has been driven through its own
//! commit window (or not at all, if any of them failed — see "nothing
//! partial persists" below). The ordinary
//! [`commit_window::execute_short_commit_window`] is unchanged and
//! still correct for its existing single-call callers.
//!
//! # A sibling's failure must not strand an already-committed write
//!
//! If any placement's commit window refuses ([`OrchestratorError::Commit`])
//! or reports an outcome requiring physical recovery
//! ([`OrchestratorError::RequiresPhysicalRecovery`]), [`run_slice`] stops
//! attempting the remaining placements and, once every placement already
//! committed has been driven through the rest of §8.2 (see below), returns
//! the error. A placement that committed *before* the failure is never left
//! unauthored: [`run_slice_unchecked`] drives every committed placement
//! through custody transfer, classification, captured authoring and its
//! retained obligation — the same sequence a fully successful slice runs —
//! regardless of whether a later sibling in the slice failed. So the state a
//! mid-slice failure leaves behind is: every already-committed placement
//! fully resolved, its epoch at a terminal state (see "every epoch reaches a
//! terminal state" below); the failed placement's own epoch at a
//! recovery-visible state (`Prepared` if the failure was safely retryable,
//! `Blocked` with the parent transaction phase also `Blocked` if it was
//! not, or `RequiresPhysicalRecovery` — see
//! [`commit_window::execute_short_commit_window_core`]'s branches);
//! and any placement never attempted still at whatever the revalidation
//! step above left it. Replanning is what decides whether to redo the
//! remaining ones, not this function guessing; see
//! [`resolution_planning::plan_progress`].
//!
//! The same rule holds for a *post-commit* failure, not only a commit-window
//! one: if placement A and B both commit and A's own custody transfer,
//! classification, authoring or obligation step then errors, B must still be
//! driven through its own sequence — A's failure is no more allowed to
//! strand B than a later sibling's commit refusal is allowed to strand an
//! earlier one. [`run_slice_unchecked`]'s post-commit loop attempts every
//! committed placement unconditionally and only returns the first such
//! error once every one of them has had its turn, rather than exiting on
//! the first.
//!
//! The slice's reservations are released once every placement has been
//! attempted, *except* when the failure was `RequiresPhysicalRecovery` — the
//! one outcome with genuine physical ambiguity left to protect, so it stays
//! held the same way a single [`commit_window::
//! execute_short_commit_window`] failure already leaves it held (see that
//! function's own doc: "left un-released intentionally"). An ordinary
//! commit refusal is a proven no-op (the platform's own exchange primitive
//! is documented atomic), so nothing about the failed placement's own path,
//! or any placement never attempted, needs the reservation held past that
//! point; see [`run_slice_unchecked`]'s own comment on this release for the
//! full reasoning, including why releasing promptly also keeps this
//! composition honest with `filesystem_transaction`'s documented invariant
//! that nothing holds a reservation across a DAG admission while
//! [`filesystem_transaction::EXECUTION_ENABLED`] is closed.
//!
//! # Every epoch reaches a terminal state
//!
//! [`EpochState::is_terminal`] does not include `Committed` — by design,
//! since a captured preimage still owes custody transfer, classification
//! and authoring after its commit lands (§8.1 continues past `Committed`).
//! A caller that stopped at `Committed` would leave every successfully
//! placed epoch non-terminal forever, and the parent transaction can only
//! complete once every one of its epochs is terminal — so a fully
//! successful slice would accumulate transactions that can never complete.
//! [`drive_captured_placement`] closes this: it drives each committed
//! placement's epoch the rest of the way — `CustodyTransferred` ->
//! `AwaitingQuiescence` -> (`ClassifiedKnown` for
//! [`CustodyOutcome::NothingDisplaced`], or `ClassifiedDivergent` ->
//! `AwaitingCaptureStorage` -> `CapturedChangeAuthored` for
//! [`CustodyOutcome::Retained`]) -> `Released` -> `Completed`, matching
//! exactly the states [`resolution_planning::plan_progress`]'s own
//! `epoch_reflects_committed_placement` predicate already treats as "this
//! placement is done" — this module was simply never driving the epoch far
//! enough to reach any of them beyond `Committed` itself.
//!
//! # Nested reservation gap closed (20.46)
//!
//! `filesystem_transaction::bump_transactions_for_touched_paths` used to
//! fence only transactions whose reservation range *contained* a touched
//! path, and missed a transaction reserving a path *nested under* one this
//! slice is about to touch (a change at `a` while another transaction
//! holds `a/b`). That was a property of the containment direction
//! `bump_transactions_for_touched_paths` checked, not of acquisition order
//! within one slice, so this module could not have closed it from here.
//! `filesystem_transaction`'s own lookup now checks both containment
//! directions -- see its module doc above `transactions_holding_touched_paths`
//! -- so a nested reservation is fenced the same way an enclosing one
//! always was; this module needs no change of its own for it.
//!
//! # The prepare loop has a failure protocol too (24.4, 24.5)
//!
//! Preparation used to have no failure discipline at all where the commit
//! loop has a carefully built one: the durable record of a staged
//! artefact's location was written only *after* the artefact was created,
//! together with its identity, in one transition; and the loop `?`-returned
//! on the first [`optimistic_placement::prepare_target`] failure,
//! leaving a mix of `PreparedArtifact`, `Preparing` and untouched
//! `Allocated` epochs behind with no decision recorded anywhere.
//!
//! `stage_path` is now recorded as durable intent *before*
//! `prepare_target` is called, computed from `artefact_id` alone
//! (deterministic -- see [`reserved_namespace::artefact_component_name`],
//! which every non-`NoOp` fast path in that function also derives its own
//! stage name from). `staged_identity` still cannot be known until the
//! object exists, so it is added by a second transition once the call
//! returns. A crash between artefact creation and that second write now
//! still leaves an epoch naming the artefact's `stage_path`, which
//! `early_physical_recovery::recover_epoch`'s `mark_owned` call protects
//! from generic cleanup on every restart from then on -- closing the gap
//! where such an artefact accumulated in the reserved namespace forever,
//! named by no epoch at all.
//!
//! The prepare loop now also settles the epoch that failed explicitly
//! instead of `?`-returning: on the first prepare failure, that epoch and
//! the parent transaction both move to
//! [`yadorilink_replica_domain::filesystem_placement::EpochState::Blocked`] /
//! [`yadorilink_sync_sqlite::filesystem_transaction::TransactionPhase::Blocked`] (see
//! [`block_unpreparable_epoch`] for why `Blocked` is the epoch state
//! machine's only legal destination here, unlike a commit-window failure,
//! which sometimes has a legal retryable retreat), the loop stops
//! attempting the remaining placements, and every epoch already prepared
//! successfully is left exactly at `PreparedArtifact` -- deliberately not
//! deleted, since design §6.1 allows a prepared artifact to be reused if a
//! later plan requests the identical target generation. Every epoch never
//! attempted is left at `Allocated`, which has no physical footprint to
//! protect or clean, mirroring the commit loop's own precedent of leaving
//! never-attempted siblings exactly where allocation put them.
//!
//! Neither `PreparedArtifact` nor `Allocated` is a terminal epoch state
//! (see [`yadorilink_replica_domain::filesystem_placement::EpochState::is_terminal`]), so a
//! stranded sibling of any shape can, by itself, keep the parent
//! transaction from ever completing -- nothing in this module revisits
//! them. That is not a gap left open here: it is
//! `resolution_planning::replan_unchecked`'s job, the moment it moves a
//! `Blocked` parent back to `Planning`, to settle whatever this loop left
//! behind. See that function's own doc, and [`crate::commit_orchestration::plan_driver`]'s module
//! doc for how a driver reaches a `Blocked` transaction at all.
//!
//! # What this orchestrator deliberately does not do
//!
//! - **Does not retry `RequiresPhysicalRecovery`.** The commit window
//!   already transitions the epoch there and leaves its reservations held;
//!   resolving it is `early_physical_recovery`'s job at the next startup
//!   (design §14.1), not this module's. [`run_slice`] only surfaces
//!   [`OrchestratorError::RequiresPhysicalRecovery`] and stops — see "not
//!   a state-table gap: every state this
//!   module can reach already has a legal exit somewhere in the crate, and
//!   this module never invents a second one.
//! - **Does not wait for quiescence before authoring.** Design §8.2 step 13
//!   calls classification/authoring asynchronous, on a schedule this
//!   module has no scheduler for (`work_class_queue` is a downstream
//!   concern, not wired here). [`run_slice`] classifies and authors a
//!   displaced preimage immediately, synchronously, once custody transfer
//!   completes. This is conservative, not incorrect: the hard
//!   content-preservation guarantee (design §1.1) only requires the
//!   preimage eventually be captured, and capturing it immediately can
//!   only ever be earlier than a quiescence-delayed capture would be.
//!   Delaying capture to reduce churn from a rapidly-overwritten retained
//!   object is a real optimization this module leaves for whoever wires a
//!   scheduler in front of it.
//! - **Does not drive an obligation to deletion.** [`yadorilink_sync_sqlite::retained_obligation::
//!   delete_if_eligible`] requires a 24-hour grace window and positive
//!   durability proof — not something one synchronous placement call can
//!   satisfy. [`run_slice`] creates the obligation *before* authoring the
//!   capture (see "obligation before retention root" below) and pairs it
//!   with the authored change via
//!   [`retained_obligation::record_captured_change`], which is as far as a
//!   single synchronous drive can take it. Eventual deletion is the
//!   documented job of a periodic sweep this module does not implement —
//!   see `retained_obligation`'s own module doc, "who calls this, and
//!   when".
//! - **Does not implement late semantic recovery** (design §14.2). A
//!   placement whose custody transfer or authoring fails for a reason other
//!   than authorization loss is surfaced as an error and left exactly where
//!   it is; nothing here silently deletes or silently drops it.
//!
//! # Authorization is re-checked, not trusted, at authoring time
//!
//! `RunSliceRequest::capture_auth` is a [`CaptureAuthorizationSource`], not
//! a bare [`ChangeAuth`](yadorilink_replica_domain::change::ChangeAuth): [`drive_captured_placement`] calls
//! `current_auth` immediately before
//! [`captured_authoring::author_captured_change_unchecked`] runs, not once
//! at slice start. A single `ChangeAuth` value captured before preparation
//! and reused minutes later, after commit, custody transfer and
//! classification, would let writer authority or the policy epoch move in
//! between without this module ever noticing — the change would still
//! enter the local DAG, and every peer with the newer authorization state
//! would reject it. On loss, [`drive_captured_placement`] does not fail the
//! placement: it routes the epoch to `EpochState::
//! AwaitingCaptureAuthorization` (temporary) or `EpochState::
//! LocalRecoveryOnly` (permanent, via
//! [`retained_obligation::mark_authorization_permanently_lost`]) and
//! reports [`CustodyOutcome::AuthorizationLost`] instead — the retained
//! preimage is already safely in custody with an obligation recorded for
//! it, so nothing is lost; only the DAG publication is deferred or
//! (permanently) foregone. This module has no scheduler to retry a
//! temporary loss itself — see "does not wait for quiescence before
//! authoring" above for the same kind of scope boundary.
//!
//! # Obligation before retention root
//!
//! `retained_obligation`'s own module doc ("orphaned `captured_authoring`
//! roots") calls out a specific ordering hazard: `captured_authoring`
//! registers its `full_payload` retention root under `owner_id =
//! retained_id`, and a root with no matching obligation row younger than
//! `ORPHAN_ROOT_GRACE_PERIOD` reads as an orphan to
//! [`retained_obligation::sweep_orphaned_captured_authoring_roots`]. This
//! module always calls [`retained_obligation::create`] *before*
//! [`captured_authoring::author_captured_change`] for the same
//! `retained_id`, so the obligation row exists before the root that names
//! it — the ordering the sweep's own doc says a correct orchestrator must
//! use to avoid a false-orphan race.
//!
//! That still leaves a narrower window this ordering alone does not close:
//! [`custody_transfer::transfer_to_custody`]'s rename happens *before*
//! [`retained_obligation::create`], not after, so a crash between the two
//! leaves a retained artefact on disk with no obligation row at all — not
//! merely a retention root racing its owner, but no owner ever recorded.
//! [`drive_captured_placement`] closes it from the other end: the epoch is
//! transitioned to `EpochState::CustodyTransferred` *before*
//! `retained_obligation::create` runs, so that transition is itself the
//! durable intent a crash in this narrow window leaves behind.
//! `early_physical_recovery` recognises an epoch at `CustodyTransferred` (or
//! later) with a recorded `displaced_identity` and no matching obligation
//! row as exactly this crash shape, and recreates the missing obligation
//! from the epoch row's own already-durable fields — including
//! `displaced_generation_id`, written even earlier, at `Prepared` time (see
//! that transition's own comment) — rather than leaving the retained
//! artefact exposed to generic cleanup. [`retained_obligation::create`] is
//! idempotent on `retained_id`, so this module's own ordinary call to it
//! later in the same run is a safe no-op if recovery already won the race.
//!
//! # The granularity probe runs inline, uncached, on every call (20.30)
//!
//! `custody_transfer::transfer_to_custody` (and, one layer down, the
//! platform commit adapter itself) calls
//! `fs_capabilities::probe_birth_time_granularity` inline, which creates
//! and removes several real files in the parent directory to measure clock
//! resolution — real I/O, not a cached lookup. That function is
//! `pub(crate)` to `fs_capabilities` and is never a parameter either
//! `custody_transfer` or `fs_commit` accepts, so nothing at this module's
//! layer can precompute or inject a cached value without changing those
//! two modules' own signatures, which is out of this task's scope (compose
//! existing primitives, not restructure them). At this orchestrator's call
//! rate — at most one custody transfer per placement, and placements within
//! one slice do not share a call to this probe — the repeated probing is
//! not a hot-path concern for a single slice drive; it becomes one only if
//! a slice routinely displaces many objects in the same directory, at
//! which point caching the probe per directory belongs in
//! `fs_capabilities` itself (a `CapabilityCache`-shaped fix), not in this
//! orchestrator working around another module's internals. Recorded as a
//! non-blocking finding, not fixed here.
//!
//! # Exactly one classification per divergent placement
//!
//! This module used to classify the retained custody file itself -- for the
//! [`yadorilink_filesystem_sync::single_pass_capture::StabilityFingerprint`]
//! `retained_obligation::record_late_write` needs and the `VersionHash`
//! `retained_obligation::record_captured_change` needs -- and then
//! `captured_authoring` classified the same file a second time, internally,
//! to build the change it authored. `single_pass_capture`'s own name
//! describes what one captured object is supposed to get.
//!
//! The consequence was not a duplicated read. `rename` moves a directory
//! entry, not the object underneath it, so a descriptor opened before custody
//! transfer keeps writing to the retained object afterwards -- that is the
//! late-write scenario this whole subsystem is built around -- and a writable
//! memory mapping established before the rename behaves the same way. A write
//! landing between the two classifications produced a durably authored,
//! receipted and retention-rooted change whose real version hash differed
//! from the `VersionHash` this module had captured earlier and later handed
//! to `record_captured_change`. That call correctly refused with
//! [`RetainedObligationError::CapturedChangeVersionMismatch`] rather than
//! minting a false pairing -- but the change was already published, and the
//! obligation was left permanently unpaired, so the retained artefact could
//! never be deleted and its retention root never released. A permanent leak,
//! fail-closed.
//!
//! There is now exactly one classification, and it lives where the
//! classification becomes a version row, an operation, a receipt and a signed
//! change: [`captured_authoring::prepare_captured_change_unchecked`]. It
//! hands back an opaque, move-only [`captured_authoring::
//! PreparedCapturedChange`] that exposes its fingerprint and version hash and
//! nothing else -- no `source_path`, no [`Clone`], no method that reads a
//! file. [`drive_captured_placement`] records the late write from
//! `prepared.fingerprint()`, then consumes the same value in
//! [`captured_authoring::admit_prepared_captured_change_unchecked`] and pairs
//! the obligation with the version that admission reports. Both durable
//! records derive from one owned observation; a second classification is not
//! merely absent here, there is nothing left with which to make one.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::time::Instant;

use rusqlite::Connection;

use yadorilink_filesystem_sync::block_liveness::BlockLivenessGate;
use yadorilink_sync_sqlite::captured_authoring::{
    self, CandidateAuthorizationCoordinate, CapturedAuthoringError, CapturedAuthoringRequest,
    DisplacedBasis, PrepareOutcome,
};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use super::commit_path_locks::{self, SlicePathLocks};
use yadorilink_filesystem_sync::custody_transfer::{self, CustodyTransferError, CustodyTransferOutcome};
use yadorilink_sync_sqlite::dag_store::{self, ChangeEmitter};
use crate::sync_error::SyncError;
use yadorilink_replica_domain::filesystem_placement::EpochState;
use yadorilink_sync_sqlite::filesystem_transaction::{self, EpochRecord, EpochUpdate, TransactionPhase};
use yadorilink_root_authority::fs_capabilities::DurabilityLevel;
use yadorilink_filesystem_sync::fs_commit::{CommitRequest, FilesystemCommitAdapter, ParentDirHandle};
use yadorilink_root_authority::fs_identity::DirectoryIdentity;
use yadorilink_sync_sqlite::file_identity_codec::GenerationId;
use yadorilink_sync_sqlite::materialized_generation::{self, MaterializedObjectKind};
use yadorilink_sync_sqlite::commit_window::{self, CommitWindowError, CommitWindowOutcome, CommitWindowRequest};
use yadorilink_filesystem_sync::optimistic_placement::{PrepareError, PrepareRequest};
use yadorilink_replica_engine::optimistic_placement::PlacementInputs;
use yadorilink_root_authority::reserved_namespace::{artefact_component_name, ArtefactKind};
use yadorilink_sync_sqlite::resolution_planning::{self, FilesystemResolutionPlan};
use yadorilink_replica_engine::resolution_planning::{
    desired_frontier_hash, slice_reservation_requests, PathFrontier, PlanSlice,
};
use yadorilink_sync_sqlite::retained_obligation::{
    self, NewObligation, RetainedObligation, RetainedObligationError,
};
use yadorilink_filesystem_sync::single_pass_capture::SinglePassCaptureError;

use yadorilink_local_storage::BlockStore;

/// Everything one placement's physical side needs that this module has no
/// way to derive on its own — an open directory handle, the bare on-disk
/// name to place content at, and the probe results a real caller already
/// has from watching the filesystem and resolving the DAG. One entry per
/// [`yadorilink_replica_engine::resolution_planning::PlannedPlacement::path`] in the slice
/// [`run_slice`] is given.
pub struct PlacementIo<'a> {
    pub parent_dir: &'a ParentDirHandle,
    pub directory_identity: DirectoryIdentity,
    /// The bare filename [`PlacementIo::parent_dir`] should hold the live
    /// object under — not the group-relative sync path
    /// [`yadorilink_replica_engine::resolution_planning::PlannedPlacement::path`] names, which
    /// may contain separators and portable-name encoding this module has
    /// no opinion on (that translation is the caller's, same as opening
    /// `parent_dir` in the first place).
    pub live_name: OsString,
    pub prepare_inputs: PlacementInputs<'a>,
    pub expected_content_hash: Option<[u8; 32]>,
    pub exec_bit: Option<bool>,
    pub object_kind: MaterializedObjectKind,
    pub version: Option<VersionHash>,
    pub causal_basis: Vec<ChangeHash>,
}

/// Whether a loss of authorization to author a captured change, discovered
/// by re-checking immediately before authoring, is expected to resolve on
/// its own. Decides which of `EpochState::AwaitingCaptureAuthorization`
/// (temporary) or `EpochState::LocalRecoveryOnly` (permanent) the epoch
/// routes to — see [`CaptureAuthorizationSource`] and
/// [`CustodyOutcome::AuthorizationLost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationLoss {
    /// The group's authorization context is unavailable right now but is
    /// expected to become available again — the same shape
    /// [`yadorilink_replica_domain::change::PolicyUnavailable`] already describes for a stale
    /// policy snapshot, healed once a valid one is admitted.
    Temporary,
    /// This device's authorization to author for this group is gone for
    /// good (for example, permanently removed from the group's writer
    /// roster), not merely temporarily unavailable.
    Permanent,
}

/// Reports the durable authorization coordinate this device claims to hold
/// for a group, checked immediately before authoring rather than trusted from
/// whenever the slice started. [`RunSliceRequest`] does not carry a bare
/// [`ChangeAuth`](yadorilink_replica_domain::change::ChangeAuth): preparation, commit, custody transfer and classification
/// can together take minutes, and nothing in this module's own primitives
/// re-derives writer authority or the policy epoch after they run — see the
/// module doc's "does not implement... authorization-loss handling"
/// (before this trait existed, that omission meant a change could be
/// authored and admitted into the local DAG under authorization every peer
/// would already reject).
///
/// Implementing this is deliberately left to a caller that actually tracks
/// writer authority and the group's policy epoch (the same kind of source
/// `index.rs`'s local-emission authorization provider already is for
/// ordinary local edits) — out of scope for this module, which only
/// orchestrates other crates' primitives and owns neither concept (see the
/// module doc's "composition, not new mechanism").
///
/// What this returns is a *candidate* coordinate, not a [`ChangeAuth`](yadorilink_replica_domain::change::ChangeAuth) that
/// gets signed as given. An earlier shape of this trait handed back a ready
/// `ChangeAuth`, which meant an implementer that answered with a constant —
/// this module's own test double answered with [`ChangeAuth::PLACEHOLDER`](yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER) —
/// had its answer stamped into a real signed change with nothing but a doc
/// comment standing in the way. Now
/// `captured_authoring`'s own
/// `validate_candidate_authorization` re-validates
/// whatever comes back against the retained history the captured change is
/// about to parent on, and refuses a placeholder outright; see that
/// function's own doc for exactly what that can and cannot prove.
pub trait CaptureAuthorizationSource {
    /// Report the authorization coordinate this device currently holds for
    /// `group_id`, or why one cannot be produced right now. The answer is
    /// re-validated against the database before it is signed.
    fn current_auth(
        &self,
        group_id: &str,
    ) -> Result<CandidateAuthorizationCoordinate, AuthorizationLoss>;
}

/// Re-reads the live DAG heads for exactly the plan's own path scope, at the
/// commit boundary — design §6.2 step 3's "revalidate ... DAG frontier",
/// which has to happen *after* the slice's reservations exist and *before*
/// the first epoch leaves `PreparedArtifact`.
///
/// # Why this is a capability and not a call
///
/// The walk that produces a path's live heads is the same ancestry walk that
/// builds a plan in the first place, and it needs group/policy context this
/// module has none of — the same reason
/// [`yadorilink_sync_sqlite::resolution_planning::plan_is_stale`] is always *given* a freshly
/// recomputed hash rather than recomputing one itself.
///
/// # Why it cannot be satisfied by answering "still current"
///
/// It returns *evidence*, never a verdict. There is no `-> bool` here and no
/// hash here: an implementation hands back the per-path head sets it read,
/// and [`run_slice`] does all the judging, against values the implementation
/// does not supply:
///
/// - the returned path set must be exactly the scope that was asked for, so
///   an empty or narrowed answer is [`OrchestratorError::FrontierScopeChanged`]
///   rather than a silent pass (a subset can never differ, which reads as
///   "never stale");
/// - every head named must be a change actually admitted **in this group**
///   ([`dag_store::has_change_or_pruned`]), so an invented frontier is
///   refused rather than believed;
/// - the hash is computed here by the single definition in
///   [`resolution_planning::desired_frontier_hash`], and compared by
///   [`resolution_planning::plan_is_stale`] against the plan revision and
///   frontier hash on the transaction's own **durable row** — not against
///   anything passed into this call.
///
/// What that does *not* close, stated plainly rather than overclaimed: an
/// implementation that replays the plan's own still-admitted heads while the
/// DAG really has moved for one of the plan's paths is indistinguishable
/// from an honest one at this seam, because distinguishing them means doing
/// the ancestry walk this capability exists to delegate. A cheaper proxy was
/// tried and removed rather than shipped: comparing the group's head set
/// before preparation against the one at the boundary is a read this module
/// *can* make on its own, but it is only sound in the direction that is not
/// useful. Refusing when the group head set is unchanged while the source
/// reports movement would have to assume no per-path resolution can change
/// without a group head changing, which retained-history pruning can break —
/// and its failure mode is a hard error on an honest source. A check that is
/// unsound in exactly the case it is meant to catch is worse than the gap it
/// papers over, so the gap is recorded here instead.
///
/// The fence is what stands behind that residual case — every transition
/// after acquisition is fenced, and acquisition is precisely what makes
/// `filesystem_transaction::bump_transactions_for_touched_paths` able to see
/// this transaction at all.
pub trait SliceFrontierSource {
    /// Re-reads the live heads for exactly `paths` (ascending) and returns
    /// one [`PathFrontier`] per path, in any order.
    fn current_frontier(
        &self,
        conn: &Connection,
        paths: &[String],
    ) -> Result<Vec<PathFrontier>, SyncError>;
}

/// The plan this slice belongs to, its path scope, and the capability that
/// re-reads that scope — everything [`run_slice`]'s §6.2 step 3 needs.
///
/// Not `Option`: a caller cannot opt out of the check by leaving a field
/// unset. `plan` and `scope` travel together with `source` for the reason
/// [`crate::commit_orchestration::plan_driver`]'s module doc gives at length — a frontier
/// recomputed over a different scope than the plan captured is not a weaker
/// comparison but a meaningless one.
pub struct SliceRevalidation<'a> {
    pub source: &'a dyn SliceFrontierSource,
    /// The plan being executed, carrying the `frontier_hash`,
    /// `plan_revision` and `execution_generation` it was built against.
    pub plan: &'a FilesystemResolutionPlan,
    /// The plan's own path scope, ascending — every path
    /// [`crate::commit_orchestration::plan_driver::PlanBuild::frontier`] resolved, which is a
    /// superset of the paths this slice places.
    pub scope: &'a [String],
}

/// Everything [`run_slice`] needs beyond the slice itself: the transaction
/// this slice belongs to, shared per-slice inputs (`filesystem_transaction`
/// takes one `capability_snapshot`/`durability_level` per slice, not per
/// placement — see [`yadorilink_sync_sqlite::resolution_planning::allocate_slice_epochs`]),
/// and the collaborators every downstream step needs.
pub struct RunSliceRequest<'a> {
    pub group_id: &'a str,
    pub transaction_id: &'a str,
    /// The transaction's true next-free epoch number — see
    /// [`yadorilink_sync_sqlite::resolution_planning::allocate_slice_epochs`]'s own doc: never
    /// a reuse of an earlier one.
    pub next_epoch: i64,
    pub expected_execution_generation: i64,
    pub slice: &'a PlanSlice,
    pub io: &'a HashMap<String, PlacementIo<'a>>,
    pub capability_snapshot: &'a [u8],
    pub durability_level: DurabilityLevel,
    pub adapter: &'a dyn FilesystemCommitAdapter,
    pub store: &'a dyn BlockStore,
    pub gate: &'a BlockLivenessGate,
    pub emitter: &'a ChangeEmitter,
    /// Re-checked immediately before authoring each placement's captured
    /// change — never the source of a single value trusted for the whole
    /// slice. See [`CaptureAuthorizationSource`].
    pub capture_auth: &'a dyn CaptureAuthorizationSource,
    /// §6.2 step 3, run inside the commit boundary — see
    /// [`SliceRevalidation`] and [`SliceFrontierSource`].
    pub revalidation: SliceRevalidation<'a>,
}

/// What happened to one placement's displaced content, if anything.
#[derive(Debug)]
pub enum CustodyOutcome {
    /// The commit displaced nothing (design: the absent-destination path,
    /// or a target that was already materialized identically).
    NothingDisplaced,
    /// The displaced preimage was moved into retained custody, classified,
    /// authored as a captured change, and its retained obligation now
    /// carries that change's hash and version identity. Eventual deletion
    /// is left to a periodic sweep — see the module doc.
    Retained {
        retained_id: String,
        obligation: Box<RetainedObligation>,
        captured_change_hash: ChangeHash,
    },
    /// The displaced preimage reached retained custody and was classified,
    /// but [`CaptureAuthorizationSource::current_auth`] refused immediately
    /// before authoring — writer authority or the policy epoch moved since
    /// the slice started. The epoch was routed to `EpochState::
    /// AwaitingCaptureAuthorization` (`loss == AuthorizationLoss::
    /// Temporary`) or, via `EpochState::LocalRecoveryOnly`, all the way to
    /// `EpochState::Completed` (`Permanent`) instead of being authored. Not
    /// a placement failure: the retained preimage is safely in custody with
    /// an obligation already recorded for it; nothing here silently drops
    /// or deletes it, and nothing here authors an unauthorized change
    /// either.
    AuthorizationLost { retained_id: String, loss: AuthorizationLoss },
}

/// One placement's full outcome.
#[derive(Debug)]
pub struct PlacementOutcome {
    pub path: String,
    pub epoch: EpochRecord,
    pub commit: CommitWindowOutcome,
    pub custody: CustodyOutcome,
}

#[derive(Debug)]
pub enum OrchestratorError {
    Sync(SyncError),
    /// [`run_slice`] was given a slice naming a path with no matching entry
    /// in `RunSliceRequest::io`. Checked before anything is allocated or
    /// mutated.
    MissingIo {
        path: String,
    },
    /// [`optimistic_placement::prepare_target`] selected
    /// [`optimistic_placement::FastPath::NoOp`] — nothing was staged
    /// because the target generation is already materialized. This
    /// module's commit path always expects a staged artefact; a caller
    /// whose slice can legitimately contain already-satisfied placements
    /// must filter them out before calling (see
    /// [`yadorilink_sync_sqlite::resolution_planning::plan_progress`], which is exactly the
    /// filter that ordinarily prevents this).
    NoOpUnsupported {
        path: String,
    },
    Prepare {
        path: String,
        error: PrepareError,
    },
    Commit {
        path: String,
        error: CommitWindowError,
    },
    /// The commit window reported an outcome requiring physical recovery.
    /// Not retried here — see the module doc's "what this orchestrator
    /// deliberately does not do".
    RequiresPhysicalRecovery {
        path: String,
        epoch: i64,
    },
    Custody {
        path: String,
        error: CustodyTransferError,
    },
    Classify {
        path: String,
        error: SinglePassCaptureError,
    },
    Author {
        path: String,
        error: CapturedAuthoringError,
    },
    Obligation {
        path: String,
        error: RetainedObligationError,
    },
    /// [`SliceFrontierSource::current_frontier`] answered about a different
    /// set of paths than the plan's own scope, so its hash and the plan's
    /// are not comparable. Refused rather than compared: a recomputation
    /// over a subset can never differ (silently never stale) and one over a
    /// superset differs the moment any unrelated path moves (replanning
    /// without end).
    ///
    /// Raised inside the commit boundary, so the whole unit — the slice's
    /// reservations included — rolls back.
    FrontierScopeChanged {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    /// A head named by [`SliceFrontierSource::current_frontier`] is not a
    /// change admitted in this group. The answer is not merely stale, it is
    /// not evidence of anything — see [`SliceFrontierSource`]'s doc on why
    /// this module verifies what it is handed instead of trusting it.
    FrontierNotAdmitted {
        path: String,
        head: ChangeHash,
    },
    /// §6.2 step 3 refused the slice at the commit boundary: the plan this
    /// slice belongs to is no longer the current one, so committing it would
    /// write a superseded winner. Nothing was committed and no reservation
    /// is left held — the whole boundary rolled back.
    ///
    /// The caller's response is to replan and rebuild, exactly as for the
    /// execution-generation fence firing (see
    /// [`crate::commit_orchestration::plan_driver::drive_plan`]), not to treat this as a fault.
    PlanSuperseded {
        reason: String,
    },
    /// Wraps another `run_slice`/`run_slice_unchecked` error together with
    /// the [`PlacementOutcome`]s of every placement in the same slice that
    /// had already committed — and been driven all the way through custody,
    /// classification, authoring and its own epoch's terminal transition —
    /// by the time the error occurred (21.9).
    ///
    /// `run_slice_unchecked`'s `Ok` return is `Vec<PlacementOutcome>`, and
    /// [`crate::commit_orchestration::plan_driver::DriveOutcome::placements`] is the only channel
    /// a caller has for what actually landed. Before this variant existed,
    /// a `run_slice` that committed placement A, then failed on sibling B
    /// (a fenced generation, a refused commit window, or a post-commit
    /// custody/authoring failure for A itself does not apply here — that
    /// one still can't strand A, see `run_slice_unchecked`'s own comments)
    /// returned only the error and silently dropped A's already-real,
    /// already-durable outcome. A caller that replans and retries (as
    /// `plan_driver` does for a fenced or superseded sibling) would never
    /// learn A ran at all.
    ///
    /// Only reachable from failures that occur strictly after at least one
    /// placement in the slice has committed: a `MissingIo`, `Prepare`,
    /// `NoOpUnsupported`, or the commit boundary's own `PlanSuperseded`/
    /// `FrontierScopeChanged`/`FrontierNotAdmitted` all occur before any
    /// commit in the slice, so wrapping them here would have nothing to
    /// attach and they are returned bare, exactly as before.
    Partial {
        error: Box<OrchestratorError>,
        placements: Vec<PlacementOutcome>,
    },
}

impl From<SyncError> for OrchestratorError {
    fn from(e: SyncError) -> Self {
        OrchestratorError::Sync(e)
    }
}

/// `filesystem_transaction` (Phase 7D-7.2, `yadorilink-sync-sqlite`) returns
/// its own `SyncSqliteError`, not this crate's `SyncError` -- this crate's
/// `?`-based call sites into it convert through the existing
/// `SyncSqliteError` -> `SyncError` bridge (`error.rs`) rather than
/// duplicating it here.
impl From<yadorilink_sync_sqlite::SyncSqliteError> for OrchestratorError {
    fn from(e: yadorilink_sync_sqlite::SyncSqliteError) -> Self {
        OrchestratorError::Sync(SyncError::from(e))
    }
}

/// `resolution_planning::desired_frontier_hash` (7D-9D move to
/// `yadorilink-replica-engine`) returns `ReplicaEngineError`, not this
/// crate's `SyncError` -- bridges through the existing
/// `ReplicaEngineError` -> `SyncError` conversion (`error.rs`) rather than
/// duplicating it here, mirroring `SyncSqliteError`'s identical bridge
/// above.
impl From<yadorilink_replica_engine::error::ReplicaEngineError> for OrchestratorError {
    fn from(e: yadorilink_replica_engine::error::ReplicaEngineError) -> Self {
        OrchestratorError::Sync(SyncError::from(e))
    }
}

fn artefact_id_for(transaction_id: &str, epoch: i64) -> String {
    format!("{transaction_id}-ep{epoch}")
}

#[cfg(test)]
thread_local! {
    /// Test-only seam: when set, [`run_slice_unchecked`]'s prepare loop
    /// returns immediately after `prepare_target` creates a
    /// placement's stage artefact, before the second (`PreparedArtifact`/
    /// `staged_identity`) transition runs -- simulating a process crash
    /// landing exactly in that window, the shape 24.5 closes. A plain
    /// on/off switch, not a general hook: no other test in this module
    /// needs to run arbitrary code mid-flight, only to stop before a
    /// specific write.
    static SIMULATE_CRASH_AFTER_ARTEFACT_CREATION_FOR_TEST: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn set_simulate_crash_after_artefact_creation_for_test(on: bool) {
    SIMULATE_CRASH_AFTER_ARTEFACT_CREATION_FOR_TEST.with(|c| c.set(on));
}

/// Settles one epoch that failed to prepare: the only legal forward edge
/// from any of the prepare-time states (`Preparing`, `PreparedArtifact`,
/// `AwaitingReservation`) is the generic "any non-terminal state may move to
/// `Blocked`" rule (see [`EpochState::can_transition_to`]) -- there is no
/// legal retry edge back to `Allocated`, and `RequiresPhysicalRecovery` is
/// reachable only from `Committing`, never from a prepare-time state. So
/// unlike a commit-window failure (which can legally retreat to `Prepared`
/// when the platform's own outcome proves the attempt was a no-op), a failed
/// prepare has no retryable destination at all: `Blocked` is not a judgement
/// call, it is the epoch state machine's only option.
///
/// The parent transaction phase moves to [`TransactionPhase::Blocked`] too,
/// for the same reason [`commit_window::execute_short_commit_window_core`]'s
/// own non-retryable `NotStarted` branch already moves it there: a failed
/// prepare's own epoch has no legal path back to `Prepared`/`Committing`, so
/// leaving the parent's phase untouched would give a caller no signal that
/// this slice can never complete as planned and needs replanning. Both
/// transitions are made in one SQL transaction, the same atomicity that
/// commit-window branch already uses, so a crash between them can never
/// leave the epoch `Blocked` under a parent that still looks like nothing
/// happened, or vice versa.
///
/// Uses [`filesystem_transaction::with_immediate_transaction`], not a plain
/// `conn.transaction()` (which opens `DEFERRED`). Both transitions above read
/// their row (`check_execution_generation`, then the row itself) before
/// writing it -- exactly the read-then-write shape `with_immediate_
/// transaction`'s own doc says must not be `DEFERRED`: on a contended
/// database the first write can fail `SQLITE_BUSY_SNAPSHOT` against a
/// snapshot that was already stale when it was taken, and `busy_timeout`
/// retries the same statement against that same stale snapshot forever.
/// Nothing here is a correctness bug either way -- both writes bind their own
/// predicates -- only a spurious hard failure under contention that opening
/// the transaction `IMMEDIATE` avoids by taking the write lock up front.
fn block_unpreparable_epoch(
    conn: &mut Connection,
    request: &RunSliceRequest,
    epoch: i64,
    reason: &str,
    now_unix_nanos: i64,
) -> Result<(), SyncError> {
    filesystem_transaction::with_immediate_transaction(conn, |tx| {
        filesystem_transaction::transition_epoch_unchecked(
            tx,
            request.transaction_id,
            epoch,
            request.expected_execution_generation,
            EpochState::Blocked,
            &EpochUpdate::default(),
            now_unix_nanos,
        )?;
        filesystem_transaction::set_transaction_phase_unchecked(
            tx,
            request.transaction_id,
            request.expected_execution_generation,
            TransactionPhase::Blocked,
            Some(reason),
            now_unix_nanos,
        )?;
        Ok(())
    })
}

/// Drives every placement in `request.slice` from allocation through
/// release, then through custody transfer / classification / authoring for
/// whatever each placement actually displaced. See the module doc for the
/// full contract and the constraints this composition satisfies. Gated
/// behind [`filesystem_transaction::EXECUTION_ENABLED`], the same gate
/// every module this composes already uses — see
/// [`run_slice_unchecked`] for the ungated core this delegates to.
pub fn run_slice(
    conn: &mut Connection,
    request: &RunSliceRequest,
    now_unix_nanos: i64,
) -> Result<Vec<PlacementOutcome>, OrchestratorError> {
    filesystem_transaction::require_execution_enabled()?;
    run_slice_unchecked(conn, request, now_unix_nanos)
}

/// The ungated core of [`run_slice`]. Every module this function composes
/// is itself gated behind [`filesystem_transaction::EXECUTION_ENABLED`], so
/// this core calls each one's own `_unchecked` seam directly rather than
/// its gated public entry point — calling the gated entry points here
/// would re-check the same crate-wide constant on every single composed
/// step (harmless but redundant once [`run_slice`] has already checked it
/// once), and, while the gate stays closed for this phase, would make it
/// impossible for this module's own tests to exercise the real
/// composition at all. Exercised directly by this module's own tests,
/// matching the `_unchecked` convention every other module in this crate
/// already follows.
pub(crate) fn run_slice_unchecked(
    conn: &mut Connection,
    request: &RunSliceRequest,
    now_unix_nanos: i64,
) -> Result<Vec<PlacementOutcome>, OrchestratorError> {
    // Fail before touching the database at all if the caller's `io` map is
    // incomplete -- a half-allocated slice is exactly the "state you cannot
    // leave" this module must not create.
    for placement in request.slice.placements() {
        if !request.io.contains_key(&placement.path) {
            return Err(OrchestratorError::MissingIo { path: placement.path.clone() });
        }
    }

    // §8.2 step 0: one epoch per placement.
    let epochs = yadorilink_sync_sqlite::resolution_planning::allocate_slice_epochs_unchecked(
        conn,
        request.transaction_id,
        request.slice,
        request.next_epoch,
        request.expected_execution_generation,
        |placement| request.io[&placement.path].directory_identity,
        request.capability_snapshot,
        request.durability_level,
        now_unix_nanos,
    )?;

    let artefact_ids: HashMap<String, String> = epochs
        .iter()
        .map(|e| (e.target_path.clone(), artefact_id_for(&e.transaction_id, e.epoch)))
        .collect();

    // §6.1/§8.2 steps 1-5: prepare every placement's staged artefact before
    // any canonical-path reservation is taken. Also captures, per path, the
    // materialized generation this placement is about to displace -- read
    // now, before the commit that will overwrite it, so `DisplacedBasis::
    // Generation` has something to author against later.
    struct PreparedPlacement {
        epoch: EpochRecord,
        stage_name: OsString,
        staged_identity: yadorilink_root_authority::fs_identity::FileIdentity,
        displaced_causal_basis_id: Option<String>,
    }
    let mut prepared: Vec<PreparedPlacement> = Vec::with_capacity(epochs.len());
    // 24.4: mirrors the commit loop's own `commit_failure` a few dozen lines
    // below -- collected rather than `?`-returned, so the first prepare
    // failure in the slice does not strand the rest of this loop's
    // decision-making. Only the epoch that actually failed is settled here
    // (to `Blocked`, via `block_unpreparable_epoch`, along with the parent
    // transaction). Every sibling already prepared successfully is left
    // exactly at `PreparedArtifact` -- deliberately not force-settled,
    // since design §6.1 allows a prepared artifact to be reused if a later
    // plan requests the identical target generation. Every epoch not yet
    // visited is left at `Allocated`, exactly as `allocate_slice_epochs_
    // unchecked` left it -- no physical footprint exists for an `Allocated`
    // epoch, so there is nothing there for a later recovery pass to protect
    // or clean. Neither `PreparedArtifact` nor `Allocated` is a terminal
    // epoch state, so neither stranded sibling can let the parent
    // transaction complete on its own; `resolution_planning::replan_
    // unchecked` closes that when it moves the parent back out of `Blocked`
    // -- see its own doc for why settling them there, not here, is the
    // right place. This function does not guess whether a sibling will be
    // redone; that is `resolution_planning::plan_progress`'s job once a
    // replan has happened.
    let mut prepare_failure: Option<OrchestratorError> = None;

    for epoch in epochs {
        let io = &request.io[&epoch.target_path];
        let artefact_id = &artefact_ids[&epoch.target_path];

        // 24.5: the deterministic stage name every non-`NoOp` fast path in
        // `optimistic_placement::prepare_target` derives from
        // `artefact_id` alone (see that module's `clone_whole_file`/
        // `range_clone_whole_file`/`hardlink_immutable_source`, all of which
        // call `reserved_namespace::artefact_component_name`/
        // `ParentDirHandle::create_artefact` with nothing else) -- computed
        // and recorded *before* `prepare_target` ever touches the
        // filesystem, as durable intent. Previously the only durable record
        // of `stage_path` was written in the same transition as
        // `staged_identity`, together, *after* the artefact was already
        // created: a crash between creation and that single write left an
        // artefact on disk that no epoch named at all.
        // `early_physical_recovery::cleanup_unstarted_artefact` no-ops on a
        // `None` `stage_path` and, by deliberate design, never infers
        // ownership from a bare reserved-namespace name -- so that artefact
        // was invisible to every later recovery pass, forever. Splitting the
        // write closes that: `stage_path` is now durable *before* the
        // filesystem call that might crash, so even a crash that lands
        // exactly there still leaves an epoch naming the artefact's
        // location, which `early_physical_recovery::recover_epoch`'s
        // `mark_owned` call protects from generic cleanup on every restart
        // from then on (see `block_unpreparable_epoch`'s own doc for what
        // happens next when the prepare call itself then fails).
        // `staged_identity` cannot be known this early -- it is only
        // observed once the object actually exists -- so it stays unset
        // here and is added by the second transition below, once
        // `prepare_target` returns it.
        let stage_name = artefact_component_name(ArtefactKind::Stage, artefact_id)
            .map_err(|e| OrchestratorError::Sync(SyncError::InvalidInput(e.to_string())))?;
        // `EpochUpdate.stage_path` binds against the commit window's own
        // `commit.parent_dir.path().join(commit.stage_name)` (see
        // `require_commit_matches_epoch`), so it must be recorded as that
        // same full joined path, not the bare artefact name.
        let stage_path = io.parent_dir.path().join(&stage_name);

        let epoch = filesystem_transaction::transition_epoch_unchecked(
            conn,
            request.transaction_id,
            epoch.epoch,
            request.expected_execution_generation,
            EpochState::Preparing,
            &EpochUpdate { stage_path: Some(&stage_path.to_string_lossy()), ..Default::default() },
            now_unix_nanos,
        )?;

        let prepare_request = PrepareRequest {
            parent_dir: io.parent_dir,
            artefact_id,
            inputs: io.prepare_inputs,
            expected_content_hash: io.expected_content_hash,
            exec_bit: io.exec_bit,
        };
        let prepare_result = yadorilink_filesystem_sync::optimistic_placement::prepare_target(&prepare_request);

        let artefact = match prepare_result {
            Ok(artefact) => artefact,
            Err(error) => {
                // See `block_unpreparable_epoch`'s own doc for why `Blocked`
                // is the epoch state machine's only legal destination here,
                // not a choice among several. What *does* vary by failure
                // kind is what `Blocked` is actually protecting:
                //  - A failure before any bytes were ever staged (`Io`,
                //    `CreateArtefact`, `ArtefactName`, or the missing-clone-
                //    source case folded into `Sync`) leaves nothing real on
                //    disk at `stage_path` -- `Blocked` here is a formality,
                //    not a leak being guarded.
                //  - `PrepareError::ContentVerificationFailed` is reached
                //    only *after* the artefact was actually created and its
                //    bytes read back (see
                //    `optimistic_placement::finish_staged_file`) -- a real
                //    object sits at the `stage_path` already recorded above,
                //    but the failing call never returns a
                //    `verified_identity` for it, so this module has no
                //    identity to record either. `Blocked` still protects it:
                //    `mark_owned` marks a `Blocked` epoch's `stage_path`
                //    owned unconditionally, regardless of whether
                //    `staged_identity` is set, so the artefact is not
                //    deleted (identity is unprovable -- the same fail-closed
                //    rule `cleanup_unstarted_artefact` already applies to
                //    every other prepare-time state) but it is no longer an
                //    invisible, unprotected orphan either. Resolving it the
                //    rest of the way is design §14.4's "retain all
                //    artefacts and block" branch -- late semantic recovery
                //    or a human, not this module.
                block_unpreparable_epoch(
                    conn,
                    request,
                    epoch.epoch,
                    &format!("prepare failed for {:?}: {error}", epoch.target_path),
                    now_unix_nanos,
                )?;
                prepare_failure =
                    Some(OrchestratorError::Prepare { path: epoch.target_path.clone(), error });
                break;
            }
        };

        #[cfg(test)]
        if SIMULATE_CRASH_AFTER_ARTEFACT_CREATION_FOR_TEST.with(|c| c.get()) {
            return Err(OrchestratorError::Sync(SyncError::NotImplemented(
                "test: simulated crash after artefact creation, before the durable identity write",
            )));
        }

        let (Some(returned_stage_name), Some(staged_identity)) =
            (artefact.stage_artefact_name.clone(), artefact.verified_identity)
        else {
            // `FastPath::NoOp`: nothing was staged, and (per `select_fast_
            // path`) nothing on disk was ever touched for this placement --
            // the same "nothing real to protect" shape as the pre-creation
            // failures above. No legal retry edge exists for this epoch
            // either, so it is routed identically.
            block_unpreparable_epoch(
                conn,
                request,
                epoch.epoch,
                &format!(
                    "prepare selected an unsupported no-op fast path for {:?}",
                    epoch.target_path
                ),
                now_unix_nanos,
            )?;
            prepare_failure =
                Some(OrchestratorError::NoOpUnsupported { path: epoch.target_path.clone() });
            break;
        };
        debug_assert_eq!(
            returned_stage_name, stage_name,
            "prepare_target's stage artefact name must match the deterministic name \
             this module already recorded durably for {:?} before calling it",
            epoch.target_path
        );

        let epoch = filesystem_transaction::transition_epoch_unchecked(
            conn,
            request.transaction_id,
            epoch.epoch,
            request.expected_execution_generation,
            EpochState::PreparedArtifact,
            &EpochUpdate { staged_identity: Some(&staged_identity), ..Default::default() },
            now_unix_nanos,
        )?;

        let displaced_causal_basis_id = materialized_generation::lookup_materialized_generation(
            conn,
            request.group_id,
            &epoch.target_path,
        )?
        .map(|g| g.causal_basis_id.0);

        prepared.push(PreparedPlacement {
            epoch,
            stage_name: OsString::from(returned_stage_name),
            staged_identity,
            displaced_causal_basis_id,
        });
    }

    // A prepare failure means the slice can never reach its "every path
    // acquired in one call" invariant -- not every placement even has a
    // staged artefact to commit. Nothing is released here: no reservation
    // was ever requested (that only happens below, once every epoch has
    // prepared successfully), so there is nothing to release. Whatever did
    // prepare successfully is left exactly at `PreparedArtifact` -- design
    // §6.1 says a prepared artifact may be reused if a later plan requests
    // the identical target generation, so deleting it here on a sibling's
    // failure would be actively wrong, not merely unneeded work; a replan
    // that asks for the same target again gets to reuse it instead of
    // re-staging.
    if let Some(error) = prepare_failure {
        return Err(error);
    }

    // =================================================================
    // §6.2 steps 1-4: the commit boundary. ONE transaction, all of it or
    // none of it.
    // =================================================================
    //
    // Everything from "reserve every path" to "every epoch has recorded
    // `Prepared`" is a single `BEGIN IMMEDIATE`. Before this, acquisition
    // committed on its own and the epoch transitions followed it as separate
    // autocommit statements, which left two gaps that could not be closed
    // separately -- hence one task, not two:
    //
    //  - there was no boundary to revalidate *at*. The frontier check sat in
    //    `plan_driver` before `run_slice`, covering §6.1 preparation and the
    //    commit window together. Preparation may take minutes (§6.1), and
    //    the fence does not reach it either: `filesystem_transaction::
    //    bump_transactions_for_touched_paths` matches only transactions
    //    already **holding a reservation** on a touched path, and §6.1
    //    deliberately holds none. So the window between the driver's check
    //    and acquisition was covered by neither signal, while everything
    //    after acquisition IS covered by the fence. Checking here -- after
    //    the reservations exist, before the first epoch leaves
    //    `PreparedArtifact` -- is what makes the two signals meet with no
    //    gap between them;
    //  - a failure mid-way through the transitions left the slice holding
    //    every reservation and some, but not all, of its epochs advanced.
    //
    // The transitions keep their own per-epoch CAS predicates
    // (`expected_execution_generation` plus the source phase, bound into
    // each `UPDATE` by `transition_epoch_unchecked`) rather than being
    // replaced by one unconditional batch update: the enclosing transaction
    // makes them atomic *with each other*, it does not make any one of them
    // safe against a sibling that raced to the same source phase, which is
    // what those predicates are for.
    let reservation_requests = slice_reservation_requests(
        request.group_id,
        request.transaction_id,
        request.slice,
    );
    let slice_paths: Vec<String> = prepared.iter().map(|p| p.epoch.target_path.clone()).collect();

    #[allow(clippy::type_complexity)]
    let (path_locks, prepared): (SlicePathLocks, Vec<PreparedPlacement>) =
        filesystem_transaction::with_immediate_transaction(&*conn, |tx| {
            // Step 1: every path in the slice, in exactly ONE call.
            filesystem_transaction::acquire_reservations_in_open_transaction(
                tx,
                &reservation_requests,
                now_unix_nanos,
            )?;

            // Step 2: the in-memory locks, in the same canonical order the
            // reservations were just taken in -- see `commit_path_locks`.
            // Taken after the reservations, not before, so the durable
            // exclusion is what decides who may proceed and this is the
            // same-process half on top of it.
            let path_locks = commit_path_locks::lock_slice_paths(request.group_id, &slice_paths)?;

            // Step 3.
            revalidate_at_commit_boundary(tx, request)?;

            // Step 4, for every epoch in the slice. A CAS failure on the
            // third epoch rolls back the first two -- and the reservations,
            // and nothing is left holding a path.
            let mut ready = Vec::with_capacity(prepared.len());
            for p in prepared {
                let epoch = filesystem_transaction::transition_epoch_unchecked(
                    tx,
                    request.transaction_id,
                    p.epoch.epoch,
                    request.expected_execution_generation,
                    EpochState::AwaitingReservation,
                    &EpochUpdate::default(),
                    now_unix_nanos,
                )?;
                // Durable intent, written well before the commit that will
                // overwrite `materialized_generation`'s own row for this
                // path, and well before custody transfer or obligation
                // creation even start: once this transition commits, the
                // exact causal basis a captured change for whatever this
                // epoch displaces must author against is on the epoch row
                // itself, not only in this call's stack. That is what lets
                // `early_physical_recovery` reconstruct a missing obligation
                // for a retained artefact that survived a crash between
                // custody transfer and `retained_obligation::create` -- see
                // that module's handling of `EpochState::CustodyTransferred`
                // and the module doc's "obligation before retention root"
                // section.
                let displaced_generation_id =
                    p.displaced_causal_basis_id.as_ref().map(|id| GenerationId(id.clone()));
                let epoch = filesystem_transaction::transition_epoch_unchecked(
                    tx,
                    request.transaction_id,
                    epoch.epoch,
                    request.expected_execution_generation,
                    EpochState::Prepared,
                    &EpochUpdate {
                        staged_identity: Some(&p.staged_identity),
                        displaced_generation_id: displaced_generation_id.as_ref(),
                        ..Default::default()
                    },
                    now_unix_nanos,
                )?;
                ready.push(PreparedPlacement { epoch, ..p });
            }
            Ok::<_, OrchestratorError>((path_locks, ready))
        })?;

    // §8.2 steps 6-12, per placement: run the short commit window -- using
    // the reservation-keeping variant so an earlier placement's own
    // `Committed` outcome cannot delete a sibling placement's still-unused
    // reservation (see the module doc's "reservations survive every
    // placement" section).
    let mut committed: Vec<(String, EpochRecord, CommitWindowOutcome, Option<String>)> =
        Vec::with_capacity(prepared.len());
    // Set the moment a placement's commit window refuses or reports an
    // outcome requiring physical recovery -- the loop below stops
    // attempting the remaining placements, but every placement already in
    // `committed` still gets driven through its own custody/classify/
    // author/obligation sequence and epoch progression before this
    // function returns the error. See the module doc's "a sibling's
    // failure must not strand an already-committed write" section: A
    // committing before B fails must never leave A's displaced object
    // unauthored just because B never got a chance to run.
    let mut commit_failure: Option<OrchestratorError> = None;

    for p in prepared {
        let io = &request.io[&p.epoch.target_path];
        let artefact_id = &artefact_ids[&p.epoch.target_path];
        let epoch = p.epoch;

        let backup_name = artefact_component_name(ArtefactKind::Backup, artefact_id)
            .map_err(|e| OrchestratorError::Sync(SyncError::InvalidInput(e.to_string())))?;
        let commit = CommitRequest {
            parent_dir: io.parent_dir,
            stage_name: p.stage_name.as_os_str(),
            live_name: io.live_name.as_os_str(),
            backup_name: OsStr::new(&backup_name),
            capabilities: io.prepare_inputs.capabilities,
            sync_root_identity: &io.directory_identity,
            expected_stage_identity: &p.staged_identity,
        };
        let commit_window_request = CommitWindowRequest {
            transaction_id: request.transaction_id,
            epoch: epoch.epoch,
            expected_execution_generation: request.expected_execution_generation,
            group_id: request.group_id,
            path: &epoch.target_path,
            causal_basis: &io.causal_basis,
            object_kind: io.object_kind,
            version: io.version.as_ref(),
            commit,
            reservation_held_since: Instant::now(),
        };

        match commit_window::execute_short_commit_window_unchecked_keeping_reservations(
            conn,
            request.adapter,
            &commit_window_request,
            now_unix_nanos,
        ) {
            Ok(outcome) => {
                committed.push((
                    epoch.target_path.clone(),
                    outcome.epoch.clone(),
                    outcome,
                    p.displaced_causal_basis_id,
                ));
            }
            Err(CommitWindowError::RequiresRecovery(_)) => {
                commit_failure = Some(OrchestratorError::RequiresPhysicalRecovery {
                    path: epoch.target_path.clone(),
                    epoch: epoch.epoch,
                });
                break;
            }
            Err(error) => {
                commit_failure =
                    Some(OrchestratorError::Commit { path: epoch.target_path.clone(), error });
                break;
            }
        }
    }

    // §6.2 step 8 / §8.2 step 12: release the whole slice's reservations
    // exactly once this pass has settled every placement's fate -- attempted
    // through its own commit window, or (for a placement later in the slice
    // than the one that failed) deliberately left untouched by the `break`
    // above -- *unless* the failure was `RequiresPhysicalRecovery`, the one
    // outcome
    // that leaves genuine physical ambiguity behind (see
    // [`commit_window::execute_short_commit_window`]'s own doc:
    // "left un-released intentionally"; resolving it is
    // `early_physical_recovery`'s job at the next startup, design §14.1).
    // Every other shape is safe to release now:
    //
    // - A placement that committed is fully resolved a few lines below
    //   (custody transfer through to a terminal epoch state) and never
    //   needed the reservation past that point in the first place --
    //   design §8.3: "`CustodyTransferred` is the point after which
    //   canonical-path exclusion is no longer required".
    // - An ordinary commit refusal (`CommitWindowError::NotStarted`) is a
    //   proven no-op -- the platform's own exchange primitive is
    //   documented atomic -- so the epoch it leaves behind (`Prepared` if
    //   retryable, `Blocked` with the parent transaction phase also
    //   `Blocked` if not; see `commit_window::execute_short_commit_
    //   window_core`'s `NotStarted` branch, which makes both transitions
    //   itself) names a path nothing actually touched. Holding its
    //   reservation open has no physical ambiguity left to protect.
    // - Any other refusal (`CommitWindowError::Sync`) is likewise
    //   pre-mutation by construction: that variant is only produced before
    //   `commit_placement` is reached, and the window leaves the epoch in a
    //   state saying so. Every failure *after* the mutation -- the
    //   `Committed` transition, the generation write, the release, the SQL
    //   commit -- is converted to `CommitWindowError::RequiresRecovery`
    //   instead (see `commit_window`'s `unjournaled_physical_
    //   outcome`), precisely so this variant-based decision cannot release
    //   a reservation over a path whose physical outcome is unrecorded.
    // - A placement never even attempted (later in the slice than the one
    //   that failed) is, by construction, untouched.
    //
    // Releasing promptly here also keeps this module's own composition
    // honest with `filesystem_transaction`'s documented invariant that
    // nothing holds a reservation across a DAG admission unless the gate
    // (`EXECUTION_ENABLED`) is open (see `bump_transactions_for_touched_
    // paths`'s own doc) -- `drive_captured_placement` below admits exactly
    // such a change for every displaced placement, on this same
    // transaction's own paths.
    let holds_for_physical_recovery =
        matches!(commit_failure, Some(OrchestratorError::RequiresPhysicalRecovery { .. }));
    if !holds_for_physical_recovery {
        filesystem_transaction::release_reservations_unchecked(conn, request.transaction_id)?;
    }
    // §6.2 step 8's other half. The in-memory locks are released here in
    // every case, including `RequiresPhysicalRecovery`: unlike a
    // reservation, an in-memory lock cannot outlive this process anyway, so
    // holding it past this point would protect nothing while blocking the
    // very recovery pass that resolves the ambiguity. The durable half of
    // the exclusion -- the reservation rows -- is what deliberately stays
    // held in that one case.
    drop(path_locks);

    // §8.2 steps 13-17 (driven synchronously here -- see the module doc):
    // custody transfer, classify, author, record the retained obligation,
    // and drive each such placement's own epoch the rest of the way to a
    // terminal state (`EpochState::is_terminal`) so a fully resolved
    // placement never sits at the non-terminal `Committed` forever and
    // blocks the parent transaction from ever completing.
    //
    // Every placement already in `committed` is driven through this
    // regardless of `commit_failure` -- an earlier placement's own
    // custody/classify/author/obligation sequence has no dependency on a
    // later sibling's outcome, so a sibling's failure must never strand it
    // unauthored. See the module doc's "a sibling's failure must not
    // strand an already-committed write" section.
    //
    // The loop below must not `?` out of `drive_captured_placement`'s own
    // result: that would apply the same "must never strand a sibling" rule
    // to `commit_failure` while breaking it for a *post-commit* failure --
    // if placement A's own custody/classify/author/obligation sequence
    // errors, a bare `?` here would exit before B, a later placement that
    // already committed independently of A, ever gets driven, leaving B
    // sitting at the non-terminal `Committed` with its reservation already
    // released above. Every committed placement is attempted here
    // regardless of whether an earlier one in this same loop failed; only
    // the first such failure is kept and returned once every placement has
    // had its turn.
    let mut outcomes = Vec::with_capacity(committed.len());
    let mut post_commit_failure: Option<OrchestratorError> = None;
    for (path, epoch, commit, displaced_causal_basis_id) in committed {
        match drive_captured_placement(
            conn,
            request,
            path,
            epoch,
            commit,
            displaced_causal_basis_id,
            now_unix_nanos,
        ) {
            Ok(outcome) => outcomes.push(outcome),
            Err(error) => {
                if post_commit_failure.is_none() {
                    post_commit_failure = Some(error);
                }
            }
        }
    }

    // 21.9 (D2): whichever failure is returned, wrap it with every
    // `PlacementOutcome` already built for this slice so a caller does not
    // silently lose the record of what already committed and was driven
    // through custody/authoring. `outcomes` is empty in the ordinary case
    // where the very first placement in the slice was the one that failed
    // to commit -- wrapping then would add nothing, so it is skipped.
    if let Some(error) = post_commit_failure {
        return Err(wrap_with_partial_outcomes(error, outcomes));
    }
    if let Some(error) = commit_failure {
        return Err(wrap_with_partial_outcomes(error, outcomes));
    }

    Ok(outcomes)
}

/// Attaches `placements` to `error` as [`OrchestratorError::Partial`],
/// unless `placements` is empty -- in which case there is nothing to
/// attach, and the bare error is more useful than a wrapper around nothing.
fn wrap_with_partial_outcomes(
    error: OrchestratorError,
    placements: Vec<PlacementOutcome>,
) -> OrchestratorError {
    if placements.is_empty() {
        error
    } else {
        OrchestratorError::Partial { error: Box::new(error), placements }
    }
}

/// Design §6.2 step 3, run inside the commit boundary's own transaction with
/// the slice's reservations already held and its path locks already taken.
///
/// # Which of step 3's six inputs this actually revalidates
///
/// Stated exhaustively, because the honest gap is worth more than a claim
/// that outruns the code:
///
///  - **`execution_generation`** — YES, twice over.
///    [`resolution_planning::plan_is_stale`] compares the plan's captured
///    value against the transaction's live fence, and every transition this
///    boundary then makes re-binds it as a CAS predicate on its own `UPDATE`.
///  - **plan revision** — YES, freshly: the transaction's durable
///    `plan_revision` is re-read here and compared against the revision the
///    plan being executed was built at. A concurrent
///    `resolution_planning::replan` bumps it, so a slice built under the
///    superseded revision is refused even in the (impossible in practice,
///    but not excluded by construction) case where the generation matched.
///  - **DAG frontier** — YES, through [`SliceFrontierSource`], plus this
///    module's own before/after read of the group head set. See that trait's
///    doc for exactly how much of it is verifiable from here.
///  - **parent-directory identity** — NO, not freshly re-observed here. The
///    identity the caller probed is carried into every placement's
///    `CommitRequest::sync_root_identity` and verified by the platform
///    commit itself at step 5, a few statements later and inside the same
///    held locks; re-`stat`ing every parent directory here would add a
///    syscall per placement inside the lock window without being able to
///    change any outcome the step-5 check does not already change.
///  - **disk generation** — NO. Nothing in this crate produces a
///    disk-generation value at this seam yet; there is no fresher value to
///    compare against, so there is nothing to check rather than a check
///    being skipped.
///  - **capability snapshot** — NO fresh re-probe. `capability_snapshot` is
///    a caller-supplied byte string recorded on each epoch at allocation
///    time, and this layer has no probe to re-derive it from. What it is
///    not is *unbound*: it is on the epoch rows, so a mismatch is
///    detectable after the fact even though it is not refused here.
fn revalidate_at_commit_boundary(
    conn: &Connection,
    request: &RunSliceRequest,
) -> Result<(), OrchestratorError> {
    let revalidation = &request.revalidation;

    // Plan revision, read from the transaction's own durable row.
    let record = filesystem_transaction::lookup_transaction(conn, request.transaction_id)?
        .ok_or_else(|| {
            SyncError::NotFound(format!("filesystem transaction {}", request.transaction_id))
        })?;
    if record.plan_revision != revalidation.plan.plan_revision {
        return Err(OrchestratorError::PlanSuperseded {
            reason: format!(
                "plan revision moved from {} to {} while this slice was being prepared",
                revalidation.plan.plan_revision, record.plan_revision
            ),
        });
    }

    // The capability's answer -- evidence, judged here.
    let current = revalidation.source.current_frontier(conn, revalidation.scope)?;
    let mut actual: Vec<String> = current.iter().map(|f| f.path.clone()).collect();
    actual.sort();
    if actual != revalidation.scope {
        return Err(OrchestratorError::FrontierScopeChanged {
            expected: revalidation.scope.to_vec(),
            actual,
        });
    }
    for entry in &current {
        for head in &entry.heads {
            if !dag_store::has_change_or_pruned(conn, request.group_id, head)? {
                return Err(OrchestratorError::FrontierNotAdmitted {
                    path: entry.path.clone(),
                    head: *head,
                });
            }
        }
    }

    let current_hash = desired_frontier_hash(&current)?;
    if resolution_planning::plan_is_stale(
        conn,
        request.transaction_id,
        revalidation.plan,
        current_hash,
    )? {
        return Err(OrchestratorError::PlanSuperseded {
            reason: format!(
                "the DAG frontier for transaction {}'s plan moved while this slice was being \
                 prepared",
                request.transaction_id
            ),
        });
    }

    Ok(())
}

/// Drives one already-committed placement through §8.2 steps 13-17 --
/// custody transfer, classification, captured authoring and the retained
/// obligation -- and, in lock-step, its epoch through the matching part of
/// the state machine (§8.1), so a placement whose commit has landed is
/// never left sitting at the non-terminal `Committed` with nothing to show
/// for it. Called once per committed placement from [`run_slice_unchecked`],
/// independently of whether a sibling placement in the same slice failed --
/// see that function's own comments.
///
/// The `CustodyTransferred` transition below runs *before*
/// `retained_obligation::create` for exactly the same reason
/// `displaced_generation_id` is written durably at `Prepared` time, well
/// before either: a crash between custody transfer's rename and the
/// obligation row's own commit must leave a state `early_physical_recovery`
/// can recognise and repair, not a retained artefact silently owned by
/// nothing. See that module's handling of `EpochState::CustodyTransferred`.
fn drive_captured_placement(
    conn: &mut Connection,
    request: &RunSliceRequest,
    path: String,
    epoch: EpochRecord,
    commit: CommitWindowOutcome,
    displaced_causal_basis_id: Option<String>,
    now_unix_nanos: i64,
) -> Result<PlacementOutcome, OrchestratorError> {
    let io = &request.io[&path];
    let artefact_id = artefact_id_for(request.transaction_id, epoch.epoch);
    let epoch_num = epoch.epoch;

    let advance =
        |conn: &mut Connection, to: EpochState| -> Result<EpochRecord, OrchestratorError> {
            filesystem_transaction::transition_epoch_unchecked(
                conn,
                request.transaction_id,
                epoch_num,
                request.expected_execution_generation,
                to,
                &EpochUpdate::default(),
                now_unix_nanos,
            )
            .map_err(OrchestratorError::from)
        };

    let mut current_epoch = epoch;

    // Custody transfer is destructive with respect to the preimage's current
    // reserved name. Prove the durable causal basis before that rename, not
    // afterward. The in-memory value is cross-checked against the epoch row so
    // a stale caller cannot smuggle a basis the journal never recorded.
    let durable_displaced_basis =
        current_epoch.displaced_generation_id.as_ref().map(|id| id.0.clone());
    if durable_displaced_basis != displaced_causal_basis_id {
        return Err(OrchestratorError::Sync(SyncError::CorruptState(format!(
            "placement for {path:?} carried displaced causal basis {:?}, but its durable epoch records {:?}",
            displaced_causal_basis_id, durable_displaced_basis
        ))));
    }
    let displaced_causal_basis_id = match (
        current_epoch.displaced_identity.as_ref(),
        durable_displaced_basis,
    ) {
        (Some(_), Some(basis_id)) => {
            if dag_store::lookup_causal_basis_members(conn, &basis_id)?.is_none() {
                return Err(OrchestratorError::Sync(SyncError::CorruptState(format!(
                    "placement for {path:?} would move a displaced preimage before causal basis {basis_id:?} is durably interned"
                ))));
            }
            Some(basis_id)
        }
        (Some(_), None) => {
            return Err(OrchestratorError::Sync(SyncError::CorruptState(format!(
                "commit for {path:?} displaced an object but no durable prior materialized causal basis exists"
            ))));
        }
        (None, _) => None,
    };

    let custody = match custody_transfer::transfer_to_custody(
        io.parent_dir,
        &artefact_id,
        current_epoch.displaced_identity.as_ref(),
    ) {
        Ok(CustodyTransferOutcome::NothingDisplaced) => {
            // No canonical-path exclusion was ever guarding a displaced
            // object here, but `EpochState::can_transition_to`'s table
            // models no shortcut around the custody-transfer step itself --
            // every placement takes it, trivially in this case.
            advance(conn, EpochState::CustodyTransferred)?;
            advance(conn, EpochState::AwaitingQuiescence)?;
            advance(conn, EpochState::ClassifiedKnown)?;
            advance(conn, EpochState::Released)?;
            current_epoch = advance(conn, EpochState::Completed)?;
            CustodyOutcome::NothingDisplaced
        }
        Ok(CustodyTransferOutcome::Transferred { custody_identity, .. }) => {
            advance(conn, EpochState::CustodyTransferred)?;

            let custody_name = artefact_component_name(ArtefactKind::Retained, &artefact_id)
                .map_err(|e| OrchestratorError::Sync(SyncError::InvalidInput(e.to_string())))?;
            let custody_path = io.parent_dir.path().join(&custody_name);

            let displaced_causal_basis_id = displaced_causal_basis_id
                .expect("a transferred preimage's causal basis was proven before custody rename");
            let custody_identity =
                yadorilink_sync_sqlite::file_identity_codec::encode_file_identity(custody_identity.as_ref());

            let parent_directory_identity =
                filesystem_transaction::encode_directory_identity(&io.directory_identity);
            let retained_id = artefact_id.clone();
            // The obligation must exist before `author_captured_change`
            // registers its retention root (see the module doc's
            // "obligation before retention root"), but nothing here needs
            // the row `create` itself returns -- the row this outcome
            // carries is the one `record_captured_change` returns below,
            // already paired with the authored change. `create` is
            // idempotent on `retained_id`, so a retry that reaches here
            // again after `early_physical_recovery` already recreated this
            // same obligation from the `CustodyTransferred` epoch this call
            // just wrote is a safe no-op, not a conflict.
            retained_obligation::create(
                conn,
                &NewObligation {
                    retained_id: &retained_id,
                    originating_transaction_id: Some(request.transaction_id),
                    source_epoch: Some(epoch_num),
                    group_id: request.group_id,
                    original_path: &path,
                    custody_path: &custody_path.to_string_lossy(),
                    parent_directory_identity: &parent_directory_identity,
                    filesystem_identity: Some(&custody_identity),
                    original_parent_basis_id: &displaced_causal_basis_id,
                },
                now_unix_nanos,
            )
            .map_err(|error| OrchestratorError::Obligation { path: path.clone(), error })?;

            advance(conn, EpochState::AwaitingQuiescence)?;

            // The one and only classification of this retained object, owned
            // by `captured_authoring` because that is where it becomes a
            // version row, an operation, a receipt and a signed change. This
            // module used to run its own separate pass here for the
            // fingerprint and version hash the obligation needs, leaving a
            // window in which a stale descriptor (a `rename` moves a
            // directory entry, not the object a writer already has open) or
            // a writable mapping established before custody transfer could
            // change the bytes between the two passes -- publishing a change
            // built from the second classification while the obligation was
            // pinned to the first, so `record_captured_change` refused the
            // pairing and the retained artefact could never be deleted nor
            // its retention root released. `PreparedCapturedChange` is the
            // single owned classification both records now derive from; it
            // carries no path, so there is nothing here to reclassify with.
            let prepared = match captured_authoring::prepare_captured_change_unchecked(
                conn,
                request.store,
                request.gate,
                CapturedAuthoringRequest {
                    retained_id: &retained_id,
                    group_id: request.group_id,
                    path: &path,
                    source_path: &custody_path,
                    displaced_basis: DisplacedBasis::Generation {
                        causal_basis_id: displaced_causal_basis_id,
                    },
                },
            )
            .map_err(|error| OrchestratorError::Author { path: path.clone(), error })?
            {
                PrepareOutcome::AlreadyAuthored(result) => {
                    // A durable receipt already covers this exact capture and
                    // a fresh classification confirms the content has not
                    // moved. There is nothing to author, but the obligation
                    // still has to be paired -- with the version that change
                    // actually writes, read back from the change itself.
                    advance(conn, EpochState::ClassifiedDivergent)?;
                    retained_obligation::record_late_write(
                        conn,
                        request.group_id,
                        &retained_id,
                        result.content_fingerprint,
                        now_unix_nanos,
                    )
                    .map_err(|error| OrchestratorError::Obligation { path: path.clone(), error })?;
                    advance(conn, EpochState::AwaitingCaptureStorage)?;
                    advance(conn, EpochState::CapturedChangeAuthored)?;
                    let obligation = retained_obligation::record_captured_change(
                        conn,
                        request.group_id,
                        &retained_id,
                        result.change_hash,
                        result.version_hash,
                        now_unix_nanos,
                    )
                    .map_err(|error| OrchestratorError::Obligation { path: path.clone(), error })?;
                    advance(conn, EpochState::Released)?;
                    current_epoch = advance(conn, EpochState::Completed)?;
                    return Ok(PlacementOutcome {
                        path,
                        epoch: current_epoch,
                        commit,
                        custody: CustodyOutcome::Retained {
                            retained_id,
                            obligation: Box::new(obligation),
                            captured_change_hash: result.change_hash,
                        },
                    });
                }
                PrepareOutcome::Prepared(prepared) => prepared,
            };

            advance(conn, EpochState::ClassifiedDivergent)?;

            retained_obligation::record_late_write(
                conn,
                request.group_id,
                &retained_id,
                prepared.fingerprint(),
                now_unix_nanos,
            )
            .map_err(|error| OrchestratorError::Obligation { path: path.clone(), error })?;

            advance(conn, EpochState::AwaitingCaptureStorage)?;

            // Re-derive authorization here, immediately before authoring --
            // never trust whatever `RunSliceRequest::capture_auth` would
            // have answered back when this slice started. Everything above
            // (prepare, commit, custody transfer, classification) can take
            // real wall-clock time; a `ChangeAuth` fixed at slice start
            // would be authoring against writer authority or a policy epoch
            // that may no longer hold. See the module doc's "authorization
            // is re-checked, not trusted, at authoring time".
            let authorization = match request.capture_auth.current_auth(request.group_id) {
                Ok(authorization) => authorization,
                Err(loss) => {
                    return match loss {
                        AuthorizationLoss::Temporary => {
                            // Stays here -- not this module's job to retry;
                            // see the module doc. `CustodyTransferred`
                            // already happened and the obligation already
                            // exists, so the retained preimage is not at
                            // risk while this epoch waits.
                            let current_epoch =
                                advance(conn, EpochState::AwaitingCaptureAuthorization)?;
                            Ok(PlacementOutcome {
                                path,
                                epoch: current_epoch,
                                commit,
                                custody: CustodyOutcome::AuthorizationLost {
                                    retained_id,
                                    loss: AuthorizationLoss::Temporary,
                                },
                            })
                        }
                        AuthorizationLoss::Permanent => {
                            // Terminal, unconditionally, per
                            // `mark_authorization_permanently_lost`'s own
                            // doc -- nothing ever authors this retained_id's
                            // capture on this device from here on. The
                            // saga itself still completes: the retained
                            // preimage stays retained (never automatically
                            // deleted -- design §12), just never published.
                            retained_obligation::mark_authorization_permanently_lost(
                                conn,
                                request.group_id,
                                &retained_id,
                                now_unix_nanos,
                            )
                            .map_err(|error| {
                                OrchestratorError::Obligation { path: path.clone(), error }
                            })?;
                            advance(conn, EpochState::LocalRecoveryOnly)?;
                            advance(conn, EpochState::Released)?;
                            let current_epoch = advance(conn, EpochState::Completed)?;
                            Ok(PlacementOutcome {
                                path,
                                epoch: current_epoch,
                                commit,
                                custody: CustodyOutcome::AuthorizationLost {
                                    retained_id,
                                    loss: AuthorizationLoss::Permanent,
                                },
                            })
                        }
                    };
                }
            };

            // Consumes `prepared` -- the same owned classification whose
            // fingerprint `record_late_write` above was given. The change
            // published here and the obligation record are therefore two
            // uses of one observation, not two observations that have to
            // agree.
            let authored = captured_authoring::admit_prepared_captured_change_unchecked(
                conn,
                request.emitter,
                authorization,
                prepared,
            )
            .map_err(|error| OrchestratorError::Author { path: path.clone(), error })?;

            advance(conn, EpochState::CapturedChangeAuthored)?;

            let obligation = retained_obligation::record_captured_change(
                conn,
                request.group_id,
                &retained_id,
                authored.change_hash,
                authored.version_hash,
                now_unix_nanos,
            )
            .map_err(|error| OrchestratorError::Obligation { path: path.clone(), error })?;

            advance(conn, EpochState::Released)?;
            current_epoch = advance(conn, EpochState::Completed)?;

            CustodyOutcome::Retained {
                retained_id,
                obligation: Box::new(obligation),
                captured_change_hash: authored.change_hash,
            }
        }
        Err(error) => {
            return Err(OrchestratorError::Custody { path: path.clone(), error });
        }
    };

    Ok(PlacementOutcome { path, epoch: current_epoch, commit, custody })
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_replica_domain::change::{ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::ids::{ChangeHash as CH, SyncPath};
    use yadorilink_sync_sqlite::dag_store;
    use yadorilink_root_authority::fs_capabilities::{Capability, FilesystemSafetyCapabilities};
    use yadorilink_filesystem_sync::fs_commit::{
        CommittedSnapshot, FilesystemCommitOutcome, NativeCommitAdapter, RecoverySnapshot,
    };
    use yadorilink_root_authority::fs_identity::{FileIdentity, ObjectKind, PlatformObjectId, VolumeIdentity};
    use yadorilink_sync_sqlite::materialized_generation;
    use yadorilink_replica_engine::optimistic_placement::CloneSource;
    use yadorilink_sync_sqlite::resolution_planning::{self};
    use yadorilink_replica_engine::resolution_planning::{
        slice_plan, PlacementGroup, PlannedPlacement, SliceBounds,
    };
    use ed25519_dalek::SigningKey;
    use std::io;
    use std::path::Path;
    use yadorilink_local_storage::FsBlockStore;

    /// A real (non-placeholder) coordinate the ordinary tests below author
    /// under. It has to be a real one now: `captured_authoring` refuses the
    /// all-zero placeholder outright, precisely so that a source cannot
    /// answer with a constant that opts out of every authorization check.
    /// It sits above the `ChangeAuth::PLACEHOLDER` its seeded parents carry,
    /// so the monotonicity re-check passes.
    const TEST_COORDINATE: CandidateAuthorizationCoordinate = CandidateAuthorizationCoordinate {
        auth_seq: 4,
        auth_epoch: 2,
        policy_head_hash: [9u8; 32],
    };

    /// Test double for [`CaptureAuthorizationSource`]: always answers with
    /// [`TEST_COORDINATE`], standing in for a caller that tracks real writer
    /// authority. `authorization_is_re_checked_immediately_before_authoring_
    /// and_routes_on_loss` below supplies a different double that reports
    /// loss instead.
    struct AlwaysAuthorized;
    impl CaptureAuthorizationSource for AlwaysAuthorized {
        fn current_auth(
            &self,
            _group_id: &str,
        ) -> Result<CandidateAuthorizationCoordinate, AuthorizationLoss> {
            Ok(TEST_COORDINATE)
        }
    }

    /// A frontier source for the tests that are not about revalidation: the
    /// plan's scope is empty, so "the frontier for this plan's paths" is the
    /// empty frontier and cannot move. Deliberately not a source that
    /// answers "still current" to whatever it is asked — there is no such
    /// answer to give, because the trait returns evidence rather than a
    /// verdict (see [`SliceFrontierSource`]).
    struct EmptyScopeFrontier;
    impl SliceFrontierSource for EmptyScopeFrontier {
        fn current_frontier(
            &self,
            _conn: &Connection,
            _paths: &[String],
        ) -> Result<Vec<PathFrontier>, SyncError> {
            Ok(Vec::new())
        }
    }

    /// A `SliceRevalidation` over the empty scope, for the transaction state
    /// the caller says it is at. Leaks the plan so the borrow is `'static`;
    /// this is a test helper and the leak is one small struct per call.
    fn empty_scope_revalidation(
        execution_generation: i64,
        plan_revision: i64,
    ) -> SliceRevalidation<'static> {
        let plan = Box::leak(Box::new(FilesystemResolutionPlan {
            plan_revision,
            frontier_hash: desired_frontier_hash(&[]).unwrap(),
            execution_generation,
            groups: Vec::new(),
        }));
        SliceRevalidation { source: &EmptyScopeFrontier, plan, scope: &[] }
    }

    fn open_schema(conn: &Connection) {
        yadorilink_sync_sqlite::dag_store::init_dag_schema(conn).unwrap();
        yadorilink_sync_sqlite::dag_store::init_conflict_copy_provenance_schema(conn).unwrap();
        materialized_generation::init_materialized_generation_schema(conn).unwrap();
        filesystem_transaction::init_filesystem_transaction_schema(conn).unwrap();
        captured_authoring::init_captured_authoring_schema(conn).unwrap();
        retained_obligation::init_retained_obligations_schema(conn).unwrap();
    }

    fn emitter(seed: u8) -> ChangeEmitter {
        ChangeEmitter::new(format!("device-{seed}"), SigningKey::from_bytes(&[seed; 32]))
    }

    fn caps() -> FilesystemSafetyCapabilities {
        FilesystemSafetyCapabilities {
            atomic_exchange: Capability::Supported,
            durable_file_flush: Capability::Supported,
            durable_directory_flush: if cfg!(windows) {
                Capability::Unsupported
            } else {
                Capability::Supported
            },
            stable_source_identity: Capability::Supported,
            stable_owned_marker_identity: Capability::Supported,
            stale_handle_preservation: Capability::Supported,
            metadata_fidelity: Capability::Supported,
            reflink_or_clone: Capability::Supported,
            range_clone: Capability::Unsupported,
        }
    }

    // Deliberately not a synthetic constant: the commit window re-observes
    // `parent_dir`'s real identity through the held handle and refuses a
    // request whose `sync_root_identity`/`directory_identity` disagrees
    // with what it actually finds (`fs_commit`'s substitution check) — a
    // fake identity here would always be `DefinitelyDifferent`.

    fn begin_tx(conn: &Connection, group_id: &str) -> String {
        filesystem_transaction::begin_transaction_unchecked(
            conn,
            &filesystem_transaction::NewFilesystemTransaction {
                group_id,
                source_path: "/",
                kind: filesystem_transaction::FilesystemTransactionKind::ObjectResolution,
                cause: filesystem_transaction::TransactionCause::ConflictResolution,
                trigger_change_hash: None,
                desired_frontier_hash: [0u8; 32],
            },
            0,
        )
        .unwrap()
        .transaction_id
    }

    /// A `target_generation` byte string, computed the same way the commit
    /// window's own `require_commit_matches_epoch` recomputes it
    /// (`materialized_generation::compute_resolved_path_state_hash`) --
    /// this module never invents a second encoding, so a test's planned
    /// placement must use the real one too, keyed on a `VersionHash`
    /// derived from `content` so different content always produces a
    /// different, but deterministic, version.
    fn version_hash_for(content: &[u8]) -> VersionHash {
        use sha2::{Digest, Sha256};
        VersionHash(Sha256::digest(content).into())
    }

    fn placement(
        group_id: &str,
        path: &str,
        content: &[u8],
    ) -> (PlacementGroup, VersionHash, Vec<u8>) {
        let version = version_hash_for(content);
        let target_generation = materialized_generation::compute_resolved_path_state_hash(
            group_id,
            path,
            MaterializedObjectKind::RegularFile,
            Some(&version),
        )
        .to_vec();
        let group = PlacementGroup::new(vec![PlannedPlacement {
            path: path.to_string(),
            role: yadorilink_replica_domain::filesystem_placement::PlacementRole::CanonicalPath,
            target_generation: target_generation.clone(),
        }])
        .unwrap();
        (group, version, target_generation)
    }

    fn io_for<'a>(
        dir: &'a Path,
        parent: &'a ParentDirHandle,
        live_name: &str,
        capabilities: &'a FilesystemSafetyCapabilities,
        content: &'a [u8],
        version: VersionHash,
    ) -> PlacementIo<'a> {
        let source_path = dir.join(format!("{live_name}.src"));
        std::fs::write(&source_path, content).unwrap();
        // Leaked rather than borrowed from a local: this test helper is
        // called once per placement and the process exits at test end, so
        // the leak is harmless and lets `PlacementIo` carry a real
        // `'static` path without a second lifetime parameter on this
        // helper — never an acceptable pattern outside a test.
        let leaked: &'static Path = Box::leak(source_path.into_boxed_path());
        PlacementIo {
            parent_dir: parent,
            directory_identity: parent.identity().unwrap(),
            live_name: OsString::from(live_name),
            prepare_inputs: PlacementInputs {
                target_already_materialized: false,
                content_identity_unchanged: false,
                // `LocalVersionPath`, not `ImmutableContentStoreObject`:
                // the hardlink fast path is refused for a canonical
                // placement target (`ReplacementNotEligible(
                // HardlinkTopologyUnsupported)`) -- a live path is never
                // allowed to alias another name's inode. Reflink/clone
                // needs `reflink_or_clone: Supported` to be true on the
                // host filesystem, not just declared; this crate's dev/CI
                // hosts (APFS, most Linux filesystems used in tests) do
                // support it.
                clone_source: Some(CloneSource::LocalVersionPath(leaked)),
                capabilities,
            },
            expected_content_hash: None,
            exec_bit: None,
            object_kind: MaterializedObjectKind::RegularFile,
            version: Some(version),
            causal_basis: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_one(
        conn: &mut Connection,
        dir: &Path,
        group_id: &str,
        transaction_id: &str,
        next_epoch: i64,
        path: &str,
        content: &[u8],
        capabilities: &FilesystemSafetyCapabilities,
        parent: &ParentDirHandle,
        store: &FsBlockStore,
        gate: &BlockLivenessGate,
        em: &ChangeEmitter,
    ) -> Result<Vec<PlacementOutcome>, OrchestratorError> {
        let (group, version, _target) = placement(group_id, path, content);
        let bounds = SliceBounds::default();
        let slices =
            slice_plan(0, &[group], &bounds, |_g| content.len() as u64);
        assert_eq!(slices.len(), 1);
        let slice = &slices[0];

        let io = io_for(dir, parent, path, capabilities, content, version);
        let mut io_map = HashMap::new();
        io_map.insert(path.to_string(), io);

        let request = RunSliceRequest {
            group_id,
            transaction_id,
            next_epoch,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store,
            gate,
            emitter: em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };
        run_slice_unchecked(conn, &request, 0)
    }

    /// End to end: a placement that runs the whole §8.2 sequence and leaves
    /// a captured change plus a retained obligation behind for the object
    /// it displaced.
    #[test]
    fn a_placement_runs_end_to_end_and_leaves_a_captured_change_and_obligation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target.txt"), b"old content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        // Seed a materialized generation for "target.txt" so a
        // `DisplacedBasis::Generation` capture has a causal basis to
        // resolve, and seed the file this run's adapter will actually
        // observe as the pre-existing live object.
        let prior = dag_store::emit_local_change(
            &conn,
            group_id,
            vec![Op::Put {
                path: SyncPath("target.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([1u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        let prior_hash = prior.compute_hash();
        materialized_generation::record_materialized_generation(
            &conn,
            group_id,
            "target.txt",
            &[prior_hash],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            0,
        )
        .unwrap();

        let outcomes = run_one(
            &mut conn,
            dir.path(),
            group_id,
            &transaction_id,
            0,
            "target.txt",
            b"new content",
            &capabilities,
            &parent,
            &store,
            &gate,
            &em,
        )
        .unwrap();

        assert_eq!(outcomes.len(), 1);
        let outcome = &outcomes[0];
        assert_eq!(
            outcome.epoch.phase,
            EpochState::Completed,
            "a fully resolved placement must reach a terminal epoch state, not stall at \
             Committed -- see EpochState::is_terminal"
        );
        assert_eq!(
            std::fs::read(dir.path().join("target.txt")).unwrap(),
            b"new content",
            "the commit must actually have landed the new content"
        );
        match &outcome.custody {
            CustodyOutcome::Retained { obligation, captured_change_hash, .. } => {
                assert!(dag_store::has_change(&conn, captured_change_hash).unwrap());
                assert_eq!(
                    obligation.last_captured_change_hash.as_ref(),
                    Some(captured_change_hash)
                );
            }
            other => panic!("expected a retained obligation, got {other:?}"),
        }

        // No reservation is left dangling once the slice finishes.
        assert!(filesystem_transaction::list_reservations(&conn, &transaction_id)
            .unwrap()
            .is_empty());
    }

    /// Regression test for the defect where `RunSliceRequest` carried a
    /// single `ChangeAuth` captured once, before the slice ran, and reused
    /// unchecked at authoring time -- minutes later in production, after
    /// preparation, commit, custody transfer and classification. If
    /// authorization was lost in between, the change still entered the
    /// local DAG under a stale `ChangeAuth`, which every peer with the
    /// current authorization state would reject. This asserts that when
    /// [`CaptureAuthorizationSource::current_auth`] reports a loss
    /// immediately before authoring, no change is authored at all -- the
    /// epoch instead routes to `EpochState::AwaitingCaptureAuthorization`
    /// (temporary) or, via `EpochState::LocalRecoveryOnly`, to
    /// `EpochState::Completed` (permanent) -- and the whole slice still
    /// succeeds rather than failing outright.
    #[test]
    fn authorization_lost_between_slice_start_and_authoring_routes_the_epoch_instead_of_authoring()
    {
        struct LosesAuthorization(AuthorizationLoss);
        impl CaptureAuthorizationSource for LosesAuthorization {
            fn current_auth(
                &self,
                _group_id: &str,
            ) -> Result<CandidateAuthorizationCoordinate, AuthorizationLoss> {
                Err(self.0)
            }
        }

        for loss in [AuthorizationLoss::Temporary, AuthorizationLoss::Permanent] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("target.txt"), b"old content").unwrap();
            let parent = ParentDirHandle::open(dir.path()).unwrap();

            let mut conn = Connection::open_in_memory().unwrap();
            open_schema(&conn);

            let group_id = "g";
            let transaction_id = begin_tx(&conn, group_id);
            let capabilities = caps();
            let store_dir = tempfile::tempdir().unwrap();
            let store = FsBlockStore::new(store_dir.path()).unwrap();
            let gate = BlockLivenessGate::default();
            let em = emitter(1);

            let prior = dag_store::emit_local_change(
                &conn,
                group_id,
                vec![Op::Put {
                    path: SyncPath("target.txt".into()),
                    version: yadorilink_replica_domain::ids::VersionHash([1u8; 32]),
                    origin: PutOrigin::Direct,
                }],
                ChangeAuth::PLACEHOLDER,
                &em,
            )
            .unwrap();
            let prior_hash = prior.compute_hash();
            materialized_generation::record_materialized_generation(
                &conn,
                group_id,
                "target.txt",
                &[prior_hash],
                MaterializedObjectKind::RegularFile,
                None,
                None,
                0,
            )
            .unwrap();
            let changes_before: i64 =
                conn.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();

            let (group, version, _target) = placement(group_id, "target.txt", b"new content");
            let bounds = SliceBounds::default();
            let slices = slice_plan(0, &[group], &bounds, |_g| {
                "new content".len() as u64
            });
            assert_eq!(slices.len(), 1);
            let slice = &slices[0];
            let io =
                io_for(dir.path(), &parent, "target.txt", &capabilities, b"new content", version);
            let mut io_map = HashMap::new();
            io_map.insert("target.txt".to_string(), io);

            let request = RunSliceRequest {
                group_id,
                transaction_id: &transaction_id,
                next_epoch: 0,
                expected_execution_generation: 0,
                slice,
                io: &io_map,
                capability_snapshot: b"caps-v1",
                durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
                adapter: &NativeCommitAdapter,
                store: &store,
                gate: &gate,
                emitter: &em,
                capture_auth: &LosesAuthorization(loss),
                revalidation: empty_scope_revalidation(0, 0),
            };
            let outcomes = run_slice_unchecked(&mut conn, &request, 0).unwrap();

            assert_eq!(outcomes.len(), 1, "loss must not fail the whole slice -- {loss:?}");
            let outcome = &outcomes[0];
            match &outcome.custody {
                CustodyOutcome::AuthorizationLost { loss: reported, .. } => {
                    assert_eq!(*reported, loss);
                }
                other => panic!("expected AuthorizationLost({loss:?}), got {other:?}"),
            }
            let expected_phase = match loss {
                AuthorizationLoss::Temporary => EpochState::AwaitingCaptureAuthorization,
                AuthorizationLoss::Permanent => EpochState::Completed,
            };
            assert_eq!(outcome.epoch.phase, expected_phase, "{loss:?}");

            // The load-bearing assertion: authorization loss must never
            // result in a change being authored under stale authorization.
            let changes_after: i64 =
                conn.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
            assert_eq!(
                changes_before, changes_after,
                "no change may be authored when authorization was lost -- {loss:?}"
            );
        }
    }

    /// The load-bearing regression: a write that lands on the retained
    /// object *after* its fingerprint has been recorded against the
    /// obligation and *before* the captured change is authored must not be
    /// able to leave the obligation unpaired while the change is published.
    ///
    /// The injection point is the real seam, not a test hook:
    /// `CaptureAuthorizationSource::current_auth` is called from exactly
    /// between those two steps, so a source that writes to the retained
    /// custody file before answering reproduces the stale descriptor this
    /// subsystem exists for (a `rename` moves a directory entry, not the
    /// object a writer already holds open) at the precise moment that used
    /// to break.
    ///
    /// Before the fix, this module classified the custody file itself for
    /// the obligation's fingerprint and `captured_authoring` classified it
    /// again for the change: the write below landed between the two, the
    /// published change carried the *new* bytes' version, and
    /// `record_captured_change` refused to pair it with the *old* bytes'
    /// version it had been handed. Correctly refused -- but the change was
    /// already authored, receipted and retention-rooted, and nothing ever
    /// revisits that pairing, so the retained artefact could never be
    /// deleted and its retention root never released.
    #[test]
    fn a_write_landing_between_the_fingerprint_record_and_authoring_never_leaves_the_obligation_unpaired(
    ) {
        /// Writes to the retained custody file at the instant the driver
        /// asks for authorization -- i.e. after `record_late_write` and
        /// before the captured change is authored.
        struct WritesThroughAStaleHandleFirst {
            custody_path: std::path::PathBuf,
        }
        impl CaptureAuthorizationSource for WritesThroughAStaleHandleFirst {
            fn current_auth(
                &self,
                _group_id: &str,
            ) -> Result<CandidateAuthorizationCoordinate, AuthorizationLoss> {
                assert!(
                    self.custody_path.exists(),
                    "the retained object must already be in custody at authorization time"
                );
                std::fs::write(
                    &self.custody_path,
                    b"late write through a descriptor opened before custody transfer",
                )
                .unwrap();
                Ok(TEST_COORDINATE)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target.txt"), b"displaced content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let prior = dag_store::emit_local_change(
            &conn,
            group_id,
            vec![Op::Put {
                path: SyncPath("target.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([1u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        materialized_generation::record_materialized_generation(
            &conn,
            group_id,
            "target.txt",
            &[prior.compute_hash()],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            0,
        )
        .unwrap();

        let (group, version, _target) = placement(group_id, "target.txt", b"new content");
        let bounds = SliceBounds::default();
        let slices =
            slice_plan(0, &[group], &bounds, |_g| "new content".len() as u64);
        let slice = &slices[0];
        let io = io_for(dir.path(), &parent, "target.txt", &capabilities, b"new content", version);
        let mut io_map = HashMap::new();
        io_map.insert("target.txt".to_string(), io);

        let retained_id = artefact_id_for(&transaction_id, 0);
        let custody_path =
            dir.path().join(artefact_component_name(ArtefactKind::Retained, &retained_id).unwrap());
        let capture_auth = WritesThroughAStaleHandleFirst { custody_path: custody_path.clone() };

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &capture_auth,
            // These two tests are about the capture pipeline, not
            // revalidation: an empty plan scope means "the frontier
            // for this plan's paths" cannot move, so the boundary
            // check passes without the test asserting anything about
            // it.
            revalidation: empty_scope_revalidation(0, 0),
        };
        let outcomes = match run_slice_unchecked(&mut conn, &request, 0) {
            Ok(outcomes) => outcomes,
            Err(error) => panic!(
                "a write landing between the obligation's fingerprint record and authoring must \
                 not fail the placement: {error:?}"
            ),
        };

        // The write really did land -- the retained object on disk is no
        // longer the bytes that were classified.
        assert_eq!(
            std::fs::read(&custody_path).unwrap(),
            b"late write through a descriptor opened before custody transfer".to_vec(),
        );

        assert_eq!(outcomes.len(), 1);
        let (obligation, captured_change_hash) = match &outcomes[0].custody {
            CustodyOutcome::Retained { obligation, captured_change_hash, .. } => {
                (obligation, *captured_change_hash)
            }
            other => panic!("expected Retained, got {other:?}"),
        };

        // The point of the whole exercise: the published change and the
        // obligation are paired. An unpaired obligation is a retained
        // artefact that can never be deleted and a retention root that can
        // never be released.
        assert_eq!(
            obligation.last_captured_change_hash,
            Some(captured_change_hash),
            "the authored change must be paired with the obligation, never published while the \
             obligation is left unpaired"
        );
        assert!(dag_store::has_change(&conn, &captured_change_hash).unwrap());
    }

    /// An authorization source that answers with a constant -- the
    /// placeholder stamp this crate's own test double used to return -- must
    /// not be able to get a change signed under it. The coordinate is
    /// re-validated against the database before it becomes a `ChangeAuth`,
    /// and nothing is authored when it fails.
    #[test]
    fn an_authorization_source_answering_with_the_placeholder_constant_authors_nothing() {
        struct AnswersWithAConstant;
        impl CaptureAuthorizationSource for AnswersWithAConstant {
            fn current_auth(
                &self,
                _group_id: &str,
            ) -> Result<CandidateAuthorizationCoordinate, AuthorizationLoss> {
                Ok(CandidateAuthorizationCoordinate {
                    auth_seq: ChangeAuth::PLACEHOLDER.auth_seq,
                    auth_epoch: ChangeAuth::PLACEHOLDER.auth_epoch,
                    policy_head_hash: ChangeAuth::PLACEHOLDER.policy_head_hash,
                })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target.txt"), b"displaced content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let prior = dag_store::emit_local_change(
            &conn,
            group_id,
            vec![Op::Put {
                path: SyncPath("target.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([1u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        materialized_generation::record_materialized_generation(
            &conn,
            group_id,
            "target.txt",
            &[prior.compute_hash()],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            0,
        )
        .unwrap();
        let changes_before: i64 =
            conn.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();

        let (group, version, _target) = placement(group_id, "target.txt", b"new content");
        let bounds = SliceBounds::default();
        let slices =
            slice_plan(0, &[group], &bounds, |_g| "new content".len() as u64);
        let slice = &slices[0];
        let io = io_for(dir.path(), &parent, "target.txt", &capabilities, b"new content", version);
        let mut io_map = HashMap::new();
        io_map.insert("target.txt".to_string(), io);

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AnswersWithAConstant,
            // These two tests are about the capture pipeline, not
            // revalidation: an empty plan scope means "the frontier
            // for this plan's paths" cannot move, so the boundary
            // check passes without the test asserting anything about
            // it.
            revalidation: empty_scope_revalidation(0, 0),
        };
        let error = run_slice_unchecked(&mut conn, &request, 0)
            .expect_err("a placeholder coordinate must not author a captured change");
        assert!(
            matches!(
                error,
                OrchestratorError::Author {
                    error: CapturedAuthoringError::AuthorizationCoordinateRejected { .. },
                    ..
                }
            ),
            "{error:?}"
        );
        let changes_after: i64 =
            conn.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(
            changes_before, changes_after,
            "nothing may be signed under a coordinate that failed re-validation"
        );
    }

    /// A commit window that refuses must leave nothing partial behind: the
    /// epoch never reaches `Committed`, and no obligation or captured
    /// change is created. The reservation *is* released -- an ordinary
    /// refusal (`NotStarted`) is a proven no-op, nothing on disk needs it
    /// held any longer -- see the module doc's "a sibling's failure must
    /// not strand an already-committed write" section.
    #[test]
    fn a_refused_commit_window_leaves_nothing_partial() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        struct AlwaysNotStarted;
        impl FilesystemCommitAdapter for AlwaysNotStarted {
            fn commit_placement(&self, _request: &CommitRequest) -> FilesystemCommitOutcome {
                FilesystemCommitOutcome::NotStarted(yadorilink_filesystem_sync::fs_commit::RetryReason::Io(
                    io::ErrorKind::PermissionDenied,
                ))
            }
            fn observe_identity(&self, _path: &Path) -> io::Result<Option<FileIdentity>> {
                Ok(None)
            }
        }

        let (group, version, _target) = placement(group_id, "blocked.txt", b"content");
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &[group], &bounds, |_| 7);
        let slice = &slices[0];

        let io = io_for(dir.path(), &parent, "blocked.txt", &capabilities, b"content", version);
        let mut io_map = HashMap::new();
        io_map.insert("blocked.txt".to_string(), io);

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &AlwaysNotStarted,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };
        let result = run_slice_unchecked(&mut conn, &request, 0);
        assert!(matches!(result, Err(OrchestratorError::Commit { .. })), "{result:?}");

        // The reservation is released -- nothing committed, so nothing on
        // disk still needs it held.
        let reservations =
            filesystem_transaction::list_reservations(&conn, &transaction_id).unwrap();
        assert!(
            reservations.is_empty(),
            "an ordinary commit refusal (a proven no-op) must release the reservation"
        );

        assert!(!dir.path().join("blocked.txt").exists());
    }

    /// A multi-path slice: both placements are acquired by the same single
    /// `acquire_reservations` call, and both commit -- proving the "keeping
    /// reservations" seam actually lets the second placement's commit
    /// window run with its reservation still intact. This does *not* prove
    /// an all-or-none guarantee across a slice's own commit attempts --
    /// there is no such guarantee (see `a_mid_slice_failure_still_
    /// resolves_the_already_committed_placement` below, and the module
    /// doc's "a sibling's failure must not strand an already-committed
    /// write" section) -- so this test is named for what it actually
    /// exercises: every placement in the slice reaching its commit window
    /// and committing, not a guarantee that a later failure would roll the
    /// earlier ones back.
    #[test]
    fn a_multi_path_slice_acquires_once_and_commits_every_placement() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let (group_a, version_a, _) = placement(group_id, "a.txt", b"content-a");
        let (group_b, version_b, _) = placement(group_id, "b.txt", b"content-b");
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &[group_a, group_b], &bounds, |_| 9);
        assert_eq!(slices.len(), 1, "both groups must land in the same slice");
        let slice = &slices[0];

        let io_a = io_for(dir.path(), &parent, "a.txt", &capabilities, b"content-a", version_a);
        let io_b = io_for(dir.path(), &parent, "b.txt", &capabilities, b"content-b", version_b);
        let mut io_map = HashMap::new();
        io_map.insert("a.txt".to_string(), io_a);
        io_map.insert("b.txt".to_string(), io_b);

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };
        let outcomes = run_slice_unchecked(&mut conn, &request, 0).unwrap();
        assert_eq!(outcomes.len(), 2);
        for outcome in &outcomes {
            assert_eq!(outcome.epoch.phase, EpochState::Completed);
        }
        assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"content-a");
        assert_eq!(std::fs::read(dir.path().join("b.txt")).unwrap(), b"content-b");
    }

    /// A mid-slice failure on a later placement must not strand an earlier
    /// placement that already committed: "a.txt" displaces real content and
    /// commits before "b.txt" fails, and its custody transfer,
    /// classification, captured authoring and retained obligation must all
    /// still run, with its epoch reaching a terminal state -- not sit
    /// forever at the non-terminal `Committed` with its displaced content
    /// unauthored and hidden. See the module doc's "a sibling's failure
    /// must not strand an already-committed write" section.
    #[test]
    fn a_mid_slice_failure_still_resolves_the_already_committed_placement() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"old-a").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        // Seed a materialized generation for "a.txt" so its displaced
        // content has a causal basis to author a captured change against --
        // same setup as `a_placement_runs_end_to_end_and_leaves_a_captured_
        // change_and_obligation`.
        let prior = dag_store::emit_local_change(
            &conn,
            group_id,
            vec![Op::Put {
                path: SyncPath("a.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([1u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        let prior_hash = prior.compute_hash();
        materialized_generation::record_materialized_generation(
            &conn,
            group_id,
            "a.txt",
            &[prior_hash],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            0,
        )
        .unwrap();

        // Commits "a.txt" through the real adapter, but refuses "b.txt"
        // outright (a non-retryable `NotStarted`) -- nothing about this
        // scenario needs `RequiresRecovery` specifically; an ordinary
        // refusal after a sibling already committed is enough to exercise
        // the strand.
        struct FailOneName(OsString);
        impl FilesystemCommitAdapter for FailOneName {
            fn commit_placement(&self, request: &CommitRequest) -> FilesystemCommitOutcome {
                if request.live_name == self.0.as_os_str() {
                    FilesystemCommitOutcome::NotStarted(yadorilink_filesystem_sync::fs_commit::RetryReason::Io(
                        io::ErrorKind::PermissionDenied,
                    ))
                } else {
                    NativeCommitAdapter.commit_placement(request)
                }
            }
            fn observe_identity(&self, path: &Path) -> io::Result<Option<FileIdentity>> {
                NativeCommitAdapter.observe_identity(path)
            }
        }
        let adapter = FailOneName(OsString::from("b.txt"));

        let (group_a, version_a, _) = placement(group_id, "a.txt", b"new-a");
        let (group_b, version_b, _) = placement(group_id, "b.txt", b"new-b");
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &[group_a, group_b], &bounds, |_| 9);
        assert_eq!(slices.len(), 1, "both groups must land in the same slice");
        let slice = &slices[0];

        let io_a = io_for(dir.path(), &parent, "a.txt", &capabilities, b"new-a", version_a);
        let io_b = io_for(dir.path(), &parent, "b.txt", &capabilities, b"new-b", version_b);
        let mut io_map = HashMap::new();
        io_map.insert("a.txt".to_string(), io_a);
        io_map.insert("b.txt".to_string(), io_b);

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &adapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };
        let result = run_slice_unchecked(&mut conn, &request, 0);
        // D2 (21.9): wrapped with the outcome "a.txt" already earned before
        // "b.txt" failed -- see this test's own assertions below on
        // `partial_placements` for why dropping it here would be wrong.
        let partial_placements = match result {
            Err(OrchestratorError::Partial { error, placements }) => {
                assert!(
                    matches!(*error, OrchestratorError::Commit { .. }),
                    "the wrapped error must still be the real failure: {error:?}"
                );
                placements
            }
            other => panic!("expected a Partial-wrapped Commit failure, got {other:?}"),
        };
        assert_eq!(
            partial_placements.iter().map(|p| p.path.as_str()).collect::<Vec<_>>(),
            vec!["a.txt"],
            "the already-committed sibling's outcome must reach the caller through the error, \
             not be dropped"
        );

        // "b.txt"'s refusal is an ordinary, proven no-op -- the slice's
        // reservations are released once every placement has been
        // attempted, same as a single-placement refusal. See the module
        // doc's "a sibling's failure must not strand an already-committed
        // write" section for why this is safe even though "a.txt" already
        // committed: its own reservation is no longer needed past custody
        // transfer, which the driving below has by now already run.
        let reservations =
            filesystem_transaction::list_reservations(&conn, &transaction_id).unwrap();
        assert!(
            reservations.is_empty(),
            "an ordinary sibling refusal must release the slice's reservations"
        );

        // "a.txt" already committed before "b.txt" failed -- it must still
        // have been driven all the way through custody transfer,
        // classification, captured authoring and its retained obligation,
        // and its epoch must have reached a terminal state.
        let epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        let a_epoch = epochs.iter().find(|e| e.target_path == "a.txt").unwrap();
        assert_eq!(
            a_epoch.phase,
            EpochState::Completed,
            "an already-committed placement must not be stranded by a sibling's failure"
        );
        assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"new-a");

        let retained_id = artefact_id_for(&transaction_id, a_epoch.epoch);
        let obligation = retained_obligation::get(&conn, group_id, &retained_id)
            .unwrap()
            .expect("a.txt's displaced content must have a retained obligation, not be orphaned");
        assert!(
            obligation.last_captured_change_hash.is_some(),
            "a.txt's displaced content must have been authored as a captured change"
        );
    }

    /// Unlike a commit-window failure, a *post-commit* failure happens after
    /// both placements have already, independently, committed -- "a.txt"
    /// and "b.txt" both land, then "a.txt"'s own custody transfer step
    /// fails (its commit really did displace something, but no prior
    /// `materialized_generation` row exists to author a captured change
    /// against, so `drive_captured_placement` hits the "structurally
    /// impossible" `CorruptState` guard). "b.txt" must still be driven all
    /// the way to `Completed` -- a bare `?` in the post-commit loop would
    /// exit on "a.txt"'s error before "b.txt", already committed, is ever
    /// attempted. See the module doc's "post-commit" addition to "a
    /// sibling's failure must not strand an already-committed write".
    #[test]
    fn a_post_commit_failure_does_not_strand_a_committed_sibling() {
        let dir = tempfile::tempdir().unwrap();
        // "a.txt" has real prior content on disk -- its commit will really
        // displace something -- but deliberately no `materialized_
        // generation` row is seeded for it, forcing the post-commit
        // `CorruptState` guard once its custody transfer step runs.
        std::fs::write(dir.path().join("a.txt"), b"old-a").unwrap();
        // "b.txt" gets the full, correct setup: real prior content plus a
        // seeded `materialized_generation` row, so its own post-commit
        // sequence succeeds normally.
        std::fs::write(dir.path().join("b.txt"), b"old-b").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let prior = dag_store::emit_local_change(
            &conn,
            group_id,
            vec![Op::Put {
                path: SyncPath("b.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([1u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        let prior_hash = prior.compute_hash();
        materialized_generation::record_materialized_generation(
            &conn,
            group_id,
            "b.txt",
            &[prior_hash],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            0,
        )
        .unwrap();

        let (group_a, version_a, _) = placement(group_id, "a.txt", b"new-a");
        let (group_b, version_b, _) = placement(group_id, "b.txt", b"new-b");
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &[group_a, group_b], &bounds, |_| 9);
        assert_eq!(slices.len(), 1, "both groups must land in the same slice");
        let slice = &slices[0];

        let io_a = io_for(dir.path(), &parent, "a.txt", &capabilities, b"new-a", version_a);
        let io_b = io_for(dir.path(), &parent, "b.txt", &capabilities, b"new-b", version_b);
        let mut io_map = HashMap::new();
        io_map.insert("a.txt".to_string(), io_a);
        io_map.insert("b.txt".to_string(), io_b);

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };
        let result = run_slice_unchecked(&mut conn, &request, 0);
        // D2 (21.9): wrapped with "b.txt"'s outcome -- it committed
        // independently of "a.txt" and was driven all the way through its
        // own custody/authoring sequence before "a.txt"'s post-commit
        // failure was returned.
        let partial_placements = match result {
            Err(OrchestratorError::Partial { error, placements }) => {
                assert!(
                    matches!(*error, OrchestratorError::Sync(SyncError::CorruptState(_))),
                    "the wrapped error must still be the real failure: {error:?}"
                );
                placements
            }
            other => panic!("expected a Partial-wrapped CorruptState failure, got {other:?}"),
        };
        assert_eq!(
            partial_placements.iter().map(|p| p.path.as_str()).collect::<Vec<_>>(),
            vec!["b.txt"],
            "the independently-committed sibling's outcome must reach the caller through the \
             error, not be dropped"
        );

        // Both commits landed on disk regardless of "a.txt"'s post-commit
        // failure.
        assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"new-a");
        assert_eq!(std::fs::read(dir.path().join("b.txt")).unwrap(), b"new-b");

        let epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();

        // "a.txt"'s own post-commit sequence now fails at the durable
        // causal-basis proof `drive_captured_placement` performs BEFORE the
        // custody-transfer rename (no `materialized_generation` row was
        // seeded for it, so the proof cannot find `displaced_generation_id`
        // durably interned) -- earlier than the old failure point right
        // after the `CustodyTransferred` transition, so the epoch is left
        // at `Committed`, not `CustodyTransferred`.
        let a_epoch = epochs.iter().find(|e| e.target_path == "a.txt").unwrap();
        assert_eq!(a_epoch.phase, EpochState::Committed);

        // "b.txt" already committed independently of "a.txt" and must not
        // be stranded by "a.txt"'s failure: it is driven all the way to a
        // terminal state, with its own retained obligation recorded.
        let b_epoch = epochs.iter().find(|e| e.target_path == "b.txt").unwrap();
        assert_eq!(
            b_epoch.phase,
            EpochState::Completed,
            "an already-committed placement must not be stranded by a sibling's post-commit \
             failure"
        );
        let retained_id = artefact_id_for(&transaction_id, b_epoch.epoch);
        let obligation = retained_obligation::get(&conn, group_id, &retained_id)
            .unwrap()
            .expect("b.txt's displaced content must have a retained obligation, not be orphaned");
        assert!(
            obligation.last_captured_change_hash.is_some(),
            "b.txt's displaced content must have been authored as a captured change"
        );
    }

    /// Unlike an ordinary commit refusal, `RequiresPhysicalRecovery` leaves
    /// genuine physical ambiguity behind -- its placement's reservation
    /// must stay held, the one exception to "release once every placement
    /// has been attempted". See the module doc's "a sibling's failure must
    /// not strand an already-committed write" section.
    #[test]
    fn a_requires_physical_recovery_failure_keeps_the_reservation_held() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        struct RequiresRecoveryForOneName(OsString);
        impl FilesystemCommitAdapter for RequiresRecoveryForOneName {
            fn commit_placement(&self, request: &CommitRequest) -> FilesystemCommitOutcome {
                if request.live_name == self.0.as_os_str() {
                    FilesystemCommitOutcome::RequiresRecovery(Box::new(RecoverySnapshot {
                        observed_live: None,
                        observed_stage: None,
                        observed_preimage: None,
                        observed_backup: None,
                    }))
                } else {
                    NativeCommitAdapter.commit_placement(request)
                }
            }
            fn observe_identity(&self, path: &Path) -> io::Result<Option<FileIdentity>> {
                NativeCommitAdapter.observe_identity(path)
            }
        }
        let adapter = RequiresRecoveryForOneName(OsString::from("b.txt"));

        let (group_a, version_a, _) = placement(group_id, "a.txt", b"content-a");
        let (group_b, version_b, _) = placement(group_id, "b.txt", b"content-b");
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &[group_a, group_b], &bounds, |_| 9);
        assert_eq!(slices.len(), 1, "both groups must land in the same slice");
        let slice = &slices[0];

        let io_a = io_for(dir.path(), &parent, "a.txt", &capabilities, b"content-a", version_a);
        let io_b = io_for(dir.path(), &parent, "b.txt", &capabilities, b"content-b", version_b);
        let mut io_map = HashMap::new();
        io_map.insert("a.txt".to_string(), io_a);
        io_map.insert("b.txt".to_string(), io_b);

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &adapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };
        let result = run_slice_unchecked(&mut conn, &request, 0);
        // D2 (21.9): wrapped with "a.txt"'s outcome, the same as any other
        // commit_failure shape.
        let partial_placements = match result {
            Err(OrchestratorError::Partial { error, placements }) => {
                assert!(
                    matches!(*error, OrchestratorError::RequiresPhysicalRecovery { .. }),
                    "the wrapped error must still be the real failure: {error:?}"
                );
                placements
            }
            other => {
                panic!("expected a Partial-wrapped RequiresPhysicalRecovery failure, got {other:?}")
            }
        };
        assert_eq!(
            partial_placements.iter().map(|p| p.path.as_str()).collect::<Vec<_>>(),
            vec!["a.txt"],
            "the already-committed sibling's outcome must reach the caller through the error, \
             not be dropped"
        );

        let reservations =
            filesystem_transaction::list_reservations(&conn, &transaction_id).unwrap();
        assert!(
            !reservations.is_empty(),
            "a RequiresPhysicalRecovery failure must keep the reservations held for \
             early_physical_recovery to find"
        );

        // "a.txt" still committed and was still driven to a terminal epoch
        // state, exactly as the ordinary-refusal case above.
        let epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        let a_epoch = epochs.iter().find(|e| e.target_path == "a.txt").unwrap();
        assert_eq!(a_epoch.phase, EpochState::Completed);
    }

    /// A replan mid-sequence must not redo already-committed work --
    /// `plan_progress` (the existing primitive this scenario exercises,
    /// not a new one) correctly reports the already-committed placement as
    /// done once the epoch this module allocated for it reaches a
    /// committed-or-later state.
    #[test]
    fn a_replan_does_not_redo_already_committed_work() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let outcomes = run_one(
            &mut conn,
            dir.path(),
            group_id,
            &transaction_id,
            0,
            "c.txt",
            b"stable content",
            &capabilities,
            &parent,
            &store,
            &gate,
            &em,
        )
        .unwrap();
        assert_eq!(outcomes[0].epoch.phase, EpochState::Completed);

        let (group, _version, target_generation) = placement(group_id, "c.txt", b"stable content");
        let done = resolution_planning::plan_progress(&conn, &transaction_id, &[group]).unwrap();
        assert!(
            done.is_empty(),
            "the placement naming the same target_generation the committed epoch already \
             placed must be reported as done, not replanned: {done:?} vs {target_generation:?}"
        );
    }

    #[test]
    fn missing_io_for_a_slice_path_is_refused_before_any_allocation() {
        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);
        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);

        let (group, _version, _target) = placement(group_id, "missing.txt", b"x");
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &[group], &bounds, |_| 1);
        let slice = &slices[0];
        let io_map: HashMap<String, PlacementIo> = HashMap::new();
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let _ = &parent; // unused in this request, IO map is intentionally empty

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };
        let result = run_slice_unchecked(&mut conn, &request, 0);
        assert!(matches!(result, Err(OrchestratorError::MissingIo { .. })));

        // Nothing was allocated -- no epoch exists for this transaction.
        assert!(filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id)
            .unwrap()
            .is_empty());
        let _ = capabilities;
        let _ = CH([0u8; 32]);
        let _ = RecoverySnapshot {
            observed_live: None,
            observed_stage: None,
            observed_preimage: None,
            observed_backup: None,
        };
        let _ = CommittedSnapshot {
            live_identity: FileIdentity {
                volume_identity: VolumeIdentity::Unix { device_id: 1 },
                object_id: PlatformObjectId::Unix { inode: 1 },
                object_kind: ObjectKind::RegularFile,
                generation_or_usn: None,
                birth_or_creation_time: None,
                observed_size: 0,
                metadata_fingerprint: [0; 32],
                link_count: Some(1),
                symlink_target_digest: None,
            },
            preimage_identity: None,
        };
    }

    /// 24.5 regression: a crash between the stage artefact's physical
    /// creation and the durable write that used to record it together with
    /// its identity must not leave the artefact invisible to
    /// `early_physical_recovery` forever.
    /// `set_simulate_crash_after_artefact_creation_for_test` stops
    /// `run_slice_unchecked` at exactly that point -- after
    /// `prepare_target` has really created and fsynced the
    /// object, before the `PreparedArtifact`/`staged_identity` transition
    /// runs -- so the epoch this test inspects afterwards is in exactly the
    /// state a real crash there would leave behind.
    #[test]
    fn a_crash_after_artefact_creation_leaves_it_owned_and_findable() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let (group, version, _target) = placement(group_id, "orphan.txt", b"content");
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &[group], &bounds, |_| 7);
        let slice = &slices[0];

        let io = io_for(dir.path(), &parent, "orphan.txt", &capabilities, b"content", version);
        let mut io_map = HashMap::new();
        io_map.insert("orphan.txt".to_string(), io);

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };

        set_simulate_crash_after_artefact_creation_for_test(true);
        let result = run_slice_unchecked(&mut conn, &request, 0);
        set_simulate_crash_after_artefact_creation_for_test(false);
        assert!(
            matches!(result, Err(OrchestratorError::Sync(SyncError::NotImplemented(_)))),
            "{result:?}"
        );

        let epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        assert_eq!(epochs.len(), 1);
        let epoch = &epochs[0];
        assert_eq!(
            epoch.phase,
            EpochState::Preparing,
            "the second (identity) transition never ran -- this is the simulated crash point"
        );
        let stage_path = epoch
            .stage_path
            .as_ref()
            .expect("the deterministic stage_path must already be durable before creation");
        assert!(
            Path::new(stage_path).exists(),
            "prepare_target really created the artefact before the simulated crash"
        );
        assert!(
            epoch.staged_identity.is_none(),
            "identity is only observed once the artefact exists, so it cannot have been \
             recorded in the same write as the pre-creation intent"
        );

        // The load-bearing assertion: even though `staged_identity` was
        // never recorded, `stage_path` alone -- durable *before* creation --
        // is enough for early physical recovery to find and protect the
        // artefact. Before this fix, nothing durable named it at all, so it
        // never appeared here.
        let report = yadorilink_sync_sqlite::early_physical_recovery::run(&conn).unwrap();
        assert!(
            report.owned_paths.contains(Path::new(stage_path)),
            "early_physical_recovery must mark the crashed-but-recorded stage artefact owned: \
             {:?}",
            report.owned_paths
        );
    }

    /// A placement whose filesystem mutation succeeded but whose journaling
    /// then failed must keep its reservations. The release decision below
    /// is made from the error variant alone, so a post-mutation failure
    /// reported as an ordinary error would release the path's exclusion
    /// while the object on disk has already been replaced and no epoch
    /// records it -- exactly the window another writer could step into
    /// before recovery ever runs.
    ///
    /// The failure is induced through the execution-generation fence: the
    /// adapter bumps the generation from an independent connection and then
    /// performs the real platform commit, so the mutation genuinely lands
    /// and the `Committing -> Committed` transition immediately after it is
    /// what fails.
    #[test]
    fn a_journaling_failure_after_the_mutation_keeps_the_reservations_held() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target.txt"), b"old content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        // File-backed rather than in-memory: the adapter below needs a
        // genuinely independent connection to the same database to bump the
        // generation from, which an in-memory database cannot provide.
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("orchestrator.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let (group, version, _target) = placement(group_id, "target.txt", b"new content");
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &[group], &bounds, |_| 11);
        let slice = &slices[0];

        let io = io_for(dir.path(), &parent, "target.txt", &capabilities, b"new content", version);
        let mut io_map = HashMap::new();
        io_map.insert("target.txt".to_string(), io);

        struct BumpsTheGenerationThenCommits {
            db_path: std::path::PathBuf,
            transaction_id: String,
        }
        impl yadorilink_filesystem_sync::fs_commit::FilesystemCommitAdapter for BumpsTheGenerationThenCommits {
            fn commit_placement(
                &self,
                request: &yadorilink_filesystem_sync::fs_commit::CommitRequest,
            ) -> yadorilink_filesystem_sync::fs_commit::FilesystemCommitOutcome {
                let racer = Connection::open(&self.db_path).unwrap();
                filesystem_transaction::increment_execution_generation_unchecked(
                    &racer,
                    &self.transaction_id,
                )
                .unwrap();
                NativeCommitAdapter.commit_placement(request)
            }
            fn observe_identity(
                &self,
                path: &Path,
            ) -> std::io::Result<Option<yadorilink_root_authority::fs_identity::FileIdentity>> {
                NativeCommitAdapter.observe_identity(path)
            }
        }
        let adapter = BumpsTheGenerationThenCommits {
            db_path: db_path.clone(),
            transaction_id: transaction_id.clone(),
        };

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &adapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };

        let result = run_slice_unchecked(&mut conn, &request, 0);

        // Asserted first, and deliberately: this is the harm, and it must
        // hold on its own rather than only as a consequence of the error
        // variant checked below.
        let reservations =
            filesystem_transaction::list_reservations(&conn, &transaction_id).unwrap();
        assert!(
            !reservations.is_empty(),
            "the filesystem was mutated and nothing durable records the outcome, so the path's \
             exclusion must stay held until recovery resolves it; run returned {result:?}"
        );
        assert!(
            matches!(result, Err(OrchestratorError::RequiresPhysicalRecovery { .. })),
            "a failure after the mutation landed must reach this level as physical ambiguity: \
             {result:?}"
        );
    }

    /// 24.4 regression: a mid-slice prepare failure must not `?`-return and
    /// strand the rest of the slice with no settled fate. "a.txt" prepares
    /// successfully (left at `PreparedArtifact`, reusable per design §6.1);
    /// "b.txt" is given a deliberately wrong `expected_content_hash`, so
    /// `optimistic_placement::finish_staged_file` fails with
    /// `ContentVerificationFailed` *after* its own artefact has already been
    /// created. Every epoch in the slice must reach a state a recovery pass
    /// can act on -- none left at `Allocated`/`Preparing` with an
    /// unprotected artefact -- and the parent transaction must be told the
    /// slice cannot proceed as planned.
    #[test]
    fn a_mid_slice_prepare_failure_blocks_the_failing_epoch_and_the_parent_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let (group_a, version_a, _) = placement(group_id, "a.txt", b"content-a");
        let (group_b, version_b, _) = placement(group_id, "b.txt", b"content-b");
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &[group_a, group_b], &bounds, |_| 9);
        assert_eq!(slices.len(), 1, "both groups must land in the same slice");
        let slice = &slices[0];

        let io_a = io_for(dir.path(), &parent, "a.txt", &capabilities, b"content-a", version_a);
        let mut io_b = io_for(dir.path(), &parent, "b.txt", &capabilities, b"content-b", version_b);
        // Deliberately wrong -- forces `ContentVerificationFailed` *after*
        // `finish_staged_file` has already created and written "b.txt"'s
        // stage artefact, the "created it but could not verify it" shape.
        io_b.expected_content_hash = Some([0xAB; 32]);
        let mut io_map = HashMap::new();
        io_map.insert("a.txt".to_string(), io_a);
        io_map.insert("b.txt".to_string(), io_b);

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };
        let result = run_slice_unchecked(&mut conn, &request, 0);
        assert!(matches!(result, Err(OrchestratorError::Prepare { .. })), "{result:?}");

        let epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        assert_eq!(epochs.len(), 2);

        // "a.txt" prepared successfully before "b.txt" failed -- left
        // exactly at `PreparedArtifact`, not force-cleaned, so a replan
        // requesting the identical target generation can reuse it (design
        // §6.1).
        let a_epoch = epochs.iter().find(|e| e.target_path == "a.txt").unwrap();
        assert_eq!(a_epoch.phase, EpochState::PreparedArtifact);
        assert!(a_epoch.stage_path.is_some());
        assert!(a_epoch.staged_identity.is_some());

        // "b.txt" is the one that actually failed -- it must not be left at
        // `Preparing`/`AwaitingReservation` (no legal retry edge exists from
        // there); it must reach the epoch state machine's only legal
        // destination.
        let b_epoch = epochs.iter().find(|e| e.target_path == "b.txt").unwrap();
        assert_eq!(
            b_epoch.phase,
            EpochState::Blocked,
            "a prepare failure has no legal retry edge; the epoch must be routed to Blocked, \
             not left at Preparing"
        );
        assert!(
            b_epoch.stage_path.is_some(),
            "the deterministic stage_path must already be durable, protecting the artefact \
             `finish_staged_file` created before verification failed"
        );

        // The parent transaction must record the decision too -- nothing
        // downstream can otherwise tell this slice needs replanning.
        let transaction =
            filesystem_transaction::lookup_transaction(&conn, &transaction_id).unwrap().unwrap();
        assert_eq!(transaction.phase, TransactionPhase::Blocked);
        assert!(transaction.blocked_reason.is_some());

        // No reservation was ever requested for this slice -- prepare never
        // got that far -- so nothing to release either.
        let reservations =
            filesystem_transaction::list_reservations(&conn, &transaction_id).unwrap();
        assert!(reservations.is_empty());
    }

    /// End-to-end regression for a mid-slice prepare failure: it must not
    /// permanently strand the parent transaction. This drives the same
    /// failure as `a_mid_slice_prepare_failure_blocks_the_failing_epoch_and_
    /// the_parent_transaction` all the way to `Completed`, exercising two
    /// fixes together -- `resolution_planning::replan_unchecked` moving the
    /// parent out of `Blocked` (the only code in this crate that does; see
    /// `plan_driver`'s own regression test for the driver noticing `Blocked`
    /// and calling it automatically) and, in the same call, settling the
    /// leftover `PreparedArtifact`/`Allocated` siblings the prepare loop
    /// deliberately left behind, which would otherwise keep the
    /// parent-completion invariant in `set_transaction_phase_unchecked`
    /// refusing `Completed` forever even after the replanned work lands.
    #[test]
    fn a_transaction_reaches_completed_after_a_mid_slice_prepare_failure_is_replanned() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);

        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let capabilities = caps();
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let (group_a, version_a, _) = placement(group_id, "a.txt", b"content-a");
        let (group_b, version_b, _) = placement(group_id, "b.txt", b"content-b");
        let bounds = SliceBounds::default();
        let slices =
            slice_plan(0, &[group_a.clone(), group_b.clone()], &bounds, |_| 9);
        assert_eq!(slices.len(), 1);
        let slice = &slices[0];

        let io_a = io_for(dir.path(), &parent, "a.txt", &capabilities, b"content-a", version_a);
        let mut io_b = io_for(dir.path(), &parent, "b.txt", &capabilities, b"content-b", version_b);
        // Wrong on purpose, exactly as the sibling regression test above --
        // "a.txt" prepares fully (`PreparedArtifact`), "b.txt" fails
        // verification after its own artefact is already staged.
        io_b.expected_content_hash = Some([0xAB; 32]);
        let mut io_map = HashMap::new();
        io_map.insert("a.txt".to_string(), io_a);
        io_map.insert("b.txt".to_string(), io_b);

        let request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice,
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(0, 0),
        };
        let result = run_slice_unchecked(&mut conn, &request, 0);
        assert!(matches!(result, Err(OrchestratorError::Prepare { .. })), "{result:?}");
        let blocked =
            filesystem_transaction::lookup_transaction(&conn, &transaction_id).unwrap().unwrap();
        assert_eq!(blocked.phase, TransactionPhase::Blocked);

        // The fix: replanning out of `Blocked` settles the leftover epochs
        // AND fences the superseded generation.
        resolution_planning::replan_unchecked(&conn, &transaction_id, None, 2).unwrap();
        let epochs_after_replan =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        assert_eq!(epochs_after_replan.len(), 2);
        // Named per epoch, and per the phase each was actually left in, on
        // purpose. This used to assert `all(|e| e.phase == Blocked)`, which
        // reads as "a replan settles everything" -- the over-broad sweep
        // this file's sibling module was later found to be performing, and
        // which loses data when the leftover set includes an epoch whose
        // placement already committed (see `resolution_planning::tests::
        // a_committed_epoch_under_a_blocked_parent_survives_a_replan`). Both
        // epochs here are pre-commit leftovers -- "a.txt" reached
        // `PreparedArtifact` and "b.txt" was blocked by its own failed
        // prepare -- so the sweep is correct for exactly these two, and
        // asserting them individually says that rather than the general
        // claim the blanket assertion made.
        let by_path =
            |path: &str| epochs_after_replan.iter().find(|e| e.target_path == path).unwrap().phase;
        assert_eq!(
            by_path("a.txt"),
            EpochState::Blocked,
            "the PreparedArtifact leftover a replan supersedes is a pre-commit state, and must be \
             settled: {epochs_after_replan:?}"
        );
        assert_eq!(
            by_path("b.txt"),
            EpochState::Blocked,
            "the epoch whose own prepare failed was already Blocked before the replan: \
             {epochs_after_replan:?}"
        );
        let replanned =
            filesystem_transaction::lookup_transaction(&conn, &transaction_id).unwrap().unwrap();
        assert_eq!(replanned.phase, TransactionPhase::Planning);

        // Redo both placements, this time with correct content, under the
        // replanned generation and a fresh pair of epoch numbers.
        let redo_slices = slice_plan(
            replanned.plan_revision,
            &[group_a, group_b],
            &bounds,
            |_| 9,
        );
        assert_eq!(redo_slices.len(), 1);
        let redo_slice = &redo_slices[0];
        let io_a2 = io_for(
            dir.path(),
            &parent,
            "a.txt",
            &capabilities,
            b"content-a",
            version_hash_for(b"content-a"),
        );
        let io_b2 = io_for(
            dir.path(),
            &parent,
            "b.txt",
            &capabilities,
            b"content-b",
            version_hash_for(b"content-b"),
        );
        let mut redo_io_map = HashMap::new();
        redo_io_map.insert("a.txt".to_string(), io_a2);
        redo_io_map.insert("b.txt".to_string(), io_b2);
        let redo_request = RunSliceRequest {
            group_id,
            transaction_id: &transaction_id,
            next_epoch: 2,
            expected_execution_generation: replanned.execution_generation,
            slice: redo_slice,
            io: &redo_io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store: &store,
            gate: &gate,
            emitter: &em,
            capture_auth: &AlwaysAuthorized,
            revalidation: empty_scope_revalidation(
                replanned.execution_generation,
                replanned.plan_revision,
            ),
        };
        let redo_result = run_slice_unchecked(&mut conn, &redo_request, 3);
        assert!(redo_result.is_ok(), "the redone slice must succeed: {redo_result:?}");

        let final_epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        assert_eq!(final_epochs.len(), 4, "two leftover epochs plus two fresh ones");
        for epoch in final_epochs.iter().filter(|e| e.epoch >= 2) {
            assert_eq!(
                epoch.phase,
                EpochState::Completed,
                "the redone placement must reach the epoch machine's terminal success state: \
                 {epoch:?}"
            );
        }

        // The load-bearing assertion: every epoch this transaction ever
        // allocated -- including the two `Blocked` leftovers from the
        // failed attempt -- is now terminal, so the parent-completion
        // invariant in `set_transaction_phase_unchecked` lets it through.
        for (phase, at) in [
            (TransactionPhase::Committing, 4),
            (TransactionPhase::AsyncPreservation, 5),
            (TransactionPhase::Completed, 6),
        ] {
            filesystem_transaction::set_transaction_phase_unchecked(
                &conn,
                &transaction_id,
                replanned.execution_generation,
                phase,
                None,
                at,
            )
            .unwrap();
        }
        let completed =
            filesystem_transaction::lookup_transaction(&conn, &transaction_id).unwrap().unwrap();
        assert_eq!(completed.phase, TransactionPhase::Completed);
    }

    // =================================================================
    // The §6.2 commit boundary
    // =================================================================

    /// Runs one slice over `paths` with a caller-supplied revalidation, so a
    /// test can script what §6.2 step 3 sees at the boundary. Mirrors
    /// `run_one` in every other respect.
    #[allow(clippy::too_many_arguments)]
    fn run_slice_with_revalidation(
        conn: &mut Connection,
        dir: &Path,
        group_id: &str,
        transaction_id: &str,
        paths: &[(&str, &[u8])],
        capabilities: &FilesystemSafetyCapabilities,
        parent: &ParentDirHandle,
        store: &FsBlockStore,
        gate: &BlockLivenessGate,
        em: &ChangeEmitter,
        revalidation: SliceRevalidation<'_>,
    ) -> Result<Vec<PlacementOutcome>, OrchestratorError> {
        let mut groups = Vec::new();
        let mut io_map = HashMap::new();
        for (path, content) in paths {
            let (group, version, _target) = placement(group_id, path, content);
            groups.push(group);
            io_map.insert(
                path.to_string(),
                io_for(dir, parent, path, capabilities, content, version),
            );
        }
        let bounds = SliceBounds {
            max_paths_per_slice: paths.len(),
            ..SliceBounds::default()
        };
        let slices = slice_plan(0, &groups, &bounds, |_g| 1);
        assert_eq!(slices.len(), 1, "the whole set must slice into exactly one slice");

        let request = RunSliceRequest {
            group_id,
            transaction_id,
            next_epoch: 0,
            expected_execution_generation: 0,
            slice: &slices[0],
            io: &io_map,
            capability_snapshot: b"caps-v1",
            durability_level: yadorilink_root_authority::fs_capabilities::DurabilityLevel::ProcessCrashSafe,
            adapter: &NativeCommitAdapter,
            store,
            gate,
            emitter: em,
            capture_auth: &AlwaysAuthorized,
            revalidation,
        };
        run_slice_unchecked(conn, &request, 0)
    }

    /// A frontier source reporting that every path it is asked about now has
    /// no heads at all — a real answer shape (a path resolved away), and one
    /// whose `desired_frontier_hash` cannot equal the plan's.
    struct FrontierMovedToNoHeads;
    impl SliceFrontierSource for FrontierMovedToNoHeads {
        fn current_frontier(
            &self,
            _conn: &Connection,
            paths: &[String],
        ) -> Result<Vec<PathFrontier>, SyncError> {
            Ok(paths.iter().map(|p| PathFrontier { path: p.clone(), heads: Vec::new() }).collect())
        }
    }

    /// The whole point of the boundary. Preparation holds no reservation and
    /// may take
    /// minutes (§6.1); the frontier moves inside that window; the boundary
    /// is the first and only place that can see it, because it is the first
    /// moment the slice holds its reservations. Nothing may commit, and
    /// nothing may be left held.
    #[test]
    fn a_frontier_that_moved_during_preparation_aborts_the_slice_at_the_commit_boundary() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target.txt"), b"old content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);
        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        // The plan captured a frontier with a head for this path; the source
        // reports none. Same scope, different hash.
        let planned_frontier = vec![PathFrontier {
            path: "target.txt".to_string(),
            heads: vec![ChangeHash([9u8; 32])],
        }];
        let plan = FilesystemResolutionPlan {
            plan_revision: 0,
            frontier_hash: desired_frontier_hash(&planned_frontier).unwrap(),
            execution_generation: 0,
            groups: Vec::new(),
        };
        let scope = vec!["target.txt".to_string()];

        let result = run_slice_with_revalidation(
            &mut conn,
            dir.path(),
            group_id,
            &transaction_id,
            &[("target.txt", b"new content")],
            &caps(),
            &parent,
            &store,
            &gate,
            &em,
            SliceRevalidation { source: &FrontierMovedToNoHeads, plan: &plan, scope: &scope },
        );

        assert!(
            matches!(result, Err(OrchestratorError::PlanSuperseded { .. })),
            "a frontier that moved during preparation must refuse the slice, got {result:?}"
        );
        assert!(
            filesystem_transaction::list_reservations(&conn, &transaction_id).unwrap().is_empty(),
            "the refused slice must leave no reservation held -- acquisition and the refusal are \
             one transaction"
        );
        let epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        assert_eq!(epochs.len(), 1);
        assert_eq!(
            epochs[0].phase,
            EpochState::PreparedArtifact,
            "no epoch may advance past preparation once the boundary refuses"
        );
        assert_eq!(
            std::fs::read(dir.path().join("target.txt")).unwrap(),
            b"old content",
            "the superseded winner must not have been written"
        );
    }

    /// Sabotages the slice's second epoch from inside the boundary, at
    /// exactly the point §6.2 step 3 runs: after the reservations are
    /// inserted, before any epoch transitions. `Blocked` is a state
    /// `AwaitingReservation` is not reachable from, so the second epoch's
    /// transition fails its own legality/CAS check while the first has
    /// already advanced.
    struct BlocksTheSecondEpochMidBoundary {
        transaction_id: String,
    }
    impl SliceFrontierSource for BlocksTheSecondEpochMidBoundary {
        fn current_frontier(
            &self,
            conn: &Connection,
            _paths: &[String],
        ) -> Result<Vec<PathFrontier>, SyncError> {
            filesystem_transaction::transition_epoch_unchecked(
                conn,
                &self.transaction_id,
                1,
                0,
                EpochState::Blocked,
                &EpochUpdate::default(),
                7,
            )?;
            Ok(Vec::new())
        }
    }

    /// The other half of "one unit": a failure part-way through the epoch
    /// transitions rolls back the epochs that already transitioned AND the
    /// reservations acquired in the same breath.
    #[test]
    fn a_transition_failing_mid_slice_rolls_back_the_whole_boundary_including_reservations() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"old a").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"old b").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);
        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let plan = FilesystemResolutionPlan {
            plan_revision: 0,
            frontier_hash: desired_frontier_hash(&[]).unwrap(),
            execution_generation: 0,
            groups: Vec::new(),
        };
        let saboteur = BlocksTheSecondEpochMidBoundary { transaction_id: transaction_id.clone() };

        let result = run_slice_with_revalidation(
            &mut conn,
            dir.path(),
            group_id,
            &transaction_id,
            &[("a.txt", b"new a"), ("b.txt", b"new b")],
            &caps(),
            &parent,
            &store,
            &gate,
            &em,
            SliceRevalidation { source: &saboteur, plan: &plan, scope: &[] },
        );

        assert!(result.is_err(), "the second epoch's transition must fail, got {result:?}");
        assert!(
            filesystem_transaction::list_reservations(&conn, &transaction_id).unwrap().is_empty(),
            "a transition failing after the reservations were inserted must roll them back too"
        );
        let epochs =
            filesystem_transaction::list_epochs_for_transaction(&conn, &transaction_id).unwrap();
        assert_eq!(epochs.len(), 2);
        for epoch in &epochs {
            assert_eq!(
                epoch.phase,
                EpochState::PreparedArtifact,
                "epoch {} must be back where the boundary found it",
                epoch.epoch
            );
        }
        assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"old a");
        assert_eq!(std::fs::read(dir.path().join("b.txt")).unwrap(), b"old b");
    }

    /// A source that names a head no change in this group carries. The
    /// answer is not stale evidence, it is not evidence — refused rather
    /// than hashed and believed. This is what a caller cannot get past by
    /// inventing an answer.
    struct FrontierNamingAnUnknownHead;
    impl SliceFrontierSource for FrontierNamingAnUnknownHead {
        fn current_frontier(
            &self,
            _conn: &Connection,
            paths: &[String],
        ) -> Result<Vec<PathFrontier>, SyncError> {
            Ok(paths
                .iter()
                .map(|p| PathFrontier { path: p.clone(), heads: vec![ChangeHash([0xAB; 32])] })
                .collect())
        }
    }

    #[test]
    fn a_frontier_naming_a_head_this_group_never_admitted_is_refused_not_hashed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target.txt"), b"old content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);
        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        // Deliberately a plan whose captured hash MATCHES the invented
        // answer: without the admitted-change check this slice would sail
        // straight through as "still current".
        let invented = vec![PathFrontier {
            path: "target.txt".to_string(),
            heads: vec![ChangeHash([0xAB; 32])],
        }];
        let plan = FilesystemResolutionPlan {
            plan_revision: 0,
            frontier_hash: desired_frontier_hash(&invented).unwrap(),
            execution_generation: 0,
            groups: Vec::new(),
        };
        let scope = vec!["target.txt".to_string()];

        let result = run_slice_with_revalidation(
            &mut conn,
            dir.path(),
            group_id,
            &transaction_id,
            &[("target.txt", b"new content")],
            &caps(),
            &parent,
            &store,
            &gate,
            &em,
            SliceRevalidation { source: &FrontierNamingAnUnknownHead, plan: &plan, scope: &scope },
        );

        assert!(
            matches!(result, Err(OrchestratorError::FrontierNotAdmitted { ref path, .. })
                if path == "target.txt"),
            "a head this group never admitted must be refused, got {result:?}"
        );
        assert!(filesystem_transaction::list_reservations(&conn, &transaction_id)
            .unwrap()
            .is_empty());
    }

    /// A source answering about a narrower scope than it was asked about.
    struct FrontierAnsweringANarrowerScope;
    impl SliceFrontierSource for FrontierAnsweringANarrowerScope {
        fn current_frontier(
            &self,
            _conn: &Connection,
            _paths: &[String],
        ) -> Result<Vec<PathFrontier>, SyncError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn a_frontier_answer_about_a_narrower_scope_is_refused_rather_than_compared() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target.txt"), b"old content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);
        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        let plan = FilesystemResolutionPlan {
            plan_revision: 0,
            frontier_hash: desired_frontier_hash(&[]).unwrap(),
            execution_generation: 0,
            groups: Vec::new(),
        };
        let scope = vec!["target.txt".to_string()];

        let result = run_slice_with_revalidation(
            &mut conn,
            dir.path(),
            group_id,
            &transaction_id,
            &[("target.txt", b"new content")],
            &caps(),
            &parent,
            &store,
            &gate,
            &em,
            SliceRevalidation {
                source: &FrontierAnsweringANarrowerScope,
                plan: &plan,
                scope: &scope,
            },
        );

        assert!(
            matches!(result, Err(OrchestratorError::FrontierScopeChanged { .. })),
            "an answer about a different scope must be refused, not hashed, got {result:?}"
        );
        assert!(filesystem_transaction::list_reservations(&conn, &transaction_id)
            .unwrap()
            .is_empty());
    }

    /// §6.2 step 3 also revalidates the plan revision, and this one IS read
    /// fresh from the transaction's durable row rather than trusted from the
    /// plan value the caller passed.
    #[test]
    fn a_plan_revision_that_moved_during_preparation_refuses_the_slice() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target.txt"), b"old content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let mut conn = Connection::open_in_memory().unwrap();
        open_schema(&conn);
        let group_id = "g";
        let transaction_id = begin_tx(&conn, group_id);
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let gate = BlockLivenessGate::default();
        let em = emitter(1);

        // The plan believes it is revision 1; the row says 0.
        let plan = FilesystemResolutionPlan {
            plan_revision: 1,
            frontier_hash: desired_frontier_hash(&[]).unwrap(),
            execution_generation: 0,
            groups: Vec::new(),
        };

        let result = run_slice_with_revalidation(
            &mut conn,
            dir.path(),
            group_id,
            &transaction_id,
            &[("target.txt", b"new content")],
            &caps(),
            &parent,
            &store,
            &gate,
            &em,
            SliceRevalidation { source: &EmptyScopeFrontier, plan: &plan, scope: &[] },
        );

        assert!(
            matches!(result, Err(OrchestratorError::PlanSuperseded { .. })),
            "a plan revision that no longer matches the transaction must refuse, got {result:?}"
        );
        assert!(filesystem_transaction::list_reservations(&conn, &transaction_id)
            .unwrap()
            .is_empty());
    }
}
