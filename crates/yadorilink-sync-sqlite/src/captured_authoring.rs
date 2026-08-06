//! Captured authoring (design `preimage-capture.md` §11.2): turns a
//! retained preimage's single-pass classification into a signed change in
//! the group's causal history — the step that makes a retained preimage a
//! fact every device eventually sees, rather than bytes only this device
//! ever kept.
//!
//! # One classification, owned
//!
//! Authoring is split in two around a single owned classification:
//! [`prepare_captured_change_unchecked`] reads the retained preimage exactly
//! once and returns an opaque [`PreparedCapturedChange`];
//! [`admit_prepared_captured_change_unchecked`] consumes it by value and
//! turns it into the version row, operation, receipt, retention root and
//! signed change.
//!
//! The split exists because a caller needs the classification's
//! [`StabilityFingerprint`] *before* the change is authored (the retained
//! obligation's late-write record) and the authored change's version
//! identity *after* (the obligation's capture pairing). Given only one
//! entry point, an orchestrator had no choice but to classify the object
//! itself for the first value, leaving this module to classify it again for
//! the change -- and a stale descriptor writing between the two (a `rename`
//! moves a directory entry, not the object a writer already holds open)
//! published a change the obligation could then never be paired with, so the
//! retained bytes could never be deleted. See `orchestrator`'s "exactly one
//! classification per divergent placement".
//!
//! [`PreparedCapturedChange`] therefore exposes its fingerprint and version
//! hash and nothing else: no `source_path`, no [`Clone`], no method that
//! touches the filesystem. A second classification is not merely absent
//! downstream; nothing downstream holds anything to make one with.
//!
//! # Authorization is a candidate, not a stamp
//!
//! Admission takes a [`CandidateAuthorizationCoordinate`] and re-validates it
//! against this database before it becomes the [`ChangeAuth`] of a signed
//! change -- see `validate_candidate_authorization` for exactly what that
//! proves and what it cannot. The validation is the last thing that happens
//! before the change is built: everything database-derived (the receipt race
//! re-check, the `file_versions` row, conflict-copy derivation, the parent
//! Lamport lookup, parent/carrier validation) is already frozen by then, so
//! only the coordinate copy, the signature, the hash and the append follow
//! it.
//!
//! Three requirements, each load-bearing (design §11.2):
//!
//! - **One SQLite transaction.** [`admit_prepared_captured_change`] commits the new
//!   `file_versions` row, the appended change (`change_parents`/
//!   `group_heads`, via [`dag_store::emit_local_change_onto`]), the new
//!   `group_block_provenance` reference rows and this module's own
//!   idempotency receipt together, on one `rusqlite::Transaction` — a crash
//!   before commit leaves none of them, never a subset.
//! - **Parenting on the displaced generation's complete causal basis**, not
//!   the current group frontier — see [`DisplacedBasis`] and "why not
//!   `group_heads`" below.
//! - **Under the existing block liveness gate**
//!   ([`yadorilink_filesystem_sync::block_liveness::BlockLivenessGate`]) — this module reuses it
//!   rather than adding a second one; see "the gate" below.
//!
//! # Why not `group_heads`
//!
//! [`dag_store::emit_local_change`] parents a new change on the group's
//! *current* live heads — correct for an ordinary local edit, wrong here.
//! Captured content was displaced by a materialization that resolved a
//! specific, already-fixed frontier (`materialized_generation::
//! DiskGenerationBasis::causal_basis_id`); by the time the slow custody
//! queue gets around to authoring it, `group_heads` may have moved past
//! that frontier entirely. Parenting on the current frontier instead of the
//! generation's own basis would misrepresent this write as superseding
//! changes it never actually observed, or as concurrent with changes it
//! causally preceded. This module therefore calls the lower-level
//! [`dag_store::emit_local_change_onto`], which accepts explicit parents,
//! and resolves those parents from [`DisplacedBasis`] rather than from
//! `group_heads`.
//!
//! # Pruned parents are still valid parents
//!
//! Design §5.7: a change this replica has already compacted to a causal
//! stub remains a legitimate explicit parent. This module does nothing
//! special to support that — `emit_local_change_onto`'s own parent-presence
//! check (`retained_history_integrity::validate_present_parent_shape`)
//! already accepts a pruned stub exactly like a fully retained change (see
//! `has_change_or_pruned`), so a captured change parenting on a pruned
//! member of the displaced basis passes the same path an ordinary emit
//! does. See `a_pruned_parent_in_the_basis_is_still_accepted` below for the
//! proof.
//!
//! # Fail-closed on an unreconstructable basis
//!
//! Three distinct ways the displaced generation's basis can fail to
//! resolve, all refused before any change is signed or any block reference
//! written:
//!
//! - the generation's `causal_basis_id` itself was never interned (or its
//!   row is gone) — [`lookup_causal_basis_members`] returns `None`, and
//!   this module returns [`CapturedAuthoringError::DisplacedBasisUnresolved`]
//!   before touching the block store or the gate;
//! - the basis interns fine but names a member hash that is genuinely
//!   *missing* from this replica's history (neither retained nor pruned —
//!   distinct from the pruned case above) — `emit_local_change_onto` itself
//!   refuses with `SyncSqliteError::CorruptState`, propagated here as
//!   [`CapturedAuthoringError::Sync`], and nothing was written.
//! - the basis interns fine and resolves, but names *no members at all* —
//!   [`CapturedAuthoringError::DisplacedBasisEmpty`], see "empty bases are
//!   never legitimate here" below.
//!
//! Either way this module never authors a change against an incomplete
//! basis and hopes; see `a_missing_non_pruned_parent_is_refused` below.
//!
//! # Empty bases are never legitimate here
//!
//! [`intern_causal_basis`](crate::dag_store::intern_causal_basis) happily
//! interns an empty member set — a stable, real `basis_id` that
//! [`lookup_causal_basis_members`] resolves to `Some(vec![])`, not `None`.
//! That is correct for `intern_causal_basis` itself (an empty frontier is a
//! legitimate frontier for a group's genuine first-ever DAG activity), and
//! for [`crate::materialized_generation::record_materialized_generation`]'s
//! other callers in general — this module does not, and must not, change
//! that shared primitive's contract.
//!
//! For a *captured* change specifically, though, an empty basis can never
//! be correct. Captured authoring exists to describe bytes that a
//! materialization already displaced (see "why not `group_heads`" above) —
//! by the time this module runs, *something* has already causally moved
//! past the generation being captured, so a real predecessor exists. An
//! empty resolved basis therefore is not "this object genuinely had no
//! antecedent"; it means the generation's basis was recorded before there
//! was anything to record (interned before the recording device had
//! observed any DAG activity for this group, or a bookkeeping bug upstream
//! passed an empty frontier where the true one was non-empty). Authoring
//! against it would mint the captured change as a second, unparented root
//! of the group DAG at Lamport 1 — `emit_local_change_onto`'s
//! present-parent-shape validation special-cases an empty parent set to
//! expect exactly that, so nothing downstream rejects it structurally.
//! Causally that root sits *below* everything, including the change that
//! displaced it, rather than concurrent with it; path resolution reads it
//! as superseded, derives no conflict copy, and the captured bytes become
//! the retained artefact's only copy while the artefact itself goes on to
//! be swept once its grace period expires. This module refuses instead,
//! before the gate or any block I/O, in [`prepare_captured_change_unchecked`]
//! — the narrow fix, at the one call site that actually treats a basis as
//! causal parentage rather than as an opaque frontier value. Broadening the
//! refusal into `intern_causal_basis`/`lookup_causal_basis_members`
//! themselves would also reject `record_materialized_generation`'s other,
//! legitimate empty-basis callers (a plain materialization's own first
//! write into a virgin group, exercised directly with `&[]` today).
//!
//! What happens to the generation row already recorded with the empty
//! basis: nothing is deleted or mutated by this refusal, and the retained
//! preimage on disk is untouched — same as every other fail-closed path
//! above. But because interned bases are content-addressed and immutable,
//! retrying [`DisplacedBasis::Generation`] against the same
//! `causal_basis_id` resolves to the same empty member set and refuses
//! identically every time; this alone can never reclaim the row. Reclaiming
//! it means authoring against a *different*, correctly non-empty basis —
//! either the group's live frontier at the time capture finally runs
//! (treating the object as an ordinary new local write rather than a
//! captured one), or, once one successful capture exists for the
//! `retained_id` under some other basis, [`DisplacedBasis::PreviousCapture`]
//! chained on it. Deciding which and re-driving it is the custody/capture
//! caller's job, not this module's — out of scope here, same as the
//! all-pruned-basis case below was until its own fix landed.
//!
//! See `a_generation_recorded_with_an_empty_basis_is_refused_not_authored`
//! below.
//!
//! # All-pruned bases
//!
//! `dag_store`'s own `emit_change_with_derived_conflict_copies` computes the
//! new change's Lamport clock from `frontier_index::max_parent_lamport`,
//! which consults `pruned_changes` as well as `changes` — the same
//! pruned-aware view `validate_present_parent_shape`'s own Lamport check
//! uses immediately after, so the two agree even when every member of the
//! displaced basis is pruned. A basis composed *entirely* of pruned members
//! is reachable in practice, not merely hypothetical: a generation
//! materializes on frontier parent `P` at some Lamport clock; the DAG
//! advances past a checkpoint that prunes `P` (replacing it with a stub)
//! while its own, later frontier stays live; a *delayed* capture (this
//! module exists specifically to run late, off a slow custody queue) then
//! resolves the displaced generation's basis to `[P]` alone, wholly pruned.
//! `an_all_pruned_basis_is_authored_with_the_pruned_member_as_its_parent`
//! below exercises exactly that sequence and asserts it succeeds, keeping
//! `P` as the captured change's explicit parent.
//!
//! # Author identity
//!
//! The captured change's `device_id` is **this device** — the one running
//! captured authoring — never the device that originally wrote the
//! displaced generation. A `Change` is only ever valid if the device named
//! in it holds the Ed25519 key that signed it (`Change::verify_signature`);
//! there is no mechanism, and must never be one, for a device to author a
//! change "on behalf of" another device's identity. Concretely this means:
//! captured content is represented in the DAG as *this* device's own new
//! write, built on the causal basis the original object actually had. For
//! conflict resolution this is exactly the same shape as an ordinary local
//! edit made on top of a known frontier — Lamport/ancestry comparisons work
//! unchanged, because what matters for correctness is the *parents*
//! (accurately the displaced generation's basis), not which device happens
//! to hold the key that got around to publishing it.
//!
//! # Idempotency
//!
//! Captured authoring takes a caller-chosen `retained_id` — a
//! stable identifier for the retained preimage being captured (design
//! §5.5's `retained_preimages.retained_id`, once that table is wired by a
//! future change; this module's own `captured_authoring_receipts` table
//! keys on the same string today so it slots in without a rename). The
//! receipt row records not just `retained_id` but the exact
//! [`DisplacedBasis`] that produced it (`basis_causal_basis_id` /
//! `basis_previous_capture_hash`, exactly one set) *and* the
//! [`StabilityFingerprint`] of the content that basis was actually paired
//! with (`content_fingerprint`) — `retained_id` alone cannot tell two
//! different captures apart: two distinct retained objects given the same
//! id, or a legitimate later capture of the same object (a stale handle
//! writing again through its own fd), both need the second call to
//! actually run, not be silently satisfied by the first call's hash.
//! Declared basis alone is not enough either: a late write that changes
//! the retained object's bytes without moving the displaced generation's
//! own basis (the basis names a *causal frontier*, not a content hash) is
//! indistinguishable from a true retry if only `displaced_basis` is
//! compared — the same declared basis, honestly resubmitted, now describes
//! different bytes. [`check_existing_receipt`] reconciles the *declared*
//! basis from fields already in memory, cheaply, with no I/O — this alone
//! is enough to refuse an incompatible `PreviousCapture`/`Generation` or to
//! greenlight a genuinely new capture. But when the declared basis is
//! structurally identical to what is already recorded, that is only
//! grounds for suspecting a retry, not proof of one: [`author_captured_
//! change_unchecked`] then classifies the retained object anyway (under the
//! gate, same as an ordinary new capture would -- and it is the same single
//! classification, not an extra one) and compares the observed
//! [`StabilityFingerprint`] against the receipt's `content_fingerprint`
//! before trusting the stored hash. A mismatch there is refused as
//! [`CapturedAuthoringError::CapturedContentDivergedSinceReceipt`], not
//! silently answered with the earlier, now-stale hash — the caller must
//! re-drive the capture as `DisplacedBasis::PreviousCapture` chained on the
//! recorded hash, the same shape a deliberate later capture already
//! requires. This is the one place idempotency is no longer free: a
//! structurally-matching declared basis costs a real classification pass to
//! confirm, because "same declared basis" and "same content" are different
//! claims and only the second one is safe to trust. Two calls with the
//! same `retained_id`:
//!
//! 1. A durable receipt (`captured_authoring_receipts`) is checked *before*
//!    any I/O. If its basis does not structurally match the request's, the
//!    call is resolved immediately from that comparison alone (a refusal,
//!    or a green light to author a genuinely new/chained capture) — no
//!    classification needed. If its basis *does* structurally match, the
//!    call still classifies the retained object (see above) before
//!    deciding; this holds across a process restart, because the receipt
//!    is a committed SQLite row, not in-memory state.
//! 2. The write transaction itself is opened `BEGIN IMMEDIATE`
//!    ([`rusqlite::TransactionBehavior::Immediate`]), taking SQLite's
//!    writer lock before the transaction's own re-check of the receipt
//!    runs. This closes the narrow race the first check alone cannot: two
//!    calls racing on the same `retained_id` serialize on that lock, so the
//!    second transaction's re-check always observes the first's committed
//!    receipt (or the first transaction never committed at all, in which
//!    case there is nothing to collide with). A `SELECT` under a merely
//!    `DEFERRED` transaction would not provide this — SQLite would not
//!    escalate to the writer lock until the first write statement, by which
//!    point both transactions could have already read "not captured yet".
//!    The race re-check is content-aware the same way the fast check is:
//!    a structurally-matching basis is confirmed against the classification
//!    this call already computed before the transaction opened.
//!
//! A crash between the file's block writes (step: gate held,
//! `single_pass_capture::classify_single_pass`) and this transaction's
//! commit leaves no receipt row — by design (design §11.2: "A crash before
//! commit leaves the retained preimage available for re-chunking"). The
//! next retry re-reads the preimage from scratch; the blocks it writes are
//! content-addressed, so any blocks the crashed attempt already wrote are
//! harmless, unreferenced duplicates for the next GC pass, exactly as
//! `single_pass_capture`'s own module doc already describes for a mid-pass
//! read error.
//!
//! # Signing and §16 (keys not yet available)
//!
//! Captured authoring requires a real, keyed [`dag_store::
//! ChangeEmitter`] — there is no path that authors an unsigned or
//! placeholder-signed captured change. Design §16 describes recovery
//! running *before* keys are available; if a device displaces an object
//! (custody transfer, quiescence, classification) before its signing key is
//! loaded, this module simply must not be called yet for that retained
//! preimage. That is not a gap this module can or should paper over: the
//! alternative (signing with a placeholder key, or leaving the change
//! unsigned) would let an unauthorized-looking or forgeable change reach
//! the shared DAG. The retained preimage stays exactly as
//! `single_pass_capture`/custody transfer left it — safely retained on disk
//! — until a caller with real keys retries; nothing here forces a timeline
//! on when that happens, matching the `AwaitingCaptureAuthorization`
//! semantics design §16 already describes for policy unavailability (a
//! missing signing key is a stricter instance of the same "temporarily
//! cannot author yet" state, not a `LocalRecoveryOnly` failure).
//!
//! # The gate
//!
//! [`yadorilink_filesystem_sync::block_liveness::BlockLivenessGate`] is process-wide readers/
//! writer exclusion already used to keep physical block GC from deleting a
//! block a writer is in the middle of referencing. This module acquires
//! [`BlockLivenessGate::begin_reference_write`] once, before calling
//! `classify_single_pass` (which performs the block-store `put`s design
//! §11.2 requires to happen under the guard) and holds it for the entire
//! SQLite transaction that follows — including the `group_block_provenance`
//! reference-write — releasing it only after commit. No second gate is
//! introduced.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use yadorilink_filesystem_sync::block_liveness::{BlockLivenessGate, BlockReferenceWriteGuard};
use yadorilink_replica_domain::change::{ChangeAuth, Op, PutOrigin};
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath};
use crate::dag_store::{self, ChangeEmitter, RetentionClass};
use crate::error::SyncSqliteError;
use crate::filesystem_transaction;
use yadorilink_filesystem_sync::single_pass_capture::{
    classify_single_pass, SinglePassCaptureError, SinglePassClassification, StabilityFingerprint,
};

use std::path::Path;

use yadorilink_local_storage::BlockStore;

/// Retention-root owner tag this module registers under in
/// `dag_retention_roots` (design §5.6) — see [`register_retention_root`]'s
/// call in [`author_captured_change_unchecked`].
const RETENTION_OWNER_KIND: &str = "captured_authoring";

pub fn init_captured_authoring_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS captured_authoring_receipts (
            group_id                      TEXT NOT NULL,
            retained_id                   TEXT NOT NULL,
            captured_change_hash          BLOB NOT NULL,
            -- Exactly one of the next two columns is set, matching whichever
            -- `DisplacedBasis` variant actually produced `captured_change_hash`
            -- -- see the module doc's "idempotency" section and
            -- `ExistingReceipt`. This is what binds the receipt to the
            -- declared *causal frontier* that was captured.
            basis_causal_basis_id         TEXT,
            basis_previous_capture_hash   BLOB,
            -- The `StabilityFingerprint` of the content actually classified
            -- for `captured_change_hash` -- see the module doc's
            -- "idempotency" section. This is what binds the receipt to the
            -- *content* that was captured, not just the causal frontier it
            -- was captured against: a late write can leave the basis
            -- columns above unchanged while this column would not match a
            -- fresh classification.
            content_fingerprint           BLOB NOT NULL,
            created_at_unix_nanos         INTEGER NOT NULL,
            PRIMARY KEY (group_id, retained_id)
        );
        "#,
    )?;
    Ok(())
}

/// What a captured change's parents are drawn from — see the module doc's
/// "why not `group_heads`" section for why this is never the group's
/// current frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplacedBasis {
    /// The first divergent capture for this retained preimage (design §12):
    /// parents on the displaced generation's own complete causal basis,
    /// resolved from the interned `causal_basis_id`
    /// [`crate::materialized_generation::DiskGenerationBasis`] recorded for
    /// the path at materialization time.
    Generation { causal_basis_id: String },
    /// A later capture in the same retained preimage's late-write chain
    /// (design §12: "later captures parent on `last_captured_change_hash`"):
    /// parents on exactly the previous captured change.
    PreviousCapture(ChangeHash),
}

/// Everything one [`author_captured_change`] call needs. Borrowed rather
/// than owned since every field is either copied into the signed `Change`
/// or consumed synchronously within the call.
pub struct CapturedAuthoringRequest<'a> {
    /// Stable identity of the retained preimage being captured — the
    /// idempotency key. See the module doc's "idempotency" section.
    pub retained_id: &'a str,
    pub group_id: &'a str,
    /// The group-relative sync path this content is published at.
    pub path: &'a str,
    /// The retained preimage's current on-disk location — read exactly
    /// once, inside the gate, by `classify_single_pass`. It is deliberately
    /// not carried forward into [`PreparedCapturedChange`]: once preparation
    /// has classified the object, nothing downstream holds a pathname it
    /// could reclassify from.
    pub source_path: &'a Path,
    pub displaced_basis: DisplacedBasis,
}

/// Failure modes for [`author_captured_change`]/
/// [`author_captured_change_unchecked`].
#[derive(Debug)]
pub enum CapturedAuthoringError {
    /// [`filesystem_transaction::require_execution_enabled`] refused — only
    /// reachable through [`author_captured_change`], never through
    /// [`author_captured_change_unchecked`]. Also wraps any other
    /// store-level failure (DB I/O, an `emit_local_change_onto` refusal
    /// including a genuinely missing — not pruned — basis member; see the
    /// module doc's "fail-closed" section).
    Sync(SyncSqliteError),
    /// [`classify_single_pass`] refused the retained preimage — see
    /// [`SinglePassCaptureError`] for which reason.
    SinglePass(SinglePassCaptureError),
    /// `displaced_basis`'s `causal_basis_id` was never interned (or its row
    /// is gone): the displaced generation's basis cannot be reconstructed
    /// at all, distinct from an individual missing parent within a basis
    /// that *did* resolve. Refused before any block write or signing.
    DisplacedBasisUnresolved(String),
    /// `displaced_basis`'s `causal_basis_id` resolved, but names no members
    /// at all. See the module doc's "empty bases are never legitimate
    /// here" section for why this is always refused rather than authored
    /// as an unparented root. Refused before any block write or signing.
    DisplacedBasisEmpty(String),
    /// `displaced_basis` was [`DisplacedBasis::PreviousCapture`] naming a
    /// hash that is not this `retained_id`'s actual last captured change —
    /// either no capture has ever been recorded for it, or the caller
    /// supplied some other change hash from the group. `PreviousCapture`
    /// must chain on exactly the receipt's own `captured_change_hash`
    /// (design §12); any other hash claims causal descent from a change
    /// this retained preimage never actually observed, which is exactly the
    /// error the basis mechanism exists to prevent. Refused before any
    /// block write or signing.
    PreviousCaptureUnbound { group_id: String, retained_id: String, supplied: ChangeHash },
    /// `displaced_basis` was [`DisplacedBasis::Generation`] but this
    /// `retained_id` already has a receipt from a prior capture.
    /// `Generation` is defined (design §12) as the *first* divergent
    /// capture for a retained preimage; every capture after that must chain
    /// on the previous one via `PreviousCapture`. Two genuinely different
    /// retained objects that were (incorrectly) given the same
    /// `retained_id` would collide exactly here — refusing rather than
    /// silently returning the first object's hash, or silently
    /// re-authoring a second "first capture" under the same id, is what
    /// makes that collision loud instead of a silent lost write.
    GenerationAfterExistingCapture { group_id: String, retained_id: String },
    /// `displaced_basis` is structurally identical to what an existing
    /// receipt for this `retained_id` already recorded, but a fresh
    /// classification of the retained object's content does not match that
    /// receipt's `content_fingerprint`. Something wrote to the retained
    /// object again after the earlier capture without the declared basis
    /// moving — a late write, not a retry. Refused rather than answered
    /// with `previously_captured_change_hash`, the earlier, now-stale
    /// hash; the caller must re-drive this capture as
    /// `DisplacedBasis::PreviousCapture` chained on that hash, the same
    /// shape a deliberate later capture already requires. See the module
    /// doc's "idempotency" section.
    CapturedContentDivergedSinceReceipt {
        group_id: String,
        retained_id: String,
        previously_captured_change_hash: ChangeHash,
    },
    /// The [`CandidateAuthorizationCoordinate`] the caller's authorization
    /// source produced does not survive re-validation against this
    /// database's own retained history — see
    /// `validate_candidate_authorization` for exactly what is checked and
    /// what a check like this can and cannot prove. Refused after every
    /// other decision is frozen but *before* anything is signed, so nothing
    /// unauthorized reaches the DAG and the transaction rolls back whole.
    AuthorizationCoordinateRejected { group_id: String, reason: String },
}

impl From<SyncSqliteError> for CapturedAuthoringError {
    fn from(e: SyncSqliteError) -> Self {
        CapturedAuthoringError::Sync(e)
    }
}
impl From<rusqlite::Error> for CapturedAuthoringError {
    fn from(e: rusqlite::Error) -> Self {
        CapturedAuthoringError::Sync(SyncSqliteError::Sqlite(e))
    }
}
/// `SinglePassCaptureError` lives in `yadorilink-filesystem-sync` (moved
/// there in 7D-9C, before this module itself moved into this crate) and does
/// not wrap this crate's own `SyncSqliteError` -- its `Io`/`Storage`/`Hex`/
/// `Chunking` variants convert into `SyncSqliteError` here instead, at this
/// one boundary (`yadorilink-filesystem-sync` cannot depend back on this
/// crate, so the conversion cannot live any closer to the source). `Storage`
/// converts via `yadorilink_local_storage::StorageError`'s own
/// `SyncSqliteError` bridge. `NotARegularFile`/`ObjectChangedDuringCapture`
/// are this module's own semantics (no `SyncSqliteError` equivalent exists,
/// nor should one) and still route to `CapturedAuthoringError::SinglePass`
/// unchanged.
impl From<SinglePassCaptureError> for CapturedAuthoringError {
    fn from(e: SinglePassCaptureError) -> Self {
        match e {
            SinglePassCaptureError::Io(e) => CapturedAuthoringError::Sync(SyncSqliteError::Io(e)),
            SinglePassCaptureError::Storage(e) => {
                CapturedAuthoringError::Sync(SyncSqliteError::from(e))
            }
            SinglePassCaptureError::Hex(e) => CapturedAuthoringError::Sync(SyncSqliteError::Hex(e)),
            SinglePassCaptureError::Chunking(msg) => {
                CapturedAuthoringError::Sync(SyncSqliteError::Chunking(msg))
            }
            other @ (SinglePassCaptureError::NotARegularFile(_)
            | SinglePassCaptureError::ObjectChangedDuringCapture) => {
                CapturedAuthoringError::SinglePass(other)
            }
        }
    }
}

/// A durable receipt row, decoded: the change it produced, and the exact
/// [`DisplacedBasis`] that produced it. The basis is what lets a retry be
/// told apart from a genuinely different capture under the same
/// `retained_id` — see [`check_existing_receipt`] and the module doc's
/// "idempotency" section.
struct ExistingReceipt {
    change_hash: ChangeHash,
    basis: DisplacedBasis,
    /// The content this receipt's `change_hash` was actually authored from
    /// — see the module doc's "idempotency" section for why `basis` alone
    /// cannot tell a true retry from a late write that left the basis
    /// unchanged.
    content_fingerprint: StabilityFingerprint,
}

/// Raw columns of a `captured_authoring_receipts` row, as read before being
/// decoded into an [`ExistingReceipt`].
type RawReceiptRow = (Vec<u8>, Option<String>, Option<Vec<u8>>, Vec<u8>);

/// Durable idempotency check: has `retained_id` already been captured for
/// `group_id`, and under what basis? Read-only, run both before any work
/// starts (the fast path) and again as the first statement inside the write
/// transaction (the race close — see the module doc's "idempotency"
/// section). Cheap: one indexed row read, no re-read of the retained
/// preimage either here or in [`check_existing_receipt`] — telling a retry
/// apart from a different capture only ever compares the caller-supplied
/// [`DisplacedBasis`] against what is already durably recorded.
fn existing_receipt(
    conn: &Connection,
    group_id: &str,
    retained_id: &str,
) -> Result<Option<ExistingReceipt>, SyncSqliteError> {
    let row: Option<RawReceiptRow> = conn
        .query_row(
            "SELECT captured_change_hash, basis_causal_basis_id, basis_previous_capture_hash, \
                    content_fingerprint \
             FROM captured_authoring_receipts WHERE group_id = ?1 AND retained_id = ?2",
            rusqlite::params![group_id, retained_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((hash_bytes, basis_causal_basis_id, basis_previous_capture_hash, fingerprint_bytes)) =
        row
    else {
        return Ok(None);
    };
    let array: [u8; 32] = hash_bytes.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "captured_authoring_receipts.captured_change_hash for {group_id}/{retained_id} \
             is not 32 bytes"
        ))
    })?;
    let change_hash = ChangeHash(array);
    let basis = match (basis_causal_basis_id, basis_previous_capture_hash) {
        (Some(causal_basis_id), None) => DisplacedBasis::Generation { causal_basis_id },
        (None, Some(bytes)) => {
            let array: [u8; 32] = bytes.try_into().map_err(|_| {
                SyncSqliteError::CorruptState(format!(
                    "captured_authoring_receipts.basis_previous_capture_hash for \
                     {group_id}/{retained_id} is not 32 bytes"
                ))
            })?;
            DisplacedBasis::PreviousCapture(ChangeHash(array))
        }
        _ => {
            return Err(SyncSqliteError::CorruptState(format!(
                "captured_authoring_receipts row for {group_id}/{retained_id} must set exactly \
                 one of basis_causal_basis_id/basis_previous_capture_hash"
            )))
        }
    };
    let fingerprint_array: [u8; 32] = fingerprint_bytes.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "captured_authoring_receipts.content_fingerprint for {group_id}/{retained_id} is \
             not 32 bytes"
        ))
    })?;
    let content_fingerprint = StabilityFingerprint(fingerprint_array);
    Ok(Some(ExistingReceipt { change_hash, basis, content_fingerprint }))
}

/// What reconciling a caller's requested [`DisplacedBasis`] against whatever
/// receipt is already durably recorded resolves to — see
/// [`check_existing_receipt`].
enum ReceiptReconciliation {
    /// No existing receipt reconciles as a possible retry purely from its
    /// *declared* basis — safe to classify and, if genuinely new, author.
    /// Covers both a true first capture (no receipt at all) and a
    /// correctly-chained later capture (`PreviousCapture` bound to the
    /// real last capture).
    ProceedToClassify,
    /// The request's declared basis is structurally identical to an
    /// existing receipt's. This is grounds to *suspect* a retry, not proof
    /// of one — see the module doc's "idempotency" section: a late write
    /// can leave the declared basis unchanged while the content it names
    /// has moved on. The caller must classify the retained object and
    /// compare the result against `content_fingerprint` before trusting
    /// `change_hash`.
    SameDeclaredBasis { change_hash: ChangeHash, content_fingerprint: StabilityFingerprint },
}

/// Reconciles a caller's requested [`DisplacedBasis`] against whatever
/// receipt is already durably recorded for this `retained_id`, implementing
/// the `PreviousCapture` binding (defect: `PreviousCapture` accepted any
/// change hash in the group, not specifically this retained object's own
/// prior capture) from *declared basis* alone, with no I/O. This function by
/// itself cannot finish telling a true retry apart from a late write that
/// left the declared basis unchanged — see [`ReceiptReconciliation::
/// SameDeclaredBasis`] and the module doc's "idempotency" section for the
/// content check the caller must still perform in that case.
///
/// - [`ReceiptReconciliation::ProceedToClassify`]: the request is shaped
///   correctly to proceed — a genuine first (`Generation`) or chained
///   (`PreviousCapture`, correctly bound to the real last capture) new
///   capture. No matching declared basis exists, so there is nothing to
///   suspect a retry against.
/// - [`ReceiptReconciliation::SameDeclaredBasis`]: the declared basis
///   matches the recorded receipt's — possibly an idempotent retry,
///   possibly a late write; the caller must classify and compare content
///   before deciding.
/// - `Err`: the request cannot be reconciled with what is durably recorded
///   — either a `PreviousCapture` not bound to this retained_id's real
///   prior capture, or a `Generation` retried for a `retained_id` that
///   already has one under a different declared basis. Refuse rather than
///   silently doing the wrong thing.
fn check_existing_receipt(
    existing: Option<&ExistingReceipt>,
    displaced_basis: &DisplacedBasis,
    group_id: &str,
    retained_id: &str,
) -> Result<ReceiptReconciliation, CapturedAuthoringError> {
    if let Some(existing) = existing {
        if existing.basis == *displaced_basis {
            return Ok(ReceiptReconciliation::SameDeclaredBasis {
                change_hash: existing.change_hash,
                content_fingerprint: existing.content_fingerprint,
            });
        }
        return match displaced_basis {
            DisplacedBasis::PreviousCapture(hash) if *hash == existing.change_hash => {
                Ok(ReceiptReconciliation::ProceedToClassify)
            }
            DisplacedBasis::PreviousCapture(hash) => {
                Err(CapturedAuthoringError::PreviousCaptureUnbound {
                    group_id: group_id.to_string(),
                    retained_id: retained_id.to_string(),
                    supplied: *hash,
                })
            }
            DisplacedBasis::Generation { .. } => {
                Err(CapturedAuthoringError::GenerationAfterExistingCapture {
                    group_id: group_id.to_string(),
                    retained_id: retained_id.to_string(),
                })
            }
        };
    }
    match displaced_basis {
        DisplacedBasis::Generation { .. } => Ok(ReceiptReconciliation::ProceedToClassify),
        DisplacedBasis::PreviousCapture(hash) => {
            Err(CapturedAuthoringError::PreviousCaptureUnbound {
                group_id: group_id.to_string(),
                retained_id: retained_id.to_string(),
                supplied: *hash,
            })
        }
    }
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// A durable authorization coordinate a caller *claims* holds right now,
/// before this module has checked it against anything.
///
/// This is deliberately not a [`ChangeAuth`]. A source that hands back a
/// ready-made `ChangeAuth` is handing back trust: whatever it returns is
/// stamped into a signed change and nothing downstream re-derives it, so a
/// source that returns a constant (or this crate's own
/// [`ChangeAuth::PLACEHOLDER`]) silently reintroduces exactly the defect the
/// re-check exists to close, and only a doc comment stands in the way. The
/// captured-authoring side therefore takes a *candidate* — the three
/// coordinates a caller must be able to name — and re-validates it against
/// the database in `validate_candidate_authorization` before it is allowed
/// to become the [`ChangeAuth`] of a signed change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateAuthorizationCoordinate {
    /// The membership authorization sequence the caller claims to hold.
    pub auth_seq: u64,
    /// The group's authorization epoch the caller claims to be writing under.
    pub auth_epoch: u64,
    /// The policy-log head the caller claims to have pinned.
    pub policy_head_hash: [u8; 32],
}

/// Re-validates a [`CandidateAuthorizationCoordinate`] against the retained
/// history the captured change is actually about to parent on, and only then
/// turns it into the [`ChangeAuth`] that will be signed.
///
/// What this can prove, and what it cannot, stated plainly:
///
/// - **A placeholder coordinate is refused.** [`ChangeAuth::PLACEHOLDER`] is
///   the "no authorization known" stamp, and live admission's own
///   monotonicity rule (`authenticated_history`) deliberately *skips* every
///   check for it. A source returning it would therefore opt the whole
///   mechanism out with one constant. Refused here, before signing.
/// - **A coordinate pinning no policy-log head is refused** for the same
///   reason: a zero head hash names nothing a peer could ever judge the
///   change against.
/// - **The coordinate must be monotone against every retained parent this
///   change will name.** This is exactly the rule live admission and startup
///   re-authentication already enforce (a non-bootstrap child may never pin
///   an older `auth_seq`/`auth_epoch` than a parent, or a revoked writer
///   could replay an older, once-valid grant on a causally newer branch).
///   Checking it here means a captured change that would have been rejected
///   by every peer is refused before it is signed, rather than after it is
///   durably in this device's own DAG.
/// - **A coordinate identical to a parent's must pin that parent's policy
///   head.** The same `(seq, epoch)` naming two different policy heads is two
///   incompatible claims about one authorization state.
///
/// What it cannot prove: that the coordinate is the group's *current* one.
/// This crate has no policy log to compare against — the only durable
/// authorization state it holds is what retained changes pinned. So a
/// dishonest source returning a constant is caught the moment retained
/// history moves past that constant (every later capture in the group is
/// refused, loudly, and permanently until the source tells the truth), but a
/// constant that happens to sit at or above the group's real coordinate is
/// not distinguishable here. Closing that last gap needs the policy log
/// itself, which lives outside this crate. The cost of what *is* checked: one
/// row read and one decode per parent, inside the write transaction that is
/// about to append, so nothing can move between the check and the signature.
fn validate_candidate_authorization(
    conn: &Connection,
    group_id: &str,
    parents: &[ChangeHash],
    candidate: CandidateAuthorizationCoordinate,
) -> Result<ChangeAuth, CapturedAuthoringError> {
    let auth = ChangeAuth {
        auth_seq: candidate.auth_seq,
        auth_epoch: candidate.auth_epoch,
        policy_head_hash: candidate.policy_head_hash,
    };
    let reject = |reason: String| CapturedAuthoringError::AuthorizationCoordinateRejected {
        group_id: group_id.to_string(),
        reason,
    };
    if auth == ChangeAuth::PLACEHOLDER {
        return Err(reject(
            "the placeholder (all-zero) authorization coordinate is not a coordinate: live \
             admission skips every authorization check for it, so accepting it here would let \
             any source opt out of authorization entirely"
                .to_string(),
        ));
    }
    if candidate.policy_head_hash == [0u8; 32] {
        return Err(reject(
            "authorization coordinate pins no policy-log head; a peer would have nothing to \
             judge the captured change against"
                .to_string(),
        ));
    }
    for parent in parents {
        // A parent this replica has pruned to a stub carries no authorization
        // coordinate to compare against -- the stub keeps the Lamport/group
        // shape, not the auth stamp. That is the same boundary
        // `authenticated_history` treats as a compaction boundary rather than
        // a violation, so it constrains nothing here either.
        let Some(encoded) = dag_store::get_encoded(conn, parent)? else {
            continue;
        };
        let parent_change = yadorilink_replica_domain::change::Change::from_wire_bytes(&encoded).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "captured change's parent {} no longer decodes: {error}",
                parent.to_hex()
            ))
        })?;
        if candidate.auth_seq < parent_change.auth_seq
            || candidate.auth_epoch < parent_change.auth_epoch
        {
            return Err(reject(format!(
                "authorization coordinate {}/{} is older than retained parent {} at {}/{}; a \
                 change stamped with it would be rejected by every peer",
                candidate.auth_seq,
                candidate.auth_epoch,
                parent.to_hex(),
                parent_change.auth_seq,
                parent_change.auth_epoch,
            )));
        }
        if candidate.auth_seq == parent_change.auth_seq
            && candidate.auth_epoch == parent_change.auth_epoch
            && candidate.policy_head_hash != parent_change.policy_head_hash
            && parent_change.policy_head_hash != [0u8; 32]
        {
            return Err(reject(format!(
                "authorization coordinate {}/{} pins a different policy head than retained \
                 parent {} does at the same coordinate",
                candidate.auth_seq,
                candidate.auth_epoch,
                parent.to_hex(),
            )));
        }
    }
    Ok(auth)
}

/// The version a already-authored captured change actually writes at `path`
/// — read back from the change itself rather than re-derived from anything.
/// Used only on the retry/race paths, where the caller needs the *authored*
/// version identity to pair its obligation with and must not invent one from
/// a fresh classification.
fn version_written_at(
    conn: &Connection,
    change_hash: &ChangeHash,
    group_id: &str,
    path: &str,
) -> Result<yadorilink_replica_domain::ids::VersionHash, CapturedAuthoringError> {
    let Some(encoded) = dag_store::get_encoded(conn, change_hash)? else {
        return Err(CapturedAuthoringError::Sync(SyncSqliteError::CorruptState(format!(
            "captured_authoring_receipts names change {} for {group_id}, which this replica no \
             longer holds",
            change_hash.to_hex()
        ))));
    };
    let change = yadorilink_replica_domain::change::Change::from_wire_bytes(&encoded).map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "receipted captured change {} no longer decodes: {error}",
            change_hash.to_hex()
        ))
    })?;
    change
        .ops
        .iter()
        .find_map(|op| match op {
            Op::Put { path: op_path, version, .. } if op_path.as_str() == path => Some(*version),
            _ => None,
        })
        .ok_or_else(|| {
            CapturedAuthoringError::Sync(SyncSqliteError::CorruptState(format!(
                "receipted captured change {} writes nothing at {path:?}",
                change_hash.to_hex()
            )))
        })
}

/// The single classification of one retained preimage, plus everything
/// derived from it, held between [`prepare_captured_change_unchecked`] and
/// [`admit_prepared_captured_change_unchecked`].
///
/// Opaque on purpose. It exposes its [`fingerprint`](Self::fingerprint) and
/// [`version_hash`](Self::version_hash) — the two values the retained
/// obligation's own two records need — and nothing else. In particular it
/// does **not** expose `source_path`, is not [`Clone`], and offers no method
/// that reads the filesystem, so no downstream code holding one has anything
/// to reclassify *with*. Finalization consumes it by value, so the
/// classification that produced the fingerprint recorded against the
/// obligation is necessarily the same one that produced the authored change:
/// not "the second classification was removed", but "there is nothing left
/// to classify a second time".
///
/// Holds the [`BlockLivenessGate`] reference-write guard for its whole
/// lifetime, so the blocks it classified stay protected from physical GC from
/// the moment they were written until the transaction that references them
/// commits.
pub struct PreparedCapturedChange<'gate> {
    retained_id: String,
    group_id: String,
    path: String,
    displaced_basis: DisplacedBasis,
    parents: Vec<ChangeHash>,
    classification: SinglePassClassification,
    _write_guard: BlockReferenceWriteGuard<'gate>,
}

impl PreparedCapturedChange<'_> {
    /// The [`StabilityFingerprint`] of the content this capture classified —
    /// what `retained_obligation::record_late_write` must be given, so that
    /// the fingerprint the obligation records and the content the change
    /// publishes are the same observation.
    pub fn fingerprint(&self) -> StabilityFingerprint {
        self.classification.fingerprint
    }

    /// The version identity this capture will publish — what
    /// `retained_obligation::record_captured_change` must be given.
    pub fn version_hash(&self) -> yadorilink_replica_domain::ids::VersionHash {
        self.classification.file_version.version_hash
    }
}

/// What one captured change is, once it exists — whether this call authored
/// it or found it already authored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedAuthoringResult {
    pub change_hash: ChangeHash,
    /// The version the change at `change_hash` actually writes, read from
    /// that change, never re-derived.
    pub version_hash: yadorilink_replica_domain::ids::VersionHash,
    /// The content fingerprint bound to `change_hash` by its receipt.
    pub content_fingerprint: StabilityFingerprint,
}

/// The result of [`prepare_captured_change_unchecked`].
pub enum PrepareOutcome<'gate> {
    /// A durable receipt already covers this exact request and a fresh
    /// classification confirms the retained object's content has not moved
    /// since — a true retry. Nothing further to author, and nothing to
    /// finalize. The existing change's own version identity and fingerprint
    /// are handed back so the caller can still pair its obligation without
    /// inventing a classification.
    AlreadyAuthored(CapturedAuthoringResult),
    /// A genuinely new capture, classified exactly once and ready for
    /// [`admit_prepared_captured_change_unchecked`].
    Prepared(PreparedCapturedChange<'gate>),
}

/// Everything a captured change needs that comes from outside the write
/// transaction: the displaced generation's parents, and the one and only
/// classification of the retained preimage.
///
/// This is where the retained object is read. It is the *only* place in this
/// module that reads it — see [`PreparedCapturedChange`].
///
/// Behind [`filesystem_transaction::EXECUTION_ENABLED`]; see
/// [`prepare_captured_change_unchecked`] for the ungated core.
pub fn prepare_captured_change<'gate>(
    conn: &Connection,
    store: &dyn BlockStore,
    gate: &'gate BlockLivenessGate,
    request: CapturedAuthoringRequest<'_>,
) -> Result<PrepareOutcome<'gate>, CapturedAuthoringError> {
    filesystem_transaction::require_execution_enabled().map_err(|e| CapturedAuthoringError::Sync(SyncSqliteError::from(e)))?;
    prepare_captured_change_unchecked(conn, store, gate, request)
}

/// The ungated core of [`prepare_captured_change`] — see that function's doc
/// and the module doc for the full contract. Exists so this module's own
/// tests can drive real state while [`filesystem_transaction::
/// EXECUTION_ENABLED`] stays `false` for the whole of this phase, the same
/// split every other filesystem-transaction-engine module in this phase uses.
pub fn prepare_captured_change_unchecked<'gate>(
    conn: &Connection,
    store: &dyn BlockStore,
    gate: &'gate BlockLivenessGate,
    request: CapturedAuthoringRequest<'_>,
) -> Result<PrepareOutcome<'gate>, CapturedAuthoringError> {
    // Fast path: reconciled from the declared basis alone, no I/O, no gate.
    // `check_existing_receipt` refuses here, cheaply, a `PreviousCapture`
    // not bound to this retained_id's real last capture and a `Generation`
    // retried for a retained_id that already has one under a different
    // declared basis — see its doc comment. A structurally-matching
    // declared basis is not, by itself, proof of a retry (see the module
    // doc's "idempotency" section) — handled immediately below.
    let fast_path_receipt = existing_receipt(conn, request.group_id, request.retained_id)?;
    let fast_reconciliation = check_existing_receipt(
        fast_path_receipt.as_ref(),
        &request.displaced_basis,
        request.group_id,
        request.retained_id,
    )?;
    if let ReceiptReconciliation::SameDeclaredBasis { change_hash, content_fingerprint } =
        fast_reconciliation
    {
        // The declared basis alone says "maybe a retry". Classify the
        // retained object under the gate — same as an ordinary new capture
        // would — and compare the observed content against what the
        // existing receipt actually captured before trusting `change_hash`.
        // Neither outcome touches the write transaction: a confirmed retry
        // reports the existing change with nothing new written; a divergence
        // is refused before any block reference or DB row is written.
        let _write_guard = gate.begin_reference_write();
        let classification = classify_single_pass(store, request.source_path)?;
        if classification.fingerprint == content_fingerprint {
            let version_hash =
                version_written_at(conn, &change_hash, request.group_id, request.path)?;
            return Ok(PrepareOutcome::AlreadyAuthored(CapturedAuthoringResult {
                change_hash,
                version_hash,
                content_fingerprint,
            }));
        }
        return Err(CapturedAuthoringError::CapturedContentDivergedSinceReceipt {
            group_id: request.group_id.to_string(),
            retained_id: request.retained_id.to_string(),
            previously_captured_change_hash: change_hash,
        });
    }

    // From here `fast_reconciliation` is `ProceedToClassify`: a genuine
    // first capture, or a later capture correctly chained via
    // `PreviousCapture` — go author it.

    // Resolve parents from the displaced generation's basis BEFORE the gate
    // and BEFORE any block is read or written — an unresolvable basis must
    // refuse cheaply, not after paying for a full-file read. See the module
    // doc's "fail-closed on an unreconstructable basis" section.
    let parents: Vec<ChangeHash> = match &request.displaced_basis {
        DisplacedBasis::Generation { causal_basis_id } => {
            let members = dag_store::lookup_causal_basis_members(conn, causal_basis_id)?
                .ok_or_else(|| {
                    CapturedAuthoringError::DisplacedBasisUnresolved(causal_basis_id.clone())
                })?;
            if members.is_empty() {
                // See the module doc's "empty bases are never legitimate
                // here" section: an empty resolved basis would author this
                // change as a second, unparented DAG root instead of the
                // displaced generation's real predecessor.
                return Err(CapturedAuthoringError::DisplacedBasisEmpty(causal_basis_id.clone()));
            }
            members
        }
        DisplacedBasis::PreviousCapture(hash) => vec![*hash],
    };

    // The gate, held from the first block-store write through the end of
    // the transaction that references those blocks — see the module doc's
    // "the gate" section. It travels inside the returned
    // `PreparedCapturedChange`, so it is still held when finalization's own
    // transaction commits.
    let write_guard = gate.begin_reference_write();

    // THE classification. Not "the first" — the only one. Nothing downstream
    // is given a path to run a second.
    let classification: SinglePassClassification =
        classify_single_pass(store, request.source_path)?;

    Ok(PrepareOutcome::Prepared(PreparedCapturedChange {
        retained_id: request.retained_id.to_string(),
        group_id: request.group_id.to_string(),
        path: request.path.to_string(),
        displaced_basis: request.displaced_basis,
        parents,
        classification,
        _write_guard: write_guard,
    }))
}

/// Turns one [`PreparedCapturedChange`] into a signed, appended change with
/// its `file_versions` row, block-provenance rows, retention root and
/// idempotency receipt, all on one `BEGIN IMMEDIATE` transaction.
///
/// Behind [`filesystem_transaction::EXECUTION_ENABLED`]; see
/// [`admit_prepared_captured_change_unchecked`] for the ungated core.
pub fn admit_prepared_captured_change(
    conn: &mut Connection,
    emitter: &ChangeEmitter,
    authorization: CandidateAuthorizationCoordinate,
    prepared: PreparedCapturedChange<'_>,
) -> Result<CapturedAuthoringResult, CapturedAuthoringError> {
    filesystem_transaction::require_execution_enabled().map_err(|e| CapturedAuthoringError::Sync(SyncSqliteError::from(e)))?;
    admit_prepared_captured_change_unchecked(conn, emitter, authorization, prepared)
}

/// The ungated core of [`admit_prepared_captured_change`].
///
/// Consumes `prepared` by value: the classification it carries is used here
/// and cannot be used again, and there is no second one to disagree with it.
///
/// # What sits between authorization and admission
///
/// `authorization` is a *candidate* coordinate, not a trusted stamp (see
/// [`CandidateAuthorizationCoordinate`]). It is validated against this
/// database — inside the already-open `BEGIN IMMEDIATE` transaction, so
/// nothing can move underneath it — only after every other database-derived
/// decision this change depends on has already been made and frozen: the
/// receipt race re-check, the `file_versions` row, the conflict-copy
/// derivation, the parent Lamport lookup and the parent/carrier validation
/// (the last three inside [`dag_store::prepare_emission`]).
///
/// After `validate_candidate_authorization` returns, in order, and nothing
/// else: the validated coordinate is copied into the change, the
/// already-validated in-memory fields are assembled, the change is signed and
/// hashed, and it is appended with its companion rows. No filesystem read, no
/// block-store I/O, no policy-log replay, no parent lookup, no conflict
/// derivation, no unrelated SQL.
pub fn admit_prepared_captured_change_unchecked(
    conn: &mut Connection,
    emitter: &ChangeEmitter,
    authorization: CandidateAuthorizationCoordinate,
    prepared: PreparedCapturedChange<'_>,
) -> Result<CapturedAuthoringResult, CapturedAuthoringError> {
    let PreparedCapturedChange {
        retained_id,
        group_id,
        path,
        displaced_basis,
        parents,
        classification,
        _write_guard,
    } = prepared;

    // `BEGIN IMMEDIATE`: take the writer lock up front so the re-check
    // below is race-free against a concurrent call for the same
    // `retained_id` — see the module doc's "idempotency" section, point 2.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let race_receipt = existing_receipt(&tx, &group_id, &retained_id)?;
    match check_existing_receipt(race_receipt.as_ref(), &displaced_basis, &group_id, &retained_id) {
        Ok(ReceiptReconciliation::SameDeclaredBasis { change_hash, content_fingerprint }) => {
            // A concurrent caller committed a receipt with the identical
            // declared basis between preparation's read and taking the
            // writer lock. Confirm against the one classification this call
            // holds the same way preparation does: matching content means we
            // lost the race to the identical capture, so report the winner's
            // change (with the version that change itself writes, never this
            // call's own classification) and roll back — the blocks already
            // written to `store` are harmless, content-addressed duplicates.
            // Diverging content means two different writes now claim the
            // same declared basis; refuse rather than trust either one
            // silently.
            if classification.fingerprint == content_fingerprint {
                let version_hash = version_written_at(&tx, &change_hash, &group_id, &path)?;
                drop(tx);
                return Ok(CapturedAuthoringResult {
                    change_hash,
                    version_hash,
                    content_fingerprint,
                });
            }
            drop(tx);
            return Err(CapturedAuthoringError::CapturedContentDivergedSinceReceipt {
                group_id,
                retained_id,
                previously_captured_change_hash: change_hash,
            });
        }
        Ok(ReceiptReconciliation::ProceedToClassify) => {}
        Err(e) => {
            // A concurrent call recorded a receipt with a genuinely
            // different declared basis for this retained_id between
            // preparation's read and taking the writer lock; re-run the same
            // binding check against what is now durably there rather than
            // proceeding to author against a request that no longer
            // reconciles with it.
            drop(tx);
            return Err(e);
        }
    }

    dag_store::put_file_version(&tx, &group_id, &classification.file_version)?;

    let version_hash = classification.file_version.version_hash;
    let put_op =
        Op::Put { path: SyncPath(path.clone()), version: version_hash, origin: PutOrigin::Direct };
    // Everything the database has to say about this emission is derived and
    // validated here, before any authorization coordinate is asked for.
    let prepared_emission = dag_store::prepare_emission(
        &tx,
        &group_id,
        parents.clone(),
        vec![put_op],
        yadorilink_replica_domain::change::ChangePurpose::Ordinary,
        false,
    )?;

    // --- authorization: acquired and re-validated exactly here ---
    let auth = validate_candidate_authorization(&tx, &group_id, &parents, authorization)?;
    // --- from here: copy the coordinate in, sign, hash, append. Nothing else. ---
    let change = dag_store::admit_prepared_emission(&tx, prepared_emission, auth, emitter)?;
    let change_hash = change.compute_hash();

    let block_hashes: Vec<Vec<u8>> =
        classification.file_version.blocks.iter().map(|b| b.hash.0.clone()).collect();
    dag_store::record_group_block_provenance(&tx, &group_id, &block_hashes)?;

    // The newly authored change needs its full payload retained at least
    // until whatever consumes `retained_id`'s captured-authoring receipt
    // (a future retained-preimage lifecycle) decides otherwise; registering
    // is idempotent and additive, never a second definition of retention
    // (see design §5.6/§13).
    dag_store::register_retention_root(
        &tx,
        RETENTION_OWNER_KIND,
        &retained_id,
        &group_id,
        &change_hash,
        RetentionClass::FullPayload,
    )?;

    // `ON CONFLICT` (rather than plain `INSERT`) because a later capture in
    // the same retained_id's chain (`DisplacedBasis::PreviousCapture`)
    // legitimately replaces an existing row from an earlier capture of the
    // same retained object — `check_existing_receipt` above already
    // confirmed the request's basis reconciles with what was there.
    let (basis_causal_basis_id, basis_previous_capture_hash): (Option<&str>, Option<&[u8]>) =
        match &displaced_basis {
            DisplacedBasis::Generation { causal_basis_id } => {
                (Some(causal_basis_id.as_str()), None)
            }
            DisplacedBasis::PreviousCapture(hash) => (None, Some(&hash.0[..])),
        };
    tx.execute(
        "INSERT INTO captured_authoring_receipts \
         (group_id, retained_id, captured_change_hash, basis_causal_basis_id, \
          basis_previous_capture_hash, content_fingerprint, created_at_unix_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         ON CONFLICT (group_id, retained_id) DO UPDATE SET \
             captured_change_hash = excluded.captured_change_hash, \
             basis_causal_basis_id = excluded.basis_causal_basis_id, \
             basis_previous_capture_hash = excluded.basis_previous_capture_hash, \
             content_fingerprint = excluded.content_fingerprint, \
             created_at_unix_nanos = excluded.created_at_unix_nanos",
        rusqlite::params![
            group_id,
            retained_id,
            &change_hash.0[..],
            basis_causal_basis_id,
            basis_previous_capture_hash,
            &classification.fingerprint.0[..],
            now_unix_nanos(),
        ],
    )?;

    tx.commit()?;

    Ok(CapturedAuthoringResult {
        change_hash,
        version_hash,
        content_fingerprint: classification.fingerprint,
    })
}

/// Prepare-then-admit with nothing in between, for callers that have no
/// obligation to record against the classification and therefore nothing to
/// do between the two halves — see the module doc for the full contract.
/// Behind [`filesystem_transaction::EXECUTION_ENABLED`], the same shared gate
/// `custody_transfer`/`optimistic_placement` use, reused rather than a second
/// flag.
pub fn author_captured_change(
    conn: &mut Connection,
    store: &dyn BlockStore,
    gate: &BlockLivenessGate,
    emitter: &ChangeEmitter,
    authorization: CandidateAuthorizationCoordinate,
    request: CapturedAuthoringRequest<'_>,
) -> Result<CapturedAuthoringResult, CapturedAuthoringError> {
    filesystem_transaction::require_execution_enabled().map_err(|e| CapturedAuthoringError::Sync(SyncSqliteError::from(e)))?;
    author_captured_change_unchecked(conn, store, gate, emitter, authorization, request)
}

/// The ungated core of [`author_captured_change`].
pub fn author_captured_change_unchecked(
    conn: &mut Connection,
    store: &dyn BlockStore,
    gate: &BlockLivenessGate,
    emitter: &ChangeEmitter,
    authorization: CandidateAuthorizationCoordinate,
    request: CapturedAuthoringRequest<'_>,
) -> Result<CapturedAuthoringResult, CapturedAuthoringError> {
    match prepare_captured_change_unchecked(conn, store, gate, request)? {
        PrepareOutcome::AlreadyAuthored(result) => Ok(result),
        PrepareOutcome::Prepared(prepared) => {
            admit_prepared_captured_change_unchecked(conn, emitter, authorization, prepared)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_replica_domain::ids::FolderGroupId;
    use crate::dag_store::{emit_local_change, ChangeEmitter};
    use crate::materialized_generation::{self, DiskGenerationBasis, MaterializedObjectKind};
    use ed25519_dalek::SigningKey;
    use yadorilink_local_storage::FsBlockStore;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::dag_store::init_conflict_copy_provenance_schema(&c).unwrap();
        crate::dag_store::init_dag_schema(&c).unwrap();
        materialized_generation::init_materialized_generation_schema(&c).unwrap();
        init_captured_authoring_schema(&c).unwrap();
        c
    }

    fn emitter(seed: u8) -> ChangeEmitter {
        ChangeEmitter::new(format!("device-{seed}"), SigningKey::from_bytes(&[seed; 32]))
    }

    fn store(dir: &std::path::Path) -> FsBlockStore {
        FsBlockStore::new(dir).unwrap()
    }

    fn write_source(dir: &std::path::Path, name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    /// Seeds a displaced generation's causal basis by emitting one ordinary
    /// change on group "g" and interning `[that change]` as a basis under
    /// `materialized_generation::record_materialized_generation` — enough
    /// for `DisplacedBasis::Generation` to resolve against a real,
    /// multi-member-capable frontier the same way production would.
    fn seed_displaced_generation_basis(conn: &Connection, group_id: &str) -> (ChangeHash, String) {
        let em = emitter(1);
        let prior = emit_local_change(
            conn,
            group_id,
            vec![Op::Put {
                path: SyncPath("prior.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([9u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        // `emit_local_change` above needed a referenced version present to
        // pass its own structural checks only for admission (not emit) --
        // emit itself does not validate referenced versions, so no extra
        // seeding is required here beyond the change itself.
        let prior_hash = prior.compute_hash();
        let basis_id =
            dag_store::intern_causal_basis(conn, group_id, std::slice::from_ref(&prior_hash))
                .unwrap();
        (prior_hash, basis_id)
    }

    fn base_request<'a>(
        retained_id: &'a str,
        group_id: &'a str,
        path: &'a str,
        source_path: &'a std::path::Path,
        causal_basis_id: String,
    ) -> CapturedAuthoringRequest<'a> {
        CapturedAuthoringRequest {
            retained_id,
            group_id,
            path,
            source_path,
            displaced_basis: DisplacedBasis::Generation { causal_basis_id },
        }
    }

    /// A real, non-placeholder authorization coordinate for the ordinary
    /// tests. It has to be real: `validate_candidate_authorization` refuses
    /// `ChangeAuth::PLACEHOLDER` outright so that no source can opt out of
    /// authorization with a constant. It sits above the placeholder stamp the
    /// seeded parent changes carry, so monotonicity passes.
    const TEST_COORDINATE: CandidateAuthorizationCoordinate = CandidateAuthorizationCoordinate {
        auth_seq: 3,
        auth_epoch: 1,
        policy_head_hash: [5u8; 32],
    };

    /// Prepare-then-admit under [`TEST_COORDINATE`], reporting just the
    /// change hash -- the shape most tests below assert on.
    fn author(
        conn: &mut Connection,
        store: &dyn BlockStore,
        gate: &BlockLivenessGate,
        emitter: &ChangeEmitter,
        request: CapturedAuthoringRequest<'_>,
    ) -> Result<ChangeHash, CapturedAuthoringError> {
        author_captured_change_unchecked(conn, store, gate, emitter, TEST_COORDINATE, request)
            .map(|result| result.change_hash)
    }

    /// Full happy path: a real classified object produces a real change
    /// whose parents are exactly the displaced generation's basis members.
    #[test]
    fn captures_a_real_object_with_parents_equal_to_the_displaced_basis() {
        let mut c = conn();
        let (prior_hash, basis_id) = seed_displaced_generation_basis(&c, "g");
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"hello captured world");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(2);

        let req = base_request("retained-1", "g", "captured.bin", &src_path, basis_id);
        let hash = author(&mut c, &blk_store, &gate, &em, req).unwrap();

        assert!(dag_store::has_change(&c, &hash).unwrap());
        let parents = dag_store::parents_of(&c, &hash).unwrap();
        assert_eq!(
            parents,
            vec![prior_hash],
            "must parent on the displaced basis, not group_heads"
        );
        // group_heads moved on independently in the meantime -- proves this
        // did NOT parent on the current frontier.
        let heads = dag_store::group_heads(&c, "g").unwrap();
        assert!(heads.contains(&hash));
    }

    /// Group heads move (an unrelated concurrent local change lands) between
    /// when the displaced generation was recorded and when captured
    /// authoring finally runs; the captured change must still parent on the
    /// generation's own basis, never on the now-different `group_heads`.
    #[test]
    fn parents_on_the_displaced_basis_even_after_group_heads_moved_on() {
        let mut c = conn();
        let (prior_hash, basis_id) = seed_displaced_generation_basis(&c, "g");

        // An unrelated local change moves group_heads forward.
        let em1 = emitter(1);
        emit_local_change(
            &c,
            "g",
            vec![Op::Put {
                path: SyncPath("unrelated.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([7u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em1,
        )
        .unwrap();

        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"late capture content");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em2 = emitter(2);

        let req = base_request("retained-2", "g", "captured.bin", &src_path, basis_id);
        let hash = author(&mut c, &blk_store, &gate, &em2, req).unwrap();

        assert_eq!(dag_store::parents_of(&c, &hash).unwrap(), vec![prior_hash]);
    }

    /// A pruned parent within the displaced basis is still accepted as a
    /// valid explicit parent (design §5.7) -- no special handling in this
    /// module is required for it to pass; it comes for free from
    /// `emit_local_change_onto`'s own pruned-aware parent check.
    #[test]
    fn a_pruned_parent_in_the_basis_is_still_accepted() {
        let mut c = conn();
        // `prior` (lamport 1) and `child` (lamport 2, prior's descendant)
        // form a chain; the displaced generation's basis is the *pair* of
        // them -- `child` real-world-realistic (a basis's non-pruned
        // members always exist and dominate the pruned ones' lamport,
        // since a checkpoint only ever prunes a causally-below prefix of
        // its own retained frontier), `prior` pruned. Proves a pruned
        // member of a basis that also has a live member is accepted.
        let (prior_hash, _prior_only_basis) = seed_displaced_generation_basis(&c, "g");
        let em1 = emitter(1);
        let child = emit_local_change(
            &c,
            "g",
            vec![Op::Put {
                path: SyncPath("child.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([8u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em1,
        )
        .unwrap();
        let child_hash = child.compute_hash();
        let basis_id = dag_store::intern_causal_basis(&c, "g", &[prior_hash, child_hash]).unwrap();

        // A checkpoint at `child` prunes `prior` while keeping the
        // checkpoint frontier (`child`) retained intact -- `commit_prune`'s
        // own contract: the frontier changes stay, only hashes strictly
        // below it are pruned.
        let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
            FolderGroupId("g".into()),
            vec![child_hash],
            [0u8; 32],
        );
        {
            let tx = c.unchecked_transaction().unwrap();
            dag_store::commit_prune(&tx, &checkpoint, &[prior_hash]).unwrap();
            tx.commit().unwrap();
        }
        // `prior_hash` is now gone from `changes` -- only reachable through
        // its pruned stub -- while still a legitimate explicit parent.
        assert!(!dag_store::has_change(&c, &prior_hash).unwrap());
        assert!(dag_store::has_change_or_pruned(&c, "g", &prior_hash).unwrap());
        assert!(dag_store::has_change(&c, &child_hash).unwrap());

        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"pruned-parent content");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(3);

        let req = base_request("retained-3", "g", "captured.bin", &src_path, basis_id);
        let hash = author(&mut c, &blk_store, &gate, &em, req).unwrap();
        let mut parents = dag_store::parents_of(&c, &hash).unwrap();
        parents.sort();
        let mut expected = vec![prior_hash, child_hash];
        expected.sort();
        assert_eq!(parents, expected);
    }

    /// A member hash inside a resolvable basis that is genuinely missing
    /// from history (never admitted, never pruned) must refuse -- fail
    /// closed, never author against an incomplete basis.
    #[test]
    fn a_missing_non_pruned_parent_is_refused() {
        let mut c = conn();
        let phantom = ChangeHash([0x77; 32]);
        let basis_id =
            dag_store::intern_causal_basis(&c, "g", std::slice::from_ref(&phantom)).unwrap();

        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"orphaned basis content");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(4);

        let req = base_request("retained-4", "g", "captured.bin", &src_path, basis_id);
        let err = author(&mut c, &blk_store, &gate, &em, req).unwrap_err();
        assert!(matches!(err, CapturedAuthoringError::Sync(SyncSqliteError::CorruptState(_))));
        assert!(!dag_store::has_change(&c, &ChangeHash([0u8; 32])).unwrap()); // sanity
                                                                              // No partial state: nothing was appended for this attempt.
        let count: i64 = c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    /// A generation recorded with a `causal_basis_id` that resolves but
    /// names no members at all — the shape `materialized_generation::
    /// record_materialized_generation` produces if it is ever given a truly
    /// empty frontier for a path whose group is not actually new (see the
    /// module doc's "empty bases are never legitimate here" section) — must
    /// be refused, never authored as an unparented root, before any block
    /// is read.
    #[test]
    fn a_generation_recorded_with_an_empty_basis_is_refused_not_authored() {
        let mut c = conn();
        let recorded = materialized_generation::record_materialized_generation(
            &c,
            "g",
            "captured.bin",
            &[],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            0,
        )
        .unwrap();
        let DiskGenerationBasis { causal_basis_id, .. } = recorded;
        // Sanity: this really is the "resolves, to nothing" shape, distinct
        // from an unresolvable basis id.
        let members =
            dag_store::lookup_causal_basis_members(&c, &causal_basis_id.0).unwrap().unwrap();
        assert!(members.is_empty());

        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"empty-basis content");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(14);

        let req = base_request("retained-14", "g", "captured.bin", &src_path, causal_basis_id.0);
        let err = author(&mut c, &blk_store, &gate, &em, req).unwrap_err();
        assert!(matches!(err, CapturedAuthoringError::DisplacedBasisEmpty(_)), "{err:?}");
        // Refused before any change was appended -- not authored as an
        // unparented root.
        let count: i64 = c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 0);
        let receipts: i64 = c
            .query_row("SELECT COUNT(*) FROM captured_authoring_receipts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(receipts, 0);
    }

    /// A `causal_basis_id` that was never interned at all (a stronger
    /// failure than "resolves but names a missing member") is refused
    /// before any block is read.
    #[test]
    fn an_unresolvable_basis_id_is_refused_before_any_read() {
        let mut c = conn();
        let src_dir = tempfile::tempdir().unwrap();
        // Deliberately do not create the file: if this module tried to
        // read it before checking basis resolution, this test would fail
        // with an I/O error instead of `DisplacedBasisUnresolved`.
        let src_path = src_dir.path().join("never-written.bin");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(5);

        let req = base_request(
            "retained-5",
            "g",
            "captured.bin",
            &src_path,
            "g:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        );
        let err = author(&mut c, &blk_store, &gate, &em, req).unwrap_err();
        assert!(matches!(err, CapturedAuthoringError::DisplacedBasisUnresolved(_)));
    }

    /// Crash simulation: block writes happen (via `classify_single_pass`,
    /// which puts content-addressed blocks into `store` before this
    /// module's transaction even opens), then the transaction never
    /// commits (simulating a crash between the block writes and the change
    /// row). Nothing partial must survive: no receipt, no change, no
    /// `file_versions` row, no `group_block_provenance` row -- while the
    /// blocks themselves remain in `store`, exactly as design §11.2 says
    /// ("A crash before commit leaves the retained preimage available for
    /// re-chunking").
    #[test]
    fn a_crash_between_block_writes_and_the_change_row_leaves_nothing_partial() {
        let mut c = conn();
        let (_prior_hash, basis_id) = seed_displaced_generation_basis(&c, "g");
        let baseline_changes: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let content = b"crash-between-blocks-and-change-row";
        let src_path = write_source(src_dir.path(), "captured.bin", content);
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(6);

        // Manually replay this function's own steps up through the block
        // write and version computation, but stop before opening (and
        // therefore before committing) the transaction -- the crash point
        // design §11.2 names.
        let parents = dag_store::lookup_causal_basis_members(&c, &basis_id).unwrap().unwrap();
        assert!(!parents.is_empty());
        let classification = classify_single_pass(&blk_store, &src_path).unwrap();
        // The block(s) really did land in the content-addressed store.
        assert!(!classification.file_version.blocks.is_empty());
        for block in &classification.file_version.blocks {
            let hash_hex = hex::encode(&block.hash.0);
            blk_store.get(&hash_hex).unwrap();
        }
        // Deliberately never open/commit a transaction -- this stands in
        // for the crash.

        let count: i64 = c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(
            count, baseline_changes,
            "no change may exist after a crash before commit, beyond the seeded baseline"
        );
        let receipts: i64 = c
            .query_row("SELECT COUNT(*) FROM captured_authoring_receipts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(receipts, 0, "no receipt may exist after a crash before commit");
        let versions: i64 =
            c.query_row("SELECT COUNT(*) FROM file_versions", [], |r| r.get(0)).unwrap();
        assert_eq!(versions, 0, "no file_versions row may exist after a crash before commit");

        // The retained preimage is exactly as re-chunkable as before: a
        // fresh, real call over the same source now succeeds and produces
        // one clean change.
        let req = base_request("retained-6", "g", "captured.bin", &src_path, basis_id);
        let hash = author(&mut c, &blk_store, &gate, &em, req).unwrap();
        assert!(dag_store::has_change(&c, &hash).unwrap());
    }

    /// Retry after a durable success is idempotent: the same `retained_id`
    /// returns the same hash and does not append a second change, even
    /// against a fresh in-memory connection standing in for "the process
    /// restarted" (the receipt itself would be on the same durable SQLite
    /// file in production; a fresh `Connection` here only proves the
    /// decision doesn't depend on any of this module's in-process state --
    /// the real cross-restart guarantee is that the row lives in the one
    /// database file, exercised directly by reading the receipt back below).
    #[test]
    fn retrying_after_a_durable_success_is_idempotent_and_appends_nothing_new() {
        let mut c = conn();
        let (_prior_hash, basis_id) = seed_displaced_generation_basis(&c, "g");
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"idempotent content");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(7);

        let req1 = base_request("retained-7", "g", "captured.bin", &src_path, basis_id.clone());
        let hash1 = author(&mut c, &blk_store, &gate, &em, req1).unwrap();

        let count_after_first: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();

        let req2 = base_request("retained-7", "g", "captured.bin", &src_path, basis_id);
        let hash2 = author(&mut c, &blk_store, &gate, &em, req2).unwrap();

        assert_eq!(hash1, hash2);
        let count_after_second: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(
            count_after_first, count_after_second,
            "a retry after a durable success must not append a second change"
        );

        // The receipt itself is a real, durable row keyed by retained_id --
        // this is what makes idempotency survive a process restart, not
        // any in-memory cache.
        let receipt: Vec<u8> = c
            .query_row(
                "SELECT captured_change_hash FROM captured_authoring_receipts \
                 WHERE group_id = 'g' AND retained_id = 'retained-7'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(receipt, hash1.0.to_vec());
    }

    /// Regression test for the content-blind receipt defect: a late write to
    /// the retained object that leaves the *declared* basis unchanged must
    /// not be silently answered with the earlier capture's stale change
    /// hash. Before the fix, `check_existing_receipt` compared only
    /// `retained_id`/`group_id`/`displaced_basis` -- never anything derived
    /// from the retained object's content -- so this exact scenario (same
    /// `Generation` basis resubmitted after content changed underneath it)
    /// returned `hash1` here.
    #[test]
    fn a_late_write_that_leaves_the_declared_basis_unchanged_is_not_answered_with_the_stale_hash() {
        let mut c = conn();
        let (_prior_hash, basis_id) = seed_displaced_generation_basis(&c, "g");
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"first write");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(15);

        let req1 = base_request("retained-15", "g", "captured.bin", &src_path, basis_id.clone());
        let hash1 = author(&mut c, &blk_store, &gate, &em, req1).unwrap();
        let count_after_first: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();

        // A late write changes the retained object's content, but nothing
        // about the displaced generation's own causal basis changes -- the
        // caller (a naive crash-retry, unaware the object was written again)
        // resubmits the identical `DisplacedBasis::Generation`.
        std::fs::write(&src_path, b"late write through the same handle, different bytes").unwrap();
        let req2 = base_request("retained-15", "g", "captured.bin", &src_path, basis_id);
        let err = author(&mut c, &blk_store, &gate, &em, req2).unwrap_err();

        match err {
            CapturedAuthoringError::CapturedContentDivergedSinceReceipt {
                previously_captured_change_hash,
                ..
            } => {
                assert_eq!(
                    previously_captured_change_hash, hash1,
                    "must never be silently satisfied by hash1 as if it were correct"
                );
            }
            other => panic!("expected CapturedContentDivergedSinceReceipt, got {other:?}"),
        }

        // Refused before anything new was authored -- and, above all, the
        // stale hash was never returned as if it described the new content.
        let count_after_second: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(count_after_first, count_after_second);
        let receipt: Vec<u8> = c
            .query_row(
                "SELECT captured_change_hash FROM captured_authoring_receipts \
                 WHERE group_id = 'g' AND retained_id = 'retained-15'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(receipt, hash1.0.to_vec(), "the stale receipt must be left untouched");
    }

    /// The `EXECUTION_ENABLED`-gated entry point refuses while the shared
    /// filesystem-transaction-engine gate stays closed, without touching
    /// the connection at all.
    #[test]
    fn the_gated_entry_point_refuses_while_execution_is_disabled() {
        let mut c = conn();
        let (_prior_hash, basis_id) = seed_displaced_generation_basis(&c, "g");
        let baseline_changes: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"gated");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(8);

        let req = base_request("retained-8", "g", "captured.bin", &src_path, basis_id);
        let err = author_captured_change(&mut c, &blk_store, &gate, &em, TEST_COORDINATE, req)
            .unwrap_err();
        assert!(matches!(err, CapturedAuthoringError::Sync(SyncSqliteError::NotImplemented(_))));
        let count: i64 = c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(count, baseline_changes);
    }

    /// Sanity: a `DiskGenerationBasis` really does carry a `causal_basis_id`
    /// resolvable the same way [`DisplacedBasis::Generation`] resolves it --
    /// proves this module's basis lookup agrees with
    /// `materialized_generation`'s own recording path, not just with the
    /// hand-interned basis the other tests above use directly.
    #[test]
    fn resolves_the_same_basis_materialized_generation_actually_records() {
        let c = conn();
        let (prior_hash, _basis_id) = seed_displaced_generation_basis(&c, "g");
        let recorded = materialized_generation::record_materialized_generation(
            &c,
            "g",
            "captured.bin",
            std::slice::from_ref(&prior_hash),
            MaterializedObjectKind::RegularFile,
            None,
            None,
            0,
        )
        .unwrap();
        let DiskGenerationBasis { causal_basis_id, .. } = recorded;
        let members =
            dag_store::lookup_causal_basis_members(&c, &causal_basis_id.0).unwrap().unwrap();
        assert_eq!(members, vec![prior_hash]);
    }

    /// A later, legitimate capture of the same retained object -- a stale
    /// handle writing again through its own fd after the first capture --
    /// must actually run and produce a new change chained on the first
    /// capture, never be suppressed by the receipt as if it were a retry of
    /// the first call. Regression test for the receipt-binding defect:
    /// before the fix, the fast receipt check keyed on `retained_id` alone
    /// and would have returned the first call's hash here without ever
    /// looking at `displaced_basis`.
    #[test]
    fn a_later_chained_capture_is_not_suppressed_by_the_first_receipt() {
        let mut c = conn();
        let (_prior_hash, basis_id) = seed_displaced_generation_basis(&c, "g");
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"first write");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(9);

        let req1 = base_request("retained-9", "g", "captured.bin", &src_path, basis_id);
        let hash1 = author(&mut c, &blk_store, &gate, &em, req1).unwrap();

        // The stale handle writes new content to the same source path, then
        // the caller captures again, chaining explicitly on the first
        // capture -- not reusing `DisplacedBasis::Generation`.
        std::fs::write(&src_path, b"second write through a stale handle").unwrap();
        let req2 = CapturedAuthoringRequest {
            retained_id: "retained-9",
            group_id: "g",
            path: "captured.bin",
            source_path: &src_path,
            displaced_basis: DisplacedBasis::PreviousCapture(hash1),
        };
        let hash2 = author(&mut c, &blk_store, &gate, &em, req2).unwrap();

        assert_ne!(hash1, hash2, "the second write must produce its own new change");
        assert!(dag_store::has_change(&c, &hash2).unwrap());
        assert_eq!(
            dag_store::parents_of(&c, &hash2).unwrap(),
            vec![hash1],
            "must chain on the first capture, not the group frontier"
        );

        // The receipt now reflects the *latest* capture for this retained_id.
        let receipt: Vec<u8> = c
            .query_row(
                "SELECT captured_change_hash FROM captured_authoring_receipts \
                 WHERE group_id = 'g' AND retained_id = 'retained-9'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(receipt, hash2.0.to_vec());

        // A true retry of the second call (identical basis) is still
        // idempotent and appends nothing new.
        let count_after_second: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        let req2_retry = CapturedAuthoringRequest {
            retained_id: "retained-9",
            group_id: "g",
            path: "captured.bin",
            source_path: &src_path,
            displaced_basis: DisplacedBasis::PreviousCapture(hash1),
        };
        let hash2_retry = author(&mut c, &blk_store, &gate, &em, req2_retry).unwrap();
        assert_eq!(hash2_retry, hash2);
        let count_after_retry: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(count_after_second, count_after_retry);
    }

    /// Two genuinely different retained objects that were (incorrectly)
    /// given the same `retained_id` must not have the second one silently
    /// satisfied by the first one's receipt -- the harm the receipt-binding
    /// defect named: a caller that treats a wrongly-returned hash as
    /// success could release the second object's custody and lose its
    /// write. The second call here reuses `DisplacedBasis::Generation`
    /// (the only shape a genuinely distinct object's first capture could
    /// use) with a basis that does not match the first receipt's, and must
    /// be refused loudly instead.
    #[test]
    fn a_second_generation_capture_under_a_reused_retained_id_is_refused_not_silently_satisfied() {
        let mut c = conn();
        let (_prior_hash, basis_id_1) = seed_displaced_generation_basis(&c, "g");
        let src_dir = tempfile::tempdir().unwrap();
        let src_path_1 = write_source(src_dir.path(), "object-a.bin", b"object a content");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(10);

        let req1 = base_request("retained-shared", "g", "object-a.bin", &src_path_1, basis_id_1);
        let hash1 = author(&mut c, &blk_store, &gate, &em, req1).unwrap();

        // A different retained object, materialized on its own distinct
        // basis, mistakenly captured under the SAME `retained_id`.
        let em2 = emitter(1);
        let other_prior = emit_local_change(
            &c,
            "g",
            vec![Op::Put {
                path: SyncPath("other.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([11u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em2,
        )
        .unwrap();
        let other_prior_hash = other_prior.compute_hash();
        let basis_id_2 =
            dag_store::intern_causal_basis(&c, "g", std::slice::from_ref(&other_prior_hash))
                .unwrap();
        let src_path_2 = write_source(src_dir.path(), "object-b.bin", b"object b content");
        let req2 = base_request("retained-shared", "g", "object-b.bin", &src_path_2, basis_id_2);

        // Baseline captured only now, after all the setup above (including
        // `other_prior`'s own change) -- the refusal below must add nothing
        // further, not merely "nothing beyond setup".
        let count_after_first: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();

        let err = author(&mut c, &blk_store, &gate, &em, req2).unwrap_err();
        assert!(
            matches!(err, CapturedAuthoringError::GenerationAfterExistingCapture { .. }),
            "{err:?}"
        );
        // The first object's receipt is untouched -- still points at its
        // own change, not silently overwritten or reused for the second
        // object.
        let receipt: Vec<u8> = c
            .query_row(
                "SELECT captured_change_hash FROM captured_authoring_receipts \
                 WHERE group_id = 'g' AND retained_id = 'retained-shared'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(receipt, hash1.0.to_vec());
        let count_after_second: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(
            count_after_first, count_after_second,
            "refused before any block was read or any change authored"
        );
    }

    /// `PreviousCapture` must be bound to this retained_id's actual last
    /// capture, not merely to any change hash present in the group.
    /// Regression test for the causality-binding defect: before the fix,
    /// `PreviousCapture(hash)` for an unrelated, genuinely-present change
    /// hash passed every guard (`emit_local_change_onto` only checks that a
    /// parent is present and the Lamport shape is consistent) and produced
    /// a change claiming false causal descent.
    #[test]
    fn previous_capture_naming_an_unrelated_change_is_refused() {
        let mut c = conn();
        let (_prior_hash, basis_id) = seed_displaced_generation_basis(&c, "g");
        // A real, present change hash in the group that has nothing to do
        // with this retained object's own capture history.
        let em1 = emitter(1);
        let unrelated = emit_local_change(
            &c,
            "g",
            vec![Op::Put {
                path: SyncPath("unrelated.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([12u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em1,
        )
        .unwrap();
        let unrelated_hash = unrelated.compute_hash();

        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"first write");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(11);

        let req1 = base_request("retained-11", "g", "captured.bin", &src_path, basis_id);
        let _hash1 = author(&mut c, &blk_store, &gate, &em, req1).unwrap();

        let req2 = CapturedAuthoringRequest {
            retained_id: "retained-11",
            group_id: "g",
            path: "captured.bin",
            source_path: &src_path,
            displaced_basis: DisplacedBasis::PreviousCapture(unrelated_hash),
        };
        let err = author(&mut c, &blk_store, &gate, &em, req2).unwrap_err();
        match err {
            CapturedAuthoringError::PreviousCaptureUnbound { supplied, .. } => {
                assert_eq!(supplied, unrelated_hash);
            }
            other => panic!("expected PreviousCaptureUnbound, got {other:?}"),
        }
    }

    /// `PreviousCapture` naming a hash for a `retained_id` that has never
    /// been captured before (no receipt at all) must also be refused --
    /// there is no real prior capture for it to bind to.
    #[test]
    fn previous_capture_with_no_prior_receipt_is_refused() {
        let mut c = conn();
        let (prior_hash, _basis_id) = seed_displaced_generation_basis(&c, "g");
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"never captured before");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(12);

        let req = CapturedAuthoringRequest {
            retained_id: "retained-never-captured",
            group_id: "g",
            path: "captured.bin",
            source_path: &src_path,
            displaced_basis: DisplacedBasis::PreviousCapture(prior_hash),
        };
        let err = author(&mut c, &blk_store, &gate, &em, req).unwrap_err();
        assert!(matches!(err, CapturedAuthoringError::PreviousCaptureUnbound { .. }));
    }

    /// The re-validation that makes the authorization source honest: a
    /// coordinate older than one the retained parent already pinned is
    /// refused, before anything is signed. This is the rule live admission
    /// and startup re-authentication already enforce (a non-bootstrap child
    /// may never pin an older seq/epoch than a parent, or a revoked writer
    /// could replay an older, once-valid grant on a causally newer branch) --
    /// enforcing it here means such a change is never authored at all,
    /// rather than authored locally and rejected by every peer. It is also
    /// what a source answering with a constant eventually runs into: once
    /// retained history moves past the constant, every later capture in the
    /// group is refused.
    #[test]
    fn an_authorization_coordinate_older_than_a_retained_parent_is_refused() {
        let mut c = conn();
        // The parent this capture will name pins a coordinate strictly newer
        // than `TEST_COORDINATE`.
        let em1 = emitter(1);
        let prior = emit_local_change(
            &c,
            "g",
            vec![Op::Put {
                path: SyncPath("prior.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([21u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth { auth_seq: 9, auth_epoch: 4, policy_head_hash: [7u8; 32] },
            &em1,
        )
        .unwrap();
        let basis_id =
            dag_store::intern_causal_basis(&c, "g", std::slice::from_ref(&prior.compute_hash()))
                .unwrap();

        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"stale-coordinate content");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(16);
        let changes_before: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();

        let req = base_request("retained-16", "g", "captured.bin", &src_path, basis_id);
        let err = author(&mut c, &blk_store, &gate, &em, req).unwrap_err();
        assert!(
            matches!(err, CapturedAuthoringError::AuthorizationCoordinateRejected { .. }),
            "{err:?}"
        );
        let changes_after: i64 =
            c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(
            changes_before, changes_after,
            "nothing may be signed under a coordinate that failed re-validation"
        );
        let receipts: i64 = c
            .query_row("SELECT COUNT(*) FROM captured_authoring_receipts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(receipts, 0);
    }

    /// A displaced basis composed *entirely* of pruned members is reachable
    /// through a delayed capture -- the DAG advances past the frontier the
    /// displaced generation was materialized on, a checkpoint prunes it, and
    /// only then does the capture resolve its basis.
    ///
    /// This used to be refused permanently: the Lamport a change was SIGNED
    /// with was computed pruned-blind and came out as 1, while the validator
    /// that checked it immediately afterwards was pruned-aware and expected
    /// the parent's real, higher clock. Every retry resolved the same basis
    /// and failed identically, so the user's write stayed local forever. Two
    /// definitions of one value, disagreeing. The signing side is now
    /// pruned-aware too; this asserts the capture succeeds and keeps the
    /// pruned member as its explicit parent.
    #[test]
    fn an_all_pruned_basis_is_authored_with_the_pruned_member_as_its_parent() {
        let mut c = conn();
        // `prior` (lamport 1) is the sole member of `prior_only_basis` --
        // unlike `a_pruned_parent_in_the_basis_is_still_accepted`, no live
        // member is ever included in the basis actually used below.
        let (prior_hash, prior_only_basis) = seed_displaced_generation_basis(&c, "g");
        let em1 = emitter(1);
        let child = emit_local_change(
            &c,
            "g",
            vec![Op::Put {
                path: SyncPath("child.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([13u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em1,
        )
        .unwrap();
        let child_hash = child.compute_hash();

        // A checkpoint at `child` prunes `prior`, exactly as in
        // `a_pruned_parent_in_the_basis_is_still_accepted` -- the DAG has
        // advanced past the frontier the displaced generation was
        // materialized on.
        let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
            FolderGroupId("g".into()),
            vec![child_hash],
            [0u8; 32],
        );
        {
            let tx = c.unchecked_transaction().unwrap();
            dag_store::commit_prune(&tx, &checkpoint, &[prior_hash]).unwrap();
            tx.commit().unwrap();
        }
        assert!(!dag_store::has_change(&c, &prior_hash).unwrap());

        let src_dir = tempfile::tempdir().unwrap();
        let src_path = write_source(src_dir.path(), "captured.bin", b"all-pruned basis content");
        let store_dir = tempfile::tempdir().unwrap();
        let blk_store = store(store_dir.path());
        let gate = BlockLivenessGate::default();
        let em = emitter(13);

        // The displaced generation's own basis was interned back when
        // `prior` was still the live frontier -- exactly what a delayed
        // capture resolves against.
        let req = base_request("retained-13", "g", "captured.bin", &src_path, prior_only_basis);
        let captured = author(&mut c, &blk_store, &gate, &em, req).unwrap();

        assert_eq!(
            dag_store::parents_of(&c, &captured).unwrap(),
            vec![prior_hash],
            "the pruned member is still the explicit parent it always was"
        );
    }
}
