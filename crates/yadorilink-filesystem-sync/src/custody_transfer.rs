//! Custody transfer: moving a commit's displaced preimage into the engine's
//! retained custody by same-filesystem rename — never a copy.
//!
//! `CustodyTransferred` (design §8.1) is the epoch state after which
//! canonical-path exclusion is no longer required: ownership of the
//! displaced inode has moved to an independently recoverable retained
//! obligation (§8.2 step 16, §12). This module is that move.
//!
//! # Why rename, never copy
//!
//! A copy duplicates bytes — unbounded time and space for a large file,
//! directly violating the performance guarantee (design §1.5) that custody
//! work never blocks a canonical path — and it breaks the identity chain
//! the engine depends on: `retained_preimages.filesystem_identity` and the
//! late-write chaining in §12 both assume the retained object *is* the
//! displaced inode, not a fresh copy of its bytes. A copy would also leave
//! a window where the content exists twice, and would silently disconnect
//! any handle a stale external writer opened before displacement — exactly
//! the guarantee §1.4/§12 exist to keep ("the inode is moved by
//! same-filesystem rename, never copy, so old Unix handles continue to
//! reach the retained object"). A rename is atomic, constant-time and
//! identity-preserving; nothing here ever falls back to a copy for any
//! reason, including an unsupported or cross-filesystem destination — see
//! below.
//!
//! # Proving same filesystem, not hoping
//!
//! [`crate::reserved_namespace`][reserved_namespace] (design §10, via
//! [`yadorilink_root_authority::reserved_namespace`]) places every artefact
//! kind, including [`ArtefactKind::Retained`], directly beside its target —
//! "to guarantee the same filesystem" is the namespace's own stated reason
//! for that placement. This module leans on that architectural placement
//! structurally, not by convention: [`transfer_to_custody`] never accepts a
//! caller-supplied destination path. It only accepts the artefact `id`
//! already embedded in the preimage's own name, derives the Retained
//! artefact's name from it, and asks
//! [`ParentDirHandle::rename_child_no_replace`] — see that method's own
//! doc — to move the preimage into that name **under the same already-open
//! directory handle** the preimage itself lives in. Both the source and
//! destination names are resolved against one directory file descriptor in
//! a single `renameat`-family syscall, so the kernel can only ever place
//! the result inside that one directory, and therefore that one
//! filesystem. There is no path string naming a foreign directory for
//! either side to be redirected to, and no window between "checked same
//! filesystem" and "renamed" for a mount change to open one — this is a
//! structural guarantee, not a check performed and then trusted.
//!
//! `EXDEV` (the errno a genuine cross-filesystem rename fails with) is
//! still classified explicitly by `rename_child_no_replace`, never treated
//! as "rename failed for some reason, try copying instead". It is kept as
//! a defensive, fail-closed branch precisely because relying on that errno
//! *alone*, with no structural guarantee behind it, would still be an
//! incomplete proof: a remote/network filesystem's client-side rename() can
//! report success across what the OS reports as a single mount without
//! that necessarily being the atomic, constant-time, purely local operation
//! this module's callers require — the same local-vs-remote distinction
//! design §9.2 draws for `fsync`-like calls and
//! [`yadorilink_root_authority::fs_capabilities::DurabilityLevel::BestEffortRemoteFilesystem`].
//! Given the current architecture, where every artefact a transaction ever
//! names lives beside its target, that gap cannot actually open: there is
//! no second, independently-reachable custody root a rename could be asked
//! to cross into. It would open the moment a future phase generalized
//! `retained_preimages.custody_path` (design §5.5) to a location *not*
//! beside the target — flagged here explicitly so that generalization does
//! not silently reopen it by routing around this module's single-dirfd
//! discipline.
//!
//! # What happens when it is *not* the same filesystem
//!
//! It cannot be, for the reason above — but if [`ParentDirHandle::
//! rename_child_no_replace`] ever did report [`RenameChildError::
//! CrossFilesystem`] (or [`RenameChildError::UnsupportedOnThisVolume`], the
//! no-atomic-primitive case), this module surfaces
//! [`CustodyTransferError::CrossFilesystem`] /
//! [`CustodyTransferError::UnsupportedOnThisVolume`] and leaves the
//! preimage exactly where it was. Neither is retried automatically here
//! and neither ever degrades to a copy — the object is never lost (it
//! stays at its pre-transfer name, still inside the reserved namespace,
//! still excluded from ordinary indexing) and never duplicated. A caller
//! surfacing this to an operator treats it the same as any other `Blocked`
//! transaction state (design §14.4): retain and report, never guess.
//!
//! # Per-platform source location
//!
//! [`displaced_preimage_artefact_kind`] is the single place that encodes
//! `fs_commit`'s per-platform convention (see [`crate::fs_commit::
//! FilesystemCommitOutcome::Committed`]'s own doc): the atomic exchange
//! primitive leaves the displaced object at the stage artefact name on
//! Linux/macOS, and `ReplaceFileW` leaves it at the explicit backup
//! artefact name on Windows. [`transfer_to_custody`] takes only an
//! `artefact_id`, never a bare path or artefact kind, specifically so a
//! caller cannot pass the wrong one — the platform-specific kind is
//! resolved internally, the same way `early_physical_recovery::
//! expected_backup_path` derives the Windows backup name from the Stage
//! artefact's own id rather than trusting a separately threaded value.
//!
//! # Hardlinks and special objects (§11.1)
//!
//! The preimage is classified fresh, immediately before the rename is
//! attempted, using the exact same [`classify_replacement_eligibility`]
//! policy `fs_commit` already applies to the live/stage participants of an
//! ordinary commit — not a copy of that policy, the same function. A
//! preimage found hardlinked (`link_count > 1`, or a platform that could
//! not determine a link count at all) is refused with
//! [`CustodyIneligibleReason::Blocked`]`(`[`BlockedObjectReason::
//! HardlinkTopologyUnsupported`]`)` (or `UnknownHardlinkTopology`), exactly
//! like an ordinary replacement — this module does not silently break a
//! hardlink topology just because the object in question is already
//! displaced. FIFOs, sockets, device nodes and unresolved reparse points
//! are refused the same way `fs_commit` refuses them. A plain symlink is
//! eligible, matching design §11's classification model (a symlink's
//! *target* is part of what gets captured, not a reason to refuse it).
//!
//! Classifying fresh here — rather than trusting whatever the commit
//! adapter observed moments earlier — matters specifically because the
//! canonical path reservation is already released by the time custody
//! transfer runs (design §8.2 step 12 happens before step 16): between
//! commit and custody transfer, nothing prevents another process with
//! filesystem access from creating a new hard link onto the preimage's
//! reserved name, or otherwise changing its kind. This module does not
//! assume that window was empty; it re-observes and re-classifies.
//!
//! A directory is refused for a distinct reason
//! ([`CustodyIneligibleReason::DirectorySubtree`]), ahead of the shared
//! hardlink/special-object policy: non-empty directory replacement is not
//! yet a supported transaction kind at all (design §17), so a directory
//! reaching this module has no single-object retained-preimage
//! representation to be moved into in the first place — refusing it here
//! is this module's own scope boundary, not a restatement of §11.1's
//! policy.
//!
//! # Source swap between the check and the rename
//!
//! [`rename_child_no_replace`][`ParentDirHandle::rename_child_no_replace`]
//! is atomic and refuses to clobber the *destination* — but it says nothing
//! about the *source*. Nothing stops another local actor from renaming the
//! real preimage away and dropping a different, individually-eligible
//! object at `source_name` between this call's own classification read and
//! the rename syscall; `rename_child_no_replace` would then move that
//! substitute into custody and report success, leaving the object this
//! call actually classified displaced somewhere else, outside custody
//! entirely, its whereabouts unknown to this call.
//!
//! There is no atomic check-and-rename primitive here to close that window
//! outright — this module does not pretend otherwise. What it does instead
//! is hold an open handle on the source across the whole
//! check-then-rename sequence
//! ([`ParentDirHandle::open_child_no_follow`], opened only after
//! classification has already confirmed the object is a kind this call
//! will actually rename — see that method's own doc for why opening
//! anything else is unsafe) and re-derive identity from that handle
//! (`FileIdentity::observe_handle`) rather than by re-resolving the name a
//! second time. A handle's identity follows the inode it was opened
//! against, not whatever name currently points at that inode — so it is
//! the one observation in this function a rename of the *name* cannot
//! invalidate. After the rename, the object now observed at the
//! destination name is compared against that handle's identity: a match
//! proves the object that moved is the one this call verified; a mismatch
//! means a swap happened, surfaced as
//! [`CustodyTransferError::PostRenameIdentitySubstituted`] rather than
//! `Transferred` — a post-rename comparison detects the swap after the
//! fact, it does not prevent it, and this module says so rather than
//! implying otherwise.
//!
//! # No `EXECUTION_ENABLED` gate of its own
//!
//! Unlike the sync-sqlite/sync-core orchestration layer this module is
//! called from, [`transfer_to_custody`] performs no gate check itself —
//! matching [`crate::fs_commit`]'s own already-established pattern (the
//! commit primitive it delegates the actual exchange logic patterns from
//! is likewise ungated at this layer). The gate is the calling
//! orchestrator's responsibility, applied once before it drives the whole
//! placement sequence this call is one step of — see the "move note"
//! section below for why this module cannot hold that gate itself.
//!
//! # Not wired into a live production sequence yet
//!
//! [`transfer_to_custody`] has no *reachable* production call site in this
//! phase: its one caller, `yadorilink_daemon`'s commit-orchestration
//! `orchestrator::drive_captured_placement`, is itself still fully gated behind
//! `yadorilink_sync_sqlite::filesystem_transaction::EXECUTION_ENABLED`,
//! which is `false` for the whole of this phase — exercised only by this
//! module's own tests (through this function directly, the same seam
//! `optimistic_placement` and `filesystem_transaction` already use for
//! tests that must run with the orchestration gate closed).
//!
//! # Move note (7D-9D)
//!
//! Moved verbatim out of `yadorilink-sync-core` — the ledger's original
//! two-destination guess (`yadorilink-filesystem-sync` +
//! `yadorilink-root-authority`) did not survive contact with the actual
//! code: every line here is filesystem rename/identity logic already
//! calling *into* `yadorilink-root-authority` (a dependency this crate
//! already has, the same way `fs_commit` already does), never code that
//! itself belongs on `yadorilink-root-authority`. Everything belongs on
//! this one crate, the same "duplicate destinations don't survive a fresh
//! read" pattern `single_pass_capture.rs` and `retroactive_conflict.rs`
//! already established for this whole sub-phase.
//!
//! The one real change from the sync-core original: this module previously
//! exposed two public entry points, an outer `transfer_to_custody` gated
//! behind `yadorilink_sync_sqlite::filesystem_transaction::
//! require_execution_enabled`, and an inner, ungated `transfer_to_custody_
//! unchecked` that its one real caller (`orchestrator::
//! drive_captured_placement`, itself already gated) actually called. This
//! crate does not depend on `yadorilink-sync-sqlite` (`yadorilink-sync-sqlite`
//! depends on `yadorilink-filesystem-sync`, not the reverse — taking that
//! dependency here would be a cycle), so the outer gated wrapper could not
//! move verbatim. Rather than invent a second, crate-local gate no other
//! primitive at this layer has (`fs_commit` itself has never had one), the
//! two entry points collapsed into the one the real caller already used:
//! `transfer_to_custody` is now what was `transfer_to_custody_unchecked`,
//! ungated, exactly like `fs_commit`'s own commit primitive. The
//! sync-core-only `gated_entry_point_refuses_while_execution_is_disabled`
//! test (which exercised the now-removed outer wrapper) was removed with
//! it; the gate it tested is still enforced, just one layer up, by
//! `orchestrator::drive_captured_placement`'s own existing
//! `require_execution_enabled` call before it ever reaches this function —
//! unchanged behavior for the only real caller, nothing here weakens what
//! actually runs in production.

use std::ffi::OsStr;
use std::io;

#[cfg(test)]
use yadorilink_root_authority::fs_identity::TimestampGranularity;
use yadorilink_root_authority::fs_identity::{
    classify_replacement_eligibility, BlockedObjectReason, FileIdentity, IdentityComparison,
    ObjectKind, ReplacementEligibility,
};
use yadorilink_root_authority::reserved_namespace::{
    artefact_component_name, ArtefactKind, ArtefactNameError,
};
use yadorilink_root_authority::RootAuthorityError;

use crate::fs_commit::{ParentDirHandle, RenameChildError};

/// Where a displaced preimage lands immediately after a commit, before
/// custody transfer — see the module doc's "per-platform source location"
/// section.
fn displaced_preimage_artefact_kind() -> ArtefactKind {
    #[cfg(windows)]
    {
        ArtefactKind::Backup
    }
    #[cfg(not(windows))]
    {
        ArtefactKind::Stage
    }
}

/// The result of one [`transfer_to_custody`] call.
#[derive(Debug)]
pub enum CustodyTransferOutcome {
    /// The preimage was renamed into custody under this name, and this is
    /// its freshly observed identity at the new location — the same
    /// object, same inode, moved rather than duplicated (see
    /// [`FileIdentity::compare`] in this module's own tests for how that
    /// is proven, not merely asserted).
    ///
    /// `custody_identity` is boxed to keep this variant from dwarfing
    /// [`Self::NothingDisplaced`]'s zero-byte payload: `FileIdentity` grew a
    /// `symlink_target_digest: Option<[u8; 32]>` field (see its own doc),
    /// which is what pushed this enum over `clippy::large_enum_variant`'s
    /// threshold.
    Transferred { custody_name: String, custody_identity: Box<FileIdentity> },
    /// The commit this artefact id names displaced nothing (`fs_commit`'s
    /// `FilesystemCommitOutcome::Committed::preimage_identity` was `None`
    /// — the absent-destination path). Not an error: there is nothing to
    /// take into custody, and this is not the same thing as
    /// [`CustodyTransferError::ExpectedPreimageAbsent`] below, which means
    /// the *opposite*: the commit said something was displaced and this
    /// call could not find it.
    NothingDisplaced,
}

/// Why a fresh observation of the preimage refused custody transfer
/// outright, before any rename was attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyIneligibleReason {
    /// The same hardlink/special-object policy `fs_commit` applies to an
    /// ordinary replacement — see the module doc's "hardlinks and special
    /// objects" section.
    Blocked(BlockedObjectReason),
    /// A directory reached this module. Non-empty directory replacement is
    /// a distinct, not-yet-implemented transaction kind (design §17); this
    /// module has no single-object representation for a directory
    /// subtree's preimage.
    DirectorySubtree,
}

/// Failure modes for [`transfer_to_custody`].
#[derive(Debug)]
pub enum CustodyTransferError {
    /// The derived artefact name for `(kind, artefact_id)` is not
    /// constructible — see [`ArtefactNameError`].
    Name(ArtefactNameError),
    /// A fresh, pre-rename classification of the preimage refused it — see
    /// [`CustodyIneligibleReason`].
    Ineligible(CustodyIneligibleReason),
    /// The caller supplied `expected_preimage_identity: Some(_)` (the
    /// commit reported something was displaced) but nothing exists at the
    /// derived preimage location. This is a real inconsistency between
    /// what the commit reported and what is on disk now, not the ordinary
    /// "nothing was displaced" case — see [`CustodyTransferOutcome::
    /// NothingDisplaced`]'s doc for that distinction.
    ExpectedPreimageAbsent,
    /// The object freshly observed at the preimage location is not
    /// provably the same object `expected_preimage_identity` names —
    /// mirrors `fs_commit`'s own pre-commit stage-identity check, applied
    /// here at the custody-transfer boundary instead of the commit
    /// boundary. Covers both a proven substitution and an ambiguous
    /// comparison: this module never treats "cannot rule out reuse" as a
    /// pass.
    PreimageIdentityChanged,
    /// The preimage vanished (or was substituted, observed as `ENOENT`
    /// either re-opening it by name immediately after classification, or on
    /// the rename attempt itself) in the narrow window between this call's
    /// own classification read and the rename syscall. Kept distinct from
    /// [`Self::ExpectedPreimageAbsent`], which fires before any
    /// classification was even attempted.
    PreimageVanishedDuringTransfer,
    /// Something already exists at the derived Retained artefact name.
    /// Refused by the platform's own atomic no-replace primitive; nothing
    /// was touched. An artefact-shaped name with no owning journal row at
    /// this destination is exactly the collision
    /// [`RootAuthorityError::ReservedNamespaceCollision`] exists for —
    /// mirrors [`crate::fs_commit::CreateArtefactError::Collision`]'s own
    /// identical variant.
    Collision(RootAuthorityError),
    /// See the module doc's "proving same filesystem" and "what happens
    /// when it is not the same filesystem" sections. Never falls back to a
    /// copy.
    CrossFilesystem,
    /// This volume or platform has no atomic no-replace rename primitive
    /// wired up. Refused outright, same reasoning as [`Self::
    /// CrossFilesystem`].
    UnsupportedOnThisVolume,
    /// The rename call itself reported success, but the object now
    /// occupying the derived Retained artefact name is not provably the
    /// object this call's own pre-rename observation classified and
    /// verified — see the module doc's "source swap" section. Unlike every
    /// other error here, something *did* move: the custody slot is now
    /// occupied by an object this call never classified, and the object
    /// this call actually verified may now be anywhere else on the
    /// filesystem, no longer at the preimage name it was displaced to.
    ///
    /// This is not a state a caller may retry as though nothing happened,
    /// and never a success: a later retry of the same `artefact_id` would
    /// see the (now-occupied) Retained name and refuse with [`Self::
    /// Collision`], which is the correct signal to stop retrying blindly —
    /// but that later `Collision` on its own gives no indication that the
    /// object which caused it was never verified. A caller reaching this
    /// variant directly, at the point it actually happened, must treat it
    /// as an operator-visible inconsistency (design §14.4's `Blocked`
    /// class: retain and report, never guess) rather than a transient
    /// failure to reschedule.
    PostRenameIdentitySubstituted { custody_name: String },
    /// A real I/O failure unrelated to any of the above.
    Io(io::Error),
}

impl From<RenameChildError> for CustodyTransferError {
    fn from(e: RenameChildError) -> Self {
        match e {
            RenameChildError::Absent => CustodyTransferError::PreimageVanishedDuringTransfer,
            RenameChildError::Collision(err) => CustodyTransferError::Collision(err),
            RenameChildError::CrossFilesystem => CustodyTransferError::CrossFilesystem,
            RenameChildError::UnsupportedOnThisVolume => {
                CustodyTransferError::UnsupportedOnThisVolume
            }
            RenameChildError::Io(e) => CustodyTransferError::Io(e),
        }
    }
}

/// Moves the displaced preimage named by `artefact_id`, directly under
/// `parent_dir`, into retained custody by same-filesystem rename — see the
/// module doc for the full contract, including the "no `EXECUTION_ENABLED`
/// gate of its own" section: gating this call is the orchestrating
/// caller's responsibility, not this function's.
///
/// `expected_preimage_identity` is the identity `fs_commit`'s own commit
/// adapter observed for the preimage moments earlier
/// (`FilesystemCommitOutcome::Committed::preimage_identity`), required —
/// not optional in the sense of "trust whatever is there" — for the same
/// reason `fs_commit::CommitRequest::expected_stage_identity` is required:
/// without it, this call would rename whatever currently sits at the
/// preimage name into custody on nothing stronger than "an object of an
/// eligible kind is present", which is exactly the substitution-blind
/// shape `fs_commit`'s own pre-commit identity check exists to close, now
/// reopened one step later. `None` means the commit itself displaced
/// nothing; see [`CustodyTransferOutcome::NothingDisplaced`].
pub fn transfer_to_custody(
    parent_dir: &ParentDirHandle,
    artefact_id: &str,
    expected_preimage_identity: Option<&FileIdentity>,
) -> Result<CustodyTransferOutcome, CustodyTransferError> {
    transfer_to_custody_inner(parent_dir, artefact_id, expected_preimage_identity, || {})
}

/// Test-only seam: identical to [`transfer_to_custody`] except
/// `pre_rename_hook` runs after this call has opened and verified
/// `source_handle` (module doc's "source swap" section) but *before* the
/// rename syscall — the exact window the fix for that defect cannot close,
/// only detect. Exists so a test can provoke the real race deterministically
/// (swap the object at `source_name` for a different one from inside the
/// hook) and exercise the actual production comparison logic against it,
/// rather than re-implementing that logic a second time just to test it —
/// see `a_source_swapped_between_the_check_and_the_rename_is_detected_
/// not_silently_transferred` below.
#[cfg(test)]
pub(crate) fn transfer_to_custody_with_pre_rename_hook(
    parent_dir: &ParentDirHandle,
    artefact_id: &str,
    expected_preimage_identity: Option<&FileIdentity>,
    pre_rename_hook: impl FnOnce(),
) -> Result<CustodyTransferOutcome, CustodyTransferError> {
    transfer_to_custody_inner(parent_dir, artefact_id, expected_preimage_identity, pre_rename_hook)
}

fn transfer_to_custody_inner(
    parent_dir: &ParentDirHandle,
    artefact_id: &str,
    expected_preimage_identity: Option<&FileIdentity>,
    pre_rename_hook: impl FnOnce(),
) -> Result<CustodyTransferOutcome, CustodyTransferError> {
    let Some(expected) = expected_preimage_identity else {
        return Ok(CustodyTransferOutcome::NothingDisplaced);
    };

    let source_name = artefact_component_name(displaced_preimage_artefact_kind(), artefact_id)
        .map_err(CustodyTransferError::Name)?;
    let dest_name = artefact_component_name(ArtefactKind::Retained, artefact_id)
        .map_err(CustodyTransferError::Name)?;

    let source_path = parent_dir.path().join(&source_name);
    let observed = match FileIdentity::observe_path(&source_path) {
        Ok(identity) => identity,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(CustodyTransferError::ExpectedPreimageAbsent);
        }
        Err(e) => return Err(CustodyTransferError::Io(e)),
    };

    // Classification before identity, deliberately reversed from an earlier
    // version of this function: both checks below decide solely from
    // `observed`'s own freshly re-read kind and link count, never from
    // `expected`, so running them first cannot weaken what either one
    // proves — an object identity would have refused is refused for
    // exactly the same reason regardless of which check runs first. What
    // ordering *does* change is which error a caller sees when an object
    // fails both: a FIFO (or any other kind with no filesystem-resident
    // "content" a comparison can read — see `FileIdentity::compare`'s doc
    // on why that kind can genuinely reach `Ambiguous` even for the
    // literal same, untouched object on a coarse-clock Linux volume) would
    // otherwise be reported `PreimageIdentityChanged`, a real but strictly
    // less informative answer than "this is a FIFO, custody transfer never
    // accepts one" — and, unlike a FIFO, that identity-first ordering was a
    // functional bug for a symlink specifically: eligibility never
    // considers a symlink for anything a comparison would need to run
    // first to protect, so surfacing the more specific reason here first is
    // always at least as safe as identity-first, and strictly more useful.
    //
    // Directories are this module's own scope boundary (§17), checked
    // ahead of the shared hardlink/special-object policy below — see the
    // module doc.
    if observed.object_kind == ObjectKind::Directory {
        return Err(CustodyTransferError::Ineligible(CustodyIneligibleReason::DirectorySubtree));
    }
    if let ReplacementEligibility::Blocked(reason) =
        classify_replacement_eligibility(observed.object_kind, observed.link_count)
    {
        return Err(CustodyTransferError::Ineligible(CustodyIneligibleReason::Blocked(reason)));
    }

    // Identity next, exactly like `fs_commit::check_stage_identity_
    // matches_expected` — this closes the substitution race before this
    // call proceeds to open a handle and rename. Granularity is measured
    // here, not accepted as a parameter — see `fs_commit::platform::commit_
    // placement`'s identical call for why a caller-supplied value was the
    // actual shape of the defect this crate had to fix.
    let timestamp_granularity =
        yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(parent_dir.path());
    // Capability-split migration note: AMBIGUOUS. `expected` is
    // `expected_preimage_identity`, a caller-supplied parameter with two
    // distinct production origins: `orchestrator::drive_captured_placement`
    // passes the in-process `current_epoch.displaced_identity` moments
    // after a commit (same boot), while `early_physical_recovery::recover_
    // committed_custody_transfer` re-drives this same function after a
    // crash using the identical field read back from the database
    // (restart-spanning) — see `EpochState::Committed if epoch.displaced_
    // identity.is_some()` in that module. The object being displaced is
    // also not reliably engine-created: it is whatever was previously live
    // at this target path, which may be the very first, user-authored
    // version this engine ever placed a Stage artefact beside. Neither
    // "engine-owned" nor "same-boot" can be assumed at this call site.
    // Conservatively treated as depending on `stable_source_identity`.
    match observed.compare(expected, timestamp_granularity) {
        IdentityComparison::SameObject => {}
        IdentityComparison::DefinitelyDifferent | IdentityComparison::Ambiguous(_) => {
            return Err(CustodyTransferError::PreimageIdentityChanged);
        }
    }

    // Every kind that reaches this point is one this call is actually
    // about to rename (a plain regular file or a plain symlink — every
    // other kind already returned above), so it is safe to open now — see
    // `open_child_no_follow`'s own doc for why that matters. Held open
    // across the rename below, and never re-derived by path afterward: see
    // the module doc's "source swap" section for what this closes (proving
    // after the fact which object a rename actually moved) and what it
    // does not (preventing the swap itself — no atomic check-and-rename
    // primitive exists here).
    let source_handle = match parent_dir.open_child_no_follow(OsStr::new(&source_name)) {
        Ok(handle) => handle,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(CustodyTransferError::PreimageVanishedDuringTransfer);
        }
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            return Err(CustodyTransferError::UnsupportedOnThisVolume);
        }
        Err(e) => return Err(CustodyTransferError::Io(e)),
    };
    let held = FileIdentity::observe_handle(&source_handle).map_err(CustodyTransferError::Io)?;
    // Re-verify against the classification just above: this open is a
    // second, independent name resolution, so the same substitution this
    // function's very first identity check exists to catch could in
    // principle have landed again in the interim. Never trusted merely
    // because the classification already passed once.
    //
    // Capability-split migration note: AMBIGUOUS, though for a different
    // reason than the `observed`/`expected` check above. Both sides here
    // (`held` and `observed`) are read within this single function
    // invocation, milliseconds apart with no restart in between — exactly
    // the "one concrete opening" D1a's own decision text names for a
    // held-descriptor comparison, which would ordinarily point cleanly at
    // `stable_owned_marker_identity`'s same-boot predicate. What keeps it
    // from classifying unambiguously is the object, not the timing: the
    // preimage this function handles is not provably something the ENGINE
    // created — it is whatever was previously live at the target path
    // before this commit's exchange (rename) moved it under a reserved
    // name, which can be a user-authored file that predates the engine
    // entirely. `stable_owned_marker_identity` (and the V-D1b measurement
    // behind it) was established specifically for an object the engine
    // creates directly in the upper layer and never copies up; a renamed,
    // possibly lower-layer-originated object does not meet that
    // precondition merely by acquiring a reserved name. Conservatively
    // treated as depending on `stable_source_identity`.
    match held.compare(&observed, timestamp_granularity) {
        IdentityComparison::SameObject => {}
        IdentityComparison::DefinitelyDifferent | IdentityComparison::Ambiguous(_) => {
            return Err(CustodyTransferError::PreimageIdentityChanged);
        }
    }

    pre_rename_hook();

    parent_dir.rename_child_no_replace(OsStr::new(&source_name), OsStr::new(&dest_name))?;

    let custody_path = parent_dir.path().join(&dest_name);
    let custody_identity =
        FileIdentity::observe_path(&custody_path).map_err(CustodyTransferError::Io)?;
    // The proof this module's own doc promises: `held`'s identity is bound
    // to the inode this call opened by name before the rename ran, immune
    // to any rename of that name afterward. If the object now at the
    // destination name does not compare `SameObject` against `held`, the
    // rename moved something other than what this call verified — surfaced
    // as a distinct error, never folded into a successful `Transferred`.
    //
    // Capability-split migration note: same classification and same
    // reasoning as the `held.compare(&observed, ...)` check above — a
    // same-boot, held-descriptor comparison of an object whose engine
    // creation cannot be shown. Conservatively `stable_source_identity`.
    match custody_identity.compare(&held, timestamp_granularity) {
        IdentityComparison::SameObject => {}
        IdentityComparison::DefinitelyDifferent | IdentityComparison::Ambiguous(_) => {
            return Err(CustodyTransferError::PostRenameIdentitySubstituted {
                custody_name: dest_name,
            });
        }
    }

    Ok(CustodyTransferOutcome::Transferred {
        custody_name: dest_name,
        custody_identity: Box::new(custody_identity),
    })
}

/// Test-only helper: the artefact name custody transfer expects a preimage
/// at, for a given id — exposed so tests can stage a preimage at exactly
/// the name this module will look for, mirroring how a real commit would
/// have named it, without duplicating [`displaced_preimage_artefact_kind`]'s
/// platform split in every test.
#[cfg(test)]
fn preimage_source_name(artefact_id: &str) -> String {
    artefact_component_name(displaced_preimage_artefact_kind(), artefact_id).unwrap()
}

#[cfg(test)]
fn retained_custody_name(artefact_id: &str) -> String {
    artefact_component_name(ArtefactKind::Retained, artefact_id).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    // Only the hardlink test reads `nlink`; that concept has no portable
    // equivalent, so the import is gated with the test that uses it.
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    fn granularity() -> TimestampGranularity {
        // `Fine`, not `Coarse`: these tests compare two observations of
        // the *literal same, untouched* object taken microseconds apart
        // (once by the test setup, once inside `transfer_to_custody`
        // itself), with no `generation_or_usn` available on this platform
        // (macOS) to fall back on. `Coarse` would refuse to trust an equal
        // birth time as proof at all and turn every untouched-object happy
        // path into `Ambiguous` -- see `FileIdentity::compare`'s own doc.
        // This is *not* a safe choice for a test that substitutes the
        // object on a coarse-clock volume with no `generation_or_usn`
        // (overlayfs, measured): a substitution landing in the same clock
        // tick would then be wrongly trusted as `SameObject` instead of
        // correctly refused.
        // `a_substituted_preimage_is_refused_not_transferred` below uses
        // `probe_birth_time_granularity_for_test` instead, precisely
        // because it is the one test here that must detect a real
        // substitution rather than assume a happy path.
        TimestampGranularity::Fine
    }

    /// Real filesystem setup + assertion throughout: no hand-built
    /// `FileIdentity` values standing in for an actual commit's output.
    #[test]
    fn real_rename_into_custody_preserves_identity_across_the_move() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let artefact_id = "ep0";
        let source_name = preimage_source_name(artefact_id);
        let source_path = dir.path().join(&source_name);
        fs::write(&source_path, b"displaced content").unwrap();

        let expected = FileIdentity::observe_path(&source_path).unwrap();

        let outcome = transfer_to_custody(&parent, artefact_id, Some(&expected)).unwrap();

        let CustodyTransferOutcome::Transferred { custody_name, custody_identity } = outcome else {
            panic!("expected Transferred, got {outcome:?}");
        };
        assert_eq!(custody_name, retained_custody_name(artefact_id));

        // Identity is the SAME object, not merely "a file exists" at the
        // new name: `compare` must reach `SameObject`, never a bare
        // presence check.
        assert_eq!(
            custody_identity.compare(&expected, granularity()),
            IdentityComparison::SameObject
        );

        // A rename, not a copy: nothing left behind at the old name, and
        // the content moved with the object rather than being duplicated.
        assert!(!source_path.exists());
        let custody_path = dir.path().join(&custody_name);
        assert_eq!(fs::read(&custody_path).unwrap(), b"displaced content");
    }

    #[test]
    fn nothing_displaced_is_not_an_error_and_touches_no_artefact() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let outcome = transfer_to_custody(&parent, "ep0", None).unwrap();
        assert!(matches!(outcome, CustodyTransferOutcome::NothingDisplaced));
    }

    #[test]
    fn expected_preimage_absent_is_a_real_error_not_nothing_displaced() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        // A caller claims something was displaced, but nothing is at the
        // derived location -- a real inconsistency, not the ordinary
        // absent-destination path.
        let other = tempfile::tempdir().unwrap();
        fs::write(other.path().join("x"), b"x").unwrap();
        let bogus_expected = FileIdentity::observe_path(&other.path().join("x")).unwrap();

        let err = transfer_to_custody(&parent, "ep0", Some(&bogus_expected)).unwrap_err();
        assert!(matches!(err, CustodyTransferError::ExpectedPreimageAbsent));
    }

    #[test]
    fn a_substituted_preimage_is_refused_not_transferred() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let artefact_id = "ep0";
        let source_path = dir.path().join(preimage_source_name(artefact_id));

        // What the commit adapter claims it displaced...
        fs::write(&source_path, b"original").unwrap();
        let expected = FileIdentity::observe_path(&source_path).unwrap();

        // ...is not what is actually there anymore by the time custody
        // transfer runs: removed and recreated under the same name.
        fs::remove_file(&source_path).unwrap();
        fs::write(&source_path, b"substituted").unwrap();

        let err = transfer_to_custody(&parent, artefact_id, Some(&expected)).unwrap_err();
        // A brand-new inode on a coarse-clock volume is `DefinitelyDifferent`
        // whenever the platform can discriminate the reuse (birth time
        // differed, or a fresh generation counter is available) --
        // otherwise it is `Ambiguous`, and this module treats both exactly
        // alike: refused, never silently transferred.
        assert!(matches!(err, CustodyTransferError::PreimageIdentityChanged));
        // Nothing was touched: the (substituted) object is still at the
        // source name, not moved anywhere.
        assert!(source_path.exists());
    }

    /// Defect: `rename_child_no_replace` is atomic and refuses to clobber
    /// the *destination*, but says nothing about the *source* — nothing
    /// stops another local actor from renaming the real, already-classified
    /// preimage away and dropping a different, individually-eligible
    /// regular file at `source_name` in the narrow window between this
    /// call's own classification/open and the rename syscall. Provoked for
    /// real, through the actual production code path (via the pre-rename
    /// test hook, not a re-implementation of the check-then-rename logic):
    /// the hook performs exactly that swap — renames the real preimage
    /// aside and writes a different regular file at `source_name` — after
    /// `transfer_to_custody_inner` has already opened and verified the real
    /// object, but before the rename runs.
    #[test]
    fn a_source_swapped_between_the_check_and_the_rename_is_detected_not_silently_transferred() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let artefact_id = "ep0";
        let source_name = preimage_source_name(artefact_id);
        let source_path = dir.path().join(&source_name);
        fs::write(&source_path, b"the real, verified preimage").unwrap();
        let expected = FileIdentity::observe_path(&source_path).unwrap();

        let displaced_elsewhere = dir.path().join("displaced-by-the-racer.bin");
        let outcome =
            transfer_to_custody_with_pre_rename_hook(&parent, artefact_id, Some(&expected), || {
                // The race: the real object is renamed away (by another
                // local actor with filesystem access, standing in for a
                // second process/thread here), and a different regular
                // file is dropped at the exact name this call is about to
                // rename into custody.
                fs::rename(&source_path, &displaced_elsewhere).unwrap();
                fs::write(&source_path, b"a substitute the racer planted").unwrap();
            })
            .unwrap_err();

        let retained_name = retained_custody_name(artefact_id);
        assert!(
            matches!(
                &outcome,
                CustodyTransferError::PostRenameIdentitySubstituted { custody_name }
                    if *custody_name == retained_name
            ),
            "expected PostRenameIdentitySubstituted, got {outcome:?}"
        );

        // Something DID move -- the substitute is what actually landed in
        // custody, since the rename primitive only ever refuses a
        // colliding *destination*, never validates the source a second
        // time.
        let custody_path = dir.path().join(&retained_name);
        assert_eq!(fs::read(&custody_path).unwrap(), b"a substitute the racer planted");
        // The real, verified preimage is exactly where the racer left it in
        // this test -- in general, "wherever the racer moved it", which is
        // the point: this call can no longer find or retain it. Proves the
        // detection did not, and could not, undo the swap or recover the
        // real object; it only ever refuses to call this a success.
        assert_eq!(fs::read(&displaced_elsewhere).unwrap(), b"the real, verified preimage");
        // A caller that mistook this for `Transferred` would need to prove
        // that never happens: outcome is `Err`, never `Ok`, full stop.
    }

    // Unix-only: the object kind this exercises has no portable
    // constructor. The refusal logic it checks is platform-independent.
    #[cfg(unix)]
    #[test]
    fn a_hardlinked_preimage_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let artefact_id = "ep0";
        let source_path = dir.path().join(preimage_source_name(artefact_id));
        fs::write(&source_path, b"content").unwrap();
        // A second name for the same inode -- link_count becomes 2.
        fs::hard_link(&source_path, dir.path().join("extra_link")).unwrap();

        let expected = FileIdentity::observe_path(&source_path).unwrap();
        assert_eq!(expected.link_count, Some(2));

        let err = transfer_to_custody(&parent, artefact_id, Some(&expected)).unwrap_err();
        assert!(matches!(
            err,
            CustodyTransferError::Ineligible(CustodyIneligibleReason::Blocked(
                BlockedObjectReason::HardlinkTopologyUnsupported
            ))
        ));
        // Refused, not touched -- still at the source name, still linked.
        assert!(source_path.exists());
        assert_eq!(fs::metadata(&source_path).unwrap().nlink(), 2);
    }

    /// The object kind custody must refuse outright: a FIFO. Also proves
    /// the refusal happens before any rename attempt -- both the FIFO and
    /// its parent directory are untouched afterward.
    // Unix-only: the object kind this exercises has no portable
    // constructor. The refusal logic it checks is platform-independent.
    #[cfg(unix)]
    #[test]
    fn a_fifo_preimage_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let artefact_id = "ep0";
        let source_path = dir.path().join(preimage_source_name(artefact_id));

        let path_c = std::ffi::CString::new(source_path.to_str().unwrap()).unwrap();
        // SAFETY: `path_c` is a valid NUL-terminated string naming a path
        // this test just built under a fresh tempdir; `0o600` is an
        // ordinary permission mode for `mkfifo`.
        let ret = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
        assert_eq!(ret, 0, "mkfifo failed: {}", io::Error::last_os_error());

        let expected = FileIdentity::observe_path(&source_path).unwrap();
        assert_eq!(expected.object_kind, ObjectKind::Fifo);

        let err = transfer_to_custody(&parent, artefact_id, Some(&expected)).unwrap_err();
        assert!(
            matches!(
                err,
                CustodyTransferError::Ineligible(CustodyIneligibleReason::Blocked(
                    BlockedObjectReason::Fifo
                ))
            ),
            "got {err:?}"
        );
        assert!(source_path.exists());
    }

    #[test]
    fn a_directory_preimage_is_refused_with_its_own_reason() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let artefact_id = "ep0";
        let source_path = dir.path().join(preimage_source_name(artefact_id));
        fs::create_dir(&source_path).unwrap();

        let expected = FileIdentity::observe_path(&source_path).unwrap();
        assert_eq!(expected.object_kind, ObjectKind::Directory);

        let err = transfer_to_custody(&parent, artefact_id, Some(&expected)).unwrap_err();
        assert!(matches!(
            err,
            CustodyTransferError::Ineligible(CustodyIneligibleReason::DirectorySubtree)
        ));
    }

    // Unix-only: the object kind this exercises has no portable
    // constructor. The refusal logic it checks is platform-independent.
    #[cfg(unix)]
    #[test]
    fn a_symlink_preimage_is_eligible_and_transfers() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let artefact_id = "ep0";
        let source_path = dir.path().join(preimage_source_name(artefact_id));
        std::os::unix::fs::symlink("/does/not/matter", &source_path).unwrap();

        let expected = FileIdentity::observe_path(&source_path).unwrap();
        assert_eq!(expected.object_kind, ObjectKind::Symlink);

        let outcome = transfer_to_custody(&parent, artefact_id, Some(&expected)).unwrap();
        assert!(matches!(outcome, CustodyTransferOutcome::Transferred { .. }));
        assert!(!source_path.exists());
    }

    #[test]
    fn refuses_to_replace_an_existing_retained_artefact() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let artefact_id = "ep0";
        let source_path = dir.path().join(preimage_source_name(artefact_id));
        fs::write(&source_path, b"content").unwrap();
        // Something already occupies the destination name -- an unowned
        // artefact-shaped collision, exactly the shape `Collision` exists
        // for.
        fs::write(dir.path().join(retained_custody_name(artefact_id)), b"other").unwrap();

        let expected = FileIdentity::observe_path(&source_path).unwrap();
        let err = transfer_to_custody(&parent, artefact_id, Some(&expected)).unwrap_err();
        assert!(matches!(err, CustodyTransferError::Collision(_)));
        // Neither participant was touched.
        assert!(source_path.exists());
        assert_eq!(
            fs::read(dir.path().join(retained_custody_name(artefact_id))).unwrap(),
            b"other"
        );
    }

    // ---- real cross-filesystem provocation (macOS RAM disk) ----
    //
    // `transfer_to_custody`'s own public API cannot reach `CrossFilesystem`
    // at all: both names it renames are resolved through one already-open
    // `ParentDirHandle`, so there is no second directory for a caller to
    // even name. What this test instead proves is the assumption the
    // defensive `EXDEV` branch in `ParentDirHandle::rename_child_no_replace`
    // relies on -- that a genuine cross-device rename really does fail
    // with `EXDEV` on this platform -- independent of whether this
    // module's own API can ever reach that branch. Ignored by default: it
    // provisions and tears down a real macOS RAM disk device via
    // `hdiutil`/`diskutil`, which needs a real macOS host and device
    // privileges this crate's ordinary `cargo test` run should not depend
    // on.
    #[cfg(target_os = "macos")]
    mod cross_filesystem {
        use std::process::Command;

        struct RamDisk {
            device: String,
            mount_point: std::path::PathBuf,
        }

        impl RamDisk {
            fn attach(volume_name: &str, size_512_byte_sectors: u64) -> RamDisk {
                let attach = Command::new("hdiutil")
                    .args(["attach", "-nomount", &format!("ram://{size_512_byte_sectors}")])
                    .output()
                    .expect("hdiutil attach");
                assert!(attach.status.success(), "hdiutil attach failed: {attach:?}");
                let device = String::from_utf8_lossy(&attach.stdout)
                    .split_whitespace()
                    .next()
                    .expect("hdiutil attach printed no device path")
                    .to_string();

                let erase = Command::new("diskutil")
                    .args(["eraseVolume", "HFS+", volume_name, &device])
                    .output()
                    .expect("diskutil eraseVolume");
                if !erase.status.success() {
                    let _ = Command::new("hdiutil").args(["detach", &device]).output();
                    panic!("diskutil eraseVolume failed: {erase:?}");
                }

                RamDisk {
                    device,
                    mount_point: std::path::PathBuf::from("/Volumes").join(volume_name),
                }
            }
        }

        impl Drop for RamDisk {
            fn drop(&mut self) {
                let _ = Command::new("diskutil").args(["eject", &self.device]).output();
            }
        }

        #[test]
        #[ignore = "provisions a real macOS RAM disk device via hdiutil/diskutil; \
                    run explicitly with `cargo test -- --ignored`"]
        fn cross_device_rename_really_does_fail_with_exdev() {
            // 65536 512-byte sectors = 32 MiB, big enough to mount, small
            // enough to provision quickly.
            let ram_disk = RamDisk::attach("custody_transfer_exdev_test", 65536);
            assert!(ram_disk.mount_point.is_dir(), "RAM disk did not mount");

            let main_disk_dir = tempfile::tempdir().unwrap();
            let source = main_disk_dir.path().join("displaced");
            std::fs::write(&source, b"content").unwrap();
            let destination = ram_disk.mount_point.join("dest");

            let err = std::fs::rename(&source, &destination).unwrap_err();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::EXDEV),
                "expected a genuine cross-device rename to fail with EXDEV, got {err:?}"
            );
            // Confirms the negative too: nothing landed on the RAM disk.
            assert!(!destination.exists());
        }
    }
}
