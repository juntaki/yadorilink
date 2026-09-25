//! Reconciles the disk under the paths a HistoryBase snapshot install
//! holds: removes what the replaced rows left there, preserves what they
//! cannot account for, places the installed row, and releases the hold.
//!
//! An install replaces index rows without touching disk (a filesystem
//! cannot join its transaction), so it holds every path whose object on
//! disk may still belong to a replaced row. While a path is held nothing
//! captures it and nothing projects it; this pass is its one writer. See
//! `yadorilink_sync_sqlite::snapshot_install_hold` for the hold itself.
//!
//! Each step is idempotent against the state a crash can leave between
//! any two of them, because every decision is made from what is on disk
//! now:
//!
//! - stale bytes are first renamed to a reserved preimage name beside the
//!   path, and only removed once the object renamed is confirmed to be
//!   them; a preimage found at the start of a pass is settled the same way
//!   before anything else;
//! - after removing stale bytes or moving divergent ones aside, the path
//!   is empty, which reads as [`DiskVerdict::Absent`] on the next pass;
//! - after placing the installed row's placeholder, it reads as
//!   [`DiskVerdict::InstalledPlaceholder`] and is kept, not quarantined;
//! - the hold is released last, in one transaction, so a crash before it
//!   leaves the path held and the next pass finishes it.
//!
//! Nothing locks a user out of a held path, so no step acts on what an
//! earlier one saw there: the object a removal takes is re-examined after
//! it is taken, and the placeholder is only ever placed at a path that is
//! still empty. A user write that lands in between is preserved as a
//! conflict copy, or left where it is for the next pass.
//!
//! Directories follow the namespace the installed rows describe (the
//! install has already moved a file whose name a live row below needs to
//! its copy name, so the rows are the namespace's shape):
//!
//! - an installed Directory row is placed through the Directory lane: a
//!   real directory with the row's mode, and its proof;
//! - a path only live rows below need becomes a structural directory,
//!   created through the recording `mkdir` helper, or adopted as
//!   structural when it is the replaced row's explicit directory;
//! - a directory nothing needs any more is removed only when this device
//!   made it (the replaced row's directory, or a structural one) and it is
//!   empty, with one non-recursive `rmdir`; one that still holds content
//!   this device does not replicate is kept and recorded as retained (D4),
//!   and a directory the user made is never touched. Structural ancestors
//!   of a dropped path go with it the same way.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use yadorilink_local_storage::{
    apply_unix_mode, create_dir_all_never_through_a_symlink, create_explicit_directory,
    create_or_defer_placeholder_if_absent, disk_bytes_match_indexed_blocks, intent_target_hash,
    remove_empty_dir, unix_mode_already_matches_disk, verify_replicated_xattrs_exact,
    verify_write_target_within_root, EmptyDirectoryRemoval, ExplicitDirectoryCreation,
    PlaceholderDiskIdentity, PlaceholderIdentityToRecord, StructuralDirectoryLedger,
    INTERNAL_INODE_PROVIDER_KIND,
};
use yadorilink_replica_domain::conflict::conflict_copy_path;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::{PriorPlacement, SnapshotInstallHold};
use yadorilink_root_authority::fs_identity::{FileIdentity, ObjectKind};
use yadorilink_root_authority::reserved_namespace::{artefact_component_name, ArtefactKind};
use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::materialization_execution::{
    GroupStructuralLedger, MaterializationExecutionError, MaterializationExecutionPort,
    RepairRowSnapshot,
};

/// What one reconciliation pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SnapshotInstallReconcileReport {
    /// Held paths whose disk now agrees with the installed row, released.
    pub released: Vec<String>,
    /// `(held path, conflict-copy path)`: an object the replaced row
    /// cannot account for, moved aside rather than discarded or authored.
    pub preserved: Vec<(String, String)>,
    /// Held paths whose reconciliation failed on this path alone; they stay
    /// held for the next pass.
    pub failed: Vec<String>,
    /// Held paths an install held again while this pass reconciled them for
    /// the row it had read; they stay held for the next pass, which reads
    /// the row now installed.
    pub renewed: Vec<String>,
}

/// What is on disk under a held path, measured against the replaced row
/// and the installed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskVerdict {
    Absent,
    /// Exactly what the replaced row placed: superseded by the install.
    Stale,
    /// An untouched placeholder of the installed row: already its
    /// projection.
    InstalledPlaceholder,
    /// A directory. Not this path's to move: its entries are other paths.
    Directory,
    /// Anything else. Its base is the replaced row, not the installed one.
    Divergent,
}

/// What the installed rows need at a held path: the namespace's node
/// there. Read from the index, because an installed base's rows are what
/// its disk has to end up matching -- the install has already given them
/// the namespace's shape (a file whose name a live descendant needs sits at
/// its copy name; see `yadorilink_sync_sqlite::snapshot_install_hold`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstalledNode {
    /// No live row, and nothing live below: nothing is needed here.
    Absent,
    /// A live File or Symlink row with nothing live below it.
    Entry,
    /// A live Directory row: a directory that is itself an entry.
    ExplicitDirectory,
    /// Live rows below and no Directory row: a directory that exists only
    /// to hold them.
    StructuralDirectory,
}

fn installed_node(row: &RepairRowSnapshot, has_live_descendant: bool) -> InstalledNode {
    let live_kind = row
        .file
        .as_ref()
        .filter(|record| !record.deleted)
        .map(|_| row.record_kind.unwrap_or_default());
    match live_kind {
        Some(RecordKind::Directory) => InstalledNode::ExplicitDirectory,
        // A File or Symlink row with live rows below is one the install
        // should have relocated; the directory wins, as in the projection,
        // and the row is left to the projection its release schedules.
        _ if has_live_descendant => InstalledNode::StructuralDirectory,
        Some(_) => InstalledNode::Entry,
        None => InstalledNode::Absent,
    }
}

/// Reconciles every held path of `group_id` under `root`. A path whose lock
/// is busy is left for the next pass.
///
/// In namespace order: first the paths nothing is needed at any more,
/// deepest first, so a dropped directory's dropped contents are gone before
/// the directory is looked at; then the rest, shallowest first, so a
/// directory is in place before anything is placed inside it.
pub fn reconcile_snapshot_install_holds(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    permit: &RootCommitPermit,
) -> Result<SnapshotInstallReconcileReport, MaterializationExecutionError> {
    let mut report = SnapshotInstallReconcileReport::default();
    let holds = state.list_snapshot_install_holds(group_id)?;
    let held: HashSet<String> = holds.iter().map(|hold| hold.path.clone()).collect();
    // Read without the path locks, for the order only: every decision is
    // made again from what is read under the lock.
    let mut removals = Vec::new();
    let mut rest = Vec::new();
    for hold in holds {
        let row = state.repair_row_snapshot(group_id, &hold.path)?;
        let descendant = state.index_has_live_descendant(group_id, &hold.path)?;
        if installed_node(&row, descendant) == InstalledNode::Absent {
            removals.push(hold);
        } else {
            rest.push(hold);
        }
    }
    // The holds come in path order, where a path sorts before everything
    // below it; reversed, everything below comes first.
    removals.reverse();
    for hold in removals.into_iter().chain(rest) {
        let path_lock = state.path_lock(group_id, &hold.path);
        let Ok(_path_guard) = path_lock.try_lock() else { continue };
        match reconcile_one(state, root, group_id, &hold, &held, permit, &mut report) {
            Ok(()) => {}
            Err(e) if e.is_path_local() => {
                tracing::warn!(
                    group_id,
                    path = %hold.path,
                    error = %e,
                    "could not reconcile a path a snapshot install replaced; it stays held"
                );
                report.failed.push(hold.path.clone());
            }
            Err(e) => return Err(e),
        }
    }
    Ok(report)
}

fn reconcile_one(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &SnapshotInstallHold,
    held: &HashSet<String>,
    permit: &RootCommitPermit,
    report: &mut SnapshotInstallReconcileReport,
) -> Result<(), MaterializationExecutionError> {
    let out_path = root.join(&hold.path);
    let ledger = GroupStructuralLedger::new(state, group_id);
    let preimage = preimage_path(&out_path, &hold.path)?;
    let installed = state.repair_row_snapshot(group_id, &hold.path)?;
    let node = installed_node(&installed, state.index_has_live_descendant(group_id, &hold.path)?);
    if node == InstalledNode::Absent && !object_at(&out_path)? && !object_at(&preimage)? {
        // Dropped, and nothing of it is on disk: nothing to take and
        // nothing to place, so no parent to create for either.
        return release(state, root, group_id, hold, held, node, permit, None, None, report);
    }
    verify_write_target_within_root(&out_path, root, &ledger)?;
    if object_at(&preimage)? {
        // A previous pass took the object aside and crashed before it
        // settled it.
        state.begin_snapshot_install_disk_write(group_id, &hold.path)?;
        settle_taken_object(root, &ledger, group_id, hold, &preimage, report)?;
    }
    let installed_placeholder_size = (node == InstalledNode::Entry)
        .then(|| installed_regular_file(&installed))
        .flatten()
        .map(|record| record.size);
    // The placeholder this pass itself creates, if it creates one.
    let mut placed = None;
    // The explicit directory this pass itself creates, if it creates one.
    let mut made_directory = None;
    let mut verdict = classify(&out_path, hold.prior.as_ref(), installed_placeholder_size)?;
    reached(ReconcileStepForTest::Classified, &out_path);
    let writes_placeholder = installed_placeholder_size.is_some()
        && matches!(verdict, DiskVerdict::Absent | DiskVerdict::Stale | DiskVerdict::Divergent);
    if writes_placeholder || matches!(verdict, DiskVerdict::Stale | DiskVerdict::Divergent) {
        state.begin_snapshot_install_disk_write(group_id, &hold.path)?;
    }
    match verdict {
        DiskVerdict::Absent | DiskVerdict::InstalledPlaceholder | DiskVerdict::Directory => {}
        DiskVerdict::Stale => {
            // Whatever is at the path now may not be what was classified:
            // take that exact object first, then look at what was taken.
            if take_object(&out_path, &preimage)? {
                settle_taken_object(root, &ledger, group_id, hold, &preimage, report)?;
            }
        }
        DiskVerdict::Divergent => {
            preserve(root, &ledger, group_id, hold, &out_path, report)?;
        }
    }

    match node {
        InstalledNode::Entry => {
            // A directory where an entry is installed goes only when this
            // device made it and it is empty. While a held path below it
            // still waits for its own reconciliation, the path stays held
            // for the pass after that one. Anything else is kept, with
            // everything in it, and the entry goes to its copy name beside
            // it, as the live projection places it.
            if verdict == DiskVerdict::Directory {
                if remove_directory_at_held_path(state, root, group_id, hold, &out_path, false)? {
                    verdict = DiskVerdict::Absent;
                    state.begin_snapshot_install_disk_write(group_id, &hold.path)?;
                } else if has_held_descendant(state, group_id, &hold.path)? {
                    return Ok(());
                } else {
                    return keep_directory_and_relocate_entry(
                        state, root, group_id, hold, held, &out_path, permit, report,
                    );
                }
            }
            if let Some(record) = installed_regular_file(&installed) {
                placed = place_installed_placeholder(
                    state, root, group_id, hold, &out_path, &ledger, record, &installed, verdict,
                    permit,
                )?;
            }
        }
        InstalledNode::ExplicitDirectory => {
            made_directory = place_installed_directory(
                state, root, group_id, hold, &out_path, &installed, permit,
            )?;
        }
        InstalledNode::StructuralDirectory => {
            settle_structural_directory(state, root, group_id, hold, &out_path, &ledger)?;
        }
        InstalledNode::Absent => {
            if verdict == DiskVerdict::Directory {
                // Not empty only because a held path below has not been
                // reconciled yet (its lock was busy, or it failed): that is
                // no untracked content, and the path stays held until the
                // pass that finds it gone.
                let waits_for_descendant = has_held_descendant(state, group_id, &hold.path)?;
                if !remove_directory_at_held_path(
                    state,
                    root,
                    group_id,
                    hold,
                    &out_path,
                    !waits_for_descendant,
                )? && waits_for_descendant
                {
                    return Ok(());
                }
            }
        }
    }
    release(state, root, group_id, hold, held, node, permit, placed, made_directory, report)
}

/// Whether a path strictly below `path` is still held: installed or
/// dropped content under it that its own reconciliation has not settled.
fn has_held_descendant(
    state: &dyn MaterializationExecutionPort,
    group_id: &str,
    path: &str,
) -> Result<bool, MaterializationExecutionError> {
    let below = format!("{path}/");
    Ok(state.list_snapshot_install_holds(group_id)?.iter().any(|h| h.path.starts_with(&below)))
}

/// A directory this pass may not remove -- the user's, or one holding
/// content this device does not replicate -- holds the name the installed
/// entry at `out_path` needs. As in the live projection, the directory is
/// kept (recorded as retained, removable once empty when this device made
/// it) and the entry goes to its copy name beside it: the index moves the
/// row there and holds the copy name for the next pass to place. Left at
/// the held path, the row would name a file where the disk has a
/// directory, which the offline-delete scan reads as that file's deletion.
#[allow(clippy::too_many_arguments)]
fn keep_directory_and_relocate_entry(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &SnapshotInstallHold,
    held: &HashSet<String>,
    out_path: &Path,
    permit: &RootCommitPermit,
    report: &mut SnapshotInstallReconcileReport,
) -> Result<(), MaterializationExecutionError> {
    let Some(copy) =
        state.relocate_held_entry_beside_directory(group_id, &hold.path, hold.generation)?
    else {
        // An install renewed the hold: the release sees it and leaves the
        // path for the next pass.
        return release(
            state,
            root,
            group_id,
            hold,
            held,
            InstalledNode::Entry,
            permit,
            None,
            None,
            report,
        );
    };
    let observed = FileIdentity::observe_path(out_path).ok();
    let made_here = match &observed {
        Some(identity) if identity.object_kind == ObjectKind::Directory => {
            placed_by_replaced_row_as_directory(hold)
                || state.is_structural_directory(group_id, &hold.path, root, identity)?
        }
        _ => false,
    };
    state.retain_directory_with_untracked_content(
        group_id,
        &hold.path,
        observed.as_ref().filter(|_| made_here),
    )?;
    tracing::info!(
        group_id,
        path = %hold.path,
        copy = %copy,
        "a directory this device may not remove holds the name an installed entry needs; the \
         entry goes to its copy name"
    );
    report.released.push(hold.path.clone());
    Ok(())
}

/// Places the installed row's placeholder at `out_path`, or recognises the
/// one a crashed pass already placed there, and records its identity.
/// Returns the identity of a placeholder this call created.
#[allow(clippy::too_many_arguments)]
fn place_installed_placeholder(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &SnapshotInstallHold,
    out_path: &Path,
    ledger: &dyn StructuralDirectoryLedger,
    record: &yadorilink_replica_domain::file::FileRecord,
    installed: &RepairRowSnapshot,
    verdict: DiskVerdict,
    permit: &RootCommitPermit,
) -> Result<Option<PlaceholderDiskIdentity>, MaterializationExecutionError> {
    match verdict {
        DiskVerdict::InstalledPlaceholder => {
            // Already placed, by this pass before a crash. Record the
            // identity it has unless one was recorded before the crash.
            let metadata = std::fs::symlink_metadata(out_path)?;
            if let Some(identity) = PlaceholderDiskIdentity::from_metadata(&metadata) {
                state.record_placeholder_identity(
                    group_id,
                    &hold.path,
                    PlaceholderIdentityToRecord::RecordIfAbsent {
                        identity,
                        provider_kind: INTERNAL_INODE_PROVIDER_KIND,
                    },
                    permit,
                )?;
            }
            Ok(None)
        }
        DiskVerdict::Directory => Ok(None),
        DiskVerdict::Absent | DiskVerdict::Stale | DiskVerdict::Divergent => {
            verify_write_target_within_root(out_path, root, ledger)?;
            reached(ReconcileStepForTest::PlacingPlaceholder, out_path);
            // Never over something that appeared since the path was
            // emptied: that fails this path, which stays held, and the
            // next pass preserves what appeared.
            let outcome = create_or_defer_placeholder_if_absent(
                out_path,
                record.size,
                record.mtime_unix_nanos,
            )?;
            let deferred = outcome.is_deferred_to_a_separate_process();
            let placed = match &outcome {
                PlaceholderIdentityToRecord::RecordOverwrite { identity, .. } => Some(*identity),
                _ => None,
            };
            state.record_placeholder_identity(group_id, &hold.path, outcome, permit)?;
            if !deferred {
                apply_unix_mode(out_path, installed.unix_mode)?;
            }
            reached(ReconcileStepForTest::PlaceholderPlaced, out_path);
            Ok(placed)
        }
    }
}

/// Places the installed explicit Directory row at `out_path` through the
/// Directory lane: the directory itself (its missing ancestors structural,
/// recorded by the `mkdir` helper), its mode, and the proof naming the
/// installed version, journaled like any other rebuild of a single object.
/// A directory already there is kept, with whatever is in it (D4), and
/// becomes the entry's. Returns the identity of a directory this call
/// created, which a renewed hold withdraws while it is still empty.
fn place_installed_directory(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &SnapshotInstallHold,
    out_path: &Path,
    installed: &RepairRowSnapshot,
    permit: &RootCommitPermit,
) -> Result<Option<FileIdentity>, MaterializationExecutionError> {
    let Some(version) = installed.current_version else {
        tracing::warn!(
            group_id,
            path = %hold.path,
            "an installed directory row names no version; nothing to prove it against"
        );
        return Ok(None);
    };
    let canonical_root = std::fs::canonicalize(root)?;
    let (mutation_generation, intent_guard) = state.open_repair_object_rebuild(
        group_id,
        &hold.path,
        RecordKind::Directory,
        &intent_target_hash(&[]),
        permit,
    )?;
    let created = create_explicit_directory(
        out_path,
        &canonical_root,
        &GroupStructuralLedger::new(state, group_id),
    )?;
    apply_unix_mode(out_path, installed.unix_mode)?;
    reached(ReconcileStepForTest::DirectoryPlaced, out_path);
    // The settle below clears the intent; dropping the guard uncleared is
    // inert.
    drop(intent_guard);
    let made = match created {
        ExplicitDirectoryCreation::Created => FileIdentity::observe_path(out_path).ok(),
        ExplicitDirectoryCreation::AlreadyDirectory => None,
    };
    let published = state.settle_repair_object_rebuild(
        group_id,
        &hold.path,
        RecordKind::Directory,
        out_path,
        version,
        installed.materialization_state,
        installed.current_authoring.as_ref(),
        mutation_generation,
        permit,
    )?;
    if !published {
        tracing::info!(
            group_id,
            path = %hold.path,
            "the installed directory row moved before its proof was committed; the intent \
             stays open for the next pass"
        );
    }
    Ok(made)
}

/// Makes `out_path` the directory the installed rows below it need, when it
/// has no Directory row of its own: creates it (recorded as structural)
/// when nothing is there, and keeps a directory that is. A directory the
/// replaced row placed as an explicit entry is adopted as structural, so
/// it goes with the last descendant instead of staying as a directory of
/// unknown origin.
fn settle_structural_directory(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &SnapshotInstallHold,
    out_path: &Path,
    ledger: &dyn StructuralDirectoryLedger,
) -> Result<(), MaterializationExecutionError> {
    match std::fs::symlink_metadata(out_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let canonical_root = std::fs::canonicalize(root)?;
            create_dir_all_never_through_a_symlink(out_path, &canonical_root, out_path, ledger)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
        Ok(metadata) if metadata.is_dir() => {
            if !placed_by_replaced_row_as_directory(hold) {
                return Ok(());
            }
            let Ok(identity) = FileIdentity::observe_path(out_path) else { return Ok(()) };
            if identity.object_kind == ObjectKind::Directory
                && !state.is_structural_directory(group_id, &hold.path, root, &identity)?
            {
                state.adopt_as_structural_directory(group_id, &hold.path, &identity)?;
            }
            Ok(())
        }
        // Appeared since the path was emptied: the next pass preserves it.
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} is occupied by something that is not a directory", out_path.display()),
        )
        .into()),
    }
}

/// Whether the replaced row was an explicit Directory entry: what it
/// placed at the path is a directory this device made for that entry.
///
/// Bound to the row, not to the directory's identity: an install forgets
/// the group's materialized generations, which is where that identity was
/// recorded. So a directory a user put in place of that one, after this
/// device materialized it and before this pass, reads as this device's
/// too. What that can cost is the same bounded residual every
/// identity-checked `rmdir` has: one empty directory removed, never a file
/// and never anything inside a directory.
fn placed_by_replaced_row_as_directory(hold: &SnapshotInstallHold) -> bool {
    hold.prior.as_ref().is_some_and(|prior| prior.record_kind == RecordKind::Directory)
}

/// Removes the directory at a held path when this device made it (the
/// replaced row's explicit directory, or a structural directory) and it is
/// empty: one non-recursive `rmdir`, after a fence bump. `true` when it is
/// gone. A directory the user made is kept as it is. One this device made
/// that still holds something is kept too (D4: nothing untracked is ever
/// deleted); with `retain` it is recorded as retained, removable once it is
/// empty.
fn remove_directory_at_held_path(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &SnapshotInstallHold,
    out_path: &Path,
    retain: bool,
) -> Result<bool, MaterializationExecutionError> {
    let Ok(identity) = FileIdentity::observe_path(out_path) else { return Ok(false) };
    if identity.object_kind != ObjectKind::Directory {
        return Ok(false);
    }
    if !placed_by_replaced_row_as_directory(hold)
        && !state.is_structural_directory(group_id, &hold.path, root, &identity)?
    {
        return Ok(false);
    }
    state.begin_snapshot_install_disk_write(group_id, &hold.path)?;
    match remove_empty_dir(out_path)? {
        EmptyDirectoryRemoval::Removed | EmptyDirectoryRemoval::Absent => {
            state.forget_removed_directory(group_id, &hold.path)?;
            Ok(true)
        }
        EmptyDirectoryRemoval::NotEmpty => {
            if retain {
                tracing::info!(
                    group_id,
                    path = %hold.path,
                    "a directory a snapshot install dropped still holds content this device does \
                     not replicate; it is kept"
                );
                state.retain_directory_with_untracked_content(
                    group_id,
                    &hold.path,
                    Some(&identity),
                )?;
            }
            Ok(false)
        }
        EmptyDirectoryRemoval::NotADirectory => Ok(false),
    }
}

/// Releases the hold at the generation this pass read. When an install
/// renewed it meanwhile, what this pass placed for a row no longer
/// installed is withdrawn instead and the hold stays for the next pass.
#[allow(clippy::too_many_arguments)]
fn release(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &SnapshotInstallHold,
    held: &HashSet<String>,
    node: InstalledNode,
    permit: &RootCommitPermit,
    placed: Option<PlaceholderDiskIdentity>,
    made_directory: Option<FileIdentity>,
    report: &mut SnapshotInstallReconcileReport,
) -> Result<(), MaterializationExecutionError> {
    let out_path = root.join(&hold.path);
    if node == InstalledNode::Absent {
        // The structural ancestors go before the hold does: the hold is
        // what brings a dropped path back to this pass, and nothing else
        // would ever look at an ancestor left behind by a crash here or by
        // a busy ancestor lock. While one is busy the hold stays, and the
        // next pass tries again.
        reached(ReconcileStepForTest::PruningAncestors, &out_path);
        if !prune_structural_ancestors(state, root, group_id, &hold.path, held)? {
            return Ok(());
        }
    }
    if !state.release_snapshot_install_hold(group_id, &hold.path, hold.generation)? {
        // An install held the path again after this pass read its row, so
        // what this pass placed and recorded was for a row that is no
        // longer installed. The hold stays for the next pass. What this
        // pass recorded is withdrawn, since the path lock does not keep the
        // install from replacing the row either before or after the record,
        // and so is the placeholder or directory it created while it is
        // still untouched: left in place, it would be read as the newer
        // row's projection or moved aside as a conflict copy of nothing.
        state.record_placeholder_identity(
            group_id,
            &hold.path,
            PlaceholderIdentityToRecord::Clear,
            permit,
        )?;
        if let Some(identity) = placed {
            let ledger = GroupStructuralLedger::new(state, group_id);
            let preimage = preimage_path(&out_path, &hold.path)?;
            withdraw_own_placeholder(
                root, &ledger, group_id, hold, &out_path, &preimage, identity, report,
            )?;
        }
        if let Some(identity) = made_directory {
            withdraw_own_directory(&out_path, &identity)?;
        }
        report.renewed.push(hold.path.clone());
        return Ok(());
    }
    report.released.push(hold.path.clone());
    Ok(())
}

/// Removes the directory this pass created at `out_path` while it is still
/// exactly that object and empty. Anything else is left for the next pass.
fn withdraw_own_directory(
    out_path: &Path,
    identity: &FileIdentity,
) -> Result<(), MaterializationExecutionError> {
    let Ok(observed) = FileIdentity::observe_path(out_path) else { return Ok(()) };
    if observed.volume_identity == identity.volume_identity
        && observed.object_id == identity.object_id
    {
        remove_empty_dir(out_path)?;
    }
    Ok(())
}

/// After a dropped path is gone, removes each ancestor directory this
/// device created only for descendants that no installed row needs any
/// more: nearest first, each with one non-recursive `rmdir` while it is
/// empty, stopping at the first that stays. An ancestor that is itself held
/// is left to its own reconciliation, which comes after this one.
///
/// `false` only when an ancestor that would be removed has its lock busy:
/// the one outcome a later attempt can change. Every other stop (a live
/// row, a directory this device did not make, one that is not empty) is
/// settled, and `true`.
fn prune_structural_ancestors(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    path: &str,
    held: &HashSet<String>,
) -> Result<bool, MaterializationExecutionError> {
    let ancestors = std::iter::successors(path.rsplit_once('/').map(|(parent, _)| parent), |p| {
        p.rsplit_once('/').map(|(parent, _)| parent)
    });
    for ancestor in ancestors {
        if held.contains(ancestor) {
            return Ok(true);
        }
        let row = state.repair_row_snapshot(group_id, ancestor)?;
        if row.file.as_ref().is_some_and(|record| !record.deleted)
            || state.index_has_live_descendant(group_id, ancestor)?
        {
            return Ok(true);
        }
        let dir = root.join(ancestor);
        let Ok(identity) = FileIdentity::observe_path(&dir) else { return Ok(true) };
        if identity.object_kind != ObjectKind::Directory
            || !state.is_structural_directory(group_id, ancestor, root, &identity)?
        {
            return Ok(true);
        }
        let path_lock = state.path_lock(group_id, ancestor);
        let Ok(_guard) = path_lock.try_lock() else { return Ok(false) };
        state.begin_snapshot_install_disk_write(group_id, ancestor)?;
        match remove_empty_dir(&dir)? {
            EmptyDirectoryRemoval::Removed | EmptyDirectoryRemoval::Absent => {
                state.forget_removed_directory(group_id, ancestor)?;
            }
            EmptyDirectoryRemoval::NotEmpty | EmptyDirectoryRemoval::NotADirectory => {
                return Ok(true);
            }
        }
    }
    Ok(true)
}

/// Whether anything is at `path`, by name. A parent that is not a
/// directory (`ENOTDIR`) means nothing can be.
fn object_at(path: &Path) -> Result<bool, MaterializationExecutionError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

/// Removes the placeholder this pass created at `out_path` while it is still
/// exactly that, untouched. Whatever else is there is left for the next
/// pass, or preserved if it was already taken aside.
#[allow(clippy::too_many_arguments)]
fn withdraw_own_placeholder(
    root: &Path,
    ledger: &dyn StructuralDirectoryLedger,
    group_id: &str,
    hold: &SnapshotInstallHold,
    out_path: &Path,
    preimage: &Path,
    identity: PlaceholderDiskIdentity,
    report: &mut SnapshotInstallReconcileReport,
) -> Result<(), MaterializationExecutionError> {
    let is_own_untouched = |metadata: &std::fs::Metadata| {
        metadata.file_type().is_file()
            && PlaceholderDiskIdentity::from_metadata(metadata) == Some(identity)
            && holds_no_data(metadata)
    };
    match std::fs::symlink_metadata(out_path) {
        Ok(metadata) if is_own_untouched(&metadata) => {}
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    // As everywhere in this pass: take the object first, then look at what
    // was taken, since a user write can land in between.
    if !take_object(out_path, preimage)? {
        return Ok(());
    }
    if is_own_untouched(&std::fs::symlink_metadata(preimage)?) {
        std::fs::remove_file(preimage)?;
        return Ok(());
    }
    preserve(root, ledger, group_id, hold, preimage, report)
}

/// The installed row, when it is a live regular file: the one kind this
/// pass places itself, as a placeholder. A live symlink is placed by the
/// projection the release schedules; a deleted or absent row needs nothing
/// on disk.
fn installed_regular_file(
    row: &RepairRowSnapshot,
) -> Option<&yadorilink_replica_domain::file::FileRecord> {
    let record = row.file.as_ref()?;
    (!record.deleted && row.record_kind.unwrap_or_default() == RecordKind::File).then_some(record)
}

fn classify(
    out_path: &Path,
    prior: Option<&PriorPlacement>,
    installed_placeholder_size: Option<u64>,
) -> Result<DiskVerdict, MaterializationExecutionError> {
    let metadata = match std::fs::symlink_metadata(out_path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(DiskVerdict::Absent),
        Err(e) => return Err(e.into()),
    };
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        return Ok(DiskVerdict::Directory);
    }
    if file_type.is_file()
        && installed_placeholder_size == Some(metadata.len())
        && holds_no_data(&metadata)
    {
        return Ok(DiskVerdict::InstalledPlaceholder);
    }
    Ok(if is_replaced_rows_object(out_path, &metadata, prior)? {
        DiskVerdict::Stale
    } else {
        DiskVerdict::Divergent
    })
}

/// Whether the object at `path` is exactly what the replaced row placed.
fn is_replaced_rows_object(
    path: &Path,
    metadata: &std::fs::Metadata,
    prior: Option<&PriorPlacement>,
) -> Result<bool, MaterializationExecutionError> {
    let Some(prior) = prior else { return Ok(false) };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        let target = std::fs::read_link(path)?;
        let target = yadorilink_root_authority::fs_identity::target_to_bytes(&target);
        return Ok(prior.record_kind == RecordKind::Symlink
            && prior.symlink_target.as_deref() == Some(target.as_slice()));
    }
    if !file_type.is_file() || prior.record_kind != RecordKind::File || metadata.len() != prior.size
    {
        return Ok(false);
    }
    if prior.placeholder {
        return Ok(holds_no_data(metadata));
    }
    Ok(disk_bytes_match_indexed_blocks(path, &prior.blocks)?
        && unix_mode_already_matches_disk(path, prior.unix_mode)?
        // Strict: an attribute set that cannot be read is not a match.
        && matches!(verify_replicated_xattrs_exact(path, &prior.xattrs), Ok(true)))
}

/// A regular file with no data blocks allocated: this crate's own sparse
/// placeholder shape, which carries no content anyone wrote.
#[cfg(unix)]
fn holds_no_data(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.blocks() == 0
}

/// Without a portable allocation count, no file is provably content-free,
/// so a placeholder is never recognized and falls to the preserving arm.
#[cfg(not(unix))]
fn holds_no_data(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// Where a held path's object is taken while it is examined: a reserved
/// name beside it, which nothing captures or sweeps, fixed per path so a
/// pass that crashed holding one is finished by the next.
fn preimage_path(
    out_path: &Path,
    rel_path: &str,
) -> Result<PathBuf, MaterializationExecutionError> {
    let id = hex::encode(Sha256::digest(rel_path.as_bytes()));
    let name = artefact_component_name(ArtefactKind::Preimage, &id)
        .map_err(|e| MaterializationExecutionError::CorruptState(e.to_string()))?;
    Ok(out_path.with_file_name(name))
}

/// Renames the object at `out_path` to `preimage`, returning whether there
/// was one. A rename moves the object that has the name at that instant,
/// so what it takes is exactly what is examined afterwards.
fn take_object(out_path: &Path, preimage: &Path) -> Result<bool, MaterializationExecutionError> {
    match std::fs::rename(out_path, preimage) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Removes the object taken to `taken` when it is the replaced row's, and
/// preserves it otherwise.
fn settle_taken_object(
    root: &Path,
    ledger: &dyn StructuralDirectoryLedger,
    group_id: &str,
    hold: &SnapshotInstallHold,
    taken: &Path,
    report: &mut SnapshotInstallReconcileReport,
) -> Result<(), MaterializationExecutionError> {
    let metadata = std::fs::symlink_metadata(taken)?;
    if is_replaced_rows_object(taken, &metadata, hold.prior.as_ref())? {
        std::fs::remove_file(taken)?;
        return Ok(());
    }
    preserve(root, ledger, group_id, hold, taken, report)
}

/// Moves the object at `src` aside as a conflict copy of the held path.
fn preserve(
    root: &Path,
    ledger: &dyn StructuralDirectoryLedger,
    group_id: &str,
    hold: &SnapshotInstallHold,
    src: &Path,
    report: &mut SnapshotInstallReconcileReport,
) -> Result<(), MaterializationExecutionError> {
    let preserved_as = move_aside(root, &hold.path, src, ledger)?;
    tracing::warn!(
        group_id,
        path = %hold.path,
        preserved_as = %preserved_as,
        "a path a snapshot install replaced held something its replaced version cannot \
         account for; moved it aside as a conflict copy rather than authoring it over \
         the installed version"
    );
    report.preserved.push((hold.path.clone(), preserved_as));
    Ok(())
}

/// Moves the object at `src` to a conflict-copy sibling of `rel_path` and
/// returns the sibling's link-relative path. Named like any other conflict
/// copy, so local capture captures it as a new file and every peer gets it.
/// The disambiguator digests the object's own bytes, so two different
/// objects moved aside from one path get different names however alike
/// their size and timestamps are, and the move never replaces anything
/// already under the name it picks: an occupied name moves on to the next.
fn move_aside(
    root: &Path,
    rel_path: &str,
    src: &Path,
    ledger: &dyn StructuralDirectoryLedger,
) -> Result<String, MaterializationExecutionError> {
    /// Far more than distinct objects at one path ever need; reaching it
    /// means something keeps occupying the names, and the path stays held.
    const MAX_NAME_ATTEMPTS: u32 = 64;
    let metadata = std::fs::symlink_metadata(src)?;
    let mtime_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let content = object_digest(src, &metadata)?;
    for attempt in 0..MAX_NAME_ATTEMPTS {
        let disambiguator = if attempt == 0 {
            content
        } else {
            Sha256::new().chain_update(content).chain_update(attempt.to_le_bytes()).finalize()
        };
        let preserved_as =
            conflict_copy_path(rel_path, mtime_unix_nanos, "local-preserved", &disambiguator);
        let dst = root.join(&preserved_as);
        verify_write_target_within_root(&dst, root, ledger)?;
        match rename_no_replace(src, &dst) {
            Ok(()) => return Ok(preserved_as),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("every conflict-copy name for {rel_path} tried is already taken"),
    )
    .into())
}

/// A digest of what the object at `path` holds: a regular file's bytes, a
/// symlink's target, and for anything else (which has no content to read
/// without side effects) its identity on disk.
fn object_digest(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<sha2::digest::Output<Sha256>, MaterializationExecutionError> {
    let mut hasher = Sha256::new();
    let file_type = metadata.file_type();
    if file_type.is_file() {
        hasher.update(b"file");
        let mut file = std::fs::File::open(path)?;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = std::io::Read::read(&mut file, &mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    } else if file_type.is_symlink() {
        hasher.update(b"symlink");
        let target = std::fs::read_link(path)?;
        hasher.update(yadorilink_root_authority::fs_identity::target_to_bytes(&target));
    } else {
        hasher.update(b"other");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            hasher.update(metadata.dev().to_le_bytes());
            hasher.update(metadata.ino().to_le_bytes());
        }
    }
    Ok(hasher.finalize())
}

/// Renames `from` to `to` only if nothing is at `to`, failing with
/// `AlreadyExists` otherwise. Atomic where the platform has a no-replace
/// rename and the volume supports it; elsewhere a check followed by a
/// rename, which leaves only the instant between the two open.
fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let from_c = CString::new(from.as_os_str().as_bytes())?;
        let to_c = CString::new(to.as_os_str().as_bytes())?;
        loop {
            // SAFETY: both are valid NUL-terminated paths that outlive the
            // call.
            #[cfg(target_os = "linux")]
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    from_c.as_ptr(),
                    libc::AT_FDCWD,
                    to_c.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            // SAFETY: as above.
            #[cfg(target_os = "macos")]
            let ret =
                unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) };
            if ret == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                // The volume or kernel has no no-replace rename.
                Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP) => break,
                _ => return Err(error),
            }
        }
    }
    match std::fs::symlink_metadata(to) {
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} already exists", to.display()),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::rename(from, to),
        Err(e) => Err(e),
    }
}

/// A point inside one held path's reconciliation at which a test can act
/// on the disk the way a concurrent user would. Nothing locks a user out of
/// a held path, so every step after one of these must hold up against
/// whatever such a write left there.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileStepForTest {
    /// The disk has been classified; nothing on it has been changed yet.
    Classified,
    /// The path is about to receive the installed row's placeholder.
    PlacingPlaceholder,
    /// The installed row's placeholder is placed and its identity recorded;
    /// the hold is not released yet.
    PlaceholderPlaced,
    /// The installed explicit directory is on disk with its mode; its proof
    /// is not committed yet.
    DirectoryPlaced,
    /// A dropped path is gone from disk; its structural ancestors are
    /// about to be pruned.
    PruningAncestors,
}

/// Where reconciliation takes the object at `rel_path` under `root` while
/// it examines it -- for a test to leave one there, as a crash would.
#[cfg(any(test, feature = "test-support"))]
pub fn taken_object_path_for_test(root: &Path, rel_path: &str) -> PathBuf {
    preimage_path(&root.join(rel_path), rel_path).expect("a digest id always names an artefact")
}

#[cfg(any(test, feature = "test-support"))]
type StepHook = Box<dyn FnMut(ReconcileStepForTest, &Path)>;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static STEP_HOOK: std::cell::RefCell<Option<StepHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Clears the hook [`set_reconcile_step_hook_for_test`] installed when
/// dropped. Per thread, so concurrently running tests never see each
/// other's hooks.
#[cfg(any(test, feature = "test-support"))]
pub struct ReconcileStepHookForTest(());

#[cfg(any(test, feature = "test-support"))]
impl Drop for ReconcileStepHookForTest {
    fn drop(&mut self) {
        STEP_HOOK.with(|hook| hook.borrow_mut().take());
    }
}

/// Runs `hook` with each step and the held path's absolute path whenever
/// this thread's reconciliation reaches one.
#[cfg(any(test, feature = "test-support"))]
pub fn set_reconcile_step_hook_for_test(
    hook: impl FnMut(ReconcileStepForTest, &Path) + 'static,
) -> ReconcileStepHookForTest {
    STEP_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    ReconcileStepHookForTest(())
}

#[cfg(any(test, feature = "test-support"))]
fn reached(step: ReconcileStepForTest, out_path: &Path) {
    STEP_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(step, out_path);
        }
    });
}

#[cfg(not(any(test, feature = "test-support")))]
#[derive(Clone, Copy)]
enum ReconcileStepForTest {
    Classified,
    PlacingPlaceholder,
    PlaceholderPlaced,
    DirectoryPlaced,
    PruningAncestors,
}

#[cfg(not(any(test, feature = "test-support")))]
fn reached(_step: ReconcileStepForTest, _out_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Moving aside never creates a directory: the copy is a sibling of
    /// the object it preserves. Nothing to record.
    struct NoLedger;
    impl StructuralDirectoryLedger for NoLedger {
        fn record_intent(
            &self,
            rel_path: &str,
        ) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("moving aside created a directory: {rel_path}")
        }
        fn complete(
            &self,
            rel_path: &str,
            _identity: &yadorilink_root_authority::fs_identity::FileIdentity,
        ) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("moving aside created a directory: {rel_path}")
        }
        fn abandon(&self, rel_path: &str) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("moving aside created a directory: {rel_path}")
        }
    }

    /// Two different objects moved aside from one path must both survive,
    /// even when they agree on everything but their bytes: the same size
    /// and the same modification time, as a tool that restores timestamps
    /// or a coarse-timestamp filesystem produces.
    #[test]
    fn two_objects_moved_aside_from_one_path_do_not_overwrite_each_other() {
        let root = tempfile::tempdir().unwrap();
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let mut preserved = Vec::new();
        for content in [b"first edit!".as_slice(), b"other edit!".as_slice()] {
            let src = root.path().join("doc.txt");
            std::fs::write(&src, content).unwrap();
            std::fs::File::options().write(true).open(&src).unwrap().set_modified(mtime).unwrap();
            preserved.push(move_aside(root.path(), "doc.txt", &src, &NoLedger).unwrap());
        }

        assert_ne!(preserved[0], preserved[1], "both objects were given one name");
        assert_eq!(std::fs::read(root.path().join(&preserved[0])).unwrap(), b"first edit!");
        assert_eq!(std::fs::read(root.path().join(&preserved[1])).unwrap(), b"other edit!");
    }

    /// Moving aside never replaces what already has the name it picks,
    /// whatever that is.
    #[test]
    fn moving_aside_does_not_replace_an_object_already_at_its_name() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("doc.txt");
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let place = || {
            std::fs::write(&src, b"an edit").unwrap();
            std::fs::File::options().write(true).open(&src).unwrap().set_modified(mtime).unwrap();
        };
        place();
        let first = move_aside(root.path(), "doc.txt", &src, &NoLedger).unwrap();
        // The user edits the conflict copy, then the same bytes turn up at
        // the held path again.
        std::fs::write(root.path().join(&first), b"the user's edit of the copy").unwrap();
        place();

        let second = move_aside(root.path(), "doc.txt", &src, &NoLedger).unwrap();

        assert_ne!(first, second);
        assert_eq!(
            std::fs::read(root.path().join(&first)).unwrap(),
            b"the user's edit of the copy"
        );
        assert_eq!(std::fs::read(root.path().join(&second)).unwrap(), b"an edit");
    }
}
