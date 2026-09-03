//! Crash-recovery startup repair, crash-safe restore-journal reconciliation,
//! and offline-edit quarantine: `repair_interrupted_materializations[_emitting_deletes]`/
//! `_inner`, `reconstruct_file_journaled`, `reconcile_restore_operations`, and
//! `quarantine_dirty_disk_file`. Moved out of `yadorilink-sync-core`'s
//! `materialization.rs` (Phase 7D-9C, sixth pass) alongside `evict_file`'s
//! own earlier move in this sub-phase -- per that move's own exit-report
//! addendum (§11.5), a method-by-method audit of every `state.<method>` call
//! this group makes found `MaterializationExecutionPort` already covers the
//! entire surface (`get_unix_mode`, `get_file`, `list_materialization_states`,
//! `has_materialization_intent`, `clear_materialization_intent`,
//! `mark_deleted_emitting_change`, `record_dirty_path`,
//! `set_materialization_state`, `path_lock`, `repair_row_snapshot`,
//! `open_root`, `open_materialization_intent_guard`, `list_restore_operations`,
//! `commit_restore_operation`, `discard_restore_operation`) -- no port
//! extension was needed, only this module split itself.
//!
//! `MaterializationIntentGuard` (the concrete struct this group's
//! `reconstruct_file_journaled` and the live peer materialize path both
//! bracket their writes with) stays in `yadorilink-sync-core`: it borrows a
//! concrete `&'a SyncState`, the same reason `open_materialization_intent_guard`
//! itself is a narrow delegate rather than a trait object constructor (see
//! `materialization_execution.rs`'s own doc comment). This module never names
//! that struct -- it only ever sees the guard through the
//! `Box<dyn OpenMaterializationIntent + Send + '_>` the port method returns.
//!
//! `yadorilink-sync-core::materialization` re-exports every `pub` item here
//! at its original path, so this move needed no consumer repoint -- same
//! shim shape as `evict_file`'s own earlier move in this sub-phase.

use std::path::Path;

use sha2::{Digest, Sha256};

use yadorilink_local_storage::{
    apply_unix_mode, apply_xattrs, create_or_defer_placeholder, disk_bytes_match_indexed_blocks,
    intent_target_hash, reconstruct_file, verify_write_target_within_root, BlockContentStore,
    PlaceholderDiskIdentity, PlaceholderIdentityToRecord, INTERNAL_INODE_PROVIDER_KIND,
};
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::conflict::conflict_copy_path;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;

use crate::materialization_execution::{
    MaterializationExecutionError, MaterializationExecutionPort,
};
use crate::materialization_types::RestoreCommitOutcome;

// --- Startup recovery ------------------------------------------------------

/// Result of one `repair_interrupted_materializations` pass — which paths
/// were found inconsistent, and how each was resolved.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MaterializationRepairReport {
    /// Content on disk was missing/mismatched but every block was still
    /// present in the local block store — self-healed with a fresh
    /// `reconstruct_file`, no peer round-trip needed.
    pub reconstructed: Vec<String>,
    /// Content on disk was missing/mismatched and at least one block was
    /// also missing locally — demoted from `Hydrated` to `Placeholder` so
    /// normal on-demand hydration re-fetches it from a peer.
    pub demoted_to_placeholder: Vec<String>,
    /// Existing disk bytes differed from the indexed block identity and might
    /// be an offline or pending user edit. Rather than overwrite them from the
    /// older index, they were moved to the paired conflict-copy path recorded
    /// here before the canonical path was repaired — `(original_path,
    /// quarantine_path)`.
    pub quarantined_dirty: Vec<(String, String)>,
    /// A `Hydrated` record whose on-disk file was missing *and* had no
    /// in-progress materialization intent journaled — i.e. the write had
    /// already completed and the file was then deleted (or renamed away)
    /// while the daemon was stopped. These are NOT reconstructed from the
    /// index (doing so would silently resurrect a user's offline deletion);
    /// each is classified as an offline deletion. When this pass was given a
    /// change emitter, the tombstone + `Delete` change was emitted here
    /// through the same seam the disk scan uses; otherwise the row is left
    /// untouched for the startup reconcile scan to tombstone.
    pub offline_deleted: Vec<String>,
}

/// Whether one `repair_interrupted_materializations[_emitting_deletes]`
/// pass runs at daemon startup, before any watcher/live-capture pipeline
/// exists for this link, or on the periodic live cadence, while ordinary
/// local edits can be racing it.
///
/// The distinction matters for exactly one thing: what a `Hydrated`
/// record whose on-disk bytes have no in-progress materialization intent
/// means. At startup, before any watcher exists, this can only be an
/// offline user edit or deletion made while the daemon was stopped --
/// quarantining a present-but-divergent file (or deferring a missing
/// one's tombstone to the startup reconcile scan) is the correct,
/// conservative disambiguation. On the live cadence, the SAME
/// observation can just as easily be a user edit **in progress right
/// now** -- sitting in the debounce accumulator, or captured but not yet
/// past its own per-path lock -- neither of which this repair pass's own
/// `try_lock` can see (a confirmed, reproduced race: this repair pass's
/// very next tick after a fresh restart grabbed a just-synced file's path
/// lock a live incoming peer edit had not yet reached, read the disk
/// bytes as "diverged," and quarantined them). Treating that the same
/// way the startup pass does -- quarantining the user's own in-flight
/// edit, or tombstoning a file mid-deletion -- would race and corrupt a
/// live edit instead of merely repairing a crash. `Live` mode instead
/// hands the path to the existing dirty-journal backstop
/// (`MaterializationExecutionPort::record_dirty_path`, already
/// redriven on its own periodic cadence -- see `local_change.rs`'s
/// "re-driving journaled local dirty paths" sweep) and leaves the
/// canonical file/row untouched, rather than acting on it directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairMode {
    Startup,
    Live,
}

impl MaterializationRepairReport {
    /// Whether this pass found nothing to repair — the common case on a
    /// clean startup. Public so callers (`yadorilink-daemon::main`'s
    /// startup wiring) can decide whether to log anything at all without
    /// duplicating this check.
    pub fn is_empty(&self) -> bool {
        self.reconstructed.is_empty()
            && self.demoted_to_placeholder.is_empty()
            && self.quarantined_dirty.is_empty()
            && self.offline_deleted.is_empty()
    }
}

/// startup self-heal for a file whose local index already
/// recorded a `Hydrated` materialization state (and the new version/block
/// list) *before* the crash, but whose on-disk content was never fully
/// (re)written — the exact window `PeerSyncSession::materialize`'s
/// eager-fetch branch leaves open: like every other materialization write
/// path in this crate, it commits the index row first and only then
/// performs the actual temp-write-then-rename (local-change self-echo
/// suppression, `local_change::process_event`, depends on the index
/// already reflecting the new state by the time the watcher sees the
/// resulting filesystem event — see `evict_file`'s doc comment for the
/// same discipline elsewhere in this crate — so that ordering is
/// deliberately not reversed here). A crash between those two steps
/// leaves the index correctly describing the new version while the
/// on-disk file is either stale (still the previous version's bytes) or
/// missing outright — indistinguishable from a genuinely synced file to
/// every other code path, which is exactly what the "avoid
/// partial materialization being mistaken for a valid synced file"
/// invariant forbids.
///
/// Originally intended to run once at daemon startup for every configured
/// link, mirroring `SyncState::reset_stale_hydrating_to_placeholder`'s
/// placement and rationale — the two together cover both
/// materialization states (`Hydrating`, handled there; `Hydrated`,
/// handled here) that a crash can leave in a state inconsistent with
/// reality.
///
/// This same check (a
/// `Hydrated` record whose on-disk state doesn't match) can also arise
/// during live operation, not just from a crash — see this function's
/// caller in `yadorilink-daemon`'s `link_manager.rs`, which now also
/// invokes it on a periodic background cadence for exactly this reason,
/// as defense-in-depth alongside the direct fixes to
/// `try_apply_metadata_only_update` and the debounce batch executor that
/// address the actual root causes.
///
/// For every `Hydrated`, non-deleted, ordinary-`File`-kind record in
/// `group_id` (symlinks/directories carry no block-based content to
/// verify or reconstruct, so are skipped entirely): if the on-disk file at
/// `root.join(path)` is missing, or its bytes do not match the indexed block
/// sequence, this is diagnosed as a disk/index divergence. Block hashes are
/// checked at their recorded boundaries, including when total size is equal,
/// because an edit made while the daemon was stopped has no dirty journal and
/// must not be mistaken for a clean or interrupted materialization.
///
/// If every one of the record's blocks is still present in the local
/// block store (the common case — the final write step failed or never
/// ran, but the fetched bytes it would have assembled from are already
/// durably stored, content-addressed, independent of that failed write),
/// the file is reconstructed again with no peer round-trip needed. Only
/// when a block is also missing locally is the record demoted to
/// `Placeholder`, so it is never left claiming hydrated content that
/// isn't actually there.
/// Returns `Err` — never an empty `Ok` report — when `root`'s identity cannot
/// be established (see [`yadorilink_root_authority::root_identity`]). That distinction is the whole
/// fail-closed lane: this pass is the crash-vs-offline-delete disambiguator, so
/// a caller that reads "nothing to repair" from an unverifiable root goes on to
/// scan it and tombstone everything. An `Err` instead lands the link in the
/// daemon's existing `repair_failed_local_paths` set, which already suppresses
/// that scan's delete emission.
pub fn repair_interrupted_materializations(
    state: &dyn MaterializationExecutionPort,
    store: &dyn BlockContentStore,
    root: &Path,
    group_id: &str,
    mode: RepairMode,
    permit: &RootCommitPermit,
) -> Result<MaterializationRepairReport, MaterializationExecutionError> {
    let root = state.open_root(root, group_id)?;
    repair_interrupted_materializations_inner(state, store, &root, group_id, None, mode, permit)
}

/// Same as [`repair_interrupted_materializations`], but additionally tombstones
/// and emits a `Delete` change — through the same change-emitting seam the disk
/// reconcile scan uses — for every `Hydrated`-but-missing file that has *no*
/// in-progress materialization intent (a file that was materialized cleanly and
/// then deleted or renamed away while the daemon was stopped). Used by callers
/// that already have the group's `ChangeEmitter` in hand and want the deletion
/// propagated immediately rather than deferred to the startup reconcile scan.
/// The plain [`repair_interrupted_materializations`] leaves such a row for that
/// scan instead, so a caller without an emitter never resurrects the file
/// either — it just does not itself emit the tombstone.
///
/// Deliberately not yet wired into a production caller: the live sweep/startup
/// path (`yadorilink-daemon`'s `link_manager`/`app`) runs the plain variant,
/// which never resurrects an offline delete and defers the tombstone to the
/// disk reconcile scan that immediately follows in the same startup barrier —
/// that scan owns the group's `ChangeEmitter` and emits the `Delete` through
/// the identical seam. Routing repair itself through the emitting variant would
/// only move that emission a few milliseconds earlier while duplicating the
/// scan's own per-subtree deletion guards, so the plain variant stays the sole
/// live caller. This entry point is retained as the tested, ready seam for a
/// future caller that wants the tombstone emitted at repair time rather than
/// deferred, and as the direct target for the crash-vs-offline-delete
/// disambiguation tests, which assert the emitted-`Delete` behavior end to end.
pub fn repair_interrupted_materializations_emitting_deletes(
    state: &dyn MaterializationExecutionPort,
    store: &dyn BlockContentStore,
    root: &Path,
    group_id: &str,
    delete_emitter: &ChangeEmitter,
    mode: RepairMode,
    permit: &RootCommitPermit,
) -> Result<MaterializationRepairReport, MaterializationExecutionError> {
    let root = state.open_root(root, group_id)?;
    repair_interrupted_materializations_inner(
        state,
        store,
        &root,
        group_id,
        Some(delete_emitter),
        mode,
        permit,
    )
}

/// M1-5: backfills a persisted placeholder identity for every path this
/// group's index still shows as `Placeholder` with none recorded --
/// closes a crash window an independent review found in M1-2's own
/// design: `write_placeholder` durably writes the sparse placeholder
/// file, then its identity is recorded in a SEPARATE commit
/// (`record_placeholder_generation`), and a crash between the two
/// leaves exactly this state. Run at startup, before any watcher can
/// observe such a row: without a recorded identity to compare against,
/// `local_change.rs`'s dirty-detection falls through to the full
/// chunk-and-compare path for ANY `CreatedOrModified` event on it --
/// including this crate's own harmless placeholder-refresh echo --
/// which would chunk and index the placeholder's own sparse/all-zero
/// bytes as if they were the file's real content, corrupting the file
/// group-wide on the very first watcher tick after a mistimed crash.
///
/// For each such path, re-derives an identity from whatever is on disk
/// RIGHT NOW, but ONLY when it still looks exactly like the placeholder
/// this process would itself have written (regular file, exact indexed
/// `size`) -- a path that no longer matches (diverged, or removed) is
/// left with no generation. That is not a gap: the existing fail-closed
/// behavior (fall through to full chunk-and-compare) is exactly correct
/// there, since something genuinely unaccounted-for happened to it while
/// this device was down.
pub fn backfill_placeholder_generations(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    permit: &RootCommitPermit,
) -> Result<usize, MaterializationExecutionError> {
    let root = state.open_root(root, group_id)?;
    let root = root.path();
    let mut backfilled = 0usize;
    // Deliberately does NOT `?`-propagate a single path's failure out of
    // this loop -- an independent review's finding: a transient error on
    // one candidate (a DB read hiccup, say) must not abandon every OTHER
    // candidate this same pass could otherwise have safely backfilled.
    // `local_change.rs`'s own `untouched_placeholder_verdict` also carries
    // an independent, identity-free fallback for exactly the paths this
    // loop leaves unbackfilled (a still-fully-sparse object at the exact
    // indexed size), so a path skipped here is not left as exposed as it
    // would be without that second layer.
    for path in state.list_placeholder_paths_missing_generation(group_id)? {
        let record = match state.get_file(group_id, &path) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(
                    group_id,
                    path = %path,
                    error = %e,
                    "failed to read the index row for a placeholder-generation backfill candidate; \
                     skipping this path this boot"
                );
                continue;
            }
        };
        if record.deleted {
            continue;
        }
        let out_path = root.join(&path);
        let Ok(metadata) = std::fs::symlink_metadata(&out_path) else { continue };
        if !metadata.is_file() || metadata.len() != record.size {
            continue;
        }
        let Some(identity) = PlaceholderDiskIdentity::from_metadata(&metadata) else { continue };
        if let Err(e) = state.record_placeholder_generation(
            group_id,
            &path,
            identity,
            INTERNAL_INODE_PROVIDER_KIND,
            permit,
        ) {
            tracing::warn!(
                group_id,
                path = %path,
                error = %e,
                "failed to record a backfilled placeholder identity; skipping this path this boot"
            );
            continue;
        }
        backfilled += 1;
    }
    Ok(backfilled)
}

/// Takes a [`VerifiedRoot`] for the same reason
/// `local_change::reconcile_disk_with_ignore` does, and it is the same bug:
/// this pass independently grew its own root guard, and that guard
/// independently checked only that the path existed. An unmounted volume leaves
/// its mountpoint behind, so `fs::metadata` succeeded, every `Hydrated` file
/// looked missing, and the classification below turned the folder into
/// offline-delete tombstones (and, before that, rewrote every file as a
/// placeholder). Requiring the proof in the signature is what stops a third
/// copy of the same mistake: the check now cannot be written incompletely here,
/// because it is not written here at all.
fn repair_interrupted_materializations_inner(
    state: &dyn MaterializationExecutionPort,
    store: &dyn BlockContentStore,
    root: &VerifiedRoot,
    group_id: &str,
    delete_emitter: Option<&ChangeEmitter>,
    mode: RepairMode,
    permit: &RootCommitPermit,
) -> Result<MaterializationRepairReport, MaterializationExecutionError> {
    let mut report = MaterializationRepairReport::default();
    let root = root.path();
    // Per-sweep cost attribution (see the summary `warn!` at this
    // function's end): this pass runs on a live periodic cadence over
    // every materialization-state row in the group, so its per-row costs
    // are multiplied by the whole folder's size on every tick -- a shape
    // that is invisible from the outside because a healthy sweep reports
    // an EMPTY report and therefore logs nothing at all.
    // The exact set of paths that currently carry an intent, read ONCE for the
    // whole pass. Both "already fine, drop a moot intent" arms below (the file
    // arm and the symlink arm) used to issue an unconditional
    // `clear_materialization_intent` for every healthy path they visited --
    // one fsync-backed write transaction, each taking the process-wide writer
    // gate, for a DELETE that matches no row. The journal is empty in steady
    // state, so on a large folder that is the sweep's entire cost: measured at
    // 91k paths, 1.64M such no-op writes holding the writer gate for a
    // cumulative 2,223 seconds while the sweeps ran back-to-back (a single
    // pass outlasting its own 90s cadence).
    //
    // Skipping a clear for a path absent from this snapshot is safe in the
    // direction this module already relies on. An intent created after the
    // snapshot belongs to a materialize that is running RIGHT NOW and clears
    // its own intent on completion; if that materialize instead crashes, the
    // next pass's snapshot sees it. And a lingering intent is explicitly
    // fail-safe here already -- see this function's own opening comment on the
    // orphaned-intent edge, which deliberately leaves such intents in place.
    // Deferring a moot clear by one pass can therefore never lose data; it can
    // at worst defer one offline-delete classification by one cadence.
    //
    // This is emphatically NOT a per-write "read first, skip the write if it
    // looks unnecessary" pre-check: it is one read per pass, the write it
    // guards is a DELETE of a row this pass has positive evidence does not
    // exist, and the loop additionally holds the path's own lock (which every
    // materialize also holds while opening an intent) for the whole decision.
    let outstanding_intents = state.list_materialization_intent_paths(group_id)?;
    let sweep_started = std::time::Instant::now();
    let mut diag_rows_scanned = 0usize;
    let mut diag_hydrated = 0usize;
    let mut diag_lock_skipped = 0usize;
    let mut diag_disk_compared = 0usize;
    let mut diag_disk_matched = 0usize;
    let mut diag_intent_clears = 0usize;
    // Orphaned-intent edge (deliberately not swept here): a crash in the narrow
    // window between opening a materialization intent and committing this path's
    // index/materialization-state row leaves an intent with no corresponding
    // row. This loop is keyed on materialization-state rows, so it never visits
    // such an intent, and it is left in place. That is fail-SAFE: an orphaned
    // intent whose path has no index row cannot drive a spurious reconstruct
    // (the reconstruct arms below all require a present `Hydrated` record), and
    // the disk-reconcile tombstone loop only iterates indexed rows, so the
    // orphan does not block any current deletion either. Its only effect is that
    // if the SAME path is later reused, the scan defers tombstoning it once (see
    // `local_change.rs`) — a deferred delete, never a wrong one. Proactively
    // clearing it is intentionally NOT done: this same function also runs on a
    // live periodic cadence, where an intent that merely looks orphaned may
    // belong to a materialize that just opened it and has not yet committed its
    // row; clearing that live intent would reopen exactly the crash-mid-write
    // data-loss window the journal exists to close. The safe recovery is instead
    // to leave it — a genuine reuse of the path re-opens (and later clears) its
    // own intent, overwriting the stale one.
    for (path, snapshot_mstate) in state.list_materialization_states(group_id)? {
        // Cheap pre-filter on the snapshot: skip rows that are obviously not
        // candidates without paying to take their lock. This snapshot can go
        // stale before the lock is acquired, so every check it informs is
        // re-read authoritatively under the lock below — it is only an
        // optimization to avoid locking every row in the group.
        diag_rows_scanned += 1;
        if snapshot_mstate != MaterializationState::Hydrated {
            continue;
        }
        diag_hydrated += 1;

        // Serialize this path's disk+index repair against the same per-path
        // lock the watcher/local-change pipeline, `hydrate_inner`, and the
        // eviction sweep hold while writing this file and its index row. Since
        // this pass now runs live on a periodic cadence (not only at startup
        // before any watcher exists), it would otherwise rename/rewrite the
        // file and flip its materialization state underneath a concurrent
        // writer, tearing the write or flipping the index row out from under
        // them. `try_lock` (never a blocking `lock`) so a path whose operation
        // is in progress is skipped and repaired on the next pass rather than
        // blocking the sweep — mirroring `evict_file`'s acquisition. Repair
        // touches no block-liveness gate (only `evict_file` does), so holding
        // just this one lock per iteration introduces no lock-ordering hazard
        // against physical block deletion and cannot deadlock.
        let path_lock = state.path_lock(group_id, &path);
        let Ok(_path_guard) = path_lock.try_lock() else {
            diag_lock_skipped += 1;
            continue;
        };

        // Re-read the authoritative state under the lock, exactly as
        // `evict_file` re-checks after acquiring it. Between the snapshot above
        // and taking the lock, a concurrent eviction sweep (or a
        // local-change/hydrate) may have already transitioned this row and
        // rewritten the file. Acting on the stale snapshot would, for example,
        // mistake a freshly written eviction placeholder (a sparse zero file)
        // for a divergent user edit — quarantining it as a bogus conflict copy
        // and reversing the just-completed eviction. Only a row still currently
        // `Hydrated` here is a genuine interrupted-materialization candidate.
        // One snapshot-shaped read replacing the three separate CRUD
        // re-checks this loop used to make individually under the path
        // lock. See `MaterializationExecutionPort::repair_row_snapshot`.
        let row = state.repair_row_snapshot(group_id, &path)?;
        if row.materialization_state != Some(MaterializationState::Hydrated) {
            continue;
        }
        if row.record_kind.unwrap_or_default() == RecordKind::Symlink {
            // An independent review's finding: this loop used to filter
            // to `RecordKind::File` only, so a symlink row left `Hydrated`
            // by a crash between the index commit and the physical
            // symlink write (see `materialize_symlink_at`'s matching
            // intent-guard fix) was never examined by repair at all --
            // "new symlink row committed, crash, physical symlink never
            // created, restart" was simply never healed.
            let Some(record) = &row.file else { continue };
            if record.deleted {
                continue;
            }
            repair_one_interrupted_symlink(
                state,
                root,
                group_id,
                &path,
                delete_emitter,
                mode,
                permit,
                &outstanding_intents,
                &mut report,
            )?;
            continue;
        }
        if row.record_kind.unwrap_or_default() != RecordKind::File {
            continue;
        }
        let Some(record) = row.file else { continue };
        if record.deleted || record.blocks.is_empty() {
            continue;
        }

        let out_path = root.join(&path);
        diag_disk_compared += 1;
        let on_disk_size = std::fs::metadata(&out_path).ok().map(|m| m.len());
        let disk_matches_index = on_disk_size == Some(record.size)
            && disk_bytes_match_indexed_blocks(&out_path, &record.blocks)?;
        if disk_matches_index {
            diag_disk_matched += 1;
            // The write completed and its bytes match the index. Any intent
            // left dangling by a crash in the narrow window between the rename
            // and its own clear is now moot — drop it so a later offline
            // deletion of this same path is never misread as a crash. Only
            // when there actually is one: see `outstanding_intents` above.
            if outstanding_intents.contains(&path) {
                diag_intent_clears += 1;
                state.clear_materialization_intent(group_id, &path, permit)?;
            }
            continue;
        }

        // MISSING file, disambiguated by the durable materialization journal.
        // A missing file with no in-progress intent is not an interrupted
        // write: the write had already completed (its intent was cleared) and
        // the file was then deleted or renamed away while the daemon was
        // stopped. Reconstructing it from the index would silently resurrect
        // that offline deletion — and for a rename, restore the now-stale
        // source path. Classify it as an offline delete instead of healing it.
        // (A missing file WITH an intent is a genuine crash mid-write and falls
        // through to the reconstruct path below, as does any present-but-
        // divergent file.)
        let has_intent = state.has_materialization_intent(group_id, &path)?;
        if on_disk_size.is_none() && !has_intent && mode == RepairMode::Live {
            // See `RepairMode::Live`'s own doc comment: on the live cadence
            // this "missing, no intent" observation may be a delete the
            // user is making RIGHT NOW, not yet captured -- hand it to the
            // dirty-journal backstop rather than deciding here whether it
            // is an offline deletion.
            state.record_dirty_path(group_id, &path, "removed", repair_now_unix_nanos(), permit)?;
            continue;
        }
        if on_disk_size.is_none() && !has_intent {
            match delete_emitter {
                Some(emitter) => match state.mark_deleted_emitting_change(
                    group_id,
                    &path,
                    emitter.device_id(),
                    repair_now_unix_nanos(),
                    // No proof: this is the offline-delete repair scanner,
                    // not local_change.rs's own watcher-driven capture --
                    // it has no matching path-lock-scoped revalidation
                    // discipline to satisfy adopt_observed_actual_
                    // generation_in_tx's own preconditions. Always safe to
                    // decline; the Convergence Engine's existing
                    // fail-closed path handles it exactly as before.
                    false,
                    emitter,
                    permit,
                ) {
                    Ok(_) => {
                        tracing::info!(
                            group_id,
                            path = %path,
                            "a Hydrated file was missing with no materialization intent; \
                             classified it as an offline deletion and emitted a tombstone \
                             rather than resurrecting it from the index"
                        );
                        report.offline_deleted.push(path);
                    }
                    // The group's policy has not loaded this run, so the emit
                    // withheld the tombstone (see `upsert_file_emitting_change`)
                    // rather than stamp a placeholder-auth change. Leave the row
                    // for the reconcile scan to re-emit once policy heals; the
                    // key property — the file is NOT resurrected — already holds
                    // because this arm never reconstructs.
                    Err(MaterializationExecutionError::PolicyUnavailable) => {
                        report.offline_deleted.push(path);
                    }
                    Err(e) => return Err(e),
                },
                None => {
                    // No emitter: the startup pass runs before the group's
                    // change emitter/auth exist. Leave the row `Hydrated` and
                    // the file missing exactly as they are — the startup
                    // reconcile scan, which runs inside the group startup
                    // barrier through the same change-emitting seam and with its
                    // own root-availability and per-subtree deletion guards,
                    // tombstones the path. NOT reconstructing here is the whole
                    // fix; the scan does the propagation.
                    report.offline_deleted.push(path);
                }
            }
            continue;
        }

        // An existing mismatched file is ambiguous: it may be a stale
        // interrupted write, or a user edit made while the daemon was stopped
        // (which has no dirty marker). Preserve it unconditionally before
        // healing the canonical path. Full block-identity verification above
        // also catches same-size offline edits that the old size-only fast
        // path silently missed.
        //
        // On the live cadence, `!has_intent` here is the exact race
        // `RepairMode::Live`'s own doc comment describes: a present intent
        // still means a genuine interrupted materialization (safe to
        // quarantine+heal even live), but its absence no longer proves an
        // offline edit the way it does at startup -- it may be a live edit
        // not yet captured. Defer to the dirty-journal backstop instead of
        // touching the file at all.
        if on_disk_size.is_some() && !has_intent && mode == RepairMode::Live {
            state.record_dirty_path(
                group_id,
                &path,
                "created_or_modified",
                repair_now_unix_nanos(),
                permit,
            )?;
            continue;
        }
        if on_disk_size.is_some() {
            // This whole function has no DAG-frontier proof to publish
            // under, so every physical mutation below only ever
            // invalidates via a bump, never publishes. `path_lock` is held
            // for this whole loop iteration via `_path_guard` above.
            state.dag_bump_mutation_fence(group_id, &path, "repair_quarantine_dirty_disk_file")?;
            match quarantine_dirty_disk_file(root, &path) {
                Ok(Some((quarantine_path, observed_at_unix_nanos))) => {
                    // The conflict copy is not merely a backup. Journal it as
                    // a newly-created local path before repairing the
                    // canonical file, so the daemon's startup dirty-journal
                    // re-drive promotes these bytes through the ordinary
                    // local-change/index/DAG path even if the filesystem
                    // watcher was not running when repair moved the file.
                    state.record_dirty_path(
                        group_id,
                        &quarantine_path,
                        "created_or_modified",
                        observed_at_unix_nanos,
                        permit,
                    )?;
                    tracing::warn!(
                        group_id,
                        path = %path,
                        quarantine_path = %quarantine_path,
                        "local disk bytes diverged from the index during repair; quarantined \
                         its current bytes as a conflict copy before healing the canonical path"
                    );
                    report.quarantined_dirty.push((path.clone(), quarantine_path));
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        group_id,
                        path = %path,
                        error = %e,
                        "failed to quarantine divergent local file bytes; skipping repair of \
                         this path rather than overwriting a possible newer local edit"
                    );
                    continue;
                }
            }
        }

        let hashes: Vec<String> = record.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
        let present = store.present_blocks(&hashes)?;
        if !present.is_empty() && present.iter().all(|&p| p) {
            verify_write_target_within_root(&out_path, root)?;
            // Every block is present locally, so the assembly needs no peer
            // round-trip. If the reconstruct nonetheless fails, the cause is
            // *transient* — a block-store read error during this pass (an EIO,
            // or a torn block failing checksum verification), or a failure of
            // the exec-bit `chmod` that completes the sequence — NOT a missing
            // block; the content is still durably present. Do not
            // `?`-propagate: that would abort the whole repair sweep for every
            // remaining path. Instead demote this one row to a retriable
            // `Placeholder` (the blocks stay in the store) and continue, so a
            // later reconcile re-drives the assembly from those same blocks on
            // a non-faulting read. Only a genuinely-missing block (the `else`
            // arm) is an unavoidable placeholder.
            let target_hash = intent_target_hash(&record.blocks);
            // This is a DIFFERENT physical write than the quarantine above
            // (real content, not a divergent-bytes relocation) -- its own
            // bump.
            state.dag_bump_mutation_fence(group_id, &path, "repair_reconstruct")?;
            match reconstruct_file_journaled(JournaledReconstruction {
                state,
                store,
                group_id,
                path: &path,
                out_path: &out_path,
                blocks: &record.blocks,
                mtime_unix_nanos: record.mtime_unix_nanos,
                target_version_hash: &target_hash,
                permit,
            }) {
                Ok(()) => {
                    // M5-A review follow-up (blocker #56, second round):
                    // this repair path reconstructs real content and
                    // leaves the row `Hydrated` too, exactly like the
                    // live peer materialize/hydrate paths -- it needs the
                    // SAME fingerprint recording those do, or every
                    // repaired row lands in the unprotected "Hydrated +
                    // no fingerprint" state hydrate_inner's shortcut
                    // treats as unproven, defeating this fix for any
                    // file that ever goes through repair.
                    if let Err(e) = state.record_materialized_fingerprint(
                        group_id,
                        &path,
                        yadorilink_peer_session::peer_session::disk_race_fingerprint(&out_path),
                        permit,
                    ) {
                        tracing::warn!(
                            group_id,
                            path = %path,
                            error = %e,
                            "failed to record a materialized fingerprint after repair reconstruct"
                        );
                    }
                    report.reconstructed.push(path)
                }
                Err(e) => {
                    tracing::warn!(
                        group_id,
                        path = %path,
                        error = %e,
                        "repair reconstruct failed with all blocks present; leaving retriable placeholder"
                    );
                    state.set_materialization_state(
                        group_id,
                        &path,
                        MaterializationState::Placeholder,
                        permit,
                    )?;
                    verify_write_target_within_root(&out_path, root)?;
                    // A different physical write than the failed
                    // reconstruct above (a placeholder instead of real
                    // content) -- its own bump.
                    state.dag_bump_mutation_fence(
                        group_id,
                        &path,
                        "repair_reconstruct_failed_placeholder",
                    )?;
                    match create_or_defer_placeholder(
                        &out_path,
                        record.size,
                        record.mtime_unix_nanos,
                    )? {
                        PlaceholderIdentityToRecord::RecordOverwrite {
                            identity,
                            provider_kind,
                        } => state.record_placeholder_generation(
                            group_id,
                            &path,
                            identity,
                            provider_kind,
                            permit,
                        )?,
                        PlaceholderIdentityToRecord::RecordIfAbsent { identity, provider_kind } => {
                            state.record_placeholder_generation_if_absent(
                                group_id,
                                &path,
                                identity,
                                provider_kind,
                                permit,
                            )?;
                        }
                        PlaceholderIdentityToRecord::Clear => {
                            state.clear_placeholder_generation(group_id, &path, permit)?
                        }
                    }
                    apply_unix_mode(&out_path, state.get_unix_mode(group_id, &path)?)?;
                    apply_xattrs(&out_path, &state.get_xattrs(group_id, &path)?)?;
                    // A Placeholder is not an in-progress write; drop any intent
                    // (`reconstruct_file_journaled` only clears on success) so a
                    // later offline delete of this path is not misread as a
                    // crash to reconstruct.
                    state.clear_materialization_intent(group_id, &path, permit)?;
                    report.demoted_to_placeholder.push(path);
                }
            }
        } else {
            state.set_materialization_state(
                group_id,
                &path,
                MaterializationState::Placeholder,
                permit,
            )?;
            verify_write_target_within_root(&out_path, root)?;
            // No blocks were even present locally -- this is its own,
            // independent physical write, its own bump.
            state.dag_bump_mutation_fence(group_id, &path, "repair_missing_blocks_placeholder")?;
            match create_or_defer_placeholder(&out_path, record.size, record.mtime_unix_nanos)? {
                PlaceholderIdentityToRecord::RecordOverwrite { identity, provider_kind } => state
                    .record_placeholder_generation(
                    group_id,
                    &path,
                    identity,
                    provider_kind,
                    permit,
                )?,
                PlaceholderIdentityToRecord::RecordIfAbsent { identity, provider_kind } => {
                    state.record_placeholder_generation_if_absent(
                        group_id,
                        &path,
                        identity,
                        provider_kind,
                        permit,
                    )?;
                }
                PlaceholderIdentityToRecord::Clear => {
                    state.clear_placeholder_generation(group_id, &path, permit)?
                }
            }
            // A placeholder is a fresh file too, so it needs the recorded exec
            // bit applied for the same reason the reconstruct path does — the
            // live peer materialize path stamps its own placeholders
            // identically, and hydration re-applies the bit once real content
            // lands, so it survives the placeholder → hydrated transition.
            apply_unix_mode(&out_path, state.get_unix_mode(group_id, &path)?)?;
            apply_xattrs(&out_path, &state.get_xattrs(group_id, &path)?)?;
            // See the reconstruct-failure arm above: a Placeholder carries no
            // in-progress intent.
            state.clear_materialization_intent(group_id, &path, permit)?;
            report.demoted_to_placeholder.push(path);
        }
    }
    // PERMANENT per-sweep cost summary (kept -- this pass runs on a live
    // ~90s periodic cadence per group, not per-event, so this is not the
    // noisy kind of diagnostic). `warn` deliberately, not `debug`: the
    // whole point is that a healthy sweep is otherwise invisible (an empty
    // report logs nothing on its own), and the question this answers is
    // how much a HEALTHY sweep costs.
    tracing::warn!(
        group_id,
        rows_scanned = diag_rows_scanned,
        hydrated = diag_hydrated,
        lock_skipped = diag_lock_skipped,
        disk_compared = diag_disk_compared,
        disk_matched = diag_disk_matched,
        intent_clears = diag_intent_clears,
        outstanding_intents = outstanding_intents.len(),
        elapsed_ms = sweep_started.elapsed().as_millis() as u64,
        "C4_DIAG: materialization repair sweep pass finished"
    );
    Ok(report)
}

/// Repairs one interrupted symlink materialization -- the symlink
/// counterpart of the block-based reconstruct arm above, much simpler
/// since a symlink has no partial/torn content: it either exists on disk
/// matching its recorded target, or it does not, with no "some blocks
/// present, some missing" middle state at all. Mirrors the file arm's
/// offline-delete-vs-interrupted-write disambiguation (`has_intent`) and
/// live-mode dirty-journal deferral.
///
/// Deliberately does NOT attempt the file arm's "quarantine a diverged
/// on-disk object as a conflict copy" repair: a symlink present on disk
/// but not matching the recorded target, with no repair intent, is left
/// untouched rather than silently overwritten -- a real, scoped
/// limitation, not an oversight.
fn repair_one_interrupted_symlink(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    path: &str,
    delete_emitter: Option<&ChangeEmitter>,
    mode: RepairMode,
    permit: &RootCommitPermit,
    // See the caller's own `outstanding_intents` comment: the whole-pass
    // snapshot of which paths actually carry an intent.
    outstanding_intents: &std::collections::HashSet<String>,
    report: &mut MaterializationRepairReport,
) -> Result<(), MaterializationExecutionError> {
    let Some(target) = state.get_symlink_target(group_id, path)? else {
        // No target recorded at all -- matches `materialize_symlink_at`'s
        // own `PolicySkipped` outcome, which never attempts a write and
        // therefore never opens an intent either. Nothing to repair.
        return Ok(());
    };

    let out_path = root.join(path);
    let on_disk_target = std::fs::symlink_metadata(&out_path)
        .ok()
        .filter(|m| m.file_type().is_symlink())
        .and_then(|_| std::fs::read_link(&out_path).ok())
        .map(|t| yadorilink_root_authority::fs_identity::target_to_bytes(&t));
    if on_disk_target.as_deref() == Some(target.as_slice()) {
        // Already matches -- any intent left dangling by a crash in the
        // narrow window between the symlink syscall and the intent clear
        // is now moot, same reasoning as the file arm. And, for the same
        // reason as the file arm, only written when one actually exists.
        if outstanding_intents.contains(path) {
            state.clear_materialization_intent(group_id, path, permit)?;
        }
        return Ok(());
    }

    let has_intent = state.has_materialization_intent(group_id, path)?;
    let on_disk_exists = std::fs::symlink_metadata(&out_path).is_ok();

    if !on_disk_exists && !has_intent && mode == RepairMode::Live {
        // See `RepairMode::Live`'s own doc comment: this "missing, no
        // intent" observation may be a delete the user is making RIGHT
        // NOW, not yet captured.
        state.record_dirty_path(group_id, path, "removed", repair_now_unix_nanos(), permit)?;
        return Ok(());
    }
    if !on_disk_exists && !has_intent {
        // Missing, disambiguated by the durable materialization journal:
        // the write had already completed (its intent was cleared) and
        // the symlink was then deleted while the daemon was stopped.
        // Reconstructing it from the index would silently resurrect that
        // offline deletion.
        match delete_emitter {
            Some(emitter) => match state.mark_deleted_emitting_change(
                group_id,
                path,
                emitter.device_id(),
                repair_now_unix_nanos(),
                // See the sibling call site's own comment just above in
                // this file for why this is always `false` here.
                false,
                emitter,
                permit,
            ) {
                Ok(_) => report.offline_deleted.push(path.to_string()),
                Err(MaterializationExecutionError::PolicyUnavailable) => {
                    report.offline_deleted.push(path.to_string())
                }
                Err(e) => return Err(e),
            },
            None => report.offline_deleted.push(path.to_string()),
        }
        return Ok(());
    }
    if on_disk_exists && !has_intent && mode == RepairMode::Live {
        // Present but diverged, no intent, on the live cadence: may be a
        // local edit not yet captured. Defer to the dirty-journal
        // backstop rather than touching the symlink at all.
        state.record_dirty_path(
            group_id,
            path,
            "created_or_modified",
            repair_now_unix_nanos(),
            permit,
        )?;
        return Ok(());
    }
    if on_disk_exists && !has_intent {
        // Startup, present, diverged, no intent: an offline edit this
        // pass cannot safely resolve without the file arm's quarantine
        // machinery (not yet extended to symlinks). Left untouched rather
        // than silently overwriting a possible local change.
        tracing::warn!(
            group_id,
            path,
            "a diverged on-disk symlink with no repair intent was left untouched -- symlink \
             quarantine-on-diverge is not implemented"
        );
        return Ok(());
    }

    // Either missing with an intent (a genuine crash mid-write), or
    // present-but-wrong with an intent (a genuine interrupted overwrite)
    // -- both are safe to reconstruct from the durably recorded target.
    #[cfg(unix)]
    let write_eligible = true;
    #[cfg(windows)]
    let write_eligible = state.windows_symlink_opt_in_for_group(group_id)?;
    #[cfg(not(any(unix, windows)))]
    let write_eligible = false;
    if !write_eligible {
        // Matches the live materialize path's own policy: a Windows link
        // that has not opted in never gets a real symlink written, so
        // repair must not write one on its behalf either.
        return Ok(());
    }

    verify_write_target_within_root(&out_path, root)?;
    state.dag_bump_mutation_fence(group_id, path, "repair_reconstruct_symlink")?;
    let target_hash = yadorilink_local_storage::intent_target_hash_for_bytes(&target);
    let intent_guard = state.open_materialization_intent_guard(group_id, path, &target_hash, permit)?;
    #[cfg(unix)]
    yadorilink_local_storage::materialize_symlink(&out_path, &target)?;
    #[cfg(windows)]
    yadorilink_local_storage::materialize_symlink_windows(&out_path, &target)?;
    intent_guard.clear()?;
    report.reconstructed.push(path.to_string());
    Ok(())
}

/// Assembles `record`'s indexed blocks onto disk at `out_path` under a durable
/// materialization intent, so a crash *during this write itself* is recoverable
/// (the intent is still present on the next repair pass) rather than being
/// misread as an offline deletion of a `Hydrated` file. Brackets the write with
/// `MaterializationExecutionPort::open_materialization_intent_guard`'s
/// returned guard — the same single seam the live peer materialize path uses
/// (through its own `yadorilink-peer-session::ports::OpenMaterializationIntent`
/// marker) — so the intent is durable before the temp-write-then-rename begins
/// and cleared only after it completes. This module never names the concrete
/// guard type (`yadorilink-sync-core`'s `MaterializationIntentGuard`, which
/// borrows a concrete `&SyncState`) — only the opaque
/// `Box<dyn OpenMaterializationIntent + Send + '_>` the port method returns.
///
/// `Ok(())` means the *whole* materialization sequence completed — bytes
/// assembled, intent cleared, and the indexed owner-exec bit applied — not
/// merely that the content landed. Repair reports a path as `reconstructed` on
/// exactly that basis, so a file it lists is left the way the live peer
/// materialize path would have left it, permissions included, rather than
/// being a second, weaker materialization implementation.
struct JournaledReconstruction<'a> {
    state: &'a dyn MaterializationExecutionPort,
    store: &'a dyn BlockContentStore,
    group_id: &'a str,
    path: &'a str,
    out_path: &'a Path,
    blocks: &'a [yadorilink_replica_domain::file::BlockInfo],
    mtime_unix_nanos: i64,
    target_version_hash: &'a [u8],
    permit: &'a RootCommitPermit<'a>,
}

fn reconstruct_file_journaled(
    request: JournaledReconstruction<'_>,
) -> Result<(), MaterializationExecutionError> {
    let guard = request.state.open_materialization_intent_guard(
        request.group_id,
        request.path,
        request.target_version_hash,
        request.permit,
    )?;
    // On `Err` the `?` returns while `guard` is still live, so it drops without
    // clearing — the intent stays, and the next repair pass treats a resulting
    // missing file as a crash to recover, never as an offline delete.
    reconstruct_file(request.store, request.out_path, request.blocks, request.mtime_unix_nanos)?;
    // Clear as soon as the rename is durable — BEFORE the exec-bit touch below,
    // never after. `apply_unix_mode` is a real `chmod` on POSIX, so clearing only
    // after it would leak the intent whenever reading or applying the bit
    // errored, even though the bytes are already durably on disk; a later
    // genuine offline delete of this path would then read `missing + intent
    // present` and wrongly resurrect it from the blocks. The live peer
    // materialize path orders these two steps this way for the same reason.
    guard.clear()?;
    // `reconstruct_file` assembles into a fresh temp file, which gets default
    // permissions — so the assembled result does NOT carry the exec bit the
    // index recorded for this path, and a repaired POSIX executable would come
    // back as a plain file if this call were skipped. `local_change.rs`'s
    // content-only self-echo suppression now compares the on-disk exec bit
    // against the index too (fixed alongside `reconstruct_file`'s own mtime
    // stamping — see this arc's exit report addendum), so a later local scan
    // would eventually notice and self-heal the divergence rather than
    // leaving it permanently silent as it once did. Still not a reason to
    // skip this call: repair's own contract (this function's doc comment
    // above) is that a path it reports `reconstructed` was left exactly as
    // the live peer materialize path would have left it, exec bit included,
    // not merely "eventually correct once some other pass notices."
    apply_unix_mode(
        request.out_path,
        request.state.get_unix_mode(request.group_id, request.path)?,
    )?;
    Ok(apply_xattrs(request.out_path, &request.state.get_xattrs(request.group_id, request.path)?)?)
}

/// Wall-clock now in unix nanoseconds, for stamping an offline-delete tombstone
/// this pass emits (mirrors the observed-time stamp the disk scan's delete path
/// uses). Monotonic-clock skew is irrelevant here — this is an observed-at
/// timestamp on a local tombstone, not an ordering primitive.
fn repair_now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RestoreRecoveryReport {
    pub committed: Vec<String>,
    pub discarded_unstarted: Vec<String>,
    pub preserved_divergent: Vec<String>,
}

/// Reconciles restore intents before generic startup materialization repair.
/// The disk content, not the journal state alone, is authoritative because a
/// process can die after the atomic rename but before persisting
/// `DiskCommitted`. Publishing and deleting the journal is one SQLite
/// transaction (`SyncState::commit_restore_operation`), so rerunning this
/// function cannot append a second version.
pub fn reconcile_restore_operations(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    permit: &RootCommitPermit,
) -> Result<RestoreRecoveryReport, MaterializationExecutionError> {
    let mut report = RestoreRecoveryReport::default();
    for operation in state.list_restore_operations(group_id)? {
        let out_path = root.join(&operation.path);
        verify_write_target_within_root(&out_path, root)?;

        if disk_bytes_match_indexed_blocks(&out_path, &operation.record.blocks)? {
            let already_committed = state
                .get_file(group_id, &operation.path)?
                .is_some_and(|current| current == operation.record);
            if already_committed {
                state.discard_restore_operation(&operation.operation_id)?;
            } else {
                match state.commit_restore_operation(&operation.operation_id)? {
                    RestoreCommitOutcome::Committed(_) => {}
                    RestoreCommitOutcome::Missing => continue,
                    RestoreCommitOutcome::Superseded => {
                        state.record_dirty_path(
                            group_id,
                            &operation.path,
                            "created_or_modified",
                            std::fs::metadata(&out_path)
                                .and_then(|metadata| metadata.modified())
                                .ok()
                                .and_then(|modified| {
                                    modified.duration_since(std::time::UNIX_EPOCH).ok()
                                })
                                .map(|duration| duration.as_nanos() as i64)
                                .unwrap_or(0),
                            permit,
                        )?;
                        state.discard_restore_operation(&operation.operation_id)?;
                        report.preserved_divergent.push(operation.path);
                        continue;
                    }
                }
            }
            report.committed.push(operation.path);
            continue;
        }

        let current = state.get_file(group_id, &operation.path)?;
        let disk_still_matches_current = match current.as_ref() {
            Some(record) if record.deleted => !out_path.exists(),
            Some(record) => disk_bytes_match_indexed_blocks(&out_path, &record.blocks)?,
            None => !out_path.exists(),
        };
        if disk_still_matches_current {
            state.discard_restore_operation(&operation.operation_id)?;
            report.discarded_unstarted.push(operation.path);
            continue;
        }

        // Neither side of the interrupted operation explains the bytes. They
        // may be an offline/local edit, so make the ordinary startup repair
        // quarantine and re-index them rather than overwriting them.
        let change_kind = if out_path.exists() { "created_or_modified" } else { "removed" };
        state.record_dirty_path(
            group_id,
            &operation.path,
            change_kind,
            std::fs::metadata(&out_path)
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos() as i64)
                .unwrap_or(0),
            permit,
        )?;
        state.discard_restore_operation(&operation.operation_id)?;
        report.preserved_divergent.push(operation.path);
    }
    Ok(report)
}

/// Moves the current on-disk bytes of `rel_path` (under `root`) aside to a
/// conflict-copy sibling, returning the link-relative quarantine path — or
/// `None` if there is nothing on disk to move. Used by
/// `repair_interrupted_materializations` before it would otherwise overwrite a
/// path whose journaled local edit means the on-disk bytes may be a newer user
/// edit the watcher had not yet indexed. The quarantine name follows the same
/// `(conflicted copy, ...)` convention as DAG conflict copies
/// (`yadorilink_replica_domain::conflict::conflict_copy_path`), so it reads naturally to the user
/// and the watcher re-syncs it as an ordinary new file. The disambiguator is a
/// cheap `Sha256` of the on-disk `(size, mtime)` rather than a full re-read of
/// the file's bytes — enough to keep two genuinely different pending edits
/// (which differ in mtime on every save) from colliding on one name — and the
/// move itself is a `rename` (atomic, no large copy). A fixed `"local-recovered"`
/// device component names the origin without threading this device's id in.
/// The rename target is verified to stay within `root`, exactly like every
/// other write path in this module.
fn quarantine_dirty_disk_file(
    root: &Path,
    rel_path: &str,
) -> Result<Option<(String, i64)>, MaterializationExecutionError> {
    let src = root.join(rel_path);
    let meta = match std::fs::metadata(&src) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mtime_unix_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(meta.len().to_le_bytes());
    hasher.update(mtime_unix_nanos.to_le_bytes());
    let disamb = hasher.finalize();
    let quarantine_rel = conflict_copy_path(rel_path, mtime_unix_nanos, "local-recovered", &disamb);
    let dst = root.join(&quarantine_rel);
    verify_write_target_within_root(&dst, root)?;
    std::fs::rename(&src, &dst)?;
    Ok(Some((quarantine_rel, mtime_unix_nanos)))
}
