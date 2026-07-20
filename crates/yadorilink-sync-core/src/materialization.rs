//! Materialization lifecycle operations that need only local state (no
//! peer connection) — manual/automatic eviction. Hydration (the inverse
//! direction, which does need a peer to fetch blocks from) lives on
//! `PeerSyncSession` instead.

use std::path::{Path, PathBuf};

use yadorilink_local_storage::free_space::{self, FreeSpaceState};
use yadorilink_local_storage::BlockStore;

use crate::block_deletion::BlockDeletionCoordinator;
use crate::block_liveness::BlockLivenessGate;
#[cfg(test)]
use crate::change::{VersionBlock, VersionHash};
use crate::chunker::{
    apply_exec_bit, reconstruct_file, verify_write_target_within_root, write_placeholder,
};
use crate::custody::CustodyVerifier;
pub use crate::custody::FullReplicaCustody;
use crate::dag_store::ChangeEmitter;
use crate::error::SyncError;
use crate::index::SyncState;
use crate::root_identity::VerifiedRoot;
use crate::types::{MaterializationState, RecordKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DiskIdentity {
    len: u64,
    modified_unix_nanos: Option<u128>,
}

fn disk_identity(path: &Path) -> Result<Option<DiskIdentity>, SyncError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos());
    Ok(Some(DiskIdentity { len: metadata.len(), modified_unix_nanos }))
}

/// What one [`evict_file`] call did. The materialized file is always reduced
/// to a placeholder; whether its cached blocks were reclaimed (freeing real
/// space) depends on full-replica custody, and never happens on a full
/// replica.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EvictionOutcome {
    /// Cached blocks deleted from the block store.
    pub blocks_reclaimed: u64,
    /// Bytes freed by reclaiming those blocks.
    pub bytes_reclaimed: u64,
    /// The file became a placeholder but its blocks were retained (custody
    /// unconfirmed, this is a full replica, or the blocks still back other
    /// locally hydrated/pinned content) rather than freed.
    pub blocks_retained: bool,
    /// The on-disk file was reduced to a placeholder — the materialized
    /// working-tree copy was freed. `false` means this call left the file
    /// materialized (an early-return path: no longer current, pinned,
    /// not `Hydrated`, path dirty, or its on-disk identity changed), so it
    /// freed no working-tree bytes and an eviction sweep must not count it.
    pub dehydrated: bool,
}

/// Preflight check before a hydration
/// fetch or a materialize-to-temp-and-rename write begins, scoped to the
/// volume hosting `root` (the target link's local folder) — shares the
/// exact classification (`yadorilink_local_storage::free_space`) the
/// block-store preflight and `yadorilink status`'s per-volume reporting
/// both use, so a single computed state backs the decision here
/// and what's reported elsewhere. Returns `Ok()` when the write may
/// proceed, or `SyncError::DiskPressure` — never partially writing anything,
/// since this is checked *before* any temp file is created — when
/// completing a write of `additional_bytes` more would breach the
/// configured headroom.
///
/// `headroom_override_bytes`: `None` uses the default `max(1 GiB, 5%)`
/// formula; `Some(_)` is an explicit override, both resolved the same way
/// `yadorilink_local_storage::free_space::classify_volume` resolves it for
/// the block-store preflight. Callers that haven't opted into disk-pressure
/// enforcement at all (mirroring `FsBlockStore::headroom_enforced`'s "off
/// by default" behavior) should not call this at all rather than passing a
/// sentinel — see `PeerSyncSession::headroom_enforced`/`yadorilink-daemon`'s
/// governance wiring for where that decision is made.
pub fn check_disk_headroom(
    root: &Path,
    target_path: &Path,
    additional_bytes: u64,
    headroom_override_bytes: Option<u64>,
) -> Result<(), SyncError> {
    let space = free_space::classify_volume(root, headroom_override_bytes)?;
    if space.would_breach(additional_bytes) {
        return Err(SyncError::DiskPressure {
            path: target_path.display().to_string(),
            volume: root.display().to_string(),
            available_bytes: space.available_bytes,
            headroom_bytes: space.headroom_bytes,
        });
    }
    Ok(())
}

/// The handles a materialization/eviction operation needs: the index, the
/// block-liveness gate, the block store, and the linked folder's local root.
/// Shared by [`evict_file`], [`run_eviction_sweep`], and
/// [`run_disk_pressure_eviction_sweep`].
pub struct MaterializationContext<'a> {
    pub state: &'a SyncState,
    pub liveness_gate: &'a BlockLivenessGate,
    pub store: &'a dyn BlockStore,
    pub root: &'a Path,
}

/// Evicts one hydrated, unpinned file back to a placeholder and, on an
/// on-demand device, reclaims its now-cached blocks from the block store to
/// free real disk space — the sync state (version, block list) is untouched.
/// Rejects a pinned file (spec "Pinned files cannot be evicted") without
/// touching it.
///
/// Block reclamation is gated fail-closed by two rules:
/// - `is_full_replica`: a full replica is the group's durable holder and MUST
///   NOT drop live blocks, so it never reclaims — the file is placeholdered
///   but every block is kept.
/// - `custody`: an on-demand device deletes a block only once a full replica
///   is confirmed to hold it. When custody is unconfirmed (e.g. a brand-new
///   local edit no full replica has yet), the file may still become a
///   placeholder but its blocks are retained, so this device is never the
///   sole holder of content.
///
/// Even when custody is confirmed, only blocks that no longer back any
/// locally hydrated or pinned file are freed; a block still shared with such
/// a file is kept so its bytes stay materializable on disk.
///
/// Physical reclamation is currently fail-closed in production: until the
/// responder persists an exact-version custody lease as a GC live root, a
/// manual eviction writes the placeholder but retains every local block. A
/// VersionPresent acknowledgement alone is instantaneous and cannot authorize
/// deleting the requester's last recoverable copy.
///
/// Index update happens before the disk write, same discipline as
/// `PeerSyncSession::materialize` and for the same reason: this device's
/// own watcher would otherwise race the state transition (see
/// `local_change::process_event`'s placeholder-aware self-echo
/// suppression, which only works if the index already says `Placeholder`
/// by the time the watcher processes the resulting filesystem event).
pub fn evict_file(
    ctx: MaterializationContext<'_>,
    group_id: &str,
    path: &str,
    is_full_replica: bool,
    custody: &dyn FullReplicaCustody,
) -> Result<EvictionOutcome, SyncError> {
    let MaterializationContext { state, liveness_gate, store, root } = ctx;
    let reference_write = liveness_gate.begin_reference_write();
    if state.is_pinned(group_id, path)? {
        return Err(SyncError::EvictionRejected(path.to_string()));
    }
    // Read the current row's blocks AND metadata as ONE atomic snapshot, so
    // the `change::VersionHash` the custody query carries describes a version
    // some single row actually held — never a hybrid stitched across
    // separate `get_file` + metadata reads that a concurrent transition could
    // tear apart.
    let Some(record) = state.get_current_version_record(group_id, path)? else {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    };
    if record.deleted {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    }
    // The exact version being evicted, pinned up front. Custody below is
    // confirmed for *this* version, and the deletion coordinator later
    // rechecks that exact version before deriving the reclaimable hashes.
    let evicting_version = record.to_file_version();
    let out_path = root.join(path);
    // defense-in-depth — see `verify_write_target_within_root`'s
    // doc comment; applied here too for consistency with the other
    // materialization write paths, even though eviction writes through an
    // already-indexed path rather than fresh peer input.
    verify_write_target_within_root(&out_path, root)?;
    let initial_disk_identity = disk_identity(&out_path)?;
    let verified_custody = (!is_full_replica)
        .then(|| {
            CustodyVerifier::new(custody).verify_for_reclaim(
                group_id,
                path,
                &evicting_version.version_hash,
                &evicting_version.blocks,
            )
        })
        .flatten();

    let path_lock = state.path_lock(group_id, path);
    let _path_guard =
        path_lock.try_lock().map_err(|_| SyncError::EvictionRejected(format!("{path} is busy")))?;
    let still_current = state.get_current_version_record(group_id, path)?.is_some_and(|current| {
        !current.deleted && current.to_file_version().version_hash == evicting_version.version_hash
    });
    if !still_current
        || state.is_pinned(group_id, path)?
        || state.get_materialization_state(group_id, path)? != Some(MaterializationState::Hydrated)
        || state.is_path_dirty(group_id, path)?
        || disk_identity(&out_path)? != initial_disk_identity
    {
        // Bail out before writing the placeholder: the file is left fully
        // materialized, so `dehydrated` stays `false` (the default) and an
        // automatic sweep must not count it as having freed any bytes.
        return Ok(EvictionOutcome { blocks_retained: true, ..Default::default() });
    }

    state.set_materialization_state(group_id, path, MaterializationState::Evicting)?;
    let placeholder_result = verify_write_target_within_root(&out_path, root)
        .and_then(|_| write_placeholder(&out_path, record.size, record.mtime_unix_nanos));
    if let Err(error) = placeholder_result {
        // The placeholder write failed, so the file is still fully materialized
        // on disk. Roll the row back out of the transient `Evicting` state to
        // `Hydrated` so the index reflects that on-disk reality. Do not silently
        // drop this write's result: a failure to roll back would strand the row
        // in `Evicting`, so surface it. This is not itself fatal — the next
        // daemon startup resets any stale `Evicting` row to `Placeholder` (see
        // `app::run`'s startup recovery), and the periodic eviction/repair sweep
        // re-derives the correct state — so log rather than mask the primary
        // placeholder-write error the caller needs to see.
        if let Err(rollback_error) = state.transition_materialization_state(
            group_id,
            path,
            MaterializationState::Evicting,
            MaterializationState::Hydrated,
        ) {
            tracing::warn!(
                group_id,
                path = %path,
                error = %rollback_error,
                "failed to roll a file back from Evicting to Hydrated after a placeholder-write \
                 error; the row is left in the transient Evicting state for startup recovery to reset"
            );
        }
        return Err(error);
    }
    if !state.transition_materialization_state(
        group_id,
        path,
        MaterializationState::Evicting,
        MaterializationState::Placeholder,
    )? {
        return Ok(EvictionOutcome {
            blocks_retained: true,
            dehydrated: true,
            ..Default::default()
        });
    }

    // A full replica never drops live blocks; an on-demand device reclaims
    // only after a full replica is confirmed to hold this exact version. Either
    // way, fail closed to retaining the blocks.
    let Some(verified_custody) = verified_custody else {
        return Ok(EvictionOutcome {
            blocks_retained: true,
            dehydrated: true,
            ..Default::default()
        });
    };

    // Upgrade from the shared reference-write phase to an exclusive physical
    // deletion phase. The Coordinator revalidates the exact version and all
    // cross-group references only after exclusivity is established.
    drop(reference_write);
    let physical_deletion = liveness_gate.begin_physical_deletion();
    let report = BlockDeletionCoordinator::new(store).reclaim_cached_blocks(
        &physical_deletion,
        verified_custody,
        state,
    )?;
    if report.blocks_deleted == 0 {
        return Ok(EvictionOutcome {
            blocks_retained: true,
            dehydrated: true,
            ..Default::default()
        });
    }
    Ok(EvictionOutcome {
        blocks_reclaimed: report.blocks_deleted,
        bytes_reclaimed: report.bytes_reclaimed,
        blocks_retained: false,
        dehydrated: true,
    })
}

/// Runs one pass of the automatic eviction sweep for a single
/// `OnDemand` folder group with a configured disk-usage cap: evicts
/// least-recently-accessed unpinned hydrated files until usage is back at
/// or under `max_local_size_bytes`. Returns the paths evicted, in the
/// order they were evicted (least-recently-accessed first).
///
/// No-ops (returns an empty list) if `max_local_size_bytes` is `None` —
/// the daemon-level caller is expected to only invoke this for folder
/// groups that actually have a cap configured, but this is a safe no-op
/// either way, matching the "no cap configured = no automatic eviction"
/// requirement even if called unconditionally by mistake.
///
/// Before ranking candidates, best-effort fills in `last_accessed_unix`
/// from each file's on-disk `atime` for files that have *never* recorded
/// one at all — chiefly, a file that was already
/// fully materialized before this device ever supported on-demand sync at
/// all, per the "existing materialized content is preserved on upgrade"
/// requirement, so hydration's own `touch_last_accessed` call never ran
/// for it). Deliberately does **not** overwrite an *existing* recorded
/// value: atime also advances on writes (not just reads), so once a real
/// access timestamp is on record, trusting it over a possibly
/// write-inflated atime is the safer default, accepting the trade-off
/// this implies for files hydrated once, then only
/// ever read (never re-hydrated) afterward.
///
/// Errors reading a given file's metadata (e.g. it vanished) are ignored
/// for that one file rather than failing the whole sweep.
///
/// Without remote custody leases, eviction still replaces hydrated working-tree
/// files with placeholders, but retains their content-addressed blocks. This
/// releases the materialized copy without treating retained cache blocks as
/// physically reclaimed custody-backed storage.
pub fn run_eviction_sweep(
    ctx: MaterializationContext<'_>,
    group_id: &str,
    is_full_replica: bool,
    max_local_size_bytes: Option<i64>,
    custody: &dyn FullReplicaCustody,
) -> Result<Vec<String>, SyncError> {
    let MaterializationContext { state, liveness_gate, store, root } = ctx;
    // A full replica is the group's durable holder and never evicts.
    if is_full_replica {
        return Ok(vec![]);
    }
    let Some(cap) = max_local_size_bytes else {
        return Ok(vec![]);
    };
    let cap = cap.max(0) as u64;

    let mut candidates = state.list_evictable_files(group_id)?;
    refresh_missing_last_accessed(state, root, group_id, &candidates);
    // Re-read now that any refreshed access times have been persisted, so
    // the LRU ordering below reflects them.
    candidates = state.list_evictable_files(group_id)?;

    // usage must include pinned-but-hydrated content too, even
    // though `candidates` (eviction *candidates*) deliberately excludes
    // pinned files — otherwise the sweep undercounts real disk usage and
    // can stop while still over the configured cap.
    let mut current_usage = state.hydrated_usage_bytes(group_id)?;
    let mut evicted = Vec::new();

    for candidate in candidates {
        if current_usage <= cap {
            break;
        }
        // `evict_file` always runs the path-state and disk-identity checks.
        // It may replace the working-tree file with a placeholder even when
        // remote custody cannot authorize physical CAS deletion; in that case
        // it explicitly retains every block. It may also early-return having
        // freed nothing (the candidate is no longer current, was pinned or
        // rehydrated, went dirty, or its on-disk identity changed) — only a
        // call that actually dehydrated the working-tree copy reduces the
        // hydrated-usage figure this sweep tracks, so gate the accounting on
        // it rather than assuming every candidate was reclaimed.
        let outcome = evict_file(
            MaterializationContext { state, liveness_gate, store, root },
            group_id,
            &candidate.path,
            false,
            custody,
        )?;
        if !outcome.dehydrated {
            continue;
        }
        current_usage = current_usage.saturating_sub(candidate.size);
        evicted.push(candidate.path);
    }
    Ok(evicted)
}

/// Best-effort refresh of `last_accessed_unix` from on-disk `atime` for
/// evictable candidates that have never recorded one — the same fallback
/// `run_eviction_sweep` performs (see its doc comment), factored out so the
/// disk-pressure-triggered sweep below reuses it verbatim instead
/// of duplicating the LRU-freshening logic.
fn refresh_missing_last_accessed(
    state: &SyncState,
    root: &Path,
    group_id: &str,
    candidates: &[crate::index::EvictableFile],
) {
    for candidate in candidates {
        if candidate.last_accessed_unix.is_some() {
            continue;
        }
        let Ok(metadata) = std::fs::metadata(root.join(&candidate.path)) else { continue };
        let Ok(accessed) = metadata.accessed() else { continue };
        let Ok(unix_secs) = accessed.duration_since(std::time::UNIX_EPOCH) else { continue };
        let _ = state.touch_last_accessed(group_id, &candidate.path, unix_secs.as_secs() as i64);
    }
}

/// Runs the automatic eviction sweep
/// in response to disk-space pressure on the volume hosting `root`,
/// independent of whether `group_id`'s link has any `max_local_size_bytes`
/// cap configured at all — the disk-pressure trigger `run_eviction_sweep`
/// above's cap-based one doesn't cover, per the `on-demand-sync` spec's
/// "disk-space pressure triggers a sweep regardless of configured cap".
///
/// Reuses, rather than reimplements, the exact same
/// `list_evictable_files` LRU-ordering and pinned-file exclusion
/// `run_eviction_sweep` already relies on — the only difference is the
/// stopping condition (volume free-space classification instead of a
/// configured byte cap). Evicts least-recently-accessed unpinned hydrated
/// files until the volume's free-space classification would no longer be
/// `Low`/`Critical` (estimated from bytes freed so far, without re-`stat`ing
/// the volume after every single eviction), or there are no more evictable
/// candidates. A no-op (`Ok(vec![])`) if the volume is already `Ok`, or if
/// its free space can't currently be determined at all (e.g. `root` doesn't
/// exist yet) — nothing to evict for in either case. Returns the paths
/// evicted, in eviction order, so a caller (e.g. the daemon's
/// hydration/materialization preflight) can re-check headroom afterward and
/// let the original operation proceed if enough space was reclaimed.
/// Without crash-durable remote custody leases, candidates may still become
/// placeholders while their CAS blocks remain retained.
pub fn run_disk_pressure_eviction_sweep(
    ctx: MaterializationContext<'_>,
    group_id: &str,
    is_full_replica: bool,
    headroom_override_bytes: Option<u64>,
    custody: &dyn FullReplicaCustody,
) -> Result<Vec<String>, SyncError> {
    let MaterializationContext { state, liveness_gate, store, root } = ctx;
    // A full replica is the group's durable holder and never evicts.
    if is_full_replica {
        return Ok(vec![]);
    }
    let Ok(space) = free_space::classify_volume(root, headroom_override_bytes) else {
        return Ok(vec![]);
    };
    if space.classify() == FreeSpaceState::Ok {
        return Ok(vec![]);
    }

    let mut candidates = state.list_evictable_files(group_id)?;
    refresh_missing_last_accessed(state, root, group_id, &candidates);
    // Re-read now that any refreshed access times have been persisted, so
    // the LRU ordering below reflects them (same discipline as
    // `run_eviction_sweep` above).
    candidates = state.list_evictable_files(group_id)?;

    // The "no longer Low/Critical" boundary is the same `> 2x headroom`
    // threshold `classify` itself uses for `Ok` — stop once enough has been
    // freed (estimated, not re-queried per file) to cross it.
    let target_available = space.headroom_bytes.saturating_mul(2);
    let mut freed: u64 = 0;
    let mut evicted = Vec::new();
    for candidate in candidates {
        if space.available_bytes.saturating_add(freed) > target_available {
            break;
        }
        // Placeholdering releases the materialized working-tree copy. The
        // inner eviction operation separately requires verified custody before
        // deleting any content-addressed block. When `evict_file` early-returns
        // without writing the placeholder (candidate no longer current, pinned,
        // rehydrated, dirty, or on-disk identity changed) it freed no bytes, so
        // only count the working-tree copy against `freed` when it actually
        // dehydrated — otherwise the sweep over-estimates reclaimed space and
        // can stop while the volume is still under pressure.
        let outcome = evict_file(
            MaterializationContext { state, liveness_gate, store, root },
            group_id,
            &candidate.path,
            false,
            custody,
        )?;
        if !outcome.dehydrated {
            continue;
        }
        freed = freed.saturating_add(candidate.size);
        evicted.push(candidate.path);
    }
    Ok(evicted)
}

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
/// same discipline elsewhere in this file — so that ordering is
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
/// be established (see [`crate::root_identity`]). That distinction is the whole
/// fail-closed lane: this pass is the crash-vs-offline-delete disambiguator, so
/// a caller that reads "nothing to repair" from an unverifiable root goes on to
/// scan it and tombstone everything. An `Err` instead lands the link in the
/// daemon's existing `repair_failed_local_paths` set, which already suppresses
/// that scan's delete emission.
pub fn repair_interrupted_materializations(
    state: &SyncState,
    store: &dyn BlockStore,
    root: &Path,
    group_id: &str,
) -> Result<MaterializationRepairReport, SyncError> {
    let root = VerifiedRoot::open(root, group_id, state)?;
    repair_interrupted_materializations_inner(state, store, &root, group_id, None)
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
    state: &SyncState,
    store: &dyn BlockStore,
    root: &Path,
    group_id: &str,
    delete_emitter: &ChangeEmitter,
) -> Result<MaterializationRepairReport, SyncError> {
    let root = VerifiedRoot::open(root, group_id, state)?;
    repair_interrupted_materializations_inner(state, store, &root, group_id, Some(delete_emitter))
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
    state: &SyncState,
    store: &dyn BlockStore,
    root: &VerifiedRoot,
    group_id: &str,
    delete_emitter: Option<&ChangeEmitter>,
) -> Result<MaterializationRepairReport, SyncError> {
    let mut report = MaterializationRepairReport::default();
    let root = root.path();
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
        if snapshot_mstate != MaterializationState::Hydrated {
            continue;
        }

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
        if state.get_materialization_state(group_id, &path)? != Some(MaterializationState::Hydrated)
        {
            continue;
        }
        if state.get_record_kind(group_id, &path)?.unwrap_or_default() != RecordKind::File {
            continue;
        }
        let Some(record) = state.get_file(group_id, &path)? else { continue };
        if record.deleted || record.blocks.is_empty() {
            continue;
        }

        let out_path = root.join(&path);
        let on_disk_size = std::fs::metadata(&out_path).ok().map(|m| m.len());
        let disk_matches_index = on_disk_size == Some(record.size)
            && disk_bytes_match_indexed_blocks(&out_path, &record.blocks)?;
        if disk_matches_index {
            // The write completed and its bytes match the index. Any intent
            // left dangling by a crash in the narrow window between the rename
            // and its own clear is now moot — drop it so a later offline
            // deletion of this same path is never misread as a crash.
            state.clear_materialization_intent(group_id, &path)?;
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
        if on_disk_size.is_none() && !has_intent {
            match delete_emitter {
                Some(emitter) => match state.mark_deleted_emitting_change(
                    group_id,
                    &path,
                    emitter.device_id(),
                    repair_now_unix_nanos(),
                    emitter,
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
                    Err(SyncError::PolicyUnavailable) => {
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
        if on_disk_size.is_some() {
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
            match reconstruct_file_journaled(
                state,
                store,
                group_id,
                &path,
                &out_path,
                &record.blocks,
                &target_hash,
            ) {
                Ok(()) => report.reconstructed.push(path),
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
                    )?;
                    verify_write_target_within_root(&out_path, root)?;
                    write_placeholder(&out_path, record.size, record.mtime_unix_nanos)?;
                    apply_exec_bit(&out_path, state.get_exec_bit(group_id, &path)?)?;
                    // A Placeholder is not an in-progress write; drop any intent
                    // (`reconstruct_file_journaled` only clears on success) so a
                    // later offline delete of this path is not misread as a
                    // crash to reconstruct.
                    state.clear_materialization_intent(group_id, &path)?;
                    report.demoted_to_placeholder.push(path);
                }
            }
        } else {
            state.set_materialization_state(group_id, &path, MaterializationState::Placeholder)?;
            verify_write_target_within_root(&out_path, root)?;
            write_placeholder(&out_path, record.size, record.mtime_unix_nanos)?;
            // A placeholder is a fresh file too, so it needs the recorded exec
            // bit applied for the same reason the reconstruct path does — the
            // live peer materialize path stamps its own placeholders
            // identically, and hydration re-applies the bit once real content
            // lands, so it survives the placeholder → hydrated transition.
            apply_exec_bit(&out_path, state.get_exec_bit(group_id, &path)?)?;
            // See the reconstruct-failure arm above: a Placeholder carries no
            // in-progress intent.
            state.clear_materialization_intent(group_id, &path)?;
            report.demoted_to_placeholder.push(path);
        }
    }
    Ok(report)
}

/// The single sanctioned owner of the materialization-intent discipline:
/// "write a durable intent BEFORE the file's bytes / before any `Hydrated`
/// commit, and clear it ONLY after the temp-write-then-rename is durable (or
/// when the write is abandoned to a `Placeholder`, which is not an in-progress
/// write)". Both repair's own reconstruct ([`reconstruct_file_journaled`]) and
/// the live peer materialize path (`PeerSyncSession::materialize`) bracket their
/// disk write with this guard, so the crash-vs-offline-delete disambiguation in
/// [`repair_interrupted_materializations`] can never be defeated by a write path
/// that forgets to journal.
///
/// Opening the guard writes the intent (durable under `PRAGMA synchronous =
/// FULL`). [`Self::clear`] removes it — call it only once the bytes are durably
/// on disk, or once the write has been demoted to a `Placeholder`. Dropping the
/// guard WITHOUT calling `clear` (an early `?` return on a failed write, or a
/// panic) deliberately leaves the intent in place: that is the crash-safe
/// default that makes the next repair pass reconstruct from the blocks rather
/// than tombstone a genuinely-interrupted write. Callers must route ALL intent
/// begin/clear through this type — see `scripts/check-materialization-journal.py`,
/// which forbids raw `begin_materialization_intent`/`clear_materialization_intent`
/// calls outside this module so a new write path cannot reintroduce the
/// forgot-to-journal data-loss bug.
#[must_use = "an intent guard that is neither cleared nor deliberately dropped leaves a durable \
              materialization intent behind"]
pub(crate) struct MaterializationIntentGuard<'a> {
    state: &'a SyncState,
    group_id: &'a str,
    path: &'a str,
}

impl<'a> MaterializationIntentGuard<'a> {
    /// Opens (durably writes) the materialization intent for `(group_id, path)`
    /// targeting `target_version_hash`'s content. MUST be called before the
    /// bytes are written and before any `Hydrated` row is committed for this
    /// path.
    pub(crate) fn open(
        state: &'a SyncState,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
    ) -> Result<Self, SyncError> {
        state.begin_materialization_intent(group_id, path, target_version_hash)?;
        Ok(Self { state, group_id, path })
    }

    /// Clears the intent. Call ONLY after the temp-write-then-rename is durable,
    /// or when the write has been abandoned to a `Placeholder` — neither is an
    /// in-progress write, so a later offline delete of this path must NOT be
    /// misread as a crash to reconstruct.
    pub(crate) fn clear(self) -> Result<(), SyncError> {
        // Consumes the guard so a caller cannot clear twice or keep using it.
        self.state.clear_materialization_intent(self.group_id, self.path)
    }
}

/// Assembles `record`'s indexed blocks onto disk at `out_path` under a durable
/// materialization intent, so a crash *during this write itself* is recoverable
/// (the intent is still present on the next repair pass) rather than being
/// misread as an offline deletion of a `Hydrated` file. Brackets the write with
/// [`MaterializationIntentGuard`] — the same single seam the live peer
/// materialize path uses — so the intent is durable before the
/// temp-write-then-rename begins and cleared only after it completes.
///
/// `Ok(())` means the *whole* materialization sequence completed — bytes
/// assembled, intent cleared, and the indexed owner-exec bit applied — not
/// merely that the content landed. Repair reports a path as `reconstructed` on
/// exactly that basis, so a file it lists is left the way the live peer
/// materialize path would have left it, permissions included, rather than
/// being a second, weaker materialization implementation.
fn reconstruct_file_journaled(
    state: &SyncState,
    store: &dyn BlockStore,
    group_id: &str,
    path: &str,
    out_path: &Path,
    blocks: &[crate::types::BlockInfo],
    target_version_hash: &[u8],
) -> Result<(), SyncError> {
    let guard = MaterializationIntentGuard::open(state, group_id, path, target_version_hash)?;
    // On `Err` the `?` returns while `guard` is still live, so it drops without
    // clearing — the intent stays, and the next repair pass treats a resulting
    // missing file as a crash to recover, never as an offline delete.
    reconstruct_file(store, out_path, blocks)?;
    // Clear as soon as the rename is durable — BEFORE the exec-bit touch below,
    // never after. `apply_exec_bit` is a real `chmod` on POSIX, so clearing only
    // after it would leak the intent whenever reading or applying the bit
    // errored, even though the bytes are already durably on disk; a later
    // genuine offline delete of this path would then read `missing + intent
    // present` and wrongly resurrect it from the blocks. The live peer
    // materialize path orders these two steps this way for the same reason.
    guard.clear()?;
    // `reconstruct_file` assembles into a fresh temp file, which gets default
    // permissions — so the assembled result does NOT carry the exec bit the
    // index recorded for this path, and a repaired POSIX executable would come
    // back as a plain file. Nothing downstream would ever notice: the startup
    // scan re-reads these bytes, finds them byte-identical to the indexed
    // blocks, and suppresses the path as a self-echo before any exec-bit
    // comparison, leaving the index permanently claiming an exec bit the file
    // on disk does not have.
    apply_exec_bit(out_path, state.get_exec_bit(group_id, path)?)
}

/// A stable content-derived identifier for a materialization intent's target:
/// SHA-256 over the record's block-hash sequence. Only its *presence* gates
/// repair's crash-vs-offline-delete decision; this value is stored for
/// diagnostics and to let the intent name the exact content it was producing.
/// Shared with the live peer materialize path (`PeerSyncSession::materialize`),
/// which journals the same intent before committing a brand-new row, so both
/// the repair-side and live-side intents name their target the same way.
pub(crate) fn intent_target_hash(blocks: &[crate::types::BlockInfo]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for block in blocks {
        hasher.update(&block.hash);
    }
    hasher.finalize().to_vec()
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

pub fn disk_bytes_match_indexed_blocks(
    path: &Path,
    blocks: &[crate::types::BlockInfo],
) -> Result<bool, SyncError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    for block in blocks {
        let mut bytes = vec![0u8; block.size as usize];
        if let Err(error) = file.read_exact(&mut bytes) {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(false);
            }
            return Err(error.into());
        }
        if Sha256::digest(&bytes).as_slice() != block.hash.as_slice() {
            return Ok(false);
        }
    }
    let mut trailing = [0u8; 1];
    Ok(file.read(&mut trailing)? == 0)
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
    state: &SyncState,
    root: &Path,
    group_id: &str,
) -> Result<RestoreRecoveryReport, SyncError> {
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
                    crate::index::RestoreCommitOutcome::Committed(_) => {}
                    crate::index::RestoreCommitOutcome::Missing => continue,
                    crate::index::RestoreCommitOutcome::Superseded => {
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
/// (`crate::conflict::conflict_copy_path`), so it reads naturally to the user
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
) -> Result<Option<(String, i64)>, SyncError> {
    use sha2::{Digest, Sha256};
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
    let quarantine_rel =
        crate::conflict::conflict_copy_path(rel_path, mtime_unix_nanos, "local-recovered", &disamb);
    let dst = root.join(&quarantine_rel);
    verify_write_target_within_root(&dst, root)?;
    std::fs::rename(&src, &dst)?;
    Ok(Some((quarantine_rel, mtime_unix_nanos)))
}

/// recursively removes stale temp-write artifacts left behind by
/// an interrupted `chunker::reconstruct_file`/`write_placeholder`/
/// `materialize_symlink_at` call (or `FsBlockStore::put`, when `root` is a
/// block-store root instead of a link's synced folder — both crates'
/// `unique_tmp_path` helpers generate the identical naming scheme). A
/// crash between creating one of those temp files and the rename that
/// would have replaced it leaves it sitting on disk forever, since nothing
/// else ever revisits it.
///
/// Only ever removes a filename matching the *exact*
/// `<original-name>.yadorilink-tmp.<pid>.<counter>` suffix shape those
/// functions generate (both `<pid>` and `<counter>` non-empty and
/// ASCII-digit-only) — see `is_own_stale_temp_file_name`. Aggressive
/// cleanup could delete user files, so a
/// user file that merely *contains* the substring `.yadorilink-tmp.`
/// somewhere in a name it chose itself (e.g. `notes.yadorilink-tmp.txt`,
/// or `report.yadorilink-tmp.12345.7.bak`) is deliberately left untouched
/// — real temp files this crate creates never have anything follow the
/// numeric counter.
///
/// Safe to call unconditionally at every startup, before any other
/// recovery or sync work begins: any matching file that still exists at
/// that point is by definition orphaned — this process hasn't performed a
/// single write yet, and the only path that ever creates one either
/// completes with a rename that removes it, or is a *previous* run's
/// writer that got killed mid-write.
///
/// Best-effort per-entry: a failure to read one subdirectory, or to remove
/// one matching file (e.g. a permissions problem), is skipped rather than
/// aborting the whole walk — one bad entry should not block cleanup of
/// every other stale temp file. Returns the paths actually removed.
pub fn cleanup_stale_temp_files(root: &Path) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    if root.is_dir() {
        walk_and_remove_stale_temp_files(root, &mut removed);
    }
    removed
}

fn walk_and_remove_stale_temp_files(dir: &Path, removed: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        let path = entry.path();
        if file_type.is_dir() {
            walk_and_remove_stale_temp_files(&path, removed);
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        if is_own_stale_temp_file_name(&name) && std::fs::remove_file(&path).is_ok() {
            removed.push(path);
        }
    }
}

/// Recognizes exactly the `.yadorilink-tmp.<pid>.<counter>` suffix
/// `unique_tmp_path` (`chunker.rs`, and `yadorilink-local-storage`'s
/// `fs_backend.rs`) appends — see `cleanup_stale_temp_files`'s doc comment
/// for why this must be strict rather than a bare substring match.
fn is_own_stale_temp_file_name(name: &str) -> bool {
    const MARKER: &str = ".yadorilink-tmp.";
    let Some(idx) = name.find(MARKER) else { return false };
    let suffix = &name[idx + MARKER.len()..];
    let mut parts = suffix.split('.');
    let (Some(pid), Some(counter), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    is_ascii_digits(pid) && is_ascii_digits(counter)
}

fn is_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BlockInfo, FileRecord};
    use crate::version_vector::VersionVector;

    /// Gives `root` a sync-root marker for `group`, the way a real link acquires
    /// one: adopt while the index is still empty.
    ///
    /// The repair tests below index a `Hydrated` file and then leave the root
    /// empty, which is exactly what an unmounted volume looks like — so
    /// `VerifiedRoot::open` would rightly refuse to repair it. Adopting first
    /// states what those tests actually mean: the volume is mounted, and this
    /// particular file is missing from a folder that really is this link's.
    fn adopt_root(state: &SyncState, group: &str, root: &Path) {
        VerifiedRoot::open(root, group, state).unwrap();
    }

    /// Custody stub: a full replica always holds the exact version —
    /// exercises the reclamation path in isolation from the netmap wiring.
    fn always_confirmed(
        _group_id: &str,
        _path: &str,
        _version_hash: &VersionHash,
        _blocks: &[VersionBlock],
    ) -> bool {
        true
    }
    /// The fail-closed opposite: custody is never confirmed, so an on-demand
    /// device retains its cached blocks.
    fn never_confirmed(
        _group_id: &str,
        _path: &str,
        _version_hash: &VersionHash,
        _blocks: &[VersionBlock],
    ) -> bool {
        false
    }

    /// A fresh filesystem block store plus its owning tempdir (which must be
    /// kept alive for the store's lifetime).
    fn new_store() -> (yadorilink_local_storage::FsBlockStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = yadorilink_local_storage::FsBlockStore::new(dir.path()).unwrap();
        (store, dir)
    }

    /// Stores `content` as one block and returns a hydrated record whose
    /// single `BlockInfo` references it — so eviction has a real block in the
    /// store to reclaim (or retain).
    fn store_and_record(
        store: &yadorilink_local_storage::FsBlockStore,
        path: &str,
        content: &[u8],
    ) -> FileRecord {
        use yadorilink_local_storage::BlockStore as _;
        let hash_hex = store.put(content).unwrap();
        let hash = hex::decode(&hash_hex).unwrap();
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        }
    }

    fn hydrated_record(path: &str, size: u64) -> FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![BlockInfo { hash: vec![0xAB; 32], offset: 0, size: size as u32 }],
            deleted: false,
        }
    }

    #[test]
    fn evict_replaces_content_with_a_placeholder_of_the_same_size() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();
        state.upsert_file("group-1", &hydrated_record("a.bin", 1000)).unwrap();
        std::fs::write(root.path().join("a.bin"), vec![9u8; 1000]).unwrap();

        evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "a.bin",
            false,
            &always_confirmed,
        )
        .unwrap();

        assert_eq!(
            state.get_materialization_state("group-1", "a.bin").unwrap(),
            Some(MaterializationState::Placeholder)
        );
        let metadata = std::fs::metadata(root.path().join("a.bin")).unwrap();
        assert_eq!(metadata.len(), 1000);
        assert!(std::fs::read(root.path().join("a.bin")).unwrap().iter().all(|&b| b == 0));

        // Sync state (version, blocks) is untouched by eviction.
        let record = state.get_file("group-1", "a.bin").unwrap().unwrap();
        assert_eq!(record.version.get("device-a"), 1);
        assert_eq!(record.blocks.len(), 1);
    }

    #[test]
    fn evict_rejects_a_pinned_file() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &hydrated_record("a.bin", 1000)).unwrap();
        state.set_pinned("group-1", "a.bin", true).unwrap();
        std::fs::write(root.path().join("a.bin"), vec![9u8; 1000]).unwrap();

        let (store, _store_dir) = new_store();
        let err = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "a.bin",
            false,
            &always_confirmed,
        )
        .unwrap_err();
        assert!(matches!(err, SyncError::EvictionRejected(_)));
        assert_eq!(
            state.get_materialization_state("group-1", "a.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
    }

    #[test]
    fn eviction_fails_closed_while_the_same_path_is_busy() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();
        let content = b"content protected by an active path operation".to_vec();
        let record = store_and_record(&store, "busy.bin", &content);
        state.upsert_file("group-1", &record).unwrap();
        std::fs::write(root.path().join("busy.bin"), &content).unwrap();

        let path_lock = state.path_lock("group-1", "busy.bin");
        let _active_operation = path_lock.try_lock().unwrap();
        let result = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "busy.bin",
            false,
            &always_confirmed,
        );

        assert!(matches!(result, Err(SyncError::EvictionRejected(_))));
        assert_eq!(
            state.get_materialization_state("group-1", "busy.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
        assert_eq!(std::fs::read(root.path().join("busy.bin")).unwrap(), content);
    }

    /// Regression guard for the version race: a custody confirmation obtained
    /// during eviction authorizes deleting only the *exact* version it was
    /// confirmed for. If a concurrent local edit advances the file to a new
    /// version (different blocks) while the confirmation is in flight, the
    /// compare-and-set before reclaim must detect the change and retain the
    /// blocks rather than delete the now-current version's data on the strength
    /// of a superseded confirmation. Note the two versions here share a version
    /// vector but differ in blocks — proving the guard keys on the block set
    /// (the true content identity), not on causal version metadata.
    ///
    /// This is the acceptance condition for "a superseded version's
    /// confirmation is not reused for a later version": the CAS lives here,
    /// in `evict_file`, and is agnostic to how `custody.full_replica_holds`
    /// was answered, so a real peer-to-peer `confirm_version_present_via_peer`
    /// reply plugged in as the confirmer (as `yadorilink-daemon`'s
    /// `P2pCustodyConfirmer` does) is checked by this same post-confirmation
    /// re-read; exercising the guard with a fake confirmer closure already
    /// covers the real one too, and there is no separate "current version"
    /// notion at the `confirm_version_present_via_peer` layer for a second
    /// test to target. `custody_version_present.rs`'s "a hash set that does
    /// not match held.bin's current version must not confirm" assertion
    /// additionally covers the responder-side half: a live full replica
    /// refusing to confirm a block set that no longer matches its own current
    /// record.
    #[test]
    fn eviction_retains_blocks_when_version_changes_during_confirmation() {
        use yadorilink_local_storage::BlockStore as _;

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();

        // v1 of race.bin, with a real block in the store.
        let v1 = store_and_record(&store, "race.bin", b"version one contents");
        let v1_hash_hex = hex::encode(&v1.blocks[0].hash);
        state.upsert_file("group-1", &v1).unwrap();
        std::fs::write(root.path().join("race.bin"), b"version one contents").unwrap();

        // A superseding version with a different block, applied *during* the
        // custody confirmation to model a concurrent local edit landing while
        // the peer round-trip is in flight.
        let v2 = store_and_record(&store, "race.bin", b"version two, different bytes");
        let v2_hash_hex = hex::encode(&v2.blocks[0].hash);
        let confirm_then_supersede =
            |_g: &str, _p: &str, _vh: &VersionHash, _blocks: &[VersionBlock]| {
                state.upsert_file("group-1", &v2).unwrap();
                true
            };

        let outcome = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "race.bin",
            false,
            &confirm_then_supersede,
        )
        .unwrap();

        assert!(
            outcome.blocks_retained,
            "confirmation was for v1 but the record is now v2; the CAS must retain"
        );
        assert_eq!(outcome.blocks_reclaimed, 0);
        assert!(
            store.exists(&v1_hash_hex).unwrap(),
            "v1's block must not be reclaimed on the strength of a superseded confirmation"
        );
        assert!(store.exists(&v2_hash_hex).unwrap(), "v2's block is untouched");
    }

    /// The post-custody CAS binds the FULL `change::VersionHash`, not just the
    /// block set: a METADATA-ONLY current-version transition (identical
    /// blocks, flipped exec bit) that lands after custody was confirmed for
    /// the old identity must make the reclaim retain, because custody attested
    /// the old VersionHash and the current version is now a different one. If
    /// the CAS compared block hashes alone, this meta-only change would slip
    /// through and reclaim blocks confirmed for a version that is no longer
    /// current. Paired with a positive baseline (no change → reclaims) so the
    /// retain is provably the meta change, not a broken reclaim path.
    #[test]
    fn eviction_retains_blocks_on_a_metadata_only_change_during_confirmation() {
        use yadorilink_local_storage::BlockStore as _;

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();

        // --- Positive baseline: no change during confirmation -> reclaims. ---
        let plain = store_and_record(&store, "plain.bin", b"plain file, evicted cleanly");
        let plain_hash_hex = hex::encode(&plain.blocks[0].hash);
        state.upsert_file("group-1", &plain).unwrap();
        std::fs::write(root.path().join("plain.bin"), b"plain file, evicted cleanly").unwrap();

        let baseline = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "plain.bin",
            false,
            &always_confirmed,
        )
        .unwrap();
        assert!(!baseline.blocks_retained, "baseline: no version change, so blocks are reclaimed");
        assert_eq!(baseline.blocks_reclaimed, 1);
        assert!(
            !store.exists(&plain_hash_hex).unwrap(),
            "baseline: the reclaimed block is gone from the store"
        );

        // --- Meta-only change during confirmation -> retains. ---
        let meta = store_and_record(&store, "meta.bin", b"file whose exec bit will flip");
        let meta_hash_hex = hex::encode(&meta.blocks[0].hash);
        state.upsert_file("group-1", &meta).unwrap();
        std::fs::write(root.path().join("meta.bin"), b"file whose exec bit will flip").unwrap();

        // The confirmer flips the exec bit on the CURRENT row — SAME blocks,
        // different `change::VersionHash` — modeling a metadata-only local
        // edit landing while the custody round-trip is in flight.
        let flip_exec_bit_mid_confirm =
            |_g: &str, _p: &str, _vh: &VersionHash, _blocks: &[VersionBlock]| {
                state.set_exec_bit("group-1", "meta.bin", true).unwrap();
                true
            };

        let outcome = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "meta.bin",
            false,
            &flip_exec_bit_mid_confirm,
        )
        .unwrap();

        assert!(
            outcome.blocks_retained,
            "custody was confirmed for the pre-flip VersionHash; a meta-only change makes the \
             current version a different VersionHash, so the CAS must retain"
        );
        assert_eq!(outcome.blocks_reclaimed, 0);
        assert!(
            store.exists(&meta_hash_hex).unwrap(),
            "the block must survive: it is confirmed only for a now-superseded version identity"
        );
    }

    #[test]
    fn sweep_evicts_least_recently_used_until_under_cap() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();

        for (name, size, accessed) in
            [("old.bin", 400, Some(100)), ("mid.bin", 400, Some(200)), ("new.bin", 400, Some(300))]
        {
            state.upsert_file("group-1", &hydrated_record(name, size)).unwrap();
            std::fs::write(root.path().join(name), vec![1u8; size as usize]).unwrap();
            if let Some(ts) = accessed {
                state.touch_last_accessed("group-1", name, ts).unwrap();
            }
        }
        // Total usage 1200; cap 500 — must evict old.bin and mid.bin
        // (800 bytes freed) to get to 400, but stop before evicting new.bin.
        let (store, _store_dir) = new_store();
        let evicted = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            false,
            Some(500),
            &always_confirmed,
        )
        .unwrap();
        assert_eq!(evicted, vec!["old.bin".to_string(), "mid.bin".to_string()]);

        assert_eq!(
            state.get_materialization_state("group-1", "new.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
    }

    /// 's atime fallback: a file read many times without ever
    /// going through the daemon (so `last_accessed_unix` was never
    /// recorded) must still be recognized as recently used via its
    /// on-disk `atime`, rather than looking like it was never accessed
    /// at all and getting evicted ahead of a genuinely older file.
    #[test]
    fn sweep_refreshes_last_accessed_from_atime_for_files_never_touched_via_hydration() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();

        state.upsert_file("group-1", &hydrated_record("recently-read.bin", 1000)).unwrap();
        let path = root.path().join("recently-read.bin");
        std::fs::write(&path, vec![1u8; 1000]).unwrap();
        // Same write-access requirement as local_change.rs's mtime-setting
        // test -- Windows' SetFileTime needs a write-capable handle even
        // to set atime; File::open alone is read-only there.
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_accessed(std::time::SystemTime::now()))
            .unwrap();

        state.upsert_file("group-1", &hydrated_record("old.bin", 1000)).unwrap();
        std::fs::write(root.path().join("old.bin"), vec![1u8; 1000]).unwrap();
        state.touch_last_accessed("group-1", "old.bin", 100).unwrap();

        let (store, _store_dir) = new_store();
        let evicted = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            false,
            Some(1000),
            &always_confirmed,
        )
        .unwrap();
        assert_eq!(evicted, vec!["old.bin".to_string()]);
    }

    #[test]
    fn sweep_never_evicts_pinned_files_even_when_over_cap() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &hydrated_record("pinned.bin", 1000)).unwrap();
        state.set_pinned("group-1", "pinned.bin", true).unwrap();
        std::fs::write(root.path().join("pinned.bin"), vec![1u8; 1000]).unwrap();

        let (store, _store_dir) = new_store();
        let evicted = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            false,
            Some(0),
            &always_confirmed,
        )
        .unwrap();
        assert!(evicted.is_empty());
        assert_eq!(
            state.get_materialization_state("group-1", "pinned.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
    }

    /// pinned-but-hydrated content must count toward usage even
    /// though it's never itself a candidate. Before the fix, usage was
    /// summed only from evictable (unpinned) candidates — with a large
    /// pinned file plus a small unpinned one, that undercount made the
    /// sweep think it was already under cap and evict nothing, even
    /// though real total usage (pinned + unpinned) exceeded it.
    #[test]
    fn sweep_counts_pinned_usage_toward_cap_even_though_only_unpinned_is_evicted() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();

        state.upsert_file("group-1", &hydrated_record("pinned.bin", 800)).unwrap();
        state.set_pinned("group-1", "pinned.bin", true).unwrap();
        std::fs::write(root.path().join("pinned.bin"), vec![1u8; 800]).unwrap();

        state.upsert_file("group-1", &hydrated_record("unpinned.bin", 500)).unwrap();
        std::fs::write(root.path().join("unpinned.bin"), vec![1u8; 500]).unwrap();

        // Total real usage is 1300 (800 pinned + 500 unpinned), over the
        // cap of 1000 — but the unpinned-only candidate list sums to just
        // 500, which is already under 1000. The old bug would stop here
        // and evict nothing.
        let (store, _store_dir) = new_store();
        let evicted = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            false,
            Some(1000),
            &always_confirmed,
        )
        .unwrap();
        assert_eq!(evicted, vec!["unpinned.bin".to_string()]);
        assert_eq!(
            state.get_materialization_state("group-1", "unpinned.bin").unwrap(),
            Some(MaterializationState::Placeholder)
        );
        assert_eq!(
            state.get_materialization_state("group-1", "pinned.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
    }

    /// A sweep must only count a candidate as evicted when `evict_file`
    /// actually dehydrated it. A candidate that `evict_file` early-returns on
    /// (here: a path with a pending local edit, so it's still an evictable
    /// candidate but must not be overwritten) frees no working-tree bytes, so
    /// it must not appear in `evicted` and must not be subtracted from the
    /// tracked usage — otherwise the sweep over-reports reclaimed capacity and
    /// can stop while still over the cap. A clean hydrated candidate, which
    /// does dehydrate to a placeholder (blocks retained under unconfirmed
    /// custody), still must be reported.
    #[test]
    fn sweep_skips_a_candidate_that_evict_file_declines_to_dehydrate() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();

        // `dirty.bin` is hydrated and unpinned (so `list_evictable_files`
        // still ranks it) but carries a pending local edit — `evict_file`
        // early-returns on it before writing any placeholder, freeing nothing.
        // It sorts first (least-recently-accessed) so a buggy sweep would
        // count it before reaching the clean candidate.
        state.upsert_file("group-1", &hydrated_record("dirty.bin", 1000)).unwrap();
        std::fs::write(root.path().join("dirty.bin"), vec![1u8; 1000]).unwrap();
        state.touch_last_accessed("group-1", "dirty.bin", 100).unwrap();
        state.record_dirty_path("group-1", "dirty.bin", "created_or_modified", 0).unwrap();

        // `clean.bin` genuinely dehydrates to a placeholder (blocks retained,
        // since custody is unconfirmed) and must be the only reported eviction.
        state.upsert_file("group-1", &hydrated_record("clean.bin", 1000)).unwrap();
        std::fs::write(root.path().join("clean.bin"), vec![1u8; 1000]).unwrap();
        state.touch_last_accessed("group-1", "clean.bin", 200).unwrap();

        // Total hydrated usage is 2000, cap 500 — both files are candidates,
        // dirty.bin first. Only clean.bin actually dehydrates.
        let evicted = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            false,
            Some(500),
            &never_confirmed,
        )
        .unwrap();

        assert_eq!(
            evicted,
            vec!["clean.bin".to_string()],
            "only the candidate that actually dehydrated is reported; the path-dirty \
             early-return must not be counted"
        );
        assert_eq!(
            state.get_materialization_state("group-1", "dirty.bin").unwrap(),
            Some(MaterializationState::Hydrated),
            "the declined candidate is left materialized"
        );
        assert_eq!(
            state.get_materialization_state("group-1", "clean.bin").unwrap(),
            Some(MaterializationState::Placeholder)
        );
    }

    #[test]
    fn sweep_no_ops_when_no_cap_configured() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &hydrated_record("a.bin", 1_000_000)).unwrap();
        std::fs::write(root.path().join("a.bin"), vec![1u8; 1_000_000]).unwrap();

        let (store, _store_dir) = new_store();
        let evicted = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            false,
            None,
            &always_confirmed,
        )
        .unwrap();
        assert!(evicted.is_empty());
        assert_eq!(
            state.get_materialization_state("group-1", "a.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
    }

    // --- Custody-gated cache reclamation ----------------------------------

    /// Once a full replica is confirmed to hold a file's blocks, evicting it on
    /// an on-demand device deletes those cached blocks from the block store,
    /// freeing real space — not just placeholdering the file.
    #[test]
    fn evict_reclaims_cached_blocks_once_custody_is_confirmed() {
        use yadorilink_local_storage::BlockStore as _;
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();

        let content = b"content a full replica already holds".to_vec();
        let record = store_and_record(&store, "doc.bin", &content);
        let hash_hex = hex::encode(&record.blocks[0].hash);
        state.upsert_file("group-1", &record).unwrap();
        std::fs::write(root.path().join("doc.bin"), &content).unwrap();
        assert!(store.exists(&hash_hex).unwrap(), "block present before eviction");

        let outcome = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "doc.bin",
            false,
            &always_confirmed,
        )
        .unwrap();

        assert_eq!(
            state.get_materialization_state("group-1", "doc.bin").unwrap(),
            Some(MaterializationState::Placeholder)
        );
        assert!(!store.exists(&hash_hex).unwrap(), "cached block reclaimed once custody confirmed");
        assert_eq!(outcome.blocks_reclaimed, 1);
        assert_eq!(outcome.bytes_reclaimed, content.len() as u64);
        assert!(!outcome.blocks_retained);
        // Sync state (version, blocks) is untouched — the block list still
        // references the (now-absent) block so hydration can re-fetch it.
        let after = state.get_file("group-1", "doc.bin").unwrap().unwrap();
        assert_eq!(after.blocks.len(), 1);
    }

    /// Fail-closed: when custody cannot be confirmed (e.g. an un-replicated
    /// local edit), the file may still become a placeholder but its blocks are
    /// retained — this device must not delete a possibly last copy.
    #[test]
    fn evict_retains_cached_blocks_when_custody_is_unconfirmed() {
        use yadorilink_local_storage::BlockStore as _;
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();

        let content = b"content no full replica has yet".to_vec();
        let record = store_and_record(&store, "edit.bin", &content);
        let hash_hex = hex::encode(&record.blocks[0].hash);
        state.upsert_file("group-1", &record).unwrap();
        std::fs::write(root.path().join("edit.bin"), &content).unwrap();

        let outcome = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "edit.bin",
            false,
            &never_confirmed,
        )
        .unwrap();

        assert!(outcome.blocks_retained);
        assert_eq!(outcome.blocks_reclaimed, 0);
        assert!(store.exists(&hash_hex).unwrap(), "block retained while custody unconfirmed");
    }

    /// A full replica is the group's durable holder and never evicts live
    /// blocks, even when custody would otherwise be confirmed.
    #[test]
    fn full_replica_never_reclaims_blocks() {
        use yadorilink_local_storage::BlockStore as _;
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();

        let content = b"durable full-replica content".to_vec();
        let record = store_and_record(&store, "keep.bin", &content);
        let hash_hex = hex::encode(&record.blocks[0].hash);
        state.upsert_file("group-1", &record).unwrap();
        std::fs::write(root.path().join("keep.bin"), &content).unwrap();

        let outcome = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "keep.bin",
            true, // this device is a full replica
            &always_confirmed,
        )
        .unwrap();

        assert!(outcome.blocks_retained);
        assert_eq!(outcome.blocks_reclaimed, 0);
        assert!(store.exists(&hash_hex).unwrap(), "a full replica never drops a live block");
    }

    /// A pin/hydrate transition that wins while eviction waits for custody
    /// makes the old reclaim decision stale. The block must remain because
    /// the final state again requires local materialized content.
    #[test]
    fn eviction_must_not_reclaim_after_same_version_is_pinned_and_rehydrated() {
        use yadorilink_local_storage::BlockStore as _;
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();

        let content = b"rehydrated while custody confirmation waits".to_vec();
        let record = store_and_record(&store, "race.bin", &content);
        let hash_hex = hex::encode(&record.blocks[0].hash);
        state.upsert_file("group-1", &record).unwrap();
        std::fs::write(root.path().join("race.bin"), &content).unwrap();

        let custody = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| {
            state.set_pinned("group-1", "race.bin", true).unwrap();
            state
                .set_materialization_state("group-1", "race.bin", MaterializationState::Hydrated)
                .unwrap();
            true
        };

        evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "race.bin",
            false,
            &custody,
        )
        .unwrap();

        assert!(state.is_pinned("group-1", "race.bin").unwrap());
        assert_eq!(
            state.get_materialization_state("group-1", "race.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
        assert!(store.exists(&hash_hex).unwrap(), "rehydrated content still needs its block");
    }

    #[test]
    fn eviction_retains_content_when_disk_changes_during_custody_confirmation() {
        use yadorilink_local_storage::BlockStore as _;
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();

        let content = b"indexed bytes before custody wait".to_vec();
        let local_edit = b"local edit made during custody confirmation".to_vec();
        let record = store_and_record(&store, "disk-race.bin", &content);
        let hash_hex = hex::encode(&record.blocks[0].hash);
        state.upsert_file("group-1", &record).unwrap();
        let out_path = root.path().join("disk-race.bin");
        std::fs::write(&out_path, &content).unwrap();

        let custody = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| {
            std::fs::write(&out_path, &local_edit).unwrap();
            true
        };
        let outcome = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "disk-race.bin",
            false,
            &custody,
        )
        .unwrap();

        assert!(outcome.blocks_retained);
        assert_eq!(std::fs::read(&out_path).unwrap(), local_edit);
        assert!(store.exists(&hash_hex).unwrap(), "stale custody must not authorize reclaim");
        assert_eq!(
            state.get_materialization_state("group-1", "disk-race.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
    }

    /// Failing to write the placeholder must leave the index describing the
    /// still-materialized file, rather than hiding its real bytes behind a
    /// committed `Placeholder` state.
    #[test]
    fn failed_placeholder_write_must_not_commit_placeholder_state() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().to_path_buf();
        let (store, _store_dir) = new_store();

        let content = b"real user bytes must remain watcher-visible".to_vec();
        let record = store_and_record(&store, "write-fails.bin", &content);
        state.upsert_file("group-1", &record).unwrap();
        std::fs::write(root_path.join("write-fails.bin"), &content).unwrap();

        std::fs::remove_dir_all(&root_path).unwrap();
        std::fs::write(&root_path, b"not a directory").unwrap();

        let result = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: &root_path,
            },
            "group-1",
            "write-fails.bin",
            false,
            &always_confirmed,
        );

        assert!(result.is_err(), "invalid output root must fail placeholder write");
        assert_eq!(
            state.get_materialization_state("group-1", "write-fails.bin").unwrap(),
            Some(MaterializationState::Hydrated),
            "failed placeholder write must not hide the real file from the watcher"
        );
    }

    /// A block still shared with another hydrated file is kept even when the
    /// evicted file's own, unshared block is reclaimed.
    #[test]
    fn evict_keeps_blocks_still_backing_another_hydrated_file() {
        use yadorilink_local_storage::BlockStore as _;
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();

        let shared = b"shared block bytes".to_vec();
        let exclusive = b"exclusive-to-a block bytes".to_vec();
        let shared_hash = store.put(&shared).unwrap();
        let exclusive_hash = store.put(&exclusive).unwrap();

        let mut version = VersionVector::new();
        version.increment("device-a");
        let record_a = FileRecord {
            path: "a.bin".to_string(),
            size: (shared.len() + exclusive.len()) as u64,
            mtime_unix_nanos: 0,
            version: version.clone(),
            blocks: vec![
                BlockInfo {
                    hash: hex::decode(&shared_hash).unwrap(),
                    offset: 0,
                    size: shared.len() as u32,
                },
                BlockInfo {
                    hash: hex::decode(&exclusive_hash).unwrap(),
                    offset: shared.len() as u64,
                    size: exclusive.len() as u32,
                },
            ],
            deleted: false,
        };
        let record_b = FileRecord {
            path: "b.bin".to_string(),
            size: shared.len() as u64,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![BlockInfo {
                hash: hex::decode(&shared_hash).unwrap(),
                offset: 0,
                size: shared.len() as u32,
            }],
            deleted: false,
        };
        state.upsert_file("group-1", &record_a).unwrap();
        state.upsert_file("group-1", &record_b).unwrap();
        std::fs::write(root.path().join("a.bin"), b"a").unwrap();
        std::fs::write(root.path().join("b.bin"), b"b").unwrap();

        // b.bin stays hydrated, so the shared block must survive evicting a.bin.
        evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            "a.bin",
            false,
            &always_confirmed,
        )
        .unwrap();

        assert!(store.exists(&shared_hash).unwrap(), "shared block still backs b.bin");
        assert!(!store.exists(&exclusive_hash).unwrap(), "a.bin's exclusive block reclaimed");
    }

    fn assert_cross_group_reference_retains_shared_block(
        other_state: MaterializationState,
        pinned: bool,
    ) {
        use yadorilink_local_storage::BlockStore as _;
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();
        let content = b"same content shared across folder groups".to_vec();
        let record_a = store_and_record(&store, "group-a.bin", &content);
        let mut record_b = record_a.clone();
        record_b.path = "group-b.bin".to_string();
        let hash = hex::encode(&record_a.blocks[0].hash);
        state.upsert_file("group-a", &record_a).unwrap();
        state.upsert_file("group-b", &record_b).unwrap();
        state.set_materialization_state("group-b", "group-b.bin", other_state).unwrap();
        state.set_pinned("group-b", "group-b.bin", pinned).unwrap();
        std::fs::write(root.path().join("group-a.bin"), &content).unwrap();

        evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-a",
            "group-a.bin",
            false,
            &always_confirmed,
        )
        .unwrap();

        assert!(store.exists(&hash).unwrap(), "another group still references the shared block");
    }

    #[test]
    fn eviction_must_not_delete_block_used_by_hydrated_file_in_another_group() {
        assert_cross_group_reference_retains_shared_block(MaterializationState::Hydrated, false);
    }

    #[test]
    fn eviction_must_not_delete_block_retained_for_uncustodied_placeholder_in_another_group() {
        assert_cross_group_reference_retains_shared_block(MaterializationState::Placeholder, false);
    }

    #[test]
    fn eviction_must_not_delete_block_used_by_pinned_file_in_another_group() {
        assert_cross_group_reference_retains_shared_block(MaterializationState::Hydrated, true);
    }

    #[test]
    fn concurrent_evictions_across_groups_must_preserve_shared_block() {
        use std::sync::{Arc, Barrier};
        use yadorilink_local_storage::BlockStore as _;

        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();
        let store = Arc::new(store);
        let content = b"concurrently evicted cross-group content".to_vec();
        let record_a = store_and_record(store.as_ref(), "a.bin", &content);
        let mut record_b = record_a.clone();
        record_b.path = "b.bin".to_string();
        let hash = hex::encode(&record_a.blocks[0].hash);
        state.upsert_file("group-a", &record_a).unwrap();
        state.upsert_file("group-b", &record_b).unwrap();
        std::fs::write(root.path().join("a.bin"), &content).unwrap();
        std::fs::write(root.path().join("b.bin"), &content).unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let root = Arc::new(root.path().to_path_buf());
        let liveness_gate = Arc::new(BlockLivenessGate::default());
        let handles: Vec<_> = [("group-a", "a.bin"), ("group-b", "b.bin")]
            .into_iter()
            .map(|(group, path)| {
                let state = state.clone();
                let store = store.clone();
                let barrier = barrier.clone();
                let root = root.clone();
                let liveness_gate = liveness_gate.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    evict_file(
                        MaterializationContext {
                            state: state.as_ref(),
                            liveness_gate: liveness_gate.as_ref(),
                            store: store.as_ref(),
                            root: root.as_ref(),
                        },
                        group,
                        path,
                        false,
                        &always_confirmed,
                    )
                    .unwrap()
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        assert!(store.exists(&hash).unwrap(), "concurrent cross-group eviction deleted shared H");
    }

    /// The automatic sweep separates working-tree dehydrate from physical CAS
    /// reclamation: both files become placeholders, but only the version with
    /// verified custody may have its block deleted.
    #[test]
    fn sweep_dehydrates_unconfirmed_custody_but_retains_its_blocks() {
        use yadorilink_local_storage::BlockStore as _;
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (store, _store_dir) = new_store();

        let confirmed = store_and_record(&store, "confirmed.bin", &vec![7u8; 400]);
        let unconfirmed = store_and_record(&store, "unconfirmed.bin", &vec![8u8; 400]);
        let confirmed_hash = hex::encode(&confirmed.blocks[0].hash);
        let unconfirmed_hash = hex::encode(&unconfirmed.blocks[0].hash);
        state.upsert_file("group-1", &confirmed).unwrap();
        state.upsert_file("group-1", &unconfirmed).unwrap();
        std::fs::write(root.path().join("confirmed.bin"), vec![7u8; 400]).unwrap();
        std::fs::write(root.path().join("unconfirmed.bin"), vec![8u8; 400]).unwrap();
        // Access times make the unconfirmed candidate first, exercising the
        // retained-block path before the confirmed deletion path.
        state.touch_last_accessed("group-1", "unconfirmed.bin", 100).unwrap();
        state.touch_last_accessed("group-1", "confirmed.bin", 200).unwrap();

        // Custody only for confirmed.bin. Cap 0 forces the sweep to try every
        // candidate.
        let only_confirmed = |_g: &str, path: &str, _vh: &VersionHash, _blocks: &[VersionBlock]| {
            path == "confirmed.bin"
        };
        let evicted = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            false,
            Some(0),
            &only_confirmed,
        )
        .unwrap();

        assert_eq!(evicted, vec!["unconfirmed.bin".to_string(), "confirmed.bin".to_string()]);
        assert!(!store.exists(&confirmed_hash).unwrap(), "confirmed file's block reclaimed");
        assert!(store.exists(&unconfirmed_hash).unwrap(), "unconfirmed file's block retained");
        assert_eq!(
            state.get_materialization_state("group-1", "unconfirmed.bin").unwrap(),
            Some(MaterializationState::Placeholder)
        );
    }

    // --- Disk-space preflight ---------------------------------------------

    /// a materialize/hydrate write that would breach headroom
    /// fails with `DiskPressure` before anything is written — forced
    /// deterministically via a headroom override far larger than any real
    /// disk's free space (this crate's tests must not depend on the host
    /// machine's actual free space, confirmed a real concern elsewhere in
    /// this change).
    #[test]
    fn check_disk_headroom_rejects_when_it_would_breach() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("big-file.bin");
        let err = check_disk_headroom(dir.path(), &target, 1024, Some(u64::MAX / 2)).unwrap_err();
        assert!(matches!(err, SyncError::DiskPressure { .. }));
        // Nothing was written — the preflight runs before any temp file is
        // ever created, and this function itself never touches the
        // filesystem beyond the read-only free-space query.
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    /// The converse: a write comfortably under headroom (a zero-byte
    /// override, i.e. "no headroom required") is allowed.
    #[test]
    fn check_disk_headroom_allows_a_write_under_headroom() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("small-file.bin");
        check_disk_headroom(dir.path(), &target, 1024, Some(0)).unwrap();
    }

    // --- Disk-pressure-triggered
    // eviction ---------------------------------------------------------

    /// disk pressure on a volume triggers eviction on an
    /// OnDemand-style link with **no** configured cap at all
    /// (`run_eviction_sweep` itself would no-op here — see
    /// `sweep_no_ops_when_no_cap_configured` above — this is exactly the gap
    /// the disk-pressure trigger closes), evicting least-recently-used
    /// unpinned files until the volume is no longer `Low`/`Critical`.
    #[test]
    fn disk_pressure_sweep_evicts_lru_first_with_no_cap_configured() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();

        for (name, size, accessed) in
            [("old.bin", 400, Some(100)), ("mid.bin", 400, Some(200)), ("new.bin", 400, Some(300))]
        {
            state.upsert_file("group-1", &hydrated_record(name, size)).unwrap();
            std::fs::write(root.path().join(name), vec![1u8; size as usize]).unwrap();
            state.touch_last_accessed("group-1", name, accessed.unwrap()).unwrap();
        }

        // Force a `Critical` classification via a huge headroom override,
        // then confirm eviction runs and stops in LRU order — same
        // assertion shape as `sweep_evicts_least_recently_used_until_under_cap`,
        // but reached with *no* cap configured at all.
        let (store, _store_dir) = new_store();
        let evicted = run_disk_pressure_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            false,
            Some(u64::MAX / 2),
            &always_confirmed,
        )
        .unwrap();
        assert!(!evicted.is_empty(), "expected at least one eviction under forced disk pressure");
        assert_eq!(evicted[0], "old.bin", "least-recently-accessed must be evicted first");
    }

    /// pinned files are never evicted by the disk-pressure
    /// trigger, exactly as they're already excluded from the cap trigger
    /// (reused, not reimplemented).
    #[test]
    fn disk_pressure_sweep_never_evicts_pinned_files() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &hydrated_record("pinned.bin", 1000)).unwrap();
        state.set_pinned("group-1", "pinned.bin", true).unwrap();
        std::fs::write(root.path().join("pinned.bin"), vec![1u8; 1000]).unwrap();

        let (store, _store_dir) = new_store();
        let evicted = run_disk_pressure_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            false,
            Some(u64::MAX / 2),
            &always_confirmed,
        )
        .unwrap();
        assert!(evicted.is_empty());
        assert_eq!(
            state.get_materialization_state("group-1", "pinned.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
    }

    /// a volume that isn't under pressure (`Ok` classification —
    /// a zero headroom override, "no headroom required," is always `Ok`) is
    /// never swept, leaving an unrelated healthy link's files untouched.
    #[test]
    fn disk_pressure_sweep_no_ops_when_volume_is_not_under_pressure() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &hydrated_record("a.bin", 1000)).unwrap();
        std::fs::write(root.path().join("a.bin"), vec![1u8; 1000]).unwrap();

        let (store, _store_dir) = new_store();
        let evicted = run_disk_pressure_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
            },
            "group-1",
            false,
            Some(0),
            &always_confirmed,
        )
        .unwrap();
        assert!(evicted.is_empty());
        assert_eq!(
            state.get_materialization_state("group-1", "a.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
    }

    // --- Startup recovery ---------------------------------------------------

    use yadorilink_local_storage::FsBlockStore;

    fn record_with_blocks(path: &str, content: &[u8], hash: Vec<u8>) -> FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        }
    }

    #[test]
    fn restore_crash_after_rename_before_index_commit_recovers_exactly_once() {
        use crate::index::{RestoreOperation, RestoreOperationState};
        use yadorilink_local_storage::BlockStore as _;

        let (store, _store_dir) = new_store();
        let root = tempfile::tempdir().unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let old = b"restored-v1";

        let mut v1 = store_and_record(&store, "doc.txt", old);
        state.upsert_file_with_origin("group-1", &v1, "device-a").unwrap();
        state.mark_deleted("group-1", "doc.txt", "device-a").unwrap();
        let tombstone = state.get_file("group-1", "doc.txt").unwrap().unwrap();
        assert!(tombstone.deleted);
        assert!(!root.path().join("doc.txt").exists());

        let mut restored_version = tombstone.version;
        restored_version.increment("device-local");
        v1.version = restored_version;
        v1.mtime_unix_nanos = 1234;
        state
            .record_restore_operation(&RestoreOperation {
                operation_id: "restore-op-1".into(),
                group_id: "group-1".into(),
                path: "doc.txt".into(),
                target_version_seq: 1,
                expected_current_version_seq: Some(2),
                // The rename can land before this row is advanced to
                // DiskCommitted, so recovery must inspect bytes even while the
                // durable state still says Prepared.
                state: RestoreOperationState::Prepared,
                record: v1.clone(),
                origin_device_id: "device-local".into(),
            })
            .unwrap();

        // Simulate the durable rename having landed while SQLite still has
        // the V2 tombstone and the journal state update was not persisted.
        std::fs::write(root.path().join("doc.txt"), old).unwrap();
        let first = reconcile_restore_operations(&state, root.path(), "group-1").unwrap();
        assert_eq!(first.committed, vec!["doc.txt"]);
        assert_eq!(state.get_file("group-1", "doc.txt").unwrap(), Some(v1.clone()));
        assert_eq!(state.list_versions("group-1", "doc.txt").unwrap().len(), 3);

        // Recovery may be invoked again after another crash. The journal was
        // removed in the same transaction as V3, so no V4 can be created.
        let second = reconcile_restore_operations(&state, root.path(), "group-1").unwrap();
        assert_eq!(second, RestoreRecoveryReport::default());
        assert_eq!(state.list_versions("group-1", "doc.txt").unwrap().len(), 3);
        assert!(state.list_restore_operations("group-1").unwrap().is_empty());
        assert!(store.exists(&hex::encode(&v1.blocks[0].hash)).unwrap());
    }

    #[test]
    fn restore_recovery_preserves_unexplained_same_size_disk_edit() {
        use crate::index::{RestoreOperation, RestoreOperationState};

        let (store, _store_dir) = new_store();
        let root = tempfile::tempdir().unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let current_bytes = b"current-data";
        let restore_bytes = b"restore-data";
        let user_bytes = b"user-edit---";
        assert_eq!(current_bytes.len(), restore_bytes.len());
        assert_eq!(restore_bytes.len(), user_bytes.len());

        let current = store_and_record(&store, "doc.txt", current_bytes);
        state.upsert_file("group-1", &current).unwrap();
        let mut intended = store_and_record(&store, "doc.txt", restore_bytes);
        intended.version = current.version.clone();
        intended.version.increment("device-local");
        state
            .record_restore_operation(&RestoreOperation {
                operation_id: "restore-op-edit".into(),
                group_id: "group-1".into(),
                path: "doc.txt".into(),
                target_version_seq: 1,
                expected_current_version_seq: Some(1),
                state: RestoreOperationState::Prepared,
                record: intended,
                origin_device_id: "device-local".into(),
            })
            .unwrap();
        std::fs::write(root.path().join("doc.txt"), user_bytes).unwrap();

        let report = reconcile_restore_operations(&state, root.path(), "group-1").unwrap();
        assert_eq!(report.preserved_divergent, vec!["doc.txt"]);
        assert!(state.is_path_dirty("group-1", "doc.txt").unwrap());
        assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), user_bytes);
        assert_eq!(state.list_versions("group-1", "doc.txt").unwrap().len(), 1);
    }

    #[test]
    fn restore_recovery_preserves_local_delete_as_removed_dirty_path() {
        use crate::index::{RestoreOperation, RestoreOperationState};

        let (store, _store_dir) = new_store();
        let root = tempfile::tempdir().unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let current = store_and_record(&store, "doc.txt", b"current");
        state.upsert_file("group-1", &current).unwrap();
        std::fs::write(root.path().join("doc.txt"), b"current").unwrap();

        let mut intended = store_and_record(&store, "doc.txt", b"restore");
        intended.version = current.version.clone();
        intended.version.increment("device-local");
        state
            .record_restore_operation(&RestoreOperation {
                operation_id: "restore-op-delete".into(),
                group_id: "group-1".into(),
                path: "doc.txt".into(),
                target_version_seq: 1,
                expected_current_version_seq: Some(1),
                state: RestoreOperationState::Prepared,
                record: intended,
                origin_device_id: "device-local".into(),
            })
            .unwrap();
        std::fs::remove_file(root.path().join("doc.txt")).unwrap();

        let report = reconcile_restore_operations(&state, root.path(), "group-1").unwrap();
        assert_eq!(report.preserved_divergent, vec!["doc.txt"]);
        let dirty = state.list_dirty_paths("group-1").unwrap();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].change_kind, "removed");
        assert!(!root.path().join("doc.txt").exists());
    }

    #[test]
    fn stale_restore_journal_does_not_overwrite_a_newer_current_version() {
        use crate::index::{RestoreOperation, RestoreOperationState};

        let (store, _store_dir) = new_store();
        let root = tempfile::tempdir().unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let base = store_and_record(&store, "doc.txt", b"base-v1");
        state.upsert_file("group-1", &base).unwrap();

        let mut intended = store_and_record(&store, "doc.txt", b"restore");
        intended.version = base.version.clone();
        intended.version.increment("device-local");
        state
            .record_restore_operation(&RestoreOperation {
                operation_id: "restore-op-stale".into(),
                group_id: "group-1".into(),
                path: "doc.txt".into(),
                target_version_seq: 1,
                expected_current_version_seq: Some(1),
                state: RestoreOperationState::Prepared,
                record: intended,
                origin_device_id: "device-local".into(),
            })
            .unwrap();

        // A second daemon/process commits a newer current row while the first
        // process's journal is still outstanding.
        let mut newer = store_and_record(&store, "doc.txt", b"newer-v2");
        newer.version = base.version.clone();
        newer.version.increment("device-b");
        state.upsert_file("group-1", &newer).unwrap();
        std::fs::write(root.path().join("doc.txt"), b"restore").unwrap();

        let report = reconcile_restore_operations(&state, root.path(), "group-1").unwrap();
        assert_eq!(report.preserved_divergent, vec!["doc.txt"]);
        assert_eq!(state.get_file("group-1", "doc.txt").unwrap(), Some(newer));
        assert_eq!(state.list_versions("group-1", "doc.txt").unwrap().len(), 2);
        assert!(state.is_path_dirty("group-1", "doc.txt").unwrap());
        assert!(state.list_restore_operations("group-1").unwrap().is_empty());
    }

    /// (crash-before-rename): the index already has the new
    /// version/blocks committed (as `PeerSyncSession::materialize`'s
    /// eager-fetch branch does *before* its `reconstruct_file` call), but
    /// the process was killed before that write's rename ever landed —
    /// simulated directly (task instruction: reproduce the exact on-disk
    /// state a crash would leave) by leaving the real
    /// `chunker::unique_tmp_path`-shaped temp artifact on disk and never
    /// creating the final `out_path` at all. Content is still fully
    /// present in the local block store (it was fetched before the crash),
    /// so recovery must self-heal locally with no peer round-trip: the
    /// final file must exist afterward with exactly the right bytes, and
    /// the stale temp artifact must be gone too.
    #[test]
    fn repair_reconstructs_locally_after_a_simulated_crash_before_rename() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let content = b"hello from before the crash".to_vec();
        let hash_hex = store.put(&content).unwrap();
        let hash = hex::decode(&hash_hex).unwrap();

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        state.upsert_file("group-1", &record_with_blocks("doc.txt", &content, hash)).unwrap();
        // Index says Hydrated (the default for a fresh row) even though
        // `doc.txt` was never actually written — the exact inconsistency
        // an interrupted materialize leaves behind.
        assert_eq!(
            state.get_materialization_state("group-1", "doc.txt").unwrap(),
            Some(MaterializationState::Hydrated)
        );
        // A genuine crash mid-materialize leaves the durable intent in place
        // (it is written before the temp-write-then-rename and only cleared
        // after it completes). This is exactly what tells repair to reconstruct
        // here rather than treat the missing file as an offline deletion.
        state.begin_materialization_intent("group-1", "doc.txt", &[0u8; 32]).unwrap();

        // The orphaned temp artifact `reconstruct_file` would have renamed
        // away, left behind by the simulated crash.
        // A real artifact survived a previous process, so its PID differs
        // from this recovery process. Using the current PID with counter 0
        // collides with `unique_tmp_path` when this test runs in isolation
        // (its process-global counter also starts at 0), causing repair to
        // consume the fixture as its own output temp before cleanup sees it.
        let crashed_pid = std::process::id().wrapping_add(1);
        let stale_tmp = root.path().join(format!("doc.txt.yadorilink-tmp.{crashed_pid}.0"));
        std::fs::write(&stale_tmp, b"partial garbage").unwrap();
        assert!(!root.path().join("doc.txt").exists(), "out_path must not exist pre-repair");

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();
        assert_eq!(report.reconstructed, vec!["doc.txt".to_string()]);
        assert!(report.demoted_to_placeholder.is_empty());

        assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), content);
        assert_eq!(
            state.get_materialization_state("group-1", "doc.txt").unwrap(),
            Some(MaterializationState::Hydrated)
        );

        // The startup temp-file sweep is a separate, independent pass —
        // confirm it also cleans up the same orphaned artifact.
        let removed = cleanup_stale_temp_files(root.path());
        assert_eq!(removed, vec![stale_tmp.clone()]);
        assert!(!stale_tmp.exists());
    }

    /// (crash-after-rename, the converse): the rename already
    /// completed before the crash (or there was no crash at all) — on-disk
    /// content matches the index exactly, so repair must be a pure no-op,
    /// not just "doesn't error" but genuinely untouched (verified via an
    /// mtime that would change on any rewrite).
    #[test]
    fn repair_is_a_noop_when_on_disk_content_already_matches_the_index() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let content = b"already fully synced".to_vec();
        let hash_hex = store.put(&content).unwrap();
        let hash = hex::decode(&hash_hex).unwrap();

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &record_with_blocks("done.txt", &content, hash)).unwrap();
        let out_path = root.path().join("done.txt");
        std::fs::write(&out_path, &content).unwrap();
        let mtime_before = std::fs::metadata(&out_path).unwrap().modified().unwrap();

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();
        assert!(report.is_empty());
        assert_eq!(std::fs::metadata(&out_path).unwrap().modified().unwrap(), mtime_before);
    }

    /// A user may edit a file while the daemon is stopped, so no
    /// `local_dirty_paths` row can exist. Startup repair must not interpret a
    /// size mismatch alone as proof that the disk write is an interrupted
    /// materialization and overwrite those newer bytes from the old index.
    #[test]
    fn startup_repair_must_not_overwrite_offline_edit_with_different_size() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let indexed = b"old indexed bytes".to_vec();
        let hash = hex::decode(store.put(&indexed).unwrap()).unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &record_with_blocks("offline.txt", &indexed, hash)).unwrap();

        let offline_edit = b"newer offline user edit with a different size".to_vec();
        let path = root.path().join("offline.txt");
        std::fs::write(&path, &offline_edit).unwrap();
        assert!(!state.is_path_dirty("group-1", "offline.txt").unwrap());

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();
        assert_eq!(report.quarantined_dirty.len(), 1);
        let recovered = root.path().join(&report.quarantined_dirty[0].1);
        assert_eq!(std::fs::read(recovered).unwrap(), offline_edit);
        assert_eq!(std::fs::read(path).unwrap(), indexed);
        assert!(state.is_path_dirty("group-1", &report.quarantined_dirty[0].1).unwrap());
    }

    /// Same-size offline edits are even harder: the old repair fast path
    /// treats size equality as proof of consistency. The pass must surface
    /// this disk/index divergence for capture instead of reporting a clean
    /// startup while the index still names different content.
    #[test]
    fn startup_repair_must_detect_same_size_offline_edit() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let indexed = b"indexed-version".to_vec();
        let hash = hex::decode(store.put(&indexed).unwrap()).unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &record_with_blocks("same.txt", &indexed, hash)).unwrap();

        let offline_edit = b"offline-change!".to_vec();
        assert_eq!(offline_edit.len(), indexed.len());
        std::fs::write(root.path().join("same.txt"), &offline_edit).unwrap();

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();
        assert_eq!(report.quarantined_dirty.len(), 1);
        let recovered = root.path().join(&report.quarantined_dirty[0].1);
        assert_eq!(std::fs::read(recovered).unwrap(), offline_edit);
        assert_eq!(std::fs::read(root.path().join("same.txt")).unwrap(), indexed);
        assert!(state.is_path_dirty("group-1", &report.quarantined_dirty[0].1).unwrap());
    }

    /// a crash-before-rename where the block(s) are *not* fully
    /// present locally either (e.g. the block store itself never finished
    /// receiving them) cannot be self-healed without a peer — repair must
    /// demote the record to `Placeholder` rather than leaving it claiming
    /// `Hydrated` content that provably isn't there, so normal on-demand
    /// hydration re-fetches it.
    #[test]
    fn repair_demotes_to_placeholder_when_blocks_are_also_missing_locally() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        // A syntactically valid hash that was never actually `put` into
        // this store — never fetched, or evicted/GC'd since.
        let missing_hash = vec![0xCDu8; 32];

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        state
            .upsert_file(
                "group-1",
                &record_with_blocks("missing.bin", b"not present", missing_hash),
            )
            .unwrap();
        // A crash mid-materialize leaves the intent present, so repair treats
        // this missing file as an interrupted write (to demote) rather than an
        // offline deletion.
        state.begin_materialization_intent("group-1", "missing.bin", &[0u8; 32]).unwrap();

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();
        assert!(report.reconstructed.is_empty());
        assert_eq!(report.demoted_to_placeholder, vec!["missing.bin".to_string()]);
        assert_eq!(
            state.get_materialization_state("group-1", "missing.bin").unwrap(),
            Some(MaterializationState::Placeholder)
        );
        let placeholder = root.path().join("missing.bin");
        assert!(placeholder.exists(), "demotion should leave a real placeholder on disk");
        assert_eq!(
            std::fs::metadata(&placeholder).unwrap().len(),
            "not present".len() as u64,
            "placeholder should preserve the logical file size"
        );
    }

    /// `Placeholder`/`Hydrating` records (the file was never
    /// claimed to be hydrated in the first place) are never touched by
    /// this pass — it only ever repairs/demotes rows currently claiming
    /// `Hydrated`.
    #[test]
    fn repair_ignores_files_not_currently_marked_hydrated() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        state.upsert_file("group-1", &hydrated_record("placeholder.bin", 100)).unwrap();
        state
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
            )
            .unwrap();

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();
        assert!(report.is_empty());
        assert_eq!(
            state.get_materialization_state("group-1", "placeholder.bin").unwrap(),
            Some(MaterializationState::Placeholder)
        );
    }

    /// The periodic live repair pass runs while the watcher/local-change
    /// pipeline and hydration may be mutating the same file+index row under the
    /// per-path lock. Repair must acquire that same lock (`try_lock`) before it
    /// touches a path's disk/index, and skip — leaving the path completely
    /// untouched — while the lock is held by a concurrent writer, exactly as
    /// `evict_file` does. This is the deterministic form of that guarantee:
    /// holding the path lock makes repair's own `try_lock` fail, so the busy
    /// path is provably left for the next pass instead of racing the writer.
    /// Releasing the lock and re-running proves nothing else stopped the repair
    /// from happening — the only thing that held it off was the lock.
    #[test]
    fn live_repair_skips_a_path_whose_path_lock_is_held_and_repairs_it_once_free() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let content = b"content a concurrent writer holds the path lock for".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        state.upsert_file("group-1", &record_with_blocks("busy.txt", &content, hash)).unwrap();
        // Index says Hydrated but the file was never written — a divergence
        // repair would normally heal by reconstructing from the stored blocks.
        // The intent present marks this as a crash mid-materialize (not an
        // offline delete), so repair reconstructs it once the lock is free.
        state.begin_materialization_intent("group-1", "busy.txt", &[0u8; 32]).unwrap();
        let out_path = root.path().join("busy.txt");
        assert!(!out_path.exists());

        // A concurrent path operation (watcher/local-change/hydrate) holds the
        // per-path lock for the whole critical section.
        let path_lock = state.path_lock("group-1", "busy.txt");
        let active_operation = path_lock.try_lock().unwrap();

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();
        // Busy path skipped: nothing reconstructed, nothing demoted, disk and
        // index left exactly as the concurrent writer expects them.
        assert!(report.is_empty(), "repair must not touch a path whose lock is held");
        assert!(!out_path.exists(), "repair must not write the file while the path is busy");
        assert_eq!(
            state.get_materialization_state("group-1", "busy.txt").unwrap(),
            Some(MaterializationState::Hydrated)
        );

        // Once the concurrent operation releases the lock, the next repair pass
        // heals the same path — proving the lock was the only thing holding it
        // off, and repair still functions when the path is free.
        drop(active_operation);
        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();
        assert_eq!(report.reconstructed, vec!["busy.txt".to_string()]);
        assert_eq!(std::fs::read(&out_path).unwrap(), content);
    }

    // --- Offline delete/rename disambiguation via the materialization journal ---

    fn test_delete_emitter() -> ChangeEmitter {
        use ed25519_dalek::SigningKey;
        ChangeEmitter::new("device-a", SigningKey::from_bytes(&[7u8; 32]))
    }

    /// The paths of every `Delete` op carried by the group's current DAG head
    /// changes — used to prove repair propagated an offline deletion through the
    /// change seam, not merely mutated the local index row. A locally-emitted
    /// change is stored already-applied (so it is not in the *unapplied* list);
    /// reading it back through the group heads is how the existing local-change
    /// tests inspect an emitted change too. Sufficient for these fresh-group
    /// single-delete scenarios, where the emitted delete is itself the head.
    fn emitted_delete_paths(state: &SyncState, group_id: &str) -> Vec<String> {
        let mut out = Vec::new();
        for head in state.dag_group_heads(group_id).unwrap() {
            if let Some(change) = state.dag_get_change(&head).unwrap() {
                for op in &change.ops {
                    if let crate::change::Op::Delete { path } = op {
                        out.push(path.as_str().to_string());
                    }
                }
            }
        }
        out
    }

    /// A file that was fully materialized (its write completed, so no
    /// materialization intent remains) and then removed from disk while the
    /// daemon was stopped MUST NOT be reconstructed from the index by the
    /// startup repair pass — doing so silently resurrects the user's offline
    /// deletion. Repair classifies it as a deletion and, given an emitter,
    /// propagates a `Delete` through the same seam the disk scan uses. The file
    /// stays gone; the tombstone stands.
    #[test]
    fn offline_delete_is_not_reconstructed_before_startup_scan() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let content = b"a file the user later deleted while offline".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        state.upsert_file("group-1", &record_with_blocks("gone.txt", &content, hash)).unwrap();
        // Materialized cleanly: the content was on disk and the write's intent
        // was cleared (a fresh row carries no intent — exactly the completed
        // state). Then the user deletes it while the daemon is stopped.
        let out_path = root.path().join("gone.txt");
        std::fs::write(&out_path, &content).unwrap();
        std::fs::remove_file(&out_path).unwrap();
        assert!(!state.has_materialization_intent("group-1", "gone.txt").unwrap());

        let emitter = test_delete_emitter();
        let report = repair_interrupted_materializations_emitting_deletes(
            &state,
            &store,
            root.path(),
            "group-1",
            &emitter,
        )
        .unwrap();

        // Not resurrected.
        assert!(!out_path.exists(), "an offline-deleted file must not be recreated by repair");
        assert!(report.reconstructed.is_empty(), "repair must not reconstruct an offline delete");
        assert_eq!(report.offline_deleted, vec!["gone.txt".to_string()]);
        // Tombstoned locally AND propagated through the change seam.
        assert!(
            state.get_file("group-1", "gone.txt").unwrap().is_none_or(|r| r.deleted),
            "the index row must be a tombstone, not a live Hydrated record"
        );
        assert_eq!(
            emitted_delete_paths(&state, "group-1"),
            vec!["gone.txt".to_string()],
            "the deletion must be emitted as a Delete change, not silently undone"
        );
    }

    /// An offline rename is a missing source (no intent) plus a new target on
    /// disk that the index has never seen. Startup repair must treat the source
    /// as a deletion — never restore its stale path from the index — and must
    /// leave the not-yet-indexed target file untouched for the scan to adopt.
    #[test]
    fn offline_rename_does_not_restore_the_source_path() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let content = b"contents moved from src to dst while offline".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        state.upsert_file("group-1", &record_with_blocks("src.txt", &content, hash)).unwrap();
        // The rename, performed while stopped: the source path is gone from disk
        // (no intent — the source had been materialized and completed) and the
        // target exists on disk but is not in the index yet.
        let src_path = root.path().join("src.txt");
        let dst_path = root.path().join("dst.txt");
        std::fs::write(&dst_path, &content).unwrap();
        assert!(!src_path.exists());
        assert!(!state.has_materialization_intent("group-1", "src.txt").unwrap());

        let emitter = test_delete_emitter();
        let report = repair_interrupted_materializations_emitting_deletes(
            &state,
            &store,
            root.path(),
            "group-1",
            &emitter,
        )
        .unwrap();

        // The source is a deletion, never restored.
        assert!(!src_path.exists(), "repair must not restore the rename's source path");
        assert!(report.reconstructed.is_empty());
        assert_eq!(report.offline_deleted, vec!["src.txt".to_string()]);
        assert_eq!(emitted_delete_paths(&state, "group-1"), vec!["src.txt".to_string()]);
        // The target the user moved the bytes to is left exactly as found —
        // adopting it as a create is the reconcile scan's job, not repair's.
        assert_eq!(std::fs::read(&dst_path).unwrap(), content, "the rename target must be intact");
        assert!(
            state.get_file("group-1", "dst.txt").unwrap().is_none(),
            "repair must not index the new target path itself"
        );
    }

    /// The converse of the offline-delete case: a missing `Hydrated` file WITH
    /// an in-progress materialization intent is a genuine crash mid-write and
    /// MUST still be reconstructed from the locally-present blocks — the fix
    /// must not over-correct into dropping legitimate crash recoveries. The
    /// intent is consumed (cleared) once the reconstruct completes.
    #[test]
    fn crash_mid_materialization_missing_target_is_reconstructed() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let content = b"bytes fetched just before the process was killed".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        state.upsert_file("group-1", &record_with_blocks("doc.txt", &content, hash)).unwrap();
        // The crash: the intent was written before the temp-write-then-rename
        // (which never landed), so the file is missing but the intent remains.
        state.begin_materialization_intent("group-1", "doc.txt", &[0u8; 32]).unwrap();
        let out_path = root.path().join("doc.txt");
        assert!(!out_path.exists());

        // Even given an emitter, the intent forces reconstruction, not deletion.
        let emitter = test_delete_emitter();
        let report = repair_interrupted_materializations_emitting_deletes(
            &state,
            &store,
            root.path(),
            "group-1",
            &emitter,
        )
        .unwrap();

        assert_eq!(report.reconstructed, vec!["doc.txt".to_string()]);
        assert!(report.offline_deleted.is_empty(), "a crash mid-write is not an offline delete");
        assert_eq!(std::fs::read(&out_path).unwrap(), content);
        assert!(
            emitted_delete_paths(&state, "group-1").is_empty(),
            "a genuine crash recovery must emit no Delete"
        );
        // The intent is consumed once the write completes.
        assert!(!state.has_materialization_intent("group-1", "doc.txt").unwrap());
    }

    /// The second, independent copy of the same root-guard hole, on the repair
    /// path. This pass grew its own guard —
    /// `if std::fs::metadata(root).is_err() { return Ok(report) }` — which, like
    /// the disk scan's, tested only that the path EXISTED. An unmounted volume
    /// leaves its mountpoint directory behind, so that check passed, every
    /// `Hydrated` file looked missing, and the pass classified the whole folder
    /// as offline deletes.
    ///
    /// Two things are asserted and the first is the subtle one: repair must
    /// return `Err`, NOT the empty `Ok(report)` the old guard returned. `Ok`
    /// reads as "nothing to repair", which lets the caller go on to scan the
    /// same unverifiable root; the `Err` is what routes the link into the
    /// daemon's existing `repair_failed_local_paths` lane and suppresses that
    /// scan's deletes.
    #[test]
    fn repair_on_empty_but_present_root_errors_and_gates_tombstones() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let content = b"bytes that live on the volume that just went away".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &record_with_blocks("doc.txt", &content, hash)).unwrap();
        // No intent: on a healthy, verified root this is a genuine offline
        // delete and repair SHOULD tombstone it (see
        // `missing_file_without_materialization_intent_becomes_delete`). The
        // root being unidentifiable is the only thing that may spare it here --
        // which is what makes this a test of the root guard, not of the intent.
        assert!(!state.has_materialization_intent("group-1", "doc.txt").unwrap());
        // The unmount: the mountpoint directory is present and readable, just
        // empty. Deliberately NOT removed -- `fs::metadata` must succeed, or
        // this would be testing the already-covered root-removed case instead.
        assert!(root.path().is_dir());
        assert!(std::fs::metadata(root.path()).is_ok(), "the old guard's check must still pass");
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);

        let emitter = test_delete_emitter();
        let result = repair_interrupted_materializations_emitting_deletes(
            &state,
            &store,
            root.path(),
            "group-1",
            &emitter,
        );

        assert!(
            result.is_err(),
            "repair on a root it cannot identify must return Err, not an empty Ok report: Ok \
             reads as 'nothing to repair' and lets the caller scan the same root and tombstone it"
        );
        assert!(
            emitted_delete_paths(&state, "group-1").is_empty(),
            "no Hydrated file may be classified as an offline delete"
        );
        let indexed = state.get_file("group-1", "doc.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "the index row must be left intact");
        assert_eq!(
            state.get_materialization_state("group-1", "doc.txt").unwrap(),
            Some(MaterializationState::Hydrated),
            "and must not be demoted to a placeholder either -- the demote path rewrites every \
             file in the group just as destructively as the tombstone path"
        );
    }

    /// The core disambiguation, isolated: two identical setups -- a `Hydrated`
    /// record whose blocks are all present locally and whose file is missing --
    /// diverge solely on the presence of a materialization intent. Without an
    /// intent the missing file is an offline deletion (tombstoned, never
    /// reconstructed); the intent-present twin is covered by
    /// `crash_mid_materialization_missing_target_is_reconstructed`.
    #[test]
    fn missing_file_without_materialization_intent_becomes_delete() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let content = b"present-in-store but deleted from disk".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        state.upsert_file("group-1", &record_with_blocks("f.txt", &content, hash)).unwrap();
        // Blocks are present in the store, so the OLD repair would have happily
        // reconstructed this file. The ONLY thing that makes it a deletion
        // rather than a crash is the absence of a materialization intent.
        assert!(!state.has_materialization_intent("group-1", "f.txt").unwrap());
        let out_path = root.path().join("f.txt");
        assert!(!out_path.exists());

        let emitter = test_delete_emitter();
        let report = repair_interrupted_materializations_emitting_deletes(
            &state,
            &store,
            root.path(),
            "group-1",
            &emitter,
        )
        .unwrap();

        assert!(
            report.reconstructed.is_empty(),
            "no intent => must not reconstruct from the index"
        );
        assert!(!out_path.exists());
        assert_eq!(report.offline_deleted, vec!["f.txt".to_string()]);
        assert_eq!(emitted_delete_paths(&state, "group-1"), vec!["f.txt".to_string()]);
    }

    /// The no-emitter (startup) path must also refuse to resurrect an offline
    /// delete: it leaves the missing file and the row untouched so the reconcile
    /// scan (which runs inside the group startup barrier, with an emitter) does
    /// the tombstoning. The invariant that matters — the file is not recreated —
    /// holds without an emitter too.
    #[test]
    fn offline_delete_without_emitter_is_left_for_the_scan_not_resurrected() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let content = b"deleted offline; startup repair has no emitter yet".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        state.upsert_file("group-1", &record_with_blocks("later.txt", &content, hash)).unwrap();
        let out_path = root.path().join("later.txt");
        assert!(!out_path.exists());

        // The plain (no-emitter) entry point, exactly what the daemon's startup
        // pass calls before the group's change emitter exists.
        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();

        assert!(!out_path.exists(), "repair must not resurrect the file even without an emitter");
        assert!(report.reconstructed.is_empty());
        assert_eq!(report.offline_deleted, vec!["later.txt".to_string()]);
        // Nothing emitted here (no emitter), and the row is deliberately left
        // for the scan rather than tombstoned locally (a local-only tombstone
        // would suppress the scan's own change emission).
        assert!(emitted_delete_paths(&state, "group-1").is_empty());
    }

    /// `cleanup_stale_temp_files` must remove only genuine
    /// orphaned temp artifacts matching this crate's own exact
    /// `.yadorilink-tmp.<pid>.<counter>` naming scheme — a user's own file
    /// that merely resembles that name (no numeric suffix at all, or one
    /// with something following the counter) must be left completely
    /// untouched, proving the cleanup can't be tricked into deleting real
    /// user data. Also proves the walk recurses into subdirectories.
    #[test]
    fn cleanup_removes_only_genuine_own_temp_files_and_recurses_into_subdirectories() {
        let root = tempfile::tempdir().unwrap();
        let genuine_top = root.path().join("photo.jpg.yadorilink-tmp.4242.3");
        std::fs::write(&genuine_top, b"orphaned").unwrap();

        let sub = root.path().join("nested");
        std::fs::create_dir_all(&sub).unwrap();
        let genuine_nested = sub.join("clip.mov.yadorilink-tmp.99.0");
        std::fs::write(&genuine_nested, b"orphaned too").unwrap();

        // Look-alikes that must survive.
        let user_literal = root.path().join("notes.yadorilink-tmp.txt");
        std::fs::write(&user_literal, b"my actual notes").unwrap();
        let extra_suffix = root.path().join("report.yadorilink-tmp.123.456.bak");
        std::fs::write(&extra_suffix, b"my actual backup").unwrap();
        let ordinary = sub.join("keep.txt");
        std::fs::write(&ordinary, b"keep me").unwrap();

        let mut removed = cleanup_stale_temp_files(root.path());
        removed.sort();
        let mut expected = vec![genuine_top.clone(), genuine_nested.clone()];
        expected.sort();
        assert_eq!(removed, expected);

        assert!(!genuine_top.exists());
        assert!(!genuine_nested.exists());
        assert!(user_literal.exists());
        assert!(extra_suffix.exists());
        assert!(ordinary.exists());
    }

    #[test]
    fn cleanup_is_a_noop_on_a_root_that_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("never-created");
        assert!(cleanup_stale_temp_files(&missing).is_empty());
    }

    /// True when `path`'s owner-executable permission bit is set.
    #[cfg(unix)]
    fn disk_exec_bit(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o100 != 0
    }

    /// Indexes `path` as a `Hydrated` executable whose blocks are all in the
    /// store but whose file is missing, with the materialization intent a crash
    /// mid-write leaves behind — the exact state repair reconstructs from.
    #[cfg(unix)]
    fn crashed_executable(state: &SyncState, store: &FsBlockStore, path: &str, content: &[u8]) {
        let hash = hex::decode(store.put(content).unwrap()).unwrap();
        state.upsert_file("group-1", &record_with_blocks(path, content, hash)).unwrap();
        // `set_exec_bit` is UPDATE-only, so the row must exist first.
        state.set_exec_bit("group-1", path, true).unwrap();
        state.begin_materialization_intent("group-1", path, &[0u8; 32]).unwrap();
    }

    /// Reconstructing content is only half of materializing a file: repair must
    /// also restore the exec bit the index recorded, because `reconstruct_file`
    /// assembles into a fresh temp file that carries default permissions. A
    /// repaired POSIX executable that comes back as a plain file is not
    /// self-healing — the startup scan finds its bytes byte-identical to the
    /// indexed blocks and suppresses it as a self-echo (see
    /// `repair_leaves_disk_exec_bit_agreeing_with_the_index_across_a_scan`), so
    /// no later pass ever notices the index still claims an exec bit the file
    /// on disk lacks.
    #[cfg(unix)]
    #[test]
    fn repaired_executable_keeps_its_indexed_exec_bit() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        let content = b"#!/bin/sh\necho hello\n".to_vec();
        crashed_executable(&state, &store, "tool.sh", &content);

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();

        assert_eq!(report.reconstructed, vec!["tool.sh".to_string()]);
        let out_path = root.path().join("tool.sh");
        assert_eq!(std::fs::read(&out_path).unwrap(), content);
        assert!(
            disk_exec_bit(&out_path),
            "a repaired executable must come back executable -- the index still records \
             exec_bit=true, and nothing else ever re-applies it to an already-Hydrated file"
        );
    }

    /// The converse, so the fix cannot degrade into an unconditional `chmod +x`:
    /// a repaired non-executable file must stay non-executable.
    #[cfg(unix)]
    #[test]
    fn repaired_plain_file_is_not_made_executable() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        let content = b"just some prose".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();
        state.upsert_file("group-1", &record_with_blocks("doc.txt", &content, hash)).unwrap();
        state.set_exec_bit("group-1", "doc.txt", false).unwrap();
        state.begin_materialization_intent("group-1", "doc.txt", &[0u8; 32]).unwrap();

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();

        assert_eq!(report.reconstructed, vec!["doc.txt".to_string()]);
        assert!(!disk_exec_bit(&root.path().join("doc.txt")));
    }

    /// End-to-end over the seam that decides how bad a dropped exec bit is: a
    /// repair followed by the startup scan the daemon runs next.
    ///
    /// The scan does NOT rescue a dropped bit, and does not propagate it either.
    /// It re-chunks the repaired file, finds the blocks identical to the indexed
    /// ones, and returns "nothing changed" (`local_change.rs`'s self-echo
    /// suppression) before reaching any exec-bit comparison — so it mints no
    /// version and leaves the index's `exec_bit` untouched. Peers therefore never
    /// hear about the loss, but neither does anything ever correct it: the index
    /// keeps claiming an exec bit the file does not have, and only repair writing
    /// the bit in the first place keeps the two in agreement. The scan's own
    /// chmod detection cannot step in, because it is gated behind an mtime match
    /// and repair's fresh write always bumps mtime.
    #[cfg(unix)]
    #[test]
    fn repair_leaves_disk_exec_bit_agreeing_with_the_index_across_a_scan() {
        use std::sync::Arc;

        let block_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(block_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        crashed_executable(&state, &store, "tool.sh", b"#!/bin/sh\necho hello\n");

        let report =
            repair_interrupted_materializations(&state, store.as_ref(), root.path(), "group-1")
                .unwrap();
        assert_eq!(report.reconstructed, vec!["tool.sh".to_string()]);

        let minted = crate::local_change::LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "device-a".to_string(),
        )
        .scan_existing_files("group-1", root.path())
        .unwrap();

        assert!(
            minted.is_empty(),
            "the scan suppresses the repaired file as a self-echo, so it can neither propagate \
             a dropped exec bit nor repair one: {minted:?}"
        );
        assert!(
            state.get_exec_bit("group-1", "tool.sh").unwrap(),
            "the index keeps exec_bit=true across the scan"
        );
        assert!(
            disk_exec_bit(&root.path().join("tool.sh")),
            "so the disk must already agree with it -- no later pass reconciles the two"
        );
    }

    /// A repair that cannot assemble the content demotes the row to a
    /// `Placeholder` and writes one to disk — a fresh file with default
    /// permissions, exactly like the reconstruct path's temp. The live peer
    /// materialize path stamps its own placeholders with the recorded exec bit,
    /// so repair must too rather than being a weaker second implementation.
    #[cfg(unix)]
    #[test]
    fn placeholder_demoted_by_repair_keeps_its_indexed_exec_bit() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(block_dir.path()).unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        // Index a block that was never put in the store: repair finds it
        // missing locally and must demote instead of reconstructing.
        let content = b"#!/bin/sh\nnever stored\n".to_vec();
        let absent_hash = vec![7u8; 32];
        state
            .upsert_file("group-1", &record_with_blocks("tool.sh", &content, absent_hash))
            .unwrap();
        state.set_exec_bit("group-1", "tool.sh", true).unwrap();
        // Without an intent a missing file reads as an offline deletion and is
        // never demoted at all -- the intent is what makes this a crash.
        state.begin_materialization_intent("group-1", "tool.sh", &[0u8; 32]).unwrap();

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1").unwrap();

        assert_eq!(report.demoted_to_placeholder, vec!["tool.sh".to_string()]);
        assert!(
            disk_exec_bit(&root.path().join("tool.sh")),
            "a placeholder is a real on-disk artifact under the user's filename; it carries the \
             recorded exec bit until hydration re-applies it alongside the real content"
        );
    }
}
