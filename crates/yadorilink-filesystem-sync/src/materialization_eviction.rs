//! Manual/automatic eviction: reduces a hydrated file back to a placeholder
//! and, on an on-demand device, reclaims its now-cached blocks once a full
//! replica's custody is confirmed. Moved out of `yadorilink-sync-core`'s
//! `materialization.rs` (Phase 7D-9C) now that `MaterializationExecutionPort`
//! covers this function family's entire state-access surface -- every
//! `state.<method>` call here was already going through `&dyn
//! crate::ports::MaterializationStatePort` (sync-core's wider trait) before
//! this move, never a concrete `SyncState`, so this module's own code was
//! already policy/filesystem-lifecycle-flavored, not SQL-flavored; only the
//! trait it depended on has changed, to this crate's own narrower one.
//!
//! `yadorilink-sync-core::materialization` re-exports every `pub` item here
//! at its original path (`crate::materialization::evict_file`/
//! `MaterializationContext`/...), so this move needed no consumer repoint --
//! same shape as `materialized_generation.rs`'s and `RestoreOperation`'s own
//! earlier moves in this sub-phase.

use std::path::Path;

use yadorilink_local_storage::disk_bytes_match_indexed_blocks;
use yadorilink_local_storage::free_space::{self, FreeSpaceState};
use yadorilink_local_storage::verify_write_target_within_root;
use yadorilink_local_storage::BlockReclamationStore;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::custody::FullReplicaCustody;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::block_liveness::BlockLivenessGate;
use crate::materialization_execution::{
    MaterializationExecutionError, MaterializationExecutionPort,
};
use crate::materialization_types::EvictableFile;

/// Reuses `yadorilink-peer-session`'s `disk_race_fingerprint` rather than a
/// local `(size, mtime)` pair: size+mtime alone lets a same-size local edit
/// landing within the filesystem's mtime granularity slip past the
/// pre-eviction revalidation below undetected -- and unlike the hydration
/// race this same fingerprint also closes, eviction's outcome on a false
/// match is more destructive: `write_placeholder` below replaces the
/// user's just-edited bytes with a sparse hole, not merely stale remote
/// content.
type DiskIdentity = Option<(u64, Option<std::time::SystemTime>, i64, i64)>;

fn disk_identity(path: &Path) -> Result<DiskIdentity, MaterializationExecutionError> {
    Ok(yadorilink_peer_session::peer_session::disk_race_fingerprint(path))
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

/// The handles a materialization/eviction operation needs: the index, the
/// block-liveness gate, the block store, and the linked folder's local root.
/// Shared by [`evict_file`], [`run_eviction_sweep`], and
/// [`run_disk_pressure_eviction_sweep`].
pub struct MaterializationContext<'a> {
    pub state: &'a dyn MaterializationExecutionPort,
    pub liveness_gate: &'a BlockLivenessGate,
    // Narrowed to the reclamation surface: every caller sharing this context
    // (`evict_file`, `run_eviction_sweep`, `run_disk_pressure_eviction_sweep`)
    // only ever forwards `store` into `MaterializationExecutionPort::
    // reclaim_cached_blocks`, never calls a content method
    // (`put`/`get`/`present_blocks`) on it directly.
    pub store: &'a dyn BlockReclamationStore,
    pub root: &'a Path,
    /// Minted from the caller's per-link root authority (the daemon's
    /// operation fence + root-identity check); re-verified by every
    /// `SyncState` mutation this module makes, immediately before its
    /// commit. See `root_commit::RootCommitPermit`'s own doc.
    pub permit: &'a RootCommitPermit<'a>,
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
) -> Result<EvictionOutcome, MaterializationExecutionError> {
    let MaterializationContext { state, liveness_gate, store, root, permit } = ctx;
    let reference_write = liveness_gate.begin_reference_write();
    state.verify_root(root, group_id)?;
    // One snapshot-shaped read replacing the three unconditional pre-lock
    // CRUD reads (`is_pinned`/`get_current_version_record`/`get_record_kind`)
    // this function used to make individually — see
    // `MaterializationExecutionPort::eviction_eligibility_snapshot`'s doc
    // comment for why this changes nothing about consistency, only call
    // count.
    let eligibility = state.eviction_eligibility_snapshot(group_id, path)?;
    if eligibility.pinned {
        return Err(MaterializationExecutionError::EvictionRejected(path.to_string()));
    }
    // Read the current row's blocks AND metadata as ONE atomic snapshot, so
    // the `change::VersionHash` the custody query carries describes a version
    // some single row actually held — never a hybrid stitched across
    // separate `get_file` + metadata reads that a concurrent transition could
    // tear apart.
    let Some(record) = eligibility.current_version else {
        return Err(MaterializationExecutionError::NotFound(format!("file {group_id}/{path}")));
    };
    if record.deleted {
        return Err(MaterializationExecutionError::NotFound(format!("file {group_id}/{path}")));
    }
    if eligibility.record_kind.unwrap_or_default() != RecordKind::File {
        return Err(MaterializationExecutionError::EvictionRejected(format!(
            "{path} is not a regular file and cannot be represented by a placeholder"
        )));
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
    // `#[cfg(test)]` alone would only select this crate's OWN test build --
    // a downstream crate's tests (e.g. yadorilink-sync-core's own
    // materialization.rs test module, which exercises the confirmed-custody
    // reclaim path directly) link this crate as an ordinary dependency,
    // compiled without `--cfg test`, so `cfg(test)` here would silently fall
    // through to the production verifier for every downstream caller's
    // tests. `feature = "evict-custody-test-bypass"` is what actually
    // crosses the crate boundary for the handful of callers that
    // deliberately want to exercise the confirmed-custody deletion path in
    // their own tests.
    //
    // This is a DIFFERENT feature than this crate's general `test-support`
    // (which gates unrelated test doubles like `OverrideForTest`/
    // `FakeCommitAdapter`): `yadorilink-daemon` and `yadorilink-cli` both
    // need `test-support` for those, but their own tests
    // (`preflight_disk_pressure_runs_eviction_sweep_for_on_demand_link_first`,
    // `eviction_without_remote_lease_never_reaches_physical_reclaim`)
    // specifically assert that an instantaneous custody confirmation
    // *without* a durable remote lease must NOT authorize physical block
    // deletion -- i.e. they need the real, fails-closed
    // `verify_reclaim_custody`, not the bypass. Folding this into the
    // shared `test-support` feature previously made every consumer of that
    // feature (not just the ones that opt into
    // `evict-custody-test-bypass`) silently skip the durable-lease gate,
    // which is exactly the regression these two tests caught.
    let verified_custody = (!is_full_replica)
        .then(|| {
            #[cfg(any(test, feature = "evict-custody-test-bypass"))]
            {
                yadorilink_replica_engine::custody::verify_reclaim_custody_for_test(
                    custody,
                    group_id,
                    path,
                    &evicting_version.version_hash,
                    &evicting_version.blocks,
                )
            }
            #[cfg(not(any(test, feature = "evict-custody-test-bypass")))]
            {
                yadorilink_replica_engine::custody::verify_reclaim_custody(
                    custody,
                    group_id,
                    path,
                    &evicting_version.version_hash,
                    &evicting_version.blocks,
                )
            }
        })
        .flatten();

    let path_lock = state.path_lock(group_id, path);
    let _path_guard = path_lock
        .try_lock()
        .map_err(|_| MaterializationExecutionError::EvictionRejected(format!("{path} is busy")))?;
    // One snapshot-shaped read replacing the four separate CRUD re-checks
    // this function used to make individually, immediately after acquiring
    // the lock — this IS the "permit/lease re-verification point" the
    // module's behavioral invariants pin in place; grouping the reads does
    // not move it. See `MaterializationExecutionPort::eviction_revalidation_snapshot`.
    let revalidation = state.eviction_revalidation_snapshot(group_id, path)?;
    let still_current = revalidation.current_version.is_some_and(|current| {
        !current.deleted && current.to_file_version().version_hash == evicting_version.version_hash
    });
    if !still_current
        || revalidation.pinned
        || revalidation.materialization_state != Some(MaterializationState::Hydrated)
        || revalidation.path_dirty
        || disk_identity(&out_path)? != initial_disk_identity
        || !disk_bytes_match_indexed_blocks(&out_path, &record.blocks)?
    {
        // Bail out before writing the placeholder: the file is left fully
        // materialized, so `dehydrated` stays `false` (the default) and an
        // automatic sweep must not count it as having freed any bytes.
        return Ok(EvictionOutcome { blocks_retained: true, ..Default::default() });
    }

    state.set_materialization_state(group_id, path, MaterializationState::Evicting, permit)?;
    let placeholder_result: Result<
        yadorilink_local_storage::PlaceholderIdentityToRecord,
        MaterializationExecutionError,
    > = state
        .verify_root(root, group_id)
        .and_then(|_| Ok(verify_write_target_within_root(&out_path, root)?))
        .and_then(|_| {
            if disk_identity(&out_path)? != initial_disk_identity
                || !disk_bytes_match_indexed_blocks(&out_path, &record.blocks)?
            {
                return Err(MaterializationExecutionError::EvictionRejected(format!(
                    "{path} changed before placeholder commit"
                )));
            }
            Ok(yadorilink_local_storage::create_or_defer_placeholder(
                &out_path,
                record.size,
                record.mtime_unix_nanos,
            )?)
        });
    let placeholder_outcome = match placeholder_result {
        Ok(outcome) => outcome,
        Err(error) => {
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
                permit,
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
    };
    if !state.transition_materialization_state(
        group_id,
        path,
        MaterializationState::Evicting,
        MaterializationState::Placeholder,
        permit,
    )? {
        return Ok(EvictionOutcome {
            blocks_retained: true,
            dehydrated: true,
            ..Default::default()
        });
    }
    match placeholder_outcome {
        yadorilink_local_storage::PlaceholderIdentityToRecord::RecordOverwrite {
            identity,
            provider_kind,
        } => {
            state.record_placeholder_generation(group_id, path, identity, provider_kind, permit)?
        }
        yadorilink_local_storage::PlaceholderIdentityToRecord::RecordIfAbsent {
            identity,
            provider_kind,
        } => {
            state.record_placeholder_generation_if_absent(
                group_id,
                path,
                identity,
                provider_kind,
                permit,
            )?;
        }
        yadorilink_local_storage::PlaceholderIdentityToRecord::Clear => {
            state.clear_placeholder_generation(group_id, path, permit)?
        }
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
    // deletion phase. The coordinator revalidates the exact version and all
    // cross-group references only after exclusivity is established.
    drop(reference_write);
    let physical_deletion = liveness_gate.begin_physical_deletion();
    let report =
        state.reclaim_verified_cached_blocks(&physical_deletion, verified_custody, store)?;
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
) -> Result<Vec<String>, MaterializationExecutionError> {
    let MaterializationContext { state, liveness_gate, store, root, permit } = ctx;
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
            MaterializationContext { state, liveness_gate, store, root, permit },
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
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    candidates: &[EvictableFile],
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
) -> Result<Vec<String>, MaterializationExecutionError> {
    let MaterializationContext { state, liveness_gate, store, root, permit } = ctx;
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
            MaterializationContext { state, liveness_gate, store, root, permit },
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
