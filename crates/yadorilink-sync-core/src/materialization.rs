//! Materialization lifecycle operations that need only local state (no
//! peer connection) — manual/automatic eviction (`on-demand-sync` design
//! D6, tasks 2.5/2.7). Hydration (the inverse direction, which does need a
//! peer to fetch blocks from) lives on `PeerSyncSession` instead.

use std::path::{Path, PathBuf};

use yadorilink_local_storage::free_space::{self, FreeSpaceState};
use yadorilink_local_storage::BlockStore;

use crate::chunker::{reconstruct_file, verify_write_target_within_root, write_placeholder};
use crate::error::SyncError;
use crate::index::SyncState;
use crate::types::{MaterializationState, RecordKind};

/// Preflight check before a hydration
/// fetch or a materialize-to-temp-and-rename write begins, scoped to the
/// volume hosting `root` (the target link's local folder) — shares the
/// exact classification (`yadorilink_local_storage::free_space`) the
/// block-store preflight and `yadorilink status`'s per-volume reporting
/// both use, so a single computed state backs the decision here
/// and what's reported elsewhere. Returns `Ok(())` when the write may
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

/// Evicts one hydrated, unpinned file back to a placeholder, reclaiming
/// its local disk space without touching its sync state (version, block
/// list) — `on-demand-sync` spec "Manual Eviction". Rejects a pinned file
/// (spec "Pinned files cannot be evicted") without touching it.
///
/// Index update happens before the disk write, same discipline as
/// `PeerSyncSession::materialize` and for the same reason: this device's
/// own watcher would otherwise race the state transition (see
/// `local_change::process_event`'s placeholder-aware self-echo
/// suppression, which only works if the index already says `Placeholder`
/// by the time the watcher processes the resulting filesystem event).
pub fn evict_file(
    state: &SyncState,
    root: &Path,
    group_id: &str,
    path: &str,
) -> Result<(), SyncError> {
    if state.is_pinned(group_id, path)? {
        return Err(SyncError::EvictionRejected(path.to_string()));
    }
    let Some(record) = state.get_file(group_id, path)? else {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    };
    if record.deleted {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    }

    state.set_materialization_state(group_id, path, MaterializationState::Placeholder)?;
    let out_path = root.join(path);
    // SEC-SYNC-5 defense-in-depth — see `verify_write_target_within_root`'s
    // doc comment; applied here too for consistency with the other
    // materialization write paths, even though eviction writes through an
    // already-indexed path rather than fresh peer input.
    verify_write_target_within_root(&out_path, root)?;
    write_placeholder(&out_path, record.size, record.mtime_unix_nanos)?;
    Ok(())
}

/// Runs one pass of the automatic eviction sweep () for a single
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
/// one at all ('s fallback — chiefly, a file that was already
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
pub fn run_eviction_sweep(
    state: &SyncState,
    root: &Path,
    group_id: &str,
    max_local_size_bytes: Option<i64>,
) -> Result<Vec<String>, SyncError> {
    let Some(cap) = max_local_size_bytes else {
        return Ok(vec![]);
    };
    let cap = cap.max(0) as u64;

    let mut candidates = state.list_evictable_files(group_id)?;
    refresh_missing_last_accessed(state, root, group_id, &candidates);
    // Re-read now that any refreshed access times have been persisted, so
    // the LRU ordering below reflects them.
    candidates = state.list_evictable_files(group_id)?;

    // COR-10: usage must include pinned-but-hydrated content too, even
    // though `candidates` (eviction *candidates*) deliberately excludes
    // pinned files — otherwise the sweep undercounts real disk usage and
    // can stop while still over the configured cap.
    let mut current_usage = state.hydrated_usage_bytes(group_id)?;
    let mut evicted = Vec::new();

    for candidate in candidates {
        if current_usage <= cap {
            break;
        }
        evict_file(state, root, group_id, &candidate.path)?;
        current_usage = current_usage.saturating_sub(candidate.size);
        evicted.push(candidate.path);
    }
    Ok(evicted)
}

/// Best-effort refresh of `last_accessed_unix` from on-disk `atime` for
/// evictable candidates that have never recorded one — the same fallback
/// `run_eviction_sweep` performs (see its doc comment), factored out so the
/// disk-pressure-triggered sweep below reuses it verbatim (task 4.3: reuse,
/// not reimplementation) instead of duplicating the LRU-freshening logic.
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
/// Reuses (task 4.3), rather than reimplements, the exact same
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
/// evicted, in eviction order, so a caller (task 4.2: the daemon's
/// hydration/materialization preflight) can re-check headroom afterward and
/// let the original operation proceed if enough space was reclaimed.
pub fn run_disk_pressure_eviction_sweep(
    state: &SyncState,
    root: &Path,
    group_id: &str,
    headroom_override_bytes: Option<u64>,
) -> Result<Vec<String>, SyncError> {
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
        evict_file(state, root, group_id, &candidate.path)?;
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
}

impl MaterializationRepairReport {
    /// Whether this pass found nothing to repair — the common case on a
    /// clean startup. Public so callers (`yadorilink-daemon::main`'s
    /// startup wiring) can decide whether to log anything at all without
    /// duplicating this check.
    pub fn is_empty(&self) -> bool {
        self.reconstructed.is_empty() && self.demoted_to_placeholder.is_empty()
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
/// placement and rationale (COR-7) — the two together cover both
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
/// `root.join(path)` is missing, or its size doesn't match the record's
/// expected `size`, this is diagnosed as an interrupted materialization.
/// The size check is a deliberately cheap proxy, not a full content-hash
/// verification pass over every synced byte — surviving arbitrary disk
/// corruption is explicitly out of scope; this exists
/// only to catch the specific interrupted-write window this crate's own
/// materialization code can leave, not to be a general integrity scanner
/// (a torn/corrupt block itself is still separately caught by
/// `FsBlockStore::get`'s own checksum verification, whether reached from
/// here or from any other read path).
///
/// If every one of the record's blocks is still present in the local
/// block store (the common case — the final write step failed or never
/// ran, but the fetched bytes it would have assembled from are already
/// durably stored, content-addressed, independent of that failed write),
/// the file is reconstructed again with no peer round-trip needed. Only
/// when a block is also missing locally is the record demoted to
/// `Placeholder`, so it is never left claiming hydrated content that
/// isn't actually there.
pub fn repair_interrupted_materializations(
    state: &SyncState,
    store: &dyn BlockStore,
    root: &Path,
    group_id: &str,
) -> Result<MaterializationRepairReport, SyncError> {
    let mut report = MaterializationRepairReport::default();
    for (path, mstate) in state.list_materialization_states(group_id)? {
        if mstate != MaterializationState::Hydrated {
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
        if on_disk_size == Some(record.size) {
            continue;
        }

        let hashes: Vec<String> = record.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
        let present = store.present_blocks(&hashes)?;
        if !present.is_empty() && present.iter().all(|&p| p) {
            verify_write_target_within_root(&out_path, root)?;
            reconstruct_file(store, &out_path, &record.blocks)?;
            report.reconstructed.push(path);
        } else {
            state.set_materialization_state(group_id, &path, MaterializationState::Placeholder)?;
            verify_write_target_within_root(&out_path, root)?;
            write_placeholder(&out_path, record.size, record.mtime_unix_nanos)?;
            report.demoted_to_placeholder.push(path);
        }
    }
    Ok(report)
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
        state.upsert_file("group-1", &hydrated_record("a.bin", 1000)).unwrap();
        std::fs::write(root.path().join("a.bin"), vec![9u8; 1000]).unwrap();

        evict_file(&state, root.path(), "group-1", "a.bin").unwrap();

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

        let err = evict_file(&state, root.path(), "group-1", "a.bin").unwrap_err();
        assert!(matches!(err, SyncError::EvictionRejected(_)));
        assert_eq!(
            state.get_materialization_state("group-1", "a.bin").unwrap(),
            Some(MaterializationState::Hydrated)
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
        let evicted = run_eviction_sweep(&state, root.path(), "group-1", Some(500)).unwrap();
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

        let evicted = run_eviction_sweep(&state, root.path(), "group-1", Some(1000)).unwrap();
        assert_eq!(evicted, vec!["old.bin".to_string()]);
    }

    #[test]
    fn sweep_never_evicts_pinned_files_even_when_over_cap() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &hydrated_record("pinned.bin", 1000)).unwrap();
        state.set_pinned("group-1", "pinned.bin", true).unwrap();
        std::fs::write(root.path().join("pinned.bin"), vec![1u8; 1000]).unwrap();

        let evicted = run_eviction_sweep(&state, root.path(), "group-1", Some(0)).unwrap();
        assert!(evicted.is_empty());
        assert_eq!(
            state.get_materialization_state("group-1", "pinned.bin").unwrap(),
            Some(MaterializationState::Hydrated)
        );
    }

    /// COR-10: pinned-but-hydrated content must count toward usage even
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
        let evicted = run_eviction_sweep(&state, root.path(), "group-1", Some(1000)).unwrap();
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

    #[test]
    fn sweep_no_ops_when_no_cap_configured() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &hydrated_record("a.bin", 1_000_000)).unwrap();
        std::fs::write(root.path().join("a.bin"), vec![1u8; 1_000_000]).unwrap();

        let evicted = run_eviction_sweep(&state, root.path(), "group-1", None).unwrap();
        assert!(evicted.is_empty());
        assert_eq!(
            state.get_materialization_state("group-1", "a.bin").unwrap(),
            Some(MaterializationState::Hydrated)
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
        let evicted =
            run_disk_pressure_eviction_sweep(&state, root.path(), "group-1", Some(u64::MAX / 2))
                .unwrap();
        assert!(!evicted.is_empty(), "expected at least one eviction under forced disk pressure");
        assert_eq!(evicted[0], "old.bin", "least-recently-accessed must be evicted first");
    }

    /// pinned files are never evicted by the disk-pressure
    /// trigger, exactly as they're already excluded from the cap trigger
    /// (reused, not reimplemented — task 4.3).
    #[test]
    fn disk_pressure_sweep_never_evicts_pinned_files() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &hydrated_record("pinned.bin", 1000)).unwrap();
        state.set_pinned("group-1", "pinned.bin", true).unwrap();
        std::fs::write(root.path().join("pinned.bin"), vec![1u8; 1000]).unwrap();

        let evicted =
            run_disk_pressure_eviction_sweep(&state, root.path(), "group-1", Some(u64::MAX / 2))
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

        let evicted =
            run_disk_pressure_eviction_sweep(&state, root.path(), "group-1", Some(0)).unwrap();
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
        state.upsert_file("group-1", &record_with_blocks("doc.txt", &content, hash)).unwrap();
        // Index says Hydrated (the default for a fresh row) even though
        // `doc.txt` was never actually written — the exact inconsistency
        // an interrupted materialize leaves behind.
        assert_eq!(
            state.get_materialization_state("group-1", "doc.txt").unwrap(),
            Some(MaterializationState::Hydrated)
        );

        // The orphaned temp artifact `reconstruct_file` would have renamed
        // away, left behind by the simulated crash.
        let stale_tmp =
            root.path().join(format!("doc.txt.yadorilink-tmp.{}.0", std::process::id()));
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
        state
            .upsert_file(
                "group-1",
                &record_with_blocks("missing.bin", b"not present", missing_hash),
            )
            .unwrap();

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
}
