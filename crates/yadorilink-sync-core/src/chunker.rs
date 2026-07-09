//! Fixed-size block splitting (Syncthing-proven fixed-size blocks,
//! content-defined chunking deferred by default) is the default, plus an
//! opt-in, size-gated content-defined chunking (CDC) path for large files
//! edited internally rather than appended to or replaced wholesale (VM
//! images, databases, large project files), where fixed-size blocks
//! re-transfer everything after an edit point due to boundary shift.
//! Blocks are content-addressed and stored via `yadorilink-local-storage`,
//! giving free local dedup: an identical block from any other file/version
//! is only ever stored once, regardless of which chunking method produced
//! it.

use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use yadorilink_local_storage::BlockStore;

use crate::error::SyncError;
use crate::types::BlockInfo;

/// Default block size (128 KiB), matching Syncthing's default.
pub const DEFAULT_BLOCK_SIZE: usize = 128 * 1024;
/// Upper bound blocks scale to for very large files, matching Syncthing's
/// max (16 MiB), so a huge file doesn't produce an unwieldy block count.
///
/// `pub(crate)`, not private: the decompression-bomb
/// guard (`peer_session::decompress_block`) reuses this exact constant as
/// its maximum-decompressed-size bound, rather than duplicating the number
/// — no legitimate block payload should ever decompress past it, which
/// makes this the natural ceiling to reuse.
pub(crate) const MAX_BLOCK_SIZE: usize = 16 * 1024 * 1024;
/// Target upper bound on block count per file before scaling the block
/// size up (doubling), keeping index/request overhead bounded.
const TARGET_MAX_BLOCKS: u64 = 2000;

/// Chunk-size parameters targeting Borg/restic's large-binary-backup range
/// (512 KiB-8 MiB, ~2 MiB target) rather than Xet's ML-model-weights range
/// (~64 KiB target) — yadorilink's CDC use case (VM images, databases,
/// large project files) doesn't need Xet's finer granularity, and a
/// coarser target keeps block counts (and therefore index/request
/// overhead) reasonable for multi-gigabyte files.
pub const CDC_MIN_SIZE: usize = 512 * 1024;
pub const CDC_AVG_SIZE: usize = 2 * 1024 * 1024;
pub const CDC_MAX_SIZE: usize = 8 * 1024 * 1024;

/// Files smaller than this always use fixed-size chunking regardless of a
/// link's chunking policy — CDC's rolling-hash cost isn't justified until
/// there's enough content for boundary-shift resilience to actually
/// matter. Comfortably above the fixed chunker's own default block size.
pub const CDC_SIZE_THRESHOLD: u64 = 32 * 1024 * 1024;

/// Picks a block size for a file of `file_size` bytes: the default, unless
/// that would produce more than `TARGET_MAX_BLOCKS` blocks, in which case
/// it doubles (power-of-two steps) up to `MAX_BLOCK_SIZE`.
pub fn block_size_for(file_size: u64) -> usize {
    let mut size = DEFAULT_BLOCK_SIZE;
    while file_size / (size as u64) > TARGET_MAX_BLOCKS && size < MAX_BLOCK_SIZE {
        size *= 2;
    }
    size
}

/// Reads `path`, splits it into fixed-size blocks, stores each block via
/// `store` (deduplicating against anything already held), and returns the
/// block list describing how to reconstruct the file.
pub fn chunk_file(store: &dyn BlockStore, path: &Path) -> Result<Vec<BlockInfo>, SyncError> {
    let metadata = fs::metadata(path)?;
    let block_size = block_size_for(metadata.len());

    let mut file = fs::File::open(path)?;
    let mut blocks = Vec::new();
    let mut offset: u64 = 0;
    let mut buf = vec![0u8; block_size];

    loop {
        let n = read_up_to(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        let hash_hex = store.put(chunk)?;
        blocks.push(BlockInfo { hash: hex::decode(&hash_hex)?, offset, size: n as u32 });
        offset += n as u64;
        if n < block_size {
            break; // short read = end of file
        }
    }

    Ok(blocks)
}

/// Reads `path`, splits it into content-defined (variable-size) blocks
/// using `fastcdc`'s Gear-hash CDC algorithm, stores each via `store`, and
/// returns the block list in the same shape `chunk_file` produces —
/// `reconstruct_file` needs no changes since it already handles arbitrary,
/// variable block sizes. Intended for files at or above
/// `CDC_SIZE_THRESHOLD`; the caller decides when to use this versus
/// `chunk_file` (policy plus size gate).
pub fn chunk_file_content_defined(
    store: &dyn BlockStore,
    path: &Path,
) -> Result<Vec<BlockInfo>, SyncError> {
    let file = fs::File::open(path)?;
    let chunker = fastcdc::v2020::StreamCDC::new(file, CDC_MIN_SIZE, CDC_AVG_SIZE, CDC_MAX_SIZE);

    let mut blocks = Vec::new();
    for result in chunker {
        let chunk = result.map_err(|e| SyncError::Chunking(e.to_string()))?;
        let hash_hex = store.put(&chunk.data)?;
        blocks.push(BlockInfo {
            hash: hex::decode(&hash_hex)?,
            offset: chunk.offset,
            size: chunk.length as u32,
        });
    }

    Ok(blocks)
}

/// Appends a collision-free `.yadorilink-tmp` suffix to `path`'s full
/// filename (never `with_extension`, which *replaces* the extension —
/// `report.txt`/`report.docx`/`report` would otherwise all map to the
/// same `report.yadorilink-tmp`). Also mixes in the current process id and
/// a per-process monotonic counter so two concurrent reconstructions of
/// files sharing a stem+extension (or a hydrate racing a placeholder
/// write of the same path) never share a temp path either — each
/// inbound peer message is handled in its own spawned task
/// (`peer_session.rs`), so this collision was reachable in practice, not
/// just in theory.
fn unique_tmp_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = OsString::from(path.file_name().unwrap_or_default());
    name.push(format!(".yadorilink-tmp.{}.{n}", std::process::id()));
    path.with_file_name(name)
}

/// Defense-in-depth: creates `out_path`'s parent directory (if
/// needed) then canonicalizes it and confirms it still `starts_with`
/// `sync_root`'s own canonical form, before any caller writes through
/// `out_path`. `is_safe_relative_path` (`peer_session.rs`) already rejects
/// a peer-advertised path containing `..` or an absolute-path component,
/// but that's a purely lexical check on the *string* — it cannot detect a
/// **symlink** at an intermediate path component already present on disk
/// (planted by a local actor, or a TOCTOU race), which the plain
/// `create`/`rename` calls in `reconstruct_file`/`write_placeholder` below
/// would otherwise follow right out of the sync root. This closes that
/// specific gap for the common case (a symlinked *directory* component);
/// it does not fully eliminate every TOCTOU window (e.g. a symlink swapped
/// in between this check and the write) — this is a known "Low / TOCTOU"
/// severity residual gap: exploiting even this residual window
/// requires a locally pre-planted symlink or a racing local actor, not
/// something a remote peer can create on its own.
///
/// Self-contained (canonicalizes `sync_root` itself on every call) —
/// callers that invoke this on a hot, concurrency-sensitive path for the
/// same `sync_root` repeatedly should prefer
/// `verify_write_target_within_canonical_root` with a `sync_root`
/// canonicalized once up front, to avoid paying the extra resolution cost
/// (and, in `peer_session.rs`'s case, avoid widening timing-sensitive
/// windows in bounded per-peer-message concurrency) on every single write.
pub fn verify_write_target_within_root(out_path: &Path, sync_root: &Path) -> Result<(), SyncError> {
    fs::create_dir_all(sync_root)?;
    let canonical_root = fs::canonicalize(sync_root)?;
    verify_write_target_within_canonical_root(out_path, &canonical_root)
}

/// Like `verify_write_target_within_root`, but takes an already-canonical
/// `canonical_root` (resolved once by the caller) instead of re-resolving
/// it on every call — see that function's doc comment for why this
/// matters on a hot path.
pub fn verify_write_target_within_canonical_root(
    out_path: &Path,
    canonical_root: &Path,
) -> Result<(), SyncError> {
    let parent = out_path.parent().unwrap_or(out_path);
    fs::create_dir_all(parent)?;
    let canonical_parent = fs::canonicalize(parent)?;
    if !canonical_parent.starts_with(canonical_root) {
        return Err(SyncError::PathEscapesRoot(out_path.display().to_string()));
    }
    Ok(())
}

/// Reconstructs a file at `out_path` from `blocks`, reading each block's
/// content from `store` in order and concatenating.
pub fn reconstruct_file(
    store: &dyn BlockStore,
    out_path: &Path,
    blocks: &[BlockInfo],
) -> Result<(), SyncError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = unique_tmp_path(out_path);
    {
        let mut out = fs::File::create(&tmp_path)?;
        for block in blocks {
            let hash_hex = hex::encode(&block.hash);
            let data = store.get(&hash_hex)?;
            std::io::Write::write_all(&mut out, &data)?;
        }
    }
    fs::rename(&tmp_path, out_path)?;
    Ok(())
}

/// Writes a placeholder at `out_path`: a sparse file of `size` bytes with
/// no real content, so `stat`/`ls` report the file's correct size and
/// modification time without its bytes occupying disk space or requiring
/// a block fetch. This is the
/// platform-neutral core representation; sections 6/7's platform shell
/// extensions layer the OS-specific placeholder markers on top (a reparse
/// point via the Cloud Filter API on Windows, a File Provider item on
/// macOS) — neither is implemented in this iteration.
///
/// Content-addressed dedup means this never collides with a genuine empty
/// file: a placeholder is never chunked/indexed as content (see
/// `local_change::process_event`'s placeholder-aware self-echo suppression).
pub fn write_placeholder(
    out_path: &Path,
    size: u64,
    mtime_unix_nanos: i64,
) -> Result<(), SyncError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = unique_tmp_path(out_path);
    {
        let file = fs::File::create(&tmp_path)?;
        file.set_len(size)?;
        if mtime_unix_nanos >= 0 {
            let mtime = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_nanos(mtime_unix_nanos as u64);
            let times = fs::FileTimes::new().set_modified(mtime);
            // Best-effort: some filesystems/platforms don't support setting
            // mtime this way, but that's cosmetic, not a correctness issue.
            let _ = file.set_times(times);
        }
    }
    fs::rename(&tmp_path, out_path)?;
    Ok(())
}

/// Materializes a symlink record at `out_path`, pointing at `target` (the
/// record's raw, unresolved target text — a symlink target
/// is never dereferenced by this crate) using the same atomic
/// temp-path-then-rename pattern `reconstruct_file`/`write_placeholder`
/// already use: `unique_tmp_path`'s
/// existing collision-free naming scheme picks a temp path,
/// `std::os::unix::fs::symlink` creates the link there, and `fs::rename`
/// atomically swaps it into place — a torn/partial symlink is never
/// observable at `out_path`, matching the guarantee `Materialization
/// Writes Are Atomic And Collision-Free` already gives regular-file
/// materialization.
#[cfg(unix)]
pub fn materialize_symlink(out_path: &Path, target: &str) -> Result<(), SyncError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = unique_tmp_path(out_path);
    std::os::unix::fs::symlink(target, &tmp_path)?;
    fs::rename(&tmp_path, out_path)?;
    Ok(())
}

/// Windows per-link opt-in symlink materialization: the default
/// Windows policy is skip-with-visible-status (the record is tracked and
/// synced, but nothing is written to disk — see
/// `peer_session::materialize_symlink_at`'s Windows branch), and this
/// function is only ever reached once a link has explicitly opted in
/// (`SyncState::windows_symlink_opt_in_for_group`). It attempts a real
/// `CreateSymbolicLinkW` via `std::os::windows::fs`, using the same atomic
/// temp-path-then-rename pattern as `materialize_symlink`. Creating a
/// Windows symlink requires `SeCreateSymbolicLinkPrivilege` or Developer
/// Mode; when that precondition isn't met the OS call fails, which is
/// surfaced here as a clear, actionable `SyncError::Io` — never a silent
/// no-op or a panic — since an opted-in link that can't actually
/// materialize symlinks on this machine should be loud about it, unlike
/// the default (non-opt-in) skip policy, which is silent by design.
///
/// Windows symlinks are typed (file vs. directory) at creation time; since
/// a target is never dereferenced for *classification* purposes elsewhere
/// in this crate (D1), this does a best-effort *local* check instead: if
/// `target`, resolved relative to `out_path`'s parent, currently exists
/// locally as a directory, a directory symlink is created; otherwise
/// (doesn't exist yet, resolves elsewhere, or any I/O error reading it)
/// this defaults to a file symlink, the more common case.
///
/// Not exercised by this crate's own test suite (no Windows CI/dev
/// machine available at the time this was written) — reviewed carefully
/// against the documented `std::os::windows::fs` API shape, but treat as
/// unverified until run on real Windows.
#[cfg(windows)]
pub fn materialize_symlink_windows(out_path: &Path, target: &str) -> Result<(), SyncError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = unique_tmp_path(out_path);
    let target_hint = out_path.parent().unwrap_or(out_path).join(target);
    let is_dir = fs::metadata(&target_hint).map(|m| m.is_dir()).unwrap_or(false);
    let create_result = if is_dir {
        std::os::windows::fs::symlink_dir(target, &tmp_path)
    } else {
        std::os::windows::fs::symlink_file(target, &tmp_path)
    };
    if let Err(e) = create_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(SyncError::from(std::io::Error::new(
            e.kind(),
            format!(
                "failed to create Windows symlink at {out_path:?} (target {target:?}): {e}. \
                 Creating symlinks on Windows requires SeCreateSymbolicLinkPrivilege \
                 or Developer Mode to be enabled for the running user."
            ),
        )));
    }
    fs::rename(&tmp_path, out_path)?;
    Ok(())
}

/// Applies the POSIX owner-executable bit to `path`'s on-disk permissions,
/// after materialization/hydration has already written its content.
/// Idempotent (only calls `set_permissions` when the mode would actually
/// change). A no-op — `Ok(())`, no attempted mode change, no error — on
/// any non-Unix platform (Windows has no equivalent owner-exec permission
/// bit, so this must be silent there, not an error).
#[cfg(unix)]
pub fn apply_exec_bit(path: &Path, exec_bit: bool) -> Result<(), SyncError> {
    use std::os::unix::fs::PermissionsExt;
    const OWNER_EXEC: u32 = 0o100;
    let metadata = fs::metadata(path)?;
    let mut perms = metadata.permissions();
    let mode = perms.mode();
    let new_mode = if exec_bit { mode | OWNER_EXEC } else { mode & !OWNER_EXEC };
    if new_mode != mode {
        perms.set_mode(new_mode);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// See the `#[cfg(unix)]` `apply_exec_bit` above — the no-op
/// Windows/other-platform counterpart needed for cross-platform parity.
#[cfg(not(unix))]
pub fn apply_exec_bit(_path: &Path, _exec_bit: bool) -> Result<(), SyncError> {
    Ok(())
}

fn read_up_to(file: &mut fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = file.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_local_storage::FsBlockStore;

    #[test]
    fn chunk_and_reconstruct_roundtrip() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();

        let src_dir = tempfile::tempdir().unwrap();
        let src_path = src_dir.path().join("file.bin");
        let content: Vec<u8> = (0..DEFAULT_BLOCK_SIZE * 3 + 777).map(|i| (i % 251) as u8).collect();
        fs::write(&src_path, &content).unwrap();

        let blocks = chunk_file(&store, &src_path).unwrap();
        assert_eq!(blocks.len(), 4); // 3 full blocks + 1 partial

        let out_path = src_dir.path().join("reconstructed.bin");
        reconstruct_file(&store, &out_path, &blocks).unwrap();

        let reconstructed = fs::read(&out_path).unwrap();
        assert_eq!(reconstructed, content);
    }

    #[test]
    fn identical_blocks_across_files_are_deduped_in_storage() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let src_dir = tempfile::tempdir().unwrap();

        let content = vec![9u8; DEFAULT_BLOCK_SIZE];
        let path_a = src_dir.path().join("a.bin");
        let path_b = src_dir.path().join("b.bin");
        fs::write(&path_a, &content).unwrap();
        fs::write(&path_b, &content).unwrap();

        let blocks_a = chunk_file(&store, &path_a).unwrap();
        let blocks_b = chunk_file(&store, &path_b).unwrap();
        assert_eq!(blocks_a[0].hash, blocks_b[0].hash);
    }

    #[test]
    fn block_size_scales_up_for_very_large_files() {
        assert_eq!(block_size_for(1024), DEFAULT_BLOCK_SIZE);
        let huge = (TARGET_MAX_BLOCKS + 1) * DEFAULT_BLOCK_SIZE as u64;
        assert!(block_size_for(huge) > DEFAULT_BLOCK_SIZE);
    }

    /// A placeholder reports the file's correct size via `stat`
    /// without its content actually occupying disk space or being fetched.
    #[test]
    fn write_placeholder_reports_correct_size_with_no_content() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("placeholder.bin");

        write_placeholder(&out_path, 5_000_000, 1_700_000_000_000_000_000).unwrap();

        let metadata = fs::metadata(&out_path).unwrap();
        assert_eq!(metadata.len(), 5_000_000);
        // No real bytes were written — reading it back is all zeros, not
        // whatever content a real 5MB file might have had.
        let content = fs::read(&out_path).unwrap();
        assert!(content.iter().all(|&b| b == 0));
    }

    /// Deterministic pseudo-random content — real CDC boundary-finding
    /// behavior depends on actual byte entropy, so a trivially repetitive
    /// pattern (unlike the fixed-size tests above, which don't care)
    /// isn't representative here.
    fn pseudo_random_content(size: usize, seed: u64) -> Vec<u8> {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        (0..size).map(|_| rng.r#gen()).collect()
    }

    /// A large file chunked with CDC round-trips correctly through
    /// `reconstruct_file`.
    #[test]
    fn cdc_chunk_and_reconstruct_roundtrip() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = src_dir.path().join("file.bin");

        let content = pseudo_random_content(10 * 1024 * 1024, 42);
        fs::write(&src_path, &content).unwrap();

        let blocks = chunk_file_content_defined(&store, &src_path).unwrap();
        assert!(blocks.len() > 1, "a 10MB file should produce multiple CDC chunks");

        let out_path = src_dir.path().join("reconstructed.bin");
        reconstruct_file(&store, &out_path, &blocks).unwrap();
        assert_eq!(fs::read(&out_path).unwrap(), content);
    }

    /// Inserting bytes partway through a large file and re-chunking with
    /// CDC leaves most block hashes unchanged for the untouched regions,
    /// while the same edit under fixed-size chunking changes every block
    /// hash from the edit point onward.
    #[test]
    fn cdc_resists_boundary_shift_unlike_fixed_size_chunking() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let src_dir = tempfile::tempdir().unwrap();

        let original = pseudo_random_content(10 * 1024 * 1024, 7);
        let original_path = src_dir.path().join("original.bin");
        fs::write(&original_path, &original).unwrap();

        // Insert 37 bytes (not aligned to any block boundary) near the
        // start of the file — everything from there on shifts by 37 bytes
        // relative to fixed byte offsets.
        let insertion_point = 1024;
        let mut edited = original[..insertion_point].to_vec();
        edited.extend_from_slice(&pseudo_random_content(37, 999));
        edited.extend_from_slice(&original[insertion_point..]);
        let edited_path = src_dir.path().join("edited.bin");
        fs::write(&edited_path, &edited).unwrap();

        let fixed_before = chunk_file(&store, &original_path).unwrap();
        let fixed_after = chunk_file(&store, &edited_path).unwrap();
        let fixed_unchanged = count_shared_hashes(&fixed_before, &fixed_after);

        let cdc_before = chunk_file_content_defined(&store, &original_path).unwrap();
        let cdc_after = chunk_file_content_defined(&store, &edited_path).unwrap();
        let cdc_unchanged = count_shared_hashes(&cdc_before, &cdc_after);

        // Fixed-size: only the one block containing the insertion point
        // can coincidentally still match (it won't, since content shifted
        // within it) — expect (close to) nothing shared after the edit.
        assert!(
            fixed_unchanged <= 1,
            "fixed-size chunking should share almost no blocks after a mid-file insertion, shared {fixed_unchanged}"
        );
        // CDC: the vast majority of blocks after the (small, localized)
        // edit region should be found at the same content-relative
        // boundary and therefore hash identically to before the edit.
        assert!(
            cdc_unchanged as f64 / cdc_before.len() as f64 > 0.7,
            "CDC should preserve most block hashes after a small localized edit: {cdc_unchanged}/{} shared",
            cdc_before.len()
        );
        assert!(
            cdc_unchanged > fixed_unchanged,
            "CDC must share strictly more unchanged blocks than fixed-size chunking for the same edit"
        );
    }

    fn count_shared_hashes(before: &[BlockInfo], after: &[BlockInfo]) -> usize {
        let before_hashes: std::collections::HashSet<&Vec<u8>> =
            before.iter().map(|b| &b.hash).collect();
        after.iter().filter(|b| before_hashes.contains(&b.hash)).count()
    }

    /// Content below `CDC_SIZE_THRESHOLD` is a caller-side decision (this
    /// function itself doesn't enforce the threshold) — confirm it still
    /// functions correctly for a small file, since nothing here should
    /// assume a minimum input size beyond `fastcdc`'s own `CDC_MIN_SIZE`.
    #[test]
    fn cdc_chunking_handles_small_input_correctly() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = src_dir.path().join("small.bin");

        let content = pseudo_random_content(1000, 3);
        fs::write(&src_path, &content).unwrap();

        let blocks = chunk_file_content_defined(&store, &src_path).unwrap();
        let out_path = src_dir.path().join("out.bin");
        reconstruct_file(&store, &out_path, &blocks).unwrap();
        assert_eq!(fs::read(&out_path).unwrap(), content);
    }

    /// `materialize_symlink` creates a real, correctly-targeted symlink at
    /// `out_path`, atomically (via `unique_tmp_path` + rename — no
    /// partial/temp artifact left behind at the final path).
    #[cfg(unix)]
    #[test]
    fn materialize_symlink_creates_a_real_symlink_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("link.txt");

        materialize_symlink(&out_path, "../outside/target.txt").unwrap();

        let link_meta = fs::symlink_metadata(&out_path).unwrap();
        assert!(link_meta.file_type().is_symlink(), "must be a real symlink, not a regular file");
        assert_eq!(fs::read_link(&out_path).unwrap(), Path::new("../outside/target.txt"));
    }

    /// Re-materializing the same path (e.g. a re-sent index
    /// update for an unchanged symlink record) must cleanly replace the
    /// old link via the same atomic rename, not error on "already exists".
    #[cfg(unix)]
    #[test]
    fn materialize_symlink_can_replace_an_existing_link_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("link.txt");

        materialize_symlink(&out_path, "old-target.txt").unwrap();
        materialize_symlink(&out_path, "new-target.txt").unwrap();

        assert_eq!(fs::read_link(&out_path).unwrap(), Path::new("new-target.txt"));
    }

    /// Flipping the exec bit on and off actually changes the
    /// owner-executable permission bit on disk, and is idempotent (calling
    /// it again with the same value doesn't error or otherwise misbehave).
    #[cfg(unix)]
    #[test]
    fn apply_exec_bit_sets_and_clears_owner_exec_permission() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("script.sh");
        fs::write(&path, b"#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        apply_exec_bit(&path, true).unwrap();
        let mode_after_set = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode_after_set & 0o777, 0o744, "owner-exec bit must be set");

        // Idempotent: setting it again when already set is a harmless no-op.
        apply_exec_bit(&path, true).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o744);

        apply_exec_bit(&path, false).unwrap();
        let mode_after_clear = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode_after_clear & 0o777, 0o644, "owner-exec bit must be cleared");

        // Other permission bits (group/other read, in this case) are left
        // alone — this only ever touches the owner-exec bit.
        assert_eq!(mode_after_clear & 0o077, 0o044);
    }

    /// `apply_exec_bit` must never error on a plain file — this
    /// runs unconditionally (not `#[cfg(unix)]`-gated) so the non-Unix
    /// no-op arm is at least compiled and exercised on every platform this
    /// crate builds for; on this dev machine it's the `#[cfg(unix)]`-arm's
    /// real permission-changing behavior above that's exercised.
    #[test]
    fn apply_exec_bit_never_errors_on_a_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.txt");
        fs::write(&path, b"hello").unwrap();
        apply_exec_bit(&path, true).unwrap();
        apply_exec_bit(&path, false).unwrap();
    }
}
