//! Fixed-size block splitting (Syncthing-proven fixed-size blocks,
//! content-defined chunking deferred by default) is the default, plus an
//! opt-in, size-gated content-defined chunking (CDC) path for large files
//! edited internally rather than appended to or replaced wholesale (VM
//! images, databases, large project files), where fixed-size blocks
//! re-transfer everything after an edit point due to boundary shift.
//! Blocks are content-addressed and stored via [`crate::BlockContentStore`],
//! giving free local dedup: an identical block from any other file/version
//! is only ever stored once, regardless of which chunking method produced
//! it.
//!
//! Moved here from `yadorilink-sync-core::chunker` in Phase 7D-8.1 --
//! `chunk_file`/`chunk_file_content_defined`'s only production dependencies
//! were already [`crate::BlockContentStore`] and
//! `yadorilink_replica_domain::file::BlockInfo`, both already at or below
//! this crate in the dependency graph (`yadorilink-sync-core::chunker`'s
//! other functions -- `reconstruct_file`, `write_placeholder`,
//! `materialize_symlink*`, `apply_exec_bit`, the `verify_*_target_within_*`
//! guards -- were already thin `SyncError`-converting wrappers over this
//! crate's `materialize_write` module as of Phase 7D-6, and stay in
//! `yadorilink-sync-core` unchanged, since `yadorilink-sync-core` callers
//! still need a `SyncError`-returning entry point for them).
//!
//! `owner_exec_bit_from_metadata` (a 6-line `std::fs::Metadata` read, zero
//! dependencies of its own) moved alongside for the same reason: it feeds
//! exactly the same file-capture call sites `chunk_file`/
//! `chunk_file_content_defined` do.

use std::fs;
use std::io::Read;
use std::path::Path;

use crate::BlockContentStore;
use crate::StorageError;
use yadorilink_replica_domain::file::BlockInfo;

/// Default block size (128 KiB), matching Syncthing's default.
pub const DEFAULT_BLOCK_SIZE: usize = 128 * 1024;
/// Upper bound blocks scale to for very large files, matching Syncthing's
/// max (16 MiB), so a huge file doesn't produce an unwieldy block count.
const MAX_BLOCK_SIZE: usize = yadorilink_replica_domain::limits::MAX_BLOCK_SIZE_BYTES as usize;
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
pub fn chunk_file(
    store: &dyn BlockContentStore,
    path: &Path,
) -> Result<Vec<BlockInfo>, StorageError> {
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
    store: &dyn BlockContentStore,
    path: &Path,
) -> Result<Vec<BlockInfo>, StorageError> {
    let file = fs::File::open(path)?;
    let chunker = fastcdc::v2020::StreamCDC::new(file, CDC_MIN_SIZE, CDC_AVG_SIZE, CDC_MAX_SIZE);

    let mut blocks = Vec::new();
    for result in chunker {
        let chunk = result.map_err(|e| StorageError::Chunking(e.to_string()))?;
        let hash_hex = store.put(&chunk.data)?;
        blocks.push(BlockInfo {
            hash: hex::decode(&hash_hex)?,
            offset: chunk.offset,
            size: chunk.length as u32,
        });
    }

    Ok(blocks)
}

/// Applies the POSIX owner-executable bit reading convention `chunker`'s
/// own callers capture alongside a file's content — the read-side
/// counterpart to `materialize_write::apply_exec_bit`. Moved here from
/// `yadorilink-sync-core::types` in Phase 7D-8.1: a 6-line
/// `std::fs::Metadata` bit-read, zero dependencies beyond `std`.
#[cfg(unix)]
pub fn owner_exec_bit_from_metadata(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o100 != 0
}

#[cfg(not(unix))]
pub fn owner_exec_bit_from_metadata(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// Short-read-retry loop shared by `chunk_file`'s fixed-size block read and
/// (a duplicate copy, per this branch's established "duplicate small leaf
/// helpers rather than force an awkward shared dependency" precedent --
/// see `unique_tmp_path`'s own split between `materialize_write.rs` and
/// `fs_backend.rs`) `yadorilink-sync-core::single_pass_capture`'s own
/// fixed-size block read, which must fill a block buffer exactly the same
/// way (retrying on a short read instead of treating it as EOF) to agree
/// byte-for-byte with this function's output.
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
    use crate::FsBlockStore;

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
        crate::reconstruct_file(&store, &out_path, &blocks, -1).unwrap();

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

    /// Deterministic pseudo-random content — real CDC boundary-finding
    /// behavior depends on actual byte entropy, so a trivially repetitive
    /// pattern (unlike the fixed-size tests above, which don't care)
    /// isn't representative here.
    fn pseudo_random_content(size: usize, seed: u64) -> Vec<u8> {
        use rand::{RngExt, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        (0..size).map(|_| rng.random()).collect()
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
        crate::reconstruct_file(&store, &out_path, &blocks, -1).unwrap();
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
        crate::reconstruct_file(&store, &out_path, &blocks, -1).unwrap();
        assert_eq!(fs::read(&out_path).unwrap(), content);
    }

    /// Flipping the exec bit on and off actually changes the
    /// owner-executable permission bit `owner_exec_bit_from_metadata`
    /// reads back correctly.
    #[cfg(unix)]
    #[test]
    fn reads_owner_exec_bit() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("maybe-script");
        fs::write(&path, b"echo hi").unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!owner_exec_bit_from_metadata(&fs::metadata(&path).unwrap()));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o744)).unwrap();
        assert!(owner_exec_bit_from_metadata(&fs::metadata(&path).unwrap()));
    }

    #[test]
    fn owner_exec_reader_accepts_ordinary_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.txt");
        fs::write(&path, b"hello").unwrap();
        let _ = owner_exec_bit_from_metadata(&fs::metadata(&path).unwrap());
    }
}
