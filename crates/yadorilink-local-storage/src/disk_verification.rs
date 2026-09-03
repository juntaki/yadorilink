//! Pure disk-content verification and headroom-preflight helpers: no SQL,
//! no port dependency, just filesystem reads/hashing and the free-space
//! classification this crate already owns. Moved out of
//! `yadorilink-sync-core`'s `materialization.rs` in Phase 7D-6: needed
//! directly by `yadorilink-peer-session` production code
//! (`disk_content_comparison`/`disk_bytes_match_indexed_blocks`/
//! `intent_target_hash`/`check_disk_headroom`), and by
//! `materialization.rs`/`root_identity.rs` (staying in sync-core) alike.

use std::path::Path;

use sha2::{Digest, Sha256};
use yadorilink_replica_domain::file::BlockInfo;

use crate::free_space;
use crate::StorageError;

/// Preflight check before a hydration fetch or a materialize-to-temp-and-
/// rename write begins, scoped to the volume hosting `root`. Returns
/// `Ok(())` when the write may proceed, or `StorageError::DiskPressure` --
/// never partially writing anything, since this is checked *before* any
/// temp file is created -- when completing a write of `additional_bytes`
/// more would breach the configured headroom.
///
/// `headroom_override_bytes`: `None` uses the default `max(1 GiB, 5%)`
/// formula; `Some(_)` is an explicit override, both resolved the same way
/// the block-store preflight resolves it. Callers that haven't opted into
/// disk-pressure enforcement at all should not call this at all rather
/// than passing a sentinel.
pub fn check_disk_headroom(
    root: &Path,
    target_path: &Path,
    additional_bytes: u64,
    headroom_override_bytes: Option<u64>,
) -> Result<(), StorageError> {
    let space = free_space::classify_volume(root, headroom_override_bytes)?;
    if space.would_breach(additional_bytes) {
        return Err(StorageError::DiskPressure {
            path: target_path.to_path_buf(),
            volume: root.to_path_buf(),
            available_bytes: space.available_bytes,
            headroom_bytes: space.headroom_bytes,
        });
    }
    Ok(())
}

/// A stable content-derived identifier for a materialization intent's
/// target: SHA-256 over the record's block-hash sequence.
pub fn intent_target_hash(blocks: &[BlockInfo]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for block in blocks {
        hasher.update(&block.hash);
    }
    hasher.finalize().to_vec()
}

/// [`intent_target_hash`]'s counterpart for a materialization intent whose
/// target is not a block list at all -- a symlink's raw target bytes.
/// SHA-256 over the bytes directly, matching `intent_target_hash`'s own
/// "stable content-derived identifier" shape.
pub fn intent_target_hash_for_bytes(target: &[u8]) -> Vec<u8> {
    Sha256::digest(target).to_vec()
}

/// The three distinct ways a path's on-disk content can relate to a set of
/// indexed blocks. Collapsing `PresentButDifferent` and `Absent` into one
/// `false` is what let a pre-materialize guard misread "this path's parent
/// directory was renamed and the local pipeline hasn't caught up yet" as
/// "an unauthored local edit is on disk", declining a legitimate
/// fast-forward materialize forever -- callers must not silently
/// re-collapse this distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskContentComparison {
    /// The file exists and every indexed block's bytes match, with no
    /// trailing content beyond the last block.
    Matched,
    /// A file exists at the path, but its bytes diverge from the indexed
    /// blocks (a different hash, a short read, or trailing bytes past the
    /// last indexed block).
    PresentButDifferent,
    /// Nothing exists at the path at all.
    Absent,
}

/// Compares a path's on-disk bytes against a set of indexed blocks,
/// distinguishing "content differs" from "nothing is there" -- see
/// [`DiskContentComparison`]'s doc for why that distinction matters. Reads
/// the file once, streaming each block's SHA-256 in sequence and
/// early-exiting on the first mismatch.
pub fn disk_content_comparison(
    path: &Path,
    blocks: &[BlockInfo],
) -> Result<DiskContentComparison, StorageError> {
    use std::io::Read;

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DiskContentComparison::Absent);
        }
        Err(e) => return Err(e.into()),
    };
    for block in blocks {
        let mut bytes = vec![0u8; block.size as usize];
        if let Err(error) = file.read_exact(&mut bytes) {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(DiskContentComparison::PresentButDifferent);
            }
            return Err(error.into());
        }
        if Sha256::digest(&bytes).as_slice() != block.hash.as_slice() {
            return Ok(DiskContentComparison::PresentButDifferent);
        }
    }
    let mut trailing = [0u8; 1];
    Ok(if file.read(&mut trailing)? == 0 {
        DiskContentComparison::Matched
    } else {
        DiskContentComparison::PresentButDifferent
    })
}

/// Whether a path's on-disk bytes exactly match a set of indexed blocks --
/// a thin wrapper over [`disk_content_comparison`] for the (common) callers
/// that only need "is this already current", where `PresentButDifferent`
/// and `Absent` are equally "no, it isn't" and nothing downstream needs to
/// tell them apart.
///
/// **Do not use this for a "may I overwrite this path" decision.** That
/// question needs [`disk_content_comparison`] directly: overwriting
/// `PresentButDifferent` bytes destroys an unauthored local edit
/// permanently, while a path that is `Absent` may legitimately be safe to
/// write into.
pub fn disk_bytes_match_indexed_blocks(
    path: &Path,
    blocks: &[BlockInfo],
) -> Result<bool, StorageError> {
    Ok(matches!(disk_content_comparison(path, blocks)?, DiskContentComparison::Matched))
}
