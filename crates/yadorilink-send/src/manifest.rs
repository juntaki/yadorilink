//! Builds an offer's manifest by chunking the source path into Track
//! Send's own `FsBlockStore` (see [`crate::session::SendService::new`]) --
//! reusing `yadorilink_local_storage::chunker::chunk_file` exactly as the
//! sync engine does for its own captures, just against a wholly separate
//! store root (see `store.rs`'s own doc comment for why: dedup and crash-
//! durable commits for free, with zero visibility to the sync engine's
//! DAG-driven GC liveness sweep).
//!
//! Chunking a file freezes its offered content at offer time: once
//! `build_outbound_manifest` returns, every chunk is durably content-
//! addressed in the local store, so a later pull never re-reads (or can be
//! confused by an edit to) the original source path.

use std::path::{Path, PathBuf};

use yadorilink_ipc_proto::send::{SendFileEntry, SendManifest};
#[cfg(test)]
use yadorilink_local_storage::DEFAULT_BLOCK_SIZE;
use yadorilink_local_storage::{block_size_for, chunk_file, BlockContentStore};

use crate::error::{Result, SendError};

/// Walks `source_path`: a single regular file becomes one entry named by
/// its own file name; a directory becomes one entry per regular file found
/// by a recursive walk, named by its path relative to `source_path` with
/// forward slashes (never the platform separator, so a manifest built on
/// Windows and received on macOS/Linux names files identically).
///
/// Symlinks are skipped rather than followed or sent as symlinks -- v1
/// scope is plain file content, matching a one-shot Taildrop/Resilio-style
/// send; nothing downstream (the manifest, the wire protocol,
/// `reconstruct_file`) has a symlink representation to skip past.
fn collect_files(source_path: &Path) -> Result<Vec<(String, PathBuf)>> {
    let metadata = std::fs::symlink_metadata(source_path)?;
    if metadata.is_file() {
        let name = source_path
            .file_name()
            .ok_or_else(|| {
                SendError::Protocol(format!("{}: has no file name", source_path.display()))
            })?
            .to_string_lossy()
            .into_owned();
        return Ok(vec![(name, source_path.to_path_buf())]);
    }
    if !metadata.is_dir() {
        // Symlink, device file, etc. -- neither a file nor a directory
        // this walk knows how to represent.
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(source_path).follow_links(false).sort_by_file_name() {
        let entry = entry.map_err(std::io::Error::from)?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(source_path)
            .expect("walkdir yields paths under its own root");
        // Forward slashes on every platform -- see this function's own
        // doc comment.
        let relative_str = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        out.push((relative_str, entry.path().to_path_buf()));
    }
    Ok(out)
}

/// Chunks every file under `source_path` into `store`, returning a
/// manifest describing the offer -- `total_size` mirrors
/// `manifest.total_size` for a caller that just needs the number without
/// decoding.
pub fn build_outbound_manifest(
    store: &dyn BlockContentStore,
    source_path: &Path,
    transfer_id: &str,
) -> Result<(SendManifest, u64)> {
    let files = collect_files(source_path)?;
    if files.is_empty() {
        return Err(SendError::EmptyManifest(source_path.display().to_string()));
    }
    let mut entries = Vec::with_capacity(files.len());
    let mut total_size: u64 = 0;
    for (relative_path, absolute_path) in files {
        let size = std::fs::metadata(&absolute_path)?.len();
        let blocks = chunk_file(store, &absolute_path)?;
        let chunk_hashes = blocks.into_iter().map(|b| b.hash).collect::<Vec<_>>();
        let chunk_size = block_size_for(size) as u32;
        total_size += size;
        entries.push(SendFileEntry { relative_path, size, chunk_size, chunk_hashes });
    }
    let offered_at_unix_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64;
    Ok((
        SendManifest {
            transfer_id: transfer_id.to_string(),
            files: entries,
            total_size,
            offered_at_unix_nanos,
        },
        total_size,
    ))
}

/// The byte size of chunk `chunk_index` within `entry` -- every chunk is
/// `entry.chunk_size` bytes except the last, which is whatever remains.
/// Matches `chunk_file`'s own fixed-size splitting exactly (a short final
/// read), so a value computed here always agrees with what the sender's
/// local store actually holds under that chunk's hash.
pub fn chunk_byte_size(entry: &SendFileEntry, chunk_index: usize) -> Result<u32> {
    let num_chunks = entry.chunk_hashes.len();
    if chunk_index >= num_chunks {
        return Err(SendError::Protocol(format!(
            "chunk index {chunk_index} out of range for {} chunks",
            num_chunks
        )));
    }
    if chunk_index + 1 < num_chunks {
        return Ok(entry.chunk_size);
    }
    let full_chunks = (num_chunks - 1) as u64 * entry.chunk_size as u64;
    Ok(entry.size.saturating_sub(full_chunks) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_local_storage::FsBlockStore;

    fn store(dir: &std::path::Path) -> FsBlockStore {
        FsBlockStore::new(dir).unwrap()
    }

    #[test]
    fn a_single_file_becomes_one_entry_named_by_its_own_basename() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = store(block_dir.path());
        let source_dir = tempfile::tempdir().unwrap();
        let path = source_dir.path().join("hello.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let (manifest, total) = build_outbound_manifest(&store, &path, "t1").unwrap();
        assert_eq!(total, 11);
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].relative_path, "hello.txt");
        assert_eq!(manifest.files[0].size, 11);
        assert_eq!(manifest.files[0].chunk_hashes.len(), 1);
    }

    #[test]
    fn a_directory_becomes_one_entry_per_file_with_forward_slash_relative_paths() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = store(block_dir.path());
        let source_dir = tempfile::tempdir().unwrap();
        std::fs::write(source_dir.path().join("root.txt"), b"r").unwrap();
        std::fs::create_dir(source_dir.path().join("sub")).unwrap();
        std::fs::write(source_dir.path().join("sub").join("nested.txt"), b"n").unwrap();

        let (manifest, total) = build_outbound_manifest(&store, source_dir.path(), "t1").unwrap();
        assert_eq!(total, 2);
        let mut names: Vec<_> = manifest.files.iter().map(|f| f.relative_path.clone()).collect();
        names.sort();
        assert_eq!(names, vec!["root.txt".to_string(), "sub/nested.txt".to_string()]);
    }

    #[test]
    fn an_empty_directory_is_rejected_rather_than_offering_nothing() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = store(block_dir.path());
        let source_dir = tempfile::tempdir().unwrap();

        let error = build_outbound_manifest(&store, source_dir.path(), "t1").unwrap_err();
        assert!(matches!(error, SendError::EmptyManifest(_)));
    }

    #[test]
    fn chunk_byte_size_matches_a_real_multi_chunk_split() {
        let block_dir = tempfile::tempdir().unwrap();
        let store = store(block_dir.path());
        let source_dir = tempfile::tempdir().unwrap();
        let path = source_dir.path().join("big.bin");
        // Three full 128 KiB chunks plus a short final one.
        let content = vec![7u8; DEFAULT_BLOCK_SIZE * 3 + 12345];
        std::fs::write(&path, &content).unwrap();

        let (manifest, _total) = build_outbound_manifest(&store, &path, "t1").unwrap();
        let entry = &manifest.files[0];
        assert_eq!(entry.chunk_hashes.len(), 4);
        for i in 0..3 {
            assert_eq!(chunk_byte_size(entry, i).unwrap(), DEFAULT_BLOCK_SIZE as u32);
        }
        assert_eq!(chunk_byte_size(entry, 3).unwrap(), 12345);
        assert!(chunk_byte_size(entry, 4).is_err());
    }
}
