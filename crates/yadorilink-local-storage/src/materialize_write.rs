//! Filesystem write primitives for materializing content from block
//! storage: write-target/delete-target symlink-escape verification,
//! atomic temp-then-rename file reconstruction, sparse placeholder
//! writes, and the owner-exec bit. Moved out of `yadorilink-sync-core`'s
//! `chunker.rs` in Phase 7D-6: needed directly by `yadorilink-peer-session`
//! production code, and already parameterized entirely over
//! `BlockContentStore` (already in this crate) rather than any SQL/port
//! type -- `local_change.rs`/`materialization.rs`/`single_pass_capture.rs`
//! (staying in sync-core) use this crate's *chunking* functions, a
//! different concern from the write-target machinery here.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::content_ports::BlockContentStore;
use crate::error::StorageError;
use crate::fs_backend::{remove_path, rename_path};
use yadorilink_replica_domain::file::BlockInfo;

fn unique_tmp_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = OsString::from(path.file_name().unwrap_or_default());
    name.push(format!(".yadorilink-tmp.{}.{n}", std::process::id()));
    path.with_file_name(name)
}

/// Defense-in-depth: creates `out_path`'s parent directory (if needed) then
/// canonicalizes it and confirms it still `starts_with` `sync_root`'s own
/// canonical form, before any caller writes through `out_path`. A purely
/// lexical `..`/absolute-path rejection on the caller's side cannot detect
/// a **symlink** at an intermediate path component already present on
/// disk (planted by a local actor, or a TOCTOU race), which the plain
/// `create`/`rename` calls in `reconstruct_file`/`write_placeholder` below
/// would otherwise follow right out of the sync root. This closes that
/// specific gap for the common case (a symlinked *directory* component);
/// it does not fully eliminate every TOCTOU window (e.g. a symlink
/// swapped in between this check and the write) — known "Low / TOCTOU"
/// severity residual: exploiting even this residual window requires a
/// locally pre-planted symlink or a racing local actor, not something a
/// remote peer can create on its own.
///
/// Self-contained (canonicalizes `sync_root` itself on every call) —
/// callers that invoke this on a hot, concurrency-sensitive path for the
/// same `sync_root` repeatedly should prefer
/// `verify_write_target_within_canonical_root` with a `sync_root`
/// canonicalized once up front.
pub fn verify_write_target_within_root(
    out_path: &Path,
    sync_root: &Path,
) -> Result<(), StorageError> {
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
) -> Result<(), StorageError> {
    let parent = out_path.parent().unwrap_or(out_path);
    create_dir_all_never_through_a_symlink(parent, canonical_root, out_path)?;
    let canonical_parent = fs::canonicalize(parent)?;
    if !canonical_parent.starts_with(canonical_root) {
        return Err(StorageError::PathEscapesRoot(out_path.display().to_string()));
    }
    Ok(())
}

/// Creates every missing directory component of `target` (`out_path`'s
/// parent) WITHOUT ever creating anything by walking through an
/// already-existing symlink -- unlike plain `fs::create_dir_all`, which
/// happily follows one. A symlink planted at an intermediate component
/// inside an already-adopted sync root (e.g. `escape -> /outside`) would
/// otherwise let `create_dir_all(parent)` create real directories on the
/// far side of that symlink, entirely outside the sync root, before any
/// `canonicalize`+`starts_with` check ever ran.
///
/// The fix: find the deepest ALREADY-EXISTING ancestor of `target` first
/// (never itself created by this call), canonicalize just that ancestor,
/// and refuse immediately if it has already escaped `canonical_root` --
/// this is the only place a pre-existing symlink can be hiding, since
/// everything below it, if any, is about to be created by this
/// function itself. Every directory this function creates from there
/// down is freshly made by `fs::create_dir` one level at a time, so it is
/// by construction a plain directory, never a symlink. A residual TOCTOU
/// window remains between the existing-ancestor check and the first
/// `create_dir` -- the same documented "Low / TOCTOU" class of residual
/// `verify_write_target_within_root`'s own doc comment already accepts.
fn create_dir_all_never_through_a_symlink(
    target: &Path,
    canonical_root: &Path,
    out_path_for_errors: &Path,
) -> Result<(), StorageError> {
    let mut existing_ancestor = target;
    let mut to_create = Vec::new();
    loop {
        match fs::symlink_metadata(existing_ancestor) {
            Ok(meta) if meta.is_dir() => break,
            Ok(_) => {
                // Exists but is not a directory (a file, or -- the case
                // this function exists to catch -- a symlink). Whether
                // it's actually an escape or just a legitimately-adopted
                // non-directory in the way, refuse rather than create
                // anything through or over it.
                return Err(StorageError::PathEscapesRoot(
                    out_path_for_errors.display().to_string(),
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let Some(parent) = existing_ancestor.parent() else {
                    // Walked all the way to a filesystem root with
                    // nothing found -- `canonical_root` itself must be an
                    // ancestor of `target` for this to ever be reached
                    // legitimately; if it isn't, there's nothing safe to
                    // create.
                    return Err(StorageError::PathEscapesRoot(
                        out_path_for_errors.display().to_string(),
                    ));
                };
                to_create.push(existing_ancestor);
                existing_ancestor = parent;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let canonical_existing_ancestor = fs::canonicalize(existing_ancestor)?;
    if !canonical_existing_ancestor.starts_with(canonical_root) {
        return Err(StorageError::PathEscapesRoot(out_path_for_errors.display().to_string()));
    }
    // `to_create` was pushed shallowest-last (closest to `target` first);
    // create shallowest-first so each `create_dir` call's own parent
    // already exists.
    for dir in to_create.into_iter().rev() {
        fs::create_dir(dir)?;
    }
    Ok(())
}

/// Like `verify_write_target_within_root`, but for a caller about to
/// DELETE `out_path` rather than write it. Two differences from the write
/// version, both because a delete target that isn't there needs no
/// escape-checking machinery at all: this never creates `sync_root` or
/// `out_path`'s parent as a side effect, and a missing `sync_root` or
/// parent is treated as "nothing to verify, proceed" rather than an error
/// — the delete itself (`remove_file`) already tolerates a missing target.
pub fn verify_delete_target_within_root(
    out_path: &Path,
    sync_root: &Path,
) -> Result<(), StorageError> {
    let canonical_root = match fs::canonicalize(sync_root) {
        Ok(root) => root,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StorageError::from(e)),
    };
    verify_delete_target_within_canonical_root(out_path, &canonical_root)
}

/// Like `verify_delete_target_within_root`, but takes an already-canonical
/// `canonical_root` — see `verify_write_target_within_canonical_root`'s doc
/// comment for why this matters on a hot path.
pub fn verify_delete_target_within_canonical_root(
    out_path: &Path,
    canonical_root: &Path,
) -> Result<(), StorageError> {
    let parent = out_path.parent().unwrap_or(out_path);
    let canonical_parent = match fs::canonicalize(parent) {
        Ok(parent) => parent,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StorageError::from(e)),
    };
    if !canonical_parent.starts_with(canonical_root) {
        return Err(StorageError::PathEscapesRoot(out_path.display().to_string()));
    }
    Ok(())
}

/// Best-effort: stamps `file`'s modified-time to `mtime_unix_nanos`, unless
/// it is negative (the "no authoritative mtime to stamp" sentinel, e.g. a
/// purely local write with no wire-carried authored time). Shared by
/// `write_placeholder` and `reconstruct_file` so every materialization write
/// — sparse placeholder or real content alike — stamps the on-disk mtime the
/// same way. Some filesystems/platforms don't support setting mtime this
/// way; that is cosmetic, not a correctness issue, so failures are ignored.
fn stamp_mtime(file: &fs::File, mtime_unix_nanos: i64) {
    if mtime_unix_nanos >= 0 {
        let mtime = std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_nanos(mtime_unix_nanos as u64);
        let times = fs::FileTimes::new().set_modified(mtime);
        let _ = file.set_times(times);
    }
}

/// Reconstructs a file at `out_path` from `blocks`, reading each block's
/// content from `store` in order and concatenating.
///
/// `mtime_unix_nanos` is the mtime this materialized content is (or is
/// about to be) indexed under — pass a negative value only when no such
/// value exists yet (e.g. a low-level test with no index row). Stamping the
/// on-disk file to match the indexed value here, the same way
/// `write_placeholder` already stamps a placeholder's mtime, is
/// correctness-critical: `yadorilink-local-capture`'s local-change fast
/// path (`local_change.rs::metadata_mtime_matches`) treats "on-disk mtime
/// equals the indexed mtime" as its signal that a file is unchanged since
/// last indexed. Before this stamp existed, a materialized (peer-received)
/// file's on-disk mtime was whatever wall-clock time this write happened to
/// land at — never equal to the wire-carried authored mtime the index
/// recorded for it — so that fast path could never fire for a materialized
/// file, and a later genuine local edit fell all the way through to the
/// content-only self-echo comparison a few steps further down that same
/// function.
pub fn reconstruct_file(
    store: &dyn BlockContentStore,
    out_path: &Path,
    blocks: &[BlockInfo],
    mtime_unix_nanos: i64,
) -> Result<(), StorageError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = unique_tmp_path(out_path);
    // Assemble into the temp file, then atomically rename it into place. Any
    // failure along the way (a block-store read error mid-loop, a short write,
    // a failed rename) must not leave the orphaned `.yadorilink-tmp.*` file
    // behind. Remove it on every error path so an interrupted reconstruct
    // leaves the directory as it found it.
    let assemble = || -> Result<(), StorageError> {
        let mut out = fs::File::create(&tmp_path)?;
        for block in blocks {
            let hash_hex = hex::encode(&block.hash);
            let data = store.get(&hash_hex)?;
            std::io::Write::write_all(&mut out, &data)?;
        }
        // Stamp the mtime before the final `sync_all`/rename below, so a
        // reader that observes the renamed-into-place file always also
        // observes its final mtime — no window where the file is visible
        // under its real name with a stale (creation-time) mtime.
        stamp_mtime(&out, mtime_unix_nanos);
        // Closing a file only releases the handle; it does not make its data
        // durable across power loss. Persist the complete temp before the
        // rename can publish it under the user-visible path.
        out.sync_all()?;
        Ok(())
        // `out` is dropped (closed) here, before the rename below.
    };
    if let Err(e) = assemble().and_then(|()| {
        rename_path(&tmp_path, out_path)?;
        sync_parent_directory(out_path)?;
        Ok(())
    }) {
        let _ = remove_path(&tmp_path);
        return Err(e);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

// Windows does not support opening a directory for `sync_all` through the
// portable `std::fs::File::open` API. The temp file itself is still flushed
// before `rename`; a handle-based `FlushFileBuffers` directory implementation
// belongs in the Windows storage backend rather than behind a misleading
// portable wrapper here.
#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

/// Identity of the exact on-disk object [`write_placeholder`] just created,
/// captured from the still-open temp-file handle before this crate's own
/// rename into place -- a rename within the same filesystem preserves the
/// inode, so this is exactly what `out_path` carries once that rename
/// succeeds, without the TOCTOU window a later path-based `stat` on
/// `out_path` itself would have (something else touching `out_path`
/// between the rename and that stat).
///
/// Never derived from size/mtime -- those are exactly the signals this
/// identity exists to stop relying on alone (see
/// `yadorilink-filesystem-sync::placeholder_backend`'s doc comment on
/// `PlaceholderGeneration`). `dev`/`ino` are the OS-assigned filesystem
/// identity, so an atomic-rename save by an editor (a new inode) is
/// distinguishable from an untouched placeholder even when it happens to
/// land on the placeholder's exact size and mtime -- the residual gap
/// `local_change.rs`'s own doc comment documents for the size/mtime-only
/// heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaceholderDiskIdentity {
    pub dev: u64,
    pub ino: u64,
}

/// The `provider_kind` string every [`write_placeholder`] caller should
/// persist alongside a `Some` [`PlaceholderDiskIdentity`] -- the single
/// identity scheme this crate implements today. A single named constant
/// (rather than each of the several call sites spelling the literal) so a
/// future real OS provider's own kind string can't accidentally collide
/// with this one, and so every persisted row this scheme ever wrote stays
/// grep-able under one name.
pub const INTERNAL_INODE_PROVIDER_KIND: &str = "internal-inode";

impl PlaceholderDiskIdentity {
    /// Extracts this identity from an already-fetched [`fs::Metadata`] --
    /// the read side of the same scheme [`write_placeholder`] mints on the
    /// write side. Used both here (via an open file handle's `metadata()`)
    /// and by `yadorilink-local-capture`'s dirty-detection, which already
    /// has an `lstat`-equivalent `Metadata` in hand and must not pay for a
    /// second stat just to compare identities. `None` on non-Unix builds,
    /// same as [`write_placeholder`]'s own return -- see that function's
    /// doc comment.
    #[cfg(unix)]
    pub fn from_metadata(metadata: &fs::Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        Some(Self { dev: metadata.dev(), ino: metadata.ino() })
    }

    #[cfg(not(unix))]
    pub fn from_metadata(_metadata: &fs::Metadata) -> Option<Self> {
        None
    }
}

fn disk_identity_of(file: &fs::File) -> Option<PlaceholderDiskIdentity> {
    file.metadata().ok().and_then(|m| PlaceholderDiskIdentity::from_metadata(&m))
}

/// Writes a placeholder at `out_path`: a sparse file of `size` bytes with
/// no real content, so `stat`/`ls` report the file's correct size and
/// modification time without its bytes occupying disk space or requiring
/// a block fetch.
///
/// Content-addressed dedup means this never collides with a genuine empty
/// file: a placeholder is never chunked/indexed as content.
///
/// Returns the new placeholder's [`PlaceholderDiskIdentity`] when this
/// platform can capture one (see [`disk_identity_of`]) -- callers should
/// persist it (`MaterializationStateRepository::record_placeholder_generation`)
/// alongside the `Placeholder` state transition this call is always paired
/// with, and clear any prior identity for the same path when it comes back
/// `None`, so a stale identity from a previous placeholder never survives
/// under a row this call could not identify.
pub fn write_placeholder(
    out_path: &Path,
    size: u64,
    mtime_unix_nanos: i64,
) -> Result<Option<PlaceholderDiskIdentity>, StorageError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = unique_tmp_path(out_path);
    let mut identity: Option<PlaceholderDiskIdentity> = None;
    let mut prepare = || -> Result<(), StorageError> {
        let file = fs::File::create(&tmp_path)?;
        file.set_len(size)?;
        stamp_mtime(&file, mtime_unix_nanos);
        // A sparse length and its metadata are not durable merely because
        // the handle is closed. Persist the complete placeholder before its
        // name becomes visible, matching `reconstruct_file`'s ordering.
        file.sync_all()?;
        identity = disk_identity_of(&file);
        Ok(())
    };
    if let Err(error) =
        prepare().and_then(|()| rename_path(&tmp_path, out_path).map_err(Into::into))
    {
        let _ = remove_path(&tmp_path);
        return Err(error);
    }
    // Once rename succeeds, callers must advance their index state to
    // Placeholder. Reporting a later directory-fsync failure as if publish
    // failed would make them roll back to Hydrated while the visible file is
    // already a placeholder. Keep the runtime state coherent and surface the
    // reduced crash-durability guarantee diagnostically.
    if let Err(error) = sync_parent_directory(out_path) {
        tracing::warn!(
            path = %out_path.display(),
            error = %error,
            "placeholder was published but its parent directory could not be synced"
        );
    }
    Ok(identity)
}

/// Sets/clears the owner-exec bit on an already-materialized file. A no-op
/// on any non-Unix platform (Windows has no equivalent owner-exec
/// permission bit, so this must be silent there, not an error).
#[cfg(unix)]
pub fn apply_exec_bit(path: &Path, exec_bit: bool) -> Result<(), StorageError> {
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
pub fn apply_exec_bit(_path: &Path, _exec_bit: bool) -> Result<(), StorageError> {
    Ok(())
}

/// Materializes a symlink record at `out_path`, pointing at `target` (the
/// record's raw, unresolved target bytes — never lossily converted, and a
/// symlink target is never dereferenced by this crate; see `fs_identity::
/// bytes_to_target`, this function's inverse) using the same atomic
/// temp-path-then-rename pattern `reconstruct_file`/`write_placeholder`
/// already use: `unique_tmp_path`'s existing collision-free naming scheme
/// picks a temp path, `std::os::unix::fs::symlink` creates the link there,
/// and `fs::rename` atomically swaps it into place — a torn/partial symlink
/// is never observable at `out_path`, matching the guarantee regular-file
/// materialization already gives. Moved out of `yadorilink-sync-core`'s
/// `chunker.rs` in Phase 7D-6: needed directly by `yadorilink-peer-session`
/// production code (`materialize_symlink_at`).
#[cfg(unix)]
pub fn materialize_symlink(out_path: &Path, target: &[u8]) -> Result<(), StorageError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = unique_tmp_path(out_path);
    std::os::unix::fs::symlink(
        yadorilink_root_authority::fs_identity::bytes_to_target(target),
        &tmp_path,
    )?;
    rename_path(&tmp_path, out_path)?;
    Ok(())
}

/// Windows per-link opt-in symlink materialization: the default Windows
/// policy is skip-with-visible-status (the record is tracked and synced,
/// but nothing is written to disk), and this function is only ever reached
/// once a link has explicitly opted in. It attempts a real
/// `CreateSymbolicLinkW` via `std::os::windows::fs`, using the same atomic
/// temp-path-then-rename pattern as `materialize_symlink`. Creating a
/// Windows symlink requires `SeCreateSymbolicLinkPrivilege` or Developer
/// Mode; when that precondition isn't met the OS call fails, which is
/// surfaced here as a clear, actionable `StorageError::Io` — never a
/// silent no-op or a panic — since an opted-in link that can't actually
/// materialize symlinks on this machine should be loud about it, unlike
/// the default (non-opt-in) skip policy, which is silent by design.
///
/// Windows symlinks are typed (file vs. directory) at creation time; since
/// a target is never dereferenced for *classification* purposes elsewhere
/// in this crate, this does a best-effort *local* check instead: if
/// `target`, resolved relative to `out_path`'s parent, currently exists
/// locally as a directory, a directory symlink is created; otherwise
/// (doesn't exist yet, resolves elsewhere, or any I/O error reading it)
/// this defaults to a file symlink, the more common case.
///
/// Not exercised by this crate's own test suite (no Windows CI/dev machine
/// available at the time this was written) — reviewed carefully against
/// the documented `std::os::windows::fs` API shape, but treat as
/// unverified until run on real Windows.
#[cfg(windows)]
pub fn materialize_symlink_windows(out_path: &Path, target: &[u8]) -> Result<(), StorageError> {
    // `target` is `target_to_bytes`'s own little-endian UTF-16 output (see
    // `fs_identity::bytes_to_target`'s doc) for any target this crate itself
    // ever captured; a malformed byte string has nothing well-formed to
    // materialize.
    let Some(target) = yadorilink_root_authority::fs_identity::bytes_to_target(target) else {
        return Err(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "symlink target for {out_path:?} is not a valid UTF-16LE byte string; cannot \
                 materialize"
            ),
        )));
    };
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = unique_tmp_path(out_path);
    let target_hint = out_path.parent().unwrap_or(out_path).join(&target);
    let is_dir = fs::metadata(&target_hint).map(|m| m.is_dir()).unwrap_or(false);
    let create_result = if is_dir {
        std::os::windows::fs::symlink_dir(&target, &tmp_path)
    } else {
        std::os::windows::fs::symlink_file(&target, &tmp_path)
    };
    if let Err(e) = create_result {
        let _ = remove_path(&tmp_path);
        return Err(StorageError::from(std::io::Error::new(
            e.kind(),
            format!(
                "failed to create Windows symlink at {out_path:?} (target {target:?}): {e}. \
                 Creating symlinks on Windows requires SeCreateSymbolicLinkPrivilege \
                 or Developer Mode to be enabled for the running user."
            ),
        )));
    }
    rename_path(&tmp_path, out_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

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

    /// The identity `write_placeholder` returns for a freshly-written
    /// placeholder must actually match the placeholder's real on-disk
    /// identity, not merely be present -- a caller comparing against it
    /// later relies on this being the truth, not a synthetic value.
    #[test]
    #[cfg(unix)]
    fn write_placeholder_returns_the_real_on_disk_identity() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("placeholder.bin");

        let identity = write_placeholder(&out_path, 4096, 0).unwrap().unwrap();

        let metadata = fs::metadata(&out_path).unwrap();
        assert_eq!(identity.dev, metadata.dev());
        assert_eq!(identity.ino, metadata.ino());
    }

    /// Two placeholders written to the SAME path in sequence (mirroring a
    /// peer sending an updated version, or a repeated eviction) must mint
    /// DIFFERENT identities -- each `write_placeholder` call creates a
    /// fresh temp file and renames it in, so the second call's inode can
    /// never equal the first's. This is the exact property M1-2's
    /// generation-staleness invariant depends on: an old identity must
    /// stop matching once its placeholder is superseded.
    #[test]
    #[cfg(unix)]
    fn successive_placeholder_writes_to_the_same_path_mint_different_identities() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("placeholder.bin");

        let first = write_placeholder(&out_path, 100, 0).unwrap().unwrap();
        let second = write_placeholder(&out_path, 100, 0).unwrap().unwrap();

        assert_ne!(first, second, "a re-written placeholder must mint a fresh identity");
    }

    #[test]
    fn failed_placeholder_rename_removes_its_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("occupied");
        fs::create_dir(&out_path).unwrap();

        assert!(write_placeholder(&out_path, 1024, 0).is_err());

        let entries: Vec<_> =
            fs::read_dir(dir.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert_eq!(entries, vec![OsString::from("occupied")]);
        assert!(out_path.is_dir());
    }

    /// `materialize_symlink` creates a real, correctly-targeted symlink at
    /// `out_path`, atomically (via `unique_tmp_path` + rename — no
    /// partial/temp artifact left behind at the final path).
    #[cfg(unix)]
    #[test]
    fn materialize_symlink_creates_a_real_symlink_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("link.txt");

        materialize_symlink(&out_path, b"../outside/target.txt").unwrap();

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

        materialize_symlink(&out_path, b"old-target.txt").unwrap();
        materialize_symlink(&out_path, b"new-target.txt").unwrap();

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

    /// An independent review's finding: `create_dir_all(parent)` follows
    /// symlinks like any other `mkdir` chain, so a symlink planted at an
    /// intermediate component (`escape -> outside`) let the OLD directory-
    /// creation step create real directories on the far side of it,
    /// entirely outside the sync root, before the `canonicalize`+
    /// `starts_with` check that runs after it could ever refuse the
    /// write. The `Err` result alone (already covered by
    /// `materialize_symlink_at_refuses_a_root_whose_marker_no_longer_
    /// matches`-style tests elsewhere) is not enough to prove this fix --
    /// the whole point is that side effects outside the root must never
    /// happen at all, error or not.
    #[cfg(unix)]
    #[test]
    fn verify_write_target_within_root_creates_no_directories_through_an_escape_symlink() {
        let sync_root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), sync_root.path().join("escape")).unwrap();

        let out_path = sync_root.path().join("escape").join("a").join("b").join("pwned.txt");
        let result = verify_write_target_within_root(&out_path, sync_root.path());

        assert!(result.is_err(), "a write target reached only through a symlink must be refused");
        assert!(
            !outside.path().join("a").exists(),
            "no directory must ever be created on the far side of the escape symlink, \
             regardless of whether the write itself is correctly refused"
        );
    }

    /// The non-escaping case must keep working exactly as before: nested
    /// directories that genuinely need creating under the real root are
    /// still created, component by component, with no regression from
    /// the old single `create_dir_all` call.
    #[test]
    fn verify_write_target_within_root_still_creates_genuine_nested_directories() {
        let sync_root = tempfile::tempdir().unwrap();
        let out_path = sync_root.path().join("a").join("b").join("c").join("file.txt");

        verify_write_target_within_root(&out_path, sync_root.path()).unwrap();

        assert!(sync_root.path().join("a").join("b").join("c").is_dir());
    }
}
