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
/// same way.
///
/// A `set_times` failure here (some filesystems/platforms don't support
/// setting mtime at all, or only at coarser precision) is silently
/// ignored, not propagated -- this is `mtime`'s retained-only treatment
/// (see `SettlementEvidence::ExactObject`'s own doc comment for the full
/// target-projection-contract model this and every other metadata field
/// follows): `mtime_unix_nanos` stays authoritative in the LOGICAL
/// version (`version_hash`) regardless of whether this stamp lands, and
/// nothing downstream currently strict-verifies disk mtime against it,
/// so a failed stamp never blocks completion. It is not, however,
/// unimportant when it succeeds: `reconstruct_file`'s own doc comment
/// below explains a real, separate mechanism (`local_change.rs`'s
/// self-echo-suppression fast path) that this stamp landing correctly
/// makes cheaper -- a failure just means that one fast path doesn't
/// fire for this file, falling through to the slower but still-correct
/// content-hash comparison a few steps further down the same function,
/// not that anything becomes wrong.
fn stamp_mtime(file: &fs::File, mtime_unix_nanos: i64) {
    if mtime_unix_nanos >= 0 {
        let mtime = std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_nanos(mtime_unix_nanos as u64);
        let times = fs::FileTimes::new().set_modified(mtime);
        let _ = file.set_times(times);
    }
}

/// [`stamp_mtime`]'s path-based counterpart, for a caller (a metadata-
/// only fast path that never opens its own fresh `File` handle the way
/// `reconstruct_file`/`write_placeholder` do mid-write) that only has
/// `path` to work with. Best-effort in exactly the same way: a
/// `set_times` failure is silently ignored, never propagated -- see
/// `stamp_mtime`'s own doc comment for the target-projection-contract
/// reasoning (mtime is retained-only, not exact-required, on every
/// target today). Only the leading `File::open` can fail here, and that
/// failure IS propagated: a metadata-only fast path only ever calls this
/// after already confirming the path exists, so an open failure at this
/// point is a genuine anomaly, not an expected "this target can't do
/// this" outcome.
pub fn stamp_mtime_at_path(path: &Path, mtime_unix_nanos: i64) -> Result<(), StorageError> {
    let file = fs::File::open(path)?;
    stamp_mtime(&file, mtime_unix_nanos);
    Ok(())
}

/// Whether `path`'s on-disk mtime already equals `desired_mtime_unix_
/// nanos` -- a pure, read-only comparison with no side effects, the
/// mtime counterpart of `unix_mode_already_matches_disk`/`xattrs_
/// already_match_disk`. Exists so a caller that must bump a physical-
/// mutation fence before its first real mutating syscall (never after)
/// can decide whether attempting `stamp_mtime_at_path` would actually
/// change anything, before committing to either it or a fence bump --
/// this is purely a fence-bump-correctness concern, NOT a completion
/// gate: mtime stays retained-only (see `SettlementEvidence::
/// ExactObject`'s own doc comment), so this function's result never
/// blocks `ExactObject` from being constructed, only decides whether the
/// stamp attempt below it needs a preceding bump.
///
/// A negative `desired_mtime_unix_nanos` (the "no authoritative mtime to
/// stamp" sentinel `stamp_mtime` itself also honors) trivially matches:
/// there is nothing to compare against, the same "not applicable, so
/// nothing to enforce" treatment `unix_mode_already_matches_disk` gives
/// `unix_mode: None`. A pre-1970 on-disk mtime (which a non-negative
/// desired value can never equal) is treated as a mismatch rather than
/// an error -- letting the caller attempt (and, being best-effort,
/// harmlessly fail or succeed at) a real stamp rather than surfacing a
/// hard error for what is, at most, a stale/unusual timestamp already on
/// disk.
pub fn mtime_already_matches_disk(
    path: &Path,
    desired_mtime_unix_nanos: i64,
) -> Result<bool, StorageError> {
    if desired_mtime_unix_nanos < 0 {
        return Ok(true);
    }
    let modified = fs::metadata(path)?.modified()?;
    let actual_nanos = match modified.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(_) => return Ok(false),
    };
    Ok(actual_nanos == desired_mtime_unix_nanos)
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
    let tmp_path = reconstruct_file_to_temp(store, out_path, blocks, mtime_unix_nanos)?;
    persist_reconstructed_file(&tmp_path, out_path)
}

/// The "assemble" half of [`reconstruct_file`]: reads `blocks` from `store`
/// and writes them, concatenated, into a fresh, durably-fsynced temp file
/// near `out_path` (same directory, so a later rename can be atomic on the
/// same filesystem) -- WITHOUT touching `out_path` itself at all. Returns
/// the temp file's path.
///
/// Split out (C4-6: receiver-side materialization batching) so a caller
/// that needs to defer the final publish -- e.g. to batch several paths'
/// SQLite commits together before any of them become visible on disk --
/// can do the slow part (this function: network-fetch-bound block reads)
/// without holding that path's lock, then take the lock only for the fast
/// [`persist_reconstructed_file`] half. Callers with no such need should
/// keep calling [`reconstruct_file`], which does both steps exactly as
/// before -- this split changes no behavior for them.
///
/// On any failure (a block-store read error mid-loop, a short write), the
/// temp file is removed so an interrupted assemble leaves the directory as
/// it found it -- the caller never receives a `tmp_path` for a file that
/// only partially exists.
pub fn reconstruct_file_to_temp(
    store: &dyn BlockContentStore,
    out_path: &Path,
    blocks: &[BlockInfo],
    mtime_unix_nanos: i64,
) -> Result<PathBuf, StorageError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = unique_tmp_path(out_path);
    let assemble = || -> Result<(), StorageError> {
        let mut out = fs::File::create(&tmp_path)?;
        for block in blocks {
            let hash_hex = hex::encode(&block.hash);
            let data = store.get(&hash_hex)?;
            std::io::Write::write_all(&mut out, &data)?;
        }
        // M6-2: receiver-side phase timing (see hydration.rs's own M6PHASE
        // lines for the daemon-level points either side of this function).
        // This function is shared with the version-restore materialization
        // path, not only on-demand hydration -- a phase-log reader
        // interested specifically in a bulk-transfer receiver run should
        // anchor these against `T_recv_materialize_start`, which only the
        // hydration path emits.
        tracing::warn!("M6PHASE T_recv_write_done: final-file write complete (all blocks written to the temp file)");
        // Stamp the mtime before the final `sync_all`/rename below, so a
        // reader that observes the renamed-into-place file always also
        // observes its final mtime — no window where the file is visible
        // under its real name with a stale (creation-time) mtime.
        stamp_mtime(&out, mtime_unix_nanos);
        // Closing a file only releases the handle; it does not make its data
        // durable across power loss. Persist the complete temp before the
        // rename can publish it under the user-visible path.
        out.sync_all()?;
        tracing::warn!("M6PHASE T_recv_fsync_done: final-file fsync complete");
        Ok(())
        // `out` is dropped (closed) here, before the rename below.
    };
    if let Err(e) = assemble() {
        let _ = remove_path(&tmp_path);
        return Err(e);
    }
    Ok(tmp_path)
}

/// The "publish" half of [`reconstruct_file`]: atomically renames an
/// already-assembled temp file (from [`reconstruct_file_to_temp`]) into
/// place at `out_path`, then syncs the parent directory. Fast (one rename,
/// one directory fsync) and does no network/block-store I/O -- the
/// intended boundary for a caller that wants to hold a path's lock across
/// only this short step, not the slower assemble step above.
///
/// On any failure, removes `tmp_path` so an interrupted publish leaves the
/// directory as it found it. `tmp_path` must not be reused after this
/// returns, whether it succeeds or fails.
pub fn persist_reconstructed_file(tmp_path: &Path, out_path: &Path) -> Result<(), StorageError> {
    let publish = || -> Result<(), StorageError> {
        rename_path(tmp_path, out_path)?;
        tracing::warn!("M6PHASE T_recv_rename_done: temp-file-to-final-path rename complete");
        sync_parent_directory(out_path)?;
        // On Unix this is a real parent-directory fsync (see `sync_parent_
        // directory`'s own doc comment); on non-Unix it is a documented
        // no-op, so this line still fires there but measures nothing real
        // -- a phase-log reader on a non-Unix capture should read this
        // span as "step skipped," not "step free."
        tracing::warn!(
            "M6PHASE T_recv_dir_fsync_done: parent-directory fsync complete (or skipped, non-Unix)"
        );
        Ok(())
    };
    if let Err(e) = publish() {
        let _ = remove_path(tmp_path);
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

/// The `provider_kind` string M2-2's Windows CfAPI generation-identity
/// scheme persists alongside a `PlaceholderDiskIdentity` -- reusing this
/// same two-`u64`-column shape even though the real value is a single
/// opaque `u64` generation token, not a `(dev, ino)` pair: `dev` is always
/// `0` (an unused sentinel) and `ino` carries the generation. See
/// `yadorilink-daemon`'s `placeholder_inspect_windows` module (the real
/// CfAPI-backed reader of this value) and `shell-ext/windows/src/cfapi.rs`'s
/// `encode_generation_identity` (the writer, over on the CfAPI side of the
/// process boundary) for the wire format this token is stored in as a
/// placeholder's actual `FileIdentity` on disk -- unrelated to how it's
/// persisted here in the daemon's own index.
pub const WINDOWS_CFAPI_GENERATION_PROVIDER_KIND: &str = "windows-cfapi-generation";

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

/// What a placeholder-creation call site must persist once
/// [`create_or_defer_placeholder`] returns, and HOW -- mirrors
/// `write_placeholder`'s own `Some`/`None` contract, but with the provider
/// kind bundled in (so a caller can never persist a Windows-minted
/// generation under [`INTERNAL_INODE_PROVIDER_KIND`] or vice versa) and the
/// persist DISCIPLINE made explicit, because the two platforms need
/// different ones:
///
/// - Unix: the write and the identity are the same atomic fact -- this
///   identity IS what's on disk right now, so persisting it must always WIN,
///   unconditionally, even over a stale prior value.
/// - Windows: real on-disk creation is deferred to a second process
///   (`cfapi-host.exe`) polling on its own schedule, so a concurrent
///   `ListFolderFilesRequest` backfill (`ensure_windows_placeholder_
///   generation`) can mint and persist its OWN generation for the same path
///   first and hand it to that process before this call's persist runs. An
///   unconditional overwrite here would then silently orphan the generation
///   already in use on disk. Must persist only-if-absent, keeping whichever
///   value won.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderIdentityToRecord {
    RecordOverwrite { identity: PlaceholderDiskIdentity, provider_kind: &'static str },
    RecordIfAbsent { identity: PlaceholderDiskIdentity, provider_kind: &'static str },
    Clear,
}

impl PlaceholderIdentityToRecord {
    /// Whether the real placeholder object this outcome describes is
    /// deferred to a separate, out-of-process step (Windows's
    /// `cfapi-host.exe`, on its own ~30s poll -- see `create_or_defer_
    /// placeholder`'s own doc comment) rather than already, durably on
    /// disk right now. `RecordOverwrite` and `Clear` both mean the real
    /// write already happened synchronously (Unix's `write_placeholder`
    /// either minted an identity or could not, but the rename onto
    /// `out_path` itself already succeeded either way) -- only
    /// `RecordIfAbsent` means nothing has actually landed on disk yet.
    ///
    /// A caller must not clear a materialization intent that is
    /// protecting this exact path, or settle an outcome that completes
    /// this path's projection obligation, while this is `true`: doing so
    /// removes every one of the tombstone loop's three vetoes for a path
    /// that genuinely has nothing under its own name yet, before
    /// `cfapi-host.exe` has had a chance to create it.
    pub fn is_deferred_to_a_separate_process(&self) -> bool {
        matches!(self, Self::RecordIfAbsent { .. })
    }
}

/// The one sanctioned entry point every production placeholder-creation
/// call site (repair, eviction, peer materialize) must use INSTEAD OF
/// calling [`write_placeholder`] directly (M2-3a).
///
/// On every platform except Windows this is exactly `write_placeholder`,
/// unchanged: writes a real sparse file and returns its on-disk identity
/// under [`INTERNAL_INODE_PROVIDER_KIND`].
///
/// On Windows this writes NOTHING to disk. Before M2-3a, every caller here
/// called `write_placeholder` unconditionally, which on Windows still wrote
/// a real sparse file (identity capture is the only part that's a no-op on
/// non-Unix) and returned `None` -- so the caller then called
/// `clear_placeholder_generation`, silently discarding any Windows CfAPI
/// generation. Two bugs followed: (1) `cfapi-host.exe`'s `sync_placeholders`
/// skips any path that already `exists()` on disk, so that real sparse file
/// permanently pre-empted the native `CfCreatePlaceholders` call -- these
/// paths never became real CfAPI placeholders at all; (2) even had it not
/// pre-empted native creation, the cleared generation meant M2-2's dirty
/// detection could never do better than fail-closed `Unknown` for a path
/// created through one of these three call sites.
///
/// Here, instead, no sparse file is written at all: a fresh generation is
/// minted and returned tagged [`WINDOWS_CFAPI_GENERATION_PROVIDER_KIND`] for
/// the caller to persist immediately (the same call-site pattern the
/// `write_placeholder` path already used, just with a different provider
/// kind). The caller's normal `set_materialization_state(..., Placeholder)`
/// still runs exactly as before. The real on-disk reparse-point placeholder
/// is created afterward by `cfapi-host.exe`'s existing poll
/// (`sync_placeholders` -> `create_placeholder`), which is unaffected by
/// this change and already reads the generation this call persists via
/// `ListFolderFilesRequest`. Not creating the parent directory here either
/// is deliberate for the same reason: `cfapi-host.exe`'s own
/// `create_placeholder` already creates it.
pub fn create_or_defer_placeholder(
    out_path: &Path,
    size: u64,
    mtime_unix_nanos: i64,
) -> Result<PlaceholderIdentityToRecord, StorageError> {
    #[cfg(any(test, feature = "test-support"))]
    if test_force_deferred_placeholder_is_armed_for(out_path) {
        let _ = (out_path, size, mtime_unix_nanos);
        return Ok(PlaceholderIdentityToRecord::RecordIfAbsent {
            identity: PlaceholderDiskIdentity {
                dev: 0,
                ino: mint_windows_placeholder_generation(),
            },
            provider_kind: WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
        });
    }
    #[cfg(windows)]
    {
        let _ = (out_path, size, mtime_unix_nanos);
        Ok(PlaceholderIdentityToRecord::RecordIfAbsent {
            identity: PlaceholderDiskIdentity {
                dev: 0,
                ino: mint_windows_placeholder_generation(),
            },
            provider_kind: WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
        })
    }
    #[cfg(not(windows))]
    {
        Ok(match write_placeholder(out_path, size, mtime_unix_nanos)? {
            Some(identity) => PlaceholderIdentityToRecord::RecordOverwrite {
                identity,
                provider_kind: INTERNAL_INODE_PROVIDER_KIND,
            },
            None => PlaceholderIdentityToRecord::Clear,
        })
    }
}

/// Test-only failure-injection flag, consumed by `create_or_defer_
/// placeholder` itself: when armed, forces the Windows-deferred
/// (`RecordIfAbsent`) outcome regardless of the actual host platform.
/// Every production caller's Windows-deferred handling is otherwise
/// exercisable only on a real Windows host -- this lets a test on any
/// platform drive that exact caller-side branch (does it skip clearing
/// the protecting intent / settling the projection obligation the way it
/// must?) without needing one. `test-support`, not just `test`: the
/// regression tests that need this live in OTHER crates' test builds
/// (`yadorilink-peer-session`, `yadorilink-filesystem-sync`), which link
/// against a normal (non-`#[cfg(test)]`) build of this crate -- see this
/// crate's own `test-support` feature. Compiled out entirely in a
/// production build.
///
/// Path-keyed, deliberately NOT a single process-wide flag: this same
/// process (a single `cargo test` binary runs every `#[test]`/
/// `#[tokio::test]` function in a crate concurrently, on separate
/// threads, by default) can be running an UNRELATED test at the exact
/// same moment that also reaches `create_or_defer_placeholder` -- for
/// example, an eviction test's own `#[cfg(not(windows))]` call site,
/// which must always take the real, synchronous `write_placeholder` path
/// regardless of what any OTHER concurrently-running test has armed. A
/// blanket global flag armed by one test's `RecordIfAbsent` scenario
/// would silently hijack that unrelated call too -- confirmed by a real,
/// intermittent (measured ~10%) test corruption this exact shape caused
/// before this fix, not a theoretical concern. Scoping the seam to the
/// exact path each test already uses (every test using this seam already
/// picks a path unique to itself) means concurrently-running tests need
/// no serialization against each other at all -- unlike a lock, this
/// requires no caller elsewhere in the workspace to remember to opt in in
/// order to stay safe.
#[cfg(any(test, feature = "test-support"))]
static TEST_FORCE_DEFERRED_PLACEHOLDER_PATHS: std::sync::Mutex<
    Option<std::collections::HashSet<std::path::PathBuf>>,
> = std::sync::Mutex::new(None);

#[cfg(any(test, feature = "test-support"))]
fn test_force_deferred_placeholder_is_armed_for(path: &Path) -> bool {
    TEST_FORCE_DEFERRED_PLACEHOLDER_PATHS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .is_some_and(|paths| paths.contains(path))
}

/// Test-only: arms (or disarms) the failure-injection flag above for one
/// exact path. Only ever affects calls to `create_or_defer_placeholder`
/// for THIS path -- see the static's own doc comment for why that
/// matters.
#[cfg(any(test, feature = "test-support"))]
pub fn set_test_force_deferred_placeholder_for_path(path: &Path, armed: bool) {
    let mut guard = TEST_FORCE_DEFERRED_PLACEHOLDER_PATHS.lock().unwrap_or_else(|p| p.into_inner());
    let paths = guard.get_or_insert_with(std::collections::HashSet::new);
    if armed {
        paths.insert(path.to_path_buf());
    } else {
        paths.remove(path);
    }
}

/// Mints a fresh Windows CfAPI placeholder generation: a process-lifetime
/// monotonic counter seeded from wall-clock time, so two placeholders
/// minted back-to-back (even at the same path, e.g. an evict immediately
/// followed by a re-create) never collide regardless of clock resolution.
/// The single shared mint site for every Windows generation-minting caller
/// in the daemon process -- both this module's [`create_or_defer_placeholder`]
/// and `yadorilink-daemon`'s `LinkFlushHandle::ensure_windows_placeholder_
/// generation` (the `ListFolderFilesRequest`-driven lazy backfill for
/// placeholders that predate this call, or that this call's own persist
/// raced with) call this same counter, since both run in the one daemon
/// process. Uniqueness only needs to hold per-path over time, not globally
/// across paths -- a live CfAPI generation comparison is always scoped to
/// one path -- so a shared counter across unrelated paths is harmless.
///
/// Deliberately NOT `#[cfg(windows)]`-gated: it's pure counter logic with no
/// platform API, and `yadorilink-daemon`'s caller invokes it unconditionally
/// (dead code on non-Windows, never compiled out).
pub fn mint_windows_placeholder_generation() -> u64 {
    static COUNTER: std::sync::OnceLock<AtomicU64> = std::sync::OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        AtomicU64::new(seed)
    });
    counter.fetch_add(1, Ordering::Relaxed)
}

/// Whether [`apply_unix_mode`] would need to perform a real
/// `set_permissions` syscall for `path` given the desired `unix_mode` -- a
/// pure, read-only comparison against what disk currently holds, with no
/// side effects. `true` means calling `apply_unix_mode` right now would be
/// a genuine no-op; `false` means it would actually change something.
/// Exists so a caller that must bump a physical-mutation fence before its
/// first real mutating syscall (never after) can decide whether it needs
/// to bump at all, before committing to either `apply_unix_mode` or a
/// fence bump.
#[cfg(unix)]
pub fn unix_mode_already_matches_disk(
    path: &Path,
    unix_mode: Option<u32>,
) -> Result<bool, StorageError> {
    use std::os::unix::fs::PermissionsExt;
    const PERMISSION_BITS: u32 = 0o777;
    let Some(unix_mode) = unix_mode else {
        return Ok(true);
    };
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    Ok((mode & PERMISSION_BITS) == (unix_mode & PERMISSION_BITS))
}

/// See the `#[cfg(unix)]` `unix_mode_already_matches_disk` above --
/// `apply_unix_mode` is already a no-op off Unix, so it never needs a
/// fence bump either.
///
/// Target projection contract (see `SettlementEvidence::ExactObject`'s
/// own doc comment for the full model): `unix_mode` is retained-only on
/// a non-Unix target, not exact-required. This function's own `Ok(true)`
/// is that retained-only status expressed as "no mutation needed," which
/// is also, deliberately, exactly what an exact-required field reports
/// once it genuinely already matches -- a caller cannot tell "nothing to
/// verify here" from "verified and it matches" from this return value
/// alone, and does not need to: either way, this field never blocks
/// `ExactObject` completion on this platform.
#[cfg(not(unix))]
pub fn unix_mode_already_matches_disk(
    _path: &Path,
    _unix_mode: Option<u32>,
) -> Result<bool, StorageError> {
    Ok(true)
}

/// Whether [`apply_xattrs`] would need to perform any real
/// `fsetxattr`/`fremovexattr` syscall for `path` given the desired
/// `xattrs` -- the xattr counterpart of `unix_mode_already_matches_disk`,
/// for the same reason. Reuses `chunker::read_replicated_xattrs`, the same
/// read side `apply_xattrs` itself is the write-side counterpart to, so
/// the two can never disagree about which names/values are "replicated"
/// ones.
#[cfg(target_os = "linux")]
pub fn xattrs_already_match_disk(
    path: &Path,
    xattrs: &[(String, Vec<u8>)],
) -> Result<bool, StorageError> {
    let file = fs::File::open(path)?;
    let mut current = crate::chunker::read_replicated_xattrs(&file);
    let mut desired = xattrs.to_vec();
    current.sort();
    desired.sort();
    Ok(current == desired)
}

/// See the `#[cfg(target_os = "linux")]` `xattrs_already_match_disk` above
/// -- `apply_xattrs` is already a no-op off Linux, so it never needs a
/// fence bump either.
#[cfg(not(target_os = "linux"))]
pub fn xattrs_already_match_disk(
    _path: &Path,
    _xattrs: &[(String, Vec<u8>)],
) -> Result<bool, StorageError> {
    Ok(true)
}

/// The `ExactObject` proof gate: whether `path`'s on-disk replicated
/// extended attributes exactly equal `desired`, verified strictly. This
/// is NOT `xattrs_already_match_disk` -- that function exists only to
/// choose snapshot-vs-bump before any mutation and reuses
/// `read_replicated_xattrs`'s best-effort reader, which silently folds a
/// real enumeration/read failure into "no attributes" (fine for deciding
/// whether a mutating syscall is needed, since falling through to
/// actually attempt the syscalls is always safe). An `ExactObject`
/// completion proof has no such fallback available: publishing it means
/// claiming disk demonstrably holds this exact desired version, and
/// `FileVersion`'s content-addressed identity bakes replicated xattr
/// bytes directly into `version_hash` (see `FileVersion::compute_hash`)
/// -- so a caller that cannot actually confirm the attributes match must
/// never be allowed to read that failure as a match.
///
/// Returns `Ok(true)`/`Ok(false)` for a confirmed match/mismatch, and
/// `Err` when this backend cannot even attempt the comparison -- a real
/// I/O failure enumerating or reading an attribute (this Linux arm
/// only; the non-Linux arm below has no replicated-xattr backend to
/// fail reading from in the first place, and always settles as
/// retained-only -- see its own doc comment). Every caller gating
/// `SettlementEvidence::ExactObject` on this Linux arm's `Err` must
/// treat it exactly like `Ok(false)`: leave the obligation outstanding
/// for retry, never propagate it as a hard failure of the write itself
/// (the content and any other metadata this call's caller already
/// applied are still genuinely on disk).
///
/// `path` is opened with ordinary, symlink-following semantics -- correct
/// (and required, to still catch a genuine stale attribute) for a
/// `RecordKind::File` whose `desired` may legitimately be empty, but
/// wrong for a symlink or directory path, which `FileMeta::xattrs`'s own
/// doc says is never scanned at all (always an empty `desired`) and
/// which may not even have a followable target (a dangling symlink is
/// perfectly valid). Callers must only invoke this for `RecordKind::
/// File`; skip it entirely for every other kind rather than passing an
/// empty `desired` and relying on this function to no-op.
#[cfg(target_os = "linux")]
pub fn verify_replicated_xattrs_exact(
    path: &Path,
    desired: &[(String, Vec<u8>)],
) -> Result<bool, StorageError> {
    let file = fs::File::open(path)?;
    let mut current = crate::chunker::read_replicated_xattrs_strict(&file)?;
    let mut desired = desired.to_vec();
    current.sort();
    desired.sort();
    Ok(current == desired)
}

/// Off Linux, replicated-xattr support does not exist at all (see
/// `apply_xattrs`'s own non-Linux stub, which never writes anything).
///
/// Design decision (target projection contract, see `SettlementEvidence::
/// ExactObject`'s own doc comment for the full model): a version's
/// `xattrs` stay part of its authoritative logical identity
/// (`VersionHash`) everywhere, but whether they are a REQUIRED-exact
/// projection field or a RETAINED-only one (present in the logical
/// version, but this target is never asked to physically reproduce it)
/// is target-specific. On a backend with no replicated-xattr support at
/// all, xattrs are always retained-only -- exactly the same "this
/// target cannot represent it, so completion does not wait on it"
/// treatment `unix_mode_already_matches_disk`'s own non-Unix arm already
/// gives `unix_mode`. An earlier version of this function treated a
/// nonempty desired set as permanently unrepresentable and refused to
/// ever settle -- correct under the OLD "ExactObject means literal
/// field-for-field equality" model, but wrong under this one: it left a
/// path with any replicated attribute permanently un-completable on any
/// non-Linux target, for a field this target was never expected to
/// physically reproduce in the first place.
#[cfg(not(target_os = "linux"))]
pub fn verify_replicated_xattrs_exact(
    _path: &Path,
    _desired: &[(String, Vec<u8>)],
) -> Result<bool, StorageError> {
    Ok(true)
}

/// Sets the replicated permission bits (`REPLICATED_MODE_MASK`,
/// owner/group/other read-write-execute) on an already-materialized file.
/// `None` -- the authoring version carries no Unix permission info, i.e. it
/// was authored on a platform with no Unix mode model -- is a deliberate
/// no-op: this device does not fabricate a mode for a peer that never had
/// one, it leaves whatever mode the write already produced (the process's
/// own umask-derived default). Only the low 9 permission bits are ever
/// touched; any higher bits (file type, setuid/setgid/sticky) already on
/// disk are preserved untouched. A no-op on any non-Unix platform (Windows
/// has no equivalent permission-bits model, so this must be silent there,
/// not an error).
#[cfg(unix)]
pub fn apply_unix_mode(path: &Path, unix_mode: Option<u32>) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    const PERMISSION_BITS: u32 = 0o777;
    let Some(unix_mode) = unix_mode else {
        return Ok(());
    };
    let metadata = fs::metadata(path)?;
    let mut perms = metadata.permissions();
    let mode = perms.mode();
    let new_mode = (mode & !PERMISSION_BITS) | (unix_mode & PERMISSION_BITS);
    if new_mode != mode {
        perms.set_mode(new_mode);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// See the `#[cfg(unix)]` `apply_unix_mode` above — the no-op
/// Windows/other-platform counterpart needed for cross-platform parity.
/// `unix_mode` is retained-only, not exact-required, on a non-Unix
/// target -- see `unix_mode_already_matches_disk`'s own non-Unix arm and
/// `SettlementEvidence::ExactObject`'s doc comment for the full model.
#[cfg(not(unix))]
pub fn apply_unix_mode(_path: &Path, _unix_mode: Option<u32>) -> Result<(), StorageError> {
    Ok(())
}

/// Sets an already-materialized regular file's replicated extended
/// attributes (Competitive Hardening C1.2a) to exactly `xattrs` — the
/// write-side counterpart to `chunker::read_replicated_xattrs`. Scoped to
/// the same `user.*` allow-list the read side captures under: only names
/// in that namespace are ever set or removed here, so an attribute this
/// device's capture path was never allowed to read is never touched by
/// materialization either, mirroring `apply_unix_mode`'s "only the bits we
/// replicate" discipline. An attribute already on disk under `user.*` but
/// absent from `xattrs` is removed (a fresh temp-then-rename target
/// normally carries none, but this keeps a re-materialized path from
/// accumulating stale attributes from an earlier, different version at the
/// same path). Best-effort: a failure to set or remove one attribute (e.g.
/// a filesystem with no xattr support) is silently skipped, matching
/// `read_replicated_xattrs`'s own "no attributes" fallback rather than
/// failing the whole materialization over metadata that was never
/// content-integrity-critical to begin with.
#[cfg(target_os = "linux")]
const LINUX_ALLOWED_XATTR_PREFIX: &str = "user.";

/// Whether `name` is inside the one extended-attribute namespace this
/// sync tool ever replicates on Linux -- the single predicate
/// `apply_xattrs` uses on BOTH its set and remove sides, so the two can
/// never disagree about which names are "replicated" ones. Factored out
/// so it is directly unit-testable without needing a real filesystem or
/// real syscalls at all (setting a genuinely privileged namespace like
/// `trusted.*`/`security.*` to prove a filter caught it would require
/// root in the first place, which would prove nothing about this
/// specific code path).
#[cfg(target_os = "linux")]
fn is_replicated_xattr_name(name: &str) -> bool {
    name.starts_with(LINUX_ALLOWED_XATTR_PREFIX)
}

#[cfg(target_os = "linux")]
pub fn apply_xattrs(path: &Path, xattrs: &[(String, Vec<u8>)]) -> Result<(), StorageError> {
    use std::os::unix::io::AsRawFd;

    let file = fs::File::open(path)?;
    let fd = file.as_raw_fd();

    let existing = crate::chunker::list_xattr_names_for_apply(fd)
        .into_iter()
        .filter(|name| is_replicated_xattr_name(name));
    for name in existing {
        if !xattrs.iter().any(|(n, _)| n == &name) {
            if let Ok(c_name) = std::ffi::CString::new(name) {
                unsafe { libc::fremovexattr(fd, c_name.as_ptr()) };
            }
        }
    }
    // Defense in depth, independent of `FileMeta::decode`'s own
    // allow-list rejection: this is the last point before a real
    // `fsetxattr` syscall, so a non-allow-listed name must never reach
    // it regardless of how it got here (a future caller that builds
    // `xattrs` some other way, a decode check that regresses). Silently
    // dropped, not an error -- exactly how every other best-effort
    // outcome in this function is already handled.
    for (name, value) in xattrs.iter().filter(|(name, _)| is_replicated_xattr_name(name)) {
        if let Ok(c_name) = std::ffi::CString::new(name.as_str()) {
            unsafe {
                libc::fsetxattr(
                    fd,
                    c_name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    0,
                )
            };
        }
    }
    Ok(())
}

/// See the `#[cfg(target_os = "linux")]` `apply_xattrs` above — every other
/// platform's read side (`read_replicated_xattrs`) never captures anything,
/// so there is nothing this device would ever need to write back; kept as
/// an explicit no-op for cross-platform parity rather than `#[cfg]`-hiding
/// the call sites.
#[cfg(not(target_os = "linux"))]
pub fn apply_xattrs(_path: &Path, _xattrs: &[(String, Vec<u8>)]) -> Result<(), StorageError> {
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

    /// C4-6: `reconstruct_file_to_temp` + `persist_reconstructed_file` must
    /// together produce exactly what the composed `reconstruct_file` always
    /// did -- and, critically, the temp-write half alone must never touch
    /// `out_path` at all, since a caller batching several paths' SQLite
    /// commits relies on being able to run this half for many paths without
    /// any of them becoming visible until the (separate, later) publish
    /// half runs.
    #[test]
    fn reconstruct_file_to_temp_then_persist_matches_reconstruct_file() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = crate::FsBlockStore::new(store_dir.path()).unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = src_dir.path().join("file.bin");
        let content: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        fs::write(&src_path, &content).unwrap();
        let blocks = crate::chunker::chunk_file(&store, &src_path).unwrap();

        let out_path = src_dir.path().join("reconstructed.bin");
        let tmp_path = reconstruct_file_to_temp(&store, &out_path, &blocks, -1).unwrap();

        assert!(!out_path.exists(), "the temp-write half must not touch out_path at all");
        assert!(tmp_path.exists());
        assert_eq!(fs::read(&tmp_path).unwrap(), content);

        persist_reconstructed_file(&tmp_path, &out_path).unwrap();

        assert!(!tmp_path.exists(), "the temp path must be gone after a successful publish");
        assert_eq!(fs::read(&out_path).unwrap(), content);
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

    /// M2-3a: on Windows, `create_or_defer_placeholder` must write NOTHING
    /// to disk -- the real reparse-point placeholder is created later by
    /// `cfapi-host.exe`'s own poll, which `write_placeholder`'s prior
    /// unconditional sparse-file write would have pre-empted (that write
    /// made `full_path.exists()` true, and `sync_placeholders` skips any
    /// path that already exists).
    #[test]
    #[cfg(windows)]
    fn windows_create_or_defer_placeholder_writes_nothing_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("placeholder.bin");

        let outcome = create_or_defer_placeholder(&out_path, 5_000_000, 0).unwrap();

        assert!(!out_path.exists(), "Windows must defer creation to cfapi-host, not pre-empt it");
        assert!(matches!(
            outcome,
            PlaceholderIdentityToRecord::RecordIfAbsent {
                provider_kind: WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
                ..
            }
        ));
    }

    /// The old bug this closes: `write_placeholder` returning `None` on
    /// Windows made every caller call `clear_placeholder_generation`,
    /// discarding any generation. `create_or_defer_placeholder` must always
    /// return `RecordIfAbsent`, never `Clear`, on Windows. It must also
    /// never return `RecordOverwrite` -- an unconditional overwrite would
    /// reintroduce the exact race this shape exists to prevent (see
    /// `PlaceholderIdentityToRecord`'s own doc comment).
    #[test]
    #[cfg(windows)]
    fn windows_create_or_defer_placeholder_never_clears() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("placeholder.bin");

        let outcome = create_or_defer_placeholder(&out_path, 100, 0).unwrap();

        assert!(matches!(outcome, PlaceholderIdentityToRecord::RecordIfAbsent { .. }));
    }

    /// Mirrors `successive_placeholder_writes_to_the_same_path_mint_
    /// different_identities` for the Windows path: a re-create at the same
    /// path (an evict immediately followed by a re-materialize) must not
    /// reuse a stale generation a live CfAPI comparison could mistake for
    /// the OLD placeholder still being untouched.
    #[test]
    #[cfg(windows)]
    fn windows_successive_defers_at_the_same_path_mint_different_generations() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("placeholder.bin");

        let first = create_or_defer_placeholder(&out_path, 100, 0).unwrap();
        let second = create_or_defer_placeholder(&out_path, 100, 0).unwrap();

        assert_ne!(first, second, "a re-deferred placeholder must mint a fresh generation");
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

    #[test]
    fn stamp_mtime_at_path_actually_changes_disk_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.txt");
        fs::write(&path, b"content").unwrap();
        let desired = 1_700_000_123_456_789i64;

        assert!(!mtime_already_matches_disk(&path, desired).unwrap());
        stamp_mtime_at_path(&path, desired).unwrap();
        assert!(mtime_already_matches_disk(&path, desired).unwrap());
    }

    /// A negative `desired_mtime_unix_nanos` (the "no authoritative
    /// mtime to stamp" sentinel) is trivially satisfied regardless of
    /// whatever the disk actually holds -- there is nothing to compare
    /// against, mirroring `unix_mode_already_matches_disk`'s own
    /// `unix_mode: None` treatment.
    #[test]
    fn mtime_already_matches_disk_is_trivially_true_for_a_negative_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.txt");
        fs::write(&path, b"content").unwrap();
        assert!(mtime_already_matches_disk(&path, -1).unwrap());
    }

    /// Changing the requested mode actually changes the on-disk permission
    /// bits, and is idempotent (calling it again with the same value
    /// doesn't error or otherwise misbehave). `None` is a deliberate no-op
    /// — never fabricates a mode for a version that carries none.
    #[cfg(unix)]
    #[test]
    fn apply_unix_mode_sets_and_clears_permission_bits() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("script.sh");
        fs::write(&path, b"#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        apply_unix_mode(&path, Some(0o744)).unwrap();
        let mode_after_set = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode_after_set & 0o777, 0o744, "owner-exec bit must be set");

        // Idempotent: setting it again when already set is a harmless no-op.
        apply_unix_mode(&path, Some(0o744)).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o744);

        apply_unix_mode(&path, Some(0o644)).unwrap();
        let mode_after_clear = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode_after_clear & 0o777, 0o644, "owner-exec bit must be cleared");

        // `None` is a no-op — the mode from the last real apply survives.
        apply_unix_mode(&path, None).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);
    }

    /// `apply_unix_mode` must never error on a plain file — this
    /// runs unconditionally (not `#[cfg(unix)]`-gated) so the non-Unix
    /// no-op arm is at least compiled and exercised on every platform this
    /// crate builds for; on this dev machine it's the `#[cfg(unix)]`-arm's
    /// real permission-changing behavior above that's exercised.
    #[test]
    fn apply_unix_mode_never_errors_on_a_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.txt");
        fs::write(&path, b"hello").unwrap();
        apply_unix_mode(&path, Some(0o755)).unwrap();
        apply_unix_mode(&path, None).unwrap();
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

    /// `apply_xattrs` must both set every attribute in the supplied list
    /// AND remove any `user.*` attribute already on disk that the list no
    /// longer carries -- the same "set exactly what's replicated, nothing
    /// left over from a prior version" contract `apply_unix_mode` gives
    /// for permission bits.
    #[cfg(target_os = "linux")]
    #[test]
    fn apply_xattrs_sets_new_attributes_and_removes_stale_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        fs::write(&path, b"content").unwrap();

        apply_xattrs(&path, &[("user.keep".to_string(), b"v1".to_vec())]).unwrap();
        assert_eq!(
            crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()),
            vec![("user.keep".to_string(), b"v1".to_vec())]
        );

        // A later version drops "user.keep" and adds "user.new" -- the
        // stale attribute must not survive the second call.
        apply_xattrs(&path, &[("user.new".to_string(), b"v2".to_vec())]).unwrap();
        assert_eq!(
            crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()),
            vec![("user.new".to_string(), b"v2".to_vec())]
        );
    }

    /// An empty attribute list is a real, meaningful target state (this
    /// version genuinely carries no extended attributes) -- confirms it
    /// clears whatever was already on disk rather than being silently
    /// treated as "nothing to do."
    #[cfg(target_os = "linux")]
    #[test]
    fn apply_xattrs_with_an_empty_list_clears_existing_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        fs::write(&path, b"content").unwrap();

        apply_xattrs(&path, &[("user.gone".to_string(), b"v".to_vec())]).unwrap();
        apply_xattrs(&path, &[]).unwrap();

        assert_eq!(crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()), Vec::new());
    }

    /// Regression for an independent review's finding: `apply_xattrs`'s
    /// own removal side already restricted itself to `user.*`, but its
    /// set side handed every incoming name straight to `fsetxattr`
    /// unconditionally -- defense-in-depth for the same allow-list
    /// `FileMeta::decode` now rejects a violation of at the wire-decode
    /// boundary (a second, independent layer, in case some future caller
    /// ever builds an `xattrs` list some other way). Confirmed genuinely
    /// RED by temporarily hardcoding this to `true` for every name: it no
    /// longer distinguished the allow-listed namespace from any other.
    #[cfg(target_os = "linux")]
    #[test]
    fn is_replicated_xattr_name_only_accepts_the_user_namespace() {
        assert!(is_replicated_xattr_name("user.foo"));
        assert!(!is_replicated_xattr_name("security.selinux"));
        assert!(!is_replicated_xattr_name("trusted.overlay"));
        assert!(!is_replicated_xattr_name("system.posix_acl_access"));
        assert!(!is_replicated_xattr_name("com.apple.quarantine"));
    }

    /// The `ExactObject` proof gate's positive case: an attribute set
    /// genuinely applied end to end verifies as an exact match.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_replicated_xattrs_exact_confirms_a_genuine_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        fs::write(&path, b"content").unwrap();
        let desired = vec![("user.a".to_string(), b"1".to_vec())];

        apply_xattrs(&path, &desired).unwrap();

        assert!(verify_replicated_xattrs_exact(&path, &desired).unwrap());
    }

    /// Regression for the exact gap an independent review caught: a
    /// desired attribute that never actually landed on disk (standing in
    /// for `apply_xattrs`'s own `fsetxattr` silently failing, which it
    /// never surfaces as an `Err`) must never verify as an exact match.
    /// Confirmed genuinely RED by temporarily hardcoding this function's
    /// comparison to `true`: the mismatch below went undetected.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_replicated_xattrs_exact_detects_an_attribute_that_never_landed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        fs::write(&path, b"content").unwrap();
        let desired = vec![("user.missing".to_string(), b"1".to_vec())];

        // No `apply_xattrs` call at all -- disk carries none of what is
        // desired, exactly what a silently-swallowed `fsetxattr` failure
        // would also leave behind.

        assert!(!verify_replicated_xattrs_exact(&path, &desired).unwrap());
    }

    /// The mirror case: a stale attribute still on disk that the desired
    /// version no longer carries (standing in for `apply_xattrs`'s
    /// `fremovexattr` silently failing) must also never verify as exact.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_replicated_xattrs_exact_detects_a_stale_attribute_that_should_be_gone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        fs::write(&path, b"content").unwrap();

        apply_xattrs(&path, &[("user.stale".to_string(), b"v".to_vec())]).unwrap();
        // The version this file is meant to now exactly hold desires no
        // attributes at all -- as if `apply_xattrs(&path, &[])`'s own
        // `fremovexattr` call for "user.stale" had silently failed.

        assert!(!verify_replicated_xattrs_exact(&path, &[]).unwrap());
    }

    /// A same-name attribute whose VALUE differs must also fail exactness
    /// -- name-only comparison would wrongly accept this.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_replicated_xattrs_exact_detects_a_value_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        fs::write(&path, b"content").unwrap();

        apply_xattrs(&path, &[("user.a".to_string(), b"old".to_vec())]).unwrap();

        assert!(
            !verify_replicated_xattrs_exact(&path, &[("user.a".to_string(), b"new".to_vec())])
                .unwrap()
        );
    }

    // The non-Linux `verify_replicated_xattrs_exact` arm (always
    // `Ok(true)`, unconditionally treating xattrs as retained-only on a
    // backend with no replicated-xattr support -- see its own doc
    // comment for the target-projection-contract reasoning) is `#[cfg(not(
    // target_os = "linux"))]`, so it never compiles on the Linux machines
    // this workspace is actually developed/tested on and has no dedicated
    // test here; it is now a single unconditional return with no branch
    // left to exercise.
}
