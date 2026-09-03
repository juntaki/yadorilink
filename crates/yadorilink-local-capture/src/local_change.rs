//! Bridges a raw filesystem event into an indexed,
//! chunked `FileRecord`. Local changes are always
//! indexed immediately regardless of the link's pause state — pausing
//! only stops *propagating* changes to peers, so nothing is
//! lost while paused; the local index itself is the queued-change backlog.
//!
//! The property that renaming a file doesn't re-transfer content falls out of this
//! design for free: chunking is content-addressed, so renaming a file
//! without editing it re-derives the exact same block hashes the local
//! store (and any peer that already synced the old path) already holds —
//! `ensure_blocks_present`'s dedup check means no bytes cross the network
//! for the unchanged content, even though the wire protocol has no
//! dedicated "rename" message.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::LocalCaptureError;
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_local_storage::{
    chunk_file, chunk_file_content_defined, read_replicated_xattrs, unix_mode_from_metadata,
    CDC_SIZE_THRESHOLD,
};
use yadorilink_replica_domain::change::{encoded_op_len, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{BlockHash, SyncPath};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_domain::session_state::{ChangeContent, LocalFileMetaColumns};
use yadorilink_root_authority::fs_identity::FileIdentity;
use yadorilink_root_authority::ignore_patterns::{
    is_ignore_file_relative_path, EffectiveIgnoreSet,
};
use yadorilink_root_authority::reserved_namespace::path_has_reserved_component;
use yadorilink_root_authority::root_identity::{is_root_marker_relative_path, VerifiedRoot};
use yadorilink_root_authority::sync_root_lock::is_sync_root_lock_relative_path;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;
use yadorilink_sync_sqlite::SyncSqliteError;

/// Same shape as this crate's other private `now_unix_nanos` helpers —
/// the default `process_event_with_ignore_at`'s `Removed` branch falls
/// back to when the caller has no better (debounce-observed) timestamp
/// to supply.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Duplicated from `yadorilink_peer_session::peer_session::disk_race_
/// fingerprint` rather than depending on that crate from production code
/// solely for this one function -- that dependency is dev-only here, same
/// "duplicate small leaf logic rather than force an awkward dependency"
/// precedent this session's own `MaterializedFingerprint` type alias
/// duplication (peer-session/filesystem-sync/here) already established.
/// See `record_local_commit_fingerprints`'s own doc comment for what this
/// is used for.
fn disk_race_fingerprint(path: &Path) -> Option<(u64, Option<std::time::SystemTime>, i64, i64)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    let (ctime, ctime_nsec) = {
        use std::os::unix::fs::MetadataExt as _;
        (meta.ctime(), meta.ctime_nsec())
    };
    #[cfg(not(unix))]
    let (ctime, ctime_nsec) = (0i64, 0i64);
    Some((meta.len(), meta.modified().ok(), ctime, ctime_nsec))
}

/// A strong `FileIdentity` for `path`, freshly observed, but ONLY if
/// `disk_race_fingerprint(path)` still matches `fingerprint_before_read`
/// (a fingerprint captured before this event's own content was read) --
/// `None` for either a fingerprint mismatch (something touched this path
/// during the read/prepare window) or a failed observation. Feeds
/// `LocalMutationStore::upsert_file_emitting_change`'s `filesystem_identity`
/// parameter: `None` here always means "publish no actual-state proof for
/// this commit," never a hard failure of the capture itself -- see that
/// parameter's own doc comment. This is deliberately a SEPARATE, later
/// stat than `fingerprint_before_read` itself: closing the race requires
/// two independent observations bracketing the read, not reusing one.
fn fresh_actual_state_identity_if_unraced(
    path: &Path,
    fingerprint_before_read: Option<(u64, Option<std::time::SystemTime>, i64, i64)>,
) -> Option<FileIdentity> {
    if fingerprint_before_read.is_none() {
        return None;
    }
    if disk_race_fingerprint(path) != fingerprint_before_read {
        return None;
    }
    FileIdentity::observe_path(path).ok()
}

/// True when a filesystem `Metadata`'s mtime equals the mtime an index row
/// recorded (`FileRecord::mtime_unix_nanos`, stored as nanoseconds since the
/// Unix epoch). Deriving this in one place keeps the "unchanged file" verdict
/// identical no matter which path reaches it: the per-file fast path
/// (`build_record_for_created_or_modified`) and the bulk startup/offline
/// reconcile scan (`reconcile_disk_with_ignore`) MUST agree, or a same-size
/// edit one path treats as a no-op the other would silently keep at the stale
/// version.
fn metadata_mtime_matches(metadata: &std::fs::Metadata, indexed_mtime_unix_nanos: i64) -> bool {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        == Some(indexed_mtime_unix_nanos)
}

/// Whether the on-disk object `lstat` describes is still proven to be this
/// crate's own untouched placeholder, for the `MaterializationState::
/// Placeholder` fast path in `build_record_for_created_or_modified`. On
/// Unix, this requires BOTH: a `(dev, ino)` identity match against
/// `placeholder_generation` (M1-2), AND the object still being sparse (no
/// allocated data blocks) -- see that call site's own doc comment for why
/// this replaces the old size/mtime/sparse-file heuristic there.
///
/// Identity alone is not sufficient -- an independent review's finding: a
/// genuine in-place edit (a `truncate`+`write` that reuses the same file
/// descriptor/inode rather than an atomic rename, or an `mmap` write) keeps
/// the SAME inode while genuinely changing the file's bytes. The OLD
/// heuristic caught this case (real content allocates disk blocks, so the
/// sparse-file check alone already said "not untouched") even though it
/// missed the atomic-rename-preserving-size/mtime case this file's own
/// identity check exists to close. Requiring both keeps the union of what
/// each signal alone catches: identity closes the atomic-rename gap,
/// sparseness closes the in-place-edit gap.
#[cfg(unix)]
fn untouched_placeholder_verdict(
    _store: &dyn crate::ports::LocalMutationStore,
    _path: &Path,
    lstat: &std::fs::Metadata,
    existing: Option<&FileRecord>,
    placeholder_generation: Option<&yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    if let Some(recorded) = placeholder_generation {
        return recorded.provider_kind == yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND
            && yadorilink_local_storage::PlaceholderDiskIdentity::from_metadata(lstat)
                == Some(recorded.identity)
            && lstat.blocks() == 0;
    }
    // Defense in depth -- an independent review's finding on M1-5's own
    // startup repair pass (`materialization_repair::
    // backfill_placeholder_generations`): persisting an identity is not
    // atomic with `write_placeholder`'s own disk write (a crash between
    // the two, or the repair pass itself failing for this one path,
    // leaves no identity recorded even though the placeholder is
    // genuinely untouched). Falling through unconditionally whenever no
    // identity is recorded would chunk and index the placeholder's own
    // sparse/all-zero bytes as if real content on every such path --
    // exactly the corruption this whole mechanism exists to prevent, and
    // it would keep happening for as long as backfill keeps failing for
    // that path.
    //
    // A completely unallocated object at EXACTLY the indexed size, with
    // no identity to compare against, is still overwhelming evidence
    // this is still the crate's own untouched placeholder: no ordinary
    // editor or real edit leaves a file fully sparse. This closes the
    // gap independent of the backfill pass's own success -- it is not a
    // substitute for identity tracking (a same-size in-place edit that
    // preserves sparseness, or a deliberately-crafted same-size sparse
    // replacement, are both still missed -- the same class of residual
    // gap the size/mtime-only heuristic always had), only a narrower,
    // still-safe fallback for the one case identity tracking cannot
    // currently guarantee it has closed.
    existing.is_some_and(|record| lstat.len() == record.size) && lstat.blocks() == 0
}

/// M2-2: on Windows, this is the ONLY signal permitted to produce
/// `true` -- a live query against the real CfAPI placeholder at `path`
/// (`LocalMutationStore::inspect_windows_placeholder`, which in
/// production calls `CfGetPlaceholderInfo`/`CfGetPlaceholderStateFromFileInfo`
/// via `yadorilink-daemon::placeholder_inspect_windows`). No size/mtime
/// comparison anywhere in this function -- the fallback this replaced
/// (plain `lstat.len() == record.size && mtime matches`) is exactly the
/// heuristic this whole mechanism exists to stop relying on (see this
/// module's own top-level doc and the `#[cfg(unix)]` overload above for
/// the residual gap a size/mtime-only check always had: an in-place edit
/// that happens to land on the same size and mtime was invisible to it).
///
/// Two independent fail-closed gates, either of which alone forces
/// `false` (never silently treated as untouched):
/// - No `placeholder_generation` recorded at all, or its `provider_kind`
///   isn't [`yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND`]
///   (a legacy/pre-M2 row, or one this build's `record_placeholder_generation`
///   call site hasn't reached yet) -- there is nothing to compare against,
///   so this cannot possibly be proven untouched.
/// - `inspect_windows_placeholder` returns anything other than
///   [`yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus::Untouched`]
///   -- `Dirty` is an honest "this was locally written since creation",
///   and `Unknown` (the path isn't a real placeholder, the identity
///   doesn't decode, the API call itself failed) is deliberately treated
///   exactly like `Dirty`, never like a confirmed match.
#[cfg(windows)]
fn untouched_placeholder_verdict(
    store: &dyn crate::ports::LocalMutationStore,
    path: &Path,
    _lstat: &std::fs::Metadata,
    _existing: Option<&FileRecord>,
    placeholder_generation: Option<&yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
) -> bool {
    let Some(recorded) = placeholder_generation else {
        return false;
    };
    if recorded.provider_kind != yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND {
        return false;
    }
    // `dev` is always `0` (an unused sentinel) for this provider kind;
    // `ino` carries the actual `u64` generation -- see
    // `WINDOWS_CFAPI_GENERATION_PROVIDER_KIND`'s own doc comment for why
    // this reuses `PlaceholderDiskIdentity`'s two-`u64` shape.
    let expected_generation = recorded.identity.ino;
    matches!(
        store.inspect_windows_placeholder(path, expected_generation),
        yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus::Untouched
    )
}

/// True when `rel_path` (a root-relative index path, `/`-separated) sits
/// under any of the `failed_prefixes` a partial scan collected — the
/// root-relative directories the walk could not read. Matching is on whole
/// path components (`Path::starts_with`), so `foo` matches `foo/bar` but not
/// `foobar`; an empty prefix (the walk root itself failed) matches every
/// path. Used to scope offline-delete tombstone suppression to the failed
/// subtree(s) only, never tombstoning a path whose directory was unreadable.
fn path_is_within_failed_subtree(rel_path: &str, failed_prefixes: &[String]) -> bool {
    let candidate = Path::new(rel_path);
    failed_prefixes.iter().any(|prefix| candidate.starts_with(Path::new(prefix)))
}

/// Whether `path` (root-relative) exists on disk RIGHT NOW as a regular
/// file or symlink, under its OWN exact spelling -- checked by directory-
/// listing the parent and matching the leaf name byte-for-byte, never by
/// resolving the full path directly (`std::fs::symlink_metadata`/
/// `exists`). A direct resolution succeeds on a case- or Unicode-
/// normalization-insensitive filesystem (macOS, Windows) for ANY sibling
/// that happens to fold to the same name, wrongly reporting "still
/// exists" for a path that, under its own exact name, is genuinely gone
/// -- the same case-fold hazard this whole investigation is about, just
/// surfacing in a disk check instead of an index one. Mirrors the main
/// reconciliation walk's own `entry.file_type()` admission predicate too
/// (`is_file() || is_symlink()`, from `lstat`, never following a
/// symlink): a directory (or fifo/socket/device) now occupying this exact
/// name is not "the file still exists" any more than it was during the
/// walk itself, which would have skipped it the same way -- an indexed
/// file silently replaced offline by one of those must still be
/// tombstoned, not permanently spared because *something* now answers to
/// its name.
fn exact_leaf_exists_as_file_or_symlink(root: &Path, path: &str) -> bool {
    let full = root.join(path);
    let (Some(leaf), Some(parent)) =
        (full.file_name().map(|n| n.to_os_string()), full.parent().map(|p| p.to_path_buf()))
    else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(&parent) else { return false };
    entries.filter_map(|e| e.ok()).any(|entry| {
        entry.file_name() == leaf
            && entry.file_type().is_ok_and(|ft| ft.is_file() || ft.is_symlink())
    })
}

/// [`build_record_for_created_or_modified`]'s Unix-mode-to-persist output:
/// the outer `None` means nothing to persist (a symlink, or nothing
/// changed); the inner `Option<u32>` is `unix_mode_from_metadata`'s own
/// value (itself `None` on a platform with no Unix permission-bits model).
type PendingUnixModeUpdate = Option<Option<u32>>;

/// What one filesystem event turned out to mean, once interpreted —
/// `process_event`'s result.
#[derive(Debug, Clone, PartialEq)]
pub enum LocalChangeOutcome {
    /// Nothing worth acting on: a directory event, a file that vanished
    /// again before it could be read, a placeholder's own write, or
    /// content that hashed identical to what was already indexed.
    None,
    /// An ordinary file was created, modified, or deleted.
    FileChanged(FileRecord),
    /// A `Removed` event for a path with no index row of its own
    /// (directories are never tracked as their own row — see
    /// `build_record_for_created_or_modified`'s doc comment) turned out
    /// to have live child records still indexed underneath it as a
    /// directory prefix (i.e. `path` used to be a directory that was
    /// deleted, or renamed away, and this device never
    /// received/synthesized an individual event for each child inside
    /// it — see `watcher.rs`'s `RenameMode::From` handling). Every such
    /// child has now been tombstoned; each is reported here so the
    /// caller broadcasts all of them, not just one.
    FilesChanged(Vec<FileRecord>),
}

/// `process_event_with_ignore_at`'s outcome once batching exists: either
/// the event was fully classified and its mutation committed synchronously,
/// exactly as this function always behaved before batching (`Ready` --
/// what every caller other than the `DebounceFlush::Paths` loop always
/// gets, since they pass `pending_batch: None`), or the simple,
/// DAG-emitting create/modify/delete case applied and a mutation was
/// prepared and pushed onto `pending_batch` instead of being committed
/// here (`Deferred`) -- only the `DebounceFlush::Paths` loop ever sees
/// this, and it alone is responsible for resolving every `Deferred` path
/// once its batch's `flush_pending_batch` call runs.
#[derive(Debug)]
enum EventOutcome {
    Ready(LocalChangeOutcome),
    Deferred,
}

/// One path's authoritative mutation, prepared during a batched flush's
/// per-path pass (chunked, hashed, and decided against the state read at
/// that moment) but not yet committed, together with everything
/// `flush_pending_batch` needs to prove it is still current before
/// including it in the shared transaction: the disk identity and index row
/// this preparation was based on, so a change to either between
/// preparation and commit excludes this mutation from the batch rather
/// than authoring stale bytes or clobbering a concurrent peer update (see
/// `flush_pending_batch`'s own doc for the full argument -- this is the
/// SAME `disk_race_fingerprint` scheme `peer_session::PeerSyncSession::
/// hydrate_inner` already relies on for the identical class of "is what I
/// prepared still current" question, applied here to local capture instead
/// of peer materialization).
struct PendingBatchedCommit {
    rel_path: String,
    event_path: PathBuf,
    observed_at_unix_nanos: i64,
    index_state_at_prepare: Option<FileRecord>,
    // A `FileRecord` comparison alone cannot catch a peer commit whose new
    // version's size/mtime/blocks happen to coincide with the old one (a
    // metadata-only change, or content that happens to hash the same) --
    // see `LocalMutationStore::get_authoring_change_hash`'s own doc for why
    // this is compared too.
    authoring_change_hash_at_prepare: Option<yadorilink_replica_domain::ids::ChangeHash>,
    disk_fingerprint_at_prepare: Option<(u64, Option<std::time::SystemTime>, i64, i64)>,
    mutation: yadorilink_replica_domain::session_state::PreparedLocalMutation,
}

/// Extra classification produced when `build_record_for_created_or_modified`
/// determines a path is a symlink — carried
/// alongside, not inside, the `FileRecord` it returns. Like
/// `types::RecordKind` itself (see its doc comment), this is index-local
/// metadata surfaced through dedicated `LocalMutationStore` columns
/// (`set_record_kind`/`set_symlink_target`/`set_symlink_out_of_root`)
/// rather than a `FileRecord` field, so every existing `FileRecord {.. }`
/// construction site keeps compiling unchanged. The caller applies it via
/// `LocalChangeProcessor::apply_symlink_classification` immediately after
/// writing the `FileRecord` itself (`upsert_file`/`upsert_files_batch`),
/// since those setters require the row to already exist.
#[derive(Debug, Clone, PartialEq)]
struct SymlinkClassification {
    /// The raw, unresolved target bytes exactly as returned by
    /// `std::fs::read_link` — never dereferenced. Platform-native bytes, not
    /// a lossy UTF-8 conversion of them — see `fs_identity::target_to_bytes`
    /// (which this is built with) and `change::FileMeta::symlink_target`'s
    /// doc for why: a symlink target is not required to be valid UTF-8, and
    /// converting it lossily would make the restored symlink a different
    /// symlink from the one that was captured.
    target: Vec<u8>,
    /// `true` when the target is an absolute path, or —
    /// resolved syntactically (never touching the filesystem) against the
    /// symlink's own parent directory — lands outside the linked folder's
    /// root.
    out_of_root: bool,
}

/// Builds the local index metadata columns for a created/modified record from
/// the same inputs [`LocalChangeProcessor::content_op`] uses to build the
/// record's `FileVersion`, so the two are guaranteed to agree: a symlink's
/// classification produces `RecordKind::Symlink` + its target / out-of-root
/// flag (and no exec bit); a regular file produces `RecordKind::File` + its
/// exec bit (and a cleared symlink target/flag). Threading the result into the
/// emitting transaction (rather than applying it via post-commit setters) is
/// what makes the index row's metadata atomic with the emitted change's
/// `FileVersion`.
fn metadata_columns_for(
    classification: &Option<SymlinkClassification>,
    unix_mode: Option<Option<u32>>,
    xattrs: Vec<(String, Vec<u8>)>,
) -> LocalFileMetaColumns {
    match classification {
        Some(c) => LocalFileMetaColumns {
            record_kind: RecordKind::Symlink,
            symlink_target: Some(c.target.clone()),
            symlink_out_of_root: c.out_of_root,
            unix_mode: None,
            // A symlink is not scanned for xattrs either, for the
            // identical reason `unix_mode` is `None` here -- matches
            // `single_pass_capture.rs`'s own symlink branch.
            xattrs: Vec::new(),
        },
        None => LocalFileMetaColumns {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: unix_mode.flatten(),
            xattrs,
        },
    }
}

pub struct LocalChangeProcessor {
    state: Arc<dyn crate::ports::LocalMutationStore>,
    store: Arc<dyn crate::ports::BlockContentStore>,
    device_id: String,
    /// When set, every accepted local mutation additionally appends a signed
    /// change to the history DAG in the same transaction as its index write.
    /// `None` (the default) preserves the pre-DAG behavior exactly — the
    /// index write happens on its own, no change is emitted — so a build that
    /// hasn't provisioned a signing key is unaffected. The daemon injects the
    /// emitter once the device's signing key is loaded.
    change_emitter: Option<Arc<ChangeEmitter>>,
    /// Required, not optional (unlike `change_emitter`): every one of this
    /// processor's mutation methods admits a `LinkOperation` against this
    /// lease and mints a `RootCommitPermit` from it, held for that
    /// operation's own commit -- see `root_commit::RootLease`'s own doc.
    /// The daemon injects its per-link lease here; tests with no real link
    /// lifecycle use `root_commit::RootLease::for_tests()`.
    root_lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
}

/// Runs one of this module's long synchronous capture passes — a whole-file
/// chunk-and-hash, or a whole-file re-verify against the indexed block
/// hashes — without leaving it holding the tokio worker core it was called
/// on.
///
/// The bound this establishes is on the CORE, not on `f`. On a
/// multi-threaded runtime `block_in_place` moves this worker's core, and
/// every task already queued on it, to a replacement thread *before* `f`
/// starts; the calling thread becomes an ordinary blocking thread for the
/// duration. So no worker core is held for longer than that one handoff,
/// however long `f` itself runs — which matters because these passes are
/// not measured in milliseconds. Chunking, hashing and durably committing a
/// 1 GiB file measures 13-20s; re-verifying one against its indexed hashes
/// is a full sequential read plus a SHA-256 per block. A held core,
/// meanwhile, can't service anything else queued on it -- including this
/// device's own QUIC endpoint driver, which has to run promptly enough to
/// send ACKs and keepalives before quinn's own loss-detection and peer
/// idle timeout react to the silence -- and it is time-to-schedule, not
/// poll turnaround, that decides whether they go out in time.
///
/// `block_in_place` rather than `spawn_blocking`, deliberately, and for the
/// same reason `peer_session::record_materialized_fingerprint_off_runtime`
/// chose it: every pass wrapped here runs inside a *synchronous* fn holding
/// a plain `&LocalChangeProcessor` (never an `Arc<Self>`), reachable from
/// this crate's own synchronous public API (`scan_existing_files` ->
/// `reconcile_disk_with_ignore`). `spawn_blocking` wants a `Send + 'static`
/// closure and an `.await` to join it, and there is no `.await` to be had
/// here without turning that whole public API async. A scoped closure needs
/// neither.
///
/// The runtime guard mirrors `peer_session::record_materialized_
/// fingerprint_off_runtime`, `daemon_state::run_blocking_sweep_offloaded`
/// and `gc::run_sweep_with_grace_cutoff`, and it is load-bearing rather
/// than defensive: `block_in_place` PANICS unless a multi-threaded runtime
/// is current, and these call sites are genuinely reached from a
/// current-thread runtime and from no runtime at all. Where there is no
/// multi-threaded worker to hand off to there is also no worker pool to
/// starve, so the plain synchronous call is already the right answer there,
/// not a degraded one.
///
/// Nesting costs nothing and needs no guarding of its own: tokio only hands
/// off a core this thread actually holds, so reaching here from a thread
/// that has none — a `spawn_blocking` thread (how the daemon runs the whole
/// initial scan), or a thread whose core an outer offload already took (the
/// daemon's flush task wraps all of `process_flush_with_ignore` in its own
/// `block_in_place`) — simply runs `f` in place.
fn run_capture_pass_off_worker<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(not(madsim))]
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(f)
            }
            _ => f(),
        }
    }
    // The deterministic simulator runs a single-threaded runtime whose
    // tokio shim exposes neither `runtime_flavor()` nor `block_in_place` —
    // referring to the latter at all does not even compile there. Always
    // take the plain synchronous path, identical to the `_ =>` branch
    // above.
    #[cfg(madsim)]
    {
        f()
    }
}

/// At or above this size, a "is the on-disk content still exactly what is
/// indexed" re-verification is handed off the calling worker's core by
/// [`disk_bytes_match_indexed_blocks_off_worker`] instead of running in
/// place. Below it the read-and-hash pass is short enough that the handoff
/// would cost more than it saves — and `reconcile_disk_with_ignore` runs
/// this verification once per already-current file across a whole tree, so
/// a per-file handoff there is not free.
///
/// Shares the chunker's own large-file threshold rather than inventing a
/// second notion of "big file": a file large enough to be worth
/// content-defined chunking is exactly a file large enough that a full
/// re-read plus per-block SHA-256 is worth getting off a worker.
const OFF_WORKER_VERIFY_MIN_BYTES: u64 = CDC_SIZE_THRESHOLD;

/// [`yadorilink_local_storage::disk_bytes_match_indexed_blocks`], off the
/// calling tokio worker's core when `size` says the pass is big enough to
/// be worth the handoff — see [`run_capture_pass_off_worker`] for the bound
/// that buys and [`OFF_WORKER_VERIFY_MIN_BYTES`] for the cutoff.
///
/// Identical verdict either way: this only decides which thread the
/// (unchanged) read-and-compare runs on, never what it concludes.
fn disk_bytes_match_indexed_blocks_off_worker(
    path: &Path,
    blocks: &[yadorilink_replica_domain::file::BlockInfo],
    size: u64,
) -> Result<bool, yadorilink_local_storage::StorageError> {
    if size < OFF_WORKER_VERIFY_MIN_BYTES {
        return yadorilink_local_storage::disk_bytes_match_indexed_blocks(path, blocks);
    }
    run_capture_pass_off_worker(|| {
        yadorilink_local_storage::disk_bytes_match_indexed_blocks(path, blocks)
    })
}

/// Max ops in a single reconciliation-emitted change. Matches the initial
/// import's [`yadorilink_replica_domain::change::IMPORT_BATCH_OP_LIMIT`] so a
/// bulk offline diff converts into a chain of same-sized changes whichever
/// path (import or reconcile) first observes it, and stays far under the
/// change decoder's hard [`yadorilink_replica_domain::limits::MAX_OPS`]
/// (65536) per-change ceiling.
const RECONCILE_CHUNK_OP_LIMIT: usize = yadorilink_replica_domain::change::IMPORT_BATCH_OP_LIMIT;

/// Max canonical op-bytes in a single reconciliation-emitted change. A change
/// cannot be wire-split, so one change must fit in one delivered
/// `ChangeBatch` message; the transport rejects any inbound control frame
/// larger than `yadorilink_transport::quic_peer_channel::MAX_CONTROL_FRAME_
/// BYTES` (2 MiB). 256 KiB stays well under that (leaving room for the
/// change's fixed header, parents, and signature, and letting several changes
/// still share one batch message) while a pathological run of long paths — up
/// to `RECONCILE_CHUNK_OP_LIMIT` * ~4 KiB ≈ 4 MiB if bounded by op-count
/// alone — is instead split by this byte cap. At least one op is always taken
/// per chunk, so a single over-cap op (never possible: one op is at most a
/// 4 KiB-ish path plus 37 bytes) could not wedge the loop. Shares
/// [`yadorilink_replica_domain::change::MAX_CHANGE_OP_BYTES`] with the initial import so the two
/// byte bounds can never drift.
const RECONCILE_CHUNK_BYTE_LIMIT: usize = yadorilink_replica_domain::change::MAX_CHANGE_OP_BYTES;

/// How much of a disk-vs-index reconciliation scan is allowed to mutate
/// the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileMode {
    /// The full startup / burst-fallback reconciliation: index new files,
    /// re-version files whose on-disk content changed, drop now-ignored
    /// rows, and tombstone indexed files no longer on disk.
    Full { emit_tombstones: bool },
    /// Add-only: index *only* files present on disk with no existing index
    /// row. Never re-versions a file that already has a row and never
    /// tombstones a row whose path isn't on disk. This is the sole
    /// disk-reconcile shape safe to run on a frequent, unconditional
    /// schedule (the periodic backstop for OS-watcher event loss): a
    /// file with no index row has never been broadcast and so cannot
    /// collide with a
    /// concurrent mid-conflict resolution the way re-versioning or
    /// tombstoning an already-known path can (the hazard `watcher.rs`'s
    /// module doc documents as "found unsafe").
    AddOnly,
}

impl ReconcileMode {
    fn is_full(self) -> bool {
        matches!(self, Self::Full { .. })
    }

    fn is_add_only(self) -> bool {
        matches!(self, Self::AddOnly)
    }

    fn emits_tombstones(self) -> bool {
        matches!(self, Self::Full { emit_tombstones: true })
    }
}

impl LocalChangeProcessor {
    pub fn new(
        state: Arc<dyn crate::ports::LocalMutationStore>,
        store: Arc<dyn crate::ports::BlockContentStore>,
        device_id: String,
        root_lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
    ) -> Self {
        Self { state, store, device_id, change_emitter: None, root_lease }
    }

    /// Admits a fresh `LinkOperation` against this processor's lease --
    /// called immediately before every `LocalMutationStore` mutation this processor
    /// makes. The caller MUST hold the returned operation for at least the
    /// duration of the specific write/commit it is admitting (Rust's own
    /// temporary-lifetime rules do this automatically for the common
    /// `&self.begin_operation()?.permit()` call-argument shape), and should
    /// hold it across any preceding same-call filesystem work whenever that
    /// work is in the same function -- see `root_commit::RootLease`'s own
    /// doc for why a momentary, immediately-dropped admission is not
    /// sufficient on its own.
    fn begin_operation(
        &self,
    ) -> Result<yadorilink_root_authority::root_commit::LinkOperation, LocalCaptureError> {
        Ok(self.root_lease.begin_operation()?)
    }

    /// Enables change-history emission: from here on, accepted local
    /// mutations dual-write a signed change alongside the index mutation.
    pub fn with_change_emitter(mut self, emitter: Arc<ChangeEmitter>) -> Self {
        self.change_emitter = Some(emitter);
        self
    }

    /// Builds the content version op for a created/updated record, together
    /// with the full [`FileVersion`] it references. The version hash covers the
    /// file's block list, size, and the metadata in scope at the write site
    /// (mtime, exec bit, and symlink target/kind when the record is a symlink).
    /// The op carries only the hash; the returned version carries the block
    /// list a receiver needs to materialize it, and is persisted alongside the
    /// emitted change.
    fn content_op(
        &self,
        record: &FileRecord,
        unix_mode: Option<u32>,
        symlink_target: Option<Vec<u8>>,
        xattrs: Vec<(String, Vec<u8>)>,
    ) -> (Op, FileVersion) {
        // The chunker's real per-block sizes are in scope here, so the version
        // carries each block's exact length; a receiver rebuilds offsets from
        // them and validates each fetched block against its declared size.
        let blocks = record
            .blocks
            .iter()
            .map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size })
            .collect();
        let record_kind =
            if symlink_target.is_some() { RecordKind::Symlink } else { RecordKind::File };
        let meta = FileMeta {
            mtime_unix_nanos: record.mtime_unix_nanos,
            unix_mode,
            symlink_target,
            record_kind,
            xattrs,
        };
        let version = FileVersion::new(blocks, record.size, meta);
        let version_hash = version.version_hash;
        let path = SyncPath(record.path.clone());
        let op = Op::Put { path, version: version_hash, origin: PutOrigin::Direct };
        (op, version)
    }

    /// Indexes every pre-existing file under `root` that isn't already
    /// indexed (`sync-engine` spec's "Initial Full Sync" requirement).
    /// Necessary because a filesystem watcher, by nature, only reports
    /// changes from the moment it starts — files already present when a
    /// folder is linked (or created while the daemon wasn't running)
    /// would otherwise never enter the index at all. Call once, before
    /// starting the live watch on `root`.
    ///
    /// Skips files whose size already matches an existing, non-deleted
    /// index entry, so restarting the daemon doesn't spuriously bump every
    /// unchanged file's version vector on every scan.
    ///
    /// The existing index and
    /// materialization states are bulk-loaded once up front (rather than
    /// one `get_file`/`get_materialization_state` query per walked entry),
    /// and every newly-indexed or changed record is committed in a single
    /// transaction at the end — so a folder with a very large number of
    /// pre-existing files (e.g. a git repository's `.git/objects/`) scans
    /// in a bounded number of SQLite round trips rather than one per file.
    pub fn scan_existing_files(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        self.scan_existing_files_with_ignore(group_id, root, &ignore_set)
    }

    pub fn scan_existing_files_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let root = self.verified_root(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::Full { emit_tombstones: true },
            None,
        )
    }

    /// Streaming sibling of `scan_existing_files_with_ignore`: identical
    /// scan/commit behavior and return value, but `on_chunk_committed` is
    /// called once per reconciliation chunk right after that chunk's own
    /// durable commit -- see `reconcile_disk_with_ignore`'s own doc for the
    /// exact guarantee (never before a commit, never for a withheld chunk).
    pub fn scan_existing_files_with_ignore_streaming(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
        on_chunk_committed: &mut dyn FnMut(&[FileRecord]),
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let root = self.verified_root(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::Full { emit_tombstones: true },
            Some(on_chunk_committed),
        )
    }

    /// Same as `scan_existing_files_with_ignore`, but lets the caller suppress
    /// this pass's missing-file tombstone emission via `emit_tombstones`.
    ///
    /// The startup crash-vs-offline-delete disambiguation depends on the
    /// interrupted-materialization repair pass having run first: repair is what
    /// distinguishes a crash-mid-materialize (missing target, blocks present
    /// locally, an open materialization intent -> reconstruct) from an offline
    /// user delete (missing target, no intent -> tombstone). When that repair
    /// pass ERRORED for this group on this boot, its disambiguation input is
    /// unavailable, so a `Hydrated`-but-missing file cannot be safely told apart
    /// from a genuine deletion. Passing `emit_tombstones = false` then defers
    /// ALL of this scan's delete emission to a later boot on which repair
    /// succeeds — fail-closed: never emit a delete when a crash cannot be told
    /// from a delete. A path is still indexed/updated as usual; only the
    /// missing-file tombstone step is withheld.
    ///
    /// `emit_tombstones = true` reproduces `scan_existing_files_with_ignore`
    /// exactly.
    pub fn scan_existing_files_with_ignore_gated(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
        emit_tombstones: bool,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let root = self.verified_root(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::Full { emit_tombstones },
            None,
        )
    }

    /// The full reconciliation scan `DebounceFlush::RescanRequired` drives
    /// from the LIVE flush loop -- a watcher-channel/OS overflow, or
    /// simply editing this link's own `.yadorilinkignore`, both ordinary
    /// triggers requiring no crash -- once this link's startup barrier has
    /// already resolved. Unlike `scan_existing_files_with_ignore[_gated/
    /// _streaming]` above (the one-time initial scan
    /// `yadorilink-daemon::link_manager::start_link_watch` runs exactly
    /// once, before the live watch begins), this runs repeatedly for the
    /// rest of an established link's lifetime, concurrently with peer
    /// apply, on-demand hydration, and the periodic repair sweep.
    ///
    /// Two independent things the three functions above get structurally
    /// right for the one-time initial scan, and this one must get right
    /// for the live, repeating case instead:
    ///
    /// - `verified_root_of_established_link`, not `verified_root`: `open`
    ///   (what `verified_root` uses) can silently ADOPT an unmarked-but-
    ///   corroborated root and does not check `sync_root_lock`'s live
    ///   ownership registry -- correct ONLY for the one-time scan that
    ///   runs before the watch starts. See that method's own doc comment
    ///   for the sidecar-unlink-and-recreate race this closes for every
    ///   OTHER already-established-link caller; this one used to be the
    ///   sole exception.
    /// - `emit_tombstones` is a caller-supplied parameter here, not
    ///   hardcoded `true`: a live rescan must respect the identical
    ///   fail-closed gates the startup scan itself was gated on (this
    ///   boot's materialization-repair success, ANDed with the two-live-
    ///   roots recovery flag) -- omitting them here silently defeated
    ///   both for the entire live lifetime of every link, deterministically,
    ///   no race required. The caller is responsible for re-reading the
    ///   live recovery flag fresh for each call (not reusing a value
    ///   frozen at link-start), since that flag can be armed or cleared at
    ///   any point during an established link's life -- see
    ///   `yadorilink-daemon`'s executor task for how it combines the two.
    pub fn scan_existing_files_with_ignore_gated_for_established_link(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
        emit_tombstones: bool,
        on_chunk_committed: Option<&mut dyn FnMut(&[FileRecord])>,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let root = self.verified_root_of_established_link(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::Full { emit_tombstones },
            on_chunk_committed,
        )
    }

    /// Establishes this link's root identity for a caller that has only a path.
    ///
    /// Every public reconcile entry point funnels through here, so verification
    /// is unconditional: there is no entry point that scans an unverified root,
    /// and `reconcile_disk_with_ignore`'s `&VerifiedRoot` parameter is what
    /// makes that structural rather than a convention a new entry point could
    /// quietly break.
    ///
    /// Uses [`VerifiedRoot::open`], which can silently ADOPT an unmarked-but-
    /// corroborated root and does not check the in-process
    /// `sync_root_lock::HELD_ROOT_IDENTITIES` registry — appropriate ONLY for
    /// the one-time "initial full sync" (`scan_existing_files*`) that
    /// `yadorilink-daemon`'s `LinkRuntimeController::start` runs exactly once,
    /// after it has already acquired this root's `SyncRootLock`, before the
    /// live watch and the periodic backstop begin. A caller that runs
    /// repeatedly for the lifetime of an established watch must use
    /// [`Self::verified_root_of_established_link`] instead — see that
    /// method's own doc for why `open` is the wrong primitive once a link is
    /// already running.
    fn verified_root(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<VerifiedRoot, LocalCaptureError> {
        Ok(self.state.open_root(root, group_id)?)
    }

    /// Re-verifies this link's root identity for a caller that runs
    /// repeatedly against an already-established, already-watched link —
    /// the live event handler (`process_event*`) and the periodic add-only
    /// backstop (`reconcile_added_files*`), both of which run for as long as
    /// `yadorilink-daemon`'s `LinkRuntimeController::start` holds this root's
    /// `SyncRootLock`.
    ///
    /// Uses [`VerifiedRoot::verify`], not `open`: `open` can silently ADOPT
    /// an unmarked-but-corroborated root (the correct behavior for the
    /// one-time initial scan, wrong here) and — the gap this method closes —
    /// does not check `sync_root_lock::verify_registered_root_ownership`.
    /// Without that check, the sidecar-unlink-and-recreate race
    /// `SyncRootLock::verify_still_owns`'s own doc describes (a live holder's
    /// OS lock survives its own sidecar being unlinked out from under it; a
    /// second process can then create-and-lock a brand-new object at the
    /// same pathname, and both processes correctly believe they exclusively
    /// own the root) goes undetected by every call that funnels through
    /// `open` instead — closed for eviction/materialization by
    /// `VerifiedRoot::verify`'s own wiring, but previously open here: the
    /// live watcher and periodic backstop kept authoring local changes,
    /// updating the index and emitting tombstones against a root whose
    /// exclusive ownership this process had actually lost.
    fn verified_root_of_established_link(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<VerifiedRoot, LocalCaptureError> {
        Ok(self.state.verify_root(root, group_id)?)
    }

    /// The add-only disk reconcile the periodic backstop runs. Walks
    /// `root` and returns/indexes a `FileRecord` only for a regular file
    /// or symlink that is present on disk but has **no** existing index
    /// row — recovering a local write whose OS filesystem-watcher event
    /// was never delivered (e.g. it fell into an FSEvents stream-recreate
    /// blind window, see `watcher.rs`'s module doc). It
    /// never re-versions an already-indexed file whose on-disk content
    /// changed and never tombstones an indexed file missing from disk (both
    /// of which `scan_existing_files_with_ignore` does): those mutate an
    /// already-known path and are unsafe to run this often (they can
    /// re-derive or false-delete a file mid-conflict-resolution between two
    /// devices). Indexing a file that has no row yet is byte-for-byte what a
    /// live create event would have done, so it carries none of that hazard.
    pub fn reconcile_added_files_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        // Root identity is still verified, even though this scope cannot
        // tombstone and so cannot cause the loss that motivates the check. The
        // converse hazard is what makes it worth paying for here: an add-only
        // walk of a *wrong* filesystem indexes that volume's files as new
        // members of this group and pushes them to every device. That is not
        // silent loss, but it is silent pollution, and this is a periodic
        // backstop — it would land repeatedly and unattended.
        //
        // `verified_root_of_established_link`, not `verified_root`: this is
        // the recurring backstop for an already-running watch, not the
        // one-time initial scan — see that method's own doc.
        let root = self.verified_root_of_established_link(group_id, root)?;
        self.reconcile_disk_with_ignore(group_id, &root, ignore_set, ReconcileMode::AddOnly, None)
    }

    /// Like `reconcile_added_files_with_ignore`, but loads `root`'s ignore
    /// set itself — the periodic backstop's own convenience entry point,
    /// mirroring `scan_existing_files`'s relationship to `scan_existing_
    /// files_with_ignore`.
    pub fn reconcile_added_files(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        self.reconcile_added_files_with_ignore(group_id, root, &ignore_set)
    }

    /// The single choke point every disk reconcile passes through, and the
    /// reason it takes a [`VerifiedRoot`] rather than a `&Path`.
    ///
    /// A scan is *authoritative*: a path it does not find on disk becomes a
    /// tombstone that propagates to every device. That is only sound if the
    /// directory walked is genuinely this link's folder, which an existence
    /// check cannot establish — an unmounted volume leaves its mountpoint
    /// behind as an empty directory that passes every such check, and the scan
    /// then reads a whole folder as deleted. `VerifiedRoot` is the proof that
    /// the check ran, carried in the type rather than repeated at each call
    /// site, so a future entry point cannot reintroduce the gap by forgetting
    /// it: there is no way to hand this function a root without having verified
    /// one first. It also arrives already canonical, which subsumes the bare
    /// `root.canonicalize()?` this used to open with — the walked entries must
    /// relativize against the same resolution `process_event` performs
    /// internally, or `strip_prefix` silently fails for every entry (the same
    /// class of mismatch that function's own doc comment warns about for OS
    /// watchers).
    /// `on_chunk_committed`, when present, is called synchronously once per
    /// reconciliation chunk immediately after that chunk's own durable
    /// commit succeeds (right where `committed.extend_from_slice` already
    /// runs below) -- never before, and never for a chunk withheld by
    /// `PolicyUnavailable`. This lets a caller (see `scan_existing_files_
    /// with_ignore_streaming`) observe already-durable progress before the
    /// whole scan returns, without this function's own return contract
    /// changing at all: every existing caller passes `None` and sees
    /// byte-identical behavior. See the C4 15k live-burst investigation
    /// (2026-09-01): a full reconciliation already commits in bounded
    /// chunks (this loop's own doc comment above), but nothing surfaced
    /// that progress until this function returned -- for a real 15k-file
    /// scan, that withheld peer visibility for the whole scan's length
    /// (tens of seconds) even though most of the work was already durable
    /// far earlier.
    /// A `try_lock_owned` + fresh disk/veto re-check for ONE tombstone
    /// candidate, immediately before it is trusted -- shared by both the
    /// candidacy filter in `reconcile_disk_with_ignore`'s main loop and
    /// the final pre-commit re-verification right before each chunk
    /// actually writes. `Ok(Some(guard))` means safe to tombstone THIS
    /// instant, with the guard that must stay held until the write this
    /// check is protecting actually lands (a caller that drops it
    /// immediately closes nothing -- see both call sites' own comments).
    /// `Ok(None)` means not safe right now (contended, protected, or the
    /// path exists again) -- skip this candidate for this pass.
    fn recheck_tombstone_candidate(
        &self,
        group_id: &str,
        root: &Path,
        path: &str,
    ) -> Result<Option<tokio::sync::OwnedMutexGuard<()>>, LocalCaptureError> {
        // `try_lock`, never a blocking `lock`: mirrors
        // `materialization_repair.rs`'s own established pattern for the
        // identical shape of problem (a synchronous sweep racing an async
        // mutator that holds this same lock) -- contention itself is the
        // answer, not something to wait out. If a real mutator is
        // actively working on this exact path right now, that alone
        // proves the "genuinely missing, nothing in progress"
        // precondition for a tombstone does not hold.
        let Ok(guard) = self.state.path_lock(group_id, path).try_lock_owned() else {
            return Ok(None);
        };
        // Exact-name, not `std::fs::symlink_metadata(...).is_ok()`: on a
        // case- or Unicode-normalization-insensitive filesystem (macOS,
        // Windows), a direct path lookup resolves to whatever sibling
        // happens to case/normalization-fold to the same name, wrongly
        // reporting "still exists" for a path that is, under its OWN
        // exact spelling, genuinely gone -- the identical case-fold
        // hazard this whole investigation is about, just in the disk
        // check instead of the index. Also mirrors the walk's own
        // `is_file() || is_symlink()` admission predicate, not a bare
        // existence check: a directory (or fifo/socket/device) now
        // occupying this exact name is not "the file still exists" any
        // more than it was during the walk itself, which would have
        // skipped it the same way.
        if exact_leaf_exists_as_file_or_symlink(root, path) {
            return Ok(None);
        }
        if self.state.has_materialization_intent(group_id, path)?
            || self.state.has_unsettled_projection_obligation(group_id, path)?
            || (self.state.is_held(group_id, path)?
                && self.state.get_materialization_state(group_id, path)?
                    != Some(MaterializationState::Hydrated))
        {
            return Ok(None);
        }
        Ok(Some(guard))
    }

    fn reconcile_disk_with_ignore(
        &self,
        group_id: &str,
        root: &VerifiedRoot,
        ignore_set: &EffectiveIgnoreSet,
        mode: ReconcileMode,
        mut on_chunk_committed: Option<&mut dyn FnMut(&[FileRecord])>,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let root = root.path();

        let existing_by_path: std::collections::HashMap<String, FileRecord> = self
            .state
            .list_files(group_id)?
            .into_iter()
            .map(|record| (record.path.clone(), record))
            .collect();
        let materialization_by_path = self.state.list_materialization_states(group_id)?;
        let placeholder_generation_by_path = self.state.list_placeholder_generations(group_id)?;

        // Test-only seam: fires right after the whole-index snapshot
        // (`existing_by_path`) has been read but before any record derived from
        // it is committed below. It lets a test deterministically inject a
        // concurrent peer change for a scanned path into exactly the
        // snapshot-vs-commit window this scan's missing per-path locking used to
        // leave open, to prove the group startup barrier closes it. Compiled out
        // entirely in non-test builds.
        #[cfg(test)]
        scan_test_hooks::fire_post_snapshot(group_id);

        // Whether this group already has change history, so the reconciliation
        // below must route its detected changes through the change-emission
        // path (the offline-edit/offline-delete case). A group whose DAG is
        // still empty is deliberately left to the chunked initial import that
        // runs right after the scan, so this fix never changes how a first
        // link's whole index becomes history.
        let has_dag_history =
            self.change_emitter.is_some() && !self.state.dag_group_heads(group_id)?.is_empty();

        // Becoming ignored is not a deletion. Drop this device's local
        // index row so future sync work no longer considers the path,
        // but do not emit a tombstone and do not touch the on-disk file.
        // This mutates an existing index row, so it is a
        // `Full`-scope-only step — the add-only backstop never removes
        // or re-versions a known path.
        if mode.is_full() {
            let ignored_existing_paths: Vec<String> = existing_by_path
                .keys()
                .filter(|path| is_excluded_from_sync(Path::new(path), false, ignore_set))
                .cloned()
                .collect();
            for path in &ignored_existing_paths {
                self.state.remove_file(group_id, path, &self.begin_operation()?.permit())?;
            }
        }

        let mut records = Vec::new();
        let mut seen_paths = std::collections::HashSet::new();
        // Classification info for any symlink discovered this scan,
        // applied via `LocalMutationStore` setters once the corresponding
        // `FileRecord` rows are actually written below (those setters
        // require the row to already exist).
        let mut pending_symlinks: Vec<(String, SymlinkClassification)> = Vec::new();
        // exec-bit updates for paths
        // whose content (size) is unchanged this scan, applied after the
        // batch write below for the same reason `pending_symlinks` is —
        // `LocalMutationStore::set_unix_mode` is `UPDATE`-only and requires the row
        // to already exist.
        let mut pending_unix_modes: Vec<(String, Option<u32>)> = Vec::new();
        // C1.2a: same reasoning and lifecycle as `pending_unix_modes` --
        // applied as an ordinary post-write setter (`already_current`'s
        // fast path below) or folded into the emitted `FileVersion`/index
        // metadata (the `build_record_for_created_or_modified` path
        // below), never dropped on the floor the way an earlier version
        // of this scan unconditionally did.
        let mut pending_xattrs: Vec<(String, Vec<(String, Vec<u8>)>)> = Vec::new();
        // `follow_links(false)` is walkdir's default, but stated
        // explicitly here — verified (not assumed) that this default is
        // what makes a symlinked directory get enumerated as a single
        // leaf entry rather than descended into; see
        // `watcher::register_non_ignored_directories` for the one place
        // that default alone was NOT sufficient (an explicitly-given walk
        // root that is itself a symlink is still descended into even with
        // `follow_links(false)` — a walkdir quirk that doesn't apply here
        // since `root` is always canonicalized above, but is guarded
        // there defensively regardless).
        let walker =
            walkdir::WalkDir::new(root).follow_links(false).into_iter().filter_entry(|entry| {
                if entry.depth() == 0 {
                    return true;
                }
                let Ok(rel_path) = entry.path().strip_prefix(root) else { return false };
                !is_excluded_from_sync(rel_path, entry.file_type().is_dir(), ignore_set)
            });
        // A walk error means `seen_paths` is not an authoritative inventory
        // *for the subtree that failed* — a file's absence from `seen_paths`
        // there might just mean we could not read its directory, not that it
        // was deleted, so absence must not be converted into a tombstone
        // under that subtree. But it says nothing about cleanly-walked
        // subtrees, so suppression is scoped per-failed-prefix rather than
        // disabling tombstoning for the whole scan: one persistently-erroring
        // directory must not indefinitely defer a real deletion elsewhere
        // (which a peer that evicted the file could then re-hydrate). Each
        // failed directory's root-relative prefix is collected here and
        // consulted in the tombstone loop below. If an error carries no path
        // at all (it cannot be attributed to a subtree), fall back to the
        // conservative whole-scan suppression via `scan_complete`.
        let mut scan_complete = true;
        let mut failed_prefixes: Vec<String> = Vec::new();
        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    match error
                        .path()
                        .and_then(|p| p.strip_prefix(root).ok())
                        .and_then(path_to_wire_relative_string)
                    {
                        Some(rel) => {
                            // The root-relative directory (or entry) walkdir
                            // could not read. An empty prefix means the walk
                            // root itself failed, which `starts_with("")`
                            // matches for every path — i.e. the whole tree is
                            // suppressed, the correct outcome when the root is
                            // unreadable.
                            failed_prefixes.push(rel);
                        }
                        None => {
                            // No attributable (or losslessly representable)
                            // path — cannot scope the suppression, so fail
                            // safe for the entire pass.
                            scan_complete = false;
                        }
                    }
                    tracing::warn!(
                        group_id,
                        root = %root.display(),
                        error = %error,
                        "filesystem scan was partial; tombstone reconciliation is \
                         suppressed for the affected subtree"
                    );
                    continue;
                }
            };
            // a symlink (whatever it points to) is admitted
            // here as its own leaf entry — `entry.file_type` reflects
            // lstat metadata (never follows) since `follow_links(false)`
            // is in effect, so a symlink to a directory shows up here as
            // `is_symlink == true`, `is_dir == false`, and walkdir
            // never descends into it to enumerate its contents. Anything
            // that's neither a regular file nor a symlink (a directory,
            // or something exotic) is skipped, same as before.
            let file_type = entry.file_type();
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            let Ok(rel_path) = path.strip_prefix(root) else { continue };
            // A name that cannot be represented losslessly as this
            // crate's UTF-8 wire path (see `path_to_wire_relative_string`'s
            // own doc comment) is skipped outright, exactly like an
            // unsupported file type just above — better than silently
            // colliding it with some other file via lossy conversion.
            let Some(rel_path) = path_to_wire_relative_string(rel_path) else { continue };
            if is_excluded_from_sync(Path::new(&rel_path), false, ignore_set) {
                continue;
            }

            seen_paths.insert(rel_path.clone());

            let existing = existing_by_path.get(&rel_path).cloned();

            // In add-only scope, a path that already has an index row is
            // left entirely untouched — no re-hash, no re-version, no
            // exec-bit update. The backstop only recovers files the
            // index has never seen (whose live watcher event was lost);
            // anything already indexed is the live watcher's /
            // conflict-resolution's business, and re-deriving it here is
            // exactly the unsafe re-versioning `watcher.rs`'s module doc
            // warns about.
            if mode.is_add_only() && existing.is_some() {
                continue;
            }

            let entry_metadata = entry.metadata().ok();
            // "Already current" must be judged on the *same* basis as the
            // per-file path (`build_record_for_created_or_modified`'s fast
            // path): the cheap size+mtime stat gate first (via the shared
            // `metadata_mtime_matches` helper), then a content verification
            // before the no-op is trusted. A size-only gate is strictly
            // weaker than both that path and the live watcher (which
            // re-hashes on Modify): an offline edit that preserves the byte
            // length but changes the bytes (a flag flip, a same-length
            // hash/uuid swap, an in-place binary/DB edit) would be skipped
            // here, pinning the index at the stale version while disk holds
            // new bytes.
            //
            // Closing the tail: an edit that preserves BOTH size and mtime
            // (`touch -r`, archive extraction that restores timestamps, an
            // in-place same-length overwrite) is invisible to any stat-only
            // check, so a regular file that passes the size+mtime gate is
            // additionally verified against its indexed block hashes with
            // `disk_bytes_match_indexed_blocks` — the same content check the
            // per-file fast path now applies. That verifier reads the file
            // once, comparing each indexed block's SHA-256 in sequence and
            // early-exiting on the first mismatch, without re-chunking or
            // writing any block to the store. When the bytes differ (or any
            // size/mtime mismatch), the path falls through to
            // `build_record_for_created_or_modified` below, which re-chunks
            // and re-versions. Symlinks carry no blocks (their identity is
            // the target text, checked in `build_symlink_record`), so they
            // keep the stat-only verdict and fall through to that path
            // unchanged. The read cost is bounded: it lands only on files
            // that already matched size+mtime, only on the infrequent full
            // startup/burst-fallback scan — the high-frequency `AddOnly`
            // backstop never reaches this path for an already-indexed file
            // (it `continue`s above at `existing.is_some()`).
            //
            // Bounded in total work is not the same as bounded per hold,
            // though. The daemon runs the *initial* scan inside its own
            // `spawn_blocking`, but the disk-reconcile backstop reaches
            // this same loop by awaiting `reconcile_added_files_from_disk`
            // straight from a runtime task — so on that route every large
            // already-current file would re-read and re-hash itself with a
            // worker core held. `disk_bytes_match_indexed_blocks_off_
            // worker` hands the core off for exactly those files and leaves
            // small ones inline, so this per-file loop pays no handoff for
            // the files that do not need one.
            let already_current = match (&existing, &entry_metadata) {
                (Some(existing), Some(metadata)) => {
                    !existing.deleted
                        && existing.size == metadata.len()
                        && metadata_mtime_matches(metadata, existing.mtime_unix_nanos)
                        && (!file_type.is_file()
                            || disk_bytes_match_indexed_blocks_off_worker(
                                path,
                                &existing.blocks,
                                metadata.len(),
                            )?)
                }
                _ => false,
            };
            if already_current {
                // content (size) is
                // unchanged, but this file's exec bit may never have been
                // captured at all (it predates this change and the
                // `unix_mode` column defaults to `false`), or may have been
                // chmod-only-changed since the last scan with no live
                // watcher running to catch it via
                // `build_record_for_created_or_modified`'s own fast path.
                // Reuse the `Metadata` already fetched above for the size
                // comparison — no extra syscall — rather than falling
                // through to that function's full machinery for what is,
                // by definition here, an unchanged-content file. Symlinks
                // carry no exec bit, so this only
                // applies to a genuine regular file.
                if file_type.is_file() {
                    if let (Some(existing), Some(metadata)) = (&existing, &entry_metadata) {
                        let on_disk_unix_mode = unix_mode_from_metadata(metadata);
                        let indexed_unix_mode = self.state.get_unix_mode(group_id, &rel_path)?;
                        // Same reasoning as the exec-bit check just
                        // above, for extended attributes (C1.2a): an
                        // offline `setxattr`-only edit changes neither
                        // size, mtime, content, nor unix_mode, so it must
                        // be checked here too or a re-scan can never
                        // discover it.
                        let on_disk_xattrs = std::fs::File::open(path)
                            .map(|f| read_replicated_xattrs(&f))
                            .unwrap_or_default();
                        let indexed_xattrs = self.state.get_xattrs(group_id, &rel_path)?;
                        if on_disk_unix_mode != indexed_unix_mode
                            || on_disk_xattrs != indexed_xattrs
                        {
                            let record = existing.clone();
                            records.push(record);
                            pending_unix_modes.push((rel_path.clone(), on_disk_unix_mode));
                            pending_xattrs.push((rel_path.clone(), on_disk_xattrs));
                        }
                    }
                }
                continue;
            }

            let materialization_state = materialization_by_path.get(&rel_path).copied();
            let placeholder_generation = placeholder_generation_by_path.get(&rel_path).cloned();
            let (outcome, classification, unix_mode) = self.build_record_for_created_or_modified(
                group_id,
                root,
                rel_path.clone(),
                path,
                existing,
                materialization_state,
                placeholder_generation,
            )?;
            if let LocalChangeOutcome::FileChanged(record) = outcome {
                records.push(record);
                // Same reasoning as `local_change.rs`'s live single-event
                // path: a fresh open, not the same handle
                // `build_record_for_created_or_modified` chunked through
                // above -- a weaker same-bytes guarantee, but xattrs are
                // best-effort metadata, never content integrity. Never
                // scanned for a symlink, matching `unix_mode`'s own `None`
                // there.
                if classification.is_none() {
                    let xattrs = std::fs::File::open(path)
                        .map(|f| read_replicated_xattrs(&f))
                        .unwrap_or_default();
                    pending_xattrs.push((rel_path.clone(), xattrs));
                }
                if let Some(classification) = classification {
                    pending_symlinks.push((rel_path.clone(), classification));
                }
                if let Some(unix_mode) = unix_mode {
                    pending_unix_modes.push((rel_path, unix_mode));
                }
            }
        }

        // the walk above only ever adds/updates files that still
        // exist on disk — it never notices a file that vanished (deleted,
        // or renamed away, since the watcher classifies a rename-source
        // as `CreatedOrModified`, see `watcher.rs`). Without this, a
        // missed removal propagates to peers as a live file forever, and
        // even the "full reconciliation" this function IS the recovery
        // path for can't fix it. Tombstone any indexed, not-already-
        // deleted file whose path wasn't observed in this walk.
        // Tombstoning increments an existing row's version, so it is
        // `Full`-scope only — the add-only backstop never deletes a
        // known path (a file missing from disk this pass might be
        // mid-materialization or mid-conflict-resolution; only the
        // deliberate full reconciliation is allowed to tombstone).
        // `emit_tombstones` is `false` when the interrupted-materialization
        // repair pass that must run before this scan ERRORED for this group on
        // this boot: without repair's crash-vs-offline-delete disambiguation, a
        // `Hydrated`-but-missing file cannot be safely told apart from a
        // genuine deletion, so ALL delete emission is deferred to a later boot
        // on which repair succeeds. Fail-closed: never emit a delete when a
        // crash cannot be told from a delete. See
        // `scan_existing_files_with_ignore_gated`.
        if mode.emits_tombstones() && scan_complete {
            for (path, existing) in &existing_by_path {
                if existing.deleted || seen_paths.contains(path) {
                    continue;
                }
                if is_excluded_from_sync(Path::new(path), false, ignore_set) {
                    continue;
                }
                // Fail-safe, per-subtree: never tombstone a path that lives
                // under a directory this pass could not walk — its absence
                // from `seen_paths` may be an unread directory, not a real
                // deletion. `Path::starts_with` matches on whole path
                // components, so the prefix `broken` suppresses `broken/x`
                // but never `broken-sibling/x`. Paths under cleanly-walked
                // subtrees are still tombstoned normally.
                if path_is_within_failed_subtree(path, &failed_prefixes) {
                    continue;
                }
                // Test-only seam: fires here, right at this path's
                // candidacy check, before any of the (potentially stale --
                // `seen_paths` was captured earlier, by the walk) checks
                // below run. Lets a test pause the scan for one targeted
                // path, inject a concurrent mutator's completed
                // transition, then resume and confirm neither the checks
                // below nor the fresh re-check further down are fooled by
                // it. Compiled out entirely in non-test builds.
                #[cfg(test)]
                scan_test_hooks::fire_pre_tombstone_recheck(group_id, path);
                // Never tombstone a path with an open materialization intent: a
                // crash interrupted its write (the file is missing precisely
                // because the rename never completed), and the durable intent
                // is the signal that the interrupted-materialization repair
                // pass must reconstruct it from the locally-present blocks — not
                // that the user deleted it. Absent this check, a crash
                // mid-eager-materialize whose repair could not run (or errored)
                // this boot would be misread here as an offline deletion and a
                // `Delete` propagated group-wide, silently destroying a fully
                // reconstructable file. Fail-closed: an errored intent lookup
                // propagates via `?` rather than falling through to a tombstone.
                if self.state.has_materialization_intent(group_id, path)? {
                    continue;
                }
                // M5-A finding: an open intent alone is not enough. A
                // path can have a durably-committed, non-deleted index
                // row whose projection obligation is still unsettled
                // (right after the DAG record was admitted, before
                // `materialize()` itself has ever run) -- no intent has
                // ever been opened for it, but it is exactly as "not yet
                // known to be deleted" as an in-flight intent is. Without
                // this check, a restart landing between DAG-record
                // admission and the obligation's first successful
                // materialize reads this as an offline deletion and
                // tombstones a file the device never even finished
                // receiving once. Same fail-closed contract as the intent
                // check above: an errored lookup propagates via `?`.
                if self.state.has_unsettled_projection_obligation(group_id, path)? {
                    continue;
                }
                // A hazard-held path is not deleted: `hold_record` demotes
                // it to `Placeholder`, writes nothing under this exact
                // name, and opens no materialization intent, ALL by
                // design (see that fix's own doc comment) -- so neither
                // check above protects it. `HazardHeld` settlement also
                // deletes the path's projection-obligation row, so the
                // check just above stops protecting it too, the instant
                // the hazard engine settles. Without this, a case-fold
                // collision or reserved-name hazard on this device alone
                // would look, to this scan, exactly like every peer having
                // deleted a file that is perfectly valid on all of them --
                // and this scan would propagate a real, signed, group-wide
                // `Delete` for it. Fail-closed, same contract as the two
                // checks above: an errored lookup propagates via `?`.
                //
                // Narrowed to `is_held && state != Hydrated`, not
                // `is_held` alone: `held_reason` and `materialization_
                // state` are independently-cleared columns
                // (`clear_held`/`set_materialization_state`/`transition_
                // materialization_state_if_same_authoring` are all
                // separate calls, not one atomic operation), so a stale
                // `held_reason` left behind on a row that a LATER,
                // successful materialize genuinely wrote real content for
                // and stamped `Hydrated` must not suppress its real
                // deletion forever -- that row's own actual, current
                // state already proves it is not the "nothing on disk
                // under this name" shape this whole check exists to
                // protect.
                if self.state.is_held(group_id, path)?
                    && self.state.get_materialization_state(group_id, path)?
                        != Some(MaterializationState::Hydrated)
                {
                    continue;
                }
                // Closes a real TOCTOU window, not a theoretical one: this
                // scan is a plain synchronous `fn`, so it structurally
                // cannot hold the async per-path lock every real mutator
                // (hydrate, materialize, materialization_repair) takes for
                // its whole operation -- and the four checks above (this
                // one plus the three vetoes) are four independent,
                // non-atomic reads on a pooled connection, each reading
                // whatever happens to be true at that instant. A
                // completed held-to-materialize transition (open intent,
                // write the real content, clear the intent/held state) can
                // land entirely between `seen_paths`' capture (the walk,
                // already finished by this point in the loop) and this
                // path reaching its candidacy check here -- every one of
                // the checks above would then read exactly the "genuinely
                // missing, fully unprotected" shape a real offline
                // deletion has, even though the file now genuinely exists.
                //
                // A cheap PRE-filter, not the authoritative check: this
                // guard is dropped at the end of this loop iteration, long
                // before the actual DAG write for this candidate happens
                // (the chunked commit loop further down, potentially many
                // paths and real elapsed time later, itself unlocked). A
                // mutator that completes a held-to-materialize transition
                // (or any other legitimate materialization) AFTER this
                // check but BEFORE this exact candidate's own chunk
                // commits would still get tombstoned if this were the only
                // check -- see the chunked commit loop's own final,
                // guard-held-through-commit re-verification for the
                // ACTUAL protection. Kept here anyway (not merely a
                // 3-veto check with no lock) so an already-doomed
                // candidate is discarded early rather than carried all the
                // way to the commit loop only to be filtered there.
                if self.recheck_tombstone_candidate(group_id, root, path)?.is_none() {
                    continue;
                }
                tracing::info!(
                    group_id,
                    path,
                    "startup reconciliation scan is tombstoning a locally-missing path (no open \
                     intent, no unsettled projection obligation) as an offline deletion"
                );
                let mut tombstone = existing.clone();
                tombstone.deleted = true;
                records.push(tombstone);
            }
        }

        // Route the reconciliation's detected changes through the same
        // change-emission path a live `process_event` uses, so an offline
        // edit or delete picked up only by this startup scan advances the
        // group's change-history DAG — not merely the local index — closing
        // the gap where a change-history-negotiating peer would otherwise
        // never learn of it. Only a group that already has history takes this
        // path (see `has_dag_history`); an empty record set emits nothing, so
        // re-running the scan never appends a duplicate head. A scan is always
        // this device's own local content — same origin as `process_event`'s
        // single-file write path.
        if has_dag_history && !records.is_empty() {
            // Present only when `has_dag_history` already required it.
            let emitter = self.change_emitter.as_ref().expect("emitter present");
            let exec_by_path: std::collections::HashMap<&str, Option<u32>> =
                pending_unix_modes.iter().map(|(p, b)| (p.as_str(), *b)).collect();
            let classification_by_path: std::collections::HashMap<&str, &SymlinkClassification> =
                pending_symlinks.iter().map(|(p, c)| (p.as_str(), c)).collect();

            // Build the emission payload for every detected record, aligned
            // 1:1 with `records`: its op, the `FileVersion` a create/update
            // references (`None` for a tombstone), and the local metadata
            // columns to write in the SAME transaction as the change so the
            // index row's kind/target/exec-bit can never lag the version the
            // change carries across a crash.
            let mut ops: Vec<Op> = Vec::with_capacity(records.len());
            let mut versions: Vec<Option<FileVersion>> = Vec::with_capacity(records.len());
            let mut metas: Vec<Option<LocalFileMetaColumns>> = Vec::with_capacity(records.len());
            for record in &records {
                if record.deleted {
                    ops.push(Op::Delete { path: SyncPath(record.path.clone()) });
                    versions.push(None);
                    metas.push(None);
                } else {
                    let unix_mode = exec_by_path.get(record.path.as_str()).copied().flatten();
                    let classification: Option<SymlinkClassification> =
                        classification_by_path.get(record.path.as_str()).map(|c| (*c).clone());
                    let symlink_target = classification.as_ref().map(|c| c.target.clone());
                    // C1.2a: re-read this record's current on-disk xattrs
                    // for the same reason `exec_for_meta` reads a fresh
                    // exec bit below -- an earlier version of this scan
                    // instead emitted `Vec::new()` unconditionally, which
                    // did not just miss an offline xattr edit: it
                    // authored a version and index row with NO xattrs for
                    // every offline content/mode change this scan
                    // detects, silently erasing attributes this same file
                    // already carried and had never actually lost. Never
                    // scanned for a symlink, matching `exec_for_meta`'s
                    // own `None` there.
                    let xattrs = if classification.is_none() {
                        std::fs::File::open(root.join(&record.path))
                            .map(|f| read_replicated_xattrs(&f))
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    let (op, version) =
                        self.content_op(record, unix_mode, symlink_target, xattrs.clone());
                    let exec_for_meta =
                        if classification.is_some() { None } else { Some(unix_mode) };
                    ops.push(op);
                    versions.push(Some(version));
                    metas.push(Some(metadata_columns_for(&classification, exec_for_meta, xattrs)));
                }
            }

            // A bulk offline diff (e.g. deleting or renaming 100k files while
            // the daemon was stopped) would otherwise become a single change
            // with 100k ops — which no peer can decode (over `change::MAX_OPS`)
            // and no wire message can carry (over the transport's control
            // frame size cap), stranding that head permanently
            // un-propagatable. Split it into
            // op-count- and byte-bounded chunks, each committed as its own
            // change. Because `dag_store::emit_local_change` takes the group's
            // current heads as parents and each chunk commits before the next
            // runs, the chunks form a single linear chain converging on one
            // head. A crash mid-way leaves the already-committed chunks durable;
            // the remaining disk-vs-index diff is re-derived and re-emitted
            // (chaining onto the last committed chunk) by the next scan.
            let mut committed: Vec<FileRecord> = Vec::new();
            let mut withheld_from: Option<usize> = None;
            let mut start = 0usize;
            while start < records.len() {
                let mut end = start;
                let mut chunk_bytes = 0usize;
                while end < records.len() {
                    let op_bytes = encoded_op_len(&ops[end]);
                    // Always take at least one op (`end == start`), so a single
                    // over-cap op could never wedge the loop; otherwise stop at
                    // either bound.
                    if end > start
                        && (end - start >= RECONCILE_CHUNK_OP_LIMIT
                            || chunk_bytes + op_bytes > RECONCILE_CHUNK_BYTE_LIMIT)
                    {
                        break;
                    }
                    chunk_bytes += op_bytes;
                    end += 1;
                }
                // The FINAL, load-bearing re-verification -- not the
                // candidacy-time one further up, which drops its guard as
                // soon as that loop iteration ends, long before this
                // point. Held through the commit call just below: for
                // each tombstone candidate in THIS chunk, re-take its lock
                // and re-run every check one more time, right here,
                // immediately before the write that actually deletes it.
                // A mutator that completes a legitimate materialization
                // after the candidacy-time check but before this exact
                // moment -- the window the candidacy-time check alone
                // cannot close, since nothing serializes between the two
                // -- is caught here instead. Non-tombstone entries (new/
                // changed content) need no re-verification; only
                // `record.deleted` candidates ever reach a delete.
                let mut kept_indices: Vec<usize> = Vec::with_capacity(end - start);
                let mut kept_guards: Vec<tokio::sync::OwnedMutexGuard<()>> = Vec::new();
                for i in start..end {
                    if !records[i].deleted {
                        kept_indices.push(i);
                        continue;
                    }
                    // Test-only seam: fires once per tombstone candidate,
                    // right before this final re-verification -- distinct
                    // from the candidacy-time hook above, so a test can
                    // inject a race specifically in THIS window (after
                    // candidacy, before commit) without also needing to
                    // race the earlier one. Compiled out entirely in
                    // non-test builds.
                    #[cfg(test)]
                    scan_test_hooks::fire_pre_chunk_commit_recheck(group_id, &records[i].path);
                    match self.recheck_tombstone_candidate(group_id, root, &records[i].path)? {
                        Some(guard) => {
                            kept_indices.push(i);
                            kept_guards.push(guard);
                        }
                        None => {
                            tracing::info!(
                                group_id,
                                path = %records[i].path,
                                "live reconciliation scan's final pre-commit re-check found \
                                 this path no longer eligible for an offline-deletion \
                                 tombstone; withholding it from this chunk's commit"
                            );
                        }
                    }
                }
                let chunk_records: Vec<FileRecord> =
                    kept_indices.iter().map(|&i| records[i].clone()).collect();
                let chunk_ops: Vec<Op> = kept_indices.iter().map(|&i| ops[i].clone()).collect();
                // Unaffected by `kept_indices` filtering above: a
                // tombstone candidate never contributes a `Some` entry to
                // `versions` in the first place (`Op::Delete` pairs with
                // `None`, see the loop that built `versions` above), so
                // excluding one here changes nothing this `.flatten()`
                // would have kept anyway. Still built from the FULL
                // `start..end` range, not `kept_indices` -- narrowing it
                // to the filtered range would be redundant, not incorrect.
                let chunk_versions: Vec<FileVersion> =
                    versions[start..end].iter().flatten().cloned().collect();
                let chunk_metas: Vec<Option<LocalFileMetaColumns>> =
                    kept_indices.iter().map(|&i| metas[i].clone()).collect();
                if chunk_records.is_empty() {
                    // Every candidate in this chunk was withheld by the
                    // re-check above (or the chunk was entirely
                    // tombstones, all now stale) -- nothing left to
                    // commit. `kept_guards` drops here, releasing every
                    // lock this iteration took.
                    start = end;
                    continue;
                }
                // `RootCommitPermit::verify` is called by `upsert_files_
                // batch_emitting_change` itself, immediately before its own
                // commit -- not just once at this whole scan's entry
                // (`root`'s caller already produced a `VerifiedRoot` before
                // this function was reached): a scan chunks into
                // potentially many sequential commits (see this loop's own
                // doc above), each separated by real elapsed time, during
                // which root ownership/lifecycle can change. This used to
                // be a standalone `sync_root_lock::verify_registered_root_
                // ownership(root)?` call here; that check is now folded
                // into the permit's own `verify`, alongside the daemon's
                // lifecycle-fence check the standalone call never covered.
                let commit_result = self.state.upsert_files_batch_emitting_change(
                    group_id,
                    &chunk_records,
                    &self.device_id,
                    ChangeContent { ops: chunk_ops, versions: &chunk_versions },
                    &chunk_metas,
                    crate::ports::LocalChangeEmission {
                        emitter,
                        permit: &self.begin_operation()?.permit(),
                    },
                );
                // Every re-verified tombstone candidate's lock is held all
                // the way through the commit call above -- dropped only
                // now, after it durably lands (or fails). This is what
                // actually closes the window: nothing else can complete a
                // materialization for any of these exact paths while this
                // commit is in flight.
                drop(kept_guards);
                match commit_result {
                    Ok(_) => {
                        committed.extend_from_slice(&chunk_records);
                        if let Some(ref mut cb) = on_chunk_committed {
                            cb(&chunk_records);
                        }
                    }
                    // The group's policy is stale or has not loaded yet this
                    // run, so the emit withheld this chunk rather than stamp a
                    // placeholder-auth change every valid-policy peer would
                    // reject (see `upsert_file_emitting_change`). Any earlier
                    // chunks already committed are real emitted changes and
                    // stand; do NOT fall back to a DAG-silent index write for
                    // the rest. Journal this chunk and the remaining tail dirty
                    // (below) so the dirty-journal re-drive re-emits them — with
                    // a real authorization stamp — once policy heals, leaving
                    // the index unadvanced for them so a later full rescan can
                    // still re-derive the same diff.
                    Err(SyncSqliteError::PolicyUnavailable) => {
                        withheld_from = Some(start);
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
                start = end;
            }

            if let Some(from) = withheld_from {
                let observed = now_unix_nanos();
                for record in &records[from..] {
                    let kind = if record.deleted {
                        FsChangeKind::Removed
                    } else {
                        FsChangeKind::CreatedOrModified
                    };
                    if let Err(e) = self.state.record_dirty_path(
                        group_id,
                        &record.path,
                        dirty_kind_str(kind),
                        observed,
                        &self.begin_operation()?.permit(),
                    ) {
                        tracing::warn!(
                            error = %e,
                            path = %record.path,
                            group_id,
                            "failed to journal a policy-withheld offline change; a later \
                             full rescan re-derives it from the unadvanced index"
                        );
                    }
                }
                // M5-A review follow-up (blocker #56, second round): see
                // `record_local_commit_fingerprints`'s own doc comment.
                self.record_local_commit_fingerprints(group_id, root, &committed);
                // Broadcast only the chunks that durably entered the DAG; the
                // withheld tail re-emits via the dirty journal.
                return Ok(committed);
            }
            // `committed`, not the original `records`: the final pre-
            // commit re-check inside the chunking loop above can withhold
            // a tombstone candidate from its own chunk even when every
            // chunk otherwise committed successfully (`withheld_from`
            // stays `None`) -- `records` would then still list a path
            // that was correctly never actually deleted.
            self.record_local_commit_fingerprints(group_id, root, &committed);
            Ok(committed)
        } else {
            // The group has no change DAG yet (a first link's whole index is
            // seeded into history by the chunked initial import that runs right
            // after this scan), so an index-only write here is not a silent DAG
            // divergence — there is no DAG to diverge from. The metadata columns
            // are applied as ordinary post-write setters (there is no change to
            // keep them atomic with, and these setters require the row the
            // batch write above just created).
            // Same permit re-check as the DAG-history branch above,
            // immediately before this scan's commit (see that branch's
            // own comment).
            self.state.upsert_files_batch(
                group_id,
                &records,
                &self.device_id,
                &self.begin_operation()?.permit(),
            )?;
            for (path, classification) in &pending_symlinks {
                self.apply_symlink_classification(group_id, path, classification)?;
            }
            for (path, unix_mode) in &pending_unix_modes {
                self.state.set_unix_mode(
                    group_id,
                    path,
                    *unix_mode,
                    &self.begin_operation()?.permit(),
                )?;
            }
            for (path, xattrs) in &pending_xattrs {
                self.state.set_xattrs(group_id, path, xattrs, &self.begin_operation()?.permit())?;
            }
            self.record_local_commit_fingerprints(group_id, root, &records);
            Ok(records)
        }
    }

    /// M5-A review follow-up (blocker #56, second round): records, for
    /// every non-deleted `record` a local commit just durably indexed, the
    /// disk identity of the exact bytes now on disk at its path -- the
    /// SAME `disk_race_fingerprint` scheme `hydrate_inner`'s already-
    /// Hydrated shortcut relies on. Without this, an ordinary local edit's
    /// version bump silently drops the row back to "Hydrated with no
    /// proven fingerprint" (a version bump never carries the fingerprint
    /// columns forward, and a locally-authored version never goes through
    /// `reconstruct_file`) -- the exact unproven state that shortcut
    /// treats as safe to reconstruct over, reopening the clobber this
    /// whole fix exists to close for any file that has ever been edited
    /// even once. Called with `root` already resolved and each `record`'s
    /// bytes freshly, durably on disk (this scan read them to build these
    /// exact records), so the stat here is safe and cheap -- best-effort
    /// (logged, never propagated): a failure here must not fail the local
    /// commit that already durably landed; `hydrate_inner`'s own fail-
    /// closed "no fingerprint -> re-verify" fallback tolerates a missed
    /// recording safely, just without the fast-path optimization for that
    /// one row until it's next rewritten.
    fn record_local_commit_fingerprints(
        &self,
        group_id: &str,
        root: &Path,
        records: &[FileRecord],
    ) {
        for record in records {
            if record.deleted {
                continue;
            }
            let out_path = root.join(&record.path);
            let Ok(op) = self.begin_operation() else { return };
            if let Err(e) = self.state.record_materialized_fingerprint(
                group_id,
                &record.path,
                disk_race_fingerprint(&out_path),
                &op.permit(),
            ) {
                tracing::warn!(
                    error = %e,
                    path = %record.path,
                    group_id,
                    "failed to record a materialized fingerprint after a local commit"
                );
            }
        }
    }

    /// Processes one filesystem event under a linked folder rooted at
    /// `root`, updating the local index (for an ordinary file change) and
    /// returning what happened. The caller is responsible for
    /// broadcasting a `FileChanged` record to connected, unpaused peer
    /// sessions via `PeerSyncSession::send_index_update`.
    pub async fn process_event(
        &self,
        group_id: &str,
        root: &Path,
        event: &FsChangeEvent,
    ) -> Result<LocalChangeOutcome, LocalCaptureError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        self.process_event_with_ignore(group_id, root, event, &ignore_set).await
    }

    pub async fn process_event_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        event: &FsChangeEvent,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<LocalChangeOutcome, LocalCaptureError> {
        // `pending_batch: None` always yields `EventOutcome::Ready` --
        // `Deferred` is only ever produced when a batch sink is supplied,
        // which only `process_flush_with_ignore`'s `DebounceFlush::Paths`
        // loop ever does.
        match self.process_event_with_ignore_at(group_id, root, event, ignore_set, None, None).await? {
            EventOutcome::Ready(outcome) => Ok(outcome),
            EventOutcome::Deferred => unreachable!(
                "process_event_with_ignore_at only defers when given a pending_batch sink"
            ),
        }
    }

    /// Like `process_event_with_ignore`, but for a `Removed` event lets the
    /// caller supply the watcher's own observed time for `mark_deleted_at`
    /// instead of defaulting to "now" — see `mark_deleted_at`'s doc comment
    /// for why this matters. `process_flush_with_ignore` (the debounced
    /// batch path, where an event may have been sitting in the debounce
    /// accumulator for a while before this dispatch runs) is the only
    /// caller that has a better answer than "now"; every direct
    /// `process_event`/`process_event_with_ignore` caller (a live
    /// undebounced call, every existing test) keeps getting `None` =>
    /// "now", identical to this method's behavior before this parameter
    /// existed.
    ///
    /// `pending_batch`, when `Some`, lets the simple, DAG-emitting
    /// create/modify/delete case (not a symlink, an emitter configured)
    /// defer its commit into a shared batch instead of committing here --
    /// see [`EventOutcome::Deferred`]/[`PendingBatchedCommit`]'s own docs.
    /// `None` (every caller but `process_flush_with_ignore`'s
    /// `DebounceFlush::Paths` loop) always yields `EventOutcome::Ready`,
    /// identical to this function's behavior before batching existed.
    async fn process_event_with_ignore_at(
        &self,
        group_id: &str,
        root: &Path,
        event: &FsChangeEvent,
        ignore_set: &EffectiveIgnoreSet,
        observed_at_unix_nanos: Option<i64>,
        pending_batch: Option<&mut Vec<PendingBatchedCommit>>,
    ) -> Result<EventOutcome, LocalCaptureError> {
        // OS-level watchers (notify's FSEvents backend on macOS in
        // particular) report fully-resolved paths — e.g. `/private/var/...`
        // rather than the `/var/...` symlink most callers construct their
        // root from (via `tempfile::tempdir` or otherwise). Without
        // canonicalizing `root` too, `strip_prefix` below silently fails
        // for every event, and no local change is ever detected. `root`
        // is the watched directory itself, so it's expected to still
        // exist here (unlike `event.path`, which may already be gone for
        // a `Removed` event and so isn't safe to canonicalize).
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        // The live watcher previously authored local changes, updated the
        // index and emitted tombstones against `root` for the rest of this
        // process's life with no ownership re-check at all — the gap
        // `verified_root_of_established_link`'s own doc describes. Checked
        // before anything else below touches the index or DAG.
        self.verified_root_of_established_link(group_id, &root)?;
        let Ok(rel_path) = event.path.strip_prefix(&root) else {
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        };
        // A name that cannot be represented losslessly as this crate's
        // UTF-8 wire path (see `path_to_wire_relative_string`'s own doc
        // comment) is treated as a no-op event -- better than silently
        // colliding it with some other file via lossy conversion. Logged,
        // since this is a live watcher event a user might reasonably
        // expect to have been synced.
        let Some(rel_path) = path_to_wire_relative_string(rel_path) else {
            tracing::warn!(
                group_id,
                path = %event.path.display(),
                "skipping a local change event for a path that cannot be represented \
                 losslessly as this crate's UTF-8 wire path"
            );
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        };
        if rel_path.is_empty() {
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        }
        if is_ignore_file_relative_path(Path::new(&rel_path)) {
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        }

        if is_excluded_from_sync(&rel_path, event.path.is_dir(), ignore_set) {
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        }

        // hold the per-(group,path) lock for the whole
        // read-compare-write below, so this local-change indexing can
        // never interleave with `PeerSyncSession::reconcile_one_file`
        // applying an incoming version for the same path concurrently —
        // see `LocalMutationStore::path_lock`'s doc comment.
        let path_lock = self.state.path_lock(group_id, &rel_path);
        let _guard = path_lock.lock().await;

        // `event.kind` reflects whatever `debounce.rs`'s per-path
        // coalescing last saw
        // -- a `HashMap<PathBuf, FsChangeKind>` where a later event for
        // the same path simply overwrites an earlier one. A genuine local
        // deletion's `Removed` event can be overwritten within the same
        // debounce window by an unrelated `CreatedOrModified` event for
        // the identical path -- most commonly this device's own sync
        // engine materializing an incoming peer update (a real disk
        // write the watcher can't distinguish from a genuine local edit)
        // racing this device's own delete -- silently discarding the
        // fact that a deletion ever happened, with no error and no
        // trace: `mark_deleted` (the `Removed` branch below) is simply
        // never called for this flush. Re-deriving whether the path is
        // currently a live entry directly from disk here, immediately
        // before dispatch, rather than trusting the coalesced kind,
        // closes this whole class of watcher-kind-vs-reality mismatches
        // symmetrically (a stale `CreatedOrModified` whose target has
        // since been deleted is exactly as wrong as a stale `Removed`
        // whose target has since been recreated) -- this is the same
        // principle Syncthing (`lib/model/folder.go`'s `scanSubdirs`,
        // reached via its watch-aggregator regardless of the aggregated
        // event kind), Nextcloud desktop (`discovery.cpp`'s `localEntry`
        // re-stat, ignoring `FolderWatcher`'s untyped path-only signal),
        // and Unison (diffing current disk state against the last-synced
        // archive) all independently converge on: the watcher is a
        // trigger to re-examine a path, not a source of truth for
        // classifying what happened to it. `symlink_metadata` (not
        // `Path::exists`, which follows symlinks) matches this file's
        // own lstat-first convention elsewhere (see
        // `build_record_for_created_or_modified`'s identical check just
        // below, and `is_real_directory` in `watcher.rs`).
        let effective_kind = if event.path.symlink_metadata().is_ok() {
            FsChangeKind::CreatedOrModified
        } else {
            FsChangeKind::Removed
        };

        match effective_kind {
            FsChangeKind::Removed => {
                // `mark_deleted` creates a brand-new tombstone row
                // even for a path that was never indexed — an editor's
                // atomic-save (temp file created then renamed away)
                // coalesces to exactly this case, and peers would
                // otherwise receive and store a tombstone for a file they
                // never had, accumulating mesh-wide junk over repeated
                // saves. Only mark-deleted (and broadcast) a path that
                // already has an index entry.
                let existing_for_delete = self.state.get_file(group_id, &rel_path)?;
                if existing_for_delete.is_none() {
                    // `rel_path` itself was never a tracked file (a
                    // directory is never its own index row), but it may
                    // just have been a directory that disappeared —
                    // deleted outright, or renamed away (`watcher.rs`'s
                    // `RenameMode::From` reports the vacated directory
                    // path itself as an ordinary `Removed` event, no
                    // different from a single file's delete; nothing
                    // synthesizes an individual event for whatever used
                    // to live inside it). If this device still has any
                    // live records filed under `rel_path` as a directory
                    // prefix, they are now orphaned: the directory that
                    // held them is confirmed gone from disk, so a later
                    // local recreation at the exact same relative path
                    // must not find that stale row still "existing" and
                    // treat a brand-new write as an edit to it, silently
                    // inheriting whatever version-vector history a peer
                    // may have since merged into it (confirmed via
                    // `taguchi_collision_matrix_v3.rs`'s row 9: a real,
                    // reproducible silent-content-loss shape, not merely
                    // a convergence delay).
                    let prefix = format!("{rel_path}/");
                    let orphaned: Vec<String> = self
                        .state
                        .list_files(group_id)?
                        .into_iter()
                        .filter(|r| !r.deleted && r.path.starts_with(&prefix))
                        .map(|r| r.path)
                        .collect();
                    if orphaned.is_empty() {
                        return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
                    }
                    let now = observed_at_unix_nanos.unwrap_or_else(now_unix_nanos);
                    let mut records = Vec::with_capacity(orphaned.len());
                    for orphan_path in &orphaned {
                        match &self.change_emitter {
                            Some(emitter) => {
                                self.state.mark_deleted_emitting_change(
                                    group_id,
                                    orphan_path,
                                    &self.device_id,
                                    now,
                                    // No Absent proof here: the path lock
                                    // this call holds (`_guard`, acquired
                                    // above) covers `rel_path` (the
                                    // directory that vanished), not
                                    // `orphan_path` itself -- `orphaned`
                                    // was a lock-free snapshot read
                                    // (`list_files`), so there is no
                                    // revalidation-under-this-path's-own-
                                    // lock guarantee to publish a proof
                                    // against. Always safe to decline;
                                    // costs nothing on this already-rare
                                    // orphaned-directory-cleanup path.
                                    false,
                                    emitter,
                                    &self.begin_operation()?.permit(),
                                )?;
                            }
                            None => {
                                self.state.mark_deleted_at(
                                    group_id,
                                    orphan_path,
                                    &self.device_id,
                                    now,
                                    &self.begin_operation()?.permit(),
                                )?;
                            }
                        }
                        if let Some(record) = self.state.get_file(group_id, orphan_path)? {
                            records.push(record);
                        }
                    }
                    return Ok(EventOutcome::Ready(LocalChangeOutcome::FilesChanged(records)));
                }
                let observed = observed_at_unix_nanos.unwrap_or_else(now_unix_nanos);
                match &self.change_emitter {
                    Some(emitter) => {
                        // The simple, common delete case: an existing row,
                        // a real emitter -- eligible to defer into a shared
                        // batch commit instead of committing here. Builds
                        // the exact same tombstone `FileRecord`
                        // `mark_deleted_emitting_change` builds internally
                        // (deleted=true, mtime stamped with this event's
                        // observed time, everything else carried forward
                        // from the current row) so the batched and
                        // immediate paths produce byte-identical rows.
                        if let Some(batch) = pending_batch {
                            let mut record = existing_for_delete.clone().unwrap_or_else(|| FileRecord {
                                path: rel_path.clone(),
                                size: 0,
                                mtime_unix_nanos: 0,
                                blocks: vec![],
                                deleted: false,
                            });
                            record.deleted = true;
                            record.mtime_unix_nanos = observed;
                            let op = Op::Delete { path: SyncPath(rel_path.clone()) };
                            let authoring_change_hash_at_prepare =
                                self.state.get_authoring_change_hash(group_id, &rel_path)?;
                            batch.push(PendingBatchedCommit {
                                rel_path: rel_path.clone(),
                                event_path: event.path.clone(),
                                observed_at_unix_nanos: observed,
                                index_state_at_prepare: existing_for_delete,
                                authoring_change_hash_at_prepare,
                                disk_fingerprint_at_prepare: disk_race_fingerprint(&event.path),
                                mutation:
                                    yadorilink_replica_domain::session_state::PreparedLocalMutation::Delete {
                                        record,
                                        op,
                                    },
                            });
                            return Ok(EventOutcome::Deferred);
                        }
                        self.state.mark_deleted_emitting_change(
                            group_id,
                            &rel_path,
                            &self.device_id,
                            observed,
                            // Safe to publish an Absent proof here:
                            // `effective_kind`'s own `symlink_metadata`
                            // re-check (this function's entry) confirmed
                            // `rel_path` -- the SAME path `_guard` above
                            // locks for this whole call -- is gone from
                            // disk, immediately before this branch and
                            // under that same lock the whole way through.
                            true,
                            emitter,
                            &self.begin_operation()?.permit(),
                        )?;
                    }
                    None => {
                        self.state.mark_deleted_at(
                            group_id,
                            &rel_path,
                            &self.device_id,
                            observed,
                            &self.begin_operation()?.permit(),
                        )?;
                    }
                }
                Ok(EventOutcome::Ready(match self.state.get_file(group_id, &rel_path)? {
                    Some(record) => LocalChangeOutcome::FileChanged(record),
                    None => LocalChangeOutcome::None,
                }))
            }
            FsChangeKind::CreatedOrModified => {
                let materialization_state =
                    self.state.get_materialization_state(group_id, &rel_path)?;
                let placeholder_generation =
                    self.state.get_placeholder_generation(group_id, &rel_path)?;
                let existing = self.state.get_file(group_id, &rel_path)?;
                // Cloned before the call below moves `existing` --
                // `PendingBatchedCommit` needs its own snapshot of the
                // index state this preparation was based on, to revalidate
                // against later at batch-commit time. Captured together so
                // both reflect the identical moment.
                let existing_at_prepare = existing.clone();
                let authoring_change_hash_at_prepare =
                    self.state.get_authoring_change_hash(group_id, &rel_path)?;
                // Captured before this event's own content read below, so
                // the eventual commit-time proof-publication check
                // (`fingerprint_before_content_read == disk_race_
                // fingerprint(&event.path)` immediately before the
                // single-immediate commit call, further down) can detect a
                // race across the WHOLE read-through-commit window, not
                // just the narrower prepare-to-commit window the batched
                // path's own `disk_fingerprint_at_prepare` already covers.
                let fingerprint_before_content_read = disk_race_fingerprint(&event.path);
                let (outcome, classification, unix_mode) = self
                    .build_record_for_created_or_modified(
                        group_id,
                        &root,
                        rel_path.clone(),
                        &event.path,
                        existing,
                        materialization_state,
                        placeholder_generation,
                    )?;
                if let LocalChangeOutcome::FileChanged(record) = &outcome {
                    // Re-verified here, immediately before the commit below,
                    // not just relied on from this function's entry check
                    // above: `build_record_for_created_or_modified` just did
                    // this event's actual file I/O and chunking/hashing,
                    // which for a large file is real elapsed time during
                    // which this process's OS root lock could have had its
                    // sidecar unlinked-and-recreated out from under it (see
                    // `verified_root_of_established_link`'s own doc for that
                    // race). Closing that window at commit time, not only at
                    // dispatch time, is what a single entry-time check
                    // cannot do. This used to be a standalone `self.
                    // verified_root_of_established_link(group_id, &root)?`
                    // call here; that re-check is now folded into
                    // `self.begin_operation()?.permit()`'s own `verify` (called by each
                    // `LocalMutationStore` mutation below, immediately before its
                    // commit), alongside the daemon's lifecycle-fence check
                    // the standalone call never covered.
                    // A local edit's origin is this device itself.
                    match &self.change_emitter {
                        Some(emitter) => {
                            let symlink_target = classification.as_ref().map(|c| c.target.clone());
                            // A fresh open, not the same handle
                            // `build_record_for_created_or_modified` chunked
                            // through above -- a weaker same-bytes guarantee
                            // than `single_pass_capture.rs`'s own xattr read,
                            // but xattrs are a best-effort metadata capture
                            // (see `read_replicated_xattrs`'s own doc
                            // comment), not content integrity, so a rare
                            // race here reads as "no attributes this time,"
                            // never a corrupt result. Never scanned for a
                            // symlink, matching `unix_mode`'s own `None`
                            // there.
                            let xattrs = if classification.is_none() {
                                std::fs::File::open(&event.path)
                                    .map(|file| read_replicated_xattrs(&file))
                                    .unwrap_or_default()
                            } else {
                                Vec::new()
                            };
                            let (op, version) = self.content_op(
                                record,
                                unix_mode.flatten(),
                                symlink_target.clone(),
                                xattrs.clone(),
                            );
                            // The record kind / symlink target / out-of-root
                            // flag / exec bit are written in the SAME
                            // transaction as the emitted change (folded into
                            // `upsert_file_emitting_change`), mirroring exactly
                            // the `FileMeta` `content_op` put in the
                            // `FileVersion` above. A crash can therefore never
                            // leave the index row's metadata columns lagging
                            // the change's `FileVersion` — the old post-commit
                            // `set_*` setters are gone from this emit path.
                            let meta = metadata_columns_for(&classification, unix_mode, xattrs);
                            // The simple, common create/modify case: not a
                            // symlink, a real emitter -- eligible to defer
                            // into a shared batch commit instead of
                            // committing here. A symlink
                            // (`classification.is_some()`) always commits
                            // immediately below, unbatched -- rare enough
                            // that it is not worth the added complexity of
                            // proving its batched revalidation covers the
                            // same identity/target checks this path relies
                            // on elsewhere.
                            if classification.is_none() {
                                if let Some(batch) = pending_batch {
                                    batch.push(PendingBatchedCommit {
                                        rel_path: rel_path.clone(),
                                        event_path: event.path.clone(),
                                        observed_at_unix_nanos: observed_at_unix_nanos
                                            .unwrap_or_else(now_unix_nanos),
                                        index_state_at_prepare: existing_at_prepare,
                                        authoring_change_hash_at_prepare,
                                        disk_fingerprint_at_prepare: disk_race_fingerprint(&event.path),
                                        mutation:
                                            yadorilink_replica_domain::session_state::PreparedLocalMutation::Upsert {
                                                record: record.clone(),
                                                op,
                                                version,
                                                meta: Some(meta),
                                            },
                                    });
                                    return Ok(EventOutcome::Deferred);
                                }
                            }
                            // M6-2 phase-timing diagnostic (temporary): see
                            // chunker.rs's matching M6PHASE comment for why
                            // this exists.
                            tracing::warn!("M6PHASE T_author_start: authoritative FileRecord/DAG commit begins");
                            let filesystem_identity = fresh_actual_state_identity_if_unraced(
                                &event.path,
                                fingerprint_before_content_read,
                            );
                            self.state.upsert_file_emitting_change(
                                group_id,
                                record,
                                &self.device_id,
                                ChangeContent {
                                    ops: vec![op],
                                    versions: std::slice::from_ref(&version),
                                },
                                Some(&meta),
                                filesystem_identity.as_ref(),
                                crate::ports::LocalChangeEmission {
                                    emitter,
                                    permit: &self.begin_operation()?.permit(),
                                },
                            )?;
                            tracing::warn!("M6PHASE T_author_done: authoritative FileRecord/DAG commit completes");
                        }
                        None => {
                            tracing::warn!("M6PHASE T_author_start: authoritative FileRecord/DAG commit begins");
                            self.state.upsert_file_with_origin(
                                group_id,
                                record,
                                &self.device_id,
                                &self.begin_operation()?.permit(),
                            )?;
                            // `upsert_file_with_origin` is a generic primitive
                            // shared with peer-driven callers, so it cannot
                            // stamp `Hydrated` unconditionally the way the
                            // local-emission-only upsert functions do -- this
                            // call site must do it itself. Just as safe to do
                            // so here as in the `Some` arm's `upsert_file_
                            // emitting_change` above: `record`'s bytes were
                            // read from this device's own disk to build it,
                            // same precondition, only the DAG-emission step is
                            // skipped (no signing key provisioned yet).
                            if !record.deleted {
                                self.state.set_materialization_state(
                                    group_id,
                                    &record.path,
                                    MaterializationState::Hydrated,
                                    &self.begin_operation()?.permit(),
                                )?;
                            }
                            tracing::warn!("M6PHASE T_author_done: authoritative FileRecord/DAG commit completes");
                            // No DAG emission here (no signing key provisioned),
                            // so there is no DAG/index divergence hazard: apply
                            // the metadata columns as ordinary post-write
                            // updates. The setters are `UPDATE`-only and require
                            // the row the write above just created.
                            if let Some(classification) = &classification {
                                self.apply_symlink_classification(
                                    group_id,
                                    &rel_path,
                                    classification,
                                )?;
                            }
                            if let Some(unix_mode) = unix_mode {
                                self.state.set_unix_mode(
                                    group_id,
                                    &rel_path,
                                    unix_mode,
                                    &self.begin_operation()?.permit(),
                                )?;
                            }
                        }
                    }
                }
                Ok(EventOutcome::Ready(outcome))
            }
        }
    }

    /// Builds the `FileRecord` for a `CreatedOrModified` event without
    /// writing it to the index — shared by `process_event` (which writes
    /// immediately, one file at a time) and `scan_existing_files` (which
    /// batches writes via `upsert_files_batch`, batch-processing changes
    /// ). `existing` and `materialization_state` are supplied by
    /// the caller rather than looked up here, so a bulk-loading caller
    /// (`scan_existing_files`) never issues a per-file query for them.
    ///
    /// The third element of the returned tuple
    /// (see [`PendingUnixModeUpdate`]) is the Unix permission bits to
    /// persist via `LocalMutationStore::set_unix_mode`, when this call determined a
    /// value needs capturing. Returned rather
    /// than applied directly here, mirroring `SymlinkClassification`'s own
    /// "apply after write" shape: `set_unix_mode` is `UPDATE`-only and the
    /// index row may not exist yet at this point (a brand-new file, not
    /// written until the caller's `upsert_file_with_origin`/
    /// `upsert_files_batch` runs).
    /// `materialization_state` and `placeholder_generation` are two
    /// separate, independently-`None`-able lookups (a row can have a
    /// materialization state with no recorded identity, e.g. right after
    /// this build's own migration) -- bundling them into one struct would
    /// obscure that rather than clarify it, so this stays a plain argument
    /// list at 8 rather than introducing a parameter object.
    #[allow(clippy::too_many_arguments)]
    fn build_record_for_created_or_modified(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: String,
        path: &Path,
        existing: Option<FileRecord>,
        materialization_state: Option<MaterializationState>,
        placeholder_generation: Option<yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
    ) -> Result<(LocalChangeOutcome, Option<SymlinkClassification>, PendingUnixModeUpdate), LocalCaptureError>
    {
        // M6-2 phase-timing diagnostic (temporary): see chunker.rs's
        // matching M6PHASE comment for why this exists.
        tracing::warn!("M6PHASE T_capture_start: local capture entry (build_record_for_created_or_modified)");
        // classify via an lstat-equivalent check first —
        // `symlink_metadata` never follows the final path component,
        // unlike `Path::is_file`/`std::fs::metadata` (used further below,
        // now only reached once a symlink has already been ruled out
        // here, so those later calls are safe to leave following-by-
        // default: at that point `path` is confirmed to be a genuine
        // regular file, not a symlink, so stat and lstat agree anyway).
        let Ok(lstat) = std::fs::symlink_metadata(path) else {
            return Ok((LocalChangeOutcome::None, None, None)); // already gone again
        };

        // Test-only synchronization seam: deterministically reproduces the
        // TOCTOU race this function's own chunk attempt further below can
        // hit against a write-then-rename save landing between this lstat
        // (which just proved `path` exists) and the chunker's later
        // `fs::metadata`/`File::open` on the same `path` — see
        // `is_source_path_vanished_error`'s doc comment for the full
        // explanation. No effect outside `#[cfg(test)]` builds.
        #[cfg(test)]
        fire_race_after_lstat_hook(path);

        if lstat.file_type().is_symlink() {
            let (outcome, classification) =
                self.build_symlink_record(group_id, root, rel_path, path, existing, &lstat)?;
            return Ok((outcome, classification, None));
        }

        if !lstat.is_file() {
            return Ok((LocalChangeOutcome::None, None, None)); // directory event, or exotic entry
        }

        // A placeholder's own creation/refresh (`peer_session::materialize`
        // writing a sparse file for an `OnDemand` folder — see
        // `chunker::write_placeholder`) fires this same
        // `CreatedOrModified` event on this device's own watcher. Its
        // content is a sparse stand-in, not the file's real bytes, so
        // chunking it would both waste effort and index wrong block
        // hashes — skip immediately, mirroring the self-echo suppression
        // below but before the expensive (and here, actively incorrect)
        // chunking step.
        //
        // BUT only when the on-disk object is PROVEN to still be this
        // crate's own untouched placeholder -- via `placeholder_generation`
        // (M1-2), the `(dev, ino)` identity `write_placeholder` captured
        // and persisted when it created this exact file, compared here
        // against the identity `lstat` (already fetched above) reports for
        // whatever object is at `path` right now. This platform has no
        // real OS-level transparent-hydration provider wired up yet (no
        // Cloud Filter API reparse point on Windows, no File Provider item
        // on macOS -- see `chunker::write_placeholder`'s own doc comment),
        // so a `Placeholder` row's on-disk file is, today, an ORDINARY
        // sparse file sitting at an ordinary path: nothing stops a user
        // (or an editor that doesn't know or care it's "just a
        // placeholder") from opening and overwriting it directly.
        // Unconditionally treating every `CreatedOrModified` on a
        // `Placeholder` path as this crate's own echo -- as this check
        // used to, with no comparison at all -- silently and PERMANENTLY
        // discarded such an edit: never chunked, never indexed, and the
        // next `hydrate` would then overwrite it again with the stale
        // synced content, with no error, no warning, and no way for the
        // user to discover their edit was ever lost.
        //
        // Deliberately NOT a size/mtime/sparse-file comparison anymore --
        // an earlier version of this check used exactly that, and an
        // independent review found the residual gap it could never close:
        // an edit that happens to preserve both byte length and mtime (an
        // in-place same-length overwrite, or any writer that restores
        // mtime via `utimes`/`touch -r` after editing) was invisible to
        // it. `(dev, ino)` closes this: a same-size/mtime edit performed
        // via an atomic-rename save (the common case for ordinary editors)
        // still mints a fresh inode, so it is caught here even though it
        // would have slipped past the old heuristic. An in-place
        // truncate-and-rewrite that reuses the same inode is the one edit
        // shape this still cannot distinguish from an untouched
        // placeholder -- accepted as the same class of residual gap the
        // old heuristic already had, not a new one, and one only a real
        // OS-transparent provider closes for good.
        //
        // `provider_kind` is checked too: only `INTERNAL_INODE_PROVIDER_KIND`
        // is a `(dev, ino)` comparison this process can perform itself. A
        // future real OS provider's own token needs its own comparison
        // logic, not this one, so an unrecognized kind falls through to
        // the ordinary local-edit path below rather than being silently
        // (and wrongly) compared as if it were an inode pair.
        if let Some(MaterializationState::Placeholder) = materialization_state {
            if untouched_placeholder_verdict(
                self.state.as_ref(),
                path,
                &lstat,
                existing.as_ref(),
                placeholder_generation.as_ref(),
            ) {
                return Ok((LocalChangeOutcome::None, None, None));
            }
            // Not proven untouched -- do NOT silently discard the event:
            // fall through to the same ordinary local-edit path (chunk,
            // compare, index) any other `CreatedOrModified` event takes.
        }

        // a size+mtime fast-path, checked before
        // any chunking. A filesystem watcher routinely reports a
        // `CreatedOrModified` event for a file whose bytes never actually
        // changed — this device's own self-echo (see the block-hash
        // comparison further down, which already resolves this case to
        // `None`, just after paying for a full read+chunk+hash first), an
        // editor's atomic rewrite that restores identical content, or a
        // backup/sync tool that bumps mtime without touching bytes. When
        // both `size` *and* `mtime` match a non-deleted index entry, that
        // is only "probably unchanged": a `stat` is orders of magnitude
        // cheaper than reading and chunking the whole file, but it is not,
        // on its own, a correctness guarantee.
        //
        // For data integrity we must not trust the stat verdict blindly.
        // A content edit that preserves BOTH byte length and mtime — an
        // in-place same-length overwrite, or any writer that restores the
        // mtime via `utimes`/`touch -r` after editing — would otherwise be
        // silently missed here, pinning the index (and every peer) at the
        // stale version while disk holds new bytes. So before taking the
        // no-op path, verify the on-disk bytes against the indexed block
        // hashes with `disk_bytes_match_indexed_blocks`: it streams the
        // file comparing each indexed block's SHA-256 in sequence and
        // early-exits on the first mismatch, without re-chunking (no
        // content-defined boundary search) and without writing any block to
        // the store — much cheaper than the full chunk path, and it runs
        // only for files that already passed the cheap size+mtime gate.
        // Cheaper is not cheap, though: for a large file it is still a full
        // sequential read plus a SHA-256 per indexed block, and this fast
        // path sits on the live `process_event` route, awaited directly on
        // a tokio worker with nothing above it offloading anything. Hence
        // `disk_bytes_match_indexed_blocks_off_worker` rather than the bare
        // verifier — identical verdict, but a large file's pass no longer
        // runs with a worker core held for its duration. If
        // the bytes differ, this whole fast-path is skipped and the edit
        // falls through to the full chunk-and-compare path below, which
        // re-versions the record and emits the change.
        if let Some(existing) = &existing {
            if !existing.deleted {
                if let Ok(metadata) = std::fs::metadata(path) {
                    let current_mtime_matches =
                        metadata_mtime_matches(&metadata, existing.mtime_unix_nanos);
                    if existing.size == metadata.len()
                        && current_mtime_matches
                        && disk_bytes_match_indexed_blocks_off_worker(
                            path,
                            &existing.blocks,
                            metadata.len(),
                        )?
                    {
                        // size, mtime, AND content are all verified
                        // identical here — but that still isn't the whole
                        // "nothing changed" story: a `chmod` (owner-exec bit
                        // toggle) touches none of them, so compare the exec
                        // bit too, off the same `Metadata` already fetched
                        // above (no extra syscall), before trusting this
                        // fast path's no-op conclusion. When only the exec
                        // bit differs, this
                        // is exactly the "metadata-only change" shape
                        // `try_apply_metadata_only_update` (`peer_session.
                        // rs`) already applies on the receiving side for a
                        // peer's advertised bit — mirrored here for local
                        // capture: bump the version (broadcast-worthy)
                        // without re-chunking.
                        let on_disk_unix_mode = unix_mode_from_metadata(&metadata);
                        let indexed_unix_mode = self.state.get_unix_mode(group_id, &rel_path)?;
                        // Same reasoning as the exec bit just above, for
                        // extended attributes (C1.2a): a `setxattr`-only
                        // edit touches none of size/mtime/content/unix_mode
                        // either, so it must be checked here too, or it is
                        // silently and permanently dropped -- never
                        // captured, never emitted, and a peer's next sync
                        // would overwrite this device's real xattr edit
                        // with the stale indexed value.
                        let on_disk_xattrs = std::fs::File::open(path)
                            .map(|f| read_replicated_xattrs(&f))
                            .unwrap_or_default();
                        let indexed_xattrs = self.state.get_xattrs(group_id, &rel_path)?;
                        if on_disk_unix_mode == indexed_unix_mode
                            && on_disk_xattrs == indexed_xattrs
                        {
                            // size, mtime, exec bit, AND xattrs all
                            // unchanged — preserve the existing no-op
                            // behavior exactly.
                            return Ok((LocalChangeOutcome::None, None, None));
                        }
                        let record = existing.clone();
                        return Ok((
                            LocalChangeOutcome::FileChanged(record),
                            None,
                            Some(on_disk_unix_mode),
                        ));
                    }
                }
            }
        }

        // Chunking algorithm is chosen automatically from file size: files
        // at or above the size threshold use content-defined chunking (so
        // an internal edit re-transfers only the affected region), and
        // everything below uses the original fixed-size chunker. Self-echo
        // suppression below just compares whatever this device's chunker
        // produced against what's indexed, so it needs no algorithm-
        // awareness either way.
        let use_cdc = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) >= CDC_SIZE_THRESHOLD;
        // Offloaded, not a bare synchronous call — for a large
        // (CDC-eligible) file this scan (chunk + hash + a real
        // `fsync`-backed `store.put` per block) runs long enough (13-20s
        // for 1 GiB, confirmed via timing diagnostics) that running it
        // in place on a tokio worker would occupy that worker for the
        // whole span, exactly the class of bug `reconstruct_file_off_
        // runtime` (peer_session.rs) already fixed on the receive side.
        // Via `run_capture_pass_off_worker`, NOT a bare
        // `tokio::task::block_in_place`. Same primitive underneath, and
        // for the same reason (a scoped closure needs no `Send + 'static`
        // ownership transfer, so it fits `self` being a plain
        // `&LocalChangeProcessor` at both call sites with zero refactor of
        // `self`/`store` access) — but the bare form
        // was a latent panic and a build break. `block_in_place` panics
        // unless a multi-threaded runtime is current, and it does not
        // exist at all in the deterministic simulator's tokio shim, so the
        // bare call failed to compile under `--cfg madsim` and would have
        // panicked outright had this path ever been reached from a
        // current-thread runtime — which it can be: this whole function is
        // reachable from the synchronous `scan_existing_files` public API.
        // See that helper's own doc comment for the guard and for the
        // bound it buys.
        //
        // `YADORILINK_DIAGNOSTIC_FORCE_FIXED_CHUNKING=1`
        // routes a file that would normally take the CDC branch (`use_cdc`)
        // through `chunk_file_fixed_with_callback` instead of content-
        // defined chunking -- same hash-once/bulk-commit pipeline, only the
        // boundary-selection algorithm differs.
        // Isolates whether `fastcdc`'s own rolling-hash cost, specifically,
        // is what dominates `capture -> chunk EOF` (found to be 73-86% of
        // `T_detect` for a real 1 GiB transfer). Not a production
        // chunking-policy change -- `use_cdc`'s own decision is untouched
        // when this env var is unset (every existing caller/test).
        let force_fixed = use_cdc
            && std::env::var("YADORILINK_DIAGNOSTIC_FORCE_FIXED_CHUNKING").as_deref() == Ok("1");
        let chunk_result = run_capture_pass_off_worker(|| -> Result<_, LocalCaptureError> {
            Ok(if force_fixed {
                yadorilink_local_storage::chunk_file_fixed_with_callback(
                    self.store.as_ref(),
                    path,
                    |_, _: std::sync::Arc<[u8]>| {},
                )?
            } else if use_cdc {
                chunk_file_content_defined(self.store.as_ref(), path)?
            } else {
                chunk_file(self.store.as_ref(), path)?
            })
        });
        let blocks = match chunk_result {
            Ok(blocks) => blocks,
            // The lstat above already confirmed `path` existed when this
            // attempt started, but a write-then-rename save pattern (write
            // to a sibling temp path, then `fs::rename` onto the final
            // name — used by both ordinary atomic-save editors and this
            // benchmark's own large-file writer) can complete its rename
            // in the narrow window between that lstat and the chunker's
            // own `fs::metadata`/`File::open` a few lines later —
            // especially for a large file, where the debounce
            // accumulator's per-path quiet period can legitimately elapse
            // for the temp path's own "modified" events just as the
            // writer finishes and renames it away. When `path` is proven
            // GONE (see `is_source_path_vanished_error`: the `NotFound`
            // error shape alone does NOT prove that — it re-stats `path`
            // itself, because a block-store fault produces the identical
            // error shape and must stay on the retry/journal path), this
            // is the exact same benign, expected race the lstat guard
            // above already treats as "already gone again" rather than an
            // error, so extend that same verdict here. Falling through to
            // `is_retriable_block_store_error` instead would waste up to
            // `MAX_LOCAL_INDEX_RETRIES` retries against a path that can
            // never come back, or — worse — occasionally "succeed" against
            // a since-fully-rewritten file, indexing a spurious record
            // under what was only ever a transient rename artifact. The
            // rename's own watcher event independently queues a fresh
            // `CreatedOrModified` for the file's real final name (see
            // `watcher.rs`'s `RenameMode::To`/`Both` handling), so nothing
            // is silently dropped here.
            Err(e) if is_source_path_vanished_error(&e, path) => {
                return Ok((LocalChangeOutcome::None, None, None));
            }
            Err(e) => return Err(e),
        };
        // Chunking has read these bytes from this group's local filesystem,
        // hashed them, and durably put them in the shared physical store.
        // Record that fact separately from peer-controlled metadata so block
        // serving cannot infer group ownership from a FileVersion reference.
        let block_hashes: Vec<Vec<u8>> = blocks.iter().map(|block| block.hash.clone()).collect();
        self.state.record_group_block_provenance(group_id, &block_hashes)?;

        // Content-addressed dedup, applied here as self-echo suppression:
        // applying a peer's update writes the file to disk
        // (`peer_session::materialize`), which — with no special-casing —
        // this *same* watcher would otherwise see as a brand-new local
        // edit, increment the version for, and rebroadcast, which the
        // peer's own watcher then does right back, forever, racing into
        // spurious conflicts. If the
        // freshly chunked content hashes to exactly the blocks already
        // indexed, nothing actually changed — regardless of *why* the fs
        // event fired — so there is nothing to re-index.
        //
        // But — same lesson as the size+mtime fast path above — matching
        // CONTENT still is not the whole "nothing changed" story: a
        // chmod-only edit changes neither bytes nor (on every POSIX
        // platform) mtime, so it can reach this content-only comparison
        // (e.g. via the same-size-in-place-overwrite path, or any other
        // route that skips the fast path above) with its content hash
        // still matching what's indexed, yet its exec bit genuinely
        // diverged from what's indexed. Unconditionally returning `None`
        // here — as this check used to, with no exec-bit comparison at
        // all — silently and permanently dropped that divergence: never
        // captured, never emitted, and the next materialize on a peer
        // would eventually overwrite this device's real exec-bit edit
        // with the stale indexed value. Compare the exec bit too, off a
        // fresh `stat`, before trusting the content match's "no-op"
        // verdict — mirroring the fast path's own exec-bit check exactly.
        if let Some(existing) = &existing {
            if !existing.deleted && existing.blocks == blocks {
                if let Ok(metadata) = std::fs::metadata(path) {
                    let on_disk_unix_mode = unix_mode_from_metadata(&metadata);
                    let indexed_unix_mode = self.state.get_unix_mode(group_id, &rel_path)?;
                    // Same reasoning as the exec-bit check just above, for
                    // extended attributes (C1.2a) -- see the size+mtime
                    // fast path's own identical comment for the full
                    // rationale.
                    let on_disk_xattrs = std::fs::File::open(path)
                        .map(|f| read_replicated_xattrs(&f))
                        .unwrap_or_default();
                    let indexed_xattrs = self.state.get_xattrs(group_id, &rel_path)?;
                    if on_disk_unix_mode != indexed_unix_mode || on_disk_xattrs != indexed_xattrs {
                        // Content is genuinely unchanged (so no re-chunk,
                        // no re-versioned block list), but the exec bit is
                        // a real, local, user-initiated divergence — bump
                        // the version and emit it, the same
                        // "metadata-only change" shape the fast path
                        // above already applies.
                        return Ok((
                            LocalChangeOutcome::FileChanged(existing.clone()),
                            None,
                            Some(on_disk_unix_mode),
                        ));
                    }
                }
                return Ok((LocalChangeOutcome::None, None, None));
            }
        }

        let metadata = std::fs::metadata(path)?;
        let mtime_unix_nanos = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        // content genuinely changed
        // (or this is a brand-new file), reached below the fast path above
        // — capture the exec bit here too, off the same `Metadata` already
        // fetched for `mtime_unix_nanos`, so a brand-new executable file's
        // exec bit is indexed from its first appearance rather than only
        // discoverable later via a subsequent metadata-only update.
        let unix_mode = unix_mode_from_metadata(&metadata);

        let record = FileRecord {
            path: rel_path,
            size: metadata.len(),
            mtime_unix_nanos,
            blocks,
            deleted: false,
        };
        Ok((LocalChangeOutcome::FileChanged(record), None, Some(unix_mode)))
    }

    /// Builds a symlink leaf record: the target's raw text
    /// and the out-of-root/absolute flag, never dereferencing the target
    /// to decide either. No content is read or chunked — a symlink record
    /// carries no blocks.
    fn build_symlink_record(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: String,
        path: &Path,
        existing: Option<FileRecord>,
        lstat: &std::fs::Metadata,
    ) -> Result<(LocalChangeOutcome, Option<SymlinkClassification>), LocalCaptureError> {
        // `read_link` reads the raw target without dereferencing it —
        // safe, unlike `metadata`/`canonicalize`, which is exactly the
        // dereference that is forbidden. `target_to_bytes` is the same raw,
        // platform-native byte conversion `fs_identity`'s own symlink-target
        // digest uses (never a lossy UTF-8 conversion) — see `change::
        // FileMeta::symlink_target`'s doc for why a symlink's captured
        // target must be these exact bytes.
        let raw_target = std::fs::read_link(path)?;
        let target_bytes = yadorilink_root_authority::fs_identity::target_to_bytes(&raw_target);
        let out_of_root = symlink_target_is_out_of_root(root, path, &raw_target);
        // `size` is derived from the same buffer as the target, not a
        // separately obtained stat length, so the two can never disagree —
        // consistent by construction rather than by a cross-check.
        let size = target_bytes.len() as u64;
        let mtime_unix_nanos = lstat
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        // Self-echo/no-op suppression, mirroring the regular-file
        // fast-path above: a redundant watcher event (or an unchanged
        // rescan) for a symlink whose target hasn't actually changed must
        // not bump the version vector every time it fires. `size` alone
        // can't disambiguate two different targets of the same length, so
        // the actual stored target bytes are checked too — a lookup bounded
        // to symlink paths only, not every scanned file.
        if let Some(existing) = &existing {
            if !existing.deleted && existing.size == size {
                let previously_symlink =
                    self.state.get_record_kind(group_id, &rel_path)? == Some(RecordKind::Symlink);
                let previous_target = self.state.get_symlink_target(group_id, &rel_path)?;
                if previously_symlink && previous_target.as_deref() == Some(target_bytes.as_slice())
                {
                    return Ok((LocalChangeOutcome::None, None));
                }
            }
        }

        let record = FileRecord {
            path: rel_path,
            size,
            mtime_unix_nanos,
            blocks: Vec::new(),
            deleted: false,
        };
        let classification = SymlinkClassification { target: target_bytes, out_of_root };
        Ok((LocalChangeOutcome::FileChanged(record), Some(classification)))
    }

    /// Applies a symlink's classification to its already-
    /// written index row — `LocalMutationStore::set_record_kind`/
    /// `set_symlink_target`/`set_symlink_out_of_root` all require the row
    /// to exist, so this must run strictly after the caller's
    /// `upsert_file`/`upsert_files_batch`.
    fn apply_symlink_classification(
        &self,
        group_id: &str,
        rel_path: &str,
        classification: &SymlinkClassification,
    ) -> Result<(), LocalCaptureError> {
        self.state.set_record_kind(
            group_id,
            rel_path,
            RecordKind::Symlink,
            &self.begin_operation()?.permit(),
        )?;
        self.state.set_symlink_target(
            group_id,
            rel_path,
            Some(classification.target.as_slice()),
        )?;
        self.state.set_symlink_out_of_root(group_id, rel_path, classification.out_of_root)?;
        Ok(())
    }

    /// Turns one debounce-window flush (`debounce::DebounceFlush`) into
    /// indexed records — the executor half of 's accumulator/executor
    /// split. `DebounceFlush::Paths` is processed one path at a time via
    /// `process_event` (each individually indexed and self-echo-checked,
    /// exactly as a live single-event call would be); `DebounceFlush::RescanRequired`
    /// runs a full `scan_existing_files` reconciliation instead.
    ///
    /// Each path in a
    /// `DebounceFlush::Paths` batch is processed independently — one
    /// path's error (logged, not silently dropped) does not prevent the
    /// batch's other, unrelated paths from still being processed. A
    /// batch's paths come from a `HashMap` (no ordering guarantee), and
    /// the real filesystem watcher only ever fires once for a given real
    /// change: the previous behavior (`?` inside this loop, aborting the
    /// whole batch on the first error) could permanently lose an
    /// already-detected, unrelated event — including a local deletion
    /// that would otherwise have self-corrected a stale index row — to a
    /// transient failure (e.g. a exhausted-retry database-lock error
    /// under heavy concurrent load) on a completely different path
    /// earlier in iteration order.
    pub async fn process_flush(
        &self,
        group_id: &str,
        root: &Path,
        flush: DebounceFlush,
    ) -> Result<FlushOutcome, LocalCaptureError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        // `true`: this convenience entry point has no caller-supplied
        // fail-closed gate to respect, so it reproduces the historical
        // (pre-gating) behavior exactly -- every real production caller
        // goes through `process_flush_with_ignore` directly instead (see
        // `yadorilink-daemon`'s executor task), passing its own freshly-
        // computed gate.
        self.process_flush_with_ignore(group_id, root, flush, &ignore_set, true).await
    }

    /// `emit_tombstones` governs ONLY the `DebounceFlush::RescanRequired`
    /// case (`DebounceFlush::Paths` never emits a missing-file tombstone
    /// at all -- see `process_event`'s own per-path handling) -- see
    /// `scan_existing_files_with_ignore_gated_for_established_link`'s own
    /// doc comment for what this must be for a live caller (this link's
    /// startup-repair success ANDed with a FRESH read of the two-live-
    /// roots recovery flag, not a value frozen at link-start).
    pub async fn process_flush_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        flush: DebounceFlush,
        ignore_set: &EffectiveIgnoreSet,
        emit_tombstones: bool,
    ) -> Result<FlushOutcome, LocalCaptureError> {
        match flush {
            DebounceFlush::Paths(paths) => {
                // Precompute each path's dirty-journal key once (`relative_key`
                // canonicalizes `root`, a syscall) and carry it alongside the
                // rest of the tuple through both the batch-journal step below
                // and the per-path processing loop that follows, instead of
                // recomputing it twice per path.
                let paths: Vec<(PathBuf, FsChangeKind, i64, Option<String>)> = paths
                    .into_iter()
                    .map(|(path, kind, observed_at)| {
                        let dirty_key = relative_key(root, &path);
                        (path, kind, observed_at, dirty_key)
                    })
                    .collect();

                // Journal the whole known batch durably in one transaction
                // *before* any path's block-store/index work runs — see
                // `record_dirty_paths_batch`'s own doc for why one commit for
                // the batch is equivalent to one commit per path here. The
                // debounce accumulator has already drained every path in this
                // flush, so if processing below crashes, restarts, or hits a
                // multi-second disk-full/EIO and the retry loop eventually
                // gives up, the in-memory knowledge that these paths changed
                // would otherwise be lost — a permanent split-brain. Rows
                // survive until the read/blockify/put/index+DAG step commits
                // (cleared on the `Ok` arms below); a startup rescan and the
                // on-failure retry both re-drive whatever is still journaled.
                // If the batch call itself fails, fall back to the previous
                // per-path journal calls rather than invent new failure
                // semantics — either way a journal write failure is only
                // logged: losing the belt-and-suspenders row must not abort
                // processing the edits the normal way.
                let batch_entries: Vec<(String, String, i64)> = paths
                    .iter()
                    .filter_map(|(_, kind, observed_at, dirty_key)| {
                        dirty_key
                            .as_ref()
                            .map(|key| (key.clone(), dirty_kind_str(*kind).to_string(), *observed_at))
                    })
                    .collect();
                if let Err(e) = self.state.record_dirty_paths_batch(
                    group_id,
                    &batch_entries,
                    &self.begin_operation()?.permit(),
                ) {
                    tracing::warn!(
                        error = %e,
                        group_id,
                        path_count = batch_entries.len(),
                        "failed to batch-journal a debounced flush before processing; \
                         falling back to journaling each path individually"
                    );
                    for (path, kind, observed_at, dirty_key) in &paths {
                        if let Some(key) = dirty_key {
                            if let Err(e) = self.state.record_dirty_path(
                                group_id,
                                key,
                                dirty_kind_str(*kind),
                                *observed_at,
                                &self.begin_operation()?.permit(),
                            ) {
                                tracing::warn!(
                                    error = %e,
                                    path = %path.display(),
                                    group_id,
                                    "failed to journal a dirty local path before processing; \
                                     proceeding with best-effort in-memory handling"
                                );
                            }
                        }
                    }
                }

                let mut records = Vec::new();
                // Successfully processed `(path, observed_at_unix_nanos)`
                // pairs, cleared from the dirty journal in bounded batches
                // (`DIRTY_CLEAR_BATCH_SIZE` at a time) rather than one
                // `write()`/fsync per path — see `clear_dirty_paths_conditional_batch`
                // for why each clear stays conditioned on its own
                // `observed_at_unix_nanos` rather than becoming an
                // unconditional `DELETE ... WHERE path IN (...)`.
                let mut pending_clears: Vec<(String, i64)> = Vec::new();
                let flush_pending_clears = |pending_clears: &mut Vec<(String, i64)>| {
                    if pending_clears.is_empty() {
                        return;
                    }
                    let result = self.begin_operation().and_then(|op| {
                        self.state
                            .clear_dirty_paths_conditional_batch(group_id, pending_clears, &op.permit())
                            .map_err(LocalCaptureError::from)
                    });
                    if let Err(e) = result {
                        tracing::warn!(
                            error = %e,
                            group_id,
                            path_count = pending_clears.len(),
                            "failed to clear a batch of processed dirty-path journal rows; \
                             a later rescan will re-verify and clear them"
                        );
                    }
                    pending_clears.clear();
                };
                // Prepared, not-yet-committed authoritative mutations for
                // the simple create/modify/delete case -- drained into one
                // shared `commit_local_mutations_batch` transaction every
                // `AUTHORITATIVE_COMMIT_BATCH_SIZE` paths (and once more
                // after this loop, for whatever remains) by
                // `flush_pending_batch`, instead of one commit per path.
                let mut pending_batch: Vec<PendingBatchedCommit> = Vec::new();
                for (path, kind, observed_at, dirty_key) in paths {
                    // A path's chunk/index step reads and writes content-
                    // addressed blocks through the block store. A *transient*
                    // block-store fault there — a disk-full
                    // (`SyncSqliteError::Storage(StorageError::DiskPressure)`)
                    // or an EIO (`SyncSqliteError::Storage(StorageError::Io)`)
                    // — must not
                    // silently drop this already-detected local edit: the
                    // debounce accumulator has already drained this path, and
                    // no live-repair sweep revisits a `Hydrated` row whose
                    // on-disk bytes then silently drifted, so a dropped local
                    // write here is a permanent split-brain (two devices at
                    // the identical version vector with different on-disk
                    // bytes, which — equal VV being the sync identity — never
                    // reconcile). This mirrors the peer-materialize
                    // `reconstruct_file` guard (`PeerSyncSession::materialize`):
                    // the transient fault clears on a later, non-faulting
                    // attempt, so re-run this path's indexing a bounded number
                    // of times before giving up. Nothing is upserted on a
                    // failed attempt (chunking runs before any index write), so
                    // a retry is idempotent — it re-derives the same record and
                    // the same single version increment. A genuinely permanent
                    // error (anything not classified retriable) is not retried
                    // and fails exactly as before, so there is no
                    // unbounded/spin-forever risk.
                    let mut attempt = 0u32;
                    loop {
                        let result = self
                            .process_event_with_ignore_at(
                                group_id,
                                root,
                                &FsChangeEvent { path: path.clone(), kind },
                                ignore_set,
                                Some(observed_at),
                                Some(&mut pending_batch),
                            )
                            .await;
                        // The read/blockify/put/index+DAG step for this path
                        // committed (or was a no-op), so its durable dirty-journal
                        // row is no longer needed — clear it. A crash in the
                        // narrow window between the index+DAG commit and this
                        // delete just leaves the row for the next rescan, which
                        // re-reads the path, finds disk == index, and clears it
                        // as a `None` outcome: idempotent, never a lost edit.
                        let mut clear_dirty = || {
                            if let Some(key) = &dirty_key {
                                pending_clears.push((key.clone(), observed_at));
                                if pending_clears.len() >= DIRTY_CLEAR_BATCH_SIZE {
                                    flush_pending_clears(&mut pending_clears);
                                }
                            }
                        };
                        match result {
                            Ok(EventOutcome::Ready(LocalChangeOutcome::FileChanged(record))) => {
                                records.push(record);
                                clear_dirty();
                                break;
                            }
                            Ok(EventOutcome::Ready(LocalChangeOutcome::FilesChanged(orphaned))) => {
                                records.extend(orphaned);
                                clear_dirty();
                                break;
                            }
                            Ok(EventOutcome::Ready(LocalChangeOutcome::None)) => {
                                clear_dirty();
                                break;
                            }
                            Ok(EventOutcome::Deferred) => {
                                // Prepared into `pending_batch`; this path's
                                // record/dirty-clear resolve once
                                // `flush_pending_batch` runs below (either
                                // right after this path, once the batch is
                                // full, or at the end of this flush).
                                break;
                            }
                            Err(LocalCaptureError::SyncCore(
                                SyncSqliteError::PolicyUnavailable,
                            )) => {
                                // The group's policy is stale, so the emit path
                                // withheld this edit's change rather than stamp
                                // it with a placeholder authorization context —
                                // a placeholder-auth change would become a local
                                // DAG head every valid-policy peer rejects,
                                // stranding this and every descendant change on
                                // an un-replicable branch. This is expected and
                                // transient, not a failure: leave the durable
                                // dirty-journal row in place (do NOT clear it)
                                // so the startup/backstop re-drive re-emits the
                                // path — with a real authorization stamp — once a
                                // valid policy snapshot restores the group.
                                // Nothing was written to the index or the DAG
                                // (the emit path returns before opening its write
                                // transaction), and the user's on-disk bytes are
                                // untouched; only the change emission is deferred.
                                let reason = SyncSqliteError::PolicyUnavailable.to_string();
                                if let Some(key) = &dirty_key {
                                    if let Err(je) = self.state.mark_dirty_path_attempt(
                                        group_id,
                                        key,
                                        &reason,
                                        &self.begin_operation()?.permit(),
                                    ) {
                                        tracing::warn!(
                                            error = %je,
                                            path = %key,
                                            group_id,
                                            "failed to record a dirty-path processing attempt"
                                        );
                                    }
                                }
                                tracing::info!(
                                    path = %path.display(),
                                    group_id,
                                    "withheld a local change because the group's policy is \
                                     stale; left the path journaled dirty to re-emit once a \
                                     valid policy snapshot is admitted"
                                );
                                break;
                            }
                            Err(e) => {
                                if is_retriable_block_store_error(&e)
                                    && attempt < MAX_LOCAL_INDEX_RETRIES
                                {
                                    attempt += 1;
                                    // Short backoff before re-reading/re-
                                    // writing the content-addressed blocks.
                                    // Under the deterministic simulator this
                                    // advances virtual time at no real cost;
                                    // in production it gives a transient disk
                                    // fault a moment to clear.
                                    tokio::time::sleep(LOCAL_INDEX_RETRY_BACKOFF).await;
                                    continue;
                                }
                                // Retries exhausted (or a permanent error).
                                // Leave the dirty-journal row in place — record
                                // the failure so the daemon's startup rescan
                                // (and any later flush touching the path)
                                // re-drives it rather than dropping the edit.
                                if let Some(key) = &dirty_key {
                                    if let Err(je) = self.state.mark_dirty_path_attempt(
                                        group_id,
                                        key,
                                        &e.to_string(),
                                        &self.begin_operation()?.permit(),
                                    ) {
                                        tracing::warn!(
                                            error = %je,
                                            path = %key,
                                            group_id,
                                            "failed to record a dirty-path processing attempt"
                                        );
                                    }
                                }
                                tracing::warn!(
                                    error = %e,
                                    path = %path.display(),
                                    group_id,
                                    attempts = attempt,
                                    "failed to process one path in a debounced batch after \
                                     retries; left journaled dirty for re-drive on rescan/restart"
                                );
                                break;
                            }
                        }
                    }
                    if pending_batch.len() >= AUTHORITATIVE_COMMIT_BATCH_SIZE {
                        for (record, key, observed_at) in
                            self.flush_pending_batch(group_id, &mut pending_batch).await?
                        {
                            records.push(record);
                            pending_clears.push((key, observed_at));
                            if pending_clears.len() >= DIRTY_CLEAR_BATCH_SIZE {
                                flush_pending_clears(&mut pending_clears);
                            }
                        }
                    }
                }
                for (record, key, observed_at) in
                    self.flush_pending_batch(group_id, &mut pending_batch).await?
                {
                    records.push(record);
                    pending_clears.push((key, observed_at));
                }
                flush_pending_clears(&mut pending_clears);
                Ok(FlushOutcome { records })
            }
            DebounceFlush::RescanRequired => {
                let records = self.scan_existing_files_with_ignore_gated_for_established_link(
                    group_id,
                    root,
                    ignore_set,
                    emit_tombstones,
                    None,
                )?;
                Ok(FlushOutcome { records })
            }
        }
    }

    /// Streaming sibling of `process_flush_with_ignore`: for
    /// `DebounceFlush::Paths`, identical (each path is already processed
    /// and indexed individually, so there is no monolithic-batch delay to
    /// fix). For `DebounceFlush::RescanRequired`, `on_chunk_committed` is
    /// called once per durably-committed reconciliation chunk instead of
    /// withholding all of them until the whole scan returns -- see
    /// `scan_existing_files_with_ignore_streaming`'s own doc. The final
    /// `Ok(FlushOutcome)` is unchanged (still the whole scan's aggregate);
    /// a caller that streams per-chunk must not also re-announce this
    /// return value's `records` for `RescanRequired`, or every chunk would
    /// be announced twice.
    pub async fn process_flush_with_ignore_streaming(
        &self,
        group_id: &str,
        root: &Path,
        flush: DebounceFlush,
        ignore_set: &EffectiveIgnoreSet,
        emit_tombstones: bool,
        on_chunk_committed: &mut dyn FnMut(&[FileRecord]),
    ) -> Result<FlushOutcome, LocalCaptureError> {
        match flush {
            DebounceFlush::Paths(_) => {
                self.process_flush_with_ignore(group_id, root, flush, ignore_set, emit_tombstones)
                    .await
            }
            DebounceFlush::RescanRequired => {
                let records = self.scan_existing_files_with_ignore_gated_for_established_link(
                    group_id,
                    root,
                    ignore_set,
                    emit_tombstones,
                    Some(on_chunk_committed),
                )?;
                Ok(FlushOutcome { records })
            }
        }
    }

    /// Commits a bounded batch of prepared authoritative mutations
    /// (`PendingBatchedCommit`, produced by `process_event_with_ignore_at`'s
    /// simple create/modify/delete case): acquires every member's per-path
    /// lock, revalidates each is still current, and commits only the
    /// still-valid subset in one `commit_local_mutations_batch` transaction
    /// — the C4 storm investigation's Stage 2 fix for the writer_gate
    /// contention Stage 1 (batched dirty-journal writes) alone did not
    /// close.
    ///
    /// Correctness rests on three things, none of which
    /// `commit_local_mutations_batch` itself can enforce (it has no
    /// filesystem/tokio dependency):
    ///
    /// 1. **Locks are held for the whole call, never released early and
    ///    re-acquired.** Releasing a path's lock between preparing its
    ///    mutation and committing it would let a concurrent peer
    ///    materialization (or another local capture) write to that exact
    ///    path in the gap — reintroducing the stale-materialization race
    ///    class this project has repeatedly had to close elsewhere.
    ///    Acquired in lexicographic path order (not the batch's original
    ///    order) so two concurrent holders of overlapping path sets can
    ///    never form a lock-order cycle; nothing else in this daemon ever
    ///    holds more than one path lock at a time (`PeerSyncSession`'s own
    ///    per-path reconcile locks, releases, then moves to the next path),
    ///    so ordering here is sufficient on its own.
    /// 2. **Revalidation immediately before commit, still under lock.**
    ///    Preparing a mutation (chunk/hash/decide) happens with no lock
    ///    held at all, so by the time this function acquires a path's
    ///    lock, disk or index state may have moved on. Re-checking both
    ///    (`disk_race_fingerprint`, `get_file`) against what preparation
    ///    observed — the same scheme `peer_session::PeerSyncSession::
    ///    hydrate_inner` already relies on for the identical question —
    ///    catches a stale mutation before it authors bytes that are no
    ///    longer current; a mismatch excludes it from this batch entirely
    ///    rather than committing it anyway.
    /// 3. **One signed `Change` per mutation, in original order.** Passed
    ///    to `commit_local_mutations_batch` in the batch's original
    ///    (flush) order, not the lock-acquisition order, so the resulting
    ///    causal chain is identical to what committing each mutation
    ///    separately, in sequence, would have produced.
    ///
    /// Drains `pending` unconditionally. Returns `(record, rel_path,
    /// observed_at_unix_nanos)` for every mutation that actually committed
    /// — the caller pushes each into its own `records`/dirty-clear
    /// bookkeeping. A mutation dropped for staleness, or every mutation in
    /// this batch if the shared commit itself fails, is simply absent from
    /// the return value: its dirty-journal row is left untouched (this
    /// function never clears one), so the normal re-drive path picks it up
    /// again with fresh state — this mirrors Stage 1's own "a failure here
    /// is only logged, never fatal to the rest of the flush" philosophy.
    async fn flush_pending_batch(
        &self,
        group_id: &str,
        pending: &mut Vec<PendingBatchedCommit>,
    ) -> Result<Vec<(FileRecord, String, i64)>, LocalCaptureError> {
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let batch = std::mem::take(pending);
        let Some(emitter) = self.change_emitter.clone() else {
            // `process_event_with_ignore_at` only ever defers into a
            // batch when `self.change_emitter` is `Some` -- see its own
            // "simple case" gating. An empty emitter here would mean a
            // mutation was queued despite that gate, which is a logic
            // error in this module, not a runtime condition to recover
            // from.
            unreachable!(
                "a batched mutation was prepared without a change_emitter configured"
            );
        };

        // Acquire every member's path lock in lexicographic order --
        // deadlock safety against any other concurrent holder of a
        // different subset of these same locks (see this function's own
        // doc comment, point 1).
        let mut sorted_paths: Vec<&str> = batch.iter().map(|p| p.rel_path.as_str()).collect();
        sorted_paths.sort_unstable();
        let mut guards: std::collections::HashMap<String, tokio::sync::OwnedMutexGuard<()>> =
            std::collections::HashMap::with_capacity(batch.len());
        for rel_path in sorted_paths {
            if guards.contains_key(rel_path) {
                // The same path cannot appear twice in one debounce flush
                // (`DebounceFlush::Paths` is keyed by path -- see its own
                // doc comment), so this only guards against a future
                // caller violating that invariant rather than double-
                // locking a path against itself here.
                continue;
            }
            let lock = self.state.path_lock(group_id, rel_path);
            guards.insert(rel_path.to_string(), lock.lock_owned().await);
        }

        // Revalidate each, in the batch's original order — see this
        // function's own doc comment, point 2.
        let mut keep = Vec::with_capacity(batch.len());
        // Actual-state evidence for a KEPT item, or `None` for "commit the
        // Change/index exactly as before, publish no proof" -- computed
        // here, under this same revalidation pass, so a fresh
        // `FileIdentity` observation for an Upsert entry is taken at the
        // exact moment `current_disk` was already confirmed to still
        // match `disk_fingerprint_at_prepare`, not a separately-timed
        // stat that could itself race a change this loop's own disk read
        // already closed the window on. Meaningless (never read) for an
        // excluded item.
        let mut evidence_if_kept = Vec::with_capacity(batch.len());
        for pending_commit in &batch {
            let current_disk = disk_race_fingerprint(&pending_commit.event_path);
            let current_index = self.state.get_file(group_id, &pending_commit.rel_path)?;
            // `current_index == index_state_at_prepare` alone cannot catch
            // a peer commit whose new version's size/mtime/blocks happen
            // to coincide with the old one (a metadata-only change, or
            // content that happens to hash the same) -- comparing the
            // row's authoring identity too closes that gap (a Codex review
            // finding on this exact batching boundary): every commit,
            // local or peer, stamps a fresh, distinct authoring hash.
            let current_authoring_change_hash =
                self.state.get_authoring_change_hash(group_id, &pending_commit.rel_path)?;
            let still_current = current_disk == pending_commit.disk_fingerprint_at_prepare
                && current_index == pending_commit.index_state_at_prepare
                && current_authoring_change_hash == pending_commit.authoring_change_hash_at_prepare;
            if !still_current {
                tracing::info!(
                    path = %pending_commit.rel_path,
                    group_id,
                    "excluding a batched local mutation: disk or index state changed between \
                     preparation and commit; left journaled dirty for normal re-drive"
                );
            }
            use yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence as Evidence;
            let evidence = if still_current {
                match &pending_commit.mutation {
                    yadorilink_replica_domain::session_state::PreparedLocalMutation::Upsert {
                        ..
                    } => FileIdentity::observe_path(&pending_commit.event_path)
                        .ok()
                        .map(|filesystem_identity| Evidence::Present { filesystem_identity }),
                    yadorilink_replica_domain::session_state::PreparedLocalMutation::Delete {
                        ..
                    } => Some(Evidence::Absent),
                }
            } else {
                None
            };
            keep.push(still_current);
            evidence_if_kept.push(evidence);
        }

        let mut resolved = Vec::with_capacity(batch.len());
        let mut valid_mutations = Vec::with_capacity(batch.len());
        let mut valid_evidence = Vec::with_capacity(batch.len());
        for ((pending_commit, ok), evidence) in
            batch.into_iter().zip(keep).zip(evidence_if_kept)
        {
            if ok {
                resolved.push((
                    pending_commit.mutation.record().clone(),
                    pending_commit.rel_path,
                    pending_commit.observed_at_unix_nanos,
                ));
                valid_mutations.push(pending_commit.mutation);
                valid_evidence.push(evidence);
            }
        }

        if !valid_mutations.is_empty() {
            let commit_result = self.state.commit_local_mutations_batch(
                group_id,
                &valid_mutations,
                &valid_evidence,
                &self.device_id,
                crate::ports::LocalChangeEmission {
                    emitter: &emitter,
                    permit: &self.begin_operation()?.permit(),
                },
            );
            if let Err(e) = commit_result {
                tracing::warn!(
                    error = %e,
                    group_id,
                    batch_len = valid_mutations.len(),
                    "failed to commit a batched group of local mutations; left journaled dirty \
                     for re-drive"
                );
                return Ok(Vec::new());
            }
        }
        Ok(resolved)
        // `guards` drops here, releasing every path lock this batch held —
        // only after the shared commit above has returned.
    }

    /// Re-drives every path still journaled dirty for `group_id` through the
    /// normal flush executor — the daemon's startup rescan and the durability
    /// backstop against a crash, a restart, or a disk fault that outlived the
    /// in-flight retry. Each `local_dirty_paths` row is turned back into the
    /// exact `FsChangeEvent` the debounce executor would have processed and run
    /// through `process_flush`, which re-reads the path, re-derives its record,
    /// commits the index + change DAG, and (on success) clears the row. A path
    /// whose on-disk content already matches the index resolves to `None` and
    /// is simply cleared — idempotent, never a spurious re-edit; one that still
    /// can't be processed stays journaled for the next attempt. Returns the
    /// produced records so the caller can announce them exactly as a live
    /// flush would.
    pub async fn redrive_dirty_journal(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<FlushOutcome, LocalCaptureError> {
        let dirty = self.state.list_dirty_paths(group_id)?;
        if dirty.is_empty() {
            return Ok(FlushOutcome::default());
        }
        tracing::info!(
            group_id,
            count = dirty.len(),
            "re-driving journaled local dirty paths (startup/backstop rescan)"
        );
        // Reconstruct absolute event paths the same way the watcher produced
        // them — `process_event_with_ignore_at` re-relativizes against a
        // canonicalized `root`, so joining onto the canonical root here round-
        // trips to the stored relative key.
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let paths: Vec<(PathBuf, FsChangeKind, i64)> = dirty
            .into_iter()
            .map(|d| {
                (
                    canonical_root.join(&d.path),
                    dirty_kind_from_str(&d.change_kind),
                    d.observed_at_unix_nanos,
                )
            })
            .collect();
        self.process_flush(group_id, root, DebounceFlush::Paths(paths)).await
    }
}

/// How many times a single path's chunk/index step is retried when it fails
/// with a *transient* block-store fault before the flush gives up on that
/// path. Bounded so a genuinely-stuck store can never spin forever; large
/// enough that a brief disk blip (or, under the deterministic simulator, a
/// fault decorator's "every Nth op" schedule) reliably clears on a later,
/// non-faulting attempt. Kept in line with the peer-materialize reconstruct
/// guard's own bound.
const MAX_LOCAL_INDEX_RETRIES: u32 = 20;

/// How many processed paths' dirty-journal clears accumulate before
/// `process_flush_with_ignore` flushes them as one
/// `clear_dirty_paths_conditional_batch` transaction, instead of committing
/// (and fsyncing) each path's clear separately.
const DIRTY_CLEAR_BATCH_SIZE: usize = 32;

/// How many prepared authoritative mutations (`PendingBatchedCommit`)
/// accumulate before `flush_pending_batch` commits them as one
/// `commit_local_mutations_batch` transaction, instead of committing (and
/// fsyncing) each path's mutation separately. Deliberately small relative
/// to `DIRTY_CLEAR_BATCH_SIZE`: every member's path lock is held for the
/// whole batch, so a large batch would hold many locks simultaneously for
/// longer than necessary.
const AUTHORITATIVE_COMMIT_BATCH_SIZE: usize = 16;

/// Backoff between local-index retry attempts (see `MAX_LOCAL_INDEX_RETRIES`).
const LOCAL_INDEX_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// Whether a `SyncSqliteError` from a path's chunk/index step is a
/// *transient* block-store fault that a bounded retry can clear, versus a
/// permanent error that must fail as before. Only the two transient
/// disk-fault shapes are retriable: a disk-full rejection (`DiskPressure`,
/// from the block store's own headroom preflight or an ENOSPC on write) and
/// a bare block-store I/O error (an EIO on the underlying `put`/`get`, which
/// the `From<StorageError>` impl wraps as `Storage(Io)` — never the
/// top-level `Io` variant, which is a filesystem call). Every other error —
/// a checksum mismatch (a torn/corrupt block), a missing block, an invalid
/// path, or a database/path-escape error — is permanent: retrying it just
/// wastes attempts, so it is classified non-retriable and fails immediately,
/// exactly as before this guard existed.
fn is_retriable_block_store_error(e: &LocalCaptureError) -> bool {
    matches!(
        e,
        LocalCaptureError::SyncCore(SyncSqliteError::Storage(
            yadorilink_local_storage::StorageError::DiskPressure { .. }
                | yadorilink_local_storage::StorageError::Io(_)
        ))
    )
}

/// Whether the failed chunk attempt for `path` failed *because `path`
/// itself no longer exists* — as opposed to because the block store it was
/// writing into faulted. Both questions are asked of the same error type,
/// and that is precisely the trap this function exists to avoid walking
/// into.
///
/// The error shape alone is NECESSARY BUT NOT SUFFICIENT, and it is worth
/// being blunt about why, because the shape check reads like it ought to be
/// enough. `chunk_file`, `chunk_file_content_defined_with_callback`, and
/// `chunk_file_fixed_with_callback` (`yadorilink-local-storage`'s
/// `chunker.rs`) read the source file via a bare `?` on `fs::metadata`/
/// `fs::File::open`, so a source-path `NotFound` arrives here as
/// `Storage(Io(NotFound))`. But `StorageError::Io` is a blanket
/// `#[from] std::io::Error` over EVERY filesystem call the block store
/// itself makes, and the block store has its own real `NotFound` paths —
/// e.g. `FsBlockStore::commit_batch` runs its free-space preflight
/// (`check_headroom` -> `free_space::classify_volume`, which stats the
/// block-store root) BEFORE any `create_dir_all` could recreate anything,
/// so a block-store root that has been deleted or whose volume was
/// unmounted also surfaces as `Storage(Io(NotFound))`; so does a
/// concurrent removal racing `commit_block_staged`'s
/// `exists()`-then-`fs::read` of an already-present block file. The error
/// value carries no path, so the two fault domains are genuinely
/// indistinguishable from the error alone — which is exactly why
/// `is_retriable_block_store_error` above does not try.
///
/// Getting that wrong is not a cosmetic misclassification. A `true` verdict
/// makes the caller return `LocalChangeOutcome::None`, and `process_flush`
/// treats `None` as a clean no-op: it CLEARS the durable
/// `local_dirty_paths` journal row for this path. For a genuinely vanished
/// source path that is right (there is nothing left to index, and the
/// rename's own watcher event queues a fresh `CreatedOrModified` for the
/// final name — see `watcher.rs`'s `RenameMode::To`/`Both` handling). For a
/// block-store fault it is a silent, permanent loss of an already-detected
/// local edit: the file is still sitting on disk, changed, with nothing
/// left to re-drive it — the exact split-brain the retry/journal machinery
/// in `process_flush` exists to prevent.
///
/// So the verdict is taken from the PATH, not from the error: the
/// `NotFound` shape only gets us as far as "one of the two files involved
/// went missing", and the `symlink_metadata` re-stat below decides which
/// one. `symlink_metadata`, not `metadata`, so a dangling symlink — whose
/// target is missing but which is itself very much still there, and is
/// handled by `build_symlink_record`, not by chunking — is never misread as
/// a vanished path.
///
/// The re-stat can of course race in its turn, and both directions of that
/// race are safe. If `path` came back between the chunk attempt and this
/// stat (a write-then-rename that has already put a NEW file at the same
/// name), the stat succeeds, this returns `false`, and the error falls
/// through to `is_retriable_block_store_error`'s bounded retry — which
/// re-derives everything from a fresh lstat and indexes whatever is
/// actually there now. A stat that fails for any reason OTHER than
/// `NotFound` likewise returns `false` and falls through to the retry
/// path. Both are the conservative direction: the worst case is some
/// wasted retries, never a dropped edit.
///
/// FUTURE READER: do not "simplify" this back into a pure match on the
/// error shape. That form looks equivalent, compiles, passes the
/// happy-path rename test, and silently drops local edits whenever the
/// block store is the thing that is missing. See
/// `a_block_store_not_found_while_the_source_file_still_exists_stays_dirty`
/// for the regression test that pins this down.
fn is_source_path_vanished_error(e: &LocalCaptureError, path: &Path) -> bool {
    let kind = match e {
        LocalCaptureError::SyncCore(SyncSqliteError::Storage(
            yadorilink_local_storage::StorageError::Io(io_err),
        )) => Some(io_err.kind()),
        LocalCaptureError::SyncCore(SyncSqliteError::Io(io_err)) => Some(io_err.kind()),
        _ => None,
    };
    if kind != Some(std::io::ErrorKind::NotFound) {
        return false;
    }
    // The shape is only half the verdict — confirm against `path` itself.
    matches!(
        std::fs::symlink_metadata(path),
        Err(stat_err) if stat_err.kind() == std::io::ErrorKind::NotFound
    )
}

/// Test-only synchronization seam backing `fire_race_after_lstat_hook`
/// below: a global, path-keyed table (not a thread-local — the chunk
/// attempt this races against runs inside `tokio::task::block_in_place`
/// under a multi-thread runtime, which is free to resume the calling task
/// on a different OS worker thread than whichever one armed the hook) so a
/// test can deterministically inject a filesystem mutation (e.g. a rename)
/// at exactly the point between `build_record_for_created_or_modified`'s
/// own lstat guard and its later chunk attempt where production code has
/// no synchronization point to hook into otherwise, without resorting to a
/// real, flaky wall-clock race. Keyed by the exact `path` a test arms so
/// concurrently-running unrelated tests (every other test in this module
/// that also exercises this same function, via its own distinct temp
/// directory) can never consume each other's armed hook. The hook closure
/// returns whether it should stay armed for a later attempt on the same
/// path (`true`) or be consumed (`false`) — every current use is one-shot
/// (a real-world race only ever fires once, and `process_event_with_
/// ignore_at`'s own fresh per-attempt existence re-check already recovers
/// a retry on its own once the path is truly gone — see that function's
/// doc comment), but a future test targeting a different window could
/// still want the hook to keep firing.
#[cfg(test)]
static RACE_AFTER_LSTAT_HOOKS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, Box<dyn FnMut() -> bool + Send>>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn arm_race_after_lstat_hook(path: PathBuf, f: impl FnMut() -> bool + Send + 'static) {
    let map = RACE_AFTER_LSTAT_HOOKS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(path, Box::new(f));
}

#[cfg(test)]
fn fire_race_after_lstat_hook(path: &Path) {
    let Some(map) = RACE_AFTER_LSTAT_HOOKS.get() else { return };
    let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let keep_armed = match guard.get_mut(path) {
        Some(f) => f(),
        None => return,
    };
    if !keep_armed {
        guard.remove(path);
    }
}

/// The link-relative, forward-slash-normalized key for `path` under `root` —
/// the exact form the index and the `local_dirty_paths` journal use as a path
/// key, so a journaled dirty row and the record it corresponds to always agree.
/// Mirrors `process_event_with_ignore_at`'s own relativization (canonicalize
/// `root`, `strip_prefix`, then `path_to_wire_relative_string`). Returns
/// `None` when `path` is not under `root`, is the root itself, or cannot be
/// represented losslessly as a wire path — all cases the executor treats as
/// a no-op anyway.
fn relative_key(root: &Path, path: &Path) -> Option<String> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let rel = path.strip_prefix(&root).ok()?;
    let rel = path_to_wire_relative_string(rel)?;
    if rel.is_empty() {
        return None;
    }
    Some(rel)
}

/// Converts `rel` (a path already relative to some root) into this crate's
/// canonical forward-slash wire-path string, or `None` if `rel` cannot be
/// represented losslessly as one. An independent review found two distinct
/// silent-collision hazards in the old `rel.to_string_lossy().replace('\\',
/// "/")` pattern every caller here used to use directly, both closed by
/// this function:
///
/// - That old code replaced `\` with `/` UNCONDITIONALLY, on every
///   platform. On Windows that's correct (the native separator IS `\`,
///   and the wire form needs `/`) — but on Unix, `\` is an ordinary, legal
///   filename BYTE, not a path separator (the native separator there is
///   already `/`). Blindly replacing it folded two genuinely different
///   real files onto the identical logical path string: a file literally
///   named `a\b.txt` and a nested file at `a/b.txt` both produced the
///   wire string `"a/b.txt"`. `Path::to_str`'s own text already uses each
///   platform's real separator, so gating the `\`→`/` substitution to
///   `#[cfg(windows)]` alone closes this without needing any Unix-side
///   logic at all.
/// - `to_string_lossy()` silently substitutes `�` (U+FFFD) for any
///   invalid UTF-8 byte sequence. Two DIFFERENT real files whose names
///   contain different non-UTF-8 byte sequences (common in practice: any
///   name that isn't valid UTF-8 at all, e.g. legacy Latin-1-encoded
///   filenames, or an archive/zip extracted from a non-UTF-8 locale) can
///   therefore silently collapse onto the identical logical path string.
///   `Path::to_str` returns `None` instead of substituting anything,
///   which every caller here now treats as "cannot safely sync this
///   path" (skip/suppress/no-op) rather than silently proceeding with a
///   corrupted string that might collide with something else.
///
/// This is a bounded mitigation, not a full fix: this crate's index/DAG/
/// wire representation is still fundamentally a UTF-8 `String`, so a
/// genuinely non-UTF-8 name still cannot be synced at all — it is now
/// refused outright rather than silently corrupted, which is strictly
/// better (no silent collision) but not the same as actually supporting
/// such names. The full fix — raw-byte (Unix) / WTF-16 (Windows) path
/// representation threaded through the wire protocol, DAG encoding, and
/// every index primary key — is a substantially larger redesign, tracked
/// as an open residual rather than attempted here.
fn path_to_wire_relative_string(rel: &Path) -> Option<String> {
    let text = rel.to_str()?;
    #[cfg(windows)]
    let text: std::borrow::Cow<'_, str> = text.replace('\\', "/").into();
    #[cfg(not(windows))]
    let text: std::borrow::Cow<'_, str> = {
        // The wire representation is consumed on Windows too, where
        // '\' is a separator. Preserving a literal Unix backslash
        // would let `a\b` and `a/b` remain distinct signed/index
        // paths while materializing onto the same Windows object.
        if text.contains('\\') {
            return None;
        }
        text.into()
    };
    Some(text.into_owned())
}

/// Serialized `FsChangeKind` as stored in the `local_dirty_paths` journal, so a
/// startup/backstop re-drive can reconstruct the exact `FsChangeEvent`.
fn dirty_kind_str(kind: FsChangeKind) -> &'static str {
    match kind {
        FsChangeKind::CreatedOrModified => "created_or_modified",
        FsChangeKind::Removed => "removed",
    }
}

/// Inverse of [`dirty_kind_str`]. Any unrecognized value maps to
/// `CreatedOrModified` — the safe default, since re-reading a path that turns
/// out to be absent still self-corrects to a deletion inside `process_event`.
fn dirty_kind_from_str(s: &str) -> FsChangeKind {
    match s {
        "removed" => FsChangeKind::Removed,
        _ => FsChangeKind::CreatedOrModified,
    }
}

fn is_excluded_from_sync(
    relative_path: impl AsRef<Path>,
    is_dir: bool,
    ignore_set: &EffectiveIgnoreSet,
) -> bool {
    let relative_path = relative_path.as_ref();
    // The reserved artefact namespace is checked before anything else in
    // this function, including the sync-root marker and ignore file
    // special-cases below: a transaction artefact must never become
    // trackable content no matter what a user's ignore file says about it.
    if path_has_reserved_component(relative_path) {
        return true;
    }
    // The sync-root marker is this device's own identity file
    // (`yadorilink_root_authority::root_identity`), not user content: every device mints its own
    // token, so syncing it would overwrite a peer's identity with ours and
    // produce a conflicted copy of the very file that proves which folder this
    // is. Excluded here — the one place scan, watch, and the becoming-ignored
    // index cleanup all consult — rather than as a pattern in the default
    // ignore set, because a user-editable `.yadorilinkignore` can negate a
    // pattern (`!.yadorilink-root`) and must not be able to.
    // The sync-root single-instance lock sidecar (`crate::sync_root_lock`) is
    // likewise this device's own process-management artefact, not user
    // content, and excluded for the identical reason as the identity marker
    // immediately above: it names no fixed identity to disagree over like the
    // marker does, but syncing it would still make it visible to `.yadorilinkignore`
    // negation and conflicted-copy machinery it has no business being subject to.
    is_root_marker_relative_path(relative_path)
        || is_sync_root_lock_relative_path(relative_path)
        || is_ignore_file_relative_path(relative_path)
        || ignore_set.is_ignored(relative_path, is_dir)
}

/// path-string analysis only — never dereferences `raw_target`
/// (no `canonicalize`, no `metadata`, no filesystem read of the target at
/// all) to decide whether it escapes `root`. `link_path` is the symlink's
/// own absolute path (used only for its parent directory, to resolve a
/// relative target); `raw_target` is exactly what `std::fs::read_link`
/// returned. Returns `true` if the target is absolute, or if — resolved
/// syntactically against the symlink's parent — it lands outside `root`.
fn symlink_target_is_out_of_root(root: &Path, link_path: &Path, raw_target: &Path) -> bool {
    if raw_target.is_absolute() {
        return true;
    }
    let parent = link_path.parent().unwrap_or(link_path);
    let joined = parent.join(raw_target);
    let normalized = normalize_syntactic(&joined);
    !normalized.starts_with(root)
}

/// Syntactic (non-filesystem-touching) `.`/`..` normalization — NOT
/// `Path::canonicalize`, which resolves symlinks and touches the
/// filesystem (dereferencing the
/// target is the one thing this check must not do). A `..` that has
/// nothing left to pop (already at the start of an absolute path) is kept
/// literally rather than dropped, so the caller's `starts_with(root)`
/// check conservatively treats it as escaping rather than silently
/// accepting it.
fn normalize_syntactic(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The result of processing one debounce flush — see `process_flush`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FlushOutcome {
    pub records: Vec<FileRecord>,
}

/// Test-only injection point for `reconcile_disk_with_ignore`. A hook, if set,
/// is invoked right after the scan has read its whole-index snapshot and before
/// it commits any record derived from that snapshot. Keyed nowhere — the hook
/// itself inspects the `group_id` and no-ops for scans it does not care about —
/// so a serial test guard plus a per-test sentinel group keep it from
/// perturbing the other scan tests in this crate. Compiled out of non-test
/// builds; production `reconcile_disk_with_ignore` never references it.
#[cfg(test)]
pub(crate) mod scan_test_hooks {
    use std::sync::{Arc, Mutex};

    type Hook = Arc<dyn Fn(&str) + Send + Sync>;
    static POST_SNAPSHOT: Mutex<Option<Hook>> = Mutex::new(None);

    pub(crate) fn set_post_snapshot_hook(hook: Option<Hook>) {
        *POST_SNAPSHOT.lock().unwrap_or_else(|p| p.into_inner()) = hook;
    }

    pub(crate) fn fire_post_snapshot(group_id: &str) {
        // Clone the Arc out and release the registry lock before invoking, so a
        // hook that blocks (the deterministic startup-race tests do) never holds
        // this lock while parked.
        let hook = POST_SNAPSHOT.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(hook) = hook {
            hook(group_id);
        }
    }

    type PathHook = Arc<dyn Fn(&str, &str) + Send + Sync>;
    static PRE_TOMBSTONE_RECHECK: Mutex<Option<PathHook>> = Mutex::new(None);

    pub(crate) fn set_pre_tombstone_recheck_hook(hook: Option<PathHook>) {
        *PRE_TOMBSTONE_RECHECK.lock().unwrap_or_else(|p| p.into_inner()) = hook;
    }

    pub(crate) fn fire_pre_tombstone_recheck(group_id: &str, path: &str) {
        // Same release-before-invoke discipline as `fire_post_snapshot`
        // above, for the same reason.
        let hook = PRE_TOMBSTONE_RECHECK.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(hook) = hook {
            hook(group_id, path);
        }
    }

    static PRE_CHUNK_COMMIT_RECHECK: Mutex<Option<PathHook>> = Mutex::new(None);

    pub(crate) fn set_pre_chunk_commit_recheck_hook(hook: Option<PathHook>) {
        *PRE_CHUNK_COMMIT_RECHECK.lock().unwrap_or_else(|p| p.into_inner()) = hook;
    }

    /// Fires once per tombstone candidate immediately before the FINAL,
    /// guard-held-through-commit re-verification that runs right before a
    /// chunk actually writes -- distinct from `fire_pre_tombstone_recheck`
    /// above, which fires earlier, at candidacy-decision time. A test that
    /// only sets this hook (leaving the other one unset) can inject a race
    /// specifically in the window the candidacy-time re-check alone cannot
    /// close: after a candidate legitimately passed that first check and
    /// was added to the batch, but before its own chunk's actual commit.
    pub(crate) fn fire_pre_chunk_commit_recheck(group_id: &str, path: &str) {
        let hook = PRE_CHUNK_COMMIT_RECHECK.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(hook) = hook {
            hook(group_id, path);
        }
    }
}

/// M2-2: pins `untouched_placeholder_verdict`'s Windows overload -- the
/// size/mtime fallback this module used to fall back to on every non-Unix
/// platform is gone; every scenario below proves the verdict now comes
/// ONLY from `LocalMutationStore::inspect_windows_placeholder` (stubbed
/// here via `TestReplica::set_windows_placeholder_inspect_result`, since
/// nothing on this crate's own test matrix can exercise a real
/// `CfGetPlaceholderInfo` call -- see that module's own doc comment).
/// `#[cfg(all(test, windows))]`, not `not(unix)`: the fallback these tests
/// replace ran on any non-Unix target as a catch-all; this project ships
/// only macOS and Windows, so there is no longer a third platform to hedge
/// for.
#[cfg(all(test, windows))]
mod untouched_placeholder_verdict_windows_tests {
    use super::{untouched_placeholder_verdict, FileRecord};
    use crate::test_support::TestReplica;
    use yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus;
    use yadorilink_local_storage::{
        PlaceholderDiskIdentity, WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
    };
    use yadorilink_sync_sqlite::RecordedPlaceholderGeneration;

    fn record(size: u64, mtime_unix_nanos: i64) -> FileRecord {
        FileRecord {
            path: "placeholder.bin".into(),
            size,
            mtime_unix_nanos,
            blocks: Vec::new(),
            deleted: false,
        }
    }

    fn metadata_for(size: u64) -> std::fs::Metadata {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, vec![0u8; size as usize]).unwrap();
        std::fs::metadata(&path).unwrap()
    }

    fn generation(value: u64) -> RecordedPlaceholderGeneration {
        RecordedPlaceholderGeneration {
            identity: PlaceholderDiskIdentity { dev: 0, ino: value },
            provider_kind: WINDOWS_CFAPI_GENERATION_PROVIDER_KIND.to_string(),
        }
    }

    /// A same-size, same-mtime "real edit" is exactly what the removed
    /// size/mtime fallback would have silently swallowed as a self-echo --
    /// proves that path no longer exists: with a real generation recorded
    /// but `inspect_windows_placeholder` reporting `Dirty`, the verdict is
    /// `false` (captured) regardless of size/mtime agreement.
    #[test]
    fn same_size_and_mtime_real_edit_is_still_captured_when_inspect_says_dirty() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Dirty);
        let metadata = metadata_for(4096);
        let mtime =
            metadata.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as i64;
        let recorded = generation(7);
        assert!(!untouched_placeholder_verdict(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            Some(&record(4096, mtime)),
            Some(&recorded),
        ));
    }

    #[test]
    fn matching_generation_and_in_sync_is_ignored_as_self_echo() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Untouched);
        let metadata = metadata_for(4096);
        let recorded = generation(7);
        assert!(untouched_placeholder_verdict(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            None,
            Some(&recorded),
        ));
    }

    /// Represents `inspect_windows_placeholder` detecting an ABA mismatch
    /// (the placeholder at `path` decodes an identity that doesn't match
    /// the expected generation -- a different object now sits at this
    /// path) -- `inspect_placeholder`'s own real implementation collapses
    /// this into `Unknown`, same as an outright API failure (see the next
    /// test): this layer cannot and must not distinguish the two, both
    /// must fail closed identically.
    #[test]
    fn generation_mismatch_is_captured() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Unknown);
        let metadata = metadata_for(4096);
        let recorded = generation(7);
        assert!(!untouched_placeholder_verdict(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            None,
            Some(&recorded),
        ));
    }

    #[test]
    fn inspect_failure_is_captured() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Unknown);
        let metadata = metadata_for(4096);
        let recorded = generation(7);
        assert!(!untouched_placeholder_verdict(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            None,
            Some(&recorded),
        ));
    }

    /// A legacy (pre-M2-2, or cross-platform-mismatched) recorded identity
    /// must never be silently trusted as `Untouched`, even if
    /// `inspect_windows_placeholder` -- which this test deliberately
    /// leaves stubbed to say `Untouched` -- would have said so: the
    /// `provider_kind` gate must short-circuit BEFORE that call is
    /// consulted at all.
    #[test]
    fn legacy_identity_is_never_silently_untouched() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Untouched);
        let metadata = metadata_for(4096);
        let legacy = RecordedPlaceholderGeneration {
            identity: PlaceholderDiskIdentity { dev: 0, ino: 7 },
            provider_kind: yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND.to_string(),
        };
        assert!(!untouched_placeholder_verdict(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            None,
            Some(&legacy),
        ));
    }

    #[test]
    fn no_recorded_generation_is_never_silently_untouched() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Untouched);
        let metadata = metadata_for(4096);
        assert!(!untouched_placeholder_verdict(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            None,
            None,
        ));
    }

    /// A generation read back from storage classifies identically on
    /// repeat reads -- the property that makes "restart, then re-read the
    /// persisted generation" safe: nothing about re-fetching the same
    /// already-recorded value (as a restarted daemon would) changes the
    /// verdict.
    #[test]
    fn repeated_reads_of_the_same_persisted_generation_classify_identically() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Untouched);
        let metadata = metadata_for(4096);
        let recorded = generation(99);
        for _ in 0..2 {
            assert!(untouched_placeholder_verdict(
                &replica,
                std::path::Path::new("placeholder.bin"),
                &metadata,
                None,
                Some(&recorded),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_replica_domain::change::ChangeAuth;
    // This crate's own tests build a real fixture via this crate's own
    // `TestReplica` (a thin wrapper around `yadorilink-daemon`'s
    // `ReplicaCoordinator` -- see `test_support`'s own doc comment for why a
    // bare `ReplicaCoordinator` does not compile in this crate's own
    // internal `#[cfg(test)]` code).
    use crate::test_support::TestReplica;
    use std::sync::Mutex;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_local_storage::FsBlockStore;

    fn processor() -> (LocalChangeProcessor, Arc<TestReplica>, tempfile::TempDir, tempfile::TempDir)
    {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(TestReplica::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        (
            LocalChangeProcessor::new(
                state.clone(),
                store,
                "device-a".into(),
                std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
            ),
            state,
            store_dir,
            root_dir,
        )
    }

    // --- `run_capture_pass_off_worker`'s runtime guard ---

    /// The bound the offload exists to establish: however long a capture
    /// pass runs, it must not hold the tokio worker core it was called on.
    ///
    /// `worker_threads = 1` is the whole point of the test, not an
    /// economy. With a single worker, a pass that held its core would leave
    /// the ticker spawned below with nowhere to run at all until the pass
    /// returned, and the tick count would not move.
    ///
    /// The pass is `tokio::spawn`ed rather than run in the test body for
    /// the same reason: `#[tokio::test]` drives the body on `block_on`'s
    /// own thread, which is not a worker and holds no core, so blocking
    /// there would pin nothing at all. Both tick reads happen on the
    /// spawned task's own thread, immediately either side of the blocking
    /// call, so the window measured is exactly the pass.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_capture_pass_does_not_hold_the_worker_core_it_runs_on() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let ticks = Arc::new(AtomicUsize::new(0));
        let ticker_ticks = Arc::clone(&ticks);
        let ticker = tokio::spawn(async move {
            loop {
                ticker_ticks.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });
        // Let the ticker reach its first await, so the worker is genuinely
        // free to pick the pass up next.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let pass_ticks = Arc::clone(&ticks);
        let (before, after) = tokio::spawn(async move {
            let before = pass_ticks.load(Ordering::SeqCst);
            run_capture_pass_off_worker(|| {
                std::thread::sleep(std::time::Duration::from_millis(300));
            });
            (before, pass_ticks.load(Ordering::SeqCst))
        })
        .await
        .unwrap();
        ticker.abort();

        // ~60 ticks are expected in 300ms; assert on a small fraction of
        // that so a loaded machine cannot make this flaky, while still
        // failing outright on the "nothing ran at all" behavior it pins.
        assert!(
            after >= before + 5,
            "the sole worker made no progress while a capture pass ran on it \
             ({before} -> {after} ticks): the pass held its core instead of \
             handing it off"
        );
    }

    /// `block_in_place` panics unless a multi-threaded runtime is current,
    /// and these passes are reachable from a current-thread one (this
    /// module's own function is called from the synchronous
    /// `scan_existing_files` public API, which an embedder may drive from
    /// any runtime flavor). The guard must degrade to a plain synchronous
    /// call there — where there is no worker pool, there is nothing to
    /// starve — rather than take the process down.
    #[tokio::test(flavor = "current_thread")]
    async fn a_capture_pass_runs_inline_on_a_current_thread_runtime() {
        assert_eq!(run_capture_pass_off_worker(|| 42), 42);
    }

    /// The same degradation with no tokio runtime in the picture at all —
    /// the shape the daemon's own initial scan already produces by running
    /// `scan_existing_files_with_ignore_gated` inside `spawn_blocking`.
    #[test]
    fn a_capture_pass_runs_inline_with_no_runtime_at_all() {
        assert_eq!(run_capture_pass_off_worker(|| 42), 42);
    }

    /// The size gate decides only which thread the verification runs on,
    /// never what it concludes — both sides of the cutoff must agree with
    /// the unwrapped verifier on the same inputs.
    #[test]
    fn the_off_worker_verify_gate_does_not_change_the_verdict() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let blocks = yadorilink_local_storage::chunk_file(&store, &path).unwrap();

        for size in [0, OFF_WORKER_VERIFY_MIN_BYTES] {
            assert!(disk_bytes_match_indexed_blocks_off_worker(&path, &blocks, size).unwrap());
        }

        std::fs::write(&path, b"hello worlds").unwrap();
        for size in [0, OFF_WORKER_VERIFY_MIN_BYTES] {
            assert!(!disk_bytes_match_indexed_blocks_off_worker(&path, &blocks, size).unwrap());
        }
    }

    // --- Startup-scan vs incoming-peer-apply race (group startup barrier) ---
    //
    // These two tests are the deterministic core of the barrier: the same real
    // `scan_existing_files_with_ignore` scan is paused (via `scan_test_hooks`)
    // exactly between reading its whole-index snapshot and committing the record
    // it derives from that snapshot, while a concurrent peer change for the same
    // path is injected. Without the barrier the scan's blind, un-path-locked
    // batch commit clobbers the peer change (last-writer overwrite); with the
    // barrier the peer apply waits for startup to finish, so it is ordered after
    // the scan commit and survives.

    const RACE_GROUP: &str = "startup-race-group";
    const RACE_PATH: &str = "raced.txt";
    const PEER_MTIME: i64 = 7_777_777;

    // Serializes the two tests that install the process-wide scan hook so they
    // never observe each other's hook. Other scan tests use different group ids,
    // and the hook no-ops for any group but `RACE_GROUP`, so they are unaffected.
    // An async-aware `Mutex`, not `std::sync::Mutex`: both tests hold this guard
    // across `.await` points for their entire body (that's the point -- the
    // whole test, not just its setup, must stay serialized against the other),
    // which a `std::sync::MutexGuard` cannot safely do.
    static SCAN_RACE_TEST_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct Latch {
        raised: Mutex<bool>,
        cv: std::sync::Condvar,
    }

    impl Latch {
        fn new() -> Self {
            Self { raised: Mutex::new(false), cv: std::sync::Condvar::new() }
        }
        fn raise(&self) {
            *self.raised.lock().unwrap_or_else(|p| p.into_inner()) = true;
            self.cv.notify_all();
        }
        /// Unbounded wait, for the scan thread's own use (waiting on
        /// `release_scan`, which the main test thread always raises promptly
        /// once it reaches that point) -- the main test thread's wait on
        /// `snapshot_read` is the one at risk of the scan never reaching the
        /// hook at all, so that call site uses `wait_timeout` below instead.
        fn wait(&self) {
            let mut raised = self.raised.lock().unwrap_or_else(|p| p.into_inner());
            while !*raised {
                raised = self.cv.wait(raised).unwrap_or_else(|p| p.into_inner());
            }
        }
        /// Bounded wait: returns whether the latch was actually raised, rather
        /// than blocking forever. The scan thread this waits on can fail
        /// *before* ever reaching the hook that raises it (e.g. `VerifiedRoot::
        /// open`'s root-marker write hitting a full disk) -- an unbounded
        /// `Condvar::wait` would then hang the test indefinitely instead of
        /// failing, since nothing else in the test is ever going to raise it.
        fn wait_timeout(&self, timeout: std::time::Duration) -> bool {
            let raised = self.raised.lock().unwrap_or_else(|p| p.into_inner());
            let (raised, result) = self
                .cv
                .wait_timeout_while(raised, timeout, |raised| !*raised)
                .unwrap_or_else(|p| p.into_inner());
            *raised && !result.timed_out()
        }
    }

    /// Extracts a readable message from a `std::thread::JoinHandle::join`
    /// panic payload, for a clearer failure than "the latch never raised" when
    /// the actual cause is the scan thread panicking before it could.
    fn scan_panic_message(payload: &(dyn std::any::Any + Send)) -> String {
        if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_string()
        }
    }

    /// Diagnoses why `snapshot_read.wait_timeout(..)` returned `false`:
    /// joins the scan thread (already finished if it panicked before
    /// reaching the hook; still running only if the hook itself is somehow
    /// stuck, which the hook's own bodies below never do) and reports what
    /// happened.
    fn describe_scan_timeout(scan_handle: std::thread::JoinHandle<()>) -> String {
        if scan_handle.is_finished() {
            match scan_handle.join() {
                Err(payload) => format!("scan thread panicked: {}", scan_panic_message(&*payload)),
                Ok(()) => "scan thread returned Ok without ever reaching the post-snapshot hook \
                           -- reconcile_disk_with_ignore must not have called it"
                    .to_string(),
            }
        } else {
            "scan thread is still running".to_string()
        }
    }

    /// Builds a fixture whose index already holds an *old* row for `RACE_PATH`
    /// and whose on-disk file has different content — so the real scan detects a
    /// change and commits a fresh (stale-relative-to-any-peer-write) record.
    fn build_race_fixture() -> (
        LocalChangeProcessor,
        Arc<TestReplica>,
        std::path::PathBuf,
        EffectiveIgnoreSet,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(TestReplica::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();

        state.link_repository().add_link(&root.to_string_lossy(), RACE_GROUP).unwrap();

        let processor = LocalChangeProcessor::new(
            state.clone(),
            store,
            "device-a".into(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        );

        // Adopt the root identity here, while the index is still empty --
        // matching `adopt_root`'s own doc comment (a real first link always
        // does this before indexing anything). Otherwise the *scan itself*
        // performs first-adoption lazily inside `VerifiedRoot::open`, which
        // includes a marker-file write; if that write fails for any reason
        // (e.g. a full disk), the scan thread panics before ever reaching
        // the race tests' post-snapshot hook, and the test hangs on an
        // unbounded latch wait instead of failing. Adopting up front makes
        // that failure mode surface immediately, in fixture setup, instead.
        adopt_root(&state, RACE_GROUP, &root);

        state
            .file_index_repository()
            .upsert_file(
                RACE_GROUP,
                &FileRecord {
                    path: RACE_PATH.to_string(),
                    size: 1,
                    mtime_unix_nanos: 1,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        std::fs::write(root.join(RACE_PATH), b"offline-local-edit-content").unwrap();

        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        (processor, state, root, ignore_set, store_dir, root_dir)
    }

    /// A concurrent peer change for the same path: a distinct device advances the
    /// version, and a sentinel mtime lets the assertion tell whose record is
    /// current after the race.
    fn race_peer_record() -> FileRecord {
        FileRecord {
            path: RACE_PATH.to_string(),
            size: 4,
            mtime_unix_nanos: PEER_MTIME,
            blocks: vec![],
            deleted: false,
        }
    }

    /// FIX ASSERTED: with the group startup barrier, a peer change injected
    /// after the scan snapshots but before it commits is ordered *after* startup
    /// completes and is NOT overwritten by the scan's stale-snapshot record.
    #[tokio::test]
    async fn startup_barrier_prevents_stale_overwrite_of_concurrent_peer_change() {
        let _serial = SCAN_RACE_TEST_GUARD.lock().await;
        let (processor, state, root, ignore_set, _store_dir, _root_dir) = build_race_fixture();

        // As `start_link_watch` does synchronously before spawning the executor.
        let generation = state.startup_readiness().begin_group_startup(RACE_GROUP);

        let snapshot_read = Arc::new(Latch::new());
        let release_scan = Arc::new(Latch::new());
        {
            let snapshot_read = snapshot_read.clone();
            let release_scan = release_scan.clone();
            scan_test_hooks::set_post_snapshot_hook(Some(Arc::new(move |gid: &str| {
                if gid != RACE_GROUP {
                    return;
                }
                snapshot_read.raise();
                release_scan.wait();
            })));
        }

        let scan_root = root.clone();
        let scan_handle = std::thread::spawn(move || {
            processor.scan_existing_files_with_ignore(RACE_GROUP, &scan_root, &ignore_set).unwrap();
        });

        // Scan has read the old snapshot and is paused before its commit.
        if !snapshot_read.wait_timeout(std::time::Duration::from_secs(10)) {
            panic!(
                "scan never reached its post-snapshot hook within 10s: {}",
                describe_scan_timeout(scan_handle)
            );
        }

        // Inject the peer change through the same gated sequence production uses:
        // wait for the group to be ready, then apply under the path lock. The
        // barrier is closed, so this parks instead of racing the scan.
        let peer_state = state.clone();
        let peer_task = tokio::spawn(async move {
            peer_state.wait_group_ready(RACE_GROUP).await.unwrap();
            let path_lock = peer_state.path_lock_registry().path_lock(RACE_GROUP, RACE_PATH);
            let _guard = path_lock.lock().await;
            peer_state
                .file_index_repository()
                .upsert_file(
                    RACE_GROUP,
                    &race_peer_record(),
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap();
        });

        // Let the scan commit its stale-snapshot record first...
        release_scan.raise();
        scan_handle.join().unwrap();
        // ...then complete startup, which is what releases the parked peer apply.
        state.startup_readiness().mark_group_ready(RACE_GROUP, generation);
        peer_task.await.unwrap();
        scan_test_hooks::set_post_snapshot_hook(None);

        let current =
            state.file_index_repository().get_file(RACE_GROUP, RACE_PATH).unwrap().unwrap();
        assert_eq!(
            current.mtime_unix_nanos, PEER_MTIME,
            "with the startup barrier the peer change is ordered after the scan's commit and \
             survives as the current record"
        );
    }

    /// REPRODUCES THE BUG the barrier exists to prevent: an unordered peer apply
    /// lands in the scan's snapshot-vs-commit window and the scan's blind batch
    /// commit overwrites it. This is the failing-without half of the acceptance
    /// pair — the only difference from the test above is that the peer apply is
    /// not ordered against the scan.
    ///
    /// It also pins the second mechanism that now prevents this: the apply below
    /// skips `wait_group_ready` deliberately, because for a live link with no
    /// registered gate that call no longer returns `Ok`. It refuses, which is
    /// asserted first — so reaching the overwrite requires bypassing the gate
    /// entirely, and both facts are proven in one place: the race is real, and
    /// the gate does not admit it.
    #[tokio::test]
    async fn startup_scan_stale_overwrites_concurrent_peer_change_without_barrier() {
        let _serial = SCAN_RACE_TEST_GUARD.lock().await;
        let (processor, state, root, ignore_set, _store_dir, _root_dir) = build_race_fixture();
        // Deliberately no `begin_group_startup`: models a startup that never
        // registered a gate for a link that is nonetheless live.
        assert!(
            state.wait_group_ready(RACE_GROUP).await.is_err(),
            "a live link with no startup gate must refuse peer apply; the overwrite below is only \
             reachable by bypassing the gate, which is what makes this the negative control"
        );

        let snapshot_read = Arc::new(Latch::new());
        let release_scan = Arc::new(Latch::new());
        {
            let snapshot_read = snapshot_read.clone();
            let release_scan = release_scan.clone();
            scan_test_hooks::set_post_snapshot_hook(Some(Arc::new(move |gid: &str| {
                if gid != RACE_GROUP {
                    return;
                }
                snapshot_read.raise();
                release_scan.wait();
            })));
        }

        let scan_root = root.clone();
        let scan_handle = std::thread::spawn(move || {
            processor.scan_existing_files_with_ignore(RACE_GROUP, &scan_root, &ignore_set).unwrap();
        });

        if !snapshot_read.wait_timeout(std::time::Duration::from_secs(10)) {
            panic!(
                "scan never reached its post-snapshot hook within 10s: {}",
                describe_scan_timeout(scan_handle)
            );
        }

        // The peer apply runs immediately in the snapshot-vs-commit window,
        // bypassing the gate that just refused it (asserted above) to show what
        // that refusal is protecting against.
        {
            let path_lock = state.path_lock_registry().path_lock(RACE_GROUP, RACE_PATH);
            let _guard = path_lock.lock().await;
            state
                .file_index_repository()
                .upsert_file(
                    RACE_GROUP,
                    &race_peer_record(),
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap();
        }

        // The scan now commits its stale record on top of the peer change.
        release_scan.raise();
        scan_handle.join().unwrap();
        scan_test_hooks::set_post_snapshot_hook(None);

        let current =
            state.file_index_repository().get_file(RACE_GROUP, RACE_PATH).unwrap().unwrap();
        assert_ne!(
            current.mtime_unix_nanos, PEER_MTIME,
            "without the startup barrier the scan's stale-snapshot commit overwrites the \
             concurrent peer change — the race the barrier closes"
        );
    }

    // --- Live-rescan TOCTOU: a completed held-to-materialize transition
    // racing the tombstone-candidate loop's own checks ---
    //
    // Unlike the group-startup-barrier tests above (which close a race
    // between the STARTUP scan and a peer apply, using the barrier itself
    // as the fix), this exercises the fresh, lock-covered re-check
    // `reconcile_disk_with_ignore` now does immediately before committing
    // any tombstone -- reproducing exactly the shape a LIVE rescan
    // (`DebounceFlush::RescanRequired`, reachable at any point during an
    // established link's life, not confined to any barrier) is exposed to.

    const TOCTOU_GROUP: &str = "toctou-group";
    const TOCTOU_PATH: &str = "held-then-materialized.bin";

    async fn build_toctou_fixture() -> (
        LocalChangeProcessor,
        Arc<TestReplica>,
        std::path::PathBuf,
        EffectiveIgnoreSet,
        tempfile::TempDir,
        tempfile::TempDir,
        Vec<u8>,
    ) {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(TestReplica::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();

        state.link_repository().add_link(&root.to_string_lossy(), TOCTOU_GROUP).unwrap();
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(ChangeAuth::PLACEHOLDER)));
        let emitter = Arc::new(ChangeEmitter::new(
            "device-a",
            ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]),
        ));
        let processor = LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "device-a".into(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(emitter);
        adopt_root(&state, TOCTOU_GROUP, &root);
        // A real, DAG-admitted edit for TOCTOU_PATH itself -- both tests
        // using this fixture exercise a LIVE rescan
        // (`scan_existing_files_with_ignore`, the same entry point
        // `DebounceFlush::RescanRequired` reaches once a link is
        // established), and a live rescan is only ever reachable once the
        // group's startup scan has already run, which always establishes
        // DAG history first (`ensure_initial_change_history`) -- so
        // `has_dag_history` must be `true` here to match production, not
        // an artifact of an otherwise-empty test fixture. Without this,
        // `reconcile_disk_with_ignore` takes its OTHER, non-chunked commit
        // path (`upsert_files_batch`, the true first-scan-of-a-brand-new-
        // link case), which has no per-chunk pre-commit re-verification
        // to exercise at all. Going through `process_event` (rather than
        // a direct `upsert_file`) is also what gives this row a real,
        // schema-required `authoring_change_hash` -- a DAG-backed current
        // row with none is rejected outright once the group has any
        // history at all (`files_require_authoring_identity_on_insert`).
        let content = b"real content, written only after the hold clears".to_vec();
        std::fs::write(root.join(TOCTOU_PATH), &content).unwrap();
        processor
            .process_event(
                TOCTOU_GROUP,
                &root,
                &FsChangeEvent {
                    path: root.join(TOCTOU_PATH),
                    kind: FsChangeKind::CreatedOrModified,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            state.sqlite().dag_group_heads(TOCTOU_GROUP).unwrap().len(),
            1,
            "sanity: TOCTOU_PATH's own creation must have established exactly one DAG head"
        );
        // Now remove the just-indexed content -- everything below mutates
        // ONLY `materialization_state`/`held_reason`/`held_since_unix_
        // nanos` (never `state`/`version_seq`/`authoring_change_hash`, the
        // columns the trigger above actually watches), so the row's valid
        // authoring identity from the real edit just above survives
        // untouched.
        std::fs::remove_file(root.join(TOCTOU_PATH)).unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        // `hold_record`'s own established shape: `Placeholder`, held, and
        // (deliberately) nothing written under this exact name yet, no
        // intent, no obligation -- the row this whole investigation's bug
        // family is about.
        state
            .materialization_state_repository()
            .set_materialization_state(
                TOCTOU_GROUP,
                TOCTOU_PATH,
                MaterializationState::Placeholder,
                &permit,
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_held(TOCTOU_GROUP, TOCTOU_PATH, "case_collision", 0)
            .unwrap();
        // `process_event`'s own real local emission (above) bumped a
        // projection obligation for this exact path, same as any other
        // local emission -- see `bump_projection_obligations_for_touched_
        // paths`'s own callers. Left unsettled, `has_unsettled_projection_
        // obligation` alone would already exclude every candidate this
        // whole fixture exists to test, for a reason unrelated to what
        // each test actually means to exercise (held vs. cleared).
        // `hold_record` itself settles this as part of its own real
        // operation (see `HazardHeld` settlement's own doc elsewhere in
        // this codebase); this fixture reproduces that same end state
        // directly, matching `NonExactProofKind::Placeholder`'s own
        // precondition (this row's `materialization_state` genuinely is
        // `Placeholder` at this point).
        let obligation = state
            .sqlite()
            .dag_lookup_projection_obligation(TOCTOU_GROUP, TOCTOU_PATH)
            .unwrap()
            .expect("sanity: the real local emission above must have bumped an obligation");
        assert!(
            state
                .sqlite()
                .dag_complete_obligation_if_non_exact_proof_current(
                    TOCTOU_GROUP,
                    TOCTOU_PATH,
                    obligation.invalidation_generation,
                    obligation.obligation_incarnation,
                    yadorilink_sync_sqlite::projection_obligations::NonExactProofKind::Placeholder,
                )
                .unwrap(),
            "sanity: settling the obligation against this row's genuine Placeholder state must \
             succeed"
        );
        assert!(
            state.sqlite().dag_lookup_projection_obligation(TOCTOU_GROUP, TOCTOU_PATH).unwrap().is_none(),
            "sanity: the obligation must be gone once settled"
        );
        assert!(
            !root.join(TOCTOU_PATH).exists(),
            "sanity: nothing must be on disk under this exact name while held"
        );

        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        (processor, state, root, ignore_set, store_dir, root_dir, content)
    }

    /// FIX ASSERTED (the CANDIDACY-time half -- see the sibling test
    /// below for the SEPARATE pre-commit-window half): the reviewer's own
    /// probe scenario. A path starts hazard-held (matching `hold_record`'s
    /// shape exactly: `Placeholder`, `held_reason` set, nothing on disk,
    /// no intent, no obligation). A live rescan's tombstone-candidate loop
    /// reaches this path; the scan is paused right at LOOP ENTRY for this
    /// path -- BEFORE `recheck_tombstone_candidate` runs at all (this
    /// test's stand-in for the loop simply not having gotten to this path
    /// yet, on a real multi-second walk) -- via `fire_pre_tombstone_
    /// recheck`. While paused, a concurrent task completes the held-to-
    /// materialize transition exactly the way a real `materialize`/
    /// `hydrate_file_with_timeout` success does: `clear_held`, write the
    /// real content under this exact name, stamp `Hydrated`. Resuming the
    /// scan must NOT tombstone this path: `recheck_tombstone_candidate`
    /// only ever runs AFTER the hook releases it, so it reads the
    /// already-fresh, post-transition state directly -- proving the
    /// candidacy-time check itself is correct, not that a candidate which
    /// legitimately passed it earlier stays protected all the way to its
    /// own chunk's commit (that is what the sibling test below proves).
    #[tokio::test]
    async fn live_rescan_does_not_tombstone_a_path_that_completed_materializing_during_the_walk() {
        let (processor, state, root, ignore_set, _store_dir, _root_dir, content) =
            build_toctou_fixture().await;

        let snapshot_read = Arc::new(Latch::new());
        let release_scan = Arc::new(Latch::new());
        {
            let snapshot_read = snapshot_read.clone();
            let release_scan = release_scan.clone();
            scan_test_hooks::set_pre_tombstone_recheck_hook(Some(Arc::new(
                move |gid: &str, path: &str| {
                    if gid != TOCTOU_GROUP || path != TOCTOU_PATH {
                        return;
                    }
                    snapshot_read.raise();
                    release_scan.wait();
                },
            )));
        }

        let scan_root = root.clone();
        let scan_handle = std::thread::spawn(move || {
            processor.scan_existing_files_with_ignore(TOCTOU_GROUP, &scan_root, &ignore_set)
        });

        if !snapshot_read.wait_timeout(std::time::Duration::from_secs(10)) {
            let outcome = if scan_handle.is_finished() {
                format!("scan thread already finished: {:?}", scan_handle.join())
            } else {
                "scan thread is still running".to_string()
            };
            panic!("scan never reached its pre-tombstone-recheck hook within 10s: {outcome}");
        }

        // Complete the held-to-materialize transition while the scan is
        // paused exactly at this path's candidacy check -- the identical
        // end state `materialize`'s on-demand-receive branch or
        // `hydrate_file_with_timeout_locked`'s own success path leaves,
        // driven directly here (rather than through the real production
        // function, which lives in a different crate this one cannot
        // depend on) since only the END STATE matters for this scan's own
        // re-check, not which caller produced it.
        let materialize_root = root.clone();
        let materialize_state = state.clone();
        let materialize_content = content.clone();
        let materialize_task = tokio::task::spawn_blocking(move || {
            std::fs::write(materialize_root.join(TOCTOU_PATH), &materialize_content).unwrap();
            materialize_state.materialization_state_repository().clear_held(TOCTOU_GROUP, TOCTOU_PATH).unwrap();
            materialize_state
                .materialization_state_repository()
                .set_materialization_state(
                    TOCTOU_GROUP,
                    TOCTOU_PATH,
                    MaterializationState::Hydrated,
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap();
        });
        materialize_task.await.unwrap();
        assert!(
            state
                .materialization_state_repository()
                .get_held_state(TOCTOU_GROUP, TOCTOU_PATH)
                .unwrap()
                .is_none(),
            "sanity: the transition must have genuinely cleared the hold before the scan resumes"
        );

        release_scan.raise();
        let records = scan_handle.join().unwrap().unwrap();

        assert!(
            !records.iter().any(|r| r.path == TOCTOU_PATH && r.deleted),
            "a path that finished materializing DURING the scan's walk must never be \
             tombstoned, even though every check read at this path's loop-entry time (before \
             the transition completed) would have said 'genuinely missing, fully unprotected': \
             {records:?}"
        );
        let indexed =
            state.file_index_repository().get_file(TOCTOU_GROUP, TOCTOU_PATH).unwrap().unwrap();
        assert!(!indexed.deleted, "the index row itself must not have been tombstoned either");
    }

    /// FIX ASSERTED (the PRE-COMMIT-WINDOW half -- the sibling test above
    /// proves the candidacy-time check itself is correct; this proves the
    /// window a review found the candidacy-time check ALONE could not
    /// close is closed too). The hold is cleared BEFORE the scan even
    /// starts, so this path legitimately passes its candidacy-time
    /// `recheck_tombstone_candidate` call (nothing protects it, and
    /// nothing is on disk yet) and is added to `records` as a genuine
    /// tombstone candidate -- the candidacy-time guard from that check is
    /// dropped at the end of that loop iteration, long before this exact
    /// path's own chunk actually commits. The scan is then paused a
    /// SECOND time, at the FINAL pre-commit re-check
    /// (`fire_pre_chunk_commit_recheck`, distinct from the candidacy-time
    /// hook the sibling test uses) -- exactly the window between
    /// "candidate accepted" and "chunk committed" that used to have no
    /// re-verification, and no lock held across it, at all. While paused
    /// there, a concurrent task completes a legitimate materialization
    /// (real content lands under this exact name). Resuming must not
    /// tombstone the path: the final re-check's own guard is held all the
    /// way through this chunk's actual commit, so nothing can race it a
    /// second time.
    #[tokio::test]
    async fn live_rescan_does_not_tombstone_a_path_materialized_between_its_candidacy_check_and_its_own_chunk_commit(
    ) {
        let (processor, state, root, ignore_set, _store_dir, _root_dir, content) =
            build_toctou_fixture().await;
        // Cleared before the scan even starts: this path must legitimately
        // pass its candidacy-time check (nothing protects it, nothing on
        // disk) rather than being excluded there the way the sibling
        // test's still-held row is -- the whole point of this test is the
        // window AFTER that acceptance, not a race with the acceptance
        // itself.
        state.materialization_state_repository().clear_held(TOCTOU_GROUP, TOCTOU_PATH).unwrap();

        let snapshot_read = Arc::new(Latch::new());
        let release_scan = Arc::new(Latch::new());
        {
            let snapshot_read = snapshot_read.clone();
            let release_scan = release_scan.clone();
            scan_test_hooks::set_pre_chunk_commit_recheck_hook(Some(Arc::new(
                move |gid: &str, path: &str| {
                    if gid != TOCTOU_GROUP || path != TOCTOU_PATH {
                        return;
                    }
                    snapshot_read.raise();
                    release_scan.wait();
                },
            )));
        }

        let scan_root = root.clone();
        let scan_handle = std::thread::spawn(move || {
            processor.scan_existing_files_with_ignore(TOCTOU_GROUP, &scan_root, &ignore_set)
        });

        if !snapshot_read.wait_timeout(std::time::Duration::from_secs(10)) {
            let outcome = if scan_handle.is_finished() {
                format!("scan thread already finished: {:?}", scan_handle.join())
            } else {
                "scan thread is still running".to_string()
            };
            panic!("scan never reached its pre-chunk-commit-recheck hook within 10s: {outcome}");
        }

        // Complete a legitimate materialization while the scan is paused
        // exactly between this path's candidacy acceptance and its own
        // chunk's actual commit -- the window that has no lock held
        // across it without this round's fix.
        let materialize_root = root.clone();
        let materialize_state = state.clone();
        let materialize_content = content.clone();
        let materialize_task = tokio::task::spawn_blocking(move || {
            std::fs::write(materialize_root.join(TOCTOU_PATH), &materialize_content).unwrap();
            materialize_state
                .materialization_state_repository()
                .set_materialization_state(
                    TOCTOU_GROUP,
                    TOCTOU_PATH,
                    MaterializationState::Hydrated,
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap();
        });
        materialize_task.await.unwrap();

        release_scan.raise();
        let records = scan_handle.join().unwrap().unwrap();
        scan_test_hooks::set_pre_chunk_commit_recheck_hook(None);

        assert!(
            !records.iter().any(|r| r.path == TOCTOU_PATH && r.deleted),
            "a path materialized between its own candidacy acceptance and its chunk's actual \
             commit must never be tombstoned -- the candidacy-time check alone already passed \
             it (correctly, at the time): {records:?}"
        );
        let indexed =
            state.file_index_repository().get_file(TOCTOU_GROUP, TOCTOU_PATH).unwrap().unwrap();
        assert!(!indexed.deleted, "the index row itself must not have been tombstoned either");
    }

    /// `process_event` canonicalizes `root` internally (see its doc
    /// comment — real OS watchers report fully-resolved paths, e.g.
    /// macOS's `/private/var/...` for what looks like `/var/...`), so
    /// tests that hand-construct `FsChangeEvent`s (rather than using a
    /// real `watch_folder`) must build paths from an already-canonical
    /// root to stay consistent, exactly as a real watcher's paths would be.
    fn canonical_root(root_dir: &tempfile::TempDir) -> std::path::PathBuf {
        root_dir.path().canonicalize().unwrap()
    }

    /// Gives `root` a sync-root marker for `group`, the way a healthy install
    /// acquires one: adopt while the index is still empty, which is what a real
    /// first link does.
    ///
    /// Needed only by tests that then index a file with no on-disk counterpart.
    /// Such a root is empty with a non-empty index — byte-for-byte what an
    /// unmounted volume looks like — so `VerifiedRoot::open` would (correctly)
    /// refuse to scan it. Adopting first states the thing those tests actually
    /// assume but cannot otherwise express: the volume is mounted, and the file
    /// really is missing from a folder that really is this link's.
    fn adopt_root(state: &ReplicaCoordinator, group: &str, root: &std::path::Path) {
        // A real link row is required: `set_link_root_token_for_group` is an
        // `UPDATE ... WHERE group_id = ?` with no matching row otherwise, so
        // without this the token silently never persists and a later
        // `VerifiedRoot::verify` (which requires the persisted token, unlike
        // `open`) fails with "no previously-adopted root token". `add_link`
        // is idempotent, so this is safe even when a caller already linked
        // the root itself.
        let _ = state.link_repository().add_link(&root.to_string_lossy(), group);
        yadorilink_root_authority::root_identity::VerifiedRoot::open(root, group, state).unwrap();
    }

    fn expect_file_changed(outcome: LocalChangeOutcome) -> FileRecord {
        match outcome {
            LocalChangeOutcome::FileChanged(record) => record,
            other => panic!("expected FileChanged, got {other:?}"),
        }
    }

    /// wraps a real `FsBlockStore` and counts
    /// `put` calls, so a test can prove the size+mtime fast-path actually
    /// skipped chunking (chunking always calls `put` at least once per
    /// block — see `chunker::chunk_file`) rather than merely asserting on
    /// the returned outcome, which the pre-existing self-echo suppression
    /// could also produce (just after paying for a full chunk first).
    struct CountingBlockStore {
        inner: FsBlockStore,
        put_calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingBlockStore {
        fn new(dir: &std::path::Path) -> Self {
            Self {
                inner: FsBlockStore::new(dir).unwrap(),
                put_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn put_call_count(&self) -> usize {
            self.put_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl yadorilink_local_storage::BlockStore for CountingBlockStore {
        fn put(&self, data: &[u8]) -> Result<String, yadorilink_local_storage::StorageError> {
            self.put_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.put(data)
        }
        fn get(&self, hash: &str) -> Result<Vec<u8>, yadorilink_local_storage::StorageError> {
            self.inner.get(hash)
        }
        fn delete(&self, hash: &str) -> Result<(), yadorilink_local_storage::StorageError> {
            self.inner.delete(hash)
        }
        fn exists(&self, hash: &str) -> Result<bool, yadorilink_local_storage::StorageError> {
            self.inner.exists(hash)
        }
        fn list_by_prefix(
            &self,
            prefix: &str,
        ) -> Result<Vec<String>, yadorilink_local_storage::StorageError> {
            self.inner.list_by_prefix(prefix)
        }
        // This test double's whole job is counting `put` calls (see its
        // own doc comment) — every other method,
        // this one included, is a pure passthrough to the wrapped real
        // `FsBlockStore`, not something these tests exercise.
        fn sweep(
            &self,
            live_hashes: &std::collections::HashSet<String>,
            older_than: std::time::SystemTime,
            dry_run: bool,
        ) -> Result<yadorilink_local_storage::GcReport, yadorilink_local_storage::StorageError>
        {
            self.inner.sweep(live_hashes, older_than, dry_run)
        }
    }

    fn processor_with_counting_store() -> (
        LocalChangeProcessor,
        Arc<TestReplica>,
        Arc<CountingBlockStore>,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(CountingBlockStore::new(store_dir.path()));
        let state = Arc::new(TestReplica::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        (
            LocalChangeProcessor::new(
                state.clone(),
                store.clone(),
                "device-a".into(),
                std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
            ),
            state,
            store,
            store_dir,
            root_dir,
        )
    }

    /// a `CreatedOrModified` event for a file
    /// whose size and mtime are both unchanged from the indexed record
    /// must resolve via the fast-path — no new block ever gets `put` into
    /// the store, proving the file was never re-chunked. The fast-path does
    /// now read the bytes once to verify them against the indexed block
    /// hashes (`disk_bytes_match_indexed_blocks`, so a size+mtime-preserved
    /// content edit can't slip through), but that verification streams and
    /// compares without ever re-chunking or writing a block — exactly what
    /// the unchanged `put` count proves: no store churn, no re-index.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unchanged_size_and_mtime_skips_rechunking_entirely() {
        let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("steady.bin");
        std::fs::write(&file_path, vec![b'x'; 5_000_000]).unwrap();

        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let calls_after_first = store.put_call_count();
        assert!(calls_after_first > 0, "the initial index must actually chunk the file");

        // No filesystem-level change at all: same bytes, same size, same
        // mtime — exactly what a self-echo or a redundant watcher event
        // for the same save looks like.
        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert_eq!(outcome, LocalChangeOutcome::None);
        assert_eq!(
            store.put_call_count(),
            calls_after_first,
            "size+mtime fast-path must skip chunking entirely, not just suppress the resulting record"
        );
        assert_eq!(
            state.sqlite().dag_list_versions("group-1", "steady.bin").unwrap().len(),
            1,
            "no spurious version bump from an unchanged file"
        );
    }

    /// DI-3 tail closed: a content edit that preserves BOTH the byte length
    /// AND the mtime (an in-place same-length overwrite, or any writer that
    /// restores mtime via `utimes` after editing) must NOT be trusted as
    /// unchanged on the strength of the stat metadata alone. The size+mtime
    /// fast-path now verifies the on-disk bytes against the indexed block
    /// hashes before concluding "no-op", so this edit is detected and
    /// re-indexed rather than silently pinning the index at the stale
    /// version while disk holds new bytes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identical_size_and_mtime_with_different_bytes_is_now_detected() {
        let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("edge-case.bin");
        std::fs::write(&file_path, vec![b'A'; 20]).unwrap();

        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let indexed_before =
            state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();
        let calls_after_first = store.put_call_count();
        let original_mtime = std::time::UNIX_EPOCH
            + std::time::Duration::from_nanos(indexed_before.mtime_unix_nanos as u64);

        // Same length (20 bytes), different bytes, mtime forced back to
        // exactly what was indexed — size AND mtime now both match the
        // index, so only a content comparison can tell this apart from a
        // genuine no-op.
        std::fs::write(&file_path, vec![b'B'; 20]).unwrap();
        // Windows' SetFileTime requires the handle to have been opened with
        // write access -- File::open is read-only there and fails this
        // with ACCESS_DENIED (Unix's utimensat has no such requirement, so
        // this only ever surfaced on this suite's first real Windows run).
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap()
            .set_modified(original_mtime)
            .unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert!(!record.deleted, "the edit must surface as a live change, not a tombstone");
        assert_ne!(
            record.blocks, indexed_before.blocks,
            "the detected edit must carry the new on-disk content's blocks"
        );
        assert!(
            store.put_call_count() > calls_after_first,
            "detecting the size+mtime-preserved edit requires actually re-chunking the new bytes"
        );
        let indexed_after =
            state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();
        assert_ne!(
            indexed_after.blocks, indexed_before.blocks,
            "the index must be re-versioned to the new content, not left at the stale blocks"
        );
    }

    // --- Regression coverage for the two materialized-file exec-bit gaps
    // (phase7e exit report, "addressing code review on PR #31" addendum):
    //
    // Gap 1: a materialized (peer-received) file's on-disk mtime never used
    // to be stamped to match the wire-carried authored mtime the index
    // recorded for it (`reconstruct_file` just wrote a fresh temp file with
    // whatever wall-clock mtime that happened to land at), so the size+mtime
    // fast path's `metadata_mtime_matches` check could never hold for such
    // a file -- a genuine local edit on it always fell through to the
    // content-only self-echo comparison further down instead.
    //
    // Gap 2: that content-only self-echo comparison never checked the exec
    // bit at all, so a content-identical edit whose exec bit genuinely
    // diverged from the index (a chmod-only edit being the paradigm case,
    // but reachable by any local write whose freshly-chunked bytes already
    // match what's indexed) was silently dropped -- no version bump, no
    // emitted change, no error.

    /// Gap 1 + gap 2 together, end to end: materialize a file the real
    /// production way (`reconstruct_file`, exactly as `PeerSyncSession::
    /// materialize`/`hydrate_file` call it), then perform a genuine
    /// chmod-only local edit on it, and confirm it is captured as a real
    /// change -- not silently dropped the way both gaps combined used to
    /// drop it.
    #[cfg(unix)]
    #[tokio::test]
    async fn chmod_only_edit_on_a_peer_materialized_file_is_captured() {
        use std::os::unix::fs::PermissionsExt;

        let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);

        // Simulate a peer materializing a file onto this device: chunk the
        // content into the block store (as the eager fetch in `materialize`
        // would), then write it to disk via the REAL production
        // `reconstruct_file` under a wire-carried authored mtime far from
        // "now" -- a materialized file's indexed mtime is the AUTHORING
        // device's mtime, not this device's wall clock, which is exactly
        // the condition gap 1 was about.
        let content = b"#!/bin/sh\necho hi\n";
        let scratch = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(scratch.path(), content).unwrap();
        let blocks = yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap();
        let file_path = root.join("received.sh");
        const PEER_AUTHORED_MTIME: i64 = 1_600_000_000_000_000_000;
        yadorilink_local_storage::reconstruct_file(
            store.as_ref(),
            &file_path,
            &blocks,
            PEER_AUTHORED_MTIME,
        )
        .unwrap();
        yadorilink_local_storage::apply_unix_mode(&file_path, Some(0o644)).unwrap();

        let record = FileRecord {
            path: "received.sh".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: PEER_AUTHORED_MTIME,
            blocks: blocks.clone(),
            deleted: false,
        };
        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .file_index_repository()
            .set_unix_mode(
                "group-1",
                "received.sh",
                Some(0o644),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // Sanity: the on-disk mtime really was stamped to match the index
        // -- otherwise this test would not actually be exercising the
        // materialized-file scenario gap 1 was about.
        let disk_mtime_after_materialize = std::fs::metadata(&file_path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        assert_eq!(
            disk_mtime_after_materialize, PEER_AUTHORED_MTIME,
            "sanity: reconstruct_file must stamp disk mtime to match the indexed authored mtime"
        );

        let calls_after_materialize = store.put_call_count();

        // The genuine local edit: chmod +x, content untouched. On POSIX a
        // chmod touches ctime, not mtime, so disk mtime stays exactly what
        // materialize stamped it to -- this is what makes the size+mtime
        // fast path reachable at all for this edit.
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let disk_mtime_after_chmod = std::fs::metadata(&file_path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        assert_eq!(
            disk_mtime_after_chmod, PEER_AUTHORED_MTIME,
            "sanity: a chmod alone must not itself change mtime on this platform"
        );

        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        let record_after = expect_file_changed(outcome);
        assert_eq!(
            record_after.blocks, blocks,
            "content is unchanged -- this must be a metadata-only change, not a re-chunk"
        );
        assert_eq!(
            store.put_call_count(),
            calls_after_materialize,
            "a chmod-only edit on a materialized file must reach the size+mtime fast path (gap 1 \
             fixed), not fall through to a full re-chunk"
        );
        assert_eq!(
            state.file_index_repository().get_unix_mode("group-1", "received.sh").unwrap(),
            Some(0o755),
            "the real chmod +x must be captured and indexed, not silently dropped"
        );
        assert_eq!(
            state.sqlite().dag_list_versions("group-1", "received.sh").unwrap().len(),
            2,
            "the exec-bit-only change must mint a new version alongside the materialized one, not \
             be silently swallowed"
        );
    }

    /// Gap 2 in isolation: a chmod-only edit that reaches the content-only
    /// self-echo comparison specifically (not the size+mtime fast path --
    /// forced by desynchronizing the indexed mtime from disk without
    /// touching the file) must still be captured, not dropped by a
    /// content-only comparison that never looked at the exec bit.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chmod_only_edit_reaching_the_content_only_self_echo_path_is_still_captured() {
        use std::os::unix::fs::PermissionsExt;

        let (proc, state, _store, _store_dir, root_dir) = processor_with_counting_store();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("script.sh");
        let content = b"#!/bin/sh\necho hi\n";
        std::fs::write(&file_path, content).unwrap();

        let record_after_create = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        assert!(
            !state
                .file_index_repository()
                .get_unix_mode("group-1", "script.sh")
                .unwrap()
                .is_some_and(|mode| mode & 0o100 != 0),
            "sanity: a freshly-written file is not executable by default"
        );

        // Deliberately desynchronize the INDEXED mtime from disk, without
        // touching the file itself -- forces `current_mtime_matches` to be
        // false on the next event, skipping the size+mtime fast path
        // entirely and falling through to the content-only self-echo
        // comparison a few lines further down
        // `build_record_for_created_or_modified`, so this test exercises
        // THAT check specifically, not the fast path's own (already
        // correct, pre-existing) exec-bit comparison.
        let mut desynced = record_after_create.clone();
        desynced.mtime_unix_nanos += 1;
        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &desynced,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // The genuine local edit: chmod +x, content untouched.
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        let record_after_chmod = expect_file_changed(outcome);
        assert_eq!(
            record_after_chmod.blocks, record_after_create.blocks,
            "content is genuinely unchanged"
        );
        assert_eq!(
            state.file_index_repository().get_unix_mode("group-1", "script.sh").unwrap(),
            Some(0o755),
            "the chmod +x reaching the content-only self-echo comparison must still be captured, \
             not silently dropped (gap 2)"
        );
    }

    /// No-regression check for the loop-prevention self-echo suppression
    /// this pass's production-code change must not break: a genuine
    /// materialization echo (this device's own watcher firing for a write
    /// `reconstruct_file` itself just performed, with content AND exec bit
    /// both already agreeing with the index) must still resolve to a no-op
    /// via the fast path -- no re-chunk, no spurious version, no emitted
    /// change.
    #[cfg(unix)]
    #[tokio::test]
    async fn materialize_echo_with_matching_content_and_unix_mode_stays_a_no_op() {
        let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);

        let content = b"peer content, unchanged\n";
        let scratch = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(scratch.path(), content).unwrap();
        let blocks = yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap();
        let file_path = root.join("mirrored.txt");
        const PEER_MTIME: i64 = 1_650_000_000_000_000_000;
        yadorilink_local_storage::reconstruct_file(store.as_ref(), &file_path, &blocks, PEER_MTIME)
            .unwrap();
        yadorilink_local_storage::apply_unix_mode(&file_path, Some(0o755)).unwrap();

        let record = FileRecord {
            path: "mirrored.txt".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: PEER_MTIME,
            blocks: blocks.clone(),
            deleted: false,
        };
        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .file_index_repository()
            .set_unix_mode(
                "group-1",
                "mirrored.txt",
                Some(0o755),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let calls_before = store.put_call_count();

        // This device's own watcher firing for the write `reconstruct_file`
        // just did, exactly as this module's own doc comment describes --
        // must resolve to a no-op via the fast path (mtime/size/content/
        // exec bit all already agree), the same loop-prevention this pass's
        // production-code change must not break.
        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert_eq!(
            outcome,
            LocalChangeOutcome::None,
            "a genuine materialization echo must stay suppressed"
        );
        assert_eq!(
            store.put_call_count(),
            calls_before,
            "must resolve via the fast path (mtime matches after gap 1's fix), no re-chunk"
        );
        assert_eq!(
            state.sqlite().dag_list_versions("group-1", "mirrored.txt").unwrap().len(),
            1,
            "must stay at exactly the one version this test's own seeding upsert created -- no \
             spurious second version from the watcher echo"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn created_file_is_chunked_and_indexed() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("hello.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert_eq!(record.path, "hello.txt");
        assert_eq!(record.size, 11);
        assert_eq!(record.blocks.len(), 1);
        // Causality is the retained version history now, not a counter: a
        // first indexing must leave exactly one version, authored here.
        let versions = state.sqlite().dag_list_versions("group-1", "hello.txt").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].origin_device_id.as_deref(), Some("device-a"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rename_produces_identical_block_hashes_as_the_original() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let original = root.join("original.txt");
        std::fs::write(&original, b"unchanged content").unwrap();
        let created = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: original.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        // Simulate a rename: delete the old path, create the new one with
        // byte-identical content (nothing edited).
        std::fs::remove_file(&original).unwrap();
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: original, kind: FsChangeKind::Removed },
        )
        .await
        .unwrap();

        let renamed = root.join("renamed.txt");
        std::fs::write(&renamed, b"unchanged content").unwrap();
        let recreated = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: renamed, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert_eq!(
            created.blocks, recreated.blocks,
            "unchanged content must hash to identical blocks"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn removed_file_is_marked_deleted_with_incremented_version() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("bye.txt");
        std::fs::write(&file_path, b"data").unwrap();
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

        // `process_event` now derives Removed-vs-CreatedOrModified from
        // the path's actual
        // current disk state rather than trusting `event.kind` verbatim
        // (closing a race where a debounce-coalesced `Removed` could be
        // silently overwritten by an unrelated later write to the same
        // path) -- so this synthetic `Removed` event must correspond to a
        // real deletion, matching what a genuine watcher would only ever
        // report after the fact.
        std::fs::remove_file(&file_path).unwrap();
        let tombstone = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::Removed },
            )
            .await
            .unwrap(),
        );

        assert!(tombstone.deleted);
        // The tombstone is a second retained version of the same path, not an
        // in-place rewrite of the first.
        assert_eq!(state.sqlite().dag_list_versions("group-1", "bye.txt").unwrap().len(), 2);
    }

    #[tokio::test]
    async fn deleting_never_indexed_ignored_paths_generates_no_tombstone() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let ignore_set = EffectiveIgnoreSet::from_user_patterns("*.tmp\n");

        let user_ignored = root.join("scratch.tmp");
        let user_outcome = proc
            .process_event_with_ignore(
                "group-1",
                &root,
                &FsChangeEvent { path: user_ignored, kind: FsChangeKind::Removed },
                &ignore_set,
            )
            .await
            .unwrap();
        assert_eq!(user_outcome, LocalChangeOutcome::None);
        assert!(state
            .file_index_repository()
            .get_file("group-1", "scratch.tmp")
            .unwrap()
            .is_none());

        let built_in_ignored = root.join(".DS_Store");
        let built_in_outcome = proc
            .process_event_with_ignore(
                "group-1",
                &root,
                &FsChangeEvent { path: built_in_ignored, kind: FsChangeKind::Removed },
                &ignore_set,
            )
            .await
            .unwrap();
        assert_eq!(built_in_outcome, LocalChangeOutcome::None);
        assert!(state.file_index_repository().get_file("group-1", ".DS_Store").unwrap().is_none());
    }

    /// Placeholder creation is not treated
    /// as a local edit": a placeholder's own write must not be indexed as
    /// a genuine local change, or chunked (which would index wrong content
    /// — the placeholder's sparse bytes, not the file's real ones).
    /// Unix-only: exercises the `(dev, ino)` identity path specifically --
    /// `write_placeholder` only captures an identity on Unix (see its own
    /// doc comment), so this test's `.expect(...)` on that identity would
    /// panic on a platform where it always returns `None`.
    #[tokio::test]
    #[cfg(unix)]
    async fn placeholder_write_is_not_treated_as_a_local_edit() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("placeholder.bin");

        // Simulate what `peer_session::materialize` does for an `OnDemand`
        // folder: index a record, then mark it Placeholder, before the
        // sparse file itself is written to disk.
        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "placeholder.bin".into(),
                    size: 5_000_000,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: vec![0xAB; 32],
                        offset: 0,
                        size: 5_000_000,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let identity = yadorilink_local_storage::write_placeholder(&file_path, 5_000_000, 0)
            .unwrap()
            .expect("this test runs on unix, where an identity is always captured");
        state
            .materialization_state_repository()
            .record_placeholder_generation(
                "group-1",
                "placeholder.bin",
                identity,
                yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let result = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert_eq!(
            result,
            LocalChangeOutcome::None,
            "a placeholder's own write must not be indexed as a local edit"
        );
        assert_eq!(
            state.sqlite().dag_list_versions("group-1", "placeholder.bin").unwrap().len(),
            1,
            "no spurious local version bump"
        );
    }

    /// The exact gap M1-2 closes, that the old size/mtime/sparse-file
    /// heuristic documented but could never fix: an atomic-save editor
    /// replaces the placeholder with a real file of the SAME size, stamped
    /// to the SAME mtime -- indistinguishable from an untouched placeholder
    /// by size and mtime alone, but the rename mints a fresh inode. Unix-
    /// only, same reason as the sibling placeholder tests above.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(unix)]
    async fn atomic_replace_edit_at_the_placeholders_exact_size_and_mtime_is_captured() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("placeholder.bin");
        let content_size: u64 = 64;

        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "placeholder.bin".into(),
                    size: content_size,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: vec![0xAB; 32],
                        offset: 0,
                        size: content_size as u32,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let identity = yadorilink_local_storage::write_placeholder(&file_path, content_size, 0)
            .unwrap()
            .expect("this test runs on unix, where an identity is always captured");
        state
            .materialization_state_repository()
            .record_placeholder_generation(
                "group-1",
                "placeholder.bin",
                identity,
                yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // Simulate an atomic-save editor: write the SAME-size real content
        // to a sibling temp path, stamp it to the EXACT same mtime the
        // placeholder carries, then rename it over the placeholder's own
        // path -- an ordinary editor save flow, and the exact edit shape
        // the old size/mtime/sparse heuristic could never distinguish from
        // an untouched placeholder.
        let tmp_path = root.join("placeholder.bin.editor-tmp");
        std::fs::write(&tmp_path, vec![0x42u8; content_size as usize]).unwrap();
        std::fs::File::open(&tmp_path).unwrap().set_modified(std::time::UNIX_EPOCH).unwrap();
        std::fs::rename(&tmp_path, &file_path).unwrap();

        let result = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert!(
            matches!(result, LocalChangeOutcome::FileChanged(_)),
            "an atomic-save edit landing at the placeholder's exact size and mtime must be \
             captured, not discarded as a self-echo -- got {result:?}"
        );
    }

    /// The OLD size/mtime/sparse-file heuristic caught an in-place edit
    /// (same inode, real bytes written directly into the placeholder's
    /// path rather than an atomic rename) via its sparse-file check: real
    /// content allocates disk blocks. A second independent review's
    /// finding: an identity-only comparison LOSES that coverage, since an
    /// in-place write never changes the inode. This pins the fix requiring
    /// BOTH identity match and continued sparseness.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(unix)]
    async fn in_place_edit_that_keeps_the_same_inode_is_still_captured() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("placeholder.bin");
        let content_size: u64 = 64;

        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "placeholder.bin".into(),
                    size: content_size,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: vec![0xAB; 32],
                        offset: 0,
                        size: content_size as u32,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let identity = yadorilink_local_storage::write_placeholder(&file_path, content_size, 0)
            .unwrap()
            .expect("this test runs on unix, where an identity is always captured");
        state
            .materialization_state_repository()
            .record_placeholder_generation(
                "group-1",
                "placeholder.bin",
                identity,
                yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // Write real content directly into the placeholder's own path (no
        // rename) -- the same inode as before, but no longer sparse, and
        // restore the exact original mtime afterward so size AND mtime
        // both still match the untouched placeholder too.
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().write(true).open(&file_path).unwrap();
            file.write_all(&vec![0x99u8; content_size as usize]).unwrap();
            file.sync_all().unwrap();
        }
        std::fs::File::open(&file_path).unwrap().set_modified(std::time::UNIX_EPOCH).unwrap();

        let result = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert!(
            matches!(result, LocalChangeOutcome::FileChanged(_)),
            "an in-place edit that keeps the same inode but writes real content must still be \
             captured -- got {result:?}"
        );
    }

    /// M1-5's defense-in-depth fallback: a placeholder with NO recorded
    /// identity at all (simulating `backfill_placeholder_generations`
    /// having not yet run, or having failed for this specific path) must
    /// still be recognized as untouched when it is still fully sparse at
    /// exactly the indexed size -- otherwise this exact event would
    /// chunk and index the placeholder's own sparse/all-zero bytes as a
    /// genuine local edit.
    #[tokio::test]
    #[cfg(unix)]
    async fn placeholder_with_no_recorded_identity_is_still_untouched_when_still_sparse() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("placeholder.bin");
        let content_size: u64 = 4096;

        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "placeholder.bin".into(),
                    size: content_size,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: vec![0xAB; 32],
                        offset: 0,
                        size: content_size as u32,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // Deliberately no `record_placeholder_generation` call -- this is
        // the exact state a crashed-before-backfill (or backfill-failed)
        // path is left in. The file itself is still the genuine, untouched
        // sparse placeholder.
        yadorilink_local_storage::write_placeholder(&file_path, content_size, 0).unwrap();

        let result = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert_eq!(
            result,
            LocalChangeOutcome::None,
            "a still-sparse placeholder at the exact indexed size must be recognized as \
             untouched even with no recorded identity -- got {result:?}"
        );
    }

    /// An independent review's finding: this platform has no real OS
    /// transparent-hydration provider wired up yet, so a `Placeholder`
    /// row's on-disk file is, today, an ordinary sparse file at an
    /// ordinary path -- nothing stops a user (or an editor) from writing
    /// directly to it. Before this fix, `build_record_for_created_or_
    /// modified` treated EVERY `CreatedOrModified` event on a `Placeholder`
    /// path as this crate's own echo, unconditionally -- a genuine user
    /// edit was silently and permanently discarded: never chunked, never
    /// indexed, with a later `hydrate` then overwriting it again with the
    /// stale synced content and no error or warning anywhere. This is the
    /// counterpart to `placeholder_write_is_not_treated_as_a_local_edit`
    /// above: that test proves the crate's OWN untouched placeholder write
    /// is still correctly ignored; this one proves a REAL edit (here,
    /// simulated as different-length content landing at the placeholder's
    /// path) is not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_direct_edit_to_a_placeholder_file_is_captured_not_silently_discarded() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("placeholder.bin");

        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "placeholder.bin".into(),
                    size: 5_000_000,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: vec![0xAB; 32],
                        offset: 0,
                        size: 5_000_000,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        yadorilink_local_storage::write_placeholder(&file_path, 5_000_000, 0).unwrap();

        // A direct user edit: real content, deliberately a different
        // length than the placeholder's own 5,000,000-byte sparse stand-in
        // -- simulating a user opening what looks like an ordinary file
        // and saving over it.
        std::fs::write(&file_path, b"the user's real, unsaved-by-the-index-yet edit").unwrap();

        let result = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert_ne!(
            result,
            LocalChangeOutcome::None,
            "a genuine edit landing at a placeholder's path must not be silently discarded as \
             self-echo"
        );
        let record =
            state.file_index_repository().get_file("group-1", "placeholder.bin").unwrap().unwrap();
        assert_eq!(
            record.size,
            b"the user's real, unsaved-by-the-index-yet edit".len() as u64,
            "the index must reflect the user's real edit, not the stale placeholder size"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_edit_while_hydrating_is_captured() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("edited-during-hydration.bin");
        std::fs::write(&file_path, b"initial bytes").unwrap();
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "edited-during-hydration.bin",
                MaterializationState::Hydrating,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        std::fs::write(&file_path, b"new local bytes that must win").unwrap();
        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        let changed = expect_file_changed(outcome);
        assert_eq!(changed.size, b"new local bytes that must win".len() as u64);
        assert_eq!(
            state
                .sqlite()
                .dag_list_versions("group-1", "edited-during-hydration.bin")
                .unwrap()
                .len(),
            2,
            "the local edit must be retained as a second version"
        );
    }

    #[test]
    fn scan_existing_files_skips_ignored_directories_and_leaf_files() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let ignore_set = EffectiveIgnoreSet::from_user_patterns("node_modules/\nsrc/*.log\n");
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("node_modules/pkg/index.js"), b"ignored dependency").unwrap();
        std::fs::write(root.join("src/debug.log"), b"ignored log").unwrap();
        std::fs::write(root.join("src/keep.txt"), b"kept").unwrap();
        std::fs::write(root.join(".yadorilinkignore"), b"node_modules/\n").unwrap();

        let records = proc.scan_existing_files_with_ignore("group-1", &root, &ignore_set).unwrap();
        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, vec!["src/keep.txt"]);
        assert!(state
            .file_index_repository()
            .get_file("group-1", "node_modules/pkg/index.js")
            .unwrap()
            .is_none());
        assert!(state
            .file_index_repository()
            .get_file("group-1", "src/debug.log")
            .unwrap()
            .is_none());
        assert!(state
            .file_index_repository()
            .get_file("group-1", ".yadorilinkignore")
            .unwrap()
            .is_none());
    }

    /// M5-A review follow-up (blocker #56, second round): a local scan's
    /// commit must record a materialized fingerprint for every non-deleted
    /// file it indexes -- without this, `hydration.rs::hydrate_inner`'s
    /// already-Hydrated shortcut would treat this row as "never proven"
    /// (a version bump alone never carries the fingerprint columns
    /// forward from any prior row) and reconstruct over any subsequent,
    /// not-yet-journaled local edit, exactly the clobber that fix exists
    /// to prevent.
    #[test]
    fn scan_existing_files_records_a_materialized_fingerprint_for_each_indexed_file() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("doc.txt"), b"locally authored content").unwrap();

        proc.scan_existing_files("group-1", &root).unwrap();

        assert!(
            state
                .materialization_state_repository()
                .get_materialized_fingerprint("group-1", "doc.txt")
                .unwrap()
                .is_some(),
            "a fresh local scan must record a fingerprint for the file it just indexed, or the \
             already-Hydrated fast path treats it as unproven and reconstructs over a later, \
             not-yet-journaled edit"
        );
    }

    #[test]
    fn scan_existing_files_drops_newly_ignored_index_entries_without_tombstones() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("keep.txt"), b"kept").unwrap();
        std::fs::write(root.join("ignored.txt"), b"still on disk").unwrap();
        let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(first_scan.len(), 2);
        assert!(state
            .file_index_repository()
            .get_file("group-1", "ignored.txt")
            .unwrap()
            .is_some());

        let ignore_set = EffectiveIgnoreSet::from_user_patterns("ignored.txt\n");
        let rescan = proc.scan_existing_files_with_ignore("group-1", &root, &ignore_set).unwrap();

        assert!(
            rescan.iter().all(|record| record.path != "ignored.txt"),
            "newly ignored paths must not be emitted as tombstones: {rescan:?}"
        );
        assert!(state
            .file_index_repository()
            .get_file("group-1", "ignored.txt")
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read(root.join("ignored.txt")).unwrap(), b"still on disk");
        assert!(state.file_index_repository().get_file("group-1", "keep.txt").unwrap().is_some());
    }

    #[test]
    fn scan_existing_files_indexes_previously_ignored_file_after_pattern_removal() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("build.log"), b"now wanted").unwrap();
        let ignored = EffectiveIgnoreSet::from_user_patterns("*.log\n");
        let first_scan = proc.scan_existing_files_with_ignore("group-1", &root, &ignored).unwrap();
        assert!(first_scan.is_empty());
        assert!(state.file_index_repository().get_file("group-1", "build.log").unwrap().is_none());

        let unignored = EffectiveIgnoreSet::defaults_only();
        let rescan = proc.scan_existing_files_with_ignore("group-1", &root, &unignored).unwrap();

        assert_eq!(rescan.len(), 1);
        assert_eq!(rescan[0].path, "build.log");
        assert!(state.file_index_repository().get_file("group-1", "build.log").unwrap().is_some());
    }

    /// a single scan correctly handles
    /// a mix of already-current, changed, and brand-new files together,
    /// using the bulk-loaded `list_files`/`list_materialization_states`
    /// maps rather than a per-file lookup for any of them.
    #[test]
    fn scan_existing_files_handles_a_mix_of_unchanged_changed_and_new_files() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

        std::fs::write(root.join("unchanged.txt"), b"same content").unwrap();
        let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(first_scan.len(), 1);
        let original_version_count =
            state.sqlite().dag_list_versions("group-1", "unchanged.txt").unwrap().len();

        // Now: leave "unchanged.txt" alone, modify "unchanged.txt" would
        // contradict its name, so instead add a genuinely-changed file
        // and a genuinely-new file, then rescan everything together.
        std::fs::write(root.join("changed-later.txt"), b"v1").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();
        std::fs::write(root.join("changed-later.txt"), b"v2, now longer").unwrap();
        std::fs::write(root.join("brand-new.txt"), b"never seen before").unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let paths: std::collections::HashSet<&str> =
            records.iter().map(|r| r.path.as_str()).collect();
        // "unchanged.txt" is already current (same size) so it's not
        // re-indexed by this final scan; the other two are.
        assert_eq!(paths, std::collections::HashSet::from(["changed-later.txt", "brand-new.txt"]));

        assert_eq!(
            state.sqlite().dag_list_versions("group-1", "unchanged.txt").unwrap().len(),
            original_version_count,
            "untouched file's version must not bump"
        );
        let changed = state
            .file_index_repository()
            .get_file("group-1", "changed-later.txt")
            .unwrap()
            .unwrap();
        assert_eq!(changed.size, "v2, now longer".len() as u64);
    }

    /// A full scan is authoritative only when its root was actually
    /// traversable. A temporarily unavailable mount/root must not look like
    /// an empty directory and turn every previously indexed path into a
    /// tombstone that is then propagated to the mesh.
    #[test]
    fn root_unavailable_scan_must_not_tombstone_indexed_files() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();

        std::fs::remove_dir_all(&root).unwrap();
        let result = proc.scan_existing_files("group-1", &root);

        assert!(result.is_err(), "an unavailable scan root must not be reported as complete");
        let indexed =
            state.file_index_repository().get_file("group-1", "survives.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "an incomplete scan must never create a tombstone");
    }

    /// The case an existence check structurally cannot catch, and the reason the
    /// guard is an identity check rather than an availability one: unmounting a
    /// volume leaves its mountpoint behind as an ordinary EMPTY directory. The
    /// root still exists, still canonicalizes, still walks — it just has nothing
    /// in it. Every indexed file therefore looks deleted, and a full scan is
    /// authoritative, so without this the whole folder tombstones and those
    /// tombstones replicate to every device: unplugging a drive destroys the
    /// data everywhere.
    ///
    /// Deliberately does NOT `remove_dir_all` the root — that is the
    /// already-covered root-*removed* case above, which the old
    /// `canonicalize()?` guard caught. The point here is that the directory is
    /// present and readable and the scan must still refuse.
    #[test]
    fn empty_but_present_root_must_not_tombstone_indexed_files() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();
        // Simulate the unmount: the mountpoint directory survives, empty. The
        // marker went with the volume, exactly as the content did — that is why
        // it is the marker, and not the path, that carries the identity.
        std::fs::remove_file(root.join("survives.txt")).unwrap();
        std::fs::remove_file(
            root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        )
        .unwrap();
        assert!(root.is_dir(), "the mountpoint directory must still be present for this test");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0, "and it must be empty");

        let result = proc.scan_existing_files("group-1", &root);

        assert!(
            result.is_err(),
            "an empty-but-present root is indistinguishable from an unmounted volume and must \
             not be reported as an authoritative empty scan"
        );
        let indexed =
            state.file_index_repository().get_file("group-1", "survives.txt").unwrap().unwrap();
        assert!(
            !indexed.deleted,
            "a scan that could not establish its root's identity must emit no tombstone"
        );
    }

    /// The wrong-volume variant: something IS mounted at the root and it does
    /// carry a marker, but the marker is not this link's. A restored backup,
    /// another device's copy of the same folder, or a different volume mounted
    /// at the same path. Its contents are not this link's history, so scanning
    /// it authoritatively would tombstone everything the real folder holds.
    #[test]
    fn a_root_marked_for_a_different_link_must_not_tombstone_indexed_files() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();

        // Swap in a foreign volume: same path, populated, but a marker naming a
        // different group and token.
        std::fs::remove_file(root.join("survives.txt")).unwrap();
        std::fs::write(root.join("someone-elses-file.txt"), b"not ours").unwrap();
        std::fs::write(
            root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
            br#"{"group_id":"a-different-group","root_token":"0123456789abcdef"}"#,
        )
        .unwrap();

        let result = proc.scan_existing_files("group-1", &root);

        assert!(result.is_err(), "a root carrying another link's marker must be refused");
        let indexed =
            state.file_index_repository().get_file("group-1", "survives.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "refusing must emit no tombstone");
        assert!(
            state
                .file_index_repository()
                .get_file("group-1", "someone-elses-file.txt")
                .unwrap()
                .is_none(),
            "and must not index the foreign volume's contents into this group"
        );
    }

    /// The token half of the check, isolated: the marker names the right group,
    /// so only the persisted token can tell this folder from the real one. This
    /// is the restored-backup / duplicated-copy case — the group is genuinely
    /// ours, the folder is not.
    #[test]
    fn a_root_whose_marker_token_is_not_the_adopted_one_must_not_tombstone_indexed_files() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();
        state.link_repository().add_link(&root.to_string_lossy(), "group-1").unwrap();
        state
            .link_repository()
            .set_link_root_token_for_group("group-1", "the-token-we-really-adopted")
            .unwrap();

        std::fs::remove_file(root.join("survives.txt")).unwrap();
        std::fs::write(
            root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
            br#"{"group_id":"group-1","root_token":"a-stale-token-from-a-copy"}"#,
        )
        .unwrap();

        let result = proc.scan_existing_files("group-1", &root);

        assert!(result.is_err(), "a marker whose token is not the adopted one must be refused");
        let indexed =
            state.file_index_repository().get_file("group-1", "survives.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "refusing must emit no tombstone");
    }

    /// The backfill path that makes the guard deployable: an install that
    /// predates root identity has no marker on any link. Refusing those would
    /// break every existing install on upgrade, so a root that corroborates the
    /// index (its files are really there) is adopted in place and scans on.
    #[test]
    fn an_unmarked_root_that_still_holds_its_indexed_files_is_adopted_on_upgrade() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();
        // Rewind to the pre-upgrade shape: index populated, no marker anywhere.
        std::fs::remove_file(
            root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        )
        .unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();

        assert!(
            root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME).exists(),
            "the upgrade boot must adopt the folder it just corroborated"
        );
        assert!(!records.iter().any(|r| r.deleted), "adoption must not tombstone anything");
        let indexed =
            state.file_index_repository().get_file("group-1", "survives.txt").unwrap().unwrap();
        assert!(!indexed.deleted);
    }

    /// Indexes a `Hydrated`-but-missing file: a `FileRecord` with real block
    /// info marked `Hydrated`, whose bytes are NOT present on disk. This is the
    /// shape the startup Full scan sees for both a crash-mid-materialize (the
    /// rename never completed) and a genuine offline deletion — the two are told
    /// apart only by the materialization intent.
    fn index_hydrated_missing_file(state: &ReplicaCoordinator, group: &str, path: &str) {
        state
            .file_index_repository()
            .upsert_file(
                group,
                &FileRecord {
                    path: path.into(),
                    size: 11,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: vec![0xAB; 32],
                        offset: 0,
                        size: 11,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                group,
                path,
                MaterializationState::Hydrated,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }

    /// The crux crash-safety guarantee: a crash mid-eager-materialize leaves a
    /// `Hydrated` row whose file is missing but whose write is still recorded by
    /// an OPEN materialization intent. The startup Full scan must NOT tombstone
    /// it — it is reconstructable from the locally-present blocks and repair
    /// will heal it. Tombstoning here would propagate a `Delete` group-wide and
    /// silently destroy a fully-reconstructable file.
    #[test]
    fn crash_mid_materialize_missing_file_with_open_intent_is_not_tombstoned() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        index_hydrated_missing_file(&state, "group-1", "doc.txt");
        // The durable "materialization write in progress" signal a crash left
        // behind — the disambiguator that makes this a crash, not a deletion.
        state
            .materialization_intent_repository()
            .begin_materialization_intent(
                "group-1",
                "doc.txt",
                &[0xAB; 32],
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // A normal boot's Full scan (tombstones enabled). The file is absent
        // from disk, so it is a tombstone candidate — but the open intent must
        // veto that.
        let records = proc.scan_existing_files("group-1", &root).unwrap();

        assert!(
            !records.iter().any(|r| r.path == "doc.txt" && r.deleted),
            "a missing file with an open materialization intent must not be tombstoned"
        );
        let indexed =
            state.file_index_repository().get_file("group-1", "doc.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "the index row must be left intact for repair to reconstruct");
    }

    /// A hazard-held path -- `hold_record`'s established shape: `Placeholder`,
    /// `held_reason` set, nothing written under this exact name, no
    /// materialization intent ever opened, and (simulating the settled state
    /// `HazardHeld` completion leaves behind) no projection obligation either
    /// -- must never be tombstoned by a Full rescan just because it is absent
    /// from disk under that name. It is this device's own deliberate,
    /// per-device refusal to materialize a name that collides with something
    /// else, not a deletion, and the file stays valid and present on every
    /// other peer. Before the `is_held` check, this scenario had NEITHER of
    /// the two existing veto signals (no intent, no obligation) and would
    /// have been silently tombstoned.
    #[test]
    fn a_hazard_held_path_is_not_tombstoned_by_a_full_rescan() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "CON.txt".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state("group-1", "CON.txt", MaterializationState::Placeholder, &permit)
            .unwrap();
        state
            .materialization_state_repository()
            .set_held("group-1", "CON.txt", "invalid_name", 0)
            .unwrap();
        // Deliberately no intent and no seeded projection obligation --
        // exactly the state a settled `HazardHeld` completion (which deletes
        // the obligation row) leaves a held path in.

        let records = proc.scan_existing_files("group-1", &root).unwrap();

        assert!(
            !records.iter().any(|r| r.path == "CON.txt" && r.deleted),
            "a hazard-held path must never be tombstoned by a full rescan: {records:?}"
        );
        let indexed =
            state.file_index_repository().get_file("group-1", "CON.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "the held row's index must be left intact");
    }

    /// The inverse of the test above, in the missed-delete direction: a
    /// row that is genuinely, currently `Hydrated` (a later, successful
    /// materialize really did write real content and stamp it) but still
    /// carries a STALE `held_reason` -- `clear_held`/`set_materialization_
    /// state` are separate calls, not one atomic operation, so a crash (or
    /// simply an as-yet-unrun hazard recheck) between them can leave this
    /// exact combination -- must still be tombstoned like any other
    /// genuine offline deletion. `is_held` alone would suppress this
    /// forever; the row's own current, real `materialization_state` is
    /// what actually decides whether it needs this scan's protection.
    #[test]
    fn a_stale_held_reason_on_a_genuinely_hydrated_row_does_not_suppress_a_real_delete() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        index_hydrated_missing_file(&state, "group-1", "stale-hold.txt");
        state
            .materialization_state_repository()
            .set_held("group-1", "stale-hold.txt", "invalid_name", 0)
            .unwrap();
        // No intent, no obligation -- same as the genuine-offline-deletion
        // sibling test below; the only difference from the "must NOT
        // tombstone" test above is that this row is `Hydrated`, not
        // `Placeholder` (via `index_hydrated_missing_file`), with a stale
        // `held_reason` left over from some earlier, now-irrelevant hold.

        let records = proc.scan_existing_files("group-1", &root).unwrap();

        assert!(
            records.iter().any(|r| r.path == "stale-hold.txt" && r.deleted),
            "a genuinely Hydrated row's real deletion must not be suppressed forever by a \
             stale held_reason left over from an earlier, now-irrelevant hold: {records:?}"
        );
        let indexed =
            state.file_index_repository().get_file("group-1", "stale-hold.txt").unwrap().unwrap();
        assert!(indexed.deleted, "the genuine offline deletion must be recorded as a tombstone");
    }

    /// The behavior that MUST be preserved alongside the fix: a file that was
    /// cleanly materialized (no lingering intent) and then deleted or renamed
    /// away while the daemon was stopped is a genuine offline deletion. The
    /// startup Full scan must still tombstone it so the deletion propagates.
    #[test]
    fn offline_deleted_hydrated_file_with_no_intent_is_still_tombstoned() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        // The root is verified and really is this link's folder, so a missing
        // file here is a genuine deletion, not an unmounted volume.
        adopt_root(&state, "group-1", &root);
        index_hydrated_missing_file(&state, "group-1", "gone.txt");
        // No materialization intent: the write had completed and its intent was
        // cleared, so the missing file is a real deletion.

        let records = proc.scan_existing_files("group-1", &root).unwrap();

        assert!(
            records.iter().any(|r| r.path == "gone.txt" && r.deleted),
            "a missing file with no materialization intent must still be tombstoned"
        );
        let indexed =
            state.file_index_repository().get_file("group-1", "gone.txt").unwrap().unwrap();
        assert!(indexed.deleted, "the genuine offline deletion must be recorded as a tombstone");
    }

    /// The defense-in-depth gate: when the startup interrupted-materialization
    /// repair pass ERRORED for the group this boot, its crash-vs-offline-delete
    /// disambiguation is unavailable, so the Full scan must emit NO deletes this
    /// boot — even for a missing file with no intent (which, on a healthy boot,
    /// would be a genuine deletion). The delete is deferred to a later boot on
    /// which repair succeeds. Fail-closed.
    #[test]
    fn repair_errored_boot_suppresses_all_scan_tombstones() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        index_hydrated_missing_file(&state, "group-1", "deferred.txt");
        // Deliberately NO intent: on a healthy boot this would tombstone. The
        // repair-errored gate must still withhold it.
        let ignore_set = EffectiveIgnoreSet::from_user_patterns("");

        let records = proc
            .scan_existing_files_with_ignore_gated("group-1", &root, &ignore_set, false)
            .unwrap();

        assert!(
            !records.iter().any(|r| r.deleted),
            "no delete may be emitted on a boot whose repair errored for the group"
        );
        let indexed =
            state.file_index_repository().get_file("group-1", "deferred.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "the delete decision must be deferred, not recorded this boot");

        // And the same missing file DOES tombstone once repair is healthy
        // (tombstones enabled) — proving the gate, not the file, was the reason
        // it was spared above.
        let healthy = proc
            .scan_existing_files_with_ignore_gated("group-1", &root, &ignore_set, true)
            .unwrap();
        assert!(
            healthy.iter().any(|r| r.path == "deferred.txt" && r.deleted),
            "the deferred deletion must propagate on a later healthy boot"
        );
    }

    /// `scan_existing_files` must
    /// not skip a genuine placeholder (OnDemand sync) during a bulk scan —
    /// the bulk-loaded materialization-state map must still
    /// correctly prevent chunking a placeholder's sparse bytes, exactly as
    /// the old per-file `get_materialization_state` lookup did. Unix-only,
    /// same reason as `placeholder_write_is_not_treated_as_a_local_edit`.
    #[test]
    #[cfg(unix)]
    fn scan_existing_files_still_skips_placeholders_when_bulk_loading_materialization_state() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "placeholder.bin".into(),
                    size: 2_000_000,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: vec![0xCD; 32],
                        offset: 0,
                        size: 2_000_000,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let identity = yadorilink_local_storage::write_placeholder(
            &root.join("placeholder.bin"),
            2_000_000,
            0,
        )
        .unwrap()
        .expect("this test runs on unix, where an identity is always captured");
        state
            .materialization_state_repository()
            .record_placeholder_generation(
                "group-1",
                "placeholder.bin",
                identity,
                yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        std::fs::write(root.join("ordinary.txt"), b"a real file").unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["ordinary.txt"],
            "the placeholder must not be re-indexed by the scan"
        );

        assert_eq!(
            state.sqlite().dag_list_versions("group-1", "placeholder.bin").unwrap().len(),
            1,
            "no spurious local version bump from the scan"
        );
    }

    /// A scan's store cost must be exactly known: one `put` per new file's
    /// single block on the first pass, and — the part that carries the
    /// weight — **zero** puts on a rescan that finds nothing changed.
    ///
    /// This is asserted by counting rather than by timing, because a
    /// wall-clock bound cannot express the property. Every `put` costs two
    /// fsyncs (the block's own `sync_all`, plus the directory `sync_all` that
    /// publishes it), so a scan's elapsed time is set by the filesystem behind
    /// `TMPDIR`, not by the scan's algorithm: the same code on the same commit
    /// runs in well under a second on tmpfs, where fsync is free, and in tens
    /// of seconds to minutes on ext4, overlayfs, or APFS, where it is not. No
    /// single bound both fails on a real regression and passes on ordinary
    /// hardware, so a timed version of this test measures the disk instead of
    /// the code — and a scan that got 50x algorithmically slower would still
    /// sit far inside any bound loose enough to be green on a real disk.
    ///
    /// Counting also catches what a timing bound provably cannot. The rescan's
    /// no-op is *not* established by the returned records being empty: a
    /// rescan that re-chunked every file would still return nothing, because
    /// re-chunking unchanged bytes reproduces the identical block hashes and
    /// the resulting record is then suppressed as a self-echo — after paying a
    /// full re-chunk and two fsyncs per file. Only the put count tells those
    /// two apart, which is the reason `CountingBlockStore` exists (see its
    /// doc).
    ///
    /// `FILE_COUNT` is deliberately small. Once the assertion is an exact
    /// count instead of a stopwatch, per-file work is visible at any count
    /// above one, so writing thousands of files — and paying thousands of
    /// fsyncs — buys no additional detection.
    #[test]
    fn scan_puts_one_block_per_new_file_and_rescans_without_touching_the_store() {
        let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
        let root = canonical_root(&root_dir);

        // Each file is far below one chunk, so "one put per file" is the
        // entire store cost of indexing the set.
        const FILE_COUNT: usize = 24;
        for i in 0..FILE_COUNT {
            std::fs::write(root.join(format!("object-{i}.bin")), format!("content {i}")).unwrap();
        }

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(records.len(), FILE_COUNT);
        assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), FILE_COUNT);
        assert_eq!(
            store.put_call_count(),
            FILE_COUNT,
            "indexing {FILE_COUNT} single-block files must cost exactly one block put each; \
             a higher count means a file was chunked more than once in a single scan"
        );

        // A rescan with nothing changed must be settled entirely by the
        // size+mtime gate and its content verification, which reads bytes but
        // never writes a block.
        let second_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(second_scan.is_empty(), "an unchanged folder must not be re-indexed on rescan");
        assert_eq!(
            store.put_call_count(),
            FILE_COUNT,
            "a rescan that finds nothing changed must not put a single block; a count that grew \
             here means every unchanged file was re-chunked and re-stored at two fsyncs apiece, \
             which the empty record list asserted above cannot detect"
        );
    }

    /// batch-processing changes (executor half): a `Paths` flush
    /// indexes every listed path and returns the resulting records,
    /// exactly as individual `process_event` calls would.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_flush_paths_indexes_each_path_and_returns_records() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        std::fs::write(root.join("a.txt"), b"aaa").unwrap();
        std::fs::write(root.join("b.txt"), b"bbb").unwrap();

        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
            (root.join("a.txt"), FsChangeKind::CreatedOrModified, 0),
            (root.join("b.txt"), FsChangeKind::CreatedOrModified, 0),
        ]);
        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

        let mut paths: Vec<&str> = outcome.records.iter().map(|r| r.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths, vec!["a.txt", "b.txt"]);
        assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), 2);
    }

    /// Regression test for the write-then-rename TOCTOU race: a debounced
    /// `CreatedOrModified` event for a path can begin processing (this
    /// module's own lstat guard, in `build_record_for_created_or_modified`,
    /// confirms the path exists) and then have that exact path renamed out
    /// from under it before the chunk attempt's own `fs::metadata`/
    /// `File::open` runs -- exactly what an ordinary write-to-a-sibling-
    /// temp-path-then-rename save does (including the benchmark's own
    /// large-file writer, `yadorilink-bench`'s `l1.rs::write_seeded_file_
    /// with_digest`, which writes to a `*.bench-write-tmp` sibling and
    /// renames it onto the real name once fully written), whenever the
    /// debounce accumulator's per-path quiet period happens to elapse for
    /// the temp path's own "modified" events right as the writer finishes
    /// and renames it away.
    ///
    /// `arm_race_after_lstat_hook`/`fire_race_after_lstat_hook` make this
    /// fully deterministic -- no sleep, no real wall-clock race, no
    /// flakiness -- by renaming the temp path away at the exact instant
    /// (right after this function's own lstat guard has just confirmed it
    /// exists) production code has no other synchronization point to hook
    /// into.
    ///
    /// This only needs to race the *first* attempt: `process_event_with_
    /// ignore_at` already re-derives a path's effective kind from a fresh
    /// `symlink_metadata` call on every attempt (see its own doc comment,
    /// "the watcher is a trigger to re-examine a path, not a source of
    /// truth"), so once the path is truly gone a retry recovers cleanly on
    /// its own -- the residual gap this test and fix close is narrower:
    /// the single, unavoidable TOCTOU window *within* one attempt, between
    /// that outer re-check and this function's own later chunk step, where
    /// production code has no re-check at all.
    ///
    /// Before the fix: the resulting `NotFound` surfaces as the identical
    /// `StorageError::Io(_)` shape a genuine block-store fault would, so
    /// `is_retriable_block_store_error` treats it as retriable -- the
    /// first attempt fails, sleeps a full `LOCAL_INDEX_RETRY_BACKOFF`, and
    /// only then recovers via the retry's own fresh re-check above. After
    /// the fix: `is_source_path_vanished_error` re-stats the path, finds
    /// it genuinely gone, and classifies it immediately, resolving as a
    /// clean no-op on the very first attempt with no retry and no backoff
    /// sleep at all -- the differentiating assertion below is exactly that
    /// elapsed-time gap. Its counterpart,
    /// `a_block_store_not_found_while_the_source_file_still_exists_stays_
    /// dirty`, pins the other side of that same re-stat: the identical
    /// error shape with the source file still present must NOT be
    /// classified this way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn source_path_renamed_away_between_lstat_and_chunk_resolves_cleanly() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);

        let tmp_path = root.join("payload.bench-write-tmp");
        let final_path = root.join("payload.bin");
        std::fs::write(&tmp_path, vec![0x7Au8; 4096]).unwrap();

        let tmp_for_hook = tmp_path.clone();
        arm_race_after_lstat_hook(tmp_path.clone(), move || {
            std::fs::rename(&tmp_for_hook, &final_path).unwrap();
            false // one-shot: only the first attempt needs to race
        });

        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            tmp_path,
            FsChangeKind::CreatedOrModified,
            0,
        )]);
        let started = std::time::Instant::now();
        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();
        let elapsed = started.elapsed();

        assert!(
            outcome.records.is_empty(),
            "a source path that vanished mid-attempt must not produce a spurious record"
        );
        assert!(
            state.dirty_path_repository().list_dirty_paths("group-1").unwrap().is_empty(),
            "a source path proven to have vanished (renamed away), not merely faulting, must \
             resolve as a clean no-op"
        );
        assert!(
            state
                .file_index_repository()
                .get_file("group-1", "payload.bench-write-tmp")
                .unwrap()
                .is_none(),
            "the transient temp-file path must never be indexed as a real synced file"
        );
        assert!(
            elapsed < LOCAL_INDEX_RETRY_BACKOFF,
            "a vanished source path must resolve on the very first attempt, with no retry \
             backoff sleep at all -- took {elapsed:?}, which is at or beyond one \
             LOCAL_INDEX_RETRY_BACKOFF ({LOCAL_INDEX_RETRY_BACKOFF:?}), the signature of falling \
             through to the generic retriable-block-store-error path instead of being \
             classified as a vanished source path on the first attempt"
        );
    }

    /// The other half of `is_source_path_vanished_error`'s verdict, and
    /// the one that actually needs a test: a `NotFound` raised by the
    /// BLOCK STORE while the source file is still sitting on disk,
    /// unchanged and unindexed, must never be mistaken for a vanished
    /// source path.
    ///
    /// The two are indistinguishable from the error value alone -- the
    /// chunker reads the source file through the same
    /// `StorageError::Io(#[from] std::io::Error)` blanket the block store
    /// raises its own filesystem faults through, and neither carries a
    /// path. This test drives the block-store side of that ambiguity
    /// through real production code rather than a hand-built error:
    /// headroom enforcement on (as `DaemonState::enable_disk_headroom_
    /// enforcement` turns it on for the real daemon) plus a block-store
    /// root that has been removed out from under the store (a deleted
    /// store directory, or an unmounted volume hosting it). A file at or
    /// above `CDC_SIZE_THRESHOLD` takes `FsBlockStore::commit_batch`,
    /// whose free-space preflight stats that now-missing root BEFORE any
    /// `create_dir_all` could recreate it -- so the block store really
    /// does hand back `Storage(Io(NotFound))` here, with the source file
    /// untouched.
    ///
    /// The assertion that matters is the surviving `local_dirty_paths`
    /// row. Classifying this as a vanished source path resolves it as
    /// `LocalChangeOutcome::None`, which `process_flush` treats as a clean
    /// no-op and CLEARS the journal row -- silently and permanently
    /// dropping an already-detected local edit whose bytes are still on
    /// disk, with nothing left to re-drive it. Keeping it on the
    /// retriable-block-store-error path instead leaves the row journaled
    /// dirty, so the startup rescan re-drives the file once the store is
    /// back.
    ///
    /// Deliberately pays for the full `MAX_LOCAL_INDEX_RETRIES` schedule
    /// (a real block-store fault SHOULD be retried), so this is one of the
    /// slower tests in this module -- it runs in parallel with its
    /// neighbours and the durability property it pins is worth it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_block_store_not_found_while_the_source_file_still_exists_stays_dirty() {
        use yadorilink_local_storage::BlockStore as _;

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(TestReplica::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let proc = LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "device-a".into(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        );
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);

        // At or above `CDC_SIZE_THRESHOLD`, so the chunk attempt takes the
        // bulk-ingest batch path whose headroom preflight stats the store
        // root first.
        let source = root.join("big.bin");
        let size = yadorilink_local_storage::CDC_SIZE_THRESHOLD as usize + 1;
        std::fs::write(&source, vec![0xABu8; size]).unwrap();

        store.set_headroom_enforced(true);
        std::fs::remove_dir_all(store_dir.path()).unwrap();

        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            source.clone(),
            FsChangeKind::CreatedOrModified,
            0,
        )]);
        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

        assert!(
            source.exists(),
            "test precondition: the SOURCE file must still be on disk -- the only thing that \
             went missing is the block store"
        );
        assert!(
            outcome.records.is_empty(),
            "a block-store fault must not produce a record for content it never durably stored"
        );
        assert_eq!(
            state.dirty_path_repository().list_dirty_paths("group-1").unwrap().len(),
            1,
            "a block-store NotFound is a durability fault, not a vanished source path: the \
             file's dirty-journal row must SURVIVE so the startup rescan re-drives it. An empty \
             journal here means the edit was silently and permanently dropped while its bytes \
             were still sitting on disk -- the signature of classifying by error shape alone \
             instead of re-stating the source path"
        );
        assert!(
            state.file_index_repository().get_file("group-1", "big.bin").unwrap().is_none(),
            "nothing may be indexed when the blocks were never durably stored"
        );
    }

    /// Stage-1 dirty-journal batching regression: a single `DebounceFlush::
    /// Paths` batch mixing successful and failing paths must clear ONLY the
    /// paths that actually succeeded from the dirty journal, even though all
    /// three were batch-journaled together up front
    /// (`record_dirty_paths_batch`) and the successes are cleared through
    /// `clear_dirty_paths_conditional_batch` rather than one
    /// `clear_dirty_path` call per path. Reuses the exact mechanism the test
    /// above pins: a small `put`'s single-block commit creates its shard
    /// directory (recreating the removed store root) BEFORE its own
    /// headroom check, so it succeeds; a big file's bulk-ingest batch
    /// checks headroom BEFORE any directory creation, against the
    /// still-missing root, so it fails and must remain journaled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_mixed_outcome_batch_clears_only_the_successfully_processed_paths() {
        use yadorilink_local_storage::BlockStore as _;

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(TestReplica::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let proc = LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "device-a".into(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        );
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);

        let small_a = root.join("a.txt");
        let small_b = root.join("b.txt");
        std::fs::write(&small_a, b"aaa").unwrap();
        std::fs::write(&small_b, b"bbb").unwrap();

        let big = root.join("big.bin");
        let size = yadorilink_local_storage::CDC_SIZE_THRESHOLD as usize + 1;
        std::fs::write(&big, vec![0xABu8; size]).unwrap();

        store.set_headroom_enforced(true);
        std::fs::remove_dir_all(store_dir.path()).unwrap();

        // `big` is processed first, deliberately: a small file's single-
        // block `put` recreates the store root as a side effect of
        // succeeding (see this test's own doc comment), which would mask
        // the fault for anything processed after it in the same batch.
        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
            (big, FsChangeKind::CreatedOrModified, 0),
            (small_a, FsChangeKind::CreatedOrModified, 0),
            (small_b, FsChangeKind::CreatedOrModified, 0),
        ]);
        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

        let mut succeeded: Vec<&str> = outcome.records.iter().map(|r| r.path.as_str()).collect();
        succeeded.sort();
        assert_eq!(
            succeeded,
            vec!["a.txt", "b.txt"],
            "the two small files must still succeed even though the batch also contained a \
             failing path"
        );

        let dirty = state.dirty_path_repository().list_dirty_paths("group-1").unwrap();
        assert_eq!(
            dirty.len(),
            1,
            "only the failing path may remain journaled once the batch's successes are cleared -- \
             a bulk unconditional clear here would have wrongly swept the failure's row too"
        );
        assert_eq!(dirty[0].path, "big.bin");
    }

    /// Stage-2 authoritative-mutation group commit: a batch of N independent
    /// path mutations (each its own file, no relation to the others) must
    /// still author N DISTINCT signed `Change`s, chained in the exact causal
    /// order sequential (one-transaction-per-path) authoring would have
    /// produced — `commit_local_mutations_batch` must never collapse them
    /// into one multi-op `Change` (that shape is `upsert_files_batch_emitting_change`'s,
    /// deliberately not reused here). Also pins the ordinary success path:
    /// every path's dirty-journal row clears once its batch actually commits.
    #[tokio::test]
    async fn batched_authoritative_commit_produces_n_distinct_changes_in_sequential_causal_order() {
        let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(ChangeAuth::PLACEHOLDER)));
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);

        const N: usize = 16;
        let mut paths = Vec::with_capacity(N);
        for i in 0..N {
            let p = root.join(format!("f-{i:02}.txt"));
            std::fs::write(&p, format!("content-{i}")).unwrap();
            paths.push((p, FsChangeKind::CreatedOrModified, 0));
        }
        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(paths);
        let outcome = proc.process_flush(group, &root, flush).await.unwrap();
        assert_eq!(outcome.records.len(), N, "every path in the batch must be committed and reported");
        assert!(
            state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty(),
            "every successfully batch-committed path's dirty-journal row must clear"
        );
        // `commit_local_mutations_batch`'s Upsert arm is the production hot
        // path for exactly this shape of local edit -- an ordinary,
        // non-symlink create/modify flush. Its `stamp_hydrated_after_local_
        // emission_in_tx` call is what earns `Hydrated` here; deleting that
        // call would leave every one of these rows on the schema's own
        // `Placeholder` default despite genuinely matching disk.
        for i in 0..N {
            let path = format!("f-{i:02}.txt");
            assert_eq!(
                state.materialization_state_repository().get_materialization_state(group, &path).unwrap(),
                Some(MaterializationState::Hydrated),
                "a batch-committed local edit must be stamped Hydrated, not left on the \
                 schema's own Placeholder default"
            );
        }

        let heads = state.sqlite().dag_group_heads(group).unwrap();
        assert_eq!(
            heads.len(),
            1,
            "a batch of independent path mutations must chain onto ONE linear head, not fork"
        );

        // Walk the chain backward from the head, collecting N distinct
        // hashes, each with exactly one op and exactly one parent (its
        // predecessor in the chain) — proving the batch's causal order
        // matches what committing each mutation sequentially would have
        // produced.
        let mut hash = heads[0].clone();
        let mut seen = std::collections::HashSet::new();
        for step in 0..N {
            let change = state.sqlite().dag_get_change(&hash).unwrap().expect("change must exist");
            assert_eq!(
                change.ops.len(),
                1,
                "each batched mutation must author its OWN single-op Change, never collapsed \
                 into one multi-op Change"
            );
            assert!(seen.insert(hash.clone()), "every mutation in the batch must produce a distinct Change hash");
            if step == N - 1 {
                // The batch's very first mutation authors onto whatever
                // the group's history already was -- empty here (a fresh
                // group), so this last hop legitimately has zero parents;
                // every other hop must chain onto exactly its predecessor.
                assert!(change.parents.len() <= 1);
                break;
            }
            assert_eq!(
                change.parents.len(),
                1,
                "each non-final Change in the chain must have exactly one parent, forming a \
                 linear chain"
            );
            hash = change.parents[0].clone();
        }
        assert_eq!(seen.len(), N);
    }

    /// If the shared batch commit itself fails (standing in for a crash
    /// between preparing every mutation and the transaction that would
    /// commit them), NOTHING may be committed — every mutation's
    /// dirty-journal row must survive untouched for a normal re-drive, not
    /// a partial subset.
    #[tokio::test]
    async fn batch_commit_failure_leaves_nothing_committed_and_every_dirty_row_survives() {
        use ed25519_dalek::SigningKey;

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(TestReplica::open_in_memory().unwrap());
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(ChangeAuth::PLACEHOLDER)));
        let lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests());
        let emitter = Arc::new(ChangeEmitter::new("device-a", SigningKey::from_bytes(&[9u8; 32])));
        let proc =
            LocalChangeProcessor::new(state.clone(), store, "device-a".into(), lease.clone())
                .with_change_emitter(emitter);
        let root_dir = tempfile::tempdir().unwrap();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);

        let ignore_set = EffectiveIgnoreSet::from_user_patterns("");
        let mut pending = Vec::new();
        for i in 0..3 {
            let name = format!("f-{i}.txt");
            let p = root.join(&name);
            std::fs::write(&p, format!("content-{i}")).unwrap();
            // Mirrors Stage 1's own batch-journal-before-processing step
            // (normally done by `process_flush_with_ignore`, bypassed here
            // since this test calls `process_event_with_ignore_at`
            // directly to control the exact timing against `lease.
            // begin_stopping()` below).
            state
                .dirty_path_repository()
                .record_dirty_path(
                    group,
                    &name,
                    dirty_kind_str(FsChangeKind::CreatedOrModified),
                    0,
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap();
            let outcome = proc
                .process_event_with_ignore_at(
                    group,
                    &root,
                    &FsChangeEvent { path: p, kind: FsChangeKind::CreatedOrModified },
                    &ignore_set,
                    Some(0),
                    Some(&mut pending),
                )
                .await
                .unwrap();
            assert!(matches!(outcome, EventOutcome::Deferred), "test precondition: must defer into the batch");
        }
        assert_eq!(pending.len(), 3);

        // Simulate the link/process stopping between preparation and
        // commit -- `begin_operation` (which `flush_pending_batch` needs
        // for its own permit) now fails for every subsequent caller.
        lease.begin_stopping();

        let resolved = proc.flush_pending_batch(group, &mut pending).await;
        let resolved = resolved.unwrap_or_default();
        assert!(resolved.is_empty(), "no mutation may resolve as committed once admission is revoked");

        for i in 0..3 {
            let path = format!("f-{i}.txt");
            assert!(
                state.file_index_repository().get_file(group, &path).unwrap().is_none(),
                "no row may exist for a mutation whose batch commit never ran"
            );
            assert!(
                state.dirty_path_repository().is_path_dirty(group, &path).unwrap(),
                "every mutation's dirty-journal row must survive a commit that never ran"
            );
        }
    }

    /// A concurrent peer materialization superseding a path's index row
    /// between this path's preparation (Phase A) and its batch's validation
    /// (Phase B) must exclude that mutation from the batch entirely, not
    /// silently commit stale bytes over the peer's own update.
    #[tokio::test]
    async fn a_peer_mutation_between_preparation_and_validation_excludes_the_stale_mutation() {
        let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(ChangeAuth::PLACEHOLDER)));
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);

        let path = root.join("doc.txt");
        std::fs::write(&path, b"local-v1").unwrap();

        // Mirrors Stage 1's own batch-journal-before-processing step
        // (normally done by `process_flush_with_ignore`, bypassed here
        // since this test calls `process_event_with_ignore_at` directly to
        // control the exact timing of the peer write below).
        state
            .dirty_path_repository()
            .record_dirty_path(
                group,
                "doc.txt",
                dirty_kind_str(FsChangeKind::CreatedOrModified),
                0,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let ignore_set = EffectiveIgnoreSet::from_user_patterns("");
        let mut pending = Vec::new();
        let outcome = proc
            .process_event_with_ignore_at(
                group,
                &root,
                &FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified },
                &ignore_set,
                Some(0),
                Some(&mut pending),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, EventOutcome::Deferred));
        assert_eq!(pending.len(), 1);

        // A concurrent peer materialization commits its own row for this
        // path while this device's mutation sat prepared but not yet
        // committed -- nothing was indexed for it before (preparation only
        // reads/chunks, it never writes), so `index_state_at_prepare` is
        // `None`; this peer write alone is enough to make Phase B's
        // revalidation observe a change.
        let peer_record = FileRecord {
            path: "doc.txt".to_string(),
            size: 999,
            mtime_unix_nanos: 123_456_789,
            blocks: vec![],
            deleted: false,
        };
        state
            .file_index_repository()
            .upsert_file_with_origin(
                group,
                &peer_record,
                "device-b",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let resolved = proc.flush_pending_batch(group, &mut pending).await.unwrap();
        assert!(
            resolved.is_empty(),
            "a prepared mutation must not commit once the index row it was based on has changed"
        );

        let current = state.file_index_repository().get_file(group, "doc.txt").unwrap().unwrap();
        assert_eq!(
            current.size, 999,
            "the peer's own write must survive; the stale local mutation must not overwrite it"
        );
        assert!(state.dirty_path_repository().is_path_dirty(group, "doc.txt").unwrap());
    }

    /// Codex review regression (Stage 2): a peer commit whose new version's
    /// `FileRecord` fields (size/mtime/blocks/deleted) happen to be
    /// byte-identical to what preparation observed — but which is a
    /// genuinely different, freshly-authored `Change` — must still exclude
    /// the stale prepared mutation. A `FileRecord`-only comparison cannot
    /// see this at all (every field matches); only comparing the row's
    /// authoring identity too catches it.
    #[tokio::test]
    async fn a_peer_rewrite_with_byte_identical_file_record_fields_still_excludes_the_stale_mutation()
    {
        use ed25519_dalek::SigningKey;

        let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(ChangeAuth::PLACEHOLDER)));
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);

        let path = root.join("doc.txt");
        std::fs::write(&path, b"v1").unwrap();
        let setup_flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            path.clone(),
            FsChangeKind::CreatedOrModified,
            0,
        )]);
        proc.process_flush(group, &root, setup_flush).await.unwrap();
        let record_after_setup = state.file_index_repository().get_file(group, "doc.txt").unwrap().unwrap();

        // Prepare a local modification, deferring it into the batch.
        std::fs::write(&path, b"v2-local").unwrap();
        state
            .dirty_path_repository()
            .record_dirty_path(
                group,
                "doc.txt",
                dirty_kind_str(FsChangeKind::CreatedOrModified),
                1,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let ignore_set = EffectiveIgnoreSet::from_user_patterns("");
        let mut pending = Vec::new();
        let outcome = proc
            .process_event_with_ignore_at(
                group,
                &root,
                &FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified },
                &ignore_set,
                Some(1),
                Some(&mut pending),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, EventOutcome::Deferred));

        // A peer republishes its own genuinely distinct signed Change for
        // this path, but the resulting row's `FileRecord` fields are
        // deliberately set byte-identical to what preparation above
        // observed (`record_after_setup`) -- the `Op` content here is a
        // throwaway placeholder; only the row's resulting authoring
        // identity, not this op's own semantics, is what this test
        // exercises.
        let peer_emitter = ChangeEmitter::new("device-b", SigningKey::from_bytes(&[42u8; 32]));
        state
            .file_index_repository()
            .upsert_file_emitting_change(
                group,
                &record_after_setup,
                "device-b",
                ChangeContent {
                    ops: vec![Op::Delete { path: SyncPath("peer-marker".to_string()) }],
                    versions: &[],
                },
                None,
                None,
                yadorilink_sync_sqlite::file_index::ChangeEmissionContext {
                    emitter: &peer_emitter,
                    permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                    auth: ChangeAuth::PLACEHOLDER,
                },
            )
            .unwrap();

        let resolved = proc.flush_pending_batch(group, &mut pending).await.unwrap();
        assert!(
            resolved.is_empty(),
            "a prepared mutation must not commit once the row's authoring identity has changed, \
             even when its FileRecord fields still coincide with what preparation observed"
        );
        assert!(state.dirty_path_repository().is_path_dirty(group, "doc.txt").unwrap());
    }

    /// A raw external write to the same path (an editor, not this daemon)
    /// between preparation and validation must exclude the stale mutation
    /// even though the INDEX row never changed — only the disk fingerprint
    /// has. Mirrors `peer_session::PeerSyncSession::hydrate_inner`'s own
    /// `disk_race_fingerprint` re-check before its physical write.
    #[tokio::test]
    async fn a_raw_disk_write_between_preparation_and_validation_excludes_the_stale_mutation() {
        let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(ChangeAuth::PLACEHOLDER)));
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);

        let path = root.join("doc.txt");
        std::fs::write(&path, b"local-v1").unwrap();

        // Mirrors Stage 1's own batch-journal-before-processing step
        // (normally done by `process_flush_with_ignore`, bypassed here
        // since this test calls `process_event_with_ignore_at` directly to
        // control the exact timing of the disk rewrite below).
        state
            .dirty_path_repository()
            .record_dirty_path(
                group,
                "doc.txt",
                dirty_kind_str(FsChangeKind::CreatedOrModified),
                0,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let ignore_set = EffectiveIgnoreSet::from_user_patterns("");
        let mut pending = Vec::new();
        let outcome = proc
            .process_event_with_ignore_at(
                group,
                &root,
                &FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified },
                &ignore_set,
                Some(0),
                Some(&mut pending),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, EventOutcome::Deferred));

        // A different size guarantees `disk_race_fingerprint` observes a
        // change regardless of filesystem mtime granularity.
        std::fs::write(&path, b"externally rewritten while this mutation was pending").unwrap();

        let resolved = proc.flush_pending_batch(group, &mut pending).await.unwrap();
        assert!(
            resolved.is_empty(),
            "a prepared mutation must not author stale bytes once the on-disk file has changed \
             since preparation"
        );
        assert!(
            state.file_index_repository().get_file(group, "doc.txt").unwrap().is_none(),
            "nothing may be indexed for content that was never durably authored"
        );
        assert!(
            state
                .sqlite()
                .dag_lookup_materialized_generation(group, "doc.txt")
                .unwrap()
                .is_none(),
            "mandatory race regression A: a path excluded by prepare-vs-commit \
             revalidation must publish no actual-state proof, not a proof for the \
             stale content it almost authored"
        );
        assert!(state.dirty_path_repository().is_path_dirty(group, "doc.txt").unwrap());
    }

    /// Two overlapping-path batches (prepared in opposite path order, so
    /// neither happens to already match `flush_pending_batch`'s own
    /// lexicographic acquisition order) run concurrently must never
    /// deadlock — `flush_pending_batch` sorts its own lock acquisition
    /// regardless of preparation order, so both converge on the same
    /// acquisition order and can only ever wait in line, never cycle.
    #[tokio::test]
    async fn concurrent_overlapping_batches_never_deadlock_regardless_of_preparation_order() {
        let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(ChangeAuth::PLACEHOLDER)));
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);

        let path_a = root.join("a.txt");
        let path_b = root.join("b.txt");
        std::fs::write(&path_a, b"aaa").unwrap();
        std::fs::write(&path_b, b"bbb").unwrap();
        let ignore_set = EffectiveIgnoreSet::from_user_patterns("");

        let mut batch1 = Vec::new();
        for p in [&path_a, &path_b] {
            proc.process_event_with_ignore_at(
                group,
                &root,
                &FsChangeEvent { path: (*p).clone(), kind: FsChangeKind::CreatedOrModified },
                &ignore_set,
                Some(0),
                Some(&mut batch1),
            )
            .await
            .unwrap();
        }
        let mut batch2 = Vec::new();
        for p in [&path_b, &path_a] {
            proc.process_event_with_ignore_at(
                group,
                &root,
                &FsChangeEvent { path: (*p).clone(), kind: FsChangeKind::CreatedOrModified },
                &ignore_set,
                Some(0),
                Some(&mut batch2),
            )
            .await
            .unwrap();
        }

        let (r1, r2) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                proc.flush_pending_batch(group, &mut batch1),
                proc.flush_pending_batch(group, &mut batch2),
            )
        })
        .await
        .expect("two concurrent overlapping batches must not deadlock");
        r1.unwrap();
        r2.unwrap();
    }

    /// More paths in one flush than `AUTHORITATIVE_COMMIT_BATCH_SIZE` must
    /// still all commit correctly, across however many bounded batch
    /// commits that takes — bounding the batch size must never drop or
    /// duplicate a path.
    #[tokio::test]
    async fn more_than_one_authoritative_batch_worth_of_paths_all_commit_correctly() {
        let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(ChangeAuth::PLACEHOLDER)));
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);

        const N: usize = 40; // more than 2x AUTHORITATIVE_COMMIT_BATCH_SIZE
        let mut paths = Vec::with_capacity(N);
        for i in 0..N {
            let p = root.join(format!("f-{i:03}.txt"));
            std::fs::write(&p, format!("content-{i}")).unwrap();
            paths.push((p, FsChangeKind::CreatedOrModified, 0));
        }
        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(paths);
        let outcome = proc.process_flush(group, &root, flush).await.unwrap();
        assert_eq!(
            outcome.records.len(),
            N,
            "batching internally into bounded groups must not drop or duplicate any path"
        );
        assert!(state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty());
        for i in 0..N {
            assert!(state
                .file_index_repository()
                .get_file(group, &format!("f-{i:03}.txt"))
                .unwrap()
                .is_some());
        }
    }

    /// A batch mixing creates/modifies AND deletes must commit both
    /// `PreparedLocalMutation` variants together, in one shared
    /// transaction — `commit_local_mutations_batch`'s `Delete` arm is
    /// otherwise never exercised by this module's other Stage-2 batching
    /// tests, which are create/modify-only.
    #[tokio::test]
    async fn a_batch_mixing_creates_and_deletes_commits_both_variants_together() {
        let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(ChangeAuth::PLACEHOLDER)));
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);

        // Two pre-existing files, indexed via their own ordinary flush
        // first, then one is deleted and the other modified in the SAME
        // later flush, alongside a brand-new third file -- a create, a
        // modify, and a delete, all in one batch.
        let to_delete = root.join("to-delete.txt");
        let to_modify = root.join("to-modify.txt");
        std::fs::write(&to_delete, b"gone-soon").unwrap();
        std::fs::write(&to_modify, b"v1").unwrap();
        let setup_flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
            (to_delete.clone(), FsChangeKind::CreatedOrModified, 0),
            (to_modify.clone(), FsChangeKind::CreatedOrModified, 0),
        ]);
        let setup_outcome = proc.process_flush(group, &root, setup_flush).await.unwrap();
        assert_eq!(setup_outcome.records.len(), 2);

        std::fs::remove_file(&to_delete).unwrap();
        std::fs::write(&to_modify, b"v2-modified").unwrap();
        let to_create = root.join("to-create.txt");
        std::fs::write(&to_create, b"brand-new").unwrap();

        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
            (to_delete, FsChangeKind::Removed, 1),
            (to_modify, FsChangeKind::CreatedOrModified, 1),
            (to_create, FsChangeKind::CreatedOrModified, 1),
        ]);
        let outcome = proc.process_flush(group, &root, flush).await.unwrap();
        assert_eq!(outcome.records.len(), 3, "the create, the modify, and the delete must all commit");
        assert!(state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty());

        assert!(
            state.file_index_repository().get_file(group, "to-delete.txt").unwrap().unwrap().deleted,
            "the batched delete must tombstone the row"
        );
        let modified =
            state.file_index_repository().get_file(group, "to-modify.txt").unwrap().unwrap();
        assert!(!modified.deleted);
        assert_eq!(modified.size, "v2-modified".len() as u64);
        assert!(state.file_index_repository().get_file(group, "to-create.txt").unwrap().is_some());

        // Every mutation authored its own signed Change (3 more on top of
        // the setup flush's 1), still chained onto one linear head.
        let heads = state.sqlite().dag_group_heads(group).unwrap();
        assert_eq!(heads.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_flush_paths_skips_ignored_files_and_ignore_config_file() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let ignore_set = EffectiveIgnoreSet::from_user_patterns("*.tmp\n");
        std::fs::write(root.join("keep.txt"), b"kept").unwrap();
        std::fs::write(root.join("scratch.tmp"), b"ignored").unwrap();
        std::fs::write(root.join(".yadorilinkignore"), b"*.tmp\n").unwrap();

        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
            (root.join("keep.txt"), FsChangeKind::CreatedOrModified, 0),
            (root.join("scratch.tmp"), FsChangeKind::CreatedOrModified, 0),
            (root.join(".yadorilinkignore"), FsChangeKind::CreatedOrModified, 0),
        ]);
        let outcome = proc
            .process_flush_with_ignore("group-1", &root, flush, &ignore_set, true)
            .await
            .unwrap();

        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].path, "keep.txt");
        assert!(state
            .file_index_repository()
            .get_file("group-1", "scratch.tmp")
            .unwrap()
            .is_none());
        assert!(state
            .file_index_repository()
            .get_file("group-1", ".yadorilinkignore")
            .unwrap()
            .is_none());
    }

    /// A `RescanRequired` flush runs a full reconciliation scan instead of
    /// per-path processing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_flush_burst_fallback_runs_full_scan() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        // `RescanRequired` now goes through `verified_root_of_established_
        // link` (`VerifiedRoot::verify`), not the one-time-scan `verified_
        // root` (`VerifiedRoot::open`, which could adopt lazily) -- a real
        // link always adopts its root during the initial scan, before any
        // live flush (including a `RescanRequired` one) can ever reach this
        // path, so this fixture must model that ordering too.
        adopt_root(&state, "group-1", &root);
        std::fs::write(root.join("a.txt"), b"aaa").unwrap();
        std::fs::write(root.join("b.txt"), b"bbb").unwrap();
        std::fs::write(root.join("c.txt"), b"ccc").unwrap();

        let outcome = proc
            .process_flush(
                "group-1",
                &root,
                yadorilink_filesystem_sync::debounce::DebounceFlush::RescanRequired,
            )
            .await
            .unwrap();

        let mut paths: Vec<&str> = outcome.records.iter().map(|r| r.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths, vec!["a.txt", "b.txt", "c.txt"]);
        assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), 3);
    }

    /// `process_flush_with_ignore`'s `RescanRequired` arm must forward its
    /// caller-supplied `emit_tombstones` gate to the scan, not silently
    /// re-harden it to `true`. Every other test exercising the gate goes
    /// through `scan_existing_files_with_ignore_gated[_for_established_link]`
    /// directly; this is the only one that drives it through the actual
    /// public entry point real callers use (see `yadorilink-daemon`'s
    /// executor task), so nothing else would catch a future refactor that
    /// re-hardcodes `emit_tombstones: true` at this arm.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_flush_rescan_required_forwards_a_false_emit_tombstones_gate() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("report.txt");
        std::fs::write(&file_path, b"version one").unwrap();
        proc.process_flush(
            "group-1",
            &root,
            yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
                file_path.clone(),
                FsChangeKind::CreatedOrModified,
                0,
            )]),
        )
        .await
        .unwrap();
        assert!(state.file_index_repository().get_file("group-1", "report.txt").unwrap().is_some());

        // Removed "offline" (no daemon in between); a plain RescanRequired
        // scan with the gate left on would tombstone this immediately.
        std::fs::remove_file(&file_path).unwrap();
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        let outcome = proc
            .process_flush_with_ignore(
                "group-1",
                &root,
                yadorilink_filesystem_sync::debounce::DebounceFlush::RescanRequired,
                &ignore_set,
                false,
            )
            .await
            .unwrap();

        assert!(
            !outcome.records.iter().any(|r| r.path == "report.txt" && r.deleted),
            "a false emit_tombstones gate must suppress the RescanRequired scan's missing-file \
             tombstone -- if this ever fails, the RescanRequired arm has stopped forwarding its \
             caller-supplied gate: {:?}",
            outcome.records
        );
        let indexed =
            state.file_index_repository().get_file("group-1", "report.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "the index row itself must not have been tombstoned either");
    }

    /// self-echo
    /// suppression still applies per-path when processing a `Paths`
    /// flush — a path whose content already matches what's indexed
    /// (as if a peer-applied write's own resulting event landed in this
    /// debounce window) produces no record, exactly as an immediate
    /// single-event `process_event` call would.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_flush_paths_applies_self_echo_suppression_per_path() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("synced.bin");
        std::fs::write(&file_path, b"peer-applied content").unwrap();

        // Index it first (simulating `peer_session::materialize` having
        // already written this exact content before its own triggered
        // watcher event ever reaches the debounce flush).
        let first_flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            file_path.clone(),
            FsChangeKind::CreatedOrModified,
            0,
        )]);
        let first = proc.process_flush("group-1", &root, first_flush).await.unwrap();
        assert_eq!(first.records.len(), 1);

        // A second flush for the same, unchanged path — as if the
        // materialize-triggered watcher event arrived in its own later
        // window — must be suppressed, not re-indexed or re-broadcast.
        let second_flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            file_path,
            FsChangeKind::CreatedOrModified,
            0,
        )]);
        let second = proc.process_flush("group-1", &root, second_flush).await.unwrap();
        assert!(second.records.is_empty(), "unchanged content must not be re-indexed");
    }

    /// the
    /// placeholder/hydrating skip still applies when processing a `Paths`
    /// flush, exactly as `process_event` does directly — a placeholder's
    /// own on-disk representation is never chunked as if it were real
    /// content, even when reached via the debounce/flush path.
    #[tokio::test]
    async fn process_flush_paths_skips_placeholders_exactly_like_process_event() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("placeholder.bin");

        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "placeholder.bin".into(),
                    size: 4_000_000,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: vec![0xEE; 32],
                        offset: 0,
                        size: 4_000_000,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        yadorilink_local_storage::write_placeholder(&file_path, 4_000_000, 0).unwrap();

        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            file_path,
            FsChangeKind::CreatedOrModified,
            0,
        )]);
        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

        assert!(outcome.records.is_empty(), "a placeholder's own write must not be indexed");
        assert_eq!(
            state.sqlite().dag_list_versions("group-1", "placeholder.bin").unwrap().len(),
            1,
            "no spurious local version bump"
        );
    }

    /// an overflow signal (as a real
    /// watcher would set on a dropped event, simulated here by setting
    /// the flag directly — see `watcher::watch_folder_with_capacity`'s
    /// own tests for proof the flag is set correctly under a genuine
    /// full channel) reaches the debouncer and, once flushed through
    /// `process_flush`'s `RescanRequired` handling, produces a fully
    /// correct index — including files whose individual creation events
    /// were never tracked at all, because the whole point of this
    /// recovery path is not needing them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watcher_overflow_recovers_to_a_fully_correct_index_via_full_rescan() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        // See `process_flush_burst_fallback_runs_full_scan`'s identical
        // comment: `RescanRequired` now re-verifies an already-adopted
        // root rather than adopting lazily.
        adopt_root(&state, "group-1", &root);
        let proc = Arc::new(proc);

        // These files exist on disk, but no event for any of them is
        // ever sent into the debouncer — standing in for what a real
        // overflow drops.
        const FILE_COUNT: usize = 25;
        for i in 0..FILE_COUNT {
            std::fs::write(root.join(format!("dropped-{i}.bin")), format!("content {i}")).unwrap();
        }

        let (_events_tx, events_rx) = tokio::sync::mpsc::channel(16);
        let (flush_tx, mut flush_rx) = tokio::sync::mpsc::channel(4);
        let overflowed = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let config = yadorilink_filesystem_sync::debounce::DebounceConfig {
            quiet_period: std::time::Duration::from_millis(20),
            max_flush_interval: std::time::Duration::from_millis(100),
            burst_threshold: 1000,
        };
        let (_flush_requests_tx, flush_requests_rx) = tokio::sync::mpsc::channel(1);
        let (_flush_all_requests_tx, flush_all_requests_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(yadorilink_filesystem_sync::debounce::run_debouncer(
            config,
            events_rx,
            flush_tx,
            overflowed,
            flush_requests_rx,
            flush_all_requests_rx,
        ));

        let flush = tokio::time::timeout(std::time::Duration::from_secs(2), flush_rx.recv())
            .await
            .expect("overflow never produced a flush")
            .unwrap();
        assert_eq!(flush, yadorilink_filesystem_sync::debounce::DebounceFlush::RescanRequired);

        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();
        assert_eq!(outcome.records.len(), FILE_COUNT, "the full rescan must discover every file");
        assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), FILE_COUNT);
        for i in [0, FILE_COUNT / 2, FILE_COUNT - 1] {
            let record = state
                .file_index_repository()
                .get_file("group-1", &format!("dropped-{i}.bin"))
                .unwrap();
            assert!(record.is_some(), "file dropped-{i}.bin is missing from the recovered index");
        }
    }

    /// a
    /// rename whose watcher event is missed entirely (the scenario a
    /// dropped/overflowed event stream produces, or simply a device that
    /// was offline while the rename happened) must be fully recovered by
    /// the next full rescan — the old path tombstoned, the new path
    /// indexed as live, and the old path never resurrected by a later
    /// scan (idempotency: nothing about a stable, already-tombstoned
    /// path should look "new" to a subsequent rescan).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_existing_files_recovers_a_dropped_rename_without_resurrecting_the_old_path() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

        let old_path = root.join("original.txt");
        std::fs::write(&old_path, b"content").unwrap();
        let scanned = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(scanned.len(), 1);
        assert!(
            !state
                .file_index_repository()
                .get_file("group-1", "original.txt")
                .unwrap()
                .unwrap()
                .deleted
        );

        // Simulate a rename whose watcher event never arrived (dropped by
        // an overflow, or the device was offline) — from the index's
        // point of view, `original.txt` just vanished and `renamed.txt`
        // appeared, with no event ever processed for either.
        std::fs::rename(&old_path, root.join("renamed.txt")).unwrap();

        let recovered = proc.scan_existing_files("group-1", &root).unwrap();
        let old_record = recovered.iter().find(|r| r.path == "original.txt");
        let new_record = recovered.iter().find(|r| r.path == "renamed.txt");
        assert!(
            old_record.is_some_and(|r| r.deleted),
            "old path must be tombstoned: {recovered:?}"
        );
        assert!(
            new_record.is_some_and(|r| !r.deleted),
            "new path must be indexed as live: {recovered:?}"
        );
        assert!(
            state
                .file_index_repository()
                .get_file("group-1", "original.txt")
                .unwrap()
                .unwrap()
                .deleted,
            "tombstone must actually be persisted to the index, not just returned"
        );

        // A further rescan (nothing changed on disk since) must not
        // resurrect the now-stable tombstone — the old path shouldn't
        // even appear in the returned records again, since nothing about
        // it changed.
        let second_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(
            second_scan.iter().all(|r| r.path != "original.txt"),
            "a stable tombstone must not be re-emitted/re-bumped by a later rescan: {second_scan:?}"
        );
        assert!(
            state
                .file_index_repository()
                .get_file("group-1", "original.txt")
                .unwrap()
                .unwrap()
                .deleted
        );
    }

    /// The add-only reconcile
    /// (`reconcile_added_files`) indexes only a disk file with no existing
    /// index row — an already-indexed file whose on-disk content changed,
    /// and an indexed file missing from disk, are both left byte-identical
    /// (no re-version, no tombstone). This is the property that makes it
    /// safe to run unconditionally on a frequent periodic schedule, unlike
    /// `scan_existing_files` (which does re-version/tombstone those two
    /// cases, and is documented — `watcher.rs`'s module doc — as unsafe to
    /// run that often against a possibly-mid-conflict-resolution index).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_added_files_only_indexes_disk_files_with_no_existing_row() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);

        // (a) current: already indexed, on-disk content unchanged.
        std::fs::write(root.join("current.txt"), b"unchanged").unwrap();
        // (b) size-changed-on-disk: indexed once, then its disk content
        // changes size *after* indexing, without going through `scan_
        // existing_files` again (mirroring a watcher-missed edit).
        std::fs::write(root.join("changed.txt"), b"original").unwrap();
        // (c) indexed-but-disk-missing: indexed once, then deleted from
        // disk directly (mirroring a watcher-missed delete).
        std::fs::write(root.join("missing.txt"), b"will be deleted").unwrap();

        let initial = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(initial.len(), 3);
        let versions_of =
            |path: &str| state.sqlite().dag_list_versions("group-1", path).unwrap().len();
        let current_versions_before = versions_of("current.txt");
        let changed_versions_before = versions_of("changed.txt");
        let missing_versions_before = versions_of("missing.txt");

        // Now make (b) and (c) diverge from the index without dispatching
        // any event for them, and add (d): a brand-new file the index has
        // never seen.
        std::fs::write(root.join("changed.txt"), b"a longer, different body").unwrap();
        std::fs::remove_file(root.join("missing.txt")).unwrap();
        std::fs::write(root.join("new.txt"), b"never indexed before").unwrap();

        let added = proc.reconcile_added_files("group-1", &root).unwrap();
        assert_eq!(
            added.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            vec!["new.txt"],
            "the add-only reconcile must emit a record only for the genuinely new file: {added:?}"
        );
        assert!(!added[0].deleted);

        // (a)/(b)/(c) must be byte-identical in the index to their
        // pre-reconcile state -- no re-version, no tombstone.
        let current_after =
            state.file_index_repository().get_file("group-1", "current.txt").unwrap().unwrap();
        assert_eq!(versions_of("current.txt"), current_versions_before);
        assert!(!current_after.deleted);

        let changed_after =
            state.file_index_repository().get_file("group-1", "changed.txt").unwrap().unwrap();
        assert_eq!(
            versions_of("changed.txt"),
            changed_versions_before,
            "a size-changed-on-disk file must not be re-versioned by the add-only reconcile"
        );
        assert!(!changed_after.deleted);

        let missing_after =
            state.file_index_repository().get_file("group-1", "missing.txt").unwrap().unwrap();
        assert_eq!(
            versions_of("missing.txt"),
            missing_versions_before,
            "a disk-missing indexed file must not be tombstoned by the add-only reconcile"
        );
        assert!(
            !missing_after.deleted,
            "the add-only reconcile must never tombstone an existing row"
        );

        // The new file is actually persisted to the index, not just
        // returned -- and a second add-only pass is idempotent (nothing
        // new to add, and still no mutation of the other three rows).
        assert!(state.file_index_repository().get_file("group-1", "new.txt").unwrap().is_some());
        let second = proc.reconcile_added_files("group-1", &root).unwrap();
        assert!(
            second.is_empty(),
            "a second add-only pass with nothing new must emit nothing: {second:?}"
        );
    }

    /// once the accumulator's internal
    /// delivery queue is forced past capacity by a backlog
    /// (see `debounce`'s own `executor_backlog_trigger_...` test for the
    /// queue-merge mechanism in isolation), every file still ends up
    /// correctly indexed end to end -- via the merged `Paths` batch the
    /// queue collapses into now (no watcher overflow occurs in this
    /// scenario, so no information was ever lost; see `push_ready`'s own
    /// doc comment for why this no longer falls back to a full rescan).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn executor_backlog_recovers_to_a_fully_correct_index() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        // Unlike the full-rescan-fallback scenarios (which never call
        // `adopt_root`), this test now genuinely exercises PER-PATH
        // capture (see `push_ready`'s own doc comment on why a mere
        // backlog no longer falls back to a full rescan), and per-path
        // capture needs the group's policy actually adopted to author
        // anything at all.
        adopt_root(&state, "group-1", &root);
        let proc = Arc::new(proc);

        const FILE_COUNT: usize = 30;
        for i in 0..FILE_COUNT {
            std::fs::write(root.join(format!("obj-{i}.bin")), format!("content {i}")).unwrap();
        }

        let (events_tx, events_rx) = tokio::sync::mpsc::channel(256);
        // Never drained: forces the internal ready_queue to merge into a
        // single Paths batch once it exceeds DEFAULT_EXECUTOR_CHANNEL_CAPACITY
        // (no watcher overflow here, so the merge stays Paths, not RescanRequired).
        let (flush_tx, mut flush_rx) = tokio::sync::mpsc::channel(1);
        let config = yadorilink_filesystem_sync::debounce::DebounceConfig {
            quiet_period: std::time::Duration::from_millis(15),
            max_flush_interval: std::time::Duration::from_millis(60),
            burst_threshold: 1000,
        };
        let (_flush_requests_tx, flush_requests_rx) = tokio::sync::mpsc::channel(1);
        let (_flush_all_requests_tx, flush_all_requests_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(yadorilink_filesystem_sync::debounce::run_debouncer(
            config,
            events_rx,
            flush_tx,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            flush_requests_rx,
            flush_all_requests_rx,
        ));

        // Many separate, well-spaced single-path windows — each one is a
        // *real* file (so a non-fallback flush would also reconstruct
        // correctly), but there are enough of them, undrained, that the
        // delivery queue must eventually merge. Every one of the
        // `FILE_COUNT` files gets its own event -- unlike the old
        // full-rescan-fallback version of this test, nothing here is
        // "unknown"; the whole point of the merge (see `push_ready`'s own
        // doc comment) is that a backlog of fully-known changes must
        // still deliver every one of them, not silently rely on a
        // directory walk to discover files this accumulator was never
        // even told about. The gap between sends needs real headroom
        // above quiet_period (15ms): on a slower/more contended CI
        // runner (observed on windows-latest at the old 25ms gap), a
        // slow-to-be-polled debouncer task can let several sends queue up
        // and then process them back-to-back, merging windows that were
        // meant to stay separate and never reaching the merge this test
        // means to exercise (same root cause as, and fixed the same way
        // as, debounce.rs's sibling test).
        for i in 0..FILE_COUNT {
            events_tx
                .send(FsChangeEvent {
                    path: root.join(format!("obj-{i}.bin")),
                    kind: FsChangeKind::CreatedOrModified,
                })
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }

        // Now drain everything and process each flush through the same
        // executor logic the daemon's flush-processing task (`link_runtime::tasks`)
        // uses. The gap between flushes is
        // bounded by max_flush_interval (60ms) under normal scheduling,
        // but this per-recv timeout needs real headroom above that on a
        // slow/contended CI runner (observed needing more than 500ms on
        // this suite's first real Windows run) -- it only ends the loop
        // once flushes genuinely stop arriving, so a generous bound here
        // doesn't weaken what the test verifies, just how patiently it
        // waits for a real signal.
        let mut total_records = Vec::new();
        while let Ok(Some(flush)) =
            tokio::time::timeout(std::time::Duration::from_secs(3), flush_rx.recv()).await
        {
            let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();
            total_records.extend(outcome.records);
        }

        // Whether via individually-tracked paths or a merged backlog
        // batch, every file must end up correctly indexed — no permanent
        // gaps from the merge.
        assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), FILE_COUNT);
        for i in [0, FILE_COUNT / 2, FILE_COUNT - 1] {
            assert!(
                state
                    .file_index_repository()
                    .get_file("group-1", &format!("obj-{i}.bin"))
                    .unwrap()
                    .is_some(),
                "file obj-{i}.bin is missing from the recovered index"
            );
        }
    }

    /// a file below the size threshold is chunked with the fixed-size
    /// chunker — the automatic size-based decision picks fixed for small
    /// files with no per-folder configuration involved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn small_file_uses_fixed_size_chunking() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let file_path = root.join("hello.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        let expected = yadorilink_local_storage::chunk_file(
            &FsBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap(),
            &file_path,
        )
        .unwrap();
        assert_eq!(record.blocks.len(), expected.len());
        assert_eq!(record.blocks[0].size, expected[0].size, "must match chunk_file's fixed sizing");
    }

    /// a file at or above the size threshold is
    /// automatically chunked with CDC — verified by comparing against
    /// `chunk_file_content_defined`'s direct output (deterministic for the
    /// same content/parameters), and confirming it differs from what
    /// fixed-size chunking would have produced for the same content.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn large_file_uses_content_defined_chunking() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);

        // Deterministic pseudo-random content, at the size threshold —
        // real CDC boundary-finding depends on actual byte entropy.
        use rand::{RngExt, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let content: Vec<u8> = (0..yadorilink_local_storage::CDC_SIZE_THRESHOLD as usize)
            .map(|_| rng.random())
            .collect();
        let file_path = root.join("big.bin");
        std::fs::write(&file_path, &content).unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        let throwaway_store = FsBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap();
        let expected_cdc =
            yadorilink_local_storage::chunk_file_content_defined(&throwaway_store, &file_path)
                .unwrap();
        let expected_fixed =
            yadorilink_local_storage::chunk_file(&throwaway_store, &file_path).unwrap();

        assert_eq!(record.blocks, expected_cdc, "must match chunk_file_content_defined's output");
        assert_ne!(
            record.blocks, expected_fixed,
            "CDC output must differ from what fixed-size chunking would have produced"
        );
    }

    /// M6-2B2 crash-safety property 4: `flush_durable`'s `staged ->
    /// durable` boundary structurally gates the `durable -> authoritative`
    /// half too -- a source capture must not publish a `FileRecord` for
    /// blocks that are not yet durable. Deterministic via `FsBlockStore::
    /// install_bulk_ingest_barrier_hook_for_tests`, which fires exactly
    /// once `commit_batch` has finished all of a batch's durability work
    /// but before it returns to its caller (`chunk_file_content_defined`,
    /// still inside `build_record_for_created_or_modified`'s own
    /// `block_in_place`) -- pausing there and observing no indexed
    /// `FileRecord` yet, then releasing and observing one appear only
    /// afterward, is a real ordering proof, not a timing-sensitive guess.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flush_durable_gates_authoritative_publication_deterministically() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(TestReplica::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let proc = LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "device-a".into(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        );
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);

        use rand::{RngExt, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(21);
        let content: Vec<u8> = (0..yadorilink_local_storage::CDC_SIZE_THRESHOLD as usize)
            .map(|_| rng.random())
            .collect();
        let file_path = root.join("gated.bin");
        std::fs::write(&file_path, &content).unwrap();

        let reached_barrier = Arc::new(Latch::new());
        let release_barrier = Arc::new(Latch::new());
        {
            let reached_barrier = reached_barrier.clone();
            let release_barrier = release_barrier.clone();
            store.install_bulk_ingest_barrier_hook_for_tests(move || {
                reached_barrier.raise();
                release_barrier.wait();
            });
        }

        let capture_task = tokio::spawn(async move {
            expect_file_changed(
                proc.process_event(
                    "group-1",
                    &root,
                    &FsChangeEvent {
                        path: file_path.clone(),
                        kind: FsChangeKind::CreatedOrModified,
                    },
                )
                .await
                .unwrap(),
            )
        });

        assert!(
            reached_barrier.wait_timeout(std::time::Duration::from_secs(20)),
            "capture never reached the bulk-ingest barrier within 20s"
        );

        // The batch's blocks are already durable on disk at this exact
        // point (that's when the hook fires) -- but nothing has published
        // a FileRecord referencing them yet, because `commit_batch` has
        // not returned to `build_record_for_created_or_modified`, which
        // has not returned to `process_event`, which is what actually
        // calls `upsert_file`. If this assertion ever fails, it means
        // some future change let authoritative publication race ahead of
        // (rather than strictly follow) the durability barrier.
        assert!(
            state.file_index_repository().get_file("group-1", "gated.bin").unwrap().is_none(),
            "no FileRecord may exist while flush_durable is still blocked mid-batch"
        );

        release_barrier.raise();
        let record = capture_task.await.unwrap();

        let published =
            state.file_index_repository().get_file("group-1", "gated.bin").unwrap().unwrap();
        assert_eq!(
            published.blocks, record.blocks,
            "the FileRecord becomes visible only after flush_durable released, and matches what \
             process_event returned"
        );
    }

    // --- Symlink pruning and cycle safety ---

    /// a symlink inside the folder is recorded as a symlink
    /// record — correct raw target text, no content blocks, and
    /// `record_kind = Symlink` in the index (not folded into `FileRecord`
    /// — see `types::RecordKind`'s doc comment).
    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_inside_folder_is_recorded_as_a_symlink_with_no_blocks() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        std::fs::write(root.join("real.txt"), b"target content").unwrap();
        let link_path = root.join("link.txt");
        std::os::unix::fs::symlink("real.txt", &link_path).unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert_eq!(record.path, "link.txt");
        assert!(record.blocks.is_empty(), "a symlink record must carry no content blocks");
        assert_eq!(
            state.file_index_repository().get_record_kind("group-1", "link.txt").unwrap(),
            Some(yadorilink_replica_domain::file::RecordKind::Symlink)
        );
        assert_eq!(
            state.file_index_repository().get_symlink_target("group-1", "link.txt").unwrap(),
            Some(b"real.txt".to_vec())
        );
        assert!(!state
            .file_index_repository()
            .get_symlink_out_of_root("group-1", "link.txt")
            .unwrap());
        // The target file itself must still be indexed normally and
        // separately — the symlink never dereferences into it.
        let target_record = state.file_index_repository().get_file("group-1", "real.txt").unwrap();
        assert!(target_record.is_none(), "target wasn't scanned in this single-event test");
    }

    /// A symlink target containing a byte that is not valid UTF-8 (real and
    /// legal on Unix — a symlink target has no UTF-8 requirement) is
    /// captured byte-exactly, not lossily. Not constructible portably on
    /// Windows (its paths are UTF-16, so there is no equivalent way to hand
    /// `std::os::unix::fs::symlink` an arbitrary invalid byte sequence);
    /// `change::non_utf8_symlink_target_round_trips_byte_exactly` and
    /// `fs_identity`'s own Windows-side tests cover the encoding and the
    /// unpaired-surrogate case respectively, so this Unix-only test is not
    /// this crate's only coverage of the byte-exactness property, just the
    /// one exercised through a real on-disk symlink and the local capture
    /// path.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_with_non_utf8_target_is_captured_byte_exactly() {
        use std::os::unix::ffi::OsStrExt;

        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let raw_target = std::ffi::OsStr::from_bytes(b"/tmp/\xffbroken-utf8/target");
        assert!(
            raw_target.to_str().is_none(),
            "fixture must actually be invalid UTF-8 (Path::to_string_lossy would replace it)"
        );
        let link_path = root.join("link.txt");
        std::os::unix::fs::symlink(raw_target, &link_path).unwrap();

        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert_eq!(
            state.file_index_repository().get_symlink_target("group-1", "link.txt").unwrap(),
            Some(raw_target.as_bytes().to_vec()),
            "the captured target must be the exact on-disk bytes, not a lossy UTF-8 conversion"
        );
    }

    /// `scan_existing_files` classifies a pre-existing
    /// symlink the same way a live watcher event does.
    #[cfg(unix)]
    #[test]
    fn scan_existing_files_records_a_symlink_with_correct_target_text() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("real.txt"), b"target content").unwrap();
        std::os::unix::fs::symlink("real.txt", root.join("link.txt")).unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let link_record = records.iter().find(|r| r.path == "link.txt").unwrap();
        assert!(link_record.blocks.is_empty());
        assert_eq!(
            state.file_index_repository().get_record_kind("group-1", "link.txt").unwrap(),
            Some(yadorilink_replica_domain::file::RecordKind::Symlink)
        );
        assert_eq!(
            state.file_index_repository().get_symlink_target("group-1", "link.txt").unwrap(),
            Some(b"real.txt".to_vec())
        );

        // The regular file target is indexed too, as its own unrelated
        // record — proves the symlink and its target are two independent
        // entries, not one dereferenced into the other.
        let target_record = records.iter().find(|r| r.path == "real.txt").unwrap();
        assert!(!target_record.blocks.is_empty());
    }

    /// a symlinked directory's contents never appear as
    /// separate scanned records — only the symlink itself is enumerated,
    /// as a single leaf entry, never descended into as a subtree.
    #[cfg(unix)]
    #[test]
    fn symlinked_directory_contents_never_appear_as_separate_scanned_records() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::create_dir_all(root.join("real_dir")).unwrap();
        std::fs::write(root.join("real_dir/secret.txt"), b"must not leak").unwrap();
        std::os::unix::fs::symlink("real_dir", root.join("link_dir")).unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();

        assert!(paths.contains(&"link_dir"), "the symlink itself must be recorded: {paths:?}");
        assert!(
            !paths.iter().any(|p| p.starts_with("link_dir/")),
            "nothing inside the symlinked directory may be enumerated via the link: {paths:?}"
        );
        assert_eq!(
            state.file_index_repository().get_record_kind("group-1", "link_dir").unwrap(),
            Some(yadorilink_replica_domain::file::RecordKind::Symlink)
        );
        // The real directory's own (non-symlinked) path is scanned
        // normally and independently.
        assert!(paths.contains(&"real_dir/secret.txt"));
    }

    /// the same "never descend into a symlinked directory"
    /// guarantee holds for the watcher's directory-registration path, not
    /// just the scanner — a `CreatedOrModified` event for a freshly
    /// created symlink-to-directory must not cause the watcher to start
    /// watching (and thus later report file events for) anything inside
    /// the target.
    #[cfg(unix)]
    #[tokio::test]
    async fn watcher_never_registers_watches_inside_a_symlinked_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("real_dir")).unwrap();
        let mut watcher = yadorilink_filesystem_sync::watcher::watch_folder(&root).unwrap();

        std::os::unix::fs::symlink(root.join("real_dir"), root.join("link_dir")).unwrap();
        // The very first event received isn't necessarily this one:
        // macOS FSEvents' watch stream can have a small replay window
        // covering moments just before it starts, so the `real_dir`
        // creation above (right before watch_folder) can legitimately
        // surface here too (observed reproducing in real CI) -- loop
        // past anything unrelated, same tolerance the leak-check below
        // already applies to this same FSEvents quirk.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_link_dir = false;
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let event = tokio::time::timeout(remaining, watcher.events.recv())
                .await
                .expect("timed out waiting for the symlink-creation event")
                .expect("watcher channel closed");
            if event.path.file_name().and_then(|n| n.to_str()) == Some("link_dir") {
                saw_link_dir = true;
                break;
            }
        }
        assert!(saw_link_dir, "the symlink creation itself must still be reported");

        // A file written *through* the symlinked directory into its real
        // target must never surface as a watched event *under the link's
        // own path* — proof no recursive watch was registered on the
        // target via the link. Checked as "strictly inside link_dir"
        // (`link_dir/<something>`), not merely "mentions link_dir"
        // anywhere: macOS FSEvents can legitimately emit more than one
        // coalesced notification for the link's own creation (a known,
        // pre-existing source of flakiness this crate's other comments
        // already call out), which would be a false positive for a
        // cruder substring check but says nothing about a leak.
        std::fs::write(root.join("real_dir/new_file.txt"), b"leak?").unwrap();
        let link_dir_path = root.join("link_dir");
        let mut leaked = None;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match tokio::time::timeout(remaining, watcher.events.recv()).await {
                Ok(Some(ev)) => {
                    if ev.path.starts_with(&link_dir_path) && ev.path != link_dir_path {
                        leaked = Some(ev);
                        break;
                    }
                    // Some other, unrelated event (e.g. a duplicate
                    // notification about `link_dir`'s own creation, or the
                    // legitimate `real_dir/new_file.txt` event reached via
                    // its real, directly-watched path) — keep draining.
                }
                _ => break,
            }
        }
        assert!(
            leaked.is_none(),
            "the watcher must never report an event reached only via the symlinked directory: {leaked:?}"
        );
    }

    /// a symlink with an absolute target is flagged.
    #[cfg(unix)]
    #[tokio::test]
    async fn absolute_target_symlink_is_flagged() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let link_path = root.join("abs_link");
        std::os::unix::fs::symlink("/etc/passwd", &link_path).unwrap();

        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert!(state
            .file_index_repository()
            .get_symlink_out_of_root("group-1", "abs_link")
            .unwrap());
        assert_eq!(
            state.file_index_repository().get_symlink_target("group-1", "abs_link").unwrap(),
            Some(b"/etc/passwd".to_vec()),
            "the raw target text is still recorded and synced, never rewritten"
        );
    }

    /// a relative symlink target that syntactically resolves
    /// outside the linked folder's root (via `..`) is flagged too, without
    /// ever dereferencing the target (the target need not even exist).
    #[cfg(unix)]
    #[tokio::test]
    async fn out_of_root_relative_target_symlink_is_flagged() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        std::fs::create_dir_all(root.join("subdir")).unwrap();
        let link_path = root.join("subdir/escape_link");
        // Climbs above `root` itself: subdir/../.. -> above root.
        std::os::unix::fs::symlink("../../outside/nonexistent", &link_path).unwrap();

        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert!(state
            .file_index_repository()
            .get_symlink_out_of_root("group-1", "subdir/escape_link")
            .unwrap());
    }

    /// a relative target that stays inside the folder root
    /// (even via a `..` that doesn't actually escape) is NOT flagged.
    #[cfg(unix)]
    #[tokio::test]
    async fn in_root_relative_target_symlink_is_not_flagged() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        std::fs::create_dir_all(root.join("subdir")).unwrap();
        std::fs::write(root.join("sibling.txt"), b"data").unwrap();
        let link_path = root.join("subdir/in_root_link");
        // subdir/../sibling.txt -> root/sibling.txt: still inside root.
        std::os::unix::fs::symlink("../sibling.txt", &link_path).unwrap();

        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert!(!state
            .file_index_repository()
            .get_symlink_out_of_root("group-1", "subdir/in_root_link")
            .unwrap());
    }

    /// a self-referential symlinked-directory cycle (`a -> a`)
    /// must not hang or recurse when scanned — proven with a real
    /// wall-clock timeout around the scan (run on a background thread,
    /// since `scan_existing_files` is synchronous) so a genuine infinite
    /// loop fails the test loudly instead of hanging the suite forever.
    /// This is expected to pass structurally, not by luck: the rule means
    /// the scanner never descends into ANY symlinked directory, cyclic or
    /// not, so there is no recursive call into the cycle to bound in the
    /// first place — this test exists to confirm that reasoning against
    /// real filesystem behavior rather than trusting it blindly.
    #[cfg(unix)]
    #[test]
    fn self_referential_symlinked_directory_cycle_does_not_hang_or_recurse() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::create_dir_all(root.join("cyc")).unwrap();
        // cyc/a -> cyc/a (a symlink whose own path is its target).
        std::os::unix::fs::symlink(root.join("cyc/a"), root.join("cyc/a")).unwrap();
        std::fs::write(root.join("ordinary.txt"), b"unrelated").unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let proc = Arc::new(proc);
        let proc_clone = proc.clone();
        let root_clone = root.clone();
        std::thread::spawn(move || {
            let result = proc_clone.scan_existing_files("group-1", &root_clone);
            let _ = tx.send(result);
        });

        let result = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("scan_existing_files hung on a self-referential symlink cycle");
        let records = result.unwrap();

        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"cyc/a"), "the cyclic symlink itself must still be recorded");
        assert!(paths.contains(&"ordinary.txt"));
        assert_eq!(
            state.file_index_repository().get_record_kind("group-1", "cyc/a").unwrap(),
            Some(yadorilink_replica_domain::file::RecordKind::Symlink)
        );
    }

    /// a two-hop symlinked-directory cycle (`a/b -> a`, i.e. a
    /// directory containing a symlink back to one of its own ancestors)
    /// also must not hang or recurse.
    #[cfg(unix)]
    #[test]
    fn ancestor_referencing_symlinked_directory_cycle_does_not_hang_or_recurse() {
        let (proc, _state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::create_dir_all(root.join("a")).unwrap();
        // a/b -> a (points back up at its own parent).
        std::os::unix::fs::symlink(root.join("a"), root.join("a/b")).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let proc = Arc::new(proc);
        let proc_clone = proc.clone();
        let root_clone = root.clone();
        std::thread::spawn(move || {
            let result = proc_clone.scan_existing_files("group-1", &root_clone);
            let _ = tx.send(result);
        });

        let result = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("scan_existing_files hung on an ancestor-referencing symlink cycle");
        let records = result.unwrap();
        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"a/b"));
        assert!(
            !paths.iter().any(|p| p.starts_with("a/b/")),
            "must never descend through the cycle"
        );
    }

    /// `normalize_syntactic`/`symlink_target_is_out_of_root`
    /// never touch the filesystem — proven by pointing at a target that
    /// does not exist at all (`read_link`-based classification must not
    /// require or attempt to resolve it).
    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_classification_does_not_require_the_target_to_exist() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&state, "group-1", &root);
        let link_path = root.join("dangling_link");
        std::os::unix::fs::symlink("this/path/does/not/exist.txt", &link_path).unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert!(record.blocks.is_empty());
        assert_eq!(
            state.file_index_repository().get_symlink_target("group-1", "dangling_link").unwrap(),
            Some(b"this/path/does/not/exist.txt".to_vec())
        );
        assert!(!state
            .file_index_repository()
            .get_symlink_out_of_root("group-1", "dangling_link")
            .unwrap());
    }

    /// The real authorization stamp a healthy policy hands local emission in
    /// the stale-policy tests below — any non-placeholder value works; these
    /// tests only care that it is *not* the all-zero placeholder and that it
    /// reaches the emitted change verbatim once policy is healthy.
    const TEST_REAL_AUTH: ChangeAuth =
        ChangeAuth { auth_seq: 5, auth_epoch: 2, policy_head_hash: [3u8; 32] };

    /// Builds a change-emitting processor whose local-emission auth provider is
    /// driven by the returned flag: `false` (the initial value) makes the
    /// provider report the group's policy as stale (`Err(PolicyUnavailable)`),
    /// and flipping it to `true` makes the provider hand back
    /// [`TEST_REAL_AUTH`] — the exact transition the daemon's provider
    /// undergoes when a failed policy snapshot is later superseded by a valid
    /// one. The `TempDir`s are returned so the caller keeps them alive.
    fn processor_with_toggleable_policy() -> (
        LocalChangeProcessor,
        Arc<TestReplica>,
        Arc<std::sync::atomic::AtomicBool>,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        use ed25519_dalek::SigningKey;
        use std::sync::atomic::Ordering;
        use yadorilink_replica_domain::change::PolicyUnavailable;

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(TestReplica::open_in_memory().unwrap());

        let policy_healthy = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let policy_healthy = policy_healthy.clone();
            state.set_local_change_auth_provider(Arc::new(move |_group_id| {
                if policy_healthy.load(Ordering::SeqCst) {
                    Ok(TEST_REAL_AUTH)
                } else {
                    Err(PolicyUnavailable)
                }
            }));
        }

        let emitter = Arc::new(ChangeEmitter::new("device-a", SigningKey::from_bytes(&[7u8; 32])));
        let proc = LocalChangeProcessor::new(
            state.clone(),
            store,
            "device-a".into(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(emitter);
        let root_dir = tempfile::tempdir().unwrap();
        (proc, state, policy_healthy, store_dir, root_dir)
    }

    /// While a group's policy is stale the auth provider returns
    /// `Err(PolicyUnavailable)`, and a local edit must then produce NO DAG
    /// change — appending a placeholder-auth change here would create a local
    /// head every valid-policy peer rejects, stranding an un-replicable
    /// branch. The edit must not be lost either: the path stays in the durable
    /// dirty-path journal so a later re-drive can emit it once policy heals.
    #[tokio::test]
    async fn stale_policy_withholds_the_dag_change_but_keeps_the_path_journaled_dirty() {
        let (proc, state, _policy_healthy, _store_dir, root_dir) =
            processor_with_toggleable_policy();
        let root = canonical_root(&root_dir);
        let file_path = root.join("note.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        let group = "group-1";
        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            file_path,
            FsChangeKind::CreatedOrModified,
            1_000,
        )]);
        let outcome = proc.process_flush(group, &root, flush).await.unwrap();

        // No record is announced and — crucially — the group's history is still
        // empty: no placeholder-auth change entered the DAG.
        assert!(outcome.records.is_empty(), "a stale-policy edit must not announce a record");
        assert!(
            state.sqlite().dag_group_heads(group).unwrap().is_empty(),
            "no placeholder-auth change may enter the DAG while policy is stale"
        );
        // The edit is not lost: it remains journaled dirty for re-drive.
        assert!(state.dirty_path_repository().is_path_dirty(group, "note.txt").unwrap());
        assert!(state
            .dirty_path_repository()
            .list_dirty_paths(group)
            .unwrap()
            .iter()
            .any(|d| d.path == "note.txt"));
    }

    /// The coordination plane's netmap push carries a `policyInvalidGroupIds`
    /// list naming groups whose stored policy state is malformed or corrupt
    /// on the coordination plane's side (see the coordination worker's
    /// netmap-computation and policy-distribution modules, which isolate
    /// such a group out of the push rather than trust it). The daemon's
    /// netmap client has no field for that list at all, so nothing ever
    /// marks a group named there stale -- unlike the whole-policy-portion
    /// failure this module's `stale_policy_withholds_...` test above covers,
    /// a per-group `policyInvalidGroupIds` entry reaches this emission layer
    /// only through the local-emission auth provider. In the daemon the
    /// unified group-policy resolver funnels a coordinator-flagged group
    /// through `mark_group_policy_stale` and reports it `Withhold`, so the
    /// provider returns `Err(PolicyUnavailable)` for exactly that group while
    /// healthy groups keep getting a real stamp. The group-aware provider
    /// installed below stands in for that resolver at this layer.
    #[tokio::test]
    async fn policy_invalid_group_id_stops_local_dag_emission_for_that_group() {
        let (proc, state, _policy_healthy, _store_dir, root_dir) =
            processor_with_toggleable_policy();
        // Only the coordinator-flagged group withholds; every other group
        // still resolves to a real stamp. This is what the daemon's resolver
        // does once `policyInvalidGroupIds` is consumed.
        state.set_local_change_auth_provider(std::sync::Arc::new(|group_id| {
            if group_id == "policy-invalid-group" {
                Err(yadorilink_replica_domain::change::PolicyUnavailable)
            } else {
                Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
            }
        }));

        let root = canonical_root(&root_dir);
        let file_path = root.join("note.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        let group = "policy-invalid-group";
        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            file_path,
            FsChangeKind::CreatedOrModified,
            1_000,
        )]);
        let outcome = proc.process_flush(group, &root, flush).await.unwrap();

        assert!(
            outcome.records.is_empty(),
            "a local edit in a group the coordination plane flagged policy-invalid must be \
             withheld, not DAG-committed like a healthy group's edit"
        );
        assert!(
            state.sqlite().dag_group_heads(group).unwrap().is_empty(),
            "no change may enter the DAG for a policy-invalid group; the daemon funnels \
             `policyInvalidGroupIds` through the same withholding staleness gate"
        );
    }

    /// A restart re-drive that fully clears the dirty journal must leave a
    /// second, immediately-following re-drive a true no-op: no records
    /// produced, no journal rows re-appear, and no duplicate DAG head. This
    /// pins `redrive_dirty_journal`'s empty-journal short-circuit against
    /// Stage-1's batched journal/clear path specifically, since a batching
    /// bug that left a stray row behind (or resurrected one) would only
    /// show up on this second call, not the first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redriving_an_already_cleared_dirty_journal_twice_in_a_row_is_a_no_op() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);

        std::fs::write(root.join("a.txt"), b"aaa").unwrap();
        std::fs::write(root.join("b.txt"), b"bbb").unwrap();
        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
            (root.join("a.txt"), FsChangeKind::CreatedOrModified, 0),
            (root.join("b.txt"), FsChangeKind::CreatedOrModified, 0),
        ]);
        proc.process_flush(group, &root, flush).await.unwrap();
        assert!(
            state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty(),
            "both paths must have succeeded and cleared their journal rows"
        );
        let heads_after_flush = state.sqlite().dag_group_heads(group).unwrap();

        let first_redrive = proc.redrive_dirty_journal(group, &root).await.unwrap();
        assert!(
            first_redrive.records.is_empty(),
            "an already-empty journal must produce no records on re-drive"
        );

        let second_redrive = proc.redrive_dirty_journal(group, &root).await.unwrap();
        assert!(
            second_redrive.records.is_empty(),
            "a second, immediately-following re-drive must remain a no-op"
        );
        assert!(state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty());
        assert_eq!(
            state.sqlite().dag_group_heads(group).unwrap(),
            heads_after_flush,
            "re-driving an empty journal twice must never move the DAG head"
        );
    }

    /// Once the policy heals — the provider flips from `Err(PolicyUnavailable)`
    /// to `Ok(auth)` — re-driving the dirty journal emits the previously
    /// withheld edit as a real, non-placeholder-auth change and clears the
    /// journal row, so the deferred edit replicates normally.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn healed_policy_reemits_the_withheld_edit_with_real_auth_and_clears_the_journal() {
        use std::sync::atomic::Ordering;

        let (proc, state, policy_healthy, _store_dir, root_dir) =
            processor_with_toggleable_policy();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);
        let file_path = root.join("note.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            file_path,
            FsChangeKind::CreatedOrModified,
            1_000,
        )]);
        // Stale phase: withheld, journaled dirty (asserted in full by the test
        // above; here it is only the precondition for the re-drive).
        proc.process_flush(group, &root, flush).await.unwrap();
        assert!(state.sqlite().dag_group_heads(group).unwrap().is_empty());
        assert!(state.dirty_path_repository().is_path_dirty(group, "note.txt").unwrap());

        // Policy heals; the backstop re-drive re-emits the withheld edit.
        policy_healthy.store(true, Ordering::SeqCst);
        let redriven = proc.redrive_dirty_journal(group, &root).await.unwrap();
        assert_eq!(redriven.records.len(), 1, "the healed re-drive emits the withheld edit");

        let heads = state.sqlite().dag_group_heads(group).unwrap();
        assert_eq!(heads.len(), 1, "exactly one change now heads the group");
        let change =
            state.sqlite().dag_get_change(&heads[0]).unwrap().expect("emitted change is stored");
        assert_eq!(change.auth_seq, TEST_REAL_AUTH.auth_seq);
        assert_eq!(change.auth_epoch, TEST_REAL_AUTH.auth_epoch);
        assert_eq!(change.policy_head_hash, TEST_REAL_AUTH.policy_head_hash);
        assert_ne!(
            change.auth_seq,
            ChangeAuth::PLACEHOLDER.auth_seq,
            "the re-emitted change must carry the real auth, not the placeholder"
        );

        // The journal row is cleared on the successful re-emission.
        assert!(!state.dirty_path_repository().is_path_dirty(group, "note.txt").unwrap());
        assert!(state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty());
    }

    /// A restart reconciliation scan that detects an offline edit while the
    /// group's policy is stale must NOT fall back to a DAG-silent index write.
    /// The historical fallback wrote the batch through the non-emitting
    /// `upsert_files_batch`, advancing the local index to match disk — so a
    /// later rescan saw no disk-vs-index diff and the change never entered the
    /// DAG, and (unlike the live `process_flush` path) nothing was journaled
    /// dirty to re-drive it either. The edit was stranded outside the DAG
    /// forever. The scan must instead withhold the index write, leave the
    /// index unadvanced, and journal the path dirty, so the dirty-journal
    /// re-drive re-emits the change and the DAG head advances once policy
    /// heals. This test fails on the old silent fallback (the DAG head never
    /// advances past the pre-edit head).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_policy_scan_withholds_index_write_then_reemits_offline_edit_once_healed() {
        use std::sync::atomic::Ordering;

        let (proc, state, policy_healthy, _store_dir, root_dir) =
            processor_with_toggleable_policy();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);
        let file_path = root.join("report.txt");

        // A healthy-policy live edit establishes the group's first DAG history.
        policy_healthy.store(true, Ordering::SeqCst);
        std::fs::write(&file_path, b"version one").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let heads_before = state.sqlite().dag_group_heads(group).unwrap();
        assert_eq!(heads_before.len(), 1, "sanity: the live edit established one DAG head");

        // Policy goes stale; the file is edited offline (daemon "stopped").
        policy_healthy.store(false, Ordering::SeqCst);
        std::fs::write(&file_path, b"version two, edited offline while policy was stale").unwrap();

        // The restart scan detects the offline edit, but policy is stale: it
        // must withhold both the DAG change and the index write and journal the
        // path dirty. The old silent fallback wrote the index here.
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        let scan_records = proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        assert!(
            scan_records.is_empty(),
            "a stale-policy scan must announce nothing — no record ever entered the DAG"
        );
        assert_eq!(
            state.sqlite().dag_group_heads(group).unwrap(),
            heads_before,
            "no change may enter the DAG while policy is stale"
        );
        // The index must NOT have advanced to the offline content: advancing it
        // is exactly what poisoned re-derivation in the old silent fallback.
        let indexed = state.file_index_repository().get_file(group, "report.txt").unwrap().unwrap();
        assert_eq!(
            indexed.size,
            b"version one".len() as u64,
            "the scan must not silently advance the index while policy is stale"
        );
        // The withheld edit is journaled dirty for the re-drive.
        assert!(
            state.dirty_path_repository().is_path_dirty(group, "report.txt").unwrap(),
            "the policy-withheld offline edit must be journaled dirty for re-drive"
        );

        // Policy heals; the dirty-journal re-drive re-emits the withheld edit.
        policy_healthy.store(true, Ordering::SeqCst);
        let redriven = proc.redrive_dirty_journal(group, &root).await.unwrap();
        assert_eq!(
            redriven.records.len(),
            1,
            "the healed re-drive emits the previously withheld offline edit"
        );

        let heads_after = state.sqlite().dag_group_heads(group).unwrap();
        assert_ne!(
            heads_after, heads_before,
            "the offline edit must advance the DAG head once policy heals; the silent fallback \
             left it stranded outside the DAG forever"
        );
        let indexed = state.file_index_repository().get_file(group, "report.txt").unwrap().unwrap();
        assert_eq!(
            indexed.size,
            b"version two, edited offline while policy was stale".len() as u64,
            "the re-drive reconciles the index to the offline content"
        );
        assert!(
            !state.dirty_path_repository().is_path_dirty(group, "report.txt").unwrap(),
            "the journal row is cleared on the successful re-emission"
        );
    }

    /// Builds a processor with change-history emission wired against a
    /// plain, always-succeeding local-change auth (unlike
    /// `processor_with_toggleable_policy`'s stale/healed toggle) — plus
    /// direct access to the underlying `ReplicaCoordinator` and `ChangeEmitter`
    /// so a test can inspect DAG heads and re-run the DAG-import path the same
    /// way the daemon's restart sequence does.
    fn processor_with_emitter() -> (
        LocalChangeProcessor,
        Arc<TestReplica>,
        Arc<ChangeEmitter>,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        use ed25519_dalek::SigningKey;

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(TestReplica::open_in_memory().unwrap());
        let emitter = Arc::new(ChangeEmitter::new("device-a", SigningKey::from_bytes(&[5u8; 32])));
        let proc = LocalChangeProcessor::new(
            state.clone(),
            store,
            "device-a".into(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(emitter.clone());
        let root_dir = tempfile::tempdir().unwrap();
        (proc, state, emitter, store_dir, root_dir)
    }

    /// Section 9A of the 2026-09 device-A local-origin fix's regression
    /// suite: a disk change between the content read and the final
    /// pre-commit revalidation must suppress the proof entirely (never a
    /// hard failure of the capture itself -- see `fresh_actual_state_
    /// identity_if_unraced`'s own doc comment). Exercises the exact
    /// helper `process_event_with_ignore_at`'s single-immediate commit
    /// path calls, directly and deterministically -- no wall-clock race,
    /// no real concurrent writer, just the two fingerprint states that
    /// helper actually compares.
    #[test]
    fn fresh_actual_state_identity_if_unraced_suppresses_on_a_fingerprint_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"v1").unwrap();
        let fingerprint_before_read = disk_race_fingerprint(&path);
        assert!(fingerprint_before_read.is_some(), "sanity: a real file must fingerprint");

        // Matching fingerprint: identity IS observed.
        assert!(
            fresh_actual_state_identity_if_unraced(&path, fingerprint_before_read).is_some(),
            "an unchanged file between the two observations must still produce an identity"
        );

        // A write between "before read" and "final revalidation" changes
        // the fingerprint (size, at minimum) -- the helper must suppress,
        // not merely warn.
        std::fs::write(&path, b"v2, raced in").unwrap();
        assert!(
            fresh_actual_state_identity_if_unraced(&path, fingerprint_before_read).is_none(),
            "a disk fingerprint mismatch between the pre-read and pre-commit observations must \
             suppress the identity entirely -- publishing a proof here would attest to content \
             that was never actually read/hashed for this commit"
        );

        // No file at all (e.g. deleted in the same window): also
        // suppressed, not a panic/error.
        std::fs::remove_file(&path).unwrap();
        assert!(fresh_actual_state_identity_if_unraced(&path, fingerprint_before_read).is_none());

        // A `None` "before" fingerprint (the read itself raced a delete)
        // must never be treated as "nothing to compare against, so
        // trust it" -- always suppressed.
        assert!(fresh_actual_state_identity_if_unraced(&path, None).is_none());
    }

    /// The RED->GREEN regression for the 2026-09 device-A local-origin
    /// zero-work fix. Before this fix (RED, provable by reverting
    /// `file_index.rs`'s `adopt_local_capture_actual_state` call and
    /// re-running this test): a local capture never wrote a
    /// `path_materialized_generations` row for its own freshly-authored
    /// content, so `dag_zero_work_settlement_if_already_current`'s
    /// `lookup_materialized_generation` call always returned `None`, and
    /// the ordinary reconcile path (`materialize_dag_content_head`) was
    /// the only way this device's own already-correct file could ever
    /// settle its projection obligation.
    ///
    /// GREEN (this fix): local capture publishes a usable exact
    /// actual-state proof in the SAME transaction as the DAG/index
    /// commit. This test asserts the durable state directly -- never a
    /// wall-clock/call-count proxy -- via the exact three preconditions
    /// `dag_zero_work_settlement_if_already_current` itself checks:
    /// (1) a projection obligation exists for the path (the universal
    /// admission invariant, unaffected by this fix), (2)
    /// `dag_lookup_materialized_generation` returns `Some` (the proof is
    /// USABLE right now, not merely present-but-stale against the
    /// mutation fence), and (3) that row's `resolved_path_state_hash`
    /// equals what `dag_desired_resolved_path_state_hash` independently
    /// derives for the group's own current DAG-resolved state --
    /// precisely the equality `dag_zero_work_settlement_if_already_
    /// current` gates a real settlement on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_capture_of_new_content_publishes_a_usable_exact_actual_state_proof() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);
        let file_path = root.join("report.txt");

        std::fs::write(&file_path, b"locally authored content").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        // (1) Admission's own universal invariant: not-admitted -> admitted
        // must have created/bumped a runnable projection obligation for
        // this path, exactly as it would for ANY admitted change,
        // regardless of this fix.
        let obligation =
            state.sqlite().dag_lookup_projection_obligation(group, "report.txt").unwrap();
        assert!(
            obligation.is_some(),
            "sanity: the Convergence Engine's own universal admission invariant must still hold \
             -- this fix must never special-case local admission by suppressing obligation \
             creation"
        );

        // (2) The proof this fix publishes must be immediately usable --
        // not merely present, which `lookup_materialized_generation`'s own
        // fail-closed contract (its `published_under_mutation_generation`
        // CAS against the live fence) would refuse to return at all if
        // this fix's fence-then-write ordering were wrong.
        let basis = state.sqlite().dag_lookup_materialized_generation(group, "report.txt").unwrap();
        let basis = basis.expect(
            "GREEN behavior missing: local capture of new content must publish a USABLE exact \
             actual-state proof in the same transaction as its DAG/index commit -- if this is \
             None, either the fix regressed to not publishing at all, or it published under a \
             stale/mismatched mutation-fence epoch",
        );
        assert_eq!(
            basis.object_kind,
            yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile
        );
        assert!(basis.version.is_some(), "a present object's proof must carry its version hash");
        assert!(
            basis.filesystem_identity.is_some(),
            "a present object's proof must carry a strong FileIdentity"
        );

        // (3) The exact equality `dag_zero_work_settlement_if_already_
        // current` gates a real settlement on: the published proof's
        // resolved_path_state_hash must equal what the group's own
        // CURRENT DAG-resolved desired state independently derives --
        // computed here via the same production hash builder
        // (`dag_desired_resolved_path_state_hash`), not re-derived by
        // this test's own logic, so this assertion fails if either side
        // of that real equality check ever drifts.
        let resolution = yadorilink_replica_engine::conflict::PathResolution::Present {
            winner: 0,
            conflict_copies: vec![],
        };
        let desired_hash = state
            .sqlite()
            .dag_desired_resolved_path_state_hash(
                group,
                "report.txt",
                &resolution,
                basis.version.as_ref(),
            )
            .unwrap();
        assert_eq!(
            basis.resolved_path_state_hash, desired_hash,
            "the published proof's resolved_path_state_hash must match the group's own current \
             desired-state hash -- this exact equality is what \
             dag_zero_work_settlement_if_already_current gates a real zero-work close on, so a \
             mismatch here means the Convergence Engine would still fall through to the \
             ordinary (non-zero-work) reconcile path despite this fix"
        );
    }

    /// Section 9E of the 2026-09 device-A local-origin fix's regression
    /// suite: a locally observed deletion must publish an exact `Absent`
    /// proof in the same transaction as its tombstone admission, so a
    /// peer's own reconcile of this now-deleted path can zero-work close
    /// (recognize "already absent") without a redundant remove syscall --
    /// the same GREEN behavior as content capture, but for
    /// `MaterializedObjectKind::Absent` rather than `RegularFile`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_capture_of_a_deletion_publishes_a_usable_exact_absent_proof() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);
        let file_path = root.join("report.txt");

        std::fs::write(&file_path, b"locally authored content").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        std::fs::remove_file(&file_path).unwrap();
        let tombstone = expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::Removed },
            )
            .await
            .unwrap(),
        );
        assert!(tombstone.deleted, "sanity: the deletion must have been admitted as a tombstone");

        // Admission's own universal invariant still holds for a deletion,
        // exactly as it does for content capture.
        let obligation =
            state.sqlite().dag_lookup_projection_obligation(group, "report.txt").unwrap();
        assert!(
            obligation.is_some(),
            "a locally observed deletion must still create/bump a runnable projection \
             obligation for its path -- this fix must never special-case local admission by \
             suppressing obligation creation, deletion included"
        );

        let basis = state.sqlite().dag_lookup_materialized_generation(group, "report.txt").unwrap();
        let basis = basis.expect(
            "GREEN behavior missing: a locally observed deletion must publish a USABLE exact \
             Absent proof in the same transaction as its tombstone admission",
        );
        assert_eq!(
            basis.object_kind,
            yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Absent,
            "a locally observed deletion's proof must describe absence, not a stale present kind"
        );
        assert!(basis.version.is_none(), "an absent object's proof must carry no version hash");
        assert!(
            basis.filesystem_identity.is_none(),
            "an absent object's proof must carry no filesystem identity"
        );

        let desired_hash = state
            .sqlite()
            .dag_desired_resolved_path_state_hash(
                group,
                "report.txt",
                &yadorilink_replica_engine::conflict::PathResolution::Absent,
                None,
            )
            .unwrap();
        assert_eq!(
            basis.resolved_path_state_hash, desired_hash,
            "the published Absent proof's resolved_path_state_hash must match the group's own \
             current desired-state hash for absence -- this exact equality is what \
             dag_zero_work_settlement_if_already_current gates a real zero-work close on"
        );
    }

    /// Section 9D of the 2026-09 device-A local-origin fix's regression
    /// suite: a second local edit's own captured proof must fully
    /// supersede the first's, never leave the first's stale
    /// `resolved_path_state_hash` sitting around able to authorize
    /// zero-work settlement of content it no longer describes. Only
    /// covers correctness from the point the second edit is OBSERVED by
    /// local capture (an ordinary second `process_event` call) --
    /// nothing here claims pre-watcher linearizability against the
    /// external write itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_local_capture_supersedes_the_first_captures_stale_proof() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);
        let file_path = root.join("report.txt");

        std::fs::write(&file_path, b"version one").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let basis_v1 = state
            .sqlite()
            .dag_lookup_materialized_generation(group, "report.txt")
            .unwrap()
            .expect("sanity: v1's own capture must publish a usable proof");

        // A second, genuinely different local edit -- observed by local
        // capture exactly like the first, an ordinary second event, not a
        // race this test needs to simulate specially.
        std::fs::write(&file_path, b"version two, a real second edit").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let basis_v2 = state
            .sqlite()
            .dag_lookup_materialized_generation(group, "report.txt")
            .unwrap()
            .expect("v2's own capture must also publish a usable proof");

        assert_ne!(
            basis_v2.version, basis_v1.version,
            "the second capture's proof must carry v2's own version hash, not v1's"
        );
        assert_ne!(
            basis_v2.resolved_path_state_hash, basis_v1.resolved_path_state_hash,
            "v1's stale resolved_path_state_hash must not still be the row's live value after \
             v2's own capture published its own -- a stale hash surviving here could let a \
             leftover v1 proof wrongly authorize zero-work settlement of v2's obligation"
        );

        // v1's own hash, independently recomputed, must no longer match
        // ANYTHING the live row now describes -- confirms this isn't just
        // "a different row exists somewhere," but that the ONE row
        // `dag_lookup_materialized_generation` returns for this path is
        // unambiguously v2's, not v1's under a still-live guise.
        let resolution = yadorilink_replica_engine::conflict::PathResolution::Present {
            winner: 0,
            conflict_copies: vec![],
        };
        let v1_hash_recomputed = state
            .sqlite()
            .dag_desired_resolved_path_state_hash(
                group,
                "report.txt",
                &resolution,
                basis_v1.version.as_ref(),
            )
            .unwrap();
        assert_ne!(
            basis_v2.resolved_path_state_hash, v1_hash_recomputed,
            "v2's live proof must not happen to match v1's own content hash recomputed fresh -- \
             confirms this test's two versions are genuinely distinct content, not a false \
             positive from picking two edits that happen to hash the same"
        );
    }

    /// Batch-path counterpart to `local_capture_of_new_content_publishes_a_
    /// usable_exact_actual_state_proof`: the SAME GREEN behavior must hold
    /// through `commit_local_mutations_batch` (a `Paths` flush with more
    /// than one non-symlink file, the shape a real debounced multi-file
    /// save/import batches into), not just the single-immediate commit --
    /// section 10's own requirement that each successfully-revalidated
    /// batched mutation gets its own exact proof inputs, and a path
    /// excluded by revalidation gets none.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn batched_local_capture_of_new_content_publishes_usable_exact_actual_state_proofs() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        adopt_root(&state, group, &root);
        std::fs::write(root.join("a.txt"), b"aaa content").unwrap();
        std::fs::write(root.join("b.txt"), b"bbb content").unwrap();

        let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
            (root.join("a.txt"), FsChangeKind::CreatedOrModified, 0),
            (root.join("b.txt"), FsChangeKind::CreatedOrModified, 0),
        ]);
        let outcome = proc.process_flush(group, &root, flush).await.unwrap();
        assert_eq!(outcome.records.len(), 2, "sanity: both files must have been captured");

        for path in ["a.txt", "b.txt"] {
            let basis = state
                .sqlite()
                .dag_lookup_materialized_generation(group, path)
                .unwrap()
                .unwrap_or_else(|| panic!("batched capture of {path} must publish a usable proof"));
            assert_eq!(
                basis.object_kind,
                yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile
            );
            let resolution = yadorilink_replica_engine::conflict::PathResolution::Present {
                winner: 0,
                conflict_copies: vec![],
            };
            let desired_hash = state
                .sqlite()
                .dag_desired_resolved_path_state_hash(
                    group,
                    path,
                    &resolution,
                    basis.version.as_ref(),
                )
                .unwrap();
            assert_eq!(
                basis.resolved_path_state_hash, desired_hash,
                "{path}'s batched proof must satisfy the same zero-work equality as the \
                 single-immediate path"
            );
        }
    }

    /// Reproduces the restart gap in the change-history DAG: a file edited
    /// while the daemon isn't running is picked up by the startup disk-vs-
    /// index reconciliation scan (`scan_existing_files_with_ignore`), which
    /// updates the local index via the batched, non-DAG-emitting writer
    /// (`LocalMutationStore::upsert_files_batch`) — never appending a change to the
    /// group's change-history DAG the way a live `process_event` call would.
    /// The restart sequence's other chance to backfill that change,
    /// re-running the idempotent initial import
    /// (`dag_import::ensure_initial_import`, exactly as
    /// `yadorilink-daemon`'s startup wiring (`link_runtime::startup`) does right after the scan),
    /// is gated on the group's DAG still being empty (see `dag_import`'s
    /// module doc) and so is a no-op once real history already exists. The
    /// on-disk file and the local index both show the new content, but the
    /// DAG head a change-history-aware peer negotiates against never moves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offline_edit_after_existing_dag_history_must_append_new_head_on_restart() {
        let (proc, state, emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        // As `offline_delete_after_existing_dag_history_must_append_delete_
        // change` documents: the later offline edit leaves the index and
        // disk disagreeing on the same path, indistinguishable from an
        // unmounted volume unless the folder's identity was established
        // first, as a real link's would have been.
        adopt_root(&state, group, &root);
        let file_path = root.join("report.txt");

        // A live edit while the daemon is running establishes the group's
        // first DAG history, exactly as a normal local save does.
        std::fs::write(&file_path, b"version one").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let heads_before = state.sqlite().dag_group_heads(group).unwrap();
        assert_eq!(heads_before.len(), 1, "sanity: the live edit established one DAG head");

        // The daemon is "stopped": the file is edited directly on disk, with
        // no processor call observing the edit as it happens.
        std::fs::write(&file_path, b"version two, edited while the daemon was stopped").unwrap();

        // The daemon "restarts": its startup scan reconciles the index
        // against disk (the real path every linked folder's restart runs),
        // then re-runs the idempotent initial import, mirroring
        // `yadorilink-daemon`'s restart sequence exactly.
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        let scan_records = proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        assert!(!scan_records.is_empty(), "sanity: the restart scan must notice the offline edit");
        yadorilink_daemon::dag_import::ensure_initial_import(state.coordinator(), group, &emitter)
            .unwrap();

        // The local index reflects the offline edit...
        let indexed = state.file_index_repository().get_file(group, "report.txt").unwrap().unwrap();
        assert_eq!(
            indexed.size,
            b"version two, edited while the daemon was stopped".len() as u64,
            "sanity: the local index was reconciled to the offline edit"
        );

        // ...but the change-history DAG must have advanced past the
        // pre-restart head too, so a peer that only negotiates via DAG heads
        // (never a legacy full-index sync) can still learn about the
        // offline edit.
        let heads_after = state.sqlite().dag_group_heads(group).unwrap();
        assert_ne!(
            heads_after, heads_before,
            "an offline edit picked up by the restart scan must append a new DAG change, not \
             just update the local index"
        );
    }

    /// Same restart gap as `offline_edit_after_existing_dag_history_must_
    /// append_new_head_on_restart`, for an offline deletion: the startup
    /// scan tombstones the local index row for a file removed while the
    /// daemon wasn't running, but that tombstone never becomes a `Delete`
    /// change in the group's history DAG.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offline_delete_after_existing_dag_history_must_append_delete_change() {
        let (proc, state, emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let file_path = root.join("report.txt");
        // Deleting the group's only file leaves an empty root, which is
        // indistinguishable from an unmounted volume unless the folder's
        // identity was established first — as a real link's would have been.
        adopt_root(&state, group, &root);

        std::fs::write(&file_path, b"version one").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let heads_before = state.sqlite().dag_group_heads(group).unwrap();
        assert_eq!(heads_before.len(), 1, "sanity: one DAG head after the initial live edit");

        // The daemon is "stopped"; the file is deleted directly on disk.
        std::fs::remove_file(&file_path).unwrap();

        // Restart: scan + re-run the idempotent import, exactly as above.
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        let scan_records = proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        assert!(
            scan_records.iter().any(|r| r.path == "report.txt" && r.deleted),
            "sanity: the restart scan must tombstone the offline delete"
        );
        yadorilink_daemon::dag_import::ensure_initial_import(state.coordinator(), group, &emitter)
            .unwrap();

        let indexed = state.file_index_repository().get_file(group, "report.txt").unwrap().unwrap();
        assert!(indexed.deleted, "sanity: the local index reflects the offline delete");

        let heads_after = state.sqlite().dag_group_heads(group).unwrap();
        assert_ne!(
            heads_after, heads_before,
            "an offline delete picked up by the restart scan must append a Delete change to \
             the DAG, not just tombstone the local index row"
        );
    }

    /// The restart scan now routes an offline edit through the same
    /// DAG-emitting path a live edit uses, so the change reaches the group's
    /// history at scan time rather than updating the index only. Re-running
    /// the reconciliation must therefore be idempotent: neither a second scan
    /// of the unchanged file nor the dirty-journal redrive
    /// (`redrive_dirty_journal`, the daemon's restart backstop) may append a
    /// duplicate head or clear the already-emitted change. The DAG head must
    /// stay advanced past the pre-edit head and remain a single head — the
    /// redrive must never silently leave the group's history stuck, nor fork
    /// or drop the change it just emitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dirty_journal_redrive_must_not_clear_a_change_missing_from_dag() {
        let (proc, state, emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        // See `offline_edit_after_existing_dag_history_must_append_new_head_
        // on_restart`'s identical adoption for why: the offline edit below
        // leaves the index and disk disagreeing, indistinguishable from an
        // unmounted volume unless the folder's identity was established
        // first.
        adopt_root(&state, group, &root);
        let file_path = root.join("report.txt");

        std::fs::write(&file_path, b"version one").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let heads_before = state.sqlite().dag_group_heads(group).unwrap();

        // Offline edit picked up by the restart scan, exactly as the
        // append-on-restart test above: the scan now routes the change through
        // the same DAG-emitting path a live edit uses, so it appends the
        // change to the group's history at scan time. The re-run initial
        // import is a no-op once real history exists.
        std::fs::write(&file_path, b"version two, edited while the daemon was stopped").unwrap();
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        yadorilink_daemon::dag_import::ensure_initial_import(state.coordinator(), group, &emitter)
            .unwrap();

        let heads_after_scan = state.sqlite().dag_group_heads(group).unwrap();
        assert_ne!(
            heads_after_scan, heads_before,
            "the restart scan must append the offline edit to the DAG at scan time, exactly \
             as the append-on-restart test proves"
        );
        assert_eq!(
            heads_after_scan.len(),
            1,
            "the offline edit must advance to a single new head, not fork the group's history"
        );

        // Re-running the reconciliation must be idempotent. A second scan of
        // the (now unchanged) on-disk file finds nothing to emit, so it must
        // not append a duplicate head for the already-committed change.
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        yadorilink_daemon::dag_import::ensure_initial_import(state.coordinator(), group, &emitter)
            .unwrap();
        assert_eq!(
            state.sqlite().dag_group_heads(group).unwrap(),
            heads_after_scan,
            "re-running the scan on an already-emitted change must not append a duplicate head"
        );

        // The dirty-journal redrive must likewise neither clear the
        // already-emitted change (reverting the DAG head to before the edit)
        // nor re-append it as a duplicate — it must leave the emitted change
        // intact.
        proc.redrive_dirty_journal(group, &root).await.unwrap();

        let heads_final = state.sqlite().dag_group_heads(group).unwrap();
        assert_eq!(
            heads_final, heads_after_scan,
            "the dirty-journal redrive must leave the already-emitted change intact — neither \
             clearing it nor appending a duplicate head"
        );
        assert_ne!(
            heads_final, heads_before,
            "the redrive must never silently leave the group's history stuck at the pre-edit head"
        );
    }

    /// Walks the linear chain of changes from `head` back to (but excluding)
    /// `stop`, tip-first. Asserts every step has exactly one parent, i.e. the
    /// chain is linear — the shape a chunked reconciliation must produce so a
    /// crash can resume from the last committed chunk and the DAG never forks.
    fn linear_chain_back_to(
        state: &ReplicaCoordinator,
        head: yadorilink_replica_domain::ids::ChangeHash,
        stop: &yadorilink_replica_domain::ids::ChangeHash,
    ) -> Vec<yadorilink_replica_domain::change::Change> {
        let mut chain = Vec::new();
        let mut cur = head;
        while &cur != stop {
            let change = state.sqlite().dag_get_change(&cur).unwrap().unwrap();
            assert_eq!(
                change.parents.len(),
                1,
                "a chunked reconciliation must form a linear chain (exactly one parent per change)"
            );
            let parent = change.parents[0];
            chain.push(change);
            cur = parent;
        }
        chain
    }

    // Only called by the #[cfg(unix)] symlink/exec-bit atomicity tests below.
    #[cfg(unix)]
    fn version_hash_for_path(
        change: &yadorilink_replica_domain::change::Change,
        path: &str,
    ) -> yadorilink_replica_domain::ids::VersionHash {
        for op in &change.ops {
            match op {
                Op::Put { path: p, version, .. } if p.as_str() == path => {
                    return *version;
                }
                _ => {}
            }
        }
        panic!("no put op for {path} in change");
    }

    /// A symlink picked up by the DAG-emitting startup scan must land its index
    /// metadata columns (record kind / target / out-of-root) in the SAME
    /// committed state as the `FileVersion` the
    /// emitted change carries — no separate post-commit setter that a crash
    /// could tear from the emit. The old code applied those columns via
    /// `set_record_kind`/`set_symlink_*` AFTER the emit committed, so a crash
    /// in between left the DAG saying "symlink -> target" while the index row
    /// still showed the old (or default) columns. This asserts consistency
    /// immediately after the single emitting scan call, with no setter run.
    #[cfg(unix)]
    #[test]
    fn scan_emits_symlink_metadata_atomically_with_its_file_version() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

        // Establish DAG history so the scan takes the emitting path.
        std::fs::write(root.join("seed.txt"), b"seed").unwrap();
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        yadorilink_daemon::dag_import::ensure_initial_import(
            state.coordinator(),
            group,
            proc.change_emitter.as_ref().unwrap(),
        )
        .unwrap();
        let heads_before = state.sqlite().dag_group_heads(group).unwrap();

        // Offline: a new symlink whose raw target escapes the root.
        std::os::unix::fs::symlink("../outside", root.join("link")).unwrap();
        let scanned = proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        assert!(scanned.iter().any(|r| r.path == "link"), "sanity: the scan noticed the symlink");

        // Index metadata columns are correct right after the single emitting
        // scan call — no post-commit setter was needed.
        assert_eq!(
            state.file_index_repository().get_record_kind(group, "link").unwrap(),
            Some(RecordKind::Symlink)
        );
        assert_eq!(
            state.file_index_repository().get_symlink_target(group, "link").unwrap(),
            Some(b"../outside".to_vec())
        );
        assert!(state.file_index_repository().get_symlink_out_of_root(group, "link").unwrap());
        assert_eq!(state.file_index_repository().get_unix_mode(group, "link").unwrap(), None);

        // ...and the DAG `FileVersion` the emitted change references agrees
        // exactly (same single committed state, not a later reconciliation).
        let heads_after = state.sqlite().dag_group_heads(group).unwrap();
        assert_ne!(heads_after, heads_before, "the symlink must have emitted a change");
        let chain = linear_chain_back_to(&state, heads_after[0], &heads_before[0]);
        let vh = version_hash_for_path(&chain[chain.len() - 1], "link");
        let version = state.sqlite().dag_get_file_version(group, &vh).unwrap().unwrap();
        assert_eq!(version.meta.record_kind, RecordKind::Symlink);
        assert_eq!(version.meta.symlink_target.as_deref(), Some(b"../outside".as_slice()));
        assert_eq!(version.meta.unix_mode, None);
        // The two views are one and the same commit — the whole point of FIX A.
        assert_eq!(
            state.file_index_repository().get_record_kind(group, "link").unwrap(),
            Some(version.meta.record_kind),
        );
        assert_eq!(
            state.file_index_repository().get_symlink_target(group, "link").unwrap(),
            version.meta.symlink_target
        );
    }

    /// Exec-bit counterpart of the symlink case above: an executable regular
    /// file picked up by the emitting scan must have its `unix_mode` index column set
    /// in the same commit as the change's `FileVersion` — not by a separate
    /// `set_unix_mode` after the commit.
    #[cfg(unix)]
    #[test]
    fn scan_emits_unix_mode_atomically_with_its_file_version() {
        use std::os::unix::fs::PermissionsExt;

        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

        std::fs::write(root.join("seed.txt"), b"seed").unwrap();
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        yadorilink_daemon::dag_import::ensure_initial_import(
            state.coordinator(),
            group,
            proc.change_emitter.as_ref().unwrap(),
        )
        .unwrap();
        let heads_before = state.sqlite().dag_group_heads(group).unwrap();

        // Offline: a new executable script.
        let script = root.join("run.sh");
        std::fs::write(&script, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

        assert_eq!(
            state.file_index_repository().get_unix_mode(group, "run.sh").unwrap(),
            Some(0o755),
            "exec bit set right after the emit"
        );
        assert_eq!(
            state.file_index_repository().get_record_kind(group, "run.sh").unwrap(),
            Some(RecordKind::File)
        );
        assert_eq!(
            state.file_index_repository().get_symlink_target(group, "run.sh").unwrap(),
            None
        );

        let heads_after = state.sqlite().dag_group_heads(group).unwrap();
        let chain = linear_chain_back_to(&state, heads_after[0], &heads_before[0]);
        let vh = version_hash_for_path(&chain[chain.len() - 1], "run.sh");
        let version = state.sqlite().dag_get_file_version(group, &vh).unwrap().unwrap();
        assert_eq!(
            version.meta.unix_mode,
            Some(0o755),
            "the emitted FileVersion carries the exec bit too"
        );
        assert_eq!(
            state.file_index_repository().get_unix_mode(group, "run.sh").unwrap(),
            version.meta.unix_mode
        );
    }

    /// Codex review finding (C1.2a metadata-semantics checkpoint): the
    /// startup reconciliation scan used to emit `Vec::new()` for every
    /// record it re-authored, regardless of whether that path already
    /// carried real xattrs -- so an OFFLINE exec-bit-only change (content
    /// untouched) to a file that separately already had a replicated
    /// xattr silently wiped that attribute the moment the scan picked up
    /// the exec-bit divergence, in both the index and the emitted
    /// `FileVersion`. This proves the fix: the xattr must survive an
    /// unrelated offline metadata change discovered by the same scan.
    #[cfg(target_os = "linux")]
    #[test]
    fn scan_preserves_existing_xattrs_across_an_unrelated_offline_exec_bit_change() {
        use std::os::unix::fs::PermissionsExt;

        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

        let script = root.join("run.sh");
        std::fs::write(&script, b"#!/bin/sh\n").unwrap();
        yadorilink_local_storage::apply_xattrs(
            &script,
            &[("user.yadorilink-test".to_string(), b"keep-me".to_vec())],
        )
        .unwrap();
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        yadorilink_daemon::dag_import::ensure_initial_import(
            state.coordinator(),
            group,
            proc.change_emitter.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(
            state.file_index_repository().get_xattrs(group, "run.sh").unwrap(),
            vec![("user.yadorilink-test".to_string(), b"keep-me".to_vec())],
            "precondition: the xattr is indexed after the first scan"
        );

        // Offline: only the exec bit changes; the xattr is untouched.
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

        assert_eq!(
            state.file_index_repository().get_unix_mode(group, "run.sh").unwrap(),
            Some(0o755),
            "the offline exec-bit change was picked up"
        );
        assert_eq!(
            state.file_index_repository().get_xattrs(group, "run.sh").unwrap(),
            vec![("user.yadorilink-test".to_string(), b"keep-me".to_vec())],
            "an unrelated offline metadata change must never erase an already-indexed xattr"
        );
    }

    /// Op-count cap: a bulk offline diff of more than
    /// `RECONCILE_CHUNK_OP_LIMIT` (1024) paths, picked up by one restart scan,
    /// must be emitted as MULTIPLE chained changes each within the op-count
    /// bound — never one oversized change that no peer could decode
    /// (`change::MAX_OPS`) and no wire message could carry.
    #[test]
    fn bulk_offline_reconcile_chunks_by_op_count_into_a_chain() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

        let n = RECONCILE_CHUNK_OP_LIMIT + 3;
        for i in 0..n {
            std::fs::write(root.join(format!("f{i}")), b"a").unwrap();
        }
        // Seed history from the initial index, then take it offline.
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        yadorilink_daemon::dag_import::ensure_initial_import(
            state.coordinator(),
            group,
            proc.change_emitter.as_ref().unwrap(),
        )
        .unwrap();
        let heads_before = state.sqlite().dag_group_heads(group).unwrap();
        assert_eq!(heads_before.len(), 1, "sanity: import converged on one head");

        // Offline-modify every file (different size => re-versioned by the scan).
        for i in 0..n {
            std::fs::write(root.join(format!("f{i}")), b"abc").unwrap();
        }
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

        let heads_after = state.sqlite().dag_group_heads(group).unwrap();
        assert_eq!(heads_after.len(), 1, "the chunk chain must converge on a single head");
        let chain = linear_chain_back_to(&state, heads_after[0], &heads_before[0]);
        assert!(
            chain.len() >= 2,
            "{n} changed paths must split into >= 2 chained changes, got {}",
            chain.len()
        );
        let mut total_ops = 0usize;
        for change in &chain {
            assert!(
                change.ops.len() <= RECONCILE_CHUNK_OP_LIMIT,
                "every chunk must stay within the op-count bound"
            );
            let bytes: usize = change.ops.iter().map(encoded_op_len).sum();
            assert!(
                bytes <= RECONCILE_CHUNK_BYTE_LIMIT,
                "every chunk must stay within the byte bound"
            );
            total_ops += change.ops.len();
        }
        assert_eq!(total_ops, n, "the chain's ops must cover every changed path exactly once");
    }

    /// C4 15k live-burst investigation (2026-09-01): before this fix,
    /// `process_flush_with_ignore`'s `RescanRequired` arm withheld every
    /// peer announcement until the WHOLE scan's `Vec<FileRecord>` was
    /// returned, even though `reconcile_disk_with_ignore`'s own chunk loop
    /// (proven by `bulk_offline_reconcile_chunks_by_op_count_into_a_chain`
    /// above) already commits each chunk durably to the DAG as it goes --
    /// a real 15,000-file scan measured this as ~75 seconds of zero
    /// peer-visible progress despite the source device's own index/DAG
    /// visibly advancing the entire time. Proves the streaming sibling
    /// surfaces each durably-committed chunk via `on_chunk_committed`
    /// DURING the scan (multiple callback invocations, each with a proper
    /// subset of the total), not only once at the very end. Confirmed
    /// genuinely RED by temporarily removing the `cb(chunk_records)` call
    /// in `reconcile_disk_with_ignore`'s chunk loop: `sizes.len()` becomes
    /// `0` even though the scan still completes and returns the same
    /// records.
    #[test]
    fn streaming_reconciliation_surfaces_each_durable_chunk_before_the_whole_scan_returns() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

        let n = RECONCILE_CHUNK_OP_LIMIT + 3;
        for i in 0..n {
            std::fs::write(root.join(format!("f{i}")), b"a").unwrap();
        }
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        yadorilink_daemon::dag_import::ensure_initial_import(
            state.coordinator(),
            group,
            proc.change_emitter.as_ref().unwrap(),
        )
        .unwrap();

        // Offline-modify every file so the second scan's diff is non-empty
        // and routes through the chunked change-emission path (the same
        // setup `bulk_offline_reconcile_chunks_by_op_count_into_a_chain`
        // uses, just observed through the streaming API instead).
        for i in 0..n {
            std::fs::write(root.join(format!("f{i}")), b"abc").unwrap();
        }

        let observed_chunk_sizes = std::cell::RefCell::new(Vec::<usize>::new());
        let mut on_chunk = |records: &[FileRecord]| {
            observed_chunk_sizes.borrow_mut().push(records.len());
        };
        let records = proc
            .scan_existing_files_with_ignore_streaming(group, &root, &ignore_set, &mut on_chunk)
            .unwrap();

        let sizes = observed_chunk_sizes.into_inner();
        assert!(
            sizes.len() >= 2,
            "{n} changed paths must stream as >= 2 chunk callbacks, got {}",
            sizes.len()
        );
        assert_eq!(
            sizes.iter().sum::<usize>(),
            n,
            "streamed chunk sizes must cover every changed path exactly once, with no overlap \
             or gap"
        );
        assert_eq!(
            records.len(),
            n,
            "the final aggregate return value must stay byte-identical to the non-streaming path"
        );
    }

    /// Byte cap: a diff of FEWER than the op-count
    /// limit but with long paths that exceed `RECONCILE_CHUNK_BYTE_LIMIT` must
    /// still split into multiple chained changes — proving the split is driven
    /// by encoded size, not op count alone (op count alone would leave a single
    /// multi-hundred-KiB change no wire message could deliver).
    #[test]
    fn bulk_offline_reconcile_chunks_by_encoded_bytes_into_a_chain() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

        std::fs::create_dir(root.join("d")).unwrap();
        // ~289 bytes/op * 1000 ops ~= 282 KiB > 256 KiB, yet 1000 < 1024 ops,
        // so only the byte cap can split this.
        let n = 1000usize;
        assert!(n < RECONCILE_CHUNK_OP_LIMIT, "this test must stay under the op-count cap");
        let name = |i: usize| format!("d/{:0>250}", i);
        for i in 0..n {
            std::fs::write(root.join(name(i)), b"a").unwrap();
        }
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        yadorilink_daemon::dag_import::ensure_initial_import(
            state.coordinator(),
            group,
            proc.change_emitter.as_ref().unwrap(),
        )
        .unwrap();
        let heads_before = state.sqlite().dag_group_heads(group).unwrap();

        for i in 0..n {
            std::fs::write(root.join(name(i)), b"abc").unwrap();
        }
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

        let heads_after = state.sqlite().dag_group_heads(group).unwrap();
        let chain = linear_chain_back_to(&state, heads_after[0], &heads_before[0]);
        assert!(
            chain.len() >= 2,
            "a >256 KiB diff of {n} (< op-count-cap) paths must split by bytes into >= 2 changes, \
             got {}",
            chain.len()
        );
        let mut total_ops = 0usize;
        for change in &chain {
            let bytes: usize = change.ops.iter().map(encoded_op_len).sum();
            assert!(
                bytes <= RECONCILE_CHUNK_BYTE_LIMIT,
                "every chunk must stay within the byte bound, got {bytes}"
            );
            assert!(change.ops.len() <= RECONCILE_CHUNK_OP_LIMIT);
            total_ops += change.ops.len();
        }
        assert_eq!(total_ops, n, "the chain's ops must cover every changed path exactly once");
    }

    /// The startup/offline full-reconcile scan must decide "already current"
    /// on the same basis as the per-file path (`build_record_for_created_or_
    /// modified`): size *and* mtime, not size alone. An offline edit that
    /// preserves the byte length but changes the file's bytes (and its
    /// mtime) — a flag flip, a same-length hash/uuid swap, an in-place binary
    /// or DB edit — must be detected and re-indexed on restart, not skipped.
    /// A size-only gate leaves the index pinned to the stale version while
    /// disk holds new bytes: silent divergence that only heals if a peer
    /// happens to re-advertise the path, with a silent-data-loss tail if a
    /// later remote edit overwrites the un-indexed local edit.
    #[test]
    fn startup_scan_detects_same_size_edit_with_changed_mtime() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("edge-case.bin");

        std::fs::write(&file_path, vec![b'A'; 20]).unwrap();
        let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(first_scan.len(), 1, "sanity: the initial scan indexes the file");
        let indexed_v1 =
            state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();

        // Same length (20 bytes), different bytes, and a distinctly newer
        // mtime — forced explicitly so the test never depends on filesystem
        // timestamp granularity happening to advance between the two writes.
        std::fs::write(&file_path, vec![b'B'; 20]).unwrap();
        let new_mtime = std::time::UNIX_EPOCH
            + std::time::Duration::from_nanos(indexed_v1.mtime_unix_nanos as u64)
            + std::time::Duration::from_secs(2);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap()
            .set_modified(new_mtime)
            .unwrap();

        let rescan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(
            rescan.iter().any(|r| r.path == "edge-case.bin" && !r.deleted),
            "a same-size offline edit whose mtime changed must be detected by the restart scan, \
             not short-circuited as already-current: {rescan:?}"
        );

        let indexed_v2 =
            state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();
        assert_ne!(
            indexed_v2.blocks, indexed_v1.blocks,
            "the re-index must capture the new on-disk content, not keep the stale blocks"
        );
        assert_eq!(
            state.sqlite().dag_list_versions("group-1", "edge-case.bin").unwrap().len(),
            2,
            "the detected offline edit must advance the file's version"
        );
    }

    /// DI-3 tail closed on the startup/offline full-reconcile path too: an
    /// offline edit that preserves BOTH the byte length AND the mtime
    /// (`touch -r`, an archive extraction that restores timestamps, an
    /// in-place same-length overwrite) must still be detected on restart.
    /// The `already_current` stat gate now verifies the on-disk bytes
    /// against the indexed block hashes before short-circuiting, so a
    /// same-size same-mtime content change is re-indexed rather than left
    /// pinned at the stale version — the same content-verified identity
    /// test the per-file/watcher path applies.
    #[test]
    fn startup_scan_detects_same_size_and_mtime_edit() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("edge-case.bin");

        std::fs::write(&file_path, vec![b'A'; 20]).unwrap();
        let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(first_scan.len(), 1, "sanity: the initial scan indexes the file");
        let indexed_v1 =
            state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();

        // Same length (20 bytes), different bytes, and mtime forced back to
        // exactly the indexed instant — size AND mtime both match, so only
        // a content comparison can distinguish this from an unchanged file.
        std::fs::write(&file_path, vec![b'B'; 20]).unwrap();
        let original_mtime = std::time::UNIX_EPOCH
            + std::time::Duration::from_nanos(indexed_v1.mtime_unix_nanos as u64);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap()
            .set_modified(original_mtime)
            .unwrap();

        let rescan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(
            rescan.iter().any(|r| r.path == "edge-case.bin" && !r.deleted),
            "a same-size, same-mtime offline edit must be detected by the restart scan, \
             not short-circuited as already-current: {rescan:?}"
        );

        let indexed_v2 =
            state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();
        assert_ne!(
            indexed_v2.blocks, indexed_v1.blocks,
            "the re-index must capture the new on-disk content, not keep the stale blocks"
        );
        assert_eq!(
            state.sqlite().dag_list_versions("group-1", "edge-case.bin").unwrap().len(),
            2,
            "the detected offline edit must advance the file's version"
        );
    }

    /// Teeth for the content-verifying fast-path: a genuinely unchanged
    /// file (same bytes, same size, same mtime) must NOT be re-emitted as a
    /// change on a repeat scan. The content check must confirm the no-op,
    /// never manufacture spurious churn that would bump the version vector
    /// and re-broadcast an identical file on every restart.
    #[test]
    fn startup_scan_leaves_unchanged_file_untouched() {
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("steady.bin");
        std::fs::write(&file_path, vec![b'Z'; 4096]).unwrap();

        let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(first_scan.len(), 1, "sanity: the initial scan indexes the file");
        let indexed_v1 =
            state.file_index_repository().get_file("group-1", "steady.bin").unwrap().unwrap();

        // No change at all — the file's bytes, size, and mtime are exactly
        // as indexed, so a second scan must treat it as a no-op.
        let rescan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(
            rescan.iter().all(|r| r.path != "steady.bin"),
            "an unchanged file must not be re-emitted by a repeat scan: {rescan:?}"
        );
        let indexed_v2 =
            state.file_index_repository().get_file("group-1", "steady.bin").unwrap().unwrap();
        assert_eq!(
            state.sqlite().dag_list_versions("group-1", "steady.bin").unwrap().len(),
            1,
            "an unchanged file's version must not advance across scans"
        );
        assert_eq!(indexed_v2.blocks, indexed_v1.blocks, "unchanged blocks stay identical");
    }

    /// A single un-walkable subtree must not disable offline-delete
    /// tombstoning for the *entire* scan. Tombstone suppression is
    /// fail-safe (never tombstone a path whose directory we could not read),
    /// but that suppression must be scoped to the failed subtree: a
    /// confirmed deletion under a cleanly-walked subtree must still be
    /// tombstoned even when an unrelated subtree errored, otherwise a
    /// persistently-erroring directory defers a real deletion indefinitely
    /// and a peer that evicted the file can re-hydrate it.
    #[test]
    #[cfg(unix)]
    fn tombstone_suppression_is_scoped_to_the_failed_subtree() {
        use std::os::unix::fs::PermissionsExt;
        let (proc, state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

        std::fs::create_dir(root.join("clean")).unwrap();
        std::fs::create_dir(root.join("broken")).unwrap();
        std::fs::write(root.join("clean/keep.txt"), b"in the clean subtree").unwrap();
        std::fs::write(root.join("broken/other.txt"), b"in the broken subtree").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();

        // Offline delete of a file under the CLEAN subtree.
        std::fs::remove_file(root.join("clean/keep.txt")).unwrap();

        // Make the OTHER subtree un-walkable so the scan hits a walk error
        // there — and only there.
        std::fs::set_permissions(root.join("broken"), std::fs::Permissions::from_mode(0o000))
            .unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();

        // Restore permissions immediately so TempDir cleanup can remove it.
        std::fs::set_permissions(root.join("broken"), std::fs::Permissions::from_mode(0o755))
            .unwrap();

        assert!(
            records.iter().any(|r| r.path == "clean/keep.txt" && r.deleted),
            "a confirmed deletion under a cleanly-walked subtree must still be tombstoned even \
             when an unrelated subtree failed to walk: {records:?}"
        );
        let clean_indexed =
            state.file_index_repository().get_file("group-1", "clean/keep.txt").unwrap().unwrap();
        assert!(clean_indexed.deleted, "the clean-subtree tombstone must be persisted");

        // Fail-safe: the file under the un-walkable subtree must NOT be
        // tombstoned — its absence could not be confirmed this pass.
        let broken_indexed =
            state.file_index_repository().get_file("group-1", "broken/other.txt").unwrap().unwrap();
        assert!(
            !broken_indexed.deleted,
            "a path under the failed subtree must never be tombstoned — absence unconfirmed"
        );
    }

    // --- One live link per group: the dominant harm --------------------------

    /// THE ANCHOR TEST. The index is group-scoped and path-relative while this
    /// scan is root-scoped and authoritative, so with two live roots on one
    /// group, root A's scan finds root B's indexed paths absent from its own
    /// `seen_paths` and tombstones them -- signed changes that ride the
    /// change-DAG to EVERY device. That is silent, group-wide, cross-device loss
    /// of the user's own data.
    ///
    /// Asserts on the emitted RECORDS, not merely that the call is `Err`: an
    /// `Err` returned AFTER the tombstones were pushed is still group-wide loss.
    /// The scan must not reach the tombstone loop at all.
    ///
    /// BOTH ROOTS ARE MARKED WITH THE SAME TOKEN, AND THAT IS THE POINT. An
    /// earlier version of this test left root B unmarked, which made it a FALSE
    /// ANCHOR: an unmarked B sends `VerifiedRoot::open` down the adoption path,
    /// whose token write trips `set_link_root_token_for_group`'s fan-out assert
    /// -- so the refusal came from the WRITER, and disabling the entire
    /// read-side gate left this test PASSING. It named the gate and tested
    /// something else. (Measured: with `ensure_unambiguous_group_on_conn`'s
    /// `paths.len() > 1` forced to `false`, `1 passed; 0 failed`.)
    ///
    /// Two rows carrying ONE token is also the realistic already-duplicated
    /// state rather than a contrivance: it is exactly what the pre-fix
    /// by-`group_id` token writer manufactured, stamping both rows on any
    /// database that already had two links. In it, `open` finds a marker whose
    /// token matches what is persisted and returns `Ok` WITHOUT WRITING -- so no
    /// writer assert can fire, and the read-side gate is the only thing standing
    /// between the user and the tombstones. Measured with the gate disabled:
    /// `SCAN SUCCEEDED, tombstoned = ["only-in-a.txt"]`.
    #[test]
    fn a_full_scan_of_an_ambiguous_group_emits_zero_tombstones() {
        let (processor, state, _store_dir, root_a) = processor();
        let root_b = tempfile::tempdir().unwrap();
        let group = "group-1";

        state.link_repository().add_link(&root_a.path().to_string_lossy(), group).unwrap();

        // Two files live under root A and are indexed for the group.
        std::fs::write(root_a.path().join("shared.txt"), b"hello").unwrap();
        std::fs::write(root_a.path().join("only-in-a.txt"), b"world").unwrap();
        let scanned = processor.scan_existing_files(group, root_a.path()).unwrap();
        assert_eq!(scanned.len(), 2, "the healthy scan must index both files");
        assert!(scanned.iter().all(|r| !r.deleted));

        // Root B holds ONE of the group's files -- the realistic shape, since a
        // second root gets populated by hydration from a peer or by the user
        // copying some of the folder in.
        std::fs::write(root_b.path().join("shared.txt"), b"hello").unwrap();

        // Both roots marked with the group's ONE persisted token: the
        // already-duplicated database. Every identity check now PASSES for
        // either root -- which is precisely why sharing a token is the damage
        // and not the safety. Nothing after this writes a token, so the writer's
        // fan-out assert is out of the picture and only the gate is left.
        //
        // Read while the group is still healthy: once it is ambiguous this
        // resolver refuses, exactly as it should.
        let token = state
            .link_repository()
            .link_root_token_for_group(group)
            .unwrap()
            .expect("root A's scan above must have adopted it");
        yadorilink_root_authority::root_identity::write_root_marker_for_test(
            root_b.path(),
            group,
            &token,
        );

        // Now the user is in the two-live-roots state -- reachable today, and
        // the state this fix must make safe rather than merely prevent.
        state
            .link_repository()
            .force_second_live_link_for_test(&root_b.path().to_string_lossy(), group)
            .unwrap();

        // B's ROW carries the same token too. Without this, B's row token is
        // NULL and the token resolver -- a first-row-wins `ORDER BY local_path`
        // -- returns `None` whenever B happens to sort first, sending `open`
        // down its backfill WRITE and back into the writer's fan-out assert.
        // That would make this test's verdict depend on tempdir naming: the gate
        // on one run, the writer on the next. Both rows, one token, is also the
        // honest shape of the state the pre-fix writer produced.
        state
            .link_repository()
            .set_link_root_token_for_path_for_test(&root_b.path().to_string_lossy(), &token)
            .unwrap();

        // Scan root B, NOT root A. This direction is the whole bug: B's scan is
        // root-scoped and authoritative, but the index it reconciles against is
        // group-scoped, so A's `only-in-a.txt` is "indexed for this group but
        // absent from the root I just walked" -> tombstone -> signed change ->
        // every device. Scanning A instead would be vacuous: A's own file is
        // present under A, so that scan emits no tombstone whether or not the
        // fix exists.
        let result = processor.scan_existing_files(group, root_b.path());

        let err = match result {
            Err(e) => e,
            Ok(records) => {
                let tombstoned: Vec<_> =
                    records.iter().filter(|r| r.deleted).map(|r| r.path.clone()).collect();
                panic!(
                    "a scan of an ambiguous group must refuse, not pick a root. SCAN SUCCEEDED, \
                     tombstoned = {tombstoned:?} -- each of those is a signed deletion bound for \
                     every device"
                );
            }
        };
        assert!(
            matches!(err, LocalCaptureError::SyncCore(SyncSqliteError::AmbiguousLink { .. })),
            "got {err:?}"
        );

        // And the index is untouched: nothing was tombstoned on the way out.
        let indexed = state.file_index_repository().list_files(group).unwrap();
        assert!(
            indexed.iter().all(|r| !r.deleted),
            "no indexed file may be tombstoned by a scan of an ambiguous group, got {indexed:?}"
        );
    }

    /// The original anchor's state, kept as its own case now that the anchor
    /// above has moved to the token-sharing one: an UNMARKED second root, where
    /// the refusal comes from the token writer's fan-out assert on the adoption
    /// path rather than from the read-side gate. Defence in depth, and labelled
    /// as such -- it is not evidence about the gate.
    #[test]
    fn a_full_scan_of_an_ambiguous_group_with_an_unadopted_second_root_emits_zero_tombstones() {
        let (processor, state, _store_dir, root_a) = processor();
        let root_b = tempfile::tempdir().unwrap();
        let group = "group-1";

        state.link_repository().add_link(&root_a.path().to_string_lossy(), group).unwrap();
        std::fs::write(root_a.path().join("shared.txt"), b"hello").unwrap();
        std::fs::write(root_a.path().join("only-in-a.txt"), b"world").unwrap();
        processor.scan_existing_files(group, root_a.path()).unwrap();

        // One of the group's files is present under B, so B is "corroborated"
        // and the marker check would ADOPT it: `IndexedFilesAllMissing` only
        // fires when NOT ONE indexed file is present.
        std::fs::write(root_b.path().join("shared.txt"), b"hello").unwrap();
        state
            .link_repository()
            .force_second_live_link_for_test(&root_b.path().to_string_lossy(), group)
            .unwrap();

        let err = processor
            .scan_existing_files(group, root_b.path())
            .expect_err("a scan of an ambiguous group must refuse, not pick a root");
        assert!(
            matches!(err, LocalCaptureError::SyncCore(SyncSqliteError::AmbiguousLink { .. })),
            "got {err:?}"
        );

        let indexed = state.file_index_repository().list_files(group).unwrap();
        assert!(
            indexed.iter().all(|r| !r.deleted),
            "no indexed file may be tombstoned by a scan of an ambiguous group, got {indexed:?}"
        );
    }

    /// The fix's own remedy must not destroy data. `DELETE FROM files` is only
    /// ever keyed by path, so unlinking B leaves B's rows in the GROUP's index;
    /// A's next scan is root-scoped and authoritative and would read every one
    /// of them as deleted and tombstone them to every device. Obeying the error
    /// message ("unlink the other one") would then delete the files the message
    /// told the user to save.
    ///
    /// Measured before this flag existed: the survivor's scan emitted
    /// `["only-in-b.txt"]`.
    #[test]
    fn the_survivors_first_post_recovery_scan_emits_no_tombstones() {
        let (processor, state, _store_dir, root_a) = processor();
        let root_b = tempfile::tempdir().unwrap();
        let group = "group-1";

        state.link_repository().add_link(&root_a.path().to_string_lossy(), group).unwrap();
        std::fs::write(root_a.path().join("in-a.txt"), b"aaa").unwrap();
        processor.scan_existing_files(group, root_a.path()).unwrap();

        // A path that only ever existed under B, indexed for the group -- the
        // shape a second root produces by hydrating from a peer.
        state
            .link_repository()
            .force_second_live_link_for_test(&root_b.path().to_string_lossy(), group)
            .unwrap();
        state
            .file_index_repository()
            .upsert_file(
                group,
                &FileRecord {
                    path: "only-in-b.txt".into(),
                    size: 3,
                    mtime_unix_nanos: 1,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // Recovery, exactly as `SyncSqliteError::AmbiguousLink` instructs, plus the
        // additive-scan flag the daemon's unlink handler arms on the survivor.
        state.link_repository().remove_link(&root_b.path().to_string_lossy()).unwrap();
        state
            .link_repository()
            .set_suppress_tombstones(&root_a.path().to_string_lossy(), true)
            .unwrap();

        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root_a.path()).unwrap();
        let emit_tombstones =
            !state.link_repository().suppress_tombstones_for_group(group).unwrap();
        let out = processor
            .scan_existing_files_with_ignore_gated(
                group,
                root_a.path(),
                &ignore_set,
                emit_tombstones,
            )
            .unwrap();

        let tombstoned: Vec<_> = out.iter().filter(|r| r.deleted).map(|r| r.path.clone()).collect();
        assert!(
            tombstoned.is_empty(),
            "the survivor's first scan after recovery must delete nothing -- these paths can \
             still hydrate from a peer that holds them, got {tombstoned:?}"
        );
        let still_live =
            state.file_index_repository().get_file(group, "only-in-b.txt").unwrap().unwrap();
        assert!(!still_live.deleted, "the departed root's file must not be tombstoned");
    }

    /// A canonical wire path must have one separator spelling on every
    /// platform. A literal Unix backslash therefore cannot be represented:
    /// preserving it would make `a\b.txt` and `a/b.txt` distinct DAG paths
    /// that address the same file when received on Windows.
    #[cfg(unix)]
    #[test]
    fn wire_relative_string_refuses_a_literal_backslash_on_unix() {
        let root = tempfile::tempdir().unwrap();
        let literal_backslash_path = root.path().join("a\\b.txt");
        assert_eq!(
            path_to_wire_relative_string(literal_backslash_path.strip_prefix(root.path()).unwrap()),
            None,
        );

        let nested_path = root.path().join("a").join("b.txt");
        assert_eq!(
            path_to_wire_relative_string(nested_path.strip_prefix(root.path()).unwrap()).as_deref(),
            Some("a/b.txt"),
        );
    }

    /// The second collision hazard an independent review found:
    /// `to_string_lossy()` silently substitutes `�` for invalid UTF-8,
    /// which can fold two DIFFERENT non-UTF-8 names onto the identical
    /// wire path string. `path_to_wire_relative_string` must refuse
    /// (`None`) rather than silently substitute.
    #[cfg(unix)]
    #[test]
    fn wire_relative_string_refuses_non_utf8_names_instead_of_silently_substituting() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        // Two DIFFERENT invalid-UTF-8 byte sequences that `to_string_
        // lossy()` would both render as the single-character placeholder
        // "�", making them indistinguishable as wire path strings.
        let name_a = OsStr::from_bytes(b"caf\xE9.txt"); // Latin-1 "café.txt"
        let name_b = OsStr::from_bytes(b"caf\xE8.txt"); // Latin-1 "cafè.txt" (different byte)

        assert_eq!(
            path_to_wire_relative_string(Path::new(name_a)),
            None,
            "a non-UTF-8 name must be refused, not silently substituted"
        );
        assert_eq!(path_to_wire_relative_string(Path::new(name_b)), None);
    }

    /// Integration-level proof through the actual scan path: a real
    /// on-disk file whose name is not valid UTF-8 must be skipped by
    /// `scan_existing_files`, not silently indexed under a lossy,
    /// potentially-colliding substitute name.
    #[cfg(unix)]
    #[test]
    fn scan_existing_files_skips_a_non_utf8_named_file_rather_than_indexing_it_lossily() {
        use std::os::unix::ffi::OsStrExt;

        let (proc, _state, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let non_utf8_name = std::ffi::OsStr::from_bytes(b"caf\xE9.txt");
        // Some filesystems (notably macOS's APFS) enforce valid UTF-8 at
        // the filesystem level and refuse to create a non-UTF-8-named
        // entry outright -- skip on a host where that's the case, rather
        // than asserting a scenario this filesystem cannot even produce.
        // The pure `wire_relative_string_refuses_non_utf8_names_instead_
        // of_silently_substituting` test above still exercises the actual
        // fix on every platform regardless.
        if std::fs::write(root.join(non_utf8_name), b"content").is_err() {
            eprintln!("skipping: this filesystem refuses to create a non-UTF-8-named file");
            return;
        }
        std::fs::write(root.join("ordinary.txt"), b"ordinary content").unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();

        assert_eq!(
            paths,
            vec!["ordinary.txt"],
            "the non-UTF-8-named file must be skipped, never indexed under a lossily \
             substituted (and potentially colliding) name"
        );
    }
}
