//! Filesystem race observation for local capture: the stat fingerprint
//! that brackets a read, the closed `DiskObservation` a commit may derive
//! actual-state evidence from, the untouched-placeholder verdict, and the
//! off-worker re-verification of on-disk bytes against indexed blocks.

use std::path::Path;

use yadorilink_local_storage::CDC_SIZE_THRESHOLD;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_root_authority::fs_identity::{
    disk_race_fingerprint, DiskRaceFingerprint, FileIdentity,
};

/// One path's closed disk observation: what the scan saw at the moment its
/// observation bracket closed, carried forward as the single thing a later
/// commit may derive an actual-state proof from.
///
/// Deliberately NOT a `FileIdentity` the commit could publish directly.
/// An identity answers "is this the same object", and there is a real
/// shape of change it cannot see: an in-place overwrite keeps the inode,
/// the length and (if the writer restores it) the mtime, so every field
/// `FileIdentity::compare` consults still agrees while the bytes the proof
/// vouches for are gone. A bracket only speaks for the window it spans,
/// and the commit carrying a prepared mutation happens later -- unlocked,
/// with other paths' work in between -- so an observation that was sound
/// when it closed is not evidence about the moment of the commit.
///
/// The token that closes that gap is already inside the observation:
/// `FileIdentity::metadata_fingerprint` digests the tracked metadata
/// subset, which on Unix includes ctime. Every write to a file moves
/// ctime, and no userspace API can put it back -- unlike mtime, which
/// `utimensat` restores freely. So an observation still describing the
/// CURRENT disk state is exactly one whose re-observation is identical
/// field for field, fingerprint included.
///
/// [`Self::into_evidence_if_still_current`] is the only way to get
/// evidence out of this type, so a commit cannot publish a proof from an
/// observation it never re-verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DiskObservation {
    pub(super) identity: FileIdentity,
}

impl DiskObservation {
    /// Turns this observation into publishable actual-state evidence, but
    /// ONLY if re-observing `path` right now yields the identical
    /// observation -- same object by every field, and the same metadata
    /// token (see the type's own doc for why the token, not just the
    /// object identity, is what makes this a statement about content).
    ///
    /// Full structural equality rather than `FileIdentity::compare`, on
    /// purpose. `compare` answers a deliberately weaker question ("same
    /// object, possibly mutated") and is three-valued, needing a volume's
    /// birth-time granularity to resolve; two observations taken moments
    /// apart on one device need neither. Anything that differs at all --
    /// including a field this crate has no opinion about -- means the
    /// observation no longer describes disk, and the fail-closed answer
    /// is no proof.
    pub(super) fn into_evidence_if_still_current(
        self,
        path: &Path,
    ) -> Option<yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence> {
        self.identity_if_still_current(path).map(|filesystem_identity| {
            yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence::Present {
                filesystem_identity,
            }
        })
    }

    /// The same gate, for a caller that publishes its proof directly
    /// rather than through `LocalCaptureActualStateEvidence` -- the
    /// no-emitter scan, which has no change to attach evidence to and
    /// hands the commit an `ImportedActualState` instead.
    ///
    /// Returns the identity THIS observation closed over, never the
    /// re-observation: the two are equal or there is no answer, and
    /// returning the original keeps it the same value the version beside
    /// it was derived from.
    pub(super) fn identity_if_still_current(self, path: &Path) -> Option<FileIdentity> {
        let observed = FileIdentity::observe_path(path).ok()?;
        (observed == self.identity).then_some(self.identity)
    }
}

/// The closed disk observation for `path`, but ONLY if
/// `disk_race_fingerprint(path)` still matches `fingerprint_before_read`
/// (a fingerprint captured before this path's own content was read) --
/// `None` for either a fingerprint mismatch (something touched this path
/// during the read/prepare window) or a failed observation. `None` here
/// always means "publish no actual-state proof for this commit," never a
/// hard failure of the capture itself.
///
/// The identity is observed INSIDE the bracket and the fingerprint
/// re-check closes it afterwards, not the other way around: a check
/// followed by an observation leaves the observation itself outside the
/// window the check vouches for, which is precisely the kind of
/// unbracketed look this whole mechanism exists to refuse. Same syscall
/// count either way.
pub(super) fn closed_disk_observation_if_unraced(
    path: &Path,
    fingerprint_before_read: Option<DiskRaceFingerprint>,
) -> Option<DiskObservation> {
    fingerprint_before_read?;
    let identity = FileIdentity::observe_path(path).ok()?;
    if disk_race_fingerprint(path) != fingerprint_before_read {
        return None;
    }
    Some(DiskObservation { identity })
}

/// Whether the on-disk object `lstat` describes is still proven to be this
/// crate's own untouched placeholder, for the `MaterializationState::
/// Placeholder` fast path in `build_record_for_created_or_modified`. On
/// Unix, this requires BOTH: a `(dev, ino)` identity match against
/// `placeholder_generation`, AND the object still being sparse (no
/// allocated data blocks) -- see that call site's own doc comment for why
/// this is used instead of a size/mtime/sparse-file heuristic there.
///
/// Identity alone is not sufficient: a
/// genuine in-place edit (a `truncate`+`write` that reuses the same file
/// descriptor/inode rather than an atomic rename, or an `mmap` write) keeps
/// the SAME inode while genuinely changing the file's bytes. The OLD
/// heuristic caught this case (real content allocates disk blocks, so the
/// sparse-file check alone already said "not untouched") even though it
/// missed the atomic-rename-preserving-size/mtime case this file's own
/// identity check exists to close. Requiring both keeps the union of what
/// each signal alone catches: identity closes the atomic-rename gap,
/// sparseness closes the in-place-edit gap.
///
/// Also the check an on-demand hydration asks before it starts: an attempt
/// may only replace the file if it is still this placeholder, so that local
/// capture and hydration agree on what counts as an uncaptured edit.
#[cfg(unix)]
pub fn untouched_placeholder_verdict(
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
    // Defense in depth for the startup repair pass (`materialization_repair::
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

/// On Windows, this is the ONLY signal permitted to produce
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
///   (a legacy non-CfAPI row, or one this build's `record_placeholder_generation`
///   call site hasn't reached yet) -- there is nothing to compare against,
///   so this cannot possibly be proven untouched.
/// - `inspect_windows_placeholder` returns anything other than
///   [`yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus::Untouched`]
///   -- `Dirty` is an honest "this was locally written since creation",
///   and `Unknown` (the path isn't a real placeholder, the identity
///   doesn't decode, the API call itself failed) is deliberately treated
///   exactly like `Dirty`, never like a confirmed match.
#[cfg(windows)]
pub fn untouched_placeholder_verdict(
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
pub(super) fn exact_leaf_exists_as_file_or_symlink(root: &Path, path: &str) -> bool {
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

/// Whether a real directory (lstat, never followed) answers to `path`'s
/// exact leaf name. The directory counterpart of
/// [`exact_leaf_exists_as_file_or_symlink`], for an explicit Directory row:
/// the walk never admits a directory, so the directory itself is the only
/// evidence that such a row is still present.
pub(super) fn exact_leaf_exists_as_directory(root: &Path, path: &str) -> bool {
    let full = root.join(path);
    let (Some(leaf), Some(parent)) =
        (full.file_name().map(|n| n.to_os_string()), full.parent().map(|p| p.to_path_buf()))
    else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(&parent) else { return false };
    entries
        .filter_map(|e| e.ok())
        .any(|entry| entry.file_name() == leaf && entry.file_type().is_ok_and(|ft| ft.is_dir()))
}

/// Runs one of this module's long synchronous capture passes — a
/// whole-file chunk-and-hash, or a whole-file re-verify against the
/// indexed block hashes — without leaving it holding the tokio worker core
/// it was called on. The bound this establishes is on the CORE, not on
/// `f`. On a multi-threaded runtime `block_in_place` moves this worker's
/// core, and every task already queued on it, to a replacement thread
/// *before* `f` starts; the calling thread becomes an ordinary blocking
/// thread for the duration. So no worker core is held for longer than that
/// one handoff, however long `f` itself runs — which matters because these
/// passes are not measured in milliseconds. Chunking, hashing and durably
/// committing a 1 GiB file measures 13-20s; re-verifying one against its
/// indexed hashes is a full sequential read plus a SHA-256 per block. A
/// held core, meanwhile, can't service anything else queued on it --
/// including this device's own QUIC endpoint driver, which has to run
/// promptly enough to send ACKs and keepalives before quinn's own
/// loss-detection and peer idle timeout react to the silence -- and it is
/// time-to-schedule, not poll turnaround, that decides whether they go out
/// in time. `spawn_blocking` wants a `Send + 'static` closure and an
/// `.await` to join it, and there is no `.await` to be had here without
/// turning that whole public API async. A scoped closure needs neither.
/// The runtime guard mirrors `peer_session::record_materialized_
/// fingerprint_off_runtime`, `daemon_state::run_blocking_sweep_offloaded`
/// and `gc::run_sweep_with_grace_cutoff`, and it is load-bearing rather
/// than defensive: `block_in_place` PANICS unless a multi-threaded runtime
/// is current, and these call sites are genuinely reached from a
/// current-thread runtime and from no runtime at all. Where there is no
/// multi-threaded worker to hand off to there is also no worker pool to
/// starve, so the plain synchronous call is already the right answer
/// there, not a degraded one. Nesting costs nothing and needs no guarding
/// of its own: tokio only hands off a core this thread actually holds, so
/// reaching here from a thread that has none — a `spawn_blocking` thread
/// (how the daemon runs the whole initial scan), or a thread whose core an
/// outer offload already took (the daemon's flush task wraps all of
/// `process_flush_with_ignore` in its own `block_in_place`) — simply runs
/// `f` in place.
pub(super) fn run_capture_pass_off_worker<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
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
pub(super) const OFF_WORKER_VERIFY_MIN_BYTES: u64 = CDC_SIZE_THRESHOLD;

/// [`yadorilink_local_storage::disk_bytes_match_indexed_blocks`], off the
/// calling tokio worker's core when `size` says the pass is big enough to
/// be worth the handoff — see [`run_capture_pass_off_worker`] for the bound
/// that buys and [`OFF_WORKER_VERIFY_MIN_BYTES`] for the cutoff.
///
/// Identical verdict either way: this only decides which thread the
/// (unchanged) read-and-compare runs on, never what it concludes.
pub(super) fn disk_bytes_match_indexed_blocks_off_worker(
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
