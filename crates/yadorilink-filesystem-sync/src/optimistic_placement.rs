//! Preparation and staging for optimistic filesystem placement — the real
//! I/O half of `yadorilink-sync-core`'s `optimistic_placement` module (7D-9D
//! eighth pass). See that module's own doc for the full design context
//! (§6.1's short-commit-window saga, §18's performance-counter accounting);
//! this module owns exactly the part that never touches SQL: assembling a
//! stage artefact via the strongest verified fast path
//! [`yadorilink_replica_engine::optimistic_placement::select_fast_path`]
//! chose (clone/reflink/hardlink/plain copy), verifying its content,
//! applying tracked metadata, and durably flushing it. Deciding *which* fast
//! path to use is not this module's job either — that decision is pure and
//! lives in `yadorilink-replica-engine::optimistic_placement` (moved there
//! by an earlier pass); this module only executes whichever one was chosen.
//!
//! What stays in `yadorilink-sync-core::optimistic_placement`: the short
//! commit window (`execute_short_commit_window_core`), which claims the
//! epoch, performs the one platform placement (via
//! [`crate::fs_commit::FilesystemCommitAdapter`]) and publishes the result
//! in one SQLite transaction — genuinely SQL-interleaved, unlike everything
//! here.

#[cfg(any(target_os = "macos", windows))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::fs_commit::{CreateArtefactError, ParentDirHandle};
use yadorilink_replica_engine::optimistic_placement::{
    select_fast_path, CloneSource, FastPath, FastPathDecision, FastPathRejection, PlacementInputs,
};
use yadorilink_root_authority::fs_identity::FileIdentity;
use yadorilink_root_authority::reserved_namespace::{self, ArtefactKind, ArtefactNameError};

// =====================================================================
// Per-epoch performance counters (§18.2)
// =====================================================================

/// Per-epoch counters accumulated across both preparation and the commit
/// window. A caller sums a preparation call's counters with a commit
/// window's via [`PreparationCounters::merge`] to get the epoch total.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PreparationCounters {
    pub preparation_bytes: u64,
    pub cloned_bytes: u64,
    pub physically_written_bytes: u64,
    pub hash_bytes: u64,
    pub flush_time_nanos: u64,
    pub reservation_hold_time_nanos: u64,
}

impl PreparationCounters {
    pub fn merge(&mut self, other: &PreparationCounters) {
        self.preparation_bytes += other.preparation_bytes;
        self.cloned_bytes += other.cloned_bytes;
        self.physically_written_bytes += other.physically_written_bytes;
        self.hash_bytes += other.hash_bytes;
        self.flush_time_nanos += other.flush_time_nanos;
        self.reservation_hold_time_nanos += other.reservation_hold_time_nanos;
    }
}

// =====================================================================
// Preparation (§6.1) — no canonical-path reservation held
// =====================================================================

#[derive(Debug)]
pub struct PreparedArtifact {
    pub fast_path: FastPath,
    /// Every stronger path considered and rejected, strongest-first — see
    /// [`FastPathDecision`].
    pub fallback: Vec<(FastPath, FastPathRejection)>,
    /// `None` only for [`FastPath::NoOp`] — nothing was staged because the
    /// target generation is already materialized.
    pub stage_artefact_name: Option<String>,
    /// The staged object's observed identity, `None` only for
    /// [`FastPath::NoOp`].
    ///
    /// This is the value a caller that transitions the epoch to
    /// `EpochState::PreparedArtifact` (design §8.2 step 5, immediately after
    /// this function's own verify-and-fsync work) must persist as
    /// `EpochUpdate.staged_identity` — not defer to the later `Prepared`
    /// transition (step 8, "expected identities"), which is several states
    /// after every state `early_physical_recovery`'s unstarted-artefact
    /// cleanup handles (`AwaitingReservation`/`Preparing`/`PreparedArtifact`).
    /// Recorded that late, `staged_identity` is absent for all of them and
    /// the cleanup can never prove ownership; see
    /// `early_physical_recovery::cleanup_unstarted_artefact`'s own doc.
    ///
    /// Already stable for that comparison despite being observed before the
    /// stage object's `Prepared`-time reservation: it is captured after
    /// [`finish_staged_file`]/[`finish_hardlinked_stage`] finish assembling,
    /// verifying and flushing content (or, on the hardlink fast path, from
    /// an object whose content this function never writes to at all), so it
    /// never observes a partially-streamed object. And even if it did,
    /// [`yadorilink_root_authority::fs_identity::FileIdentity::compare`] — what
    /// `cleanup_unstarted_artefact` actually calls — never inspects a
    /// content-derived field (`observed_size`, `metadata_fingerprint`): it
    /// compares volume, object id, kind, generation/USN, symlink-target
    /// digest and birth time, all of which are fixed at creation and
    /// unaffected by a subsequent write to the same object.
    pub verified_identity: Option<FileIdentity>,
    pub counters: PreparationCounters,
}

pub struct PrepareRequest<'a> {
    pub parent_dir: &'a ParentDirHandle,
    /// The id embedded in the generated stage artefact's name — unique per
    /// allocation so two concurrent preparations for the same eventual
    /// target never collide (see [`reserved_namespace::artefact_component_name`]).
    pub artefact_id: &'a str,
    pub inputs: PlacementInputs<'a>,
    /// Checked against the staged object's actual bytes whenever bytes are
    /// staged (every path except [`FastPath::NoOp`]/[`FastPath::Hardlink`],
    /// where identity is proven a different way). `None` skips verification —
    /// a caller that supplies `None` for a byte-staging path is choosing not
    /// to verify content, not something this module infers is safe on its
    /// own.
    pub expected_content_hash: Option<[u8; 32]>,
    /// The replicated permission bits to apply, or `None` for "no Unix
    /// permission info to apply" — same `Option<u32>` convention as
    /// [`yadorilink_replica_domain::file::FileMeta::unix_mode`].
    pub unix_mode: Option<u32>,
}

#[derive(Debug)]
pub enum PrepareError {
    Io(io::Error),
    /// A caller supplied an argument that is structurally invalid for the
    /// operation. Mirrors `yadorilink-sync-core::SyncError::InvalidInput`
    /// (this crate must not depend on that type -- see the module doc).
    InvalidInput(String),
    /// A path names a component reserved for transaction artefacts. Mirrors
    /// `yadorilink-sync-core::SyncError::ReservedNamespaceCollision`.
    ReservedNamespaceCollision(String),
    /// [`finish_staged_file`]'s `apply_unix_mode` call.
    Storage(yadorilink_local_storage::StorageError),
    CreateArtefact(CreateArtefactError),
    ArtefactName(ArtefactNameError),
    ContentVerificationFailed,
    /// [`FastPath::StreamingReconstruction`] was selected. Not implemented
    /// in this phase — see [`prepare_target`]'s doc for why. Carries the
    /// full decision so a caller still learns which weaker paths were
    /// already ruled out.
    UnimplementedFastPath(Box<FastPathDecision>),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrepareError::Io(e) => write!(f, "io error preparing artefact: {e}"),
            PrepareError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            PrepareError::ReservedNamespaceCollision(path) => write!(
                f,
                "path {path:?} names a reserved artefact component and cannot be used here"
            ),
            PrepareError::Storage(e) => write!(f, "storage error: {e}"),
            PrepareError::CreateArtefact(e) => write!(f, "could not create stage artefact: {e:?}"),
            PrepareError::ArtefactName(e) => write!(f, "artefact naming error: {e:?}"),
            PrepareError::ContentVerificationFailed => {
                write!(f, "staged content did not hash to the expected value")
            }
            PrepareError::UnimplementedFastPath(decision) => write!(
                f,
                "streaming reconstruction fast path is not implemented in this phase: {decision:?}"
            ),
        }
    }
}

impl std::error::Error for PrepareError {}

/// Prepares a stage artefact for `request`, per §6.1: allocates a uniquely
/// named reserved stage artefact beside the destination directory, assembles
/// it via the strongest verified fast path, verifies its content and applies
/// tracked metadata, and fsyncs the object and its directory entry. Holds no
/// canonical-path reservation — `request.parent_dir` is the *destination's
/// parent*, never the target path itself, and nothing here names or touches
/// the eventual live path.
///
/// [`FastPath::StreamingReconstruction`] is deliberately not implemented
/// here: this crate's content-to-disk writer
/// (`chunker::reconstruct_file`) may only be called from one of three
/// sanctioned crash-safety seam files (see
/// `scripts/check-materialization-journal.py`), none of which is this
/// module, and duplicating that writer's logic here — without also
/// duplicating the intent-journal discipline that makes it crash-safe —
/// would silently reintroduce the exact class of bug that guard exists to
/// prevent. When this fast path gets a real caller, it belongs behind one of
/// those three seams, not here.
/// 7D-9D eighth pass: this used to be `prepare_target_unchecked`, with a
/// separate `pub fn prepare_target` gating it behind
/// `filesystem_transaction::require_execution_enabled`. That gate lives in
/// `yadorilink-sync-sqlite`, which this crate must not depend on (the
/// reverse dependency already exists) -- mirrors `custody_transfer.rs`'s own
/// earlier collapse for the identical reason. The gate is not lost: its one
/// real caller, `yadorilink-sync-core`'s `orchestrator.rs`, already checks
/// `filesystem_transaction::require_execution_enabled()` exactly once at its
/// own entry point before reaching this function (the same discipline every
/// other `_unchecked` seam in this workspace exists for), so nothing here
/// needs to re-check it.
pub fn prepare_target(request: &PrepareRequest) -> Result<PreparedArtifact, PrepareError> {
    let decision = select_fast_path(&request.inputs);
    let mut counters = PreparationCounters::default();

    let (stage_name, verified_identity) = match decision.selected {
        FastPath::NoOp => (None, None),
        FastPath::MetadataOnly | FastPath::ReflinkClone => {
            let source = request.inputs.clone_source.ok_or_else(no_clone_source_error)?.path();
            let (name, file) =
                clone_whole_file(request.parent_dir, request.artefact_id, source, &mut counters)?;
            let stage_path = request.parent_dir.path().join(&name);
            finish_staged_file(&stage_path, &file, request, &mut counters)?;
            let identity = FileIdentity::observe_handle(&file).map_err(PrepareError::Io)?;
            (Some(name), Some(identity))
        }
        FastPath::RangeClone => {
            let source = request.inputs.clone_source.ok_or_else(no_clone_source_error)?.path();
            let (name, file) = range_clone_whole_file(
                request.parent_dir,
                request.artefact_id,
                source,
                &mut counters,
            )?;
            let stage_path = request.parent_dir.path().join(&name);
            finish_staged_file(&stage_path, &file, request, &mut counters)?;
            let identity = FileIdentity::observe_handle(&file).map_err(PrepareError::Io)?;
            (Some(name), Some(identity))
        }
        FastPath::Hardlink => {
            let source = match request.inputs.clone_source {
                Some(CloneSource::ImmutableContentStoreObject(p)) => p,
                _ => {
                    return Err(PrepareError::InvalidInput(
                        "hardlink fast path requires an immutable content-store source".to_string(),
                    ))
                }
            };
            let (name, identity) =
                hardlink_immutable_source(request.parent_dir, request.artefact_id, source)?;
            let stage_path = request.parent_dir.path().join(&name);
            finish_hardlinked_stage(&stage_path, source, request, &mut counters)?;
            (Some(name), Some(identity))
        }
        FastPath::StreamingReconstruction => {
            return Err(PrepareError::UnimplementedFastPath(Box::new(decision)))
        }
    };

    Ok(PreparedArtifact {
        fast_path: decision.selected,
        fallback: decision.rejected,
        stage_artefact_name: stage_name,
        verified_identity,
        counters,
    })
}

fn no_clone_source_error() -> PrepareError {
    PrepareError::InvalidInput(
        "fast path selected a clone but no clone source was supplied".to_string(),
    )
}

/// Applies tracked metadata, verifies content against
/// `request.expected_content_hash` when supplied, and durably flushes the
/// staged object per §6.1 step 7.
fn finish_staged_file(
    stage_path: &Path,
    file: &File,
    request: &PrepareRequest,
    counters: &mut PreparationCounters,
) -> Result<(), PrepareError> {
    yadorilink_local_storage::apply_unix_mode(stage_path, request.unix_mode)
        .map_err(PrepareError::Storage)?;
    if let Some(expected) = request.expected_content_hash {
        let mut reader = file.try_clone().map_err(PrepareError::Io)?;
        use std::io::{Seek, SeekFrom};
        reader.seek(SeekFrom::Start(0)).map_err(PrepareError::Io)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf).map_err(PrepareError::Io)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            counters.hash_bytes += n as u64;
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if digest != expected {
            return Err(PrepareError::ContentVerificationFailed);
        }
    }
    let flush_start = Instant::now();
    if request.inputs.capabilities.durable_file_flush.is_supported() {
        durable_flush(file).map_err(PrepareError::Io)?;
    }
    if request.inputs.capabilities.durable_directory_flush.is_supported() {
        durable_flush_directory(request.parent_dir.path()).map_err(PrepareError::Io)?;
    }
    counters.flush_time_nanos += flush_start.elapsed().as_nanos() as u64;
    Ok(())
}

/// The [`FastPath::Hardlink`] counterpart to [`finish_staged_file`]: the
/// staged object is a hardlink sharing `source`'s inode, so it cannot go
/// through the same function unchanged. A hardlink shares one set of
/// content bytes *and* one set of permission bits with `source` — every
/// other fast path stages an independent copy `finish_staged_file` is free
/// to verify and `chmod` on its own, but here `stage_path` and `source` are
/// the same object on disk, so anything this function does to `stage_path`
/// happens to `source` too.
///
/// Content verification is still safe: reading `stage_path` reads exactly
/// `source`'s bytes, so `request.expected_content_hash`, when supplied, is
/// honoured the same way as every other path.
///
/// Applying `request.unix_mode` is not safe in general: `source` is a
/// [`CloneSource::ImmutableContentStoreObject`], and `chmod`ing the
/// hardlinked stage path would mutate that same shared inode's permission
/// bits system-wide, including at every other name it's linked under —
/// exactly the "never touches an immutable content-store object" property
/// this fast path exists to preserve. A requested mode that already matches
/// `source`'s own observed mode needs no mutation and is accepted; one that
/// would actually change it is refused rather than either silently applied
/// (mutating the content store) or silently ignored (this function's own
/// defect being fixed here).
fn finish_hardlinked_stage(
    stage_path: &Path,
    source: &Path,
    request: &PrepareRequest,
    counters: &mut PreparationCounters,
) -> Result<(), PrepareError> {
    if let Some(expected) = request.expected_content_hash {
        let mut file = File::open(stage_path).map_err(PrepareError::Io)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf).map_err(PrepareError::Io)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            counters.hash_bytes += n as u64;
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if digest != expected {
            return Err(PrepareError::ContentVerificationFailed);
        }
    }
    if let Some(requested_unix_mode) = request.unix_mode {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            const PERMISSION_BITS: u32 = 0o777;
            let mode = fs::metadata(source).map_err(PrepareError::Io)?.permissions().mode();
            let current_unix_mode = mode & PERMISSION_BITS;
            if current_unix_mode != requested_unix_mode {
                return Err(PrepareError::InvalidInput(format!(
                    "hardlink fast path cannot set the mode to {requested_unix_mode:#o} for {} \
                     without mutating the shared immutable content-store object's inode at {}; \
                     refusing rather than silently applying or silently ignoring it",
                    stage_path.display(),
                    source.display(),
                )));
            }
        }
        #[cfg(not(unix))]
        {
            // No permission-bits model exists off Unix (mirroring
            // `chunker::apply_unix_mode`'s own no-op there), so there is
            // nothing to refuse or apply. `source` is only read to compare
            // against those bits, so it is unused here too.
            let _ = (requested_unix_mode, source);
        }
    }
    Ok(())
}

// ---- clone / link primitives ----

#[cfg(target_os = "linux")]
fn clone_whole_file(
    parent_dir: &ParentDirHandle,
    artefact_id: &str,
    source: &Path,
    counters: &mut PreparationCounters,
) -> Result<(String, File), PrepareError> {
    use std::os::unix::io::AsRawFd;

    let (name, dst_file) = parent_dir
        .create_artefact(ArtefactKind::Stage, artefact_id)
        .map_err(PrepareError::CreateArtefact)?;
    let src_file = File::open(source).map_err(PrepareError::Io)?;
    let source_len = src_file.metadata().map_err(PrepareError::Io)?.len();

    // SAFETY: both file descriptors are valid and kept alive for the
    // duration of this call.
    let (ret, _errno) = retry_eintr(|| {
        call_and_capture_errno!(unsafe {
            libc::ioctl(dst_file.as_raw_fd(), libc::FICLONE, src_file.as_raw_fd())
        })
    });
    if ret == 0 {
        counters.cloned_bytes += source_len;
    } else {
        // `FICLONE` unsupported on this pair despite the volume's cached
        // capability (a stale/incorrect snapshot, or a cross-filesystem
        // pair the cache does not distinguish) — the stage file `create_artefact`
        // already created is still empty, so copy into it directly rather
        // than fail outright. A slow safe fallback, recorded via the
        // `physically_written_bytes` counter rather than left silent.
        copy_into(&src_file, &dst_file).map_err(PrepareError::Io)?;
        counters.physically_written_bytes += source_len;
    }
    counters.preparation_bytes += source_len;
    Ok((name, dst_file))
}

#[cfg(target_os = "macos")]
fn clone_whole_file(
    parent_dir: &ParentDirHandle,
    artefact_id: &str,
    source: &Path,
    counters: &mut PreparationCounters,
) -> Result<(String, File), PrepareError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let name = reserved_namespace::artefact_component_name(ArtefactKind::Stage, artefact_id)
        .map_err(PrepareError::ArtefactName)?;
    let dst_path = parent_dir.path().join(&name);
    // `clonefile(2)` creates `dst_path` itself and fails if something is
    // already there — checked (not `create_artefact`'s O_CREAT|O_EXCL,
    // which would create an empty file `clonefile` would then refuse to
    // overwrite) for the same reason `fs_capabilities`'s own probe checks
    // absence before calling it: this is a narrower, already-accepted
    // path-based race (see the module doc's directory-relative discipline),
    // not a new one.
    if dst_path.symlink_metadata().is_ok() {
        return Err(PrepareError::ReservedNamespaceCollision(dst_path.display().to_string()));
    }
    let source_len = fs::metadata(source).map_err(PrepareError::Io)?.len();

    let src_c = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        PrepareError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source path contains a NUL byte",
        ))
    })?;
    let dst_c = CString::new(dst_path.as_os_str().as_bytes()).map_err(|_| {
        PrepareError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stage path contains a NUL byte",
        ))
    })?;
    // SAFETY: both paths are valid NUL-terminated strings; `dst_path` was
    // just confirmed absent above.
    let (ret, _errno) = retry_eintr(|| {
        call_and_capture_errno!(unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) })
    });
    if ret == 0 {
        let file =
            OpenOptions::new().read(true).write(true).open(&dst_path).map_err(PrepareError::Io)?;
        counters.cloned_bytes += source_len;
        counters.preparation_bytes += source_len;
        return Ok((name, file));
    }
    // `clonefile` did not create `dst_path` on failure — safe to fall back
    // to an exclusive create-and-copy at the same name.
    let mut dst_file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(&dst_path)
        .map_err(PrepareError::Io)?;
    let mut src_file = File::open(source).map_err(PrepareError::Io)?;
    io::copy(&mut src_file, &mut dst_file).map_err(PrepareError::Io)?;
    counters.physically_written_bytes += source_len;
    counters.preparation_bytes += source_len;
    Ok((name, dst_file))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn clone_whole_file(
    parent_dir: &ParentDirHandle,
    artefact_id: &str,
    source: &Path,
    counters: &mut PreparationCounters,
) -> Result<(String, File), PrepareError> {
    let (name, mut dst_file) = parent_dir
        .create_artefact(ArtefactKind::Stage, artefact_id)
        .map_err(PrepareError::CreateArtefact)?;
    let mut src_file = File::open(source).map_err(PrepareError::Io)?;
    let written = io::copy(&mut src_file, &mut dst_file).map_err(PrepareError::Io)?;
    counters.physically_written_bytes += written;
    counters.preparation_bytes += written;
    Ok((name, dst_file))
}

/// Used only by the Linux clone/range-clone fallback paths — see their own
/// docs. `cfg`-gated rather than left to a dead-code warning on other
/// platforms.
#[cfg(target_os = "linux")]
fn copy_into(src: &File, dst: &File) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut src = src.try_clone()?;
    let mut dst = dst.try_clone()?;
    src.seek(SeekFrom::Start(0))?;
    dst.seek(SeekFrom::Start(0))?;
    io::copy(&mut src, &mut dst)?;
    Ok(())
}

/// Byte-range clone via `copy_file_range` (Linux only — `range_clone` is
/// `Unsupported` by construction everywhere else, per
/// `fs_capabilities`'s doc, so `select_fast_path` never chooses this path
/// off that platform).
///
/// This clones the *entire* source range in one pass, not a real
/// changed-block-only copy: producing a partial changed-block plan needs a
/// byte-range diff input no caller in this crate computes yet. It is still
/// a genuine, verified `copy_file_range` use (distinct from
/// [`clone_whole_file`]'s `FICLONE`), correctly gated on the `range_clone`
/// capability — it is the "plus changed-block writes" half of §18.1 that is
/// not implemented, stated here rather than left to be discovered later.
#[cfg(target_os = "linux")]
fn range_clone_whole_file(
    parent_dir: &ParentDirHandle,
    artefact_id: &str,
    source: &Path,
    counters: &mut PreparationCounters,
) -> Result<(String, File), PrepareError> {
    use std::os::unix::io::AsRawFd;

    let (name, dst_file) = parent_dir
        .create_artefact(ArtefactKind::Stage, artefact_id)
        .map_err(PrepareError::CreateArtefact)?;
    let src_file = File::open(source).map_err(PrepareError::Io)?;
    let total = src_file.metadata().map_err(PrepareError::Io)?.len();
    let mut copied: u64 = 0;
    while copied < total {
        let remaining = (total - copied) as usize;
        // SAFETY: null offsets track each fd's own file position, which
        // both `src_file`/`dst_file` share from where the previous
        // iteration (if any) left them; both fds are valid and kept alive
        // for the duration of the call.
        let (ret, _errno) = retry_eintr_syscall(|| {
            call_and_capture_errno!(unsafe {
                libc::syscall(
                    libc::SYS_copy_file_range,
                    src_file.as_raw_fd(),
                    std::ptr::null_mut::<libc::loff_t>(),
                    dst_file.as_raw_fd(),
                    std::ptr::null_mut::<libc::loff_t>(),
                    remaining,
                    0u32,
                )
            })
        });
        if ret < 0 {
            // A `0`-byte-in-progress fallback: whatever wasn't copied via
            // `copy_file_range` gets a plain copy of the remainder, from
            // the current shared fd positions.
            copy_into(&src_file, &dst_file).map_err(PrepareError::Io)?;
            counters.cloned_bytes += copied;
            counters.physically_written_bytes += total - copied;
            counters.preparation_bytes += total;
            return Ok((name, dst_file));
        }
        if ret == 0 {
            // No forward progress and no error: cannot distinguish "done"
            // from "stuck" here, so treat as exhausted and fall back for
            // the remainder rather than loop forever.
            copy_into(&src_file, &dst_file).map_err(PrepareError::Io)?;
            counters.cloned_bytes += copied;
            counters.physically_written_bytes += total - copied;
            counters.preparation_bytes += total;
            return Ok((name, dst_file));
        }
        copied += ret as u64;
    }
    counters.cloned_bytes += total;
    counters.preparation_bytes += total;
    Ok((name, dst_file))
}

/// See the `#[cfg(target_os = "linux")]` sibling's doc — kept as a safe,
/// explicit fallback (a plain copy, correctly counted as such) rather than
/// a panic, in case a caller ever supplies a stale or incorrect capability
/// snapshot that reports `range_clone` as `Supported` off Linux.
#[cfg(not(target_os = "linux"))]
fn range_clone_whole_file(
    parent_dir: &ParentDirHandle,
    artefact_id: &str,
    source: &Path,
    counters: &mut PreparationCounters,
) -> Result<(String, File), PrepareError> {
    let (name, mut dst_file) = parent_dir
        .create_artefact(ArtefactKind::Stage, artefact_id)
        .map_err(PrepareError::CreateArtefact)?;
    let mut src_file = File::open(source).map_err(PrepareError::Io)?;
    let written = io::copy(&mut src_file, &mut dst_file).map_err(PrepareError::Io)?;
    counters.physically_written_bytes += written;
    counters.preparation_bytes += written;
    Ok((name, dst_file))
}

/// Hardlinks `source` (an [`CloneSource::ImmutableContentStoreObject`] —
/// enforced by every call site, never a mutable user-visible path) into a
/// freshly reserved stage name.
fn hardlink_immutable_source(
    parent_dir: &ParentDirHandle,
    artefact_id: &str,
    source: &Path,
) -> Result<(String, FileIdentity), PrepareError> {
    let name = reserved_namespace::artefact_component_name(ArtefactKind::Stage, artefact_id)
        .map_err(PrepareError::ArtefactName)?;
    let dst_path = parent_dir.path().join(&name);
    if dst_path.symlink_metadata().is_ok() {
        return Err(PrepareError::ReservedNamespaceCollision(dst_path.display().to_string()));
    }
    fs::hard_link(source, &dst_path).map_err(PrepareError::Io)?;
    let identity = FileIdentity::observe_path(&dst_path).map_err(PrepareError::Io)?;
    Ok((name, identity))
}

// =====================================================================
// Durability flush helpers
// =====================================================================

#[cfg(target_os = "macos")]
fn durable_flush(file: &File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let (ret, errno) = retry_eintr(|| {
        call_and_capture_errno!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) })
    });
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(errno.unwrap_or(0)))
    }
}

#[cfg(not(target_os = "macos"))]
fn durable_flush(file: &File) -> io::Result<()> {
    file.sync_all()
}

/// `pub`: also called from `yadorilink-sync-core`'s `optimistic_placement::
/// execute_short_commit_window_core` (7D-9D eighth pass -- this module's own
/// production code moved here, but the commit window's directory-durability
/// flush stayed behind, since it happens inside the same SQLite transaction
/// as the commit's own database write).
///
/// Flushes `dir_path`'s own directory metadata, needed so a rename/exchange
/// within it survives a crash. Reopens the directory by path rather than
/// through the caller's own handle — the same narrower, already-accepted
/// path-based race `fs_commit`'s module doc describes for identity reads
/// (not the mutation race the directory-handle discipline exists to close),
/// mirroring `chunker::sync_parent_directory`'s existing pattern.
///
/// Whether the resulting flush actually delivers power-loss durability is a
/// platform question answered by `fs_capabilities::probe_durable_directory_flush`,
/// not by this function — see that probe's Windows doc for why this
/// primitive's declared capability is `Unsupported` there even though the
/// call below can succeed.
#[cfg(not(windows))]
pub fn durable_flush_directory(dir_path: &Path) -> io::Result<()> {
    let dir = File::open(dir_path)?;
    durable_flush(&dir)
}

/// Windows counterpart of the function above. `std::fs::File::open` cannot
/// obtain a directory handle at all on Windows — the underlying
/// `CreateFileW` call requires `FILE_FLAG_BACKUP_SEMANTICS` to open a
/// directory, which plain `File::open`/`OpenOptions::open` never requests —
/// so every call here used to fail before even reaching `durable_flush`,
/// turning every commit into `RequiresRecovery` on this platform.
/// `custom_flags` is a stable `std` API
/// (`std::os::windows::fs::OpenOptionsExt`), so no hand-declared FFI or
/// extra dependency is needed just to get the handle, unlike the
/// identity/commit primitives elsewhere in this crate that really do need
/// one.
#[cfg(windows)]
pub fn durable_flush_directory(dir_path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    /// `FILE_FLAG_BACKUP_SEMANTICS`, per the Win32 `CreateFile` reference —
    /// required to open a directory at all; without it `CreateFileW`
    /// returns `ERROR_ACCESS_DENIED` for any directory path.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    let dir =
        OpenOptions::new().read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(dir_path)?;
    durable_flush(&dir)
}

// =====================================================================
// Small libc-retry helpers, mirroring `fs_capabilities`'s own (private,
// not reusable across modules) pattern.
// =====================================================================

#[cfg(unix)]
fn retry_eintr(mut attempt: impl FnMut() -> (i32, Option<i32>)) -> (i32, Option<i32>) {
    loop {
        let (ret, errno) = attempt();
        if ret != -1 || errno != Some(libc::EINTR) {
            return (ret, errno);
        }
    }
}

#[cfg(target_os = "linux")]
fn retry_eintr_syscall(mut attempt: impl FnMut() -> (i64, Option<i32>)) -> (i64, Option<i32>) {
    loop {
        let (ret, errno) = attempt();
        if ret != -1 || errno != Some(libc::EINTR) {
            return (ret, errno);
        }
    }
}

#[cfg(unix)]
macro_rules! call_and_capture_errno {
    ($ret:expr) => {{
        let ret = $ret;
        let errno = if ret == -1 { io::Error::last_os_error().raw_os_error() } else { None };
        (ret, errno)
    }};
}
#[cfg(unix)]
use call_and_capture_errno;

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_root_authority::fs_capabilities::{Capability, FilesystemSafetyCapabilities};

    fn caps(reflink: Capability, range: Capability) -> FilesystemSafetyCapabilities {
        FilesystemSafetyCapabilities {
            atomic_exchange: Capability::Supported,
            durable_file_flush: Capability::Supported,
            durable_directory_flush: Capability::Supported,
            stable_source_identity: Capability::Supported,
            stable_owned_marker_identity: Capability::Supported,
            stale_handle_preservation: Capability::Supported,
            metadata_fidelity: Capability::Supported,
            reflink_or_clone: reflink,
            range_clone: range,
        }
    }

    // `select_fast_path`'s own decision-table tests moved to
    // `yadorilink-replica-engine::optimistic_placement::tests` along with
    // the function itself (7D-9D) -- `caps()` above stays here, still used
    // by every `prepare_*`/commit-window test below that exercises real
    // filesystem I/O around the fast path `select_fast_path` chose.

    #[test]
    fn preparation_counters_merge_sums_every_field() {
        let mut total = PreparationCounters {
            preparation_bytes: 1,
            cloned_bytes: 2,
            physically_written_bytes: 3,
            hash_bytes: 4,
            flush_time_nanos: 5,
            reservation_hold_time_nanos: 6,
        };
        let other = PreparationCounters {
            preparation_bytes: 10,
            cloned_bytes: 20,
            physically_written_bytes: 30,
            hash_bytes: 40,
            flush_time_nanos: 50,
            reservation_hold_time_nanos: 60,
        };
        total.merge(&other);
        assert_eq!(
            total,
            PreparationCounters {
                preparation_bytes: 11,
                cloned_bytes: 22,
                physically_written_bytes: 33,
                hash_bytes: 44,
                flush_time_nanos: 55,
                reservation_hold_time_nanos: 66,
            }
        );
    }

    // ---- prepare_target: real filesystem I/O ----

    #[cfg(unix)]
    fn open_dir(path: &Path) -> ParentDirHandle {
        ParentDirHandle::open(path).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn prepare_reflink_clone_produces_content_identical_to_source_and_verifies_hash() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("source.txt");
        std::fs::write(&source_path, b"hello prepared world").unwrap();
        let hash: [u8; 32] = Sha256::digest(b"hello prepared world").into();

        let capabilities = caps(Capability::Supported, Capability::Unsupported);
        let parent = open_dir(dir.path());
        let request = PrepareRequest {
            parent_dir: &parent,
            artefact_id: "test-artefact-1",
            inputs: PlacementInputs {
                target_already_materialized: false,
                content_identity_unchanged: false,
                clone_source: Some(CloneSource::LocalVersionPath(&source_path)),
                capabilities: &capabilities,
            },
            expected_content_hash: Some(hash),
            unix_mode: None,
        };

        let prepared = prepare_target(&request).unwrap();
        assert_eq!(prepared.fast_path, FastPath::ReflinkClone);
        let stage_name = prepared.stage_artefact_name.expect("reflink stages an artefact");
        let staged_bytes = std::fs::read(dir.path().join(&stage_name)).unwrap();
        assert_eq!(staged_bytes, b"hello prepared world");
        assert!(prepared.counters.hash_bytes > 0);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_rejects_content_that_does_not_match_the_expected_hash() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("source.txt");
        std::fs::write(&source_path, b"actual content").unwrap();
        let wrong_hash: [u8; 32] = Sha256::digest(b"a different expectation").into();

        let capabilities = caps(Capability::Supported, Capability::Unsupported);
        let parent = open_dir(dir.path());
        let request = PrepareRequest {
            parent_dir: &parent,
            artefact_id: "test-artefact-2",
            inputs: PlacementInputs {
                target_already_materialized: false,
                content_identity_unchanged: false,
                clone_source: Some(CloneSource::LocalVersionPath(&source_path)),
                capabilities: &capabilities,
            },
            expected_content_hash: Some(wrong_hash),
            unix_mode: None,
        };

        let result = prepare_target(&request);
        assert!(matches!(result, Err(PrepareError::ContentVerificationFailed)));
        // Mutation check: neutralising the hash comparison (see the git
        // history of this test file / the accompanying report) makes this
        // assertion fail on this exact line, not on a generic "it errored"
        // check, confirming it is not vacuous.
    }

    #[cfg(unix)]
    #[test]
    fn prepare_hardlink_from_immutable_source_shares_the_same_inode() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("immutable-object");
        std::fs::write(&source_path, b"content-addressed bytes").unwrap();

        let capabilities = caps(Capability::Unsupported, Capability::Unsupported);
        let parent = open_dir(dir.path());
        let request = PrepareRequest {
            parent_dir: &parent,
            artefact_id: "test-artefact-3",
            inputs: PlacementInputs {
                target_already_materialized: false,
                content_identity_unchanged: false,
                clone_source: Some(CloneSource::ImmutableContentStoreObject(&source_path)),
                capabilities: &capabilities,
            },
            expected_content_hash: None,
            unix_mode: None,
        };

        let prepared = prepare_target(&request).unwrap();
        assert_eq!(prepared.fast_path, FastPath::Hardlink);
        let stage_name = prepared.stage_artefact_name.unwrap();
        let source_ino = std::fs::metadata(&source_path).unwrap().ino();
        let staged_ino = std::fs::metadata(dir.path().join(&stage_name)).unwrap().ino();
        assert_eq!(source_ino, staged_ino);
    }

    #[test]
    fn streaming_reconstruction_selection_is_reported_as_unimplemented_not_silently_skipped() {
        let capabilities = caps(Capability::Unsupported, Capability::Unsupported);
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let request = PrepareRequest {
            parent_dir: &parent,
            artefact_id: "test-artefact-4",
            inputs: PlacementInputs {
                target_already_materialized: false,
                content_identity_unchanged: false,
                clone_source: None,
                capabilities: &capabilities,
            },
            expected_content_hash: None,
            unix_mode: None,
        };
        let result = prepare_target(&request);
        assert!(matches!(result, Err(PrepareError::UnimplementedFastPath(_))));
    }

    // ---- Hardlink fast path: hash verification and exec-bit safety -----

    #[cfg(unix)]
    #[test]
    fn prepare_hardlink_verifies_a_supplied_content_hash() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("immutable-object");
        std::fs::write(&source_path, b"content-addressed bytes").unwrap();
        let hash: [u8; 32] = Sha256::digest(b"content-addressed bytes").into();

        let capabilities = caps(Capability::Unsupported, Capability::Unsupported);
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let request = PrepareRequest {
            parent_dir: &parent,
            artefact_id: "hardlink-hash-ok",
            inputs: PlacementInputs {
                target_already_materialized: false,
                content_identity_unchanged: false,
                clone_source: Some(CloneSource::ImmutableContentStoreObject(&source_path)),
                capabilities: &capabilities,
            },
            expected_content_hash: Some(hash),
            unix_mode: None,
        };
        let prepared = prepare_target(&request).unwrap();
        assert_eq!(prepared.fast_path, FastPath::Hardlink);
        assert!(prepared.counters.hash_bytes > 0);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_hardlink_rejects_content_that_does_not_match_the_expected_hash() {
        // Regression test for Defect 4: previously the hardlink arm never
        // called anything that checked `expected_content_hash` at all, so
        // a caller-supplied hash was silently ignored. This must fail with
        // `ContentVerificationFailed`, not silently succeed.
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("immutable-object");
        std::fs::write(&source_path, b"actual content").unwrap();
        let wrong_hash: [u8; 32] = Sha256::digest(b"a different expectation").into();

        let capabilities = caps(Capability::Unsupported, Capability::Unsupported);
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let request = PrepareRequest {
            parent_dir: &parent,
            artefact_id: "hardlink-hash-bad",
            inputs: PlacementInputs {
                target_already_materialized: false,
                content_identity_unchanged: false,
                clone_source: Some(CloneSource::ImmutableContentStoreObject(&source_path)),
                capabilities: &capabilities,
            },
            expected_content_hash: Some(wrong_hash),
            unix_mode: None,
        };
        let result = prepare_target(&request);
        assert!(matches!(result, Err(PrepareError::ContentVerificationFailed)));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_hardlink_refuses_an_unix_mode_change_rather_than_mutating_the_shared_inode() {
        // Regression test for Defect 4's exec-bit half: the hardlinked
        // stage path and `source` are the same inode, so applying a
        // changed exec bit through the stage path would silently mutate
        // the "immutable" content-store object too. This must be refused,
        // and -- the actual harm this test provokes -- `source`'s own
        // permission bits must be left untouched by the refused call.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("immutable-object");
        std::fs::write(&source_path, b"content-addressed bytes").unwrap();
        std::fs::set_permissions(&source_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mode_before = std::fs::metadata(&source_path).unwrap().permissions().mode();

        let capabilities = caps(Capability::Unsupported, Capability::Unsupported);
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let request = PrepareRequest {
            parent_dir: &parent,
            artefact_id: "hardlink-exec-bit",
            inputs: PlacementInputs {
                target_already_materialized: false,
                content_identity_unchanged: false,
                clone_source: Some(CloneSource::ImmutableContentStoreObject(&source_path)),
                capabilities: &capabilities,
            },
            // `source` was just created with mode 0o644 (no exec bit) --
            // requesting 0o744 (adds owner-exec) demands an actual change.
            expected_content_hash: None,
            unix_mode: Some(0o744),
        };
        let result = prepare_target(&request);
        assert!(matches!(result, Err(PrepareError::InvalidInput(_))));

        let mode_after = std::fs::metadata(&source_path).unwrap().permissions().mode();
        assert_eq!(
            mode_before, mode_after,
            "a refused mode change must not mutate the shared immutable content-store inode"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_hardlink_accepts_an_unix_mode_that_already_matches_the_source() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("immutable-object");
        std::fs::write(&source_path, b"content-addressed bytes").unwrap();
        std::fs::set_permissions(&source_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let capabilities = caps(Capability::Unsupported, Capability::Unsupported);
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let request = PrepareRequest {
            parent_dir: &parent,
            artefact_id: "hardlink-exec-bit-noop",
            inputs: PlacementInputs {
                target_already_materialized: false,
                content_identity_unchanged: false,
                clone_source: Some(CloneSource::ImmutableContentStoreObject(&source_path)),
                capabilities: &capabilities,
            },
            expected_content_hash: None,
            unix_mode: Some(0o644),
        };
        let prepared = prepare_target(&request);
        assert!(prepared.is_ok());
    }
}
