//! Sync-root single-instance ownership: an OS-level advisory exclusive lock
//! proving no other process is concurrently treating this folder as a sync
//! root.
//!
//! Distinct from [`crate::root_identity`]: that module proves *this is the
//! right folder* (identity, corroborated against the index). This module
//! proves *nobody else is touching it right now* (mutual exclusion between
//! processes). The two are complementary, not overlapping — a folder can be
//! the right one and still be double-owned (two daemons pointed at the same
//! path), and holding this lock does nothing to prove which folder it is.
//!
//! # Why this is not held on `VerifiedRoot`
//!
//! `VerifiedRoot::open`/`verify` run on every scan, every materialization
//! repair pass, every peer-driven write — many times over one link's life,
//! inside a *single* daemon process. An OS `flock` conflicts between two
//! open file *descriptions* of the same file, even within one process, on
//! Linux and macOS (see the identical precedent already relied on by
//! `yadorilink-daemon::resource_lock::take_exclusive_lock`). Acquiring and
//! releasing a fresh lock on every `VerifiedRoot` construction would
//! therefore make two concurrent in-process operations on the *same* root
//! serialize-or-fail against each other — not what this guards against, and
//! it would break ordinary same-process concurrency today (concurrent scans
//! and repairs over one link are routine).
//!
//! The lock this module provides is instead acquired *once*, when the
//! daemon starts actively managing a link, and held for as long as the
//! daemon keeps that link active — mirroring the config-directory lock
//! (`yadorilink-daemon::app::DaemonInstanceLock`) and the data-resource locks
//! (`yadorilink-daemon::resource_lock::DataResourceLocks`), which are
//! likewise whole-process-lifetime locks rather than per-operation ones.
//!
//! # Mechanism
//!
//! A sidecar lock file at the top level of the root
//! ([`SYNC_ROOT_LOCK_FILE_NAME`], excluded from sync exactly like the
//! identity marker — see `local_change::is_excluded_from_sync`), held with a
//! non-blocking OS advisory exclusive lock (`flock`/`LockFileEx` via `fs2`)
//! for as long as the returned [`SyncRootLock`] is alive. The OS releases
//! the lock automatically when the holding process exits for any reason —
//! including `SIGKILL` and a hard crash — so the file left behind is never
//! read for "is this stale?"; a plain re-open-and-lock either succeeds
//! (nothing else holds it) or fails (something does), and that is the whole
//! answer.
//!
//! Deliberately, no PID is stored anywhere in this file, and none is read
//! back. A stored PID is not sufficient to tell "the process that held this
//! died" apart from "an unrelated process now has that PID" — PIDs are
//! reused, and a naive stale-lock reclaimer that trusts `kill(pid, 0)` can be
//! fooled by exactly that reuse into stepping on a live owner. What actually
//! answers "is the previous holder still alive" correctly is the *live OS
//! lock state itself*: the kernel tracks the lock against the open file
//! description, not a PID, and tears it down exactly when that description's
//! last reference (the process that opened it) goes away. That is a strictly
//! stronger and simpler signal than any PID bookkeeping this module could add
//! on top, so none is added.
//!
//! # What this assumes, and what happens when the assumption fails
//!
//! This mechanism assumes the underlying filesystem honours OS advisory
//! locking (`flock`/`fcntl`/`LockFileEx`) with real, exclusive,
//! cross-process semantics. Ordinary local filesystems on all three target
//! platforms (APFS, NTFS/ReFS, ext4/btrfs/xfs, ...) satisfy this.
//!
//! A sync root living on a network volume or removable media does not
//! necessarily satisfy it, and the failure mode is a silent fail-**open**,
//! not a refusal:
//!
//! * **NFS** delegates locking to `lockd`/NLM, and a mount using `nolock` (or
//!   talking to a server with no lock manager) grants every caller's lock
//!   request immediately regardless of who else holds it. There is no
//!   portable way to detect this from the client side in advance — the
//!   `try_lock_exclusive` call simply succeeds for two hosts at once.
//! * **SMB/CIFS**: whether an advisory lock taken by one client is honoured
//!   by the server against a *different* client mounting the same share
//!   depends on the server implementation and client mount options; some
//!   configurations only enforce it within one client's own processes.
//! * **Removable media (USB, exFAT/FAT32)** is single-host by construction,
//!   so cross-*process*-on-one-host exclusion still works normally (the
//!   local OS lock manager applies regardless of the filesystem format).
//!   What it cannot do is stop two *different* hosts each believing they own
//!   the volume after a silent unplug/replug from one of them — that
//!   scenario is `root_identity`'s job (the marker/token check), not this
//!   module's.
//!
//! In short: on local storage, and on one host's view of removable media,
//! this lock is correct and load-bearing. On genuinely shared network
//! storage it degrades to whatever that network filesystem's own
//! advisory-lock implementation actually provides, which this module has no
//! way to verify and does not attempt to — it fails closed on outright I/O
//! errors, but a lock request the server silently grants to two hosts at
//! once (the NFS `nolock` case above) is invisible to it by construction.
//! Design section 15's harder "genuine multi-process operation" case ("a
//! fenced lease checked immediately before every namespace mutation") is
//! what would be needed to close that gap; this module implements the
//! simpler single-owner refusal called for today, not that lease.

use std::collections::HashMap;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::error::RootAuthorityError;
use crate::fs_identity::FileIdentity;

/// Lock file placed at the top level of a sync root. Named and handled like
/// [`yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME`]: excluded from sync
/// (`local_change::is_excluded_from_sync`), so it is never indexed,
/// never transmitted, and never a conflicted-copy candidate.
pub const SYNC_ROOT_LOCK_FILE_NAME: &str = ".yadorilink-root.lock";

static HELD_ROOT_IDENTITIES: OnceLock<Mutex<HashMap<PathBuf, FileIdentity>>> = OnceLock::new();

fn held_root_identities() -> &'static Mutex<HashMap<PathBuf, FileIdentity>> {
    HELD_ROOT_IDENTITIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// On Unix, an inode cannot be recycled while this process still has the
/// original inode open. Every `expected` passed by this module was captured
/// from the live `_sidecar` handle and remains registered only for that
/// handle's lifetime. Consequently, an equal `(device, inode, kind)` from a
/// fresh path observation is conclusive in this narrower live-handle case,
/// even when the filesystem exposes neither an inode-generation counter nor
/// a fine birth-time clock (notably overlayfs).
///
/// This is intentionally local to `SyncRootLock`; general persisted identity
/// comparisons must continue to treat a bare Unix inode match as ambiguous,
/// because a closed/unlinked inode can be reused later.
#[cfg(unix)]
fn path_still_names_live_unix_handle(expected: FileIdentity, current: FileIdentity) -> bool {
    matches!(
        (
            expected.volume_identity,
            expected.object_id,
            current.volume_identity,
            current.object_id,
        ),
        (
            crate::fs_identity::VolumeIdentity::Unix { device_id: expected_device },
            crate::fs_identity::PlatformObjectId::Unix { inode: expected_inode },
            crate::fs_identity::VolumeIdentity::Unix { device_id: current_device },
            crate::fs_identity::PlatformObjectId::Unix { inode: current_inode },
        ) if expected_device == current_device
            && expected_inode == current_inode
            && expected.object_kind == current.object_kind
    )
}

fn verify_sidecar_identity(root: &Path, expected: FileIdentity) -> Result<(), RootAuthorityError> {
    let lock_path = root.join(SYNC_ROOT_LOCK_FILE_NAME);
    let current = FileIdentity::observe_path(&lock_path).map_err(|e| {
        RootAuthorityError::Io(io::Error::new(
            e.kind(),
            format!(
                "sync-root lock sidecar {} could not be re-observed: {e} -- this root's ownership can no longer be confirmed",
                lock_path.display()
            ),
        ))
    })?;
    // Cached, not the raw probe: this function is reached from
    // `RootLease::begin_operation`, which runs on essentially every local
    // capture, materialize, and hydration operation -- an uncached probe
    // here re-pays real file-create/stat/unlink I/O, inside the very sync
    // root the filesystem watcher is watching, on every single call. See
    // `cached_probe_birth_time_granularity`'s own doc for the C4 live-burst
    // measurement that found this.
    let granularity = crate::fs_capabilities::cached_probe_birth_time_granularity(root);
    match expected.compare(&current, granularity) {
        crate::fs_identity::IdentityComparison::SameObject => Ok(()),
        crate::fs_identity::IdentityComparison::DefinitelyDifferent => {
            Err(RootAuthorityError::Io(io::Error::other(format!(
                "sync-root lock sidecar {} no longer names the object this process locked",
                lock_path.display()
            ))))
        }
        crate::fs_identity::IdentityComparison::Ambiguous(reason) => {
            #[cfg(unix)]
            if path_still_names_live_unix_handle(expected, current) {
                return Ok(());
            }
            Err(RootAuthorityError::Io(io::Error::other(format!(
                "sync-root lock sidecar {} cannot be conclusively re-verified ({reason:?})",
                lock_path.display()
            ))))
        }
    }
}

/// Re-checks the process-lifetime root lock, when one is registered
/// for `root`. Standalone sync-core callers that do not use
/// `SyncRootLock` retain their existing marker/token-only behavior;
/// daemon-managed roots fail closed if the sidecar was replaced.
pub fn verify_registered_root_ownership(root: &Path) -> Result<(), RootAuthorityError> {
    let canonical = root.canonicalize()?;
    let expected =
        held_root_identities().lock().unwrap_or_else(|p| p.into_inner()).get(&canonical).copied();
    match expected {
        Some(expected) => verify_sidecar_identity(&canonical, expected),
        None => Ok(()),
    }
}

/// True for exactly `<root>/.yadorilink-root.lock` and nothing else —
/// identical top-level-only rule to
/// [`crate::root_identity::is_root_marker_relative_path`], which this
/// mirrors so the same-named file nested in a subdirectory (ordinary user
/// content) keeps syncing normally.
pub fn is_sync_root_lock_relative_path(relative_path: impl AsRef<Path>) -> bool {
    let mut segments =
        relative_path.as_ref().components().filter(|c| !matches!(c, Component::CurDir));
    match (segments.next(), segments.next()) {
        (Some(Component::Normal(only)), None) => {
            only == std::ffi::OsStr::new(SYNC_ROOT_LOCK_FILE_NAME)
        }
        _ => false,
    }
}

/// The **wire-path** counterpart to [`is_sync_root_lock_relative_path`], for
/// a path **string** that arrived off the wire (a peer-authored path this
/// process never walked off its own directory tree) — a change's `Put`/
/// `Delete`/`Move` path, or a peer-supplied `FileRecord::path` about to be
/// materialized.
///
/// Top-level-only and exact, matching [`is_sync_root_lock_relative_path`]'s
/// semantics exactly — this is deliberately NOT the same shape as
/// [`crate::reserved_namespace::path_has_artefact_component_in_wire_path`],
/// which matches the reserved name at *any* depth because a versioned
/// artefact name is reserved wherever it appears, including as an
/// intermediate directory. The sync-root lock is different: like the
/// identity marker, a same-named file *nested* in a subdirectory is
/// ordinary user content that must keep syncing (see
/// [`is_sync_root_lock_relative_path`]'s doc comment) — only a peer path
/// that is *exactly* the lock file at the root is a genuine collision, so
/// only a single-component path is checked here.
///
/// Must be used instead of the host-`Path` form at every site that rejects a
/// remote-authored path, for the identical reason
/// [`crate::reserved_namespace::path_has_artefact_component_in_wire_path`]
/// documents: resolving a peer's raw path string through this process's own
/// `std::path::Path` finds component boundaries only where THIS platform's
/// separator convention says to, so a peer path shaped like
/// `"safe\\.yadorilink-root.lock"` would be one component (not a match) on
/// Unix and two (a match on the second, still correctly excluded here since
/// it is no longer the *only* component) on Windows — an admission decision
/// must not depend on which platform is running the check. Reuses
/// `reserved_namespace`'s own portable component splitter and
/// alternate-data-stream stripper so this agrees with the versioned-artefact
/// wire check on what counts as "the same component" in every case, rather
/// than defining that afresh here and risking the two silently diverging on
/// the exact NTFS-ADS/backslash edge cases that check's tests already pin
/// down. ASCII case-folded: this name is fixed ASCII, and the target
/// folder's filesystem may itself be case-insensitive (NTFS default, APFS
/// default), so a peer path differing only in case still names the same
/// on-disk file this device's lock lives at.
pub fn wire_path_names_sync_root_lock(path: &str) -> bool {
    let mut components = crate::reserved_namespace::wire_path_components(path);
    match (components.next(), components.next()) {
        (Some(only), None) => crate::reserved_namespace::strip_alternate_data_stream_suffix(only)
            .eq_ignore_ascii_case(SYNC_ROOT_LOCK_FILE_NAME),
        _ => false,
    }
}

/// Process-lifetime-scoped exclusive ownership of one sync root. Acquired
/// once (see the module doc for why this is not per-`VerifiedRoot`-call) and
/// held for as long as the daemon keeps this link active; dropping it
/// releases the underlying OS lock, at which point another process's
/// [`SyncRootLock::acquire`] for the same root succeeds.
#[derive(Debug)]
pub struct SyncRootLock {
    _sidecar: std::fs::File,
    /// The identity observed at the moment [`open_sidecar_file`] opened
    /// `_sidecar` — kept (not merely discarded after the open-time checks
    /// run) so a caller that later wants to confirm the held handle still
    /// names the same on-disk object it was granted the lock against has
    /// something to compare a fresh observation to (`FileIdentity::compare`
    /// against a re-observation of `_sidecar` via `FileIdentity::
    /// observe_handle`). Nothing in this module re-checks it today — the
    /// live OS lock on `_sidecar` is already this module's sole
    /// correctness signal (see the module doc) — but recording it here
    /// costs one field and means that check does not need a second, later
    /// open to become possible.
    sidecar_identity: FileIdentity,
    root: PathBuf,
}

impl SyncRootLock {
    /// Acquire exclusive ownership of `root`. Fails closed: any error
    /// resolving the path, opening the sidecar lock file, or finding it
    /// already held by a live owner is `Err` — never "probably fine".
    ///
    /// `root` must already exist (a link's root is created by the join/link
    /// flow before this runs); this deliberately does not create the
    /// directory itself, unlike the block-store root lock in
    /// `yadorilink-daemon::resource_lock`, which owns a directory this crate
    /// never does.
    pub fn acquire(root: &Path) -> Result<Self, RootAuthorityError> {
        let canonical = root.canonicalize().map_err(|e| {
            RootAuthorityError::Io(io::Error::new(
                e.kind(),
                format!("failed to resolve sync root {}: {e}", root.display()),
            ))
        })?;
        let lock_path = canonical.join(SYNC_ROOT_LOCK_FILE_NAME);
        let (sidecar, sidecar_identity) = open_sidecar_file(&canonical, &lock_path)?;
        take_exclusive_lock(&sidecar, &canonical, &lock_path)?;
        {
            let mut held = held_root_identities().lock().unwrap_or_else(|p| p.into_inner());
            if held.contains_key(&canonical) {
                return Err(RootAuthorityError::CorruptState(format!(
                    "sync root {} already has a registered process owner",
                    canonical.display()
                )));
            }
            held.insert(canonical.clone(), sidecar_identity);
        }
        Ok(Self { _sidecar: sidecar, sidecar_identity, root: canonical })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The identity of the sidecar lock file as observed at acquisition
    /// time — see the field's own doc for why this is kept rather than
    /// discarded once the open-time checks pass.
    pub fn sidecar_identity(&self) -> FileIdentity {
        self.sidecar_identity
    }

    /// Re-verifies that the sidecar path still names the exact object this
    /// lock was granted against — closes an independent review's finding:
    /// the OS lock this module relies on is held against the open file
    /// *description* (effectively the inode), not the pathname. `flock`
    /// does not prevent `unlink` — a live holder's lock survives its own
    /// sidecar being unlinked out from under it, completely undetected by
    /// that holder. A second process can then `openat(O_CREAT)` the exact
    /// same pathname (which the kernel now treats as creating a BRAND NEW
    /// object, since the old inode is unlinked but still referenced by the
    /// first holder's open descriptor) and successfully take its own
    /// exclusive lock on that new object — two processes now both
    /// correctly believe they exclusively own this sync root, because each
    /// one's OS lock genuinely is uncontended on the specific inode it
    /// holds.
    ///
    /// This method is the fencing primitive `SyncRootLock`'s own struct
    /// doc already anticipated ("nothing in this module re-checks it
    /// today") but never wired up: it re-`observe_path`s the sidecar's
    /// pathname right now and compares the result against the identity
    /// captured at acquisition time. `SameObject` means the pathname still
    /// names what this handle's lock actually covers — safe to proceed.
    /// Anything else — `DefinitelyDifferent` (the common unlink-and-
    /// recreate case; a fresh object now sits at this name), an outright
    /// I/O error (the path is gone, or has become unreadable), or
    /// `Ambiguous` (this platform's identity probe cannot conclusively
    /// prove sameness right now) — fails closed, matching every other
    /// identity check in this crate that treats "cannot prove it's still
    /// the same object" the same as "proven different," never as
    /// "probably still fine."
    ///
    /// Callers are responsible for actually invoking this before a
    /// namespace-mutating operation for full protection — this method only
    /// provides the check itself; see this crate's H2 ledger for the
    /// tracked follow-up to wire it into every such call site.
    pub fn verify_still_owns(&self) -> Result<(), RootAuthorityError> {
        verify_sidecar_identity(&self.root, self.sidecar_identity)
    }
}

impl Drop for SyncRootLock {
    fn drop(&mut self) {
        held_root_identities().lock().unwrap_or_else(|p| p.into_inner()).remove(&self.root);
    }
}

/// Removes `root`'s entry from the in-process ownership registry without
/// releasing its OS lock or dropping the handle that holds it — for tests
/// that deliberately simulate a *second, independent process* acquiring the
/// same root within a single test process. A real second process has its
/// own empty registry (a separate address space), so it is never blocked by
/// this process's registration; only a genuine same-process double
/// `acquire` is. This lets such a test exercise the OS/inode-level race
/// (`unlink` + recreate at the same pathname) that this registry is not the
/// mechanism for, without the registry's same-process guard masking it.
#[cfg(any(test, feature = "test-support"))]
pub fn forget_registered_root_for_test(root: &Path) {
    held_root_identities().lock().unwrap_or_else(|p| p.into_inner()).remove(root);
}

/// Open (creating if needed, never truncating — this is a lock file, not a
/// content file, so pre-existing bytes are never discarded just by opening
/// it) the sidecar lock file, with `0o600` permissions on Unix, and return
/// the [`FileIdentity`] of the object actually opened alongside it.
///
/// A process that can write inside `root` (any local user on a
/// single-user-writable directory, or a compromised peer's materialization
/// path) can otherwise plant a symlink at `<root>/.yadorilink-root.lock`
/// pointing anywhere on the filesystem — a naive open-by-path follows it,
/// and the OS lock this module exists to provide then locks an unrelated
/// file while [`SyncRootLock::acquire`] reports success. This function is
/// what closes that: it never follows a symlink already at the lock path,
/// and never accepts anything other than a plain regular file there, in
/// both cases refusing outright (`Err`) rather than falling back to
/// something else at the same name. This is the identical discipline
/// `fs_commit::ParentDirHandle` already applies to every artefact this
/// crate creates or opens beside user content (`create_artefact`/
/// `open_child_no_follow`) — resolved from an already-open parent-directory
/// handle rather than a second, independently-racy path lookup, and never
/// trusting a name's apparent kind without checking it. Unlike `fs_commit`'s
/// `open_child_no_follow`, this never falls back to opening the symlink
/// entry itself when the name turns out to be one: `open_child_no_follow`
/// exists for a caller that has already classified the name as a legitimate
/// symlink it wants a handle to; nothing at this sidecar's path is ever a
/// legitimate symlink, so any symlink found here is refused outright, with
/// no fallback branch to reach.
///
/// # Platform asymmetry
///
/// On Unix (Linux and macOS; see the `cfg` below) this is fully
/// directory-handle-relative: `root` is opened once as a directory
/// descriptor, and the sidecar is created/opened through `openat` against
/// that descriptor's file number with `O_NOFOLLOW`, so a rename or
/// replacement of `root` itself after the caller resolved it cannot
/// redirect where the sidecar lands, and a symlink already at the sidecar's
/// name is refused (`ELOOP`) rather than followed — matching
/// `ParentDirHandle::open`'s own directory-relative discipline.
///
/// On Windows there is no directory-handle-relative open primitive at the
/// Win32 level for this shape (`CreateFileW` has no equivalent of `openat`
/// against a parent descriptor) — the identical residual `fs_commit::
/// ParentDirHandle`'s own doc already states for its non-Unix branches. This
/// function does not pretend otherwise: the Windows path below opens
/// `lock_path` directly, by name, same as the pre-fix code did. What it does
/// still guarantee is the symlink refusal, using a mechanism Windows *does*
/// have: `FILE_FLAG_OPEN_REPARSE_POINT` (the same flag `fs_identity::
/// win_identity::query_path` already relies on for its own never-follow
/// contract) makes `CreateFileW` open a reparse point object itself —
/// whatever it is, a symlink (`IO_REPARSE_TAG_SYMLINK`), a mount point, or
/// any other reparse tag — instead of transparently resolving through it to
/// its target, and the `FILE_ATTRIBUTE_REPARSE_POINT` bit this function then
/// checks on the result is what turns "did not silently follow it" into
/// "refuses it outright", matching the Unix branch's refusal rather than
/// merely not-following. So: symlink refusal is real and equivalent on both
/// platforms; directory-handle-relative resolution is Unix-only, stated
/// plainly rather than implied closed on Windows, exactly as `fs_commit`'s
/// own Windows branches already do for the identical class of gap.
fn open_sidecar_file(
    root: &Path,
    lock_path: &Path,
) -> Result<(std::fs::File, FileIdentity), RootAuthorityError> {
    let file = open_sidecar_file_platform(root, lock_path)?;
    let identity = FileIdentity::observe_handle(&file).map_err(|e| {
        RootAuthorityError::Io(io::Error::new(
            e.kind(),
            format!(
                "failed to observe identity of sync-root lock sidecar {}: {e}",
                lock_path.display()
            ),
        ))
    })?;
    if identity.object_kind != crate::fs_identity::ObjectKind::RegularFile {
        return Err(RootAuthorityError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to use {} as the sync-root lock: it is not a plain regular file \
                 (found {:?}) — a symlink, directory, FIFO or other special file at this path \
                 is never a legitimate sync-root lock sidecar",
                lock_path.display(),
                identity.object_kind
            ),
        )));
    }
    Ok((file, identity))
}

/// Unix implementation of [`open_sidecar_file`]: directory-handle-relative,
/// never-follow. `O_NOFOLLOW` on an `openat` whose final component names a
/// symlink fails with `ELOOP` rather than following it — no fallback branch
/// is wanted here (contrast `fs_commit::ParentDirHandle::open_child_no_
/// follow`, whose fallback exists for a caller that wants a handle to a
/// *known-legitimate* symlink, which a sync-root lock sidecar never is).
///
/// `O_RDWR` (not the plain-open-existing case's `O_RDONLY`) because the
/// lock file must be creatable, and `fs2`'s `try_lock_exclusive` needs write
/// access to the descriptor regardless of whether this call created or
/// merely opened it. `O_CREAT` without `O_EXCL`: unlike `ParentDirHandle::
/// create_artefact`'s exclusive-create (which must never silently attach to
/// something already there), the sidecar's whole point is to be reused
/// across every acquisition of the same root — see the module doc's
/// "Mechanism" section on why a pre-existing, unlocked sidecar is acquired
/// with no special-casing.
///
/// A directory, FIFO, socket or device node already at the sidecar's name
/// is not refused by `O_NOFOLLOW` (which only ever refuses a *symlink*) —
/// opening a directory with `O_RDWR` already fails outright with `EISDIR`
/// on both Linux and macOS before this function's own regular-file check
/// ever runs, and opening a FIFO with `O_RDWR` never blocks (POSIX: only a
/// FIFO opened `O_RDONLY`-only or `O_WRONLY`-only can block waiting for the
/// other end), so it is safe to open here and is instead refused by
/// [`open_sidecar_file`]'s own `object_kind` check right after this
/// function returns.
#[cfg(unix)]
fn open_sidecar_file_platform(
    root: &Path,
    lock_path: &Path,
) -> Result<std::fs::File, RootAuthorityError> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let dir = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(root)?;

    // The lock file name is a fixed ASCII constant with no interior NUL, so
    // this conversion cannot fail — `expect` rather than threading a
    // fallible path through a name this module itself controls.
    let name_c = std::ffi::CString::new(std::ffi::OsStr::new(SYNC_ROOT_LOCK_FILE_NAME).as_bytes())
        .expect("SYNC_ROOT_LOCK_FILE_NAME has no interior NUL byte");
    let flags = libc::O_CREAT | libc::O_NOFOLLOW | libc::O_RDWR | libc::O_CLOEXEC;
    // SAFETY: `dir.as_raw_fd()` is a valid, open directory descriptor for
    // the duration of this call; `name_c` is a valid NUL-terminated string;
    // the variadic `mode` argument is required whenever `O_CREAT` is set
    // and is otherwise ignored (masked by the process umask on actual
    // creation).
    let fd =
        unsafe { libc::openat(dir.as_raw_fd(), name_c.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return Err(RootAuthorityError::Io(io::Error::new(
            err.kind(),
            format!("failed to open sync-root lock sidecar {}: {err}", lock_path.display()),
        )));
    }
    // SAFETY: `fd` was just returned by the successful `openat` call above,
    // is a valid open file descriptor, and is not used or closed anywhere
    // else — `File` takes sole ownership of it here.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    // `fchmod` on the already-open descriptor, not `std::fs::set_permissions`
    // on `lock_path`: the whole point of resolving through `dir`/`openat`
    // above is to never re-resolve the path after the symlink check has
    // already run, and a path-based `set_permissions` call here would
    // reopen exactly that TOCTOU window one line later.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Windows implementation of [`open_sidecar_file`] — see that function's
/// "Platform asymmetry" doc for what this can and cannot guarantee relative
/// to the Unix branch above. `custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)` is
/// a stable `std::os::windows::fs::OpenOptionsExt` call — no hand-declared
/// `CreateFileW` FFI needed for this half of the fix, unlike `fs_identity::
/// win_identity`'s own reason for declaring it by hand (this crate does not
/// need `FileIdInfo`/`GetFileInformationByHandleEx` here, only the one
/// documented `dwFlagsAndAttributes` bit `OpenOptionsExt::custom_flags`
/// already exposes on stable). UNVERIFIED, no Windows host was available to
/// confirm this branch — matching every other Windows branch in this
/// crate's `fs_commit`/`fs_identity` modules, which carry the identical
/// caveat for the identical reason.
#[cfg(windows)]
fn open_sidecar_file_platform(
    _root: &Path,
    lock_path: &Path,
) -> Result<std::fs::File, RootAuthorityError> {
    use std::os::windows::fs::OpenOptionsExt;

    /// `FILE_FLAG_OPEN_REPARSE_POINT` — identical value, and identical
    /// justification, as `fs_identity::win_identity`'s own private copy of
    /// this constant (that module's `mod win_identity` is private to
    /// `fs_identity.rs`, so this is a second declaration of the same
    /// documented Win32 constant rather than a shared one; see
    /// `fs_identity.rs`'s `FILE_FLAG_OPEN_REPARSE_POINT` for the identical
    /// value from the same Win32 header).
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(lock_path)?;

    // `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` does not itself
    // refuse to open a reparse point — it only stops silently resolving
    // through one to its target. Refusing it outright is this check's job:
    // `FILE_ATTRIBUTE_REPARSE_POINT` is set on the returned metadata for a
    // symlink, junction, mount point or any other reparse tag, and never
    // for a plain file created by this same call.
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let attributes = file.metadata()?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RootAuthorityError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to use {} as the sync-root lock: it is a reparse point (symlink, \
                 junction or mount point), not a plain file",
                lock_path.display()
            ),
        )));
    }
    Ok(file)
}

/// Take a non-blocking exclusive OS lock on `file`, mapping contention to a
/// clear "already in use" error and any other failure to a plain I/O error.
///
/// Compares against `fs2::lock_contended_error()`'s raw OS error rather than
/// `ErrorKind::WouldBlock`: on Windows, `try_lock_exclusive`'s real
/// contention error is `ERROR_LOCK_VIOLATION` (raw OS error 33), which does
/// not map to `ErrorKind::WouldBlock` in std's Windows error-kind mapping —
/// unlike Unix's `EWOULDBLOCK`, which does. Mirrors
/// `yadorilink-daemon::resource_lock::take_exclusive_lock`'s identical
/// comparison, for the identical reason (that module's own comment cites
/// `fs2`'s test suite comparing the same way).
fn take_exclusive_lock(
    file: &std::fs::File,
    root: &Path,
    lock_path: &Path,
) -> Result<(), RootAuthorityError> {
    match fs2::FileExt::try_lock_exclusive(file) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
            Err(RootAuthorityError::Io(io::Error::new(
                error.kind(),
                format!(
                    "sync root {} is already in use by another YadoriLink process",
                    root.display()
                ),
            )))
        }
        Err(error) => Err(RootAuthorityError::Io(io::Error::new(
            error.kind(),
            format!("failed to acquire sync-root lock {}: {error}", lock_path.display()),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    /// Mirrors `root_identity::only_the_top_level_marker_is_recognized`: a
    /// same-named file nested in a subdirectory is ordinary user content and
    /// must keep syncing, only the root-level lock file is this module's.
    #[test]
    fn only_the_top_level_lock_file_is_recognized() {
        assert!(is_sync_root_lock_relative_path(".yadorilink-root.lock"));
        assert!(is_sync_root_lock_relative_path("./.yadorilink-root.lock"));
        assert!(!is_sync_root_lock_relative_path("nested/.yadorilink-root.lock"));
        assert!(!is_sync_root_lock_relative_path(".yadorilink-root.lock/inner.txt"));
        assert!(!is_sync_root_lock_relative_path("notes.txt"));
    }

    /// The wire-path form must catch what the host form is not safe to be
    /// used for: a peer path spelled with a different case, or an NTFS
    /// alternate-data-stream suffix — mirroring `reserved_namespace`'s own
    /// wire-path tests for the identical reasons (see
    /// [`wire_path_names_sync_root_lock`]'s doc comment). It must also stay
    /// top-level-only (unlike the versioned-artefact wire check, which
    /// matches at any depth): a *nested* same-named path, on either
    /// separator convention, is ordinary user content and must not match.
    #[test]
    fn wire_path_form_is_top_level_only_and_matches_case_and_ads_variants() {
        assert!(wire_path_names_sync_root_lock(".yadorilink-root.lock"));
        assert!(wire_path_names_sync_root_lock(".YADORILINK-ROOT.LOCK"));
        assert!(wire_path_names_sync_root_lock(".yadorilink-root.lock::$DATA"));
        assert!(!wire_path_names_sync_root_lock("notes.txt"));
        assert!(!wire_path_names_sync_root_lock("some/dir/.yadorilink-root.lock"));
        assert!(!wire_path_names_sync_root_lock("some\\dir\\.yadorilink-root.lock"));
        assert!(!wire_path_names_sync_root_lock("nested/.yadorilink-root.lock/inner.txt"));
    }

    /// A second acquisition of the same root, while the first is still
    /// held, must be refused. Real `fs2` OS locks, not a mock: `flock`
    /// conflicts between two open file descriptions of the same file even
    /// within a single process (the same property
    /// `yadorilink-daemon::resource_lock`'s equivalent tests rely on), so
    /// this genuinely exercises the OS lock, not an in-process flag.
    #[test]
    fn a_second_acquisition_is_refused_while_the_first_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let _owner = SyncRootLock::acquire(&root).unwrap();

        let err = SyncRootLock::acquire(&root)
            .expect_err("a second holder of the same sync root must be rejected");
        assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
    }

    /// Releasing (dropping) the lock makes the root acquirable again — the
    /// ordinary "link stopped, then restarted" path within one daemon
    /// process.
    #[test]
    fn releasing_the_lock_makes_the_root_acquirable_again() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();

        let owner = SyncRootLock::acquire(&root).unwrap();
        assert!(SyncRootLock::acquire(&root).is_err(), "must be exclusive while held");
        drop(owner);

        let _reacquired = SyncRootLock::acquire(&root)
            .expect("the root must be acquirable again once the prior owner released it");
    }

    /// A lock file left on disk with nothing holding its OS lock (the
    /// steady state after any prior owner's process exited, cleanly or not
    /// — the OS releases the lock but this module never deletes the lock
    /// file itself) must be reacquired with no special-casing. Pins that
    /// there is no stale-file logic to go wrong: an unlocked pre-existing
    /// file is indistinguishable from a freshly created one.
    #[test]
    fn a_preexisting_but_unlocked_lock_file_is_acquired_normally() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::write(root.join(SYNC_ROOT_LOCK_FILE_NAME), b"").unwrap();

        let _owner = SyncRootLock::acquire(&root)
            .expect("a lock file with nothing holding its OS lock must be acquired normally");
    }

    /// THE crash-recovery case, driven with a genuine second OS process, not
    /// a same-process `drop`: a real child process acquires the lock and
    /// then is `SIGKILL`ed — no graceful shutdown, no `Drop` running in that
    /// process's own code, only the kernel tearing down its file
    /// descriptors. A new acquisition afterward must still succeed, because
    /// the reclaim signal this module relies on is entirely OS-level (the
    /// lock dies with the killed process's open file description), never a
    /// PID or a stale-file check this module would have to run itself.
    #[test]
    fn a_lock_held_by_a_process_that_was_killed_is_reclaimable() {
        const HOLD_ENV: &str = "YADORILINK_TEST_HOLD_SYNC_ROOT_LOCK";
        const ROOT_ENV: &str = "YADORILINK_TEST_SYNC_ROOT_LOCK_PATH";

        // Re-entry: when invoked under `HOLD_ENV`, this test function is
        // actually the *child* process. It acquires the lock on the path
        // named by `ROOT_ENV` and then blocks forever, so the parent can
        // kill it while it still holds the lock.
        if let Ok(root) = std::env::var(ROOT_ENV) {
            if std::env::var(HOLD_ENV).is_ok() {
                let _lock = SyncRootLock::acquire(Path::new(&root))
                    .expect("child: acquiring the lock must succeed");
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();

        let exe = std::env::current_exe().unwrap();
        let mut child = std::process::Command::new(exe)
            .arg("sync_root_lock::tests::a_lock_held_by_a_process_that_was_killed_is_reclaimable")
            .arg("--exact")
            .arg("--nocapture")
            .env(HOLD_ENV, "1")
            .env(ROOT_ENV, &root)
            .spawn()
            .expect("spawning the child holder process");

        // Poll for the child to have actually taken the lock, rather than a
        // fixed sleep: the child's own startup time (process spawn, test
        // harness init) is not bounded tightly enough for a fixed delay to
        // be both fast and reliable.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if SyncRootLock::acquire(&root).is_err() {
                break;
            }
            assert!(Instant::now() < deadline, "child never took the lock within the deadline");
            std::thread::sleep(Duration::from_millis(20));
        }

        // Simulate a crash: SIGKILL, not a graceful exit. Nothing in the
        // child's own process runs in response to this — the sole reclaim
        // signal is the kernel releasing the lock when the killed process's
        // file descriptors are torn down.
        child.kill().expect("killing the child holder");
        child.wait().expect("reaping the killed child");

        let _reacquired = SyncRootLock::acquire(&root).expect(
            "a lock left by a killed process must be reclaimable — this is the load-bearing \
             property: the daemon must not be permanently unstartable after any prior crash",
        );
    }

    /// THE symlink-planting attack this fix exists for: a process that can
    /// write inside the sync root plants a symlink at the sidecar's exact
    /// name, pointing at some other file it wants locked (or, worse, at a
    /// file it wants to be able to observe *whether* the daemon is holding
    /// open). Before the fix, `open_sidecar_file` used a plain
    /// `OpenOptions::open` by path, which follows a symlink transparently —
    /// `SyncRootLock::acquire` would then lock `target.txt`, not the sidecar,
    /// and report success while proving nothing about single-instance
    /// ownership of `root`. Pins that this is refused outright, not
    /// followed.
    #[test]
    fn a_symlink_planted_at_the_sidecar_path_is_refused_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join("target.txt");
        std::fs::write(&target, b"unrelated content").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, root.join(SYNC_ROOT_LOCK_FILE_NAME)).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, root.join(SYNC_ROOT_LOCK_FILE_NAME)).unwrap();

        let err = SyncRootLock::acquire(&root)
            .expect_err("a symlink planted at the sidecar path must be refused, not followed");
        assert!(
            !err.to_string().contains("already in use"),
            "must be refused for being a symlink, not because the (unrelated) target happens \
             to look locked: {err}"
        );

        // The real proof this wasn't silently followed: the target file's
        // own bytes are untouched, and it is still an ordinary,
        // non-locked, plain file — nothing here ever opened or locked it.
        assert_eq!(std::fs::read(&target).unwrap(), b"unrelated content");
    }

    // A "directory at the sidecar path is refused" test was written and
    // mutation-checked here, then dropped: `std::fs::OpenOptions::new().
    // write(true).open(<a directory>)` already fails with `EISDIR` even on
    // the pre-fix code (a plain path-based open with no `O_NOFOLLOW` at
    // all), because Unix refuses to open a directory for writing regardless
    // of symlink-following. That test was green before this fix and green
    // after it — it exercises the OS's own directory-vs-file distinction,
    // not anything this module's `open_sidecar_file` rewrite added, so it
    // would not have caught a regression in the actual fix and is not kept.
    // The FIFO test below is the real non-regular-file case: `O_NOFOLLOW`
    // does not refuse a FIFO (only a symlink), so a FIFO opens successfully
    // and only this module's own `object_kind` check afterward refuses it —
    // confirmed by mutation (disabling that check turns the FIFO test red).

    /// A FIFO at the sidecar's exact name is the other non-regular-file
    /// case this module's `O_NOFOLLOW` open does not implicitly exclude
    /// (`O_NOFOLLOW` only refuses a *symlink*; a FIFO opens successfully
    /// with `O_RDWR`, per POSIX, without blocking) — it is
    /// `open_sidecar_file`'s explicit `object_kind` check afterward that
    /// must catch this one. Unix-only: FIFOs are not a concept at an
    /// ordinary filesystem path on Windows (named pipes live in a separate
    /// `\\.\pipe\` namespace), so there is nothing to plant there — see
    /// `open_sidecar_file`'s own doc on the Windows-side residual this
    /// module states plainly rather than pretending symmetric.
    /// The happy path: nothing touched the sidecar since acquisition, so
    /// `verify_still_owns` must succeed.
    #[test]
    fn verify_still_owns_succeeds_while_nothing_has_touched_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let owner = SyncRootLock::acquire(&root).unwrap();

        owner.verify_still_owns().expect("nothing changed -- must still confirm ownership");
    }

    /// C4 live-burst attribution fix (2026-09-01): proves the real call
    /// chain -- not just the pure caching decision
    /// `granularity_cache_reprobes_on_a_different_volume_identity_but_not_
    /// the_same_one` in `fs_capabilities.rs` already covers -- actually
    /// stops re-probing. `RootLease::begin_operation` and every
    /// `LinkOperation::reverify()` (i.e. every `RootCommitPermit::verify()`
    /// along one operation's path) reach `verify_still_owns` repeatedly;
    /// before this fix, each call paid a full uncached
    /// `probe_birth_time_granularity` (real file-create/stat/unlink I/O).
    /// Confirmed genuinely RED against the pre-fix code (temporarily
    /// reverting `verify_sidecar_identity` to call the raw, uncached probe):
    /// this test's second assertion then failed, the count having grown by
    /// 2 instead of staying flat.
    #[test]
    fn repeated_verify_still_owns_calls_probe_at_most_once_per_volume() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let owner = SyncRootLock::acquire(&root).unwrap();

        owner.verify_still_owns().expect("first call must succeed");
        let count_after_first = crate::fs_capabilities::probe_birth_time_granularity_call_count_for_test();

        owner.verify_still_owns().expect("second call must succeed");
        owner.verify_still_owns().expect("third call must succeed");
        let count_after_more = crate::fs_capabilities::probe_birth_time_granularity_call_count_for_test();

        assert_eq!(
            count_after_more, count_after_first,
            "repeated verify_still_owns calls for the same volume must not trigger additional \
             real granularity probes -- only the first call (or a genuine cache miss on a \
             different volume) may"
        );
    }

    /// THE double-acquisition bug an independent review found: `flock` is
    /// bound to the open file description, not the pathname, so unlinking
    /// the sidecar out from under a live holder does not affect that
    /// holder's own lock at all -- but it DOES let a second `openat(
    /// O_CREAT)` at the identical pathname create a brand-new object and
    /// take its own, independently-uncontended exclusive lock on it. Both
    /// processes then correctly believe they exclusively own the root.
    /// `verify_still_owns` must detect this: after the unlink-and-recreate,
    /// the ORIGINAL holder's re-check of the pathname must fail, since the
    /// object now sitting there is not the one its lock actually covers.
    #[test]
    fn verify_still_owns_detects_an_unlink_and_recreate_of_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let owner = SyncRootLock::acquire(&root).unwrap();
        owner.verify_still_owns().expect("precondition: still fine immediately after acquiring");

        // Simulate a second process's exact sequence: unlink the sidecar
        // pathname (the first holder's lock is completely unaffected by
        // this -- it is bound to the now-unlinked inode, not the name),
        // then create and lock a fresh object at the same name.
        let lock_path = root.join(SYNC_ROOT_LOCK_FILE_NAME);
        std::fs::remove_file(&lock_path).unwrap();
        // A genuine second process has its own empty in-process registry,
        // so it is never blocked by this process's registration -- only a
        // real same-process double `acquire` is. Simulate that here so this
        // test still exercises the OS/inode-level race, not the unrelated
        // same-process guard.
        forget_registered_root_for_test(&root);
        let _second_holder = SyncRootLock::acquire(&root).expect(
            "a second acquisition after the unlink must succeed -- this IS the bug: the \
             kernel sees an entirely new, uncontended object at this pathname",
        );

        let err = owner.verify_still_owns().expect_err(
            "the original holder's re-check must detect that the pathname no longer names the \
             object its lock actually covers",
        );
        assert!(
            !err.to_string().contains("already in use"),
            "must fail as an identity mismatch, not a lock-contention error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_at_the_sidecar_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let fifo_path = root.join(SYNC_ROOT_LOCK_FILE_NAME);
        let fifo_path_c = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::CString::new(fifo_path.as_os_str().as_bytes()).unwrap()
        };
        // SAFETY: `fifo_path_c` is a valid NUL-terminated string naming a
        // path inside a directory this test just created and owns; `0o600`
        // is an ordinary permission mode for `mkfifo(3)`.
        let ret = unsafe { libc::mkfifo(fifo_path_c.as_ptr(), 0o600) };
        assert_eq!(ret, 0, "mkfifo failed: {}", io::Error::last_os_error());

        let err = SyncRootLock::acquire(&root)
            .expect_err("a FIFO at the sidecar path must be refused, never treated as a lock");
        assert!(err.to_string().contains("not a plain regular file"), "unexpected error: {err}");
    }
}
