//! Platform commit adapter: the one place a prepared replacement is
//! atomically swapped into a live filesystem location.
//!
//! Models the commit half of the backend trait a later phase generalizes
//! (`capabilities`/`prepare_target`/`transfer_to_custody` are not modeled
//! here — see [`FilesystemCommitAdapter`]'s doc for the split) for the
//! ordinary-folder case: [`FilesystemCommitAdapter::commit_placement`] and
//! [`FilesystemCommitAdapter::observe_identity`].
//!
//! Nothing in this module is wired into any caller yet — it is the model
//! and the platform implementations only, exercised through
//! [`FakeCommitAdapter`] and the real [`NativeCommitAdapter`] directly by
//! this module's own tests.
//!
//! # Directory-relative, not path-relative
//!
//! Every operation that can mutate a participant addresses it through
//! [`ParentDirHandle`] — an already-open handle to the containing
//! directory — plus a bare filename, never a freshly re-resolved path
//! string. On Unix that means every mutating syscall goes through the
//! `*at()` family against the handle's file descriptor
//! (`renameat2`/`renameatx_np`/`fstatat`), so a rename or symlink swap of
//! the directory itself, after the caller opened the handle, cannot
//! redirect where the commit actually lands. Windows has no path-relative
//! analogue at the Win32 level (`ReplaceFileW` only accepts path strings);
//! see [`ParentDirHandle`]'s doc for how that residual is handled there.
//!
//! Identity *observation* after a commit (not the commit itself) still
//! goes through a path built from the handle's own base path — a narrower,
//! already-accepted class of race (the read could target the wrong object
//! if the parent was swapped out in the instant between the mutation and
//! the read), not the class this module exists to close.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use yadorilink_root_authority::fs_capabilities::classify_errno;
use yadorilink_root_authority::RootAuthorityError;
// `Capability` is read by the Unix errno classification and by tests, and is
// named by doc links on both platforms -- so it stays imported everywhere
// rather than being `cfg`-gated out of scope, which would break those links
// on a Windows build.
#[cfg_attr(not(any(unix, test)), allow(unused_imports))]
use yadorilink_root_authority::fs_capabilities::Capability;
use yadorilink_root_authority::fs_capabilities::FilesystemSafetyCapabilities;
use yadorilink_root_authority::fs_identity::{
    classify_replacement_eligibility, BlockedObjectReason, DirectoryIdentity, FileIdentity,
    IdentityComparison, ReplacementEligibility, TimestampGranularity,
};
use yadorilink_root_authority::reserved_namespace::{
    artefact_component_name, ArtefactKind, ArtefactNameError,
};

/// The `Committed` payload — see [`FilesystemCommitOutcome`]'s doc. A
/// separate, boxed struct (rather than inline enum fields) purely so this
/// variant's stack footprint doesn't dwarf `NotStarted`'s; the shape is
/// otherwise exactly what it would be inline.
#[derive(Debug)]
pub struct CommittedSnapshot {
    pub live_identity: FileIdentity,
    pub preimage_identity: Option<FileIdentity>,
}

/// The `RequiresRecovery` payload — see [`FilesystemCommitOutcome`]'s doc.
/// Boxed for the same reason as [`CommittedSnapshot`].
///
/// Each field is `Option<RecoveryObservation>`: the outer `None` means
/// this location has no name on the current platform for this branch (the
/// Unix preimage slot, or a backup path in a branch that never used one)
/// -- there was nothing to check. `Some(_)` means the location *was*
/// checked, and [`RecoveryObservation`] says what that check found.
/// Collapsing a checked-but-unreadable location into "absent" would
/// silently lie about a location this snapshot exists to describe
/// honestly.
#[derive(Debug)]
pub struct RecoverySnapshot {
    pub observed_live: Option<RecoveryObservation>,
    pub observed_stage: Option<RecoveryObservation>,
    pub observed_preimage: Option<RecoveryObservation>,
    pub observed_backup: Option<RecoveryObservation>,
}

/// What a fresh, independent observation of one [`RecoverySnapshot`]
/// location found. Three states, not two: recovery must be able to tell
/// "checked, and confirmed absent" from "could not be checked at all"
/// (e.g. an EACCES or EIO on the stat itself) -- an observation failure
/// is not evidence the location is empty.
#[derive(Debug)]
pub enum RecoveryObservation {
    /// The location was checked and nothing is there.
    Absent,
    /// The location was checked and this is what is there.
    Present(FileIdentity),
    /// The location could not be checked. This is the raw I/O failure
    /// from the observation itself, not an inference about what state
    /// the location is actually in.
    Unreadable(io::ErrorKind),
}

impl RecoveryObservation {
    fn from_observe(result: io::Result<Option<FileIdentity>>) -> Self {
        match result {
            Ok(Some(identity)) => RecoveryObservation::Present(identity),
            Ok(None) => RecoveryObservation::Absent,
            Err(e) => RecoveryObservation::Unreadable(e.kind()),
        }
    }
}

/// The result of one [`FilesystemCommitAdapter::commit_placement`] attempt.
///
/// Exactly three shapes, deliberately not collapsible into a `Result`: a
/// caller must be able to tell "nothing happened, safe to retry from
/// scratch" from "something was attempted and the outcome needs
/// inspection" without guessing from an error message. Both non-trivial
/// shapes carry a boxed struct rather than inline fields — see
/// [`CommittedSnapshot`]'s doc for why — so match ergonomics are the only
/// difference from the design's literal inline-field shape.
#[derive(Debug)]
pub enum FilesystemCommitOutcome {
    /// The commit happened. `preimage_identity` is the identity of
    /// whatever the live object held immediately before this commit,
    /// retained rather than destroyed — `None` only when there was
    /// nothing live to displace (the absent-destination path).
    ///
    /// Where the preimage physically ends up is platform-specific and
    /// deliberately not part of this contract: on Linux/macOS the atomic
    /// exchange primitive leaves it back at the request's own
    /// `stage_name` (the two participants simply traded places); on
    /// Windows it ends up at `backup_name`, the explicit third path
    /// `ReplaceFileW` requires. A caller that needs to find it again asks
    /// this same adapter via [`FilesystemCommitAdapter::observe_identity`]
    /// at the name appropriate to the platform it is running on — this
    /// type only promises that the preimage's *identity*, wherever it
    /// landed, is exactly this.
    Committed(Box<CommittedSnapshot>),
    /// Nothing was mutated. Every participant is exactly as it was before
    /// this call; retrying (after resolving whatever `RetryReason`
    /// describes, if anything can be done about it) is always safe.
    NotStarted(RetryReason),
    /// A mutating operation was attempted and its outcome could not be
    /// confirmed as either a clean success or a no-op failure — only
    /// reachable on a platform whose commit primitive is not atomic
    /// end-to-end (Windows's `ReplaceFileW`; see its own doc). Every
    /// field is a fresh, independent observation of one named location,
    /// taken after the failure, not an inference from the error code —
    /// an error must never be read as proof nothing changed. Recovery
    /// reconciles from these four observations, not from what was
    /// intended.
    RequiresRecovery(Box<RecoverySnapshot>),
}

impl FilesystemCommitOutcome {
    fn committed(live_identity: FileIdentity, preimage_identity: Option<FileIdentity>) -> Self {
        FilesystemCommitOutcome::Committed(Box::new(CommittedSnapshot {
            live_identity,
            preimage_identity,
        }))
    }

    fn requires_recovery_from(
        observed_live: Option<RecoveryObservation>,
        observed_stage: Option<RecoveryObservation>,
        observed_preimage: Option<RecoveryObservation>,
        observed_backup: Option<RecoveryObservation>,
    ) -> Self {
        FilesystemCommitOutcome::RequiresRecovery(Box::new(RecoverySnapshot {
            observed_live,
            observed_stage,
            observed_preimage,
            observed_backup,
        }))
    }

    /// Whether this outcome is the [`FilesystemCommitOutcome::
    /// RequiresRecovery`] shape — the one case a caller cannot treat as
    /// either "done" or "safe to retry" without inspecting the four
    /// observed fields itself.
    pub fn requires_recovery(&self) -> bool {
        matches!(self, FilesystemCommitOutcome::RequiresRecovery(_))
    }

    /// The identity of the live object after a successful commit, or
    /// `None` for either other shape — `NotStarted` because nothing
    /// changed, `RequiresRecovery` because a single field cannot stand in
    /// for the full observed tuple a caller must inspect.
    pub fn committed_live_identity(&self) -> Option<&FileIdentity> {
        match self {
            FilesystemCommitOutcome::Committed(snapshot) => Some(&snapshot.live_identity),
            _ => None,
        }
    }
}

/// Why [`FilesystemCommitOutcome::NotStarted`] fired. Every variant here
/// implies no participant was mutated by this attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryReason {
    /// `stage_name` has no object at all — there is nothing to commit.
    StageAbsent,
    /// The stage and live objects report different [`ObjectKind`]s (for
    /// example a file where a directory currently lives). A kind-changing
    /// replacement is a different operation than "commit a new version of
    /// this object" and this adapter does not decide how to handle it —
    /// see the module doc's kind-mismatch section.
    ObjectKindMismatch,
    /// Either participant is [blocked][ReplacementEligibility::Blocked]
    /// from replacement at all (a hardlinked or special object) — see
    /// [`classify_replacement_eligibility`].
    ReplacementNotEligible(BlockedObjectReason),
    /// This volume's atomic-exchange primitive is not confirmed
    /// [`Capability::Supported`]. Refused outright rather than downgraded
    /// to a plain, clobbering rename — see the module doc.
    UnsupportedOnThisVolume,
    /// The destination was re-checked absent immediately before the
    /// no-replace move, but the move itself still failed because
    /// something appeared there in between (or the no-replace primitive
    /// itself is unavailable on this volume — the two are not
    /// distinguished, since a caller's response to either is identical:
    /// nothing was touched, try again later). Never mapped to a
    /// clobbering fallback.
    DestinationDidNotStayAbsent,
    /// An I/O failure unrelated to any of the above, encountered before
    /// any mutating syscall in this attempt was issued (for example
    /// failing to open the stage object at all).
    Io(io::ErrorKind),
    /// `live_name` is identity-equal to the sync root directory itself.
    /// Artefacts live beside their target specifically to guarantee they
    /// share a filesystem with it; the root's own parent is outside the
    /// link (a different filesystem, possibly unwritable, and in any case
    /// not this module's to touch), so there is no safe place to put an
    /// artefact for a commit that would displace the root. Refused
    /// outright rather than silently placing the artefact one level up,
    /// which would be invisible to every reserved-namespace and link-
    /// membership predicate that only ever looks at paths inside the root.
    TargetIsSyncRoot,
    /// The object freshly observed at `stage_name`, immediately before any
    /// mutation, is not provably the same object
    /// `expected_stage_identity` names. This covers both
    /// [`IdentityComparison::DefinitelyDifferent`] (a real substitution)
    /// and [`IdentityComparison::Ambiguous`] (the comparison could not
    /// rule reuse out) — see [`check_stage_identity_matches_expected`]'s
    /// doc for why the ambiguous case is refused here rather than passed.
    /// Something other than this commit's own preparation step replaced
    /// the staged object between `prepare_target` returning and this
    /// commit attempt running.
    StageIdentityMismatch,
}

/// An already-open handle to the directory a commit's participants live
/// in, per the module doc's directory-relative discipline.
///
/// On Windows this still records the directory's path (`ReplaceFileW` and
/// `MoveFileExW` have no directory-fd-relative form at the Win32 level —
/// reaching one would mean the native `NtCreateFile`/object-manager API,
/// which this phase does not add), so the redirection race the Unix path
/// closes is a real, currently-unaddressed residual on Windows. Stated
/// plainly because it cannot be verified here: no Windows host was
/// available to test any of this platform's code, and it is a deliberate
/// scope limitation, not an accident.
pub struct ParentDirHandle {
    #[cfg(unix)]
    dir: File,
    base_path: PathBuf,
}

/// Failure modes for [`ParentDirHandle::create_artefact`].
#[derive(Debug)]
pub enum CreateArtefactError {
    /// The requested `(kind, id)` pair does not produce a valid artefact
    /// name at all — see [`artefact_component_name`]. Nothing was
    /// attempted on disk.
    Name(ArtefactNameError),
    /// Something already exists at the artefact's path. This method never
    /// deletes to make room for its own creation: an artefact-shaped name
    /// with no owning journal row is exactly the collision
    /// [`RootAuthorityError::ReservedNamespaceCollision`] exists for elsewhere in
    /// this codebase, and this fails the same way for the same reason.
    /// There is no journal in this phase for `create_artefact` to consult,
    /// so "no owner found" and "an owner exists but this call cannot see
    /// it" are indistinguishable here — stated plainly rather than implying
    /// ownership is checked, since it is not: every collision is treated
    /// as owned by something else and left untouched.
    Collision(RootAuthorityError),
    /// A real I/O failure other than the collision above.
    Io(io::Error),
}

impl ParentDirHandle {
    #[cfg(unix)]
    pub fn open(path: &Path) -> io::Result<ParentDirHandle> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(path)?;
        Ok(ParentDirHandle { dir, base_path: path.to_path_buf() })
    }

    #[cfg(not(unix))]
    pub fn open(path: &Path) -> io::Result<ParentDirHandle> {
        if !path.is_dir() {
            return Err(io::Error::new(io::ErrorKind::NotADirectory, "not a directory"));
        }
        Ok(ParentDirHandle { base_path: path.to_path_buf() })
    }

    /// The directory's own path, for building a path to a named
    /// participant for a post-commit identity read. Not used by any
    /// mutating operation on Unix (those go through the directory file
    /// descriptor instead); it is what a Windows implementation has
    /// instead of a descriptor at all — see the struct doc.
    pub fn path(&self) -> &Path {
        &self.base_path
    }

    /// This directory's own identity, observed through the handle this
    /// struct already holds rather than by re-resolving `self.base_path`.
    /// On Unix this is [`DirectoryIdentity::observe_handle`] on the open
    /// directory descriptor — an `fstat`-shaped read that names nothing,
    /// so there is no path for a racing replace to land on between this
    /// call and whatever the caller does next with the same handle. A
    /// caller that verifies via this method and then mutates through this
    /// same `ParentDirHandle` (rather than opening a second one, or a
    /// caller that verified by path and now acts by path) never has a
    /// re-resolution window for an identity comparison to be needed to
    /// close in the first place — see `early_physical_recovery`'s
    /// `recover_epoch`/`cleanup_unstarted_artefact` for the caller this
    /// method exists for.
    ///
    /// Windows has no directory-fd-relative primitive to hold open this
    /// way (see the struct doc), so there this still re-resolves
    /// `base_path` — a real, currently-unaddressed residual there, stated
    /// plainly rather than implied closed.
    #[cfg(unix)]
    pub fn identity(&self) -> io::Result<DirectoryIdentity> {
        DirectoryIdentity::observe_handle(&self.dir)
    }

    #[cfg(not(unix))]
    pub fn identity(&self) -> io::Result<DirectoryIdentity> {
        DirectoryIdentity::observe_path(&self.base_path)
    }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        self.dir.as_raw_fd()
    }

    fn join(&self, name: &OsStr) -> PathBuf {
        self.base_path.join(name)
    }

    /// Creates a new artefact directly under this directory: exclusive
    /// (never replaces an existing object under the computed name),
    /// directory-handle-relative on Unix (not a second string-path lookup
    /// that could be redirected between naming and creation), and never
    /// follows a symlink already at that name. The name itself is not
    /// invented here — it is [`artefact_component_name`]'s job to name and
    /// length-bound it (failing rather than truncating on an oversized
    /// `id`), reused as-is.
    ///
    /// Returns the artefact's own name alongside the open file, since the
    /// caller supplied only the `(kind, id)` pair that produced it.
    #[cfg(unix)]
    pub fn create_artefact(
        &self,
        kind: ArtefactKind,
        id: &str,
    ) -> Result<(String, File), CreateArtefactError> {
        use std::os::unix::io::FromRawFd;

        let name = artefact_component_name(kind, id).map_err(CreateArtefactError::Name)?;
        let name_c = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::CString::new(OsStr::new(&name).as_bytes()).map_err(|_| {
                CreateArtefactError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "artefact name contains a NUL byte",
                ))
            })?
        };
        // `O_CREAT|O_EXCL` is POSIX-guaranteed to fail with `EEXIST`
        // rather than follow a symlink already at the final path
        // component, even without `O_NOFOLLOW` — that flag is included
        // anyway to state the no-traversal intent explicitly rather than
        // rely on a reader recalling the O_EXCL interaction.
        //
        // `O_RDWR`, not `O_WRONLY`: every current production caller
        // (`optimistic_placement`'s Linux `clone_whole_file`/
        // `range_clone_whole_file`) stages content into this handle and
        // then reads it back through the same fd (`try_clone` + `seek` +
        // `read`) to hash-verify it in `finish_staged_file`. `O_WRONLY`
        // made that read fail with `EBADF` ("bad file descriptor" is
        // POSIX's error for a read attempted on a write-only descriptor,
        // not a filesystem-support signal) — reproducible on any real
        // Linux filesystem, not a platform-specific defect. Measured
        // (2026-07-27): identical `EBADF` at the same call site on
        // overlayfs, real ext4, and XFS freshly formatted with
        // `reflink=1` — including the XFS case, where `FICLONE` genuinely
        // succeeds. That the failure did not vary with whether the clone
        // syscall itself could succeed is exactly what this fd-permissions
        // explanation predicts and a filesystem-capability explanation
        // does not: the break is in the read-back step every path shares
        // *after* the clone/copy already landed, not in cloning itself.
        // `O_RDWR` keeps the exclusive-create/no-follow guarantees above
        // unchanged and costs nothing on the paths that never read the
        // handle back.
        let flags =
            libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_RDWR | libc::O_CLOEXEC;
        // SAFETY: `self.as_raw_fd()` is a valid, open directory descriptor
        // for the duration of this call; `name_c` is a valid
        // NUL-terminated string; the variadic `mode` argument is required
        // whenever `O_CREAT` is set and is otherwise ignored (masked by
        // the process umask on actual creation).
        let fd = unsafe {
            libc::openat(self.as_raw_fd(), name_c.as_ptr(), flags, 0o600 as libc::c_uint)
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EEXIST) => Err(CreateArtefactError::Collision(
                    RootAuthorityError::ReservedNamespaceCollision(
                        self.join(OsStr::new(&name)).display().to_string(),
                    ),
                )),
                _ => Err(CreateArtefactError::Io(err)),
            };
        }
        // SAFETY: `fd` was just returned by the successful `openat` call
        // above, is a valid open file descriptor, and is not used or
        // closed anywhere else — `File` takes sole ownership of it here.
        let file = unsafe { File::from_raw_fd(fd) };
        Ok((name, file))
    }

    /// Non-Unix equivalent: still exclusive and still fails rather than
    /// truncates an oversized name, but not directory-handle-relative —
    /// see the struct doc for why no such primitive exists at the Win32
    /// level. `create_new` maps to Windows' `CREATE_NEW` disposition,
    /// which documents failing with "already exists" against a reparse
    /// point or symlink already at that name rather than following it —
    /// UNVERIFIED, no Windows host was available to confirm this branch.
    #[cfg(not(unix))]
    pub fn create_artefact(
        &self,
        kind: ArtefactKind,
        id: &str,
    ) -> Result<(String, File), CreateArtefactError> {
        let name = artefact_component_name(kind, id).map_err(CreateArtefactError::Name)?;
        let path = self.join(OsStr::new(&name));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => Ok((name, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                Err(CreateArtefactError::Collision(RootAuthorityError::ReservedNamespaceCollision(
                    path.display().to_string(),
                )))
            }
            Err(e) => Err(CreateArtefactError::Io(e)),
        }
    }

    /// Opens an *existing* child of this directory by name, directory-
    /// handle-relative and never following a terminal symlink at that name
    /// — the read-side counterpart to [`Self::create_artefact`]'s
    /// write-side no-follow-relative open. Added for `custody_transfer`'s
    /// source-swap defect: a caller holds the returned handle across its
    /// own check-then-rename sequence and re-derives identity from it
    /// (`FileIdentity::observe_handle`) instead of re-resolving `name` by
    /// path a second time. A handle's identity is bound to the inode it was
    /// opened against, not to whatever name currently points at that inode
    /// — so it stays trustworthy even if the *name* this method opened is
    /// renamed out from under it by another actor afterward, which is
    /// exactly the race a purely path-based check-then-rename cannot detect
    /// (see `custody_transfer::transfer_to_custody_unchecked`'s own doc for
    /// what this closes and what it does not: proving after the fact that
    /// the object a rename actually moved is this handle's object, not
    /// preventing the rename of the name out from under the check in the
    /// first place — there is no atomic check-and-rename primitive here to
    /// prevent that).
    ///
    /// Only meant to be called once a caller has already classified `name`
    /// as a plain regular file or a plain symlink via a prior path-based
    /// observation — the two kinds this crate ever renames into custody
    /// (see `fs_identity::classify_replacement_eligibility`). Every other
    /// kind (FIFO, socket, device node, directory) is deliberately never
    /// opened here: opening a FIFO with no writer present can block
    /// indefinitely, and opening a device node can have side effects
    /// unrelated to identity — the same hazard `fs_identity::generation_
    /// from_path`'s own doc already documents for exactly this reason.
    /// Callers that have not first excluded those kinds must not call this.
    ///
    /// A plain `O_NOFOLLOW` open is tried first — full read/ioctl access on
    /// the returned handle, in particular `FS_IOC_GETVERSION`
    /// (`fs_identity::generation_from_handle`'s strongest reuse
    /// discriminator), which an `O_PATH`/`O_SYMLINK` handle cannot support.
    /// This succeeds immediately for a regular file. For a symlink it fails
    /// with `ELOOP`, the one case this falls back to the no-follow-capable
    /// open shape documented on each platform's implementation below.
    /// `O_NONBLOCK` is included on every attempt regardless: harmless for a
    /// regular file or symlink, and cheap insurance against ever blocking
    /// if a future change to the caller's kind check let something else
    /// through.
    #[cfg(target_os = "linux")]
    pub fn open_child_no_follow(&self, name: &OsStr) -> io::Result<File> {
        use std::os::unix::io::FromRawFd;
        let name_c = cstring_for_open(name)?;
        let dirfd = self.as_raw_fd();
        let plain_flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        // SAFETY: `dirfd` is a valid, open directory descriptor for the
        // duration of this call; `name_c` is a valid NUL-terminated string.
        let fd = unsafe { libc::openat(dirfd, name_c.as_ptr(), plain_flags) };
        if fd >= 0 {
            // SAFETY: `fd` was just returned by the successful `openat`
            // call above, is open, and is not used or closed anywhere else.
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ELOOP) {
            return Err(err);
        }
        // `name` names a symlink: `O_PATH | O_NOFOLLOW` is the documented
        // way to obtain a handle to the symlink entry itself (never its
        // target) on Linux — `fstat` on the result reports the link's own
        // metadata, exactly like `symlink_metadata` does for a path.
        let path_flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: same as above.
        let fd = unsafe { libc::openat(dirfd, name_c.as_ptr(), path_flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: same as above.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// macOS equivalent of [`Self::open_child_no_follow`] above — see that
    /// method's doc for the full contract and rationale. `O_SYMLINK` is the
    /// no-follow-capable fallback here (macOS has no `O_PATH`): documented
    /// to open the symlink entry itself when `name` names one.
    #[cfg(target_os = "macos")]
    pub fn open_child_no_follow(&self, name: &OsStr) -> io::Result<File> {
        use std::os::unix::io::FromRawFd;
        let name_c = cstring_for_open(name)?;
        let dirfd = self.as_raw_fd();
        let plain_flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        // SAFETY: `dirfd` is a valid, open directory descriptor for the
        // duration of this call; `name_c` is a valid NUL-terminated string.
        let fd = unsafe { libc::openat(dirfd, name_c.as_ptr(), plain_flags) };
        if fd >= 0 {
            // SAFETY: as above.
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ELOOP) {
            return Err(err);
        }
        let symlink_flags = libc::O_SYMLINK | libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
        // SAFETY: as above.
        let fd = unsafe { libc::openat(dirfd, name_c.as_ptr(), symlink_flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// No directory-handle-relative, guaranteed-non-following open is wired
    /// up for this Unix variant in this phase (only Linux and macOS are,
    /// matching [`Self::rename_child_no_replace`]'s own split) — fail
    /// closed rather than approximate one.
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    pub fn open_child_no_follow(&self, _name: &OsStr) -> io::Result<File> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Non-Unix equivalent: not directory-handle-relative — see the struct
    /// doc for why no such Win32-level primitive exists. A plain path-based
    /// open, which — unlike the Unix branches above — does not guarantee
    /// non-following for a Windows reparse point; a real, currently-
    /// unaddressed residual there, stated plainly rather than implied
    /// closed, matching every other Windows branch in this module.
    /// UNVERIFIED, no Windows host was available to confirm this branch.
    #[cfg(not(unix))]
    pub fn open_child_no_follow(&self, name: &OsStr) -> io::Result<File> {
        OpenOptions::new().read(true).open(self.join(name))
    }

    /// Removes a plain regular file by name, directly under this
    /// directory — the removal counterpart to [`Self::create_artefact`].
    /// Exists for a caller (early physical recovery) that has already
    /// reconfirmed this handle's directory identity and now needs to
    /// delete an *unstarted* artefact its own journal row named, without
    /// re-resolving a path string that could stop meaning the same
    /// directory between that check and this call.
    ///
    /// Directory-handle-relative on Unix: both the kind check and the
    /// removal itself go through this handle's own directory file
    /// descriptor (`fstatat`/`unlinkat`), so a rename or replacement of the
    /// directory after the caller opened the handle cannot redirect where
    /// this lands — the same guarantee [`Self::create_artefact`] documents
    /// for creation, now for removal.
    ///
    /// Windows has no directory-fd-relative removal primitive at the
    /// Win32 level — the same residual this struct's own doc already
    /// states for `ReplaceFileW`/`MoveFileExW` not having a directory-
    /// handle-relative form. That is the platform's limitation, not a
    /// choice made here: the non-Unix branch below is genuinely two
    /// path-string operations (a metadata check, then a removal) with a
    /// real, if narrow, window between them, and reaching the directory-
    /// relative `NtCreateFile`/object-manager API to close it is out of
    /// scope for this phase, exactly like the rest of this struct's
    /// Windows branch.
    ///
    /// Refuses — removes nothing — unless a fresh, non-symlink-following
    /// check confirms the name is a plain regular file: never a directory,
    /// never a symlink regardless of what it points to, and never
    /// anything this check could not conclusively classify (an
    /// inconclusive check is [`RemoveChildError::Io`], not a best-effort
    /// removal attempt).
    #[cfg(unix)]
    pub fn remove_child(&self, name: &OsStr) -> Result<(), RemoveChildError> {
        use std::os::unix::ffi::OsStrExt;

        let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            RemoveChildError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "name contains a NUL byte",
            ))
        })?;
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `self.as_raw_fd()` is a valid, open directory descriptor
        // for the duration of this call; `name_c` is a valid NUL-
        // terminated string; `stat_buf` is a valid out-parameter of the
        // correct size. `AT_SYMLINK_NOFOLLOW` classifies the entry itself,
        // never a symlink's target.
        let ret = unsafe {
            libc::fstatat(
                self.as_raw_fd(),
                name_c.as_ptr(),
                &mut stat_buf,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if ret != 0 {
            return match io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOENT) => Err(RemoveChildError::Absent),
                _ => Err(RemoveChildError::Io(io::Error::last_os_error())),
            };
        }
        if stat_buf.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(RemoveChildError::NotARegularFile);
        }
        // SAFETY: as above. The `0` flags argument (no `AT_REMOVEDIR`)
        // requests file removal; passed a directory name it fails with
        // `EISDIR`/`EPERM` rather than recursing — moot here regardless,
        // since the kind check above already refused any non-regular-file
        // name before this call is reached.
        let ret = unsafe { libc::unlinkat(self.as_raw_fd(), name_c.as_ptr(), 0) };
        if ret != 0 {
            return Err(RemoveChildError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Non-Unix equivalent: still refuses anything but a plain regular
    /// file and still fails closed on an inconclusive check, but not
    /// directory-handle-relative — see this method's own doc for why no
    /// such primitive exists at the Win32 level. UNVERIFIED, no Windows
    /// host was available to confirm this branch (matching
    /// [`Self::create_artefact`]'s equivalent non-Unix branch).
    #[cfg(not(unix))]
    pub fn remove_child(&self, name: &OsStr) -> Result<(), RemoveChildError> {
        let path = self.join(name);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(RemoveChildError::Absent),
            Err(e) => return Err(RemoveChildError::Io(e)),
        };
        // `symlink_metadata` never follows a terminal symlink, so
        // `is_file()` is already false for one — never true for anything
        // but a plain regular file.
        if !metadata.is_file() {
            return Err(RemoveChildError::NotARegularFile);
        }
        std::fs::remove_file(&path).map_err(RemoveChildError::Io)
    }

    /// Removes a plain regular file by name, directly under this directory,
    /// exactly like [`Self::remove_child`] — with one addition: the object
    /// currently at `name` must also compare
    /// [`IdentityComparison::SameObject`] against `expected_identity`
    /// before anything is unlinked. Added for `early_physical_recovery`'s
    /// unstarted-artefact cleanup, which names a `stage_path` by a journal
    /// row recorded at some earlier point in time — by the time recovery
    /// runs, a plain-regular-file check alone only proves the current
    /// occupant's *kind*, never that it is the same object the row named,
    /// so a caller about to delete on that row's authority needs more than
    /// [`Self::remove_child`] gives it.
    ///
    /// [`RemoveChildIdentityError::IdentityMismatch`] covers both
    /// [`IdentityComparison::DefinitelyDifferent`] and
    /// [`IdentityComparison::Ambiguous`] — an inconclusive comparison is
    /// never treated as authorization to delete, matching this whole
    /// module's convention that an unproven case fails closed rather than
    /// guesses.
    ///
    /// On Unix, the object is opened by name through this handle's own
    /// directory descriptor (`O_NOFOLLOW`, so a symlink is refused rather
    /// than followed) and its identity is read from that open handle via
    /// [`FileIdentity::observe_handle`] — never by re-resolving `name` as a
    /// path string, which would reopen exactly the redirection window this
    /// handle exists to close. What remains is the same narrow,
    /// already-accepted window [`Self::remove_child`] itself has between
    /// its own kind check and its `unlinkat`: nothing at the POSIX level
    /// makes "unlink only if the name still refers to the object just
    /// identified" one atomic operation, so a replacement landing in the
    /// instant between this method's identity read and its `unlinkat` call
    /// is a real, narrow residual — not a window this method introduces,
    /// the same one already documented on `remove_child`.
    ///
    /// Windows has no directory-fd-relative open primitive either (see
    /// [`ParentDirHandle`]'s own struct doc), so the non-Unix branch below
    /// is a path-string check-then-remove pair with a real, wider window
    /// between the identity read and the removal — the same platform
    /// limitation already stated for [`Self::remove_child`]'s non-Unix
    /// branch, not a choice made here. UNVERIFIED, no Windows host was
    /// available to confirm this branch.
    #[cfg(unix)]
    pub fn remove_child_if_identity_matches(
        &self,
        name: &OsStr,
        expected_identity: &FileIdentity,
        birth_time_granularity: TimestampGranularity,
    ) -> Result<(), RemoveChildIdentityError> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;

        let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            RemoveChildIdentityError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "name contains a NUL byte",
            ))
        })?;
        // `O_NONBLOCK` matters here in a way it would not for a plain
        // regular file: without it, opening a FIFO for reading blocks
        // until a writer opens the other end, which would make this
        // recovery-time call hang on an object this method is about to
        // refuse anyway. `O_NOFOLLOW` refuses a symlink outright (`ELOOP`)
        // rather than opening whatever it points to.
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        // SAFETY: `self.as_raw_fd()` is a valid, open directory descriptor
        // for the duration of this call; `name_c` is a valid NUL-
        // terminated string.
        let fd = unsafe { libc::openat(self.as_raw_fd(), name_c.as_ptr(), flags, 0) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::ENOENT) => Err(RemoveChildIdentityError::Absent),
                Some(libc::ELOOP) => Err(RemoveChildIdentityError::NotARegularFile),
                _ => Err(RemoveChildIdentityError::Io(err)),
            };
        }
        // SAFETY: `fd` was just returned by the successful `openat` call
        // above, is a valid open file descriptor, and is not used or
        // closed anywhere else — `File` takes sole ownership of it here.
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(RemoveChildIdentityError::Io)?;
        if !metadata.is_file() {
            return Err(RemoveChildIdentityError::NotARegularFile);
        }
        let observed = FileIdentity::observe_handle(&file).map_err(RemoveChildIdentityError::Io)?;
        // Capability-split migration note (increment one, no behaviour
        // change): this method's only caller is `early_physical_recovery::
        // cleanup_unstarted_artefact`, comparing against `epoch.staged_
        // identity` read back from the database — a crash-recovery pass by
        // construction, so this comparison spans a restart. The object
        // itself (a Stage artefact) is one the engine wrote, which would
        // otherwise point at `stable_owned_marker_identity` — but that
        // field's weaker same-boot predicate (D1b) is explicitly usable
        // ONLY within one boot, never across a restart, so it does not
        // cover this call site either. AMBIGUOUS under the source/marker
        // split: conservatively treated as depending on
        // `stable_source_identity`, since nothing here may assume the
        // not-yet-built durable-claim mechanism `stable_owned_marker_
        // identity` will eventually need to survive a restart.
        match observed.compare(expected_identity, birth_time_granularity) {
            IdentityComparison::SameObject => {}
            IdentityComparison::DefinitelyDifferent | IdentityComparison::Ambiguous(_) => {
                return Err(RemoveChildIdentityError::IdentityMismatch);
            }
        }
        drop(file);
        // SAFETY: as above. The `0` flags argument (no `AT_REMOVEDIR`)
        // requests file removal.
        let ret = unsafe { libc::unlinkat(self.as_raw_fd(), name_c.as_ptr(), 0) };
        if ret != 0 {
            return Err(RemoveChildIdentityError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Non-Unix equivalent — see this method's own doc for the wider,
    /// real window this branch has relative to the Unix one above.
    /// UNVERIFIED, no Windows host was available to confirm this branch.
    #[cfg(not(unix))]
    pub fn remove_child_if_identity_matches(
        &self,
        name: &OsStr,
        expected_identity: &FileIdentity,
        birth_time_granularity: TimestampGranularity,
    ) -> Result<(), RemoveChildIdentityError> {
        let path = self.join(name);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(RemoveChildIdentityError::Absent)
            }
            Err(e) => return Err(RemoveChildIdentityError::Io(e)),
        };
        if !metadata.is_file() {
            return Err(RemoveChildIdentityError::NotARegularFile);
        }
        let observed = FileIdentity::observe_path(&path).map_err(RemoveChildIdentityError::Io)?;
        // Capability-split migration note: see the `#[cfg(unix)]` sibling
        // of this method above — same call site, same AMBIGUOUS
        // classification (engine-written Stage artefact, but compared
        // across a restart via `early_physical_recovery`).
        match observed.compare(expected_identity, birth_time_granularity) {
            IdentityComparison::SameObject => {}
            IdentityComparison::DefinitelyDifferent | IdentityComparison::Ambiguous(_) => {
                return Err(RemoveChildIdentityError::IdentityMismatch);
            }
        }
        std::fs::remove_file(&path).map_err(RemoveChildIdentityError::Io)
    }

    /// Renames a child of this directory to a different name **under this
    /// same directory** — never a copy, and never a rename into any other
    /// directory. Added for `custody_transfer`'s same-filesystem custody
    /// move (design §12: "the inode is moved by same-filesystem rename,
    /// never copy"): both `from` and `to` are resolved against this
    /// handle's own directory file descriptor in a single
    /// `renameat`-family call (`renameat2(RENAME_NOREPLACE)` on Linux,
    /// `renameatx_np(RENAME_EXCL)` on macOS), so the kernel can only ever
    /// place the result inside the one directory — and therefore the one
    /// filesystem — this handle already names. There is no path string
    /// naming a different directory for either side to be redirected to,
    /// so this is a structural guarantee that both names share a
    /// filesystem, not a check performed and then trusted: unlike a
    /// check-then-rename against two independently resolved path strings,
    /// there is no window in which the two names could end up resolving to
    /// different filesystems. A caller cannot even construct the "wrong"
    /// call — the signature takes bare component names, not paths, the
    /// same discipline [`Self::create_artefact`]/[`Self::remove_child`]
    /// already use.
    ///
    /// [`RenameChildError::CrossFilesystem`] (mapped from the syscall's own
    /// `EXDEV`) is still handled explicitly even though this method's own
    /// discipline should make it unreachable in the current architecture
    /// (every artefact kind lives beside its target — design §10). It is
    /// kept as a defensive, fail-closed branch rather than an
    /// `unreachable!()`: relying on `EXDEV` *alone*, with no structural
    /// guarantee behind it, would still be an incomplete proof on a
    /// remote/network filesystem, where a client's rename() can report
    /// success across what the OS treats as a single mount without that
    /// necessarily being the true atomic, constant-time local operation
    /// this method's callers require (see [`yadorilink_root_authority::fs_capabilities::
    /// DurabilityLevel::BestEffortRemoteFilesystem`]'s doc for the same
    /// local-vs-remote distinction). This method's real proof is the
    /// single-dirfd construction above; the `EXDEV` branch is only ever
    /// reached if that invariant is somehow violated, and it fails closed
    /// rather than falling back to copying bytes either way.
    ///
    /// Refuses — renames nothing — if `to` already exists, via the
    /// platform's atomic no-replace primitive itself: never a
    /// check-then-rename, which would reopen the exact collision race the
    /// primitive exists to close.
    #[cfg(target_os = "linux")]
    pub fn rename_child_no_replace(
        &self,
        from: &OsStr,
        to: &OsStr,
    ) -> Result<(), RenameChildError> {
        let from_c = cstring_for_rename(from)?;
        let to_c = cstring_for_rename(to)?;
        let dirfd = self.as_raw_fd();
        let ret = loop {
            // SAFETY: `dirfd` is a valid, open directory descriptor for the
            // duration of this call; `from_c`/`to_c` are valid
            // NUL-terminated strings kept alive across the call. Called
            // through the raw syscall number for the same reason
            // `fs_commit`'s own commit-path `rename_no_replace` is:
            // glibc only exports `renameat2` from 2.28, and uClibc does
            // not export it at all.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    dirfd,
                    from_c.as_ptr(),
                    dirfd,
                    to_c.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if ret != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break ret;
            }
        };
        if ret == 0 {
            return Ok(());
        }
        classify_rename_failure(self, to, io::Error::last_os_error())
    }

    /// macOS equivalent of [`Self::rename_child_no_replace`] above — same
    /// single-dirfd construction, same refusal semantics, only the
    /// no-replace primitive itself differs (`renameatx_np(RENAME_EXCL)`
    /// rather than `renameat2(RENAME_NOREPLACE)`), mirroring the same split
    /// `fs_commit`'s own commit-path `exchange`/`rename_no_replace`
    /// functions already use between these two platforms.
    #[cfg(target_os = "macos")]
    pub fn rename_child_no_replace(
        &self,
        from: &OsStr,
        to: &OsStr,
    ) -> Result<(), RenameChildError> {
        let from_c = cstring_for_rename(from)?;
        let to_c = cstring_for_rename(to)?;
        let dirfd = self.as_raw_fd();
        let ret = loop {
            // SAFETY: same as the Linux branch above.
            let ret = unsafe {
                libc::renameatx_np(dirfd, from_c.as_ptr(), dirfd, to_c.as_ptr(), libc::RENAME_EXCL)
            };
            if ret != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break ret as i64;
            }
        };
        if ret == 0 {
            return Ok(());
        }
        classify_rename_failure(self, to, io::Error::last_os_error())
    }

    /// No atomic no-replace rename primitive is wired up for this Unix
    /// variant in this phase (only Linux and macOS are, matching this
    /// module's `commit_placement` split) — fail closed rather than fall
    /// back to a non-atomic check-then-rename, which would reopen the
    /// exact collision race this primitive exists to close.
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    pub fn rename_child_no_replace(
        &self,
        _from: &OsStr,
        _to: &OsStr,
    ) -> Result<(), RenameChildError> {
        Err(RenameChildError::UnsupportedOnThisVolume)
    }

    /// Non-Unix (Windows) equivalent: not directory-handle-relative — see
    /// this struct's own doc for why no such Win32-level primitive exists
    /// — but still atomic-no-replace via `MoveFileExW` with no flags (the
    /// same primitive `fs_commit`'s own commit-path absent-destination
    /// branch already uses). Declared locally rather than exposing the
    /// commit path's private `mod platform` FFI items. UNVERIFIED, no
    /// Windows host was available to confirm this branch (matching every
    /// other Windows branch in this module).
    #[cfg(not(unix))]
    pub fn rename_child_no_replace(
        &self,
        from: &OsStr,
        to: &OsStr,
    ) -> Result<(), RenameChildError> {
        use std::os::windows::ffi::OsStrExt;

        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(
                lp_existing_file_name: *const u16,
                lp_new_file_name: *const u16,
                dw_flags: u32,
            ) -> i32;
            fn GetLastError() -> u32;
        }
        fn to_wide(s: &OsStr) -> Vec<u16> {
            s.encode_wide().chain(std::iter::once(0)).collect()
        }

        let from_path = self.join(from);
        let to_path = self.join(to);
        let from_w = to_wide(from_path.as_ref());
        let to_w = to_wide(to_path.as_ref());
        // SAFETY: both buffers are valid NUL-terminated UTF-16 strings kept
        // alive for the duration of the call.
        let ok = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), 0) };
        if ok != 0 {
            return Ok(());
        }
        let last_error = unsafe { GetLastError() };
        const ERROR_FILE_NOT_FOUND: u32 = 2;
        const ERROR_PATH_NOT_FOUND: u32 = 3;
        const ERROR_ALREADY_EXISTS: u32 = 183;
        const ERROR_FILE_EXISTS: u32 = 80;
        const ERROR_NOT_SAME_DEVICE: u32 = 17;
        match last_error {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Err(RenameChildError::Absent),
            ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS => Err(RenameChildError::Collision(
                RootAuthorityError::ReservedNamespaceCollision(to_path.display().to_string()),
            )),
            ERROR_NOT_SAME_DEVICE => Err(RenameChildError::CrossFilesystem),
            _ => Err(RenameChildError::Io(io::Error::from_raw_os_error(last_error as i32))),
        }
    }
}

/// Shared errno classification for [`ParentDirHandle::rename_child_no_replace`]'s
/// Linux and macOS branches — kept as one function so the two platform
/// bodies above differ only in which syscall they issue, not in how they
/// interpret the result.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn classify_rename_failure(
    handle: &ParentDirHandle,
    to: &OsStr,
    err: io::Error,
) -> Result<(), RenameChildError> {
    match err.raw_os_error() {
        Some(libc::ENOENT) => Err(RenameChildError::Absent),
        Some(libc::EEXIST) => Err(RenameChildError::Collision(
            RootAuthorityError::ReservedNamespaceCollision(handle.join(to).display().to_string()),
        )),
        Some(libc::EXDEV) => Err(RenameChildError::CrossFilesystem),
        Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::ENOTSUP) => {
            Err(RenameChildError::UnsupportedOnThisVolume)
        }
        _ => Err(RenameChildError::Io(err)),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn cstring_for_rename(name: &OsStr) -> Result<std::ffi::CString, RenameChildError> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        RenameChildError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "name contains a NUL byte",
        ))
    })
}

/// [`ParentDirHandle::open_child_no_follow`]'s own NUL-byte-safe name
/// encoding — same construction as [`cstring_for_rename`], returning a
/// plain `io::Result` since that method's error type is `io::Error`, not
/// [`RenameChildError`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn cstring_for_open(name: &OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains a NUL byte"))
}

/// Failure modes for [`ParentDirHandle::remove_child`].
#[derive(Debug)]
pub enum RemoveChildError {
    /// Nothing exists at that name. Fail-closed, not treated as an
    /// already-satisfied no-op: a caller that expected something there and
    /// finds nothing has a different problem than "already removed", and
    /// conflating the two would hide it from that caller.
    Absent,
    /// The name exists but is not a plain regular file (a directory, a
    /// symlink — whether or not its target is a regular file — or any
    /// other object kind). This method never removes anything else; asking
    /// it to is a refusal, not a best-effort partial action.
    NotARegularFile,
    /// A real I/O failure, including one that left "what kind of object is
    /// this" undetermined. Fail-closed: nothing is removed on an
    /// inconclusive check.
    Io(io::Error),
}

/// Failure modes for [`ParentDirHandle::remove_child_if_identity_matches`].
#[derive(Debug)]
pub enum RemoveChildIdentityError {
    /// Nothing exists at that name — see [`RemoveChildError::Absent`]'s
    /// identical reasoning.
    Absent,
    /// The name exists but is not a plain regular file — see
    /// [`RemoveChildError::NotARegularFile`]'s identical reasoning.
    NotARegularFile,
    /// The name exists and is a plain regular file, but it does not
    /// compare [`IdentityComparison::SameObject`] against the identity the
    /// caller expected — either [`IdentityComparison::DefinitelyDifferent`]
    /// or [`IdentityComparison::Ambiguous`]. Nothing is removed: an
    /// unproven case is never authorization to delete.
    IdentityMismatch,
    /// A real I/O failure, including one that left identity or kind
    /// undetermined. Fail-closed: nothing is removed on an inconclusive
    /// check.
    Io(io::Error),
}

/// Failure modes for [`ParentDirHandle::rename_child_no_replace`].
#[derive(Debug)]
pub enum RenameChildError {
    /// Nothing exists at `from`. Fail-closed — see [`RemoveChildError::
    /// Absent`]'s identical reasoning.
    Absent,
    /// Something already exists at `to`. Refused by the platform's own
    /// atomic no-replace primitive; nothing was touched.
    Collision(RootAuthorityError),
    /// The rename crossed filesystems — see [`ParentDirHandle::
    /// rename_child_no_replace`]'s own doc for why this should be
    /// unreachable given its single-dirfd discipline, and why it is still
    /// handled explicitly rather than assumed away.
    CrossFilesystem,
    /// This volume or platform does not support the atomic no-replace
    /// primitive this method relies on. Refused outright rather than
    /// falling back to a non-atomic check-then-rename.
    ///
    /// Constructed only on Unix, where the primitive can report absence.
    /// The Windows branch has no equivalent signal, so the variant is dead
    /// there -- kept rather than `cfg`-gated away, because a caller matching
    /// on this enum should not have to change shape per platform.
    #[cfg_attr(windows, allow(dead_code))]
    UnsupportedOnThisVolume,
    /// A real I/O failure unrelated to the above.
    Io(io::Error),
}

/// One commit attempt: move `stage_name` into `live_name`, retaining
/// whatever `live_name` held before as the preimage (see
/// [`FilesystemCommitOutcome::Committed`]'s doc for where that preimage
/// ends up).
pub struct CommitRequest<'a> {
    pub parent_dir: &'a ParentDirHandle,
    pub stage_name: &'a OsStr,
    pub live_name: &'a OsStr,
    /// Windows only: `ReplaceFileW`'s explicit backup-file argument,
    /// receiving the displaced `live_name` content on success. Ignored on
    /// Linux/macOS, whose atomic exchange has no third path argument and
    /// leaves the displaced content at `stage_name` instead. Required on
    /// every platform so one request shape serves all of them, even
    /// though only Windows reads it.
    pub backup_name: &'a OsStr,
    /// This volume's probed capabilities (from `fs_capabilities`), keyed
    /// the same way the caller already keys its
    /// [`yadorilink_root_authority::fs_capabilities::CapabilityCache`] entries. Consulted,
    /// never re-probed here — probing is `fs_capabilities`'s job, and
    /// probing again on every commit would defeat the point of caching it
    /// there at all.
    pub capabilities: &'a FilesystemSafetyCapabilities,
    /// The sync root directory's own identity — consulted on every commit
    /// to refuse one whose `live_name` turns out to be the root itself
    /// (see [`RetryReason::TargetIsSyncRoot`]). Required, not optional:
    /// making this an `Option` would let a caller omit it and silently
    /// lose the protection, the same fail-open shape as the `link_count:
    /// None` defect this codebase already fixed once today. A caller with
    /// no meaningful root context (there is none in this phase — every
    /// caller is a test) still has to construct a real value; there is no
    /// "I don't have one" escape hatch for something this cheap to
    /// observe and this expensive to get wrong.
    pub sync_root_identity: &'a DirectoryIdentity,
    /// The identity `prepare_target` verified and returned for whatever it
    /// staged at `stage_name`. Required, not optional, for the same reason
    /// `sync_root_identity` above is required: an `Option` here would let a
    /// caller omit it and silently lose the protection it exists for. Between
    /// preparation returning and this commit attempt running, `stage_name` is
    /// an ordinary, visible name in a directory this module does not hold
    /// exclusive access to — any process with write access there can replace
    /// it. Without this field, `commit_placement` would exchange whatever
    /// currently sits at `stage_name` into `live_name` on nothing stronger
    /// than "an object of the right kind is there", which is exactly the
    /// fail-open shape that lets a substituted object get published under
    /// the caller's requested version.
    pub expected_stage_identity: &'a FileIdentity,
}

/// The commit half of a filesystem transaction backend. A later phase's
/// `capabilities`/`prepare_target`/`transfer_to_custody` extend this same
/// role for a specific backend (an ordinary folder, a Mac File Provider
/// extension, a Windows Cloud Files placeholder); this phase models only
/// the two methods every backend needs regardless of how it prepares or
/// takes custody of content.
pub trait FilesystemCommitAdapter {
    fn commit_placement(&self, request: &CommitRequest) -> FilesystemCommitOutcome;

    /// Observes identity for whatever currently exists at `path`, with the
    /// same never-follow-a-terminal-symlink semantics as
    /// [`FileIdentity::observe_path`]. `Ok(None)` for a path with nothing
    /// at it; `Err` only for a real I/O failure trying to find out.
    fn observe_identity(&self, path: &Path) -> io::Result<Option<FileIdentity>>;
}

fn observe_optional(path: &Path) -> io::Result<Option<FileIdentity>> {
    match FileIdentity::observe_path(path) {
        Ok(identity) => Ok(Some(identity)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Checks that `stage` and `live` (when `live` exists) are eligible
/// participants: matching [`ObjectKind`]s, and each individually eligible
/// for replacement at all per [`classify_replacement_eligibility`]. Pure —
/// performs no I/O and mutates nothing.
fn check_participants_eligible(
    stage: &FileIdentity,
    live: Option<&FileIdentity>,
) -> Result<(), RetryReason> {
    if let ReplacementEligibility::Blocked(reason) =
        classify_replacement_eligibility(stage.object_kind, stage.link_count)
    {
        return Err(RetryReason::ReplacementNotEligible(reason));
    }
    let Some(live) = live else {
        return Ok(());
    };
    if let ReplacementEligibility::Blocked(reason) =
        classify_replacement_eligibility(live.object_kind, live.link_count)
    {
        return Err(RetryReason::ReplacementNotEligible(reason));
    }
    // A kind-changing replacement (a directory landing where a regular
    // file lives, or vice versa) is a fundamentally different operation
    // from "commit a new version of this object" and the syscall's own
    // behavior for it varies by platform and kind pair — this adapter
    // refuses explicitly rather than letting that variance decide.
    if stage.object_kind != live.object_kind {
        return Err(RetryReason::ObjectKindMismatch);
    }
    Ok(())
}

/// Refuses a commit whose `live` participant is identity-equal to the sync
/// root directory itself — see [`RetryReason::TargetIsSyncRoot`] for why.
/// Pure — performs no I/O. Compares `volume_identity`/`object_id` directly
/// rather than going through [`FileIdentity::compare`]: that method ranks
/// reuse-safety evidence for two observations taken at different times, and
/// this is instead a same-moment equality check between two observations
/// taken within the same commit attempt, so no reuse-discrimination
/// question arises.
fn check_not_the_sync_root(
    live: Option<&FileIdentity>,
    sync_root_identity: &DirectoryIdentity,
) -> Result<(), RetryReason> {
    let Some(live) = live else {
        return Ok(());
    };
    if live.volume_identity == sync_root_identity.volume_identity
        && live.object_id == sync_root_identity.object_id
    {
        return Err(RetryReason::TargetIsSyncRoot);
    }
    Ok(())
}

/// Checks that `observed_stage` — the object freshly re-observed at
/// `stage_name`, immediately before any mutation — is provably the same
/// object `expected` names. This is the binding that closes the
/// substitution defect: `prepare_target` verifies and returns an identity
/// for whatever it staged, but a caller that never checks that identity
/// again at commit time is trusting an unenforced assumption that nothing
/// touched `stage_name` in between. Anyone with write access to the
/// destination directory can replace the staged name with their own
/// object before this runs; without this check, `commit_placement` would
/// exchange whatever is currently there into `live_name` on nothing
/// stronger than "an object of the right kind is present" (see
/// [`check_participants_eligible`]), publishing someone else's bytes under
/// the caller's requested version.
///
/// Goes through [`FileIdentity::compare`], never a raw field comparison —
/// and treats [`IdentityComparison::Ambiguous`] exactly like
/// [`IdentityComparison::DefinitelyDifferent`], not like a pass. This
/// check exists specifically to prove "same object"; a comparison that
/// cannot rule out reuse is not that proof, and passing it through would
/// reopen the exact fail-open shape this module exists to close (see the
/// module-level "fail-closed" convention this crate follows throughout).
/// Pure — performs no I/O.
fn check_stage_identity_matches_expected(
    observed_stage: &FileIdentity,
    expected: &FileIdentity,
    birth_time_granularity: TimestampGranularity,
) -> Result<(), RetryReason> {
    // Capability-split migration note: this is the one of the nine
    // `compare()` call sites in this crate that classifies UNAMBIGUOUSLY.
    // `expected` traces (via `CommitRequest::expected_stage_identity`, its
    // only production construction site in `orchestrator::run_slice_
    // unchecked`) straight to `PreparedPlacement::staged_identity`, set
    // moments earlier in this same process by `prepare_target` — never
    // decoded from the database. The object is a Stage artefact the engine
    // itself wrote, and the comparison never crosses a restart. Depends on
    // `stable_owned_marker_identity` only.
    match observed_stage.compare(expected, birth_time_granularity) {
        IdentityComparison::SameObject => Ok(()),
        IdentityComparison::DefinitelyDifferent | IdentityComparison::Ambiguous(_) => {
            Err(RetryReason::StageIdentityMismatch)
        }
    }
}

/// The real, ordinary-folder commit adapter — `DirectFilesystemBackend` in
/// the later phase's naming.
pub struct NativeCommitAdapter;

impl FilesystemCommitAdapter for NativeCommitAdapter {
    fn commit_placement(&self, request: &CommitRequest) -> FilesystemCommitOutcome {
        platform::commit_placement(request)
    }

    fn observe_identity(&self, path: &Path) -> io::Result<Option<FileIdentity>> {
        observe_optional(path)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::*;

    /// `EINTR`-retrying wrapper for a raw libc call following the usual C
    /// convention (`-1` with `errno` set on failure). Mirrors
    /// `fs_capabilities`'s `retry_eintr` — not imported from there (that
    /// module's copy is private and takes its own closure shape), but the
    /// same small, well-understood pattern, not a second design.
    fn retry_eintr(mut attempt: impl FnMut() -> (i64, Option<i32>)) -> (i64, Option<i32>) {
        loop {
            let (ret, errno) = attempt();
            if ret != -1 || errno != Some(libc::EINTR) {
                return (ret, errno);
            }
        }
    }

    fn to_cstring(name: &OsStr) -> io::Result<std::ffi::CString> {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains a NUL byte"))
    }

    /// Directory-relative existence check (never follows a terminal
    /// symlink), used for the absent-destination re-check immediately
    /// before the no-replace move.
    fn exists_at(dirfd: std::os::unix::io::RawFd, name: &std::ffi::CStr) -> io::Result<bool> {
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `dirfd` is a valid, open directory file descriptor for
        // the duration of the call; `name` is a valid NUL-terminated
        // string; `stat_buf` is a valid out-parameter of the correct size.
        let ret = unsafe {
            libc::fstatat(dirfd, name.as_ptr(), &mut stat_buf, libc::AT_SYMLINK_NOFOLLOW)
        };
        if ret == 0 {
            return Ok(true);
        }
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT) => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub(super) fn commit_placement(request: &CommitRequest) -> FilesystemCommitOutcome {
        let stage_path = request.parent_dir.join(request.stage_name);
        let stage = match observe_optional(&stage_path) {
            Ok(Some(identity)) => identity,
            Ok(None) => return FilesystemCommitOutcome::NotStarted(RetryReason::StageAbsent),
            Err(e) => return FilesystemCommitOutcome::NotStarted(RetryReason::Io(e.kind())),
        };
        // Defect: bind the freshest possible observation of `stage_name`
        // to `prepare_target`'s verified identity before anything else
        // about this request is trusted — see
        // `check_stage_identity_matches_expected`'s doc. Checked before
        // eligibility/kind classification, not after: those checks exist
        // to classify what is legitimately there, and have nothing
        // meaningful to say about an object that isn't the one this
        // commit was ever supposed to be about.
        //
        // Granularity is measured here, not accepted from `request` — see
        // `check_stage_identity_matches_expected`'s doc for why a caller-
        // supplied value was the actual shape of a defect this crate had
        // to fix (every existing test constructing one hardcoded `Fine`).
        // Probing here makes it structurally impossible to reach this
        // comparison with a wrong or assumed value.
        let granularity = yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(
            request.parent_dir.path(),
        );
        if let Err(reason) = check_stage_identity_matches_expected(
            &stage,
            request.expected_stage_identity,
            granularity,
        ) {
            return FilesystemCommitOutcome::NotStarted(reason);
        }
        let live_path = request.parent_dir.join(request.live_name);
        let live = match observe_optional(&live_path) {
            Ok(live) => live,
            Err(e) => return FilesystemCommitOutcome::NotStarted(RetryReason::Io(e.kind())),
        };
        if let Err(reason) = check_participants_eligible(&stage, live.as_ref()) {
            return FilesystemCommitOutcome::NotStarted(reason);
        }
        if let Err(reason) = check_not_the_sync_root(live.as_ref(), request.sync_root_identity) {
            return FilesystemCommitOutcome::NotStarted(reason);
        }

        let (Ok(stage_c), Ok(live_c)) =
            (to_cstring(request.stage_name), to_cstring(request.live_name))
        else {
            return FilesystemCommitOutcome::NotStarted(RetryReason::Io(
                io::ErrorKind::InvalidInput,
            ));
        };
        let dirfd = request.parent_dir.as_raw_fd();

        if live.is_some() {
            // The exchange path: this volume's atomic-exchange primitive
            // must be confirmed `Supported` before it is ever attempted —
            // an unconfirmed volume is refused outright, never downgraded
            // to a plain rename that would clobber the live object (see
            // the module doc and `RetryReason::UnsupportedOnThisVolume`).
            if !request.capabilities.atomic_exchange.is_supported() {
                return FilesystemCommitOutcome::NotStarted(RetryReason::UnsupportedOnThisVolume);
            }
            let (ret, errno) = exchange(dirfd, &stage_c, &live_c);
            if ret != 0 {
                // `renameat2`/`renameatx_np` are documented atomic: a
                // failure here is a no-op, never a partial swap, so this
                // is always safe to report as `NotStarted` rather than
                // `RequiresRecovery` — unlike the Windows path, which has
                // no such guarantee (see that module's doc).
                return FilesystemCommitOutcome::NotStarted(commit_feature_absence(errno));
            }
            // The exchange swapped the two paths' contents: `live_name`
            // now holds what `stage_name` held, and `stage_name` now
            // holds what `live_name` held — the preimage, per this
            // module's documented per-platform convention.
            let live_identity = match observe_optional(&live_path) {
                Ok(Some(identity)) => identity,
                Ok(None) | Err(_) => {
                    // The exchange itself reported success; a failure to
                    // re-observe what must now be there is exactly the
                    // "attempted, outcome uncertain" shape, even on a
                    // platform whose primitive is normally atomic — the
                    // observation, not the primitive, is what's uncertain
                    // here.
                    return recovery_snapshot(&live_path, &stage_path, None);
                }
            };
            // The exchange put a live object here a moment ago (this is
            // the `live.is_some()` branch), so the exchange -- if it
            // reported success -- necessarily left a preimage at
            // `stage_path`. `Ok(None)` is as wrong here as `Err`: both
            // mean the observation, not the primitive, came back
            // uncertain, the same "attempted, outcome uncertain" shape
            // as the `live_identity` re-observation above, not the
            // "nothing was displaced" absent-destination case.
            let preimage_identity = match observe_optional(&stage_path) {
                Ok(Some(identity)) => identity,
                Ok(None) | Err(_) => {
                    return recovery_snapshot(&live_path, &stage_path, None);
                }
            };
            FilesystemCommitOutcome::committed(live_identity, Some(preimage_identity))
        } else {
            // Absent-destination path: re-check immediately before the
            // move (closing as much of the TOCTOU window as a check-then-
            // act pair can), then move using the SAME no-replace
            // primitive the identity probe already uses — belt and
            // braces: even if something appears in the residual window
            // between this check and the call, the no-replace flag itself
            // refuses to clobber it.
            match exists_at(dirfd, &live_c) {
                Ok(true) => {
                    return FilesystemCommitOutcome::NotStarted(
                        RetryReason::DestinationDidNotStayAbsent,
                    );
                }
                Ok(false) => {}
                Err(e) => return FilesystemCommitOutcome::NotStarted(RetryReason::Io(e.kind())),
            }
            let (ret, errno) = rename_no_replace(dirfd, &stage_c, &live_c);
            if ret != 0 {
                return FilesystemCommitOutcome::NotStarted(classify_no_replace_failure(errno));
            }
            let live_identity = match observe_optional(&live_path) {
                Ok(Some(identity)) => identity,
                Ok(None) | Err(_) => return recovery_snapshot(&live_path, &stage_path, None),
            };
            FilesystemCommitOutcome::committed(live_identity, None)
        }
    }

    /// Classifies a commit failure's errno. Deliberately a **different**
    /// feature-absence set than `fs_capabilities`'s atomic-exchange probe
    /// uses: the probe only ever exercises two freshly-created regular
    /// files in the same directory, so it never legitimately sees
    /// `EXDEV`; a real commit's `live_name` participant is caller-
    /// supplied and — while this module keeps every commit within one
    /// directory by construction — a filesystem that itself spans
    /// multiple devices at that path (a submount) could still surface
    /// `EXDEV` here. It is included as feature-absence for a commit
    /// specifically because there is no recovery from it by retrying: the
    /// exchange genuinely cannot happen across that boundary, which is
    /// exactly what `Unsupported` (not `Unknown`) means to a caller
    /// deciding whether to keep retrying.
    fn commit_feature_absence(errno: Option<i32>) -> RetryReason {
        #[cfg(target_os = "linux")]
        let feature_absent = &[libc::ENOSYS, libc::EINVAL, libc::EXDEV][..];
        #[cfg(target_os = "macos")]
        let feature_absent = &[libc::ENOSYS, libc::ENOTSUP, libc::EXDEV][..];
        match classify_errno(errno, feature_absent) {
            Capability::Unsupported => RetryReason::UnsupportedOnThisVolume,
            _ => {
                RetryReason::Io(errno.map(io_error_kind_from_errno).unwrap_or(io::ErrorKind::Other))
            }
        }
    }

    fn io_error_kind_from_errno(errno: i32) -> io::ErrorKind {
        io::Error::from_raw_os_error(errno).kind()
    }

    /// Builds the `RequiresRecovery` snapshot for the one case this
    /// platform can reach it: the mutating syscall itself reported
    /// success but a subsequent observation could not confirm it. Three
    /// fresh, independent reads — never a inference from what the syscall
    /// was supposed to have done.
    fn recovery_snapshot(
        live_path: &Path,
        stage_path: &Path,
        backup_path: Option<&Path>,
    ) -> FilesystemCommitOutcome {
        FilesystemCommitOutcome::requires_recovery_from(
            Some(RecoveryObservation::from_observe(observe_optional(live_path))),
            Some(RecoveryObservation::from_observe(observe_optional(stage_path))),
            // On Linux/macOS the preimage (when the exchange happened at
            // all) is the same location as `stage_path` — there is no
            // separate name for it, so it is not double-reported here.
            None,
            backup_path.map(|p| RecoveryObservation::from_observe(observe_optional(p))),
        )
    }

    #[cfg(target_os = "linux")]
    fn exchange(
        dirfd: std::os::unix::io::RawFd,
        stage_c: &std::ffi::CStr,
        live_c: &std::ffi::CStr,
    ) -> (i64, Option<i32>) {
        // Called through the raw syscall number rather than
        // `libc::renameat2`: glibc only exports that symbol from 2.28,
        // and uClibc does not export it at all (same reasoning as
        // `fs_capabilities`'s atomic-exchange probe).
        retry_eintr(|| {
            // SAFETY: `dirfd` is valid for the duration of the call;
            // `stage_c`/`live_c` are valid NUL-terminated strings kept
            // alive by the caller.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    dirfd,
                    stage_c.as_ptr(),
                    dirfd,
                    live_c.as_ptr(),
                    libc::RENAME_EXCHANGE,
                )
            };
            let errno = if ret == -1 { io::Error::last_os_error().raw_os_error() } else { None };
            (ret, errno)
        })
    }

    #[cfg(target_os = "linux")]
    fn rename_no_replace(
        dirfd: std::os::unix::io::RawFd,
        stage_c: &std::ffi::CStr,
        live_c: &std::ffi::CStr,
    ) -> (i64, Option<i32>) {
        retry_eintr(|| {
            // SAFETY: same as `exchange` above.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    dirfd,
                    stage_c.as_ptr(),
                    dirfd,
                    live_c.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            let errno = if ret == -1 { io::Error::last_os_error().raw_os_error() } else { None };
            (ret, errno)
        })
    }

    #[cfg(target_os = "macos")]
    fn exchange(
        dirfd: std::os::unix::io::RawFd,
        stage_c: &std::ffi::CStr,
        live_c: &std::ffi::CStr,
    ) -> (i64, Option<i32>) {
        retry_eintr(|| {
            // SAFETY: `dirfd` is valid for the duration of the call;
            // `stage_c`/`live_c` are valid NUL-terminated strings kept
            // alive by the caller.
            let ret = unsafe {
                libc::renameatx_np(
                    dirfd,
                    stage_c.as_ptr(),
                    dirfd,
                    live_c.as_ptr(),
                    libc::RENAME_SWAP,
                )
            };
            let errno = if ret == -1 { io::Error::last_os_error().raw_os_error() } else { None };
            (ret as i64, errno)
        })
    }

    #[cfg(target_os = "macos")]
    fn rename_no_replace(
        dirfd: std::os::unix::io::RawFd,
        stage_c: &std::ffi::CStr,
        live_c: &std::ffi::CStr,
    ) -> (i64, Option<i32>) {
        retry_eintr(|| {
            // SAFETY: same as `exchange` above.
            let ret = unsafe {
                libc::renameatx_np(
                    dirfd,
                    stage_c.as_ptr(),
                    dirfd,
                    live_c.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            let errno = if ret == -1 { io::Error::last_os_error().raw_os_error() } else { None };
            (ret as i64, errno)
        })
    }

    /// Classifies a failed no-replace move. `EEXIST` is handled first and
    /// separately from `commit_feature_absence`'s general classification:
    /// it means the destination did not stay absent between the
    /// [`exists_at`] re-check and this call — a real, expected outcome of
    /// closing that race, not a feature-absence signal — so it must not
    /// be folded into the generic errno set below (which does not, and
    /// must not, contain `EEXIST`).
    fn classify_no_replace_failure(errno: Option<i32>) -> RetryReason {
        if errno == Some(libc::EEXIST) {
            RetryReason::DestinationDidNotStayAbsent
        } else {
            commit_feature_absence(errno)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn eexist_is_reported_as_destination_did_not_stay_absent() {
            assert_eq!(
                classify_no_replace_failure(Some(libc::EEXIST)),
                RetryReason::DestinationDidNotStayAbsent
            );
        }

        #[test]
        fn an_unrelated_errno_falls_through_to_the_generic_commit_classification() {
            // Not `EEXIST` and not in either platform's feature-absent
            // set (see `commit_feature_absence`): must not be
            // misclassified as either the raced-destination case or a
            // confirmed-unsupported volume.
            let reason = classify_no_replace_failure(Some(libc::EACCES));
            assert!(matches!(reason, RetryReason::Io(_)));
            assert_ne!(reason, RetryReason::DestinationDidNotStayAbsent);
            assert_ne!(reason, RetryReason::UnsupportedOnThisVolume);
        }

        #[test]
        fn recovery_snapshot_reports_an_unreadable_location_as_unreadable_not_absent() {
            // Regression test for the fail-open defect this module fixes:
            // `recovery_snapshot` (and, before this fix, the inline
            // preimage re-observation in `commit_placement`) used
            // `.ok().flatten()`, which collapses "the stat itself failed"
            // into `None` -- the exact same value used for "confirmed
            // absent". This provokes a *real* EACCES on the stat (removes
            // execute permission from the containing directory) rather
            // than asserting on reasoning about what the code does.
            //
            // This cannot isolate the narrower in-flow shape the primary
            // fix actually guards (a successful exchange followed by a
            // failing *re*-observation of the same path that was just
            // read successfully moments earlier): the pre-exchange read
            // of that same path must also succeed for `commit_placement`
            // to ever reach the exchange, and it shares the exact same
            // permission dependency (search permission on this directory)
            // as the post-exchange re-read -- confirmed empirically that
            // revoking it fails both identically, and also fails the
            // `renameat2` exchange itself, which needs the same
            // permission to look up either name. Isolating only the
            // second read would need either a genuine timing race
            // (flaky -- could pass without ever exercising the branch) or
            // non-portable syscall interception, neither appropriate
            // here. This test instead exercises `recovery_snapshot`
            // directly, which is exactly what the fixed call sites in
            // `commit_placement` route to.
            use std::os::unix::fs::PermissionsExt;

            let dir = tempfile::tempdir().unwrap();
            let blocked = dir.path().join("blocked");
            std::fs::create_dir(&blocked).unwrap();
            let target = blocked.join("live");
            std::fs::write(&target, b"x").unwrap();
            std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();

            // Restore permissions unconditionally, even on panic, so the
            // tempdir's own `Drop` can still remove `blocked`.
            struct RestorePerms(PathBuf);
            impl Drop for RestorePerms {
                fn drop(&mut self) {
                    let _ =
                        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
                }
            }
            let _restore = RestorePerms(blocked.clone());

            if observe_optional(&target).is_ok() {
                // Running as root (or some other context where permission
                // checks are bypassed): the failure this test exists to
                // provoke did not happen, so there is nothing left here to
                // meaningfully assert. Reported explicitly rather than
                // silently passing without exercising anything.
                eprintln!(
                    "recovery_snapshot_reports_an_unreadable_location_as_unreadable_not_absent: \
                     could not provoke EACCES (likely running as root) -- this run does not \
                     exercise the fix"
                );
                return;
            }

            match recovery_snapshot(&target, &target, None) {
                FilesystemCommitOutcome::RequiresRecovery(snapshot) => {
                    assert!(
                        matches!(snapshot.observed_live, Some(RecoveryObservation::Unreadable(_))),
                        "an unreadable location must be reported as Unreadable, not silently \
                         flattened into Absent: {:?}",
                        snapshot.observed_live
                    );
                }
                other => panic!("expected RequiresRecovery, got {other:?}"),
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::ffi::OsStrExt;

    // Declared directly rather than adding a `windows-sys`/`winapi`
    // dependency for two functions — the same minimal-FFI approach the
    // rest of this crate's platform code already takes for Unix syscalls
    // not exposed by `std`.
    #[link(name = "kernel32")]
    extern "system" {
        fn ReplaceFileW(
            lp_replaced_file_name: *const u16,
            lp_replacement_file_name: *const u16,
            lp_backup_file_name: *const u16,
            dw_replace_flags: u32,
            lp_exclude: *mut std::ffi::c_void,
            lp_reserved: *mut std::ffi::c_void,
        ) -> i32;

        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;

        fn GetLastError() -> u32;
    }

    fn to_wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub(super) fn commit_placement(request: &CommitRequest) -> FilesystemCommitOutcome {
        let stage_path = request.parent_dir.join(request.stage_name);
        let stage = match observe_optional(&stage_path) {
            Ok(Some(identity)) => identity,
            Ok(None) => return FilesystemCommitOutcome::NotStarted(RetryReason::StageAbsent),
            Err(e) => return FilesystemCommitOutcome::NotStarted(RetryReason::Io(e.kind())),
        };
        // See the Unix `commit_placement`'s identical check for why this
        // runs before eligibility/kind classification, immediately after
        // the freshest possible observation of `stage_name`, and why
        // granularity is measured here rather than accepted from
        // `request` — UNVERIFIED ON REAL WINDOWS beyond this, same caveat
        // as the rest of this module (no Windows host was available).
        let granularity = yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(
            request.parent_dir.path(),
        );
        if let Err(reason) = check_stage_identity_matches_expected(
            &stage,
            request.expected_stage_identity,
            granularity,
        ) {
            return FilesystemCommitOutcome::NotStarted(reason);
        }
        let live_path = request.parent_dir.join(request.live_name);
        let live = match observe_optional(&live_path) {
            Ok(live) => live,
            Err(e) => return FilesystemCommitOutcome::NotStarted(RetryReason::Io(e.kind())),
        };
        if let Err(reason) = check_participants_eligible(&stage, live.as_ref()) {
            return FilesystemCommitOutcome::NotStarted(reason);
        }
        if let Err(reason) = check_not_the_sync_root(live.as_ref(), request.sync_root_identity) {
            return FilesystemCommitOutcome::NotStarted(reason);
        }

        // Win32 resolves a relative path argument against the process
        // current working directory, not any particular directory handle
        // — there is no dirfd-relative form for these two APIs (see
        // `ParentDirHandle`'s own doc). Passing the bare artefact names
        // here would let `ReplaceFileW`/`MoveFileExW` silently operate on
        // an unrelated same-named object in the process CWD instead of
        // the one in `request.parent_dir`, so every wide string handed to
        // Win32 below is built from the full joined path, matching every
        // `observe_optional` call in this function.
        let live_w = to_wide(live_path.as_ref());
        let stage_w = to_wide(stage_path.as_ref());

        if live.is_some() {
            if !request.capabilities.atomic_exchange.is_supported() {
                return FilesystemCommitOutcome::NotStarted(RetryReason::UnsupportedOnThisVolume);
            }
            let backup_path = request.parent_dir.join(request.backup_name);
            let backup_w = to_wide(backup_path.as_ref());
            // SAFETY: all three buffers are valid NUL-terminated UTF-16
            // strings kept alive for the duration of the call; the two
            // reserved pointers are null, which the API requires for this
            // usage.
            let ok = unsafe {
                ReplaceFileW(
                    live_w.as_ptr(),
                    stage_w.as_ptr(),
                    backup_w.as_ptr(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // UNVERIFIED ON REAL WINDOWS — no host was available to
                // test this branch. `ReplaceFileW` documents that a
                // failure here can leave objects partially moved (see the
                // module doc), so this always reports `RequiresRecovery`
                // with a fresh, independent read of every named location
                // — never `NotStarted`, and never an inference from
                // `GetLastError()` about what state things are in.
                // Automatically renaming a stray temporary file the API
                // may have left under an internal name it does not expose
                // ("mandatory post-error normalisation" in the fullest
                // sense) is NOT implemented: there is no documented way to
                // discover that name, and guessing at one without a real
                // Windows host to verify against would be worse than
                // reporting the gap plainly.
                let _last_error = unsafe { GetLastError() };
                return FilesystemCommitOutcome::requires_recovery_from(
                    Some(RecoveryObservation::from_observe(observe_optional(&live_path))),
                    Some(RecoveryObservation::from_observe(observe_optional(&stage_path))),
                    None,
                    Some(RecoveryObservation::from_observe(observe_optional(&backup_path))),
                );
            }
            let live_identity = match observe_optional(&live_path) {
                Ok(Some(identity)) => identity,
                Ok(None) | Err(_) => {
                    return FilesystemCommitOutcome::requires_recovery_from(
                        None,
                        Some(RecoveryObservation::from_observe(observe_optional(&stage_path))),
                        None,
                        Some(RecoveryObservation::from_observe(observe_optional(&backup_path))),
                    );
                }
            };
            // `ReplaceFileW` reported success and this branch only runs
            // when a live object existed to displace, so the preimage
            // necessarily landed at `backup_path` -- a failure to
            // re-observe it (`Err`, or `Ok(None)`, equally wrong here) is
            // the same "attempted, outcome uncertain" shape as the
            // `live_identity` re-observation just above, not "nothing was
            // displaced".
            let preimage_identity = match observe_optional(&backup_path) {
                Ok(Some(identity)) => identity,
                Ok(None) | Err(_) => {
                    return FilesystemCommitOutcome::requires_recovery_from(
                        Some(RecoveryObservation::Present(live_identity)),
                        Some(RecoveryObservation::from_observe(observe_optional(&stage_path))),
                        None,
                        Some(RecoveryObservation::from_observe(observe_optional(&backup_path))),
                    );
                }
            };
            FilesystemCommitOutcome::committed(live_identity, Some(preimage_identity))
        } else {
            // Absent-destination path: `ReplaceFileW` requires the target
            // to already exist, so this goes through `MoveFileExW`
            // instead, with no flags — which, like the Unix no-replace
            // rename, fails rather than overwriting an existing target.
            // Unlike `ReplaceFileW`, this primitive has no documented
            // partial-failure mode, so a failure here is `NotStarted`,
            // the same as the Unix path — UNVERIFIED, same caveat as
            // above.
            // SAFETY: both buffers are valid NUL-terminated UTF-16
            // strings kept alive for the duration of the call.
            let ok = unsafe { MoveFileExW(stage_w.as_ptr(), live_w.as_ptr(), 0) };
            if ok == 0 {
                let last_error = unsafe { GetLastError() };
                const ERROR_ALREADY_EXISTS: u32 = 183;
                const ERROR_FILE_EXISTS: u32 = 80;
                let reason =
                    if last_error == ERROR_ALREADY_EXISTS || last_error == ERROR_FILE_EXISTS {
                        RetryReason::DestinationDidNotStayAbsent
                    } else {
                        RetryReason::Io(io::ErrorKind::Other)
                    };
                return FilesystemCommitOutcome::NotStarted(reason);
            }
            let live_identity = match observe_optional(&live_path) {
                Ok(Some(identity)) => identity,
                Ok(None) | Err(_) => {
                    return FilesystemCommitOutcome::requires_recovery_from(
                        None,
                        Some(RecoveryObservation::from_observe(observe_optional(&stage_path))),
                        None,
                        None,
                    );
                }
            };
            FilesystemCommitOutcome::committed(live_identity, None)
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    use super::*;

    pub(super) fn commit_placement(_request: &CommitRequest) -> FilesystemCommitOutcome {
        // No atomic-exchange primitive is wired up on this platform in
        // this phase; fail closed rather than guess at one.
        FilesystemCommitOutcome::NotStarted(RetryReason::UnsupportedOnThisVolume)
    }
}

/// A test-only, fully synthetic [`FilesystemCommitAdapter`]: returns
/// whichever [`FilesystemCommitOutcome`] it is configured with, and
/// performs no I/O at all. Exists because the real failure modes this
/// module's most important contract ([`FilesystemCommitOutcome::
/// RequiresRecovery`]'s partial-state shapes) cannot be triggered on
/// demand against a real filesystem — this is how the caller-visible
/// contract for each shape gets exercised regardless.
#[cfg(any(test, feature = "test-support"))]
pub struct FakeCommitAdapter {
    outcome: std::sync::Mutex<Option<FilesystemCommitOutcome>>,
    identity: std::sync::Mutex<Option<io::Result<Option<FileIdentity>>>>,
}

#[cfg(any(test, feature = "test-support"))]
impl FakeCommitAdapter {
    pub fn returning(outcome: FilesystemCommitOutcome) -> FakeCommitAdapter {
        FakeCommitAdapter {
            outcome: std::sync::Mutex::new(Some(outcome)),
            identity: std::sync::Mutex::new(None),
        }
    }

    pub fn observing(result: io::Result<Option<FileIdentity>>) -> FakeCommitAdapter {
        FakeCommitAdapter {
            outcome: std::sync::Mutex::new(None),
            identity: std::sync::Mutex::new(Some(result)),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl FilesystemCommitAdapter for FakeCommitAdapter {
    fn commit_placement(&self, _request: &CommitRequest) -> FilesystemCommitOutcome {
        self.outcome.lock().unwrap().take().expect("FakeCommitAdapter: no outcome configured")
    }

    fn observe_identity(&self, _path: &Path) -> io::Result<Option<FileIdentity>> {
        match self.identity.lock().unwrap().take() {
            Some(result) => result,
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_root_authority::fs_identity::{ObjectKind, PlatformObjectId, VolumeIdentity};

    fn sample_identity(kind: ObjectKind) -> FileIdentity {
        FileIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: 1 },
            object_id: PlatformObjectId::Unix { inode: 1 },
            object_kind: kind,
            generation_or_usn: None,
            birth_or_creation_time: None,
            observed_size: 0,
            metadata_fingerprint: [0; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        }
    }

    // --- FilesystemCommitOutcome's own contract, per shape -----------

    #[test]
    fn committed_reports_no_recovery_and_exposes_its_live_identity() {
        let live = sample_identity(ObjectKind::RegularFile);
        let outcome = FilesystemCommitOutcome::committed(live, None);
        assert!(!outcome.requires_recovery());
        assert_eq!(outcome.committed_live_identity().unwrap().object_kind, ObjectKind::RegularFile);
    }

    #[test]
    fn not_started_reports_no_recovery_and_no_live_identity() {
        let outcome = FilesystemCommitOutcome::NotStarted(RetryReason::StageAbsent);
        assert!(!outcome.requires_recovery());
        assert!(outcome.committed_live_identity().is_none());
    }

    #[test]
    fn requires_recovery_reports_recovery_and_no_single_live_identity() {
        // The whole point of this shape: a caller must inspect all four
        // fields itself, not read one of them as authoritative.
        let outcome = FilesystemCommitOutcome::requires_recovery_from(
            Some(RecoveryObservation::Present(sample_identity(ObjectKind::RegularFile))),
            None,
            None,
            None,
        );
        assert!(outcome.requires_recovery());
        assert!(
            outcome.committed_live_identity().is_none(),
            "RequiresRecovery must never be read through the Committed accessor, even when \
             observed_live happens to be populated"
        );
    }

    #[test]
    fn requires_recovery_can_represent_every_participant_absent() {
        // The "syscall reported success but nothing is where it should
        // be" shape -- the fake adapter must be able to hand this back
        // exactly, since it's a real, if rare, outcome the recovery path
        // must handle without panicking on an all-`None` tuple.
        let adapter = FakeCommitAdapter::returning(
            FilesystemCommitOutcome::requires_recovery_from(None, None, None, None),
        );
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &all_unsupported_capabilities(),
            sync_root_identity: &sync_root,
            expected_stage_identity: &sample_identity(ObjectKind::RegularFile),
        };
        let outcome = adapter.commit_placement(&request);
        assert!(outcome.requires_recovery());
        match outcome {
            FilesystemCommitOutcome::RequiresRecovery(snapshot) => {
                assert!(snapshot.observed_live.is_none());
                assert!(snapshot.observed_stage.is_none());
                assert!(snapshot.observed_preimage.is_none());
                assert!(snapshot.observed_backup.is_none());
            }
            other => panic!("expected RequiresRecovery, got {other:?}"),
        }
    }

    #[test]
    fn requires_recovery_can_represent_a_partial_windows_style_move() {
        // The specific shape the module doc calls out: the replacement
        // half succeeded (live now holds new content) but the backup half
        // did not (no preimage was retained) -- exactly the case a naive
        // "error means nothing happened" read would get wrong.
        let adapter =
            FakeCommitAdapter::returning(FilesystemCommitOutcome::requires_recovery_from(
                Some(RecoveryObservation::Present(sample_identity(ObjectKind::RegularFile))),
                None,
                None,
                None,
            ));
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &all_unsupported_capabilities(),
            sync_root_identity: &sync_root,
            expected_stage_identity: &sample_identity(ObjectKind::RegularFile),
        };
        let outcome = adapter.commit_placement(&request);
        assert!(outcome.requires_recovery());
        assert!(
            outcome.committed_live_identity().is_none(),
            "even though observed_live is populated, this is RequiresRecovery, not Committed -- \
             a caller must not treat the live participant's presence alone as proof of a clean \
             commit"
        );
    }

    fn all_unsupported_capabilities() -> FilesystemSafetyCapabilities {
        FilesystemSafetyCapabilities {
            atomic_exchange: Capability::Unsupported,
            durable_file_flush: Capability::Unsupported,
            durable_directory_flush: Capability::Unsupported,
            stable_source_identity: Capability::Unsupported,
            stable_owned_marker_identity: Capability::Unsupported,
            stale_handle_preservation: Capability::Unsupported,
            metadata_fidelity: Capability::Unsupported,
            reflink_or_clone: Capability::Unsupported,
            range_clone: Capability::Unsupported,
        }
    }

    fn all_supported_capabilities() -> FilesystemSafetyCapabilities {
        FilesystemSafetyCapabilities {
            atomic_exchange: Capability::Supported,
            durable_file_flush: Capability::Supported,
            durable_directory_flush: Capability::Supported,
            stable_source_identity: Capability::Supported,
            stable_owned_marker_identity: Capability::Supported,
            stale_handle_preservation: Capability::Supported,
            metadata_fidelity: Capability::Supported,
            reflink_or_clone: Capability::Supported,
            range_clone: Capability::Supported,
        }
    }

    // --- Pure eligibility/kind-mismatch logic -------------------------

    #[test]
    fn matching_regular_files_are_eligible() {
        let stage = sample_identity(ObjectKind::RegularFile);
        let live = sample_identity(ObjectKind::RegularFile);
        assert!(check_participants_eligible(&stage, Some(&live)).is_ok());
    }

    #[test]
    fn no_live_participant_is_always_eligible_on_stage_alone() {
        let stage = sample_identity(ObjectKind::RegularFile);
        assert!(check_participants_eligible(&stage, None).is_ok());
    }

    #[test]
    fn a_file_and_a_directory_are_a_kind_mismatch() {
        let stage = sample_identity(ObjectKind::RegularFile);
        let live = sample_identity(ObjectKind::Directory);
        assert_eq!(
            check_participants_eligible(&stage, Some(&live)),
            Err(RetryReason::ObjectKindMismatch)
        );
    }

    #[test]
    fn a_hardlinked_stage_is_blocked_before_a_kind_check_even_runs() {
        let mut stage = sample_identity(ObjectKind::RegularFile);
        stage.link_count = Some(2);
        let live = sample_identity(ObjectKind::RegularFile);
        assert_eq!(
            check_participants_eligible(&stage, Some(&live)),
            Err(RetryReason::ReplacementNotEligible(
                BlockedObjectReason::HardlinkTopologyUnsupported
            ))
        );
    }

    #[test]
    fn a_hardlinked_live_object_is_blocked_too() {
        let stage = sample_identity(ObjectKind::RegularFile);
        let mut live = sample_identity(ObjectKind::RegularFile);
        live.link_count = Some(2);
        assert_eq!(
            check_participants_eligible(&stage, Some(&live)),
            Err(RetryReason::ReplacementNotEligible(
                BlockedObjectReason::HardlinkTopologyUnsupported
            ))
        );
    }

    // --- Real filesystem behavior (this host's platform) --------------

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn commits_a_new_object_when_live_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&dir.path().join("stage"))
                .unwrap(),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        match outcome {
            FilesystemCommitOutcome::Committed(snapshot) => {
                assert!(
                    snapshot.preimage_identity.is_none(),
                    "nothing was live before, so no preimage"
                );
            }
            other => panic!("expected Committed, got {other:?}"),
        }
        assert!(!dir.path().join("stage").exists());
        assert_eq!(std::fs::read(dir.path().join("live")).unwrap(), b"new content");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn exchanges_and_retains_the_preimage_when_live_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        std::fs::write(dir.path().join("live"), b"old content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&dir.path().join("stage"))
                .unwrap(),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        match outcome {
            FilesystemCommitOutcome::Committed(snapshot) => {
                assert!(
                    snapshot.preimage_identity.is_some(),
                    "the previously-live object must be retained"
                );
            }
            other => panic!("expected Committed, got {other:?}"),
        }
        assert_eq!(std::fs::read(dir.path().join("live")).unwrap(), b"new content");
        // Per this module's documented Linux/macOS convention: the
        // preimage lands back at the stage name, not deleted.
        assert_eq!(std::fs::read(dir.path().join("stage")).unwrap(), b"old content");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn refuses_to_exchange_when_atomic_exchange_is_not_confirmed_supported() {
        // The structural guarantee behind `RetryReason::
        // UnsupportedOnThisVolume`: there is no code path from here to a
        // clobbering plain rename. Mutation check: flip the capability to
        // `Supported` and this test must start observing a real exchange
        // instead (the two tests above already cover that this real
        // exchange succeeds and is correct), proving this assertion is
        // not vacuously true.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        std::fs::write(dir.path().join("live"), b"old content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_unsupported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&dir.path().join("stage"))
                .unwrap(),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(matches!(
            outcome,
            FilesystemCommitOutcome::NotStarted(RetryReason::UnsupportedOnThisVolume)
        ));
        // Neither participant was touched.
        assert_eq!(std::fs::read(dir.path().join("live")).unwrap(), b"old content");
        assert_eq!(std::fs::read(dir.path().join("stage")).unwrap(), b"new content");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn refuses_when_stage_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &sample_identity(ObjectKind::RegularFile),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(matches!(outcome, FilesystemCommitOutcome::NotStarted(RetryReason::StageAbsent)));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn refuses_a_directory_versus_file_kind_mismatch_without_touching_either() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        std::fs::create_dir(dir.path().join("live")).unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&dir.path().join("stage"))
                .unwrap(),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(matches!(
            outcome,
            FilesystemCommitOutcome::NotStarted(RetryReason::ObjectKindMismatch)
        ));
        assert!(dir.path().join("live").is_dir());
        assert_eq!(std::fs::read(dir.path().join("stage")).unwrap(), b"new content");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_preexisting_live_object_takes_the_capability_gated_exchange_path_never_a_silent_no_replace_fallback(
    ) {
        // If `live_name` already exists at eligibility-check time, commit
        // must go through the exchange path and its capability gate —
        // never silently fall back to treating an occupied destination as
        // if it were the absent case. Proven here by making the exchange
        // path's own gate (`atomic_exchange: Unsupported`) fire even
        // though the no-replace path's primitive is never even attempted.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        std::fs::write(dir.path().join("live"), b"existing content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_unsupported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&dir.path().join("stage"))
                .unwrap(),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(matches!(
            outcome,
            FilesystemCommitOutcome::NotStarted(RetryReason::UnsupportedOnThisVolume)
        ));
        assert_eq!(std::fs::read(dir.path().join("live")).unwrap(), b"existing content");
        assert_eq!(std::fs::read(dir.path().join("stage")).unwrap(), b"new content");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_absent_destination_path_does_not_consult_atomic_exchange_capability() {
        // The no-replace move is a different primitive from the exchange
        // (see the module doc); this locks in that its availability is
        // judged by actually attempting it, not by a capability gate
        // meant for a different syscall. `atomic_exchange` is deliberately
        // `Unsupported` here and the commit must still succeed, because
        // no exchange is attempted when `live_name` is absent.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_unsupported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&dir.path().join("stage"))
                .unwrap(),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(matches!(outcome, FilesystemCommitOutcome::Committed(_)));
        assert_eq!(std::fs::read(dir.path().join("live")).unwrap(), b"new content");
    }

    // --- ParentDirHandle::create_artefact -----------------------------

    #[cfg(unix)]
    #[test]
    fn create_artefact_refuses_when_the_name_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let (name, _file) = parent.create_artefact(ArtefactKind::Stage, "abc123").unwrap();

        let second = parent.create_artefact(ArtefactKind::Stage, "abc123");

        assert!(
            matches!(second, Err(CreateArtefactError::Collision(_))),
            "expected a collision on the second attempt, got {second:?}"
        );
        // Mutation check: with `O_EXCL` dropped from the creation flags,
        // this second call would silently truncate the first artefact
        // instead of refusing -- confirmed by hand (temporarily removing
        // `libc::O_EXCL` from `create_artefact`'s `flags` and re-running
        // this test makes it fail on the `matches!` assertion above,
        // because the call succeeds instead of colliding).
        assert_eq!(dir.path().join(&name).metadata().unwrap().len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn create_artefact_does_not_traverse_a_symlink_at_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let decoy_target = elsewhere.path().join("decoy");
        std::fs::write(&decoy_target, b"not an artefact").unwrap();

        let parent = ParentDirHandle::open(dir.path()).unwrap();
        // Pre-compute the name `create_artefact` will try to use, and put
        // a symlink there first, pointing outside `dir` entirely.
        let name = artefact_component_name(ArtefactKind::Preimage, "abc123").unwrap();
        std::os::unix::fs::symlink(&decoy_target, dir.path().join(&name)).unwrap();

        let result = parent.create_artefact(ArtefactKind::Preimage, "abc123");

        assert!(
            matches!(result, Err(CreateArtefactError::Collision(_))),
            "expected a collision refusing to follow the symlink, got {result:?}"
        );
        // The symlink itself must be untouched, and nothing was ever
        // written through it to the decoy target.
        assert_eq!(
            std::fs::read_link(dir.path().join(&name)).unwrap(),
            decoy_target,
            "the symlink at the artefact's name must survive unmodified"
        );
        assert_eq!(std::fs::read(&decoy_target).unwrap(), b"not an artefact");
    }

    #[cfg(unix)]
    #[test]
    fn create_artefact_errors_on_an_over_long_id_rather_than_truncating() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let oversized_id = "a".repeat(300);

        let result = parent.create_artefact(ArtefactKind::Backup, &oversized_id);

        assert!(
            matches!(result, Err(CreateArtefactError::Name(ArtefactNameError::TooLong { .. }))),
            "expected a length refusal, got {result:?}"
        );
        // Nothing truncated must have landed on disk under any name this
        // call could plausibly have produced.
        assert!(
            std::fs::read_dir(dir.path()).unwrap().next().is_none(),
            "a length refusal must not create anything, truncated or otherwise"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_artefact_preserves_an_unowned_artefact_shaped_file() {
        // An artefact-shaped name with content already there, and no
        // journal (this phase has none) to say who owns it. The only
        // fail-closed answer is to leave it alone.
        let dir = tempfile::tempdir().unwrap();
        let name = artefact_component_name(ArtefactKind::Retained, "abc123").unwrap();
        std::fs::write(dir.path().join(&name), b"belongs to someone else").unwrap();

        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let result = parent.create_artefact(ArtefactKind::Retained, "abc123");

        assert!(
            matches!(result, Err(CreateArtefactError::Collision(_))),
            "expected a collision, got {result:?}"
        );
        // Mutation check: this and the two tests above all key off the
        // same `O_EXCL` guard -- with it removed, `create_artefact` would
        // open (and, being `O_WRONLY` with no explicit truncate flag,
        // still overwrite from offset 0 on the next write) this exact
        // file instead of refusing. Confirmed by hand the same way as
        // `create_artefact_refuses_when_the_name_already_exists`.
        assert_eq!(std::fs::read(dir.path().join(&name)).unwrap(), b"belongs to someone else");
    }

    // --- remove_child --------------------------------------------------

    #[test]
    fn remove_child_removes_a_plain_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("victim"), b"gone soon").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        parent.remove_child(OsStr::new("victim")).unwrap();

        assert!(!dir.path().join("victim").exists());
    }

    #[test]
    fn remove_child_reports_absent_for_a_missing_name() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let result = parent.remove_child(OsStr::new("never-existed"));

        assert!(matches!(result, Err(RemoveChildError::Absent)), "expected Absent, got {result:?}");
    }

    #[test]
    fn remove_child_refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let result = parent.remove_child(OsStr::new("subdir"));

        assert!(
            matches!(result, Err(RemoveChildError::NotARegularFile)),
            "expected NotARegularFile, got {result:?}"
        );
        assert!(dir.path().join("subdir").is_dir(), "the directory must survive the refusal");
    }

    #[cfg(unix)]
    #[test]
    fn remove_child_refuses_a_symlink_even_when_its_target_is_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target"), b"the real file").unwrap();
        std::os::unix::fs::symlink(dir.path().join("target"), dir.path().join("link")).unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();

        let result = parent.remove_child(OsStr::new("link"));

        assert!(
            matches!(result, Err(RemoveChildError::NotARegularFile)),
            "a symlink must never be removed by this method, regardless of its target: {result:?}"
        );
        assert!(dir.path().join("link").symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(dir.path().join("target")).unwrap(), b"the real file");
    }

    // The one race this test suite can honestly exercise deterministically:
    // a genuine concurrent two-process/two-thread race is inherently
    // timing-dependent and would be flaky, not a real proof, so it is not
    // attempted here (stated plainly rather than writing one that only
    // appears to cover it). What *is* deterministic is the structural
    // property that actually closes the gap: a directory-handle-relative
    // operation resolves through the descriptor captured at `open` time,
    // never by re-walking the path string. This test proves exactly that,
    // without needing real concurrency: it renames the directory out from
    // under an already-open handle, puts an impostor with the same
    // directory *and* file name back at the stale path, and confirms
    // `remove_child` still reaches the original object through the
    // descriptor -- never the impostor sitting at the path string the
    // handle was originally opened with.
    #[cfg(unix)]
    #[test]
    fn remove_child_is_directory_handle_relative_surviving_a_parent_rename() {
        let base = tempfile::tempdir().unwrap();
        let original = base.path().join("original");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("victim"), b"the real target").unwrap();
        let handle = ParentDirHandle::open(&original).unwrap();

        let moved = base.path().join("moved");
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("victim"), b"an impostor, not the real target").unwrap();

        handle.remove_child(OsStr::new("victim")).unwrap();

        assert!(
            !moved.join("victim").exists(),
            "the real target, reached through the held descriptor, must be gone"
        );
        assert_eq!(
            std::fs::read(original.join("victim")).unwrap(),
            b"an impostor, not the real target",
            "the impostor sitting at the stale path string must be untouched -- proof this \
             resolved through the descriptor, not the path"
        );
    }

    // --- sync root as an invalid commit target ------------------------

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn commit_placement_refuses_when_the_target_is_the_sync_root() {
        let outer = tempfile::tempdir().unwrap();
        let root_path = outer.path().join("root");
        std::fs::create_dir(&root_path).unwrap();
        let stage_path = outer.path().join("stage");
        std::fs::create_dir(&stage_path).unwrap();

        let sync_root_identity = DirectoryIdentity::observe_path(&root_path).unwrap();
        let parent = ParentDirHandle::open(outer.path()).unwrap();
        let caps = all_supported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("root"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root_identity,
            expected_stage_identity: &FileIdentity::observe_path(&outer.path().join("stage"))
                .unwrap(),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(
            matches!(outcome, FilesystemCommitOutcome::NotStarted(RetryReason::TargetIsSyncRoot)),
            "expected a distinct sync-root refusal, got {outcome:?}"
        );
        // Nothing was touched: the root is still the exact directory it
        // was, and the stage object is still where it was left.
        assert_eq!(
            DirectoryIdentity::observe_path(&root_path).unwrap().object_id,
            sync_root_identity.object_id
        );
        assert!(stage_path.is_dir());
        // Mutation check: with the `check_not_the_sync_root` call site in
        // `platform::commit_placement` commented out (or the function's
        // body replaced with an unconditional `Ok(())`), this test fails
        // on the `matches!` assertion above -- the commit proceeds and
        // exchanges the root directory itself with the stage directory
        // instead of refusing. Confirmed by hand.
    }

    // --- stage identity binding (anti-substitution) --------------------

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn refuses_and_touches_nothing_when_the_staged_object_was_substituted_after_preparation() {
        // Drives the real defect end-to-end, not just the pure comparison
        // in isolation: `prepare_target` (modeled here by writing the
        // "prepared" content and capturing its identity, the same shape
        // `PreparedArtifact::verified_identity` has) stages an object, and
        // something else -- another process, in the real vulnerability --
        // replaces the name at `stage_name` with its own single-link
        // regular file before the commit runs. `commit_placement` must
        // refuse rather than exchange the substituted object into
        // `live_name`, and neither participant may be touched.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"content prepare_target verified").unwrap();
        std::fs::write(dir.path().join("live"), b"old content").unwrap();
        // Captured the moment preparation "finished" -- exactly what
        // `PreparedArtifact::verified_identity` would hold.
        let verified_identity = FileIdentity::observe_path(&dir.path().join("stage")).unwrap();

        // The substitution: something else replaces the staged name with
        // its own, different, single-link regular file before the commit
        // window runs.
        std::fs::remove_file(dir.path().join("stage")).unwrap();
        std::fs::write(dir.path().join("stage"), b"an attacker's substituted bytes").unwrap();

        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        // The refusal this test proves must hold on any platform,
        // including a coarse clock with no `generation_or_usn` (overlayfs):
        // `commit_placement` now measures this volume's real granularity
        // itself (see `check_stage_identity_matches_expected`'s call site),
        // rather than trusting a caller-supplied value that could assume
        // `Fine` and let the substituted object's coincidentally equal
        // birth time pass as proof of `SameObject`.
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &verified_identity,
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(
            matches!(
                outcome,
                FilesystemCommitOutcome::NotStarted(RetryReason::StageIdentityMismatch)
            ),
            "expected a stage-identity-mismatch refusal, got {outcome:?}"
        );
        // Neither participant was touched: the live path must still hold
        // exactly what it held before this attempt, and the substituted
        // object must still be sitting at the stage name, untouched and
        // unpublished.
        assert_eq!(std::fs::read(dir.path().join("live")).unwrap(), b"old content");
        assert_eq!(
            std::fs::read(dir.path().join("stage")).unwrap(),
            b"an attacker's substituted bytes"
        );
        // Mutation check: with the identity-binding call site in
        // `platform::commit_placement` commented out (or
        // `check_stage_identity_matches_expected` replaced with an
        // unconditional `Ok(())`), this test fails on the `matches!`
        // assertion above -- the commit proceeds, exchanges the
        // substituted object into `live_name`, and this assertion catches
        // exactly that: `live` ends up holding the attacker's bytes
        // instead of refusing. Confirmed by hand.
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn accepts_when_the_staged_object_is_genuinely_unchanged_since_preparation() {
        // The companion to the substitution test above: proves the new
        // check is not simply refusing everything. The same object,
        // re-observed, must still compare equal to itself and let a
        // legitimate commit through.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        let verified_identity = FileIdentity::observe_path(&dir.path().join("stage")).unwrap();

        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let sync_root = DirectoryIdentity::observe_path(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &verified_identity,
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(matches!(outcome, FilesystemCommitOutcome::Committed(_)), "got {outcome:?}");
        assert_eq!(std::fs::read(dir.path().join("live")).unwrap(), b"new content");
    }

    // --- Real Windows filesystem behavior -------------------------------
    //
    // Everything above this point that exercises `platform::commit_placement`
    // is gated to Linux/macOS. The Windows branch (`ReplaceFileW`/
    // `MoveFileExW`) compiled but had never actually run against a real
    // NTFS volume before these tests -- no Windows host was available
    // earlier in this project. They now do.

    #[cfg(windows)]
    fn sync_root_for(dir: &std::path::Path) -> DirectoryIdentity {
        DirectoryIdentity::observe_path(dir).unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn windows_commits_a_new_object_when_live_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let sync_root = sync_root_for(dir.path());
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&dir.path().join("stage"))
                .unwrap(),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(matches!(outcome, FilesystemCommitOutcome::Committed(_)), "got {outcome:?}");
        assert!(!dir.path().join("stage").exists());
        assert_eq!(std::fs::read(dir.path().join("live")).unwrap(), b"new content");
    }

    #[cfg(windows)]
    #[test]
    fn windows_exchanges_and_retains_the_preimage_at_the_backup_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        std::fs::write(dir.path().join("live"), b"old content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let sync_root = sync_root_for(dir.path());
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&dir.path().join("stage"))
                .unwrap(),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        match outcome {
            FilesystemCommitOutcome::Committed(snapshot) => {
                assert!(snapshot.preimage_identity.is_some());
            }
            other => panic!("expected Committed, got {other:?}"),
        }
        assert_eq!(std::fs::read(dir.path().join("live")).unwrap(), b"new content");
        // Per this module's documented Windows convention (distinct from
        // Linux/macOS): `ReplaceFileW`'s explicit backup path holds the
        // preimage, not the stage name.
        assert_eq!(std::fs::read(dir.path().join("backup")).unwrap(), b"old content");
    }

    /// Restores the process current working directory on drop, including
    /// on an unwinding panic -- used only by the CWD test below, which
    /// must not leave the test process pointed at a temp directory that
    /// is about to be deleted.
    #[cfg(windows)]
    struct RestoreCwd(std::path::PathBuf);

    #[cfg(windows)]
    impl Drop for RestoreCwd {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_commit_targets_parent_dir_not_the_process_cwd() {
        // Regression test: `platform::commit_placement` used to build its
        // `ReplaceFileW`/`MoveFileExW` wide strings from the bare artefact
        // names instead of the full paths joined against `parent_dir`.
        // Both Win32 APIs resolve a relative path argument against the
        // process's current working directory, not any directory handle
        // -- so a bare name would silently act on whatever same-named
        // object happens to sit in the CWD instead of the one this commit
        // is actually about.
        //
        // Changing the process CWD is global, process-wide state that
        // would race any other test that depends on it. No other test in
        // this module reads `std::env::current_dir()` or relies on a
        // relative path -- every one of them opens `ParentDirHandle` with
        // an absolute `tempdir().path()` -- so this is the only test that
        // needs to touch it. Serialized behind a mutex regardless, so a
        // future CWD-touching test added here cannot interleave with this
        // one, and `RestoreCwd` guarantees the original directory comes
        // back even if an assertion below panics.
        static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _serialize = CWD_LOCK.lock().unwrap();

        let real_dir = tempfile::tempdir().unwrap();
        std::fs::write(real_dir.path().join("stage"), b"real new content").unwrap();
        std::fs::write(real_dir.path().join("live"), b"real old content").unwrap();

        // A decoy with the same artefact name, living only in what is
        // about to become the process CWD -- never inside `real_dir`.
        let decoy_dir = tempfile::tempdir().unwrap();
        std::fs::write(decoy_dir.path().join("live"), b"decoy -- must survive untouched").unwrap();

        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(decoy_dir.path()).unwrap();
        let _restore = RestoreCwd(original_cwd);

        let parent = ParentDirHandle::open(real_dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let sync_root = sync_root_for(real_dir.path());
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&real_dir.path().join("stage"))
                .unwrap(),
        };

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(matches!(outcome, FilesystemCommitOutcome::Committed(_)), "got {outcome:?}");
        assert_eq!(std::fs::read(real_dir.path().join("live")).unwrap(), b"real new content");
        assert_eq!(std::fs::read(real_dir.path().join("backup")).unwrap(), b"real old content");
        assert_eq!(
            std::fs::read(decoy_dir.path().join("live")).unwrap(),
            b"decoy -- must survive untouched",
            "a commit targeting parent_dir must never touch a same-named object in the \
             process CWD"
        );
    }

    /// Opens `path` with no sharing flags at all -- not even
    /// `FILE_SHARE_DELETE` -- so a concurrent rename/replace targeting it
    /// fails with a real, reproducible `ERROR_SHARING_VIOLATION`. This is
    /// how the two tests below provoke a genuine platform failure rather
    /// than asserting on documentation alone.
    #[cfg(windows)]
    fn open_with_no_sharing(path: &std::path::Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).share_mode(0).open(path).unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn windows_a_real_replacefilew_failure_inspects_every_participant_and_never_reports_not_started(
    ) {
        // The requirement this proves: a failed `ReplaceFileW` must never
        // be mapped to `NotStarted` ("nothing changed") -- it must always
        // report `RequiresRecovery` with a fresh, independent read of
        // every named location, because the Win32 API itself documents
        // that a failure here can leave objects partially moved.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        std::fs::write(dir.path().join("live"), b"old content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let sync_root = sync_root_for(dir.path());
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&dir.path().join("stage"))
                .unwrap(),
        };

        // Hold `live` open with no sharing at all -- `ReplaceFileW` must
        // fail to replace it.
        let _lock = open_with_no_sharing(&dir.path().join("live"));

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(
            outcome.requires_recovery(),
            "a real ReplaceFileW failure must report RequiresRecovery, got {outcome:?}"
        );
        assert!(
            outcome.committed_live_identity().is_none(),
            "RequiresRecovery must never be read through the Committed accessor"
        );
        // Release the sharing lock before verifying. The handle that
        // provoked the failure denies ALL sharing, so it also blocks this
        // test's own reads -- measured on real Windows, where leaving it
        // held failed the verification with ERROR_SHARING_VIOLATION and
        // looked exactly like a product defect.
        drop(_lock);

        // Nothing actually moved: both participants still hold their
        // original content, confirmed by re-reading the real files, not
        // inferred from the error code.
        assert_eq!(std::fs::read(dir.path().join("live")).unwrap(), b"old content");
        assert_eq!(std::fs::read(dir.path().join("stage")).unwrap(), b"new content");
        assert!(!dir.path().join("backup").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_a_real_movefileexw_failure_is_not_started_and_touches_nothing() {
        // The absent-destination path has no documented partial-failure
        // mode (unlike ReplaceFileW), so a failure here is `NotStarted` --
        // proven against a real, reproducible sharing-violation failure
        // rather than asserted from the API's documentation alone.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stage"), b"new content").unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let caps = all_supported_capabilities();
        let sync_root = sync_root_for(dir.path());
        let request = CommitRequest {
            parent_dir: &parent,
            stage_name: OsStr::new("stage"),
            live_name: OsStr::new("live"),
            backup_name: OsStr::new("backup"),
            capabilities: &caps,
            sync_root_identity: &sync_root,
            expected_stage_identity: &FileIdentity::observe_path(&dir.path().join("stage"))
                .unwrap(),
        };

        let _lock = open_with_no_sharing(&dir.path().join("stage"));

        let outcome = NativeCommitAdapter.commit_placement(&request);

        assert!(matches!(outcome, FilesystemCommitOutcome::NotStarted(_)), "got {outcome:?}");
        assert!(!outcome.requires_recovery());
        // Same reason as the `ReplaceFileW` test above: the no-sharing
        // handle blocks this test's own verification read too.
        drop(_lock);
        assert_eq!(std::fs::read(dir.path().join("stage")).unwrap(), b"new content");
        assert!(!dir.path().join("live").exists());
    }

    // --- `create_artefact` on real Windows NTFS -------------------------

    #[cfg(windows)]
    #[test]
    fn windows_create_artefact_refuses_when_the_name_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let (name, _file) = parent.create_artefact(ArtefactKind::Stage, "abc123").unwrap();

        let second = parent.create_artefact(ArtefactKind::Stage, "abc123");

        assert!(
            matches!(second, Err(CreateArtefactError::Collision(_))),
            "expected a collision, got {second:?}"
        );
        assert_eq!(dir.path().join(&name).metadata().unwrap().len(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_create_artefact_preserves_an_unowned_artefact_shaped_file() {
        let dir = tempfile::tempdir().unwrap();
        let name = artefact_component_name(ArtefactKind::Retained, "abc123").unwrap();
        std::fs::write(dir.path().join(&name), b"belongs to someone else").unwrap();

        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let result = parent.create_artefact(ArtefactKind::Retained, "abc123");

        assert!(
            matches!(result, Err(CreateArtefactError::Collision(_))),
            "expected a collision, got {result:?}"
        );
        assert_eq!(std::fs::read(dir.path().join(&name)).unwrap(), b"belongs to someone else");
    }

    #[cfg(windows)]
    #[test]
    fn windows_create_artefact_errors_on_an_over_long_id_rather_than_truncating() {
        let dir = tempfile::tempdir().unwrap();
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let oversized_id = "a".repeat(300);

        let result = parent.create_artefact(ArtefactKind::Backup, &oversized_id);

        assert!(
            matches!(result, Err(CreateArtefactError::Name(ArtefactNameError::TooLong { .. }))),
            "expected a length refusal, got {result:?}"
        );
        assert!(
            std::fs::read_dir(dir.path()).unwrap().next().is_none(),
            "a length refusal must not create anything, truncated or otherwise"
        );
    }

    // --- The reserved-namespace predicate against a filesystem that
    //     genuinely strips a trailing dot/space ---------------------------

    #[cfg(windows)]
    #[test]
    fn windows_trailing_dot_and_space_are_stripped_and_the_reserved_predicate_is_not_fooled() {
        let dir = tempfile::tempdir().unwrap();
        // NTFS silently strips a trailing '.' and a trailing ' ' from a
        // requested filename -- measured directly here, not assumed.
        std::fs::write(dir.path().join("notes.txt."), b"a").unwrap();
        std::fs::write(dir.path().join("notes2.txt "), b"b").unwrap();

        let mut on_disk: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        on_disk.sort();
        assert_eq!(
            on_disk,
            vec!["notes.txt".to_string(), "notes2.txt".to_string()],
            "NTFS must have stripped the trailing dot/space from both requested names"
        );

        // Neither stripped, ordinary name is mistaken for one of our
        // reserved artefact components.
        for name in &on_disk {
            assert!(
                !yadorilink_root_authority::reserved_namespace::is_reserved_component(OsStr::new(
                    name
                )),
                "{name:?} is an ordinary stripped filename, not a reserved artefact component"
            );
        }

        // Our own artefact naming scheme never emits a trailing dot or
        // space (`artefact_component_name` only permits alphanumerics,
        // `-` and `_` in the id, and a fixed non-dot/space suffix
        // structure), so it is immune to this stripping -- confirmed by
        // creating a real one and checking the on-disk name matches
        // exactly what was requested, byte for byte.
        let parent = ParentDirHandle::open(dir.path()).unwrap();
        let (artefact_name, _file) = parent.create_artefact(ArtefactKind::Stage, "abc123").unwrap();
        let actual_on_disk = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .find(|n| n.starts_with(".yadorilink"))
            .unwrap();
        assert_eq!(actual_on_disk, artefact_name, "our own artefact name must survive untouched");
        assert!(yadorilink_root_authority::reserved_namespace::is_reserved_component(OsStr::new(
            &actual_on_disk
        )));
    }
}
