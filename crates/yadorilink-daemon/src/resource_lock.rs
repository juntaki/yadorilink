//! Process-lifetime exclusive locks on the daemon's *mutable data resources* —
//! the block-store root and the sync-state SQLite database.
//!
//! The config-directory lock ([`crate::app`]'s `DaemonInstanceLock`) only
//! guarantees a single daemon per *config directory*. But the block-store root
//! and the SQLite database path are independently overridable
//! (`YADORILINK_BLOCK_STORE` / `YADORILINK_SYNC_DB`), so two daemons started
//! with *distinct* config directories — each holding its own config-dir lock —
//! could still be pointed at the *same* store root and/or database. Two writers
//! over one block store or one SQLite index risks index/store corruption:
//! `FsBlockStore`'s internal locks are process-local and SQLite's WAL mode
//! happily lets both processes open the same file. These locks close that gap,
//! additively (the config-dir lock is untouched).
//!
//! Mechanism: an OS advisory exclusive lock (`flock`/`LockFileEx` via `fs2`),
//! applied in two layers together. First, a *sidecar* lock file whose location
//! is derived from the **canonicalized** resource path (both resources, all
//! platforms). Second (Linux/Android only, sync DB only), an additional
//! whole-file flock on the **live database inode itself**, to catch same-inode
//! aliases whose canonical path — and therefore sidecar path — differs (see
//! below). Like the config-dir lock, the OS releases the locks on process exit
//! (including SIGKILL/crash) and the lock files are left in place — acquisition
//! never parses PIDs or deletes "stale" files.
//!
//! ## What is caught
//!
//! By canonicalize + sidecar (all platforms):
//!
//! * the exact same path;
//! * `..`-relative aliases;
//! * symlinked parent directories;
//! * a symlink pointing directly at an *existing* database file (its full path
//!   canonicalizes to the real file);
//! * a **directory** bind mount of a parent: the sidecar is one real inode
//!   inside the shared directory, so both mount paths open it and conflict even
//!   though their canonical paths differ (handle identity).
//!
//! Additionally, by the live-inode flock (Linux/Android, sync DB only):
//!
//! * a **file** bind mount of the database file itself (same inode, different
//!   canonical path — hence a different sidecar);
//! * a **hard link** of the database file into another path/directory.
//!
//! ## What is NOT caught (known limitations)
//!
//! * On **macOS, the BSDs, and Windows**, the file-bind-mount and
//!   hard-link-of-DB-file cases are NOT caught — there is no live-inode flock
//!   there. This is deliberate, not an oversight: verification showed that on
//!   macOS a whole-file `flock` held on the SQLite file makes SQLite itself
//!   return `database is locked`, and on Windows `fs2`'s whole-file
//!   `LockFileEx` range overlaps the byte range SQLite locks — so locking the
//!   live DB inode is unsafe on those platforms. They get sidecar-only. (The
//!   block-store root has no equivalent gap on any platform: a directory cannot
//!   be hard-linked, and a directory bind mount is already caught by the
//!   sidecar's inode identity.)
//! * **NFS**, even on Linux: `flock` there is emulated via whole-file POSIX
//!   byte-range locks that can interact with SQLite's own POSIX locks, and
//!   SQLite is itself officially unsupported on NFS. Running the daemon's
//!   database on NFS is out of scope.
//! * **Concurrent-rename TOCTOU**: the lock is taken on the canonical path
//!   resolved at acquisition time; `SyncState`/`FsBlockStore` then open the
//!   originally-configured path. A hostile concurrent rename or symlink swap
//!   between those two steps could make them diverge. Out of threat model —
//!   this guards a cooperative env-override *misconfiguration*, not an attacker
//!   racing the filesystem.
//! * **Dangling symlink to a not-yet-created target**: when neither daemon's
//!   database exists yet, canonicalization falls back to canonical-parent +
//!   filename, so two daemons pointing distinct dangling symlinks at the same
//!   eventual target may both start until the file is created. Also out of
//!   threat model.

use std::path::{Path, PathBuf};

/// Lock file placed *inside* the block-store root. Ignored by the store itself:
/// `FsBlockStore`'s usage scan only counts 64-character hash filenames and its
/// stale-temp sweep only removes strict `.yadorilink-tmp.<pid>.<counter>`
/// names, so this sidecar is never miscounted as a block nor swept away.
const BLOCK_STORE_LOCK_FILE: &str = ".yadorilink-store.lock";

/// Process-lifetime ownership of one mutable data resource. Holding the
/// [`std::fs::File`] handles keeps the advisory lock(s); dropping the value
/// releases them (so a partially-acquired set rolls back automatically).
#[derive(Debug)]
pub(crate) struct ResourceLock {
    _sidecar: std::fs::File,
    /// (Linux/Android, sync DB only) A second whole-file flock held on the
    /// *live* database inode, so same-inode aliases (file bind mount, hard
    /// link) whose canonical path — and thus sidecar — differs are still
    /// caught. `None` for the block-store root (a directory, which cannot be
    /// hard-linked). Absent entirely on other platforms, where locking the live
    /// SQLite inode is unsafe (see the module doc).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    _live_inode: Option<std::fs::File>,
}

impl ResourceLock {
    /// Lock the block-store root. The lock file lives inside the canonicalized
    /// root, so any alias resolving to (or bind-mounting) the same directory
    /// targets the same lock-file inode and conflicts.
    pub(crate) fn lock_block_store(root: &Path) -> anyhow::Result<Self> {
        let canonical = canonicalize_dir(root).map_err(|e| {
            anyhow::anyhow!("failed to resolve block-store root {}: {e}", root.display())
        })?;
        let lock_path = canonical.join(BLOCK_STORE_LOCK_FILE);
        let label = format!("block store {}", canonical.display());
        let sidecar = open_sidecar_file(&lock_path)?;
        take_exclusive_lock(&sidecar, &label, &lock_path)?;
        Ok(Self {
            _sidecar: sidecar,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            _live_inode: None,
        })
    }

    /// Lock the sync-state SQLite database. A sidecar lock file next to the
    /// canonicalized database path handles path/symlink/dir-bind-mount aliases
    /// on every platform; on Linux/Android an additional whole-file flock on
    /// the live database inode additionally catches same-inode file aliases
    /// (bind mount, hard link). See the module doc for the platform rationale.
    pub(crate) fn lock_sync_db(db_path: &Path) -> anyhow::Result<Self> {
        let canonical_db = canonicalize_file_target(db_path).map_err(|e| {
            anyhow::anyhow!("failed to resolve sync database {}: {e}", db_path.display())
        })?;
        let parent = canonical_db.parent().ok_or_else(|| {
            anyhow::anyhow!("sync database path {} has no parent directory", canonical_db.display())
        })?;
        let file_name = canonical_db.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            anyhow::anyhow!("sync database path {} has no file name", canonical_db.display())
        })?;
        let lock_path = parent.join(format!(".{file_name}.yadorilink-lock"));
        let label = format!("sync database {}", canonical_db.display());

        // Sidecar first (portable path-alias coverage).
        let sidecar = open_sidecar_file(&lock_path)?;
        take_exclusive_lock(&sidecar, &label, &lock_path)?;

        // Then the live-inode flock, where it is safe. If this conflicts the
        // sidecar handle above is dropped as we return `Err`, releasing it.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let live_inode = {
            // Open (creating if absent, exactly as SQLite would) the real
            // database inode and flock the whole file. `truncate(false)` is
            // load-bearing: we must never truncate the live database. Verified
            // not to disturb SQLite's own WAL-mode locking on Linux local
            // filesystems, because `flock` and SQLite's POSIX `fcntl`
            // byte-range locks are independent there. We do NOT chmod the file.
            let live = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&canonical_db)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to open sync database {} for inode lock: {e}",
                        canonical_db.display()
                    )
                })?;
            take_exclusive_lock(&live, &label, &canonical_db)?;
            Some(live)
        };

        Ok(Self {
            _sidecar: sidecar,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            _live_inode: live_inode,
        })
    }
}

/// The daemon's two data-resource locks, acquired together in a deterministic
/// order so distinct instances can never deadlock waiting on each other.
#[derive(Debug)]
pub(crate) struct DataResourceLocks {
    _block_store: ResourceLock,
    _sync_db: ResourceLock,
}

impl DataResourceLocks {
    /// Acquire the block-store lock then the sync-DB lock, in that fixed order
    /// (the caller already holds the config-dir lock, so the global order is
    /// config dir → block store → DB). On any conflict the already-acquired
    /// lock is dropped as this returns `Err`, so a losing daemon fails fast
    /// holding nothing — no store or database mutation has happened yet.
    pub(crate) fn acquire(block_store_root: &Path, sync_db_path: &Path) -> anyhow::Result<Self> {
        let block_store = ResourceLock::lock_block_store(block_store_root)?;
        let sync_db = ResourceLock::lock_sync_db(sync_db_path)?;
        Ok(Self { _block_store: block_store, _sync_db: sync_db })
    }
}

/// Open (creating if needed, never truncating) a sidecar lock file at
/// `lock_path`, with `0o600` permissions on Unix. The sidecar is our own file,
/// so tightening its mode is safe (unlike the live database file, which we
/// never chmod).
fn open_sidecar_file(lock_path: &Path) -> anyhow::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|e| anyhow::anyhow!("failed to open lock file {}: {e}", lock_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(lock_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Take a non-blocking exclusive OS lock on `file`, mapping contention to a
/// clear "already in use" error and any other failure to a lock-path error.
fn take_exclusive_lock(
    file: &std::fs::File,
    resource_label: &str,
    lock_path: &Path,
) -> anyhow::Result<()> {
    match fs2::FileExt::try_lock_exclusive(file) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            anyhow::bail!("{resource_label} is already in use by another YadoriLink daemon")
        }
        Err(error) => {
            Err(anyhow::anyhow!("failed to acquire lock {}: {error}", lock_path.display()))
        }
    }
}

/// Create `dir` if needed and return its canonical path (resolving `..`,
/// symlinked components, and a symlink to the directory itself).
fn canonicalize_dir(dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    dir.canonicalize()
}

/// Resolve a *file* target to a canonical path stable across aliases. If the
/// file already exists (the common case — a prior daemon created it),
/// `canonicalize` resolves `..`, symlinked parents, and a symlink to the file
/// itself. If it does not exist yet, canonicalize the parent directory and
/// rejoin the final component so `..`/symlinked-parent aliases still collapse.
fn canonicalize_file_target(path: &Path) -> std::io::Result<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Ok(canonical);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    std::fs::create_dir_all(&parent)?;
    Ok(parent.canonicalize()?.join(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- block store ---------------------------------------------------------

    #[test]
    fn block_store_lock_rejects_second_holder_on_exact_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("blocks");
        let _owner = ResourceLock::lock_block_store(&root).unwrap();

        let err = ResourceLock::lock_block_store(&root)
            .expect_err("a second holder of the same block-store root must be rejected");
        assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
    }

    #[test]
    fn block_store_lock_rejects_dotdot_alias() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("blocks");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let _owner = ResourceLock::lock_block_store(&root).unwrap();

        // `<root>/sub/..` is an alias of `<root>` that canonicalization must
        // collapse.
        let alias = root.join("sub").join("..");
        let err = ResourceLock::lock_block_store(&alias)
            .expect_err("a `..`-relative alias of the block-store root must be rejected");
        assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn block_store_lock_rejects_symlinked_parent_alias() {
        let dir = tempfile::tempdir().unwrap();
        let real_parent = dir.path().join("real");
        let root = real_parent.join("blocks");
        let _owner = ResourceLock::lock_block_store(&root).unwrap();

        // A symlinked *parent* directory: `<link>/blocks` resolves to the same
        // real block-store root.
        let link_parent = dir.path().join("link");
        std::os::unix::fs::symlink(&real_parent, &link_parent).unwrap();
        let aliased_root = link_parent.join("blocks");

        let err = ResourceLock::lock_block_store(&aliased_root)
            .expect_err("a symlinked-parent alias of the block-store root must be rejected");
        assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
    }

    // --- sync database -------------------------------------------------------

    #[test]
    fn sync_db_lock_rejects_second_holder_on_exact_path() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("sync-state.sqlite3");
        let _owner = ResourceLock::lock_sync_db(&db).unwrap();

        let err = ResourceLock::lock_sync_db(&db)
            .expect_err("a second holder of the same sync database must be rejected");
        assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
    }

    #[test]
    fn sync_db_lock_rejects_dotdot_alias() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        let db = dir.path().join("sync-state.sqlite3");
        let _owner = ResourceLock::lock_sync_db(&db).unwrap();

        // `<dir>/sub/../sync-state.sqlite3` names the same database.
        let alias = dir.path().join("sub").join("..").join("sync-state.sqlite3");
        let err = ResourceLock::lock_sync_db(&alias)
            .expect_err("a `..`-relative alias of the sync database must be rejected");
        assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn sync_db_lock_rejects_symlink_to_existing_db_file() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("sync-state.sqlite3");
        // The database already exists (a prior owner created it), so a symlink
        // pointing straight at the file resolves to the same real path.
        std::fs::write(&db, b"").unwrap();
        let _owner = ResourceLock::lock_sync_db(&db).unwrap();

        let db_link = dir.path().join("db-link.sqlite3");
        std::os::unix::fs::symlink(&db, &db_link).unwrap();
        let err = ResourceLock::lock_sync_db(&db_link)
            .expect_err("a symlink to the existing sync database file must be rejected");
        assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
    }

    /// Live-inode flock coverage: a **hard link** of the database file has the
    /// same inode but a different canonical path (and therefore a different
    /// sidecar), so only the live-inode flock can catch it. Gated to the
    /// platforms where that flock is applied (and verified safe against SQLite).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn sync_db_lock_rejects_hard_link_via_live_inode_flock() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("sync-state.sqlite3");
        std::fs::write(&db, b"").unwrap();
        let _owner = ResourceLock::lock_sync_db(&db).unwrap();

        let hard = dir.path().join("aliased.sqlite3");
        std::fs::hard_link(&db, &hard).unwrap();
        // The two paths really are the same inode but distinct sidecars, so the
        // rejection can only come from the live-inode flock.
        let err = ResourceLock::lock_sync_db(&hard).expect_err(
            "a hard link to the same DB inode must be rejected by the live-inode flock",
        );
        assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
    }

    /// The live-inode flock must roll back with the sidecar: after the owner
    /// exits, a previously-rejected hard-link path must acquire cleanly
    /// (nothing was left locked).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn sync_db_hard_link_lock_releases_on_owner_exit() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("sync-state.sqlite3");
        std::fs::write(&db, b"").unwrap();
        let hard = dir.path().join("aliased.sqlite3");
        std::fs::hard_link(&db, &hard).unwrap();

        let owner = ResourceLock::lock_sync_db(&db).unwrap();
        assert!(ResourceLock::lock_sync_db(&hard).is_err());
        drop(owner);
        // Owner released both its sidecar and its live-inode flock.
        let _reacquire = ResourceLock::lock_sync_db(&hard)
            .expect("the live-inode flock must be released when the owner exits");
    }

    // --- no false positives + independence ----------------------------------

    #[test]
    fn distinct_block_store_and_db_do_not_collide_in_same_dir() {
        // A block-store lock and a sync-DB lock rooted in the SAME directory
        // are distinct resources and must both succeed.
        let dir = tempfile::tempdir().unwrap();
        let _store = ResourceLock::lock_block_store(&dir.path().join("blocks")).unwrap();
        let _db = ResourceLock::lock_sync_db(&dir.path().join("sync-state.sqlite3")).unwrap();
    }

    #[test]
    fn genuinely_distinct_resources_all_start() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let _a = DataResourceLocks::acquire(
            &a.path().join("blocks"),
            &a.path().join("sync-state.sqlite3"),
        )
        .unwrap();
        // Fully disjoint resources: no false positive, both instances "start".
        let _b = DataResourceLocks::acquire(
            &b.path().join("blocks"),
            &b.path().join("sync-state.sqlite3"),
        )
        .expect("a daemon with genuinely distinct resources must acquire its locks");
    }

    // --- stale (unlocked) lock file -----------------------------------------

    #[test]
    fn stale_unlocked_lock_file_is_reacquired() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("blocks");
        // First owner acquires and then exits (drop releases the OS lock but
        // deliberately leaves the lock file on disk).
        drop(ResourceLock::lock_block_store(&root).unwrap());
        assert!(root.join(BLOCK_STORE_LOCK_FILE).exists(), "lock file should persist after drop");

        // A fresh owner must acquire the pre-existing but unlocked file fine —
        // no stale-PID logic, mirroring the config-dir lock.
        let _new_owner = ResourceLock::lock_block_store(&root)
            .expect("a stale (unlocked) lock file must be reacquired by a new owner");
    }

    // --- deterministic order + rollback -------------------------------------

    #[test]
    fn conflict_on_db_rolls_back_the_block_store_lock() {
        // Owner A holds distinct block store A + DB S.
        let a = tempfile::tempdir().unwrap();
        let shared_db = a.path().join("sync-state.sqlite3");
        let _owner_a = DataResourceLocks::acquire(&a.path().join("blocks"), &shared_db).unwrap();

        // Daemon B has a *distinct* block store but shares A's DB. Acquisition
        // order is block store (succeeds) then DB (conflicts) — B must fail and
        // release the block-store lock it briefly held.
        let b = tempfile::tempdir().unwrap();
        let b_store = b.path().join("blocks");
        let err = DataResourceLocks::acquire(&b_store, &shared_db)
            .expect_err("sharing A's database must make B fail");
        assert!(err.to_string().contains("already in use"), "unexpected error: {err}");

        // Rollback check: B's block-store lock was released on failure, so it is
        // freely acquirable now.
        let _reacquire = ResourceLock::lock_block_store(&b_store)
            .expect("the block-store lock must be rolled back when the DB lock conflicts");
    }
}
