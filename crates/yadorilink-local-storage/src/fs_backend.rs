use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use crate::error::StorageError;
use crate::free_space::{self, VolumeFreeSpace};
use crate::traits::{BlockStore, ContentHash, GcReport, StorageUsage};

const GC_SWEEP_BATCH_SIZE: usize = 256;
const GC_SWEEP_BATCH_DELAY: Duration = Duration::from_millis(1);

/// Subdirectory of the store root where checksum-mismatched (corrupt) blocks
/// are retained for later forensic analysis instead of being hard-deleted.
/// Entries are named `<hash>.<n>` (a monotonic counter suffix, never a
/// wall-clock/random value that may be unavailable) so they stay traceable to
/// the original block and never collide. Its name is not a two-hex shard, and
/// its entries are not 64-char hash filenames, so the usage scan, presence
/// check, and prefix listing never treat it as a block shard.
const CORRUPT_DIR: &str = "corrupt";

/// Local filesystem-backed content-addressed block store.
///
/// Blocks are sharded under `<root>/<hash[0..2]>/<hash[2..4]>/<hash>` (git-object-style)
/// to avoid a single directory with millions of entries. The only paths ever
/// resolved are derived from validated hex-encoded SHA-256 hashes, so
/// caller-supplied strings can never escape `root` (see `validate_hash`).
pub struct FsBlockStore {
    root: PathBuf,
    usage: Mutex<StorageUsage>,
    /// An explicit headroom override (bytes), live-reloadable via
    /// `set_headroom_override_bytes` without
    /// reconstructing the store — mirrors the "mutable-after-construction
    /// field + setter" pattern `PeerSyncSession::set_authorized_groups`
    /// already established for a daemon-config-driven value that must take
    /// effect without a restart. `None` means "use the default formula"
    /// (`free_space::effective_headroom_bytes`'s `max(1 GiB, 5%)`) —
    /// consulted for `free_space_state`'s reporting unconditionally, and
    /// for `put`'s preflight only when `headroom_enforced` (below) is set.
    headroom_override_bytes: Mutex<Option<u64>>,
    /// Whether `put` actually gates writes on the headroom check at all
    /// — default `false` (bypassed, zero overhead on the default path,
    /// mirroring `TokenBucket`'s "`0` = unlimited, bypassed entirely"
    /// philosophy from the same change's rate-limiting section). A bare
    /// `FsBlockStore` constructed directly (as ~25 existing call sites
    /// across this workspace's tests, examples, and non-daemon crates
    /// already do, entirely unrelated to disk-pressure behavior) has no
    /// governance wiring context and must not start silently rejecting
    /// writes just because the *host machine's* real disk happens to be
    /// low on space relative to the `max(1 GiB, 5%)` default formula --
    /// confirmed as a real, not hypothetical, concern: this exact default
    /// tripped on the development machine used to build this feature (a
    /// disk genuinely at 96% capacity). `yadorilink-daemon` (the only
    /// production call site with real governance config) explicitly calls
    /// `set_headroom_enforced(true)` once at startup (section 5 wiring),
    /// after applying whatever headroom override its config resolves to —
    /// so production behavior still "checks the volume before every block
    /// write" once actually running as a daemon; only a bare, ungoverned
    /// `FsBlockStore` stays inert.
    headroom_enforced: AtomicBool,
    /// Hash-sharded commit/delete locks. The block path is the consistency
    /// boundary: verification, corrupt replacement, publish, and deletion
    /// must never race for the same content hash.
    hash_locks: Vec<Mutex<()>>,
    commit_io: Arc<dyn BlockCommitIo>,
    /// A block commit is authoritative once its shard directory is synced.
    /// Counter persistence happens afterward; failures mark the cheap cache
    /// dirty and are repaired by the next usage read instead of turning a
    /// durable block into a misleading `put` error.
    usage_dirty: AtomicBool,
    /// Seqlock-style coordination between physical block mutations and the
    /// occasional full-tree usage repair. A scan is adopted only when no
    /// mutation was active at either boundary and this generation did not
    /// change while the tree was walked.
    active_usage_mutations: AtomicU64,
    usage_generation: AtomicU64,
    #[cfg(test)]
    usage_scan_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

struct UsageMutationGuard<'a> {
    store: &'a FsBlockStore,
}

impl Drop for UsageMutationGuard<'_> {
    fn drop(&mut self) {
        self.store.usage_generation.fetch_add(1, Ordering::Release);
        self.store.active_usage_mutations.fetch_sub(1, Ordering::Release);
    }
}

trait BlockCommitIo: Send + Sync {
    fn prepare_shard_directory(&self, root: &Path, shard: &Path) -> Result<(), StorageError>;
    fn write_temp_durable(&self, path: &Path, data: &[u8]) -> Result<(), StorageError>;
    fn publish_noreplace(&self, temp: &Path, final_path: &Path) -> Result<(), StorageError>;
    fn sync_directory(&self, directory: &Path) -> Result<(), StorageError>;
    fn remove_file(&self, path: &Path) -> Result<(), StorageError>;
    /// Relocate a checksum-mismatched block file into the quarantine
    /// directory (creating it if needed) instead of destroying it. Renaming
    /// preserves the exact corrupt bytes for later forensic analysis while
    /// clearing the live path so the block is treated as absent and can be
    /// re-fetched/re-committed.
    fn quarantine_file(
        &self,
        quarantine_dir: &Path,
        source: &Path,
        dest: &Path,
    ) -> Result<(), StorageError>;
}

struct StdBlockCommitIo;

enum BlockCommitOutcome {
    Deduplicated,
    PublishedNew,
    RepairedCorrupt,
}

impl BlockCommitIo for StdBlockCommitIo {
    fn prepare_shard_directory(&self, root: &Path, shard: &Path) -> Result<(), StorageError> {
        let first_shard = shard.parent().expect("shard directories have a parent");
        let first_existed = first_shard.exists();
        let shard_existed = shard.exists();
        fs::create_dir_all(shard)?;
        // Persist root/aa, then aa/bb. Syncing only `bb` later persists the
        // block entry but not the newly-created shard directories themselves.
        if !first_existed {
            sync_directory(root)?;
        }
        if !shard_existed {
            sync_directory(first_shard)?;
        }
        Ok(())
    }

    fn write_temp_durable(&self, path: &Path, data: &[u8]) -> Result<(), StorageError> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    }

    fn publish_noreplace(&self, temp: &Path, final_path: &Path) -> Result<(), StorageError> {
        // A hard link publishes the already-synced inode atomically and never
        // replaces an existing winner. Temp and final live in one shard.
        fs::hard_link(temp, final_path)?;
        Ok(())
    }

    fn sync_directory(&self, directory: &Path) -> Result<(), StorageError> {
        sync_directory(directory)
    }

    fn remove_file(&self, path: &Path) -> Result<(), StorageError> {
        fs::remove_file(path)?;
        Ok(())
    }

    fn quarantine_file(
        &self,
        quarantine_dir: &Path,
        source: &Path,
        dest: &Path,
    ) -> Result<(), StorageError> {
        fs::create_dir_all(quarantine_dir)?;
        // A rename preserves the exact on-disk bytes and atomically clears the
        // live shard path, so the corrupt inode survives for analysis while
        // never masquerading as valid content on its content-addressed name.
        fs::rename(source, dest)?;
        Ok(())
    }
}

impl FsBlockStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        // The counter is a cache, never the durability authority. A crash can
        // occur after the block directory is synced but before the counter is
        // updated (or while its small file is being rewritten), so compare it
        // with the block tree on every open and repair any mismatch.
        let scanned_usage = scan_usage(&root)?;
        let usage = match read_usage_counter(&root)? {
            Some(cached) if cached == scanned_usage => cached,
            _ => {
                write_usage_counter(&root, scanned_usage)?;
                scanned_usage
            }
        };
        Ok(Self {
            root,
            usage: Mutex::new(usage),
            headroom_override_bytes: Mutex::new(None),
            headroom_enforced: AtomicBool::new(false),
            hash_locks: (0..256).map(|_| Mutex::new(())).collect(),
            commit_io: Arc::new(StdBlockCommitIo),
            usage_dirty: AtomicBool::new(false),
            active_usage_mutations: AtomicU64::new(0),
            usage_generation: AtomicU64::new(0),
            #[cfg(test)]
            usage_scan_hook: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn with_commit_io(
        root: impl Into<PathBuf>,
        commit_io: Arc<dyn BlockCommitIo>,
    ) -> Result<Self, StorageError> {
        let mut store = Self::new(root)?;
        store.commit_io = commit_io;
        Ok(store)
    }

    fn hash_lock(&self, hash: &str) -> &Mutex<()> {
        // Defense in depth: every current caller passes a hash already checked
        // by `validate_hash`, so the first two chars are valid hex. Rather than
        // `.expect()` on that invariant — which would panic the store if a
        // future caller ever reached here without validating first — derive the
        // shard leniently and fall back to shard 0 on any malformed prefix. A
        // wrong shard only costs some lock contention; it never corrupts data,
        // whereas a panic here would take down the whole block store.
        let shard = hash
            .get(0..2)
            .and_then(|prefix| u8::from_str_radix(prefix, 16).ok())
            .unwrap_or(0);
        &self.hash_locks[shard as usize]
    }

    fn headroom_override_bytes(&self) -> Option<u64> {
        *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// before persisting a block write, query free space on the
    /// volume hosting the block-store root and reject with `DiskPressure`
    /// if completing it would breach the configured headroom — checked
    /// before any temp file is created, so a rejection writes nothing. A
    /// no-op fast path (single relaxed atomic load) when `headroom_enforced`
    /// hasn't been turned on — see that field's doc comment.
    fn check_headroom(
        &self,
        target_path: &Path,
        additional_bytes: u64,
    ) -> Result<(), StorageError> {
        if !self.headroom_enforced.load(Ordering::Relaxed) {
            return Ok(());
        }
        let space = free_space::classify_volume(&self.root, self.headroom_override_bytes())?;
        if space.would_breach(additional_bytes) {
            return Err(StorageError::DiskPressure {
                path: target_path.to_path_buf(),
                volume: self.root.clone(),
                available_bytes: space.available_bytes,
                headroom_bytes: space.headroom_bytes,
            });
        }
        Ok(())
    }

    /// Default per-OS application data directory, per `local-storage` spec's
    /// "Default local storage root" scenario.
    pub fn default_root() -> Result<PathBuf, StorageError> {
        let base = dirs_next_app_data_dir().ok_or_else(|| {
            StorageError::InvalidPath("no application data directory available on this OS".into())
        })?;
        Ok(base.join("yadorilink").join("blocks"))
    }

    fn path_for_hash(&self, hash: &str) -> Result<PathBuf, StorageError> {
        validate_hash(hash)?;
        Ok(self.root.join(&hash[0..2]).join(&hash[2..4]).join(hash))
    }

    /// The shard directory a hash's block file lives under (see the struct
    /// docs for the sharding scheme). Does not validate `hash` — callers
    /// that need path-traversal protection on caller-supplied strings must
    /// call `validate_hash` (or `path_for_hash`, which does) themselves.
    fn shard_dir_for_hash(&self, hash: &str) -> PathBuf {
        self.root.join(&hash[0..2]).join(&hash[2..4])
    }

    fn hash_bytes(data: &[u8]) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn adjust_usage(&self, block_delta: i64, byte_delta: i64) -> Result<(), StorageError> {
        let mut usage = self.usage.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if block_delta >= 0 {
            usage.block_count += block_delta as u64;
        } else {
            usage.block_count = usage.block_count.saturating_sub((-block_delta) as u64);
        }
        if byte_delta >= 0 {
            usage.total_bytes += byte_delta as u64;
        } else {
            usage.total_bytes = usage.total_bytes.saturating_sub((-byte_delta) as u64);
        }
        write_usage_counter(&self.root, *usage)
    }

    fn record_committed_block(&self, bytes: u64) {
        let mut usage = self.usage.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        usage.block_count += 1;
        usage.total_bytes += bytes;
        if write_usage_counter(&self.root, *usage).is_err() {
            self.usage_dirty.store(true, Ordering::Release);
        }
    }

    fn begin_usage_mutation(&self) -> UsageMutationGuard<'_> {
        self.active_usage_mutations.fetch_add(1, Ordering::AcqRel);
        UsageMutationGuard { store: self }
    }

    fn repair_usage_from_disk(&self) -> Result<StorageUsage, StorageError> {
        loop {
            while self.active_usage_mutations.load(Ordering::Acquire) != 0 {
                std::thread::yield_now();
            }
            let generation = self.usage_generation.load(Ordering::Acquire);
            let scanned = scan_usage(&self.root);
            #[cfg(test)]
            if let Some(hook) =
                self.usage_scan_hook.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
            {
                hook();
            }

            let mut usage = self.usage.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.active_usage_mutations.load(Ordering::Acquire) != 0
                || self.usage_generation.load(Ordering::Acquire) != generation
            {
                drop(usage);
                std::thread::yield_now();
                continue;
            }
            let scanned = scanned?;
            *usage = scanned;
            if write_usage_counter(&self.root, scanned).is_err() {
                self.usage_dirty.store(true, Ordering::Release);
            }
            return Ok(scanned);
        }
    }

    /// Move a checksum-mismatched block off its live shard path, preserving
    /// its bytes under `<root>/corrupt/` for forensic analysis rather than
    /// destroying the evidence with a delete. The caller must hold the hash
    /// lock and an open usage-mutation guard. On any failure to relocate,
    /// fall back to a plain removal — a corrupt block must never be left on
    /// the live path masquerading as valid content-addressed data.
    fn quarantine_corrupt_block(&self, hash: &str, path: &Path) -> Result<(), StorageError> {
        let quarantine_dir = self.root.join(CORRUPT_DIR);
        let dest = quarantine_path(&quarantine_dir, hash);
        if self.commit_io.quarantine_file(&quarantine_dir, path, &dest).is_ok() {
            return Ok(());
        }
        self.commit_io.remove_file(path)
    }

    /// The only final-path publication primitive for block writes.
    fn commit_block(
        &self,
        hash: &str,
        data: &[u8],
        path: &Path,
    ) -> Result<BlockCommitOutcome, StorageError> {
        let mut repaired_corrupt = false;
        if path.exists() {
            let existing = fs::read(path)?;
            if Self::hash_bytes(&existing) == hash {
                self.commit_io
                    .sync_directory(path.parent().expect("block paths have a shard directory"))?;
                return Ok(BlockCommitOutcome::Deduplicated);
            }
            // A corrupt final path is not a valid copy of any block. Move it
            // into quarantine (preserving the corrupt bytes for analysis) and
            // durably record that removal before publishing its repair.
            repaired_corrupt = true;
            self.quarantine_corrupt_block(hash, path)?;
            if let Some(parent) = path.parent() {
                self.commit_io.sync_directory(parent)?;
            }
        }

        self.commit_io.prepare_shard_directory(
            &self.root,
            path.parent().expect("block paths have a shard directory"),
        )?;
        self.check_headroom(path, data.len() as u64)?;
        let tmp_path = unique_tmp_path(path);
        let publish = (|| {
            self.commit_io.write_temp_durable(&tmp_path, data)?;
            self.commit_io.publish_noreplace(&tmp_path, path)?;
            self.commit_io
                .sync_directory(path.parent().expect("block paths have a shard directory"))?;
            Ok::<(), StorageError>(())
        })();
        let _ = self.commit_io.remove_file(&tmp_path);
        match publish {
            Ok(()) if repaired_corrupt => Ok(BlockCommitOutcome::RepairedCorrupt),
            Ok(()) => Ok(BlockCommitOutcome::PublishedNew),
            Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A different store instance won the no-replace publish.
                // Treat it as dedup only after verifying its bytes.
                let winner = fs::read(path)?;
                if Self::hash_bytes(&winner) == hash {
                    self.commit_io.sync_directory(
                        path.parent().expect("block paths have a shard directory"),
                    )?;
                    Ok(BlockCommitOutcome::Deduplicated)
                } else {
                    Err(StorageError::ChecksumMismatch {
                        expected: hash.to_string(),
                        actual: Self::hash_bytes(&winner),
                    })
                }
            }
            Err(error) => Err(error),
        }
    }

    pub fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        let mut report = GcReport::default();
        for (index, hash) in self.list_by_prefix("")?.into_iter().enumerate() {
            if index > 0 && index % GC_SWEEP_BATCH_SIZE == 0 {
                std::thread::sleep(GC_SWEEP_BATCH_DELAY);
            }
            if live.contains(&hash) {
                continue;
            }
            let path = self.path_for_hash(&hash)?;
            let metadata = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(StorageError::Io(e)),
            };
            if metadata.modified().map(|mtime| mtime > grace_cutoff).unwrap_or(true) {
                continue;
            }

            report.blocks_deleted += 1;
            report.bytes_reclaimed += metadata.len();
            if !dry_run {
                self.delete(&hash)?;
            }
        }

        self.repair_usage_from_disk()?;
        Ok(report)
    }

    /// `sync-performance` the actual batched presence check,
    /// reading each shard directory's listing once and checking
    /// membership in-memory, instead of the trait's default (one `stat`
    /// per hash via `exists`). This is plain, non-runtime-aware blocking
    /// I/O; `present_blocks` below is responsible for keeping it off a
    /// tokio worker thread when one is present.
    fn present_blocks_batched(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        // Validate up front, same as the default `exists`-per-hash impl
        // would eventually reject any invalid hash — preserves the
        // "invalid input is rejected" behavior of the old default.
        for hash in hashes {
            validate_hash(hash)?;
        }

        // Group hash indices by shard directory so each shard is
        // `read_dir`'d at most once, however many of the requested hashes
        // land in it, rather than one `stat` per hash.
        let mut by_shard: HashMap<PathBuf, Vec<usize>> = HashMap::new();
        for (i, hash) in hashes.iter().enumerate() {
            by_shard.entry(self.shard_dir_for_hash(hash)).or_default().push(i);
        }

        let mut present = vec![false; hashes.len()];
        for (shard_dir, indices) in by_shard {
            let entries: HashSet<String> = match fs::read_dir(&shard_dir) {
                Ok(read_dir) => read_dir
                    .filter_map(|entry| entry.ok())
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect(),
                // A shard directory that doesn't exist yet just means none
                // of the hashes routed to it are present — same as `exists`
                // returning `false` for each of them individually.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
                Err(e) => return Err(StorageError::Io(e)),
            };
            for i in indices {
                present[i] = entries.contains(hashes[i].as_str());
            }
        }
        Ok(present)
    }
}

/// appends a collision-free `.yadorilink-tmp` suffix to `path`'s
/// full filename — never `with_extension`, which *replaces* the extension
/// and previously produced a single **fixed** `<hash>.tmp` path shared by
/// every concurrent writer of that same hash. Also mixes in the current
/// process id and a per-process monotonic counter, mirroring
/// `chunker::unique_tmp_path` (which fixed the exact same class of
/// bug for `reconstruct_file`'s write path) — so two concurrent `put`s of
/// the identical content hash (routine under up-to-16-way concurrent
/// `reconcile_files` and multi-peer fetch of the same block,
/// `peer_session.rs`'s `MAX_CONCURRENT_RECONCILES`) never share a temp
/// path, and can no longer clobber each other into a torn block (a rename
/// of a half-written temp file over the target) or a spurious `ENOENT` (one
/// writer's rename consuming the other's already-renamed-away temp file).
fn unique_tmp_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = OsString::from(path.file_name().unwrap_or_default());
    name.push(format!(".yadorilink-tmp.{}.{n}", std::process::id()));
    path.with_file_name(name)
}

/// A collision-free quarantine destination for a corrupt block. The name is
/// `<hash>.<n>` where `n` is a per-process monotonic counter — traceable back
/// to the original content hash, unique across concurrent quarantines, and
/// independent of any wall-clock/random source (which may be unavailable).
/// `hash` is always a validated 64-char hex digest (it came from
/// `path_for_hash`/`hash_bytes`), so the joined path stays inside the
/// quarantine directory.
fn quarantine_path(quarantine_dir: &Path, hash: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    quarantine_dir.join(format!("{hash}.{n}"))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), StorageError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<(), StorageError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL-terminated and remains alive for the call. The
    // returned handle is checked and closed on every successful-open path.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(StorageError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: `handle` is a valid directory handle returned by CreateFileW.
    let flushed = unsafe { FlushFileBuffers(handle) };
    let flush_error = (flushed == 0).then(std::io::Error::last_os_error);
    // SAFETY: this function owns the valid handle and closes it exactly once.
    unsafe { CloseHandle(handle) };
    if let Some(error) = flush_error {
        return Err(StorageError::Io(error));
    }
    Ok(())
}

/// A valid block key is exactly a 64-character lowercase hex SHA-256 digest.
/// This rejects path traversal sequences, absolute paths, and anything else
/// that isn't a bare content hash, before it ever reaches the filesystem.
fn validate_hash(hash: &str) -> Result<(), StorageError> {
    if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(())
    } else {
        Err(StorageError::InvalidPath(format!("not a valid content hash: {hash:?}")))
    }
}

impl BlockStore for FsBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        let hash = Self::hash_bytes(data);
        let path = self.path_for_hash(&hash)?;
        // Keep accounting in the same critical section as publication. A
        // delete of this hash cannot land after publish but before the usage
        // increment and leave the counter permanently one block too high.
        let _hash_guard =
            self.hash_lock(&hash).lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _usage_mutation = self.begin_usage_mutation();
        match self.commit_block(&hash, data, &path)? {
            BlockCommitOutcome::Deduplicated => {}
            BlockCommitOutcome::PublishedNew => {
                self.record_committed_block(data.len() as u64);
            }
            BlockCommitOutcome::RepairedCorrupt => {
                // A corrupt file can have an arbitrary old size. Defer the
                // full-tree repair until this mutation guard has closed so the
                // stable scanner cannot wait on its own active writer.
                self.usage_dirty.store(true, Ordering::Release);
            }
        }
        Ok(hash)
    }

    /// Turns `put`'s preflight gate on or off — see `headroom_enforced`'s
    /// doc comment. `yadorilink-daemon` calls this with `true` once at
    /// startup (through `Arc<dyn BlockStore>`, hence this living on the
    /// trait rather than only as an inherent method); direct/test users of
    /// this crate that never call it get the pre-existing unthrottled
    /// behavior.
    fn set_headroom_enforced(&self, enforced: bool) {
        self.headroom_enforced.store(enforced, Ordering::Relaxed);
    }

    /// Live reload for the headroom check: applied
    /// to every subsequent `put` call, no reconstruction needed.
    fn set_headroom_override_bytes(&self, headroom_bytes: Option<u64>) {
        *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner()) = headroom_bytes;
    }

    /// The block-store root's volume free-space snapshot,
    /// for `yadorilink status`'s per-volume reporting — the exact same
    /// `classify_volume` call `put`'s preflight check uses, so the two can
    /// never disagree. Always computed from real disk state (using the
    /// configured override, or the default formula) regardless of whether
    /// `headroom_enforced` is set, since a user querying status wants to
    /// see real free-space health either way.
    fn free_space(&self) -> Result<Option<VolumeFreeSpace>, StorageError> {
        Ok(Some(free_space::classify_volume(&self.root, self.headroom_override_bytes())?))
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.path_for_hash(hash)?;
        let _hash_guard =
            self.hash_lock(hash).lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let data = fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(hash.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let actual = Self::hash_bytes(&data);
        if actual != hash {
            // self-heal: a checksum mismatch here proves the
            // on-disk file is torn/corrupt garbage that does not match its
            // own content-addressed name — never valid content a caller
            // could legitimately want. Clearing it from the live path is
            // safe: a hash-named file whose bytes don't hash to that name can
            // never be the *only* copy of anything real (a correct copy can
            // always be re-fetched from any peer that has it, or re-derived
            // locally), so getting it off the live path here — rather than
            // leaving it in place to poison every future `put`'s `exists`
            // short-circuit forever — lets a subsequent `put` of the correct
            // bytes re-materialize the block instead of the referencing file
            // staying permanently un-hydratable. Rather than hard-deleting
            // (which would destroy evidence a user may need to analyze the
            // failure), quarantine it: the corrupt bytes are preserved under
            // `<root>/corrupt/` and the block is still treated as absent.
            // Best effort: if quarantine and its delete fallback both fail,
            // the mismatch is still reported (the caller's retry path is
            // unaffected either way).
            let _usage_mutation = self.begin_usage_mutation();
            let _ = self.quarantine_corrupt_block(hash, &path);
            self.usage_dirty.store(true, Ordering::Release);
            if let Some(parent) = path.parent() {
                let _ = self.commit_io.sync_directory(parent);
            }
            return Err(StorageError::ChecksumMismatch { expected: hash.to_string(), actual });
        }
        Ok(data)
    }

    /// `sync-performance` skips the SHA-256 re-hash `get`
    /// performs. Only safe for callers who already independently
    /// guarantee integrity for this read (see the trait doc); this
    /// implementation intentionally does the bare minimum (path
    /// validation + `NotFound` mapping) and nothing else.
    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.path_for_hash(hash)?;
        fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(hash.to_string())
            } else {
                StorageError::Io(e)
            }
        })
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError> {
        let path = self.path_for_hash(hash)?;
        let _hash_guard =
            self.hash_lock(hash).lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _usage_mutation = self.begin_usage_mutation();
        let size = match fs::metadata(&path) {
            Ok(metadata) => Some(metadata.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(StorageError::Io(e)),
        };
        match self.commit_io.remove_file(&path) {
            Ok(()) => {
                // From this point the filesystem changed even if directory
                // sync or counter persistence below fails. A retry sees
                // NotFound, so carry a durable-in-process repair obligation
                // into the next usage read now.
                self.usage_dirty.store(true, Ordering::Release);
                if let Some(parent) = path.parent() {
                    self.commit_io.sync_directory(parent)?;
                }
                if let Some(size) = size {
                    self.adjust_usage(-1, -(size as i64))?;
                }
                Ok(())
            }
            Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        Ok(self.path_for_hash(hash)?.exists())
    }

    /// Cache reclamation of specific on-demand blocks — the single
    /// exception to the version-liveness rule `sweep` enforces (see the
    /// trait method's doc comment for the caller's fail-closed
    /// obligations). Overridden here to size each block from its on-disk
    /// metadata rather than reading its contents. Deleting the block also
    /// reconciles the persisted usage counters via `delete`, so a later
    /// `sweep`/`usage` sees the freed space; a hash already absent is a
    /// no-op, keeping a retried reclamation idempotent.
    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError> {
        let mut report = GcReport::default();
        for hash in hashes {
            let path = self.path_for_hash(hash)?;
            let bytes = match fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(StorageError::Io(e)),
            };
            self.delete(hash)?;
            report.blocks_deleted += 1;
            report.bytes_reclaimed += bytes;
        }
        Ok(report)
    }

    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        if !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(StorageError::InvalidPath(format!("not a valid hex prefix: {prefix:?}")));
        }
        let mut results = Vec::new();
        collect_matching(&self.root, prefix, &mut results)?;
        Ok(results)
    }

    fn usage(&self) -> Result<StorageUsage, StorageError> {
        if self.usage_dirty.swap(false, Ordering::AcqRel) {
            self.repair_usage_from_disk()?;
        }
        Ok(*self.usage.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    /// Delegates to the inherent `FsBlockStore::sweep` (already exercised
    /// directly by this module's own unit tests below) so
    /// `yadorilink-daemon`'s `Arc<dyn BlockStore>` can invoke it too — see
    /// the trait method's doc comment.
    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        FsBlockStore::sweep(self, live, grace_cutoff, dry_run)
    }

    /// `sync-performance` overrides the trait's N-`stat` default
    /// with a real batch check (`present_blocks_batched`), and — since
    /// `peer_session.rs`/`hydration.rs` call this synchronously from
    /// `async fn`s with no `.await` — keeps that blocking filesystem work
    /// off a tokio worker thread when one is present, via
    /// `tokio::task::block_in_place`, without changing this method's
    /// signature (so those call sites need no changes).
    ///
    /// `block_in_place` panics if called on a current-thread tokio
    /// runtime, so this only takes that path when a *multi-threaded*
    /// runtime is actually current (true for `yadorilink-daemon`/
    /// `yadorilink-cli`'s `#[tokio::main]`, and for any
    /// `#[tokio::test(flavor = "multi_thread",...)]`). Outside a tokio
    /// runtime (plain `#[test]`s here) or on a current-thread runtime
    /// (the plain `#[tokio::test]`s used throughout
    /// `yadorilink-sync-core`), it just runs the work inline, exactly as
    /// the previous default did — behavior is unchanged in both cases.
    // `madsim`'s tokio shim has no `block_in_place`/`runtime_flavor` (its
    // cooperative scheduler has no real OS thread to block in place on) —
    // under `--cfg madsim` this always takes the same inline fallback the
    // multi-thread fast path above would take on any non-multi-thread
    // runtime anyway (see this method's doc comment), so correctness is
    // unaffected; only the off-executor-thread performance optimization is
    // skipped under simulation.
    #[cfg(not(madsim))]
    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| self.present_blocks_batched(hashes))
            }
            _ => self.present_blocks_batched(hashes),
        }
    }

    #[cfg(madsim)]
    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        self.present_blocks_batched(hashes)
    }
}

const USAGE_COUNTER_FILE: &str = ".yadorilink-usage";

fn usage_counter_path(root: &Path) -> PathBuf {
    root.join(USAGE_COUNTER_FILE)
}

fn read_usage_counter(root: &Path) -> Result<Option<StorageUsage>, StorageError> {
    match fs::read_to_string(usage_counter_path(root)) {
        Ok(contents) => Ok(parse_usage_counter(&contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StorageError::Io(e)),
    }
}

fn parse_usage_counter(contents: &str) -> Option<StorageUsage> {
    let mut parts = contents.split_whitespace();
    let block_count = parts.next()?.parse().ok()?;
    let total_bytes = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(StorageUsage { block_count, total_bytes })
}

fn write_usage_counter(root: &Path, usage: StorageUsage) -> Result<(), StorageError> {
    fs::write(usage_counter_path(root), format!("{} {}\n", usage.block_count, usage.total_bytes))
        .map_err(StorageError::Io)
}

fn scan_usage(root: &Path) -> Result<StorageUsage, StorageError> {
    let mut hashes = Vec::new();
    collect_matching(root, "", &mut hashes)?;
    let mut usage = StorageUsage { block_count: hashes.len() as u64, total_bytes: 0 };
    for hash in hashes {
        let path = root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
        usage.total_bytes += fs::metadata(path)?.len();
    }
    Ok(usage)
}

fn collect_matching(dir: &Path, prefix: &str, out: &mut Vec<String>) -> Result<(), StorageError> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_matching(&entry.path(), prefix, out)?;
        } else if let Some(name) = entry.file_name().to_str() {
            if name.len() == 64 && name.starts_with(prefix) {
                out.push(name.to_string());
            }
        }
    }
    Ok(())
}

fn dirs_next_app_data_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        #[cfg(target_os = "macos")]
        {
            return Some(home.join("Library").join("Application Support"));
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
                return Some(PathBuf::from(xdg));
            }
            return Some(home.join(".local").join("share"));
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            return Some(home);
        }
    }
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return Some(PathBuf::from(appdata));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CommitStage {
        ShardDurable,
        TempDurable,
        Published,
        DirectoryDurable,
    }

    struct RecordingCommitIo {
        inner: StdBlockCommitIo,
        completed: Mutex<Vec<CommitStage>>,
        fail_before: Option<CommitStage>,
    }

    impl RecordingCommitIo {
        fn new(fail_before: Option<CommitStage>) -> Self {
            Self { inner: StdBlockCommitIo, completed: Mutex::new(Vec::new()), fail_before }
        }

        fn complete(&self, stage: CommitStage) -> Result<(), StorageError> {
            if self.fail_before == Some(stage) {
                return Err(StorageError::Io(std::io::Error::other(format!(
                    "injected failure before {stage:?}"
                ))));
            }
            self.completed.lock().unwrap().push(stage);
            Ok(())
        }
    }

    impl BlockCommitIo for RecordingCommitIo {
        fn prepare_shard_directory(&self, root: &Path, shard: &Path) -> Result<(), StorageError> {
            self.inner.prepare_shard_directory(root, shard)?;
            self.complete(CommitStage::ShardDurable)
        }

        fn write_temp_durable(&self, path: &Path, data: &[u8]) -> Result<(), StorageError> {
            if self.fail_before == Some(CommitStage::TempDurable) {
                return self.complete(CommitStage::TempDurable);
            }
            self.inner.write_temp_durable(path, data)?;
            self.complete(CommitStage::TempDurable)
        }

        fn publish_noreplace(&self, temp: &Path, final_path: &Path) -> Result<(), StorageError> {
            if self.fail_before == Some(CommitStage::Published) {
                return self.complete(CommitStage::Published);
            }
            self.inner.publish_noreplace(temp, final_path)?;
            self.complete(CommitStage::Published)
        }

        fn sync_directory(&self, directory: &Path) -> Result<(), StorageError> {
            if self.fail_before == Some(CommitStage::DirectoryDurable) {
                return self.complete(CommitStage::DirectoryDurable);
            }
            self.inner.sync_directory(directory)?;
            self.complete(CommitStage::DirectoryDurable)
        }

        fn remove_file(&self, path: &Path) -> Result<(), StorageError> {
            self.inner.remove_file(path)
        }

        fn quarantine_file(
            &self,
            quarantine_dir: &Path,
            source: &Path,
            dest: &Path,
        ) -> Result<(), StorageError> {
            self.inner.quarantine_file(quarantine_dir, source, dest)
        }
    }

    #[test]
    fn block_commit_success_requires_file_publish_and_directory_sync_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let io = Arc::new(RecordingCommitIo::new(None));
        let store = FsBlockStore::with_commit_io(dir.path(), io.clone()).unwrap();

        let hash = store.put(b"durable block").unwrap();
        assert_eq!(store.get(&hash).unwrap(), b"durable block");
        assert_eq!(
            *io.completed.lock().unwrap(),
            vec![
                CommitStage::ShardDurable,
                CommitStage::TempDurable,
                CommitStage::Published,
                CommitStage::DirectoryDurable
            ]
        );
    }

    #[test]
    fn block_commit_does_not_report_success_before_any_durability_stage() {
        let cases = [
            (CommitStage::ShardDurable, vec![]),
            (CommitStage::TempDurable, vec![CommitStage::ShardDurable]),
            (CommitStage::Published, vec![CommitStage::ShardDurable, CommitStage::TempDurable]),
            (
                CommitStage::DirectoryDurable,
                vec![CommitStage::ShardDurable, CommitStage::TempDurable, CommitStage::Published],
            ),
        ];
        for (fail_before, expected_completed) in cases {
            let dir = tempfile::tempdir().unwrap();
            let io = Arc::new(RecordingCommitIo::new(Some(fail_before)));
            let store = FsBlockStore::with_commit_io(dir.path(), io.clone()).unwrap();

            assert!(store.put(b"not yet durable").is_err(), "stage {fail_before:?}");
            assert_eq!(*io.completed.lock().unwrap(), expected_completed, "stage {fail_before:?}");
        }
    }

    #[test]
    fn put_repairs_a_corrupt_final_without_a_prior_get() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let data = b"correct replacement bytes";
        let hash = store.put(data).unwrap();
        let path = store.path_for_hash(&hash).unwrap();
        fs::write(&path, b"corrupt final bytes").unwrap();

        assert_eq!(store.put(data).unwrap(), hash);
        assert_eq!(store.get(&hash).unwrap(), data);
        assert_eq!(store.usage().unwrap(), StorageUsage { block_count: 1, total_bytes: 25 });
    }

    #[test]
    fn usage_reports_block_count_and_total_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();

        let a = store.put(b"abc").unwrap();
        let b = store.put(b"12345").unwrap();
        let duplicate = store.put(b"abc").unwrap();
        assert_eq!(duplicate, a);

        let usage = store.usage().unwrap();
        assert_eq!(usage.block_count, 2);
        assert_eq!(usage.total_bytes, 8);

        store.delete(&a).unwrap();
        let usage_after_delete = store.usage().unwrap();
        assert_eq!(usage_after_delete.block_count, 1);
        assert_eq!(usage_after_delete.total_bytes, 5);
        assert!(store.exists(&b).unwrap());
    }

    #[test]
    fn usage_repair_retries_when_put_commits_after_its_tree_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(dir.path()).unwrap());
        store.put(b"existing").unwrap();
        store.usage_dirty.store(true, Ordering::Release);

        let scan_started = Arc::new(Barrier::new(2));
        let resume_scan = Arc::new(Barrier::new(2));
        let first_scan = Arc::new(AtomicBool::new(true));
        *store.usage_scan_hook.lock().unwrap() = Some(Arc::new({
            let scan_started = scan_started.clone();
            let resume_scan = resume_scan.clone();
            let first_scan = first_scan.clone();
            move || {
                if first_scan.swap(false, Ordering::AcqRel) {
                    scan_started.wait();
                    resume_scan.wait();
                }
            }
        }));

        let usage_store = store.clone();
        let usage_thread = std::thread::spawn(move || usage_store.usage().unwrap());
        scan_started.wait();
        store.put(b"committed after snapshot").unwrap();
        resume_scan.wait();

        assert_eq!(usage_thread.join().unwrap(), StorageUsage { block_count: 2, total_bytes: 32 });
        assert_eq!(
            parse_usage_counter(&fs::read_to_string(usage_counter_path(dir.path())).unwrap()),
            Some(StorageUsage { block_count: 2, total_bytes: 32 })
        );
    }

    #[test]
    fn usage_repair_retries_when_delete_commits_after_its_tree_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(dir.path()).unwrap());
        let deleted = store.put(b"delete me").unwrap();
        store.put(b"keep").unwrap();
        store.usage_dirty.store(true, Ordering::Release);

        let scan_started = Arc::new(Barrier::new(2));
        let resume_scan = Arc::new(Barrier::new(2));
        let first_scan = Arc::new(AtomicBool::new(true));
        *store.usage_scan_hook.lock().unwrap() = Some(Arc::new({
            let scan_started = scan_started.clone();
            let resume_scan = resume_scan.clone();
            let first_scan = first_scan.clone();
            move || {
                if first_scan.swap(false, Ordering::AcqRel) {
                    scan_started.wait();
                    resume_scan.wait();
                }
            }
        }));

        let usage_store = store.clone();
        let usage_thread = std::thread::spawn(move || usage_store.usage().unwrap());
        scan_started.wait();
        store.delete(&deleted).unwrap();
        resume_scan.wait();

        assert_eq!(usage_thread.join().unwrap(), StorageUsage { block_count: 1, total_bytes: 4 });
        assert_eq!(
            parse_usage_counter(&fs::read_to_string(usage_counter_path(dir.path())).unwrap()),
            Some(StorageUsage { block_count: 1, total_bytes: 4 })
        );
    }

    #[test]
    fn uppercase_hash_aliases_are_rejected_before_lock_or_path_resolution() {
        let hash = "A".repeat(64);
        assert!(matches!(validate_hash(&hash), Err(StorageError::InvalidPath(_))));
    }

    #[test]
    fn corrupt_self_heal_repairs_usage_after_removing_the_bad_inode() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let hash = store.put(b"correct bytes").unwrap();
        fs::write(store.path_for_hash(&hash).unwrap(), b"corrupt").unwrap();

        assert!(matches!(store.get(&hash), Err(StorageError::ChecksumMismatch { .. })));
        assert_eq!(store.usage().unwrap(), StorageUsage { block_count: 0, total_bytes: 0 });
    }

    #[test]
    fn corrupt_block_is_quarantined_not_deleted_on_get() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let hash = store.put(b"correct bytes").unwrap();
        let path = store.path_for_hash(&hash).unwrap();
        fs::write(&path, b"corrupt").unwrap();

        assert!(matches!(store.get(&hash), Err(StorageError::ChecksumMismatch { .. })));
        // The live path must end up absent so `present`/`get` report it
        // missing and the normal re-fetch/re-commit path can restore it.
        assert!(!path.exists());
        // The corrupt bytes are preserved for forensic analysis under the
        // quarantine directory, traceable to the original hash, not deleted.
        let quarantine_dir = dir.path().join("corrupt");
        let preserved: Vec<_> =
            fs::read_dir(&quarantine_dir).unwrap().filter_map(|entry| entry.ok()).collect();
        assert_eq!(preserved.len(), 1);
        let name = preserved[0].file_name().into_string().unwrap();
        assert!(name.starts_with(&hash), "quarantine entry traceable to hash: {name}");
        assert_eq!(fs::read(preserved[0].path()).unwrap(), b"corrupt");
    }

    #[test]
    fn quarantined_block_is_recoverable_by_reput_with_correct_usage() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let data = b"correct bytes";
        let hash = store.put(data).unwrap();
        let path = store.path_for_hash(&hash).unwrap();
        fs::write(&path, b"corrupt").unwrap();

        // Quarantine on `get` removes the block from the live path and from
        // usage accounting (it is treated as absent).
        assert!(matches!(store.get(&hash), Err(StorageError::ChecksumMismatch { .. })));
        assert_eq!(store.usage().unwrap(), StorageUsage { block_count: 0, total_bytes: 0 });

        // Recovery still works: re-putting the correct bytes re-establishes
        // the live block and the counters are correct.
        assert_eq!(store.put(data).unwrap(), hash);
        assert_eq!(store.get(&hash).unwrap(), data);
        assert_eq!(store.usage().unwrap(), StorageUsage { block_count: 1, total_bytes: 13 });
    }

    #[test]
    fn commit_block_quarantines_corrupt_final_before_repair() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let data = b"correct replacement bytes";
        let hash = store.put(data).unwrap();
        let path = store.path_for_hash(&hash).unwrap();
        fs::write(&path, b"corrupt final bytes").unwrap();

        // A re-put drives `commit_block`'s corrupt-final replacement path,
        // which must quarantine the old corrupt bytes before publishing the
        // repair rather than silently deleting them.
        assert_eq!(store.put(data).unwrap(), hash);
        assert_eq!(store.get(&hash).unwrap(), data);
        assert_eq!(store.usage().unwrap(), StorageUsage { block_count: 1, total_bytes: 25 });

        let quarantine_dir = dir.path().join("corrupt");
        let preserved: Vec<_> =
            fs::read_dir(&quarantine_dir).unwrap().filter_map(|entry| entry.ok()).collect();
        assert_eq!(preserved.len(), 1);
        let name = preserved[0].file_name().into_string().unwrap();
        assert!(name.starts_with(&hash), "quarantine entry traceable to hash: {name}");
        assert_eq!(fs::read(preserved[0].path()).unwrap(), b"corrupt final bytes");
    }

    #[test]
    fn delete_sync_failure_still_repairs_usage_on_next_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FsBlockStore::new(dir.path()).unwrap();
        let hash = store.put(b"delete me").unwrap();
        store.commit_io = Arc::new(RecordingCommitIo::new(Some(CommitStage::DirectoryDurable)));

        assert!(store.delete(&hash).is_err());
        assert_eq!(store.usage().unwrap(), StorageUsage { block_count: 0, total_bytes: 0 });
    }

    #[test]
    fn usage_counters_persist_and_initialize_from_walk_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        store.put(b"abcd").unwrap();
        store.put(b"123456").unwrap();
        assert_eq!(store.usage().unwrap(), StorageUsage { block_count: 2, total_bytes: 10 });
        drop(store);

        let reopened = FsBlockStore::new(dir.path()).unwrap();
        assert_eq!(reopened.usage().unwrap(), StorageUsage { block_count: 2, total_bytes: 10 });
        drop(reopened);

        // Simulate power loss after the block directory entry became durable
        // but before its usage counter update reached disk. The stale counter
        // is syntactically valid and still must not be trusted on reopen.
        fs::write(dir.path().join(USAGE_COUNTER_FILE), b"1 4\n").unwrap();
        let rebuilt_from_stale = FsBlockStore::new(dir.path()).unwrap();
        assert_eq!(
            rebuilt_from_stale.usage().unwrap(),
            StorageUsage { block_count: 2, total_bytes: 10 }
        );
        drop(rebuilt_from_stale);

        fs::remove_file(dir.path().join(USAGE_COUNTER_FILE)).unwrap();
        let rebuilt = FsBlockStore::new(dir.path()).unwrap();
        assert_eq!(rebuilt.usage().unwrap(), StorageUsage { block_count: 2, total_bytes: 10 });
    }

    #[test]
    fn sweep_deletes_only_blocks_outside_live_set_and_reconciles_usage() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let live = store.put(b"live").unwrap();
        let dead = store.put(b"dead!!").unwrap();

        let report = store
            .sweep(
                &HashSet::from([live.clone()]),
                SystemTime::now() + std::time::Duration::from_secs(1),
                false,
            )
            .unwrap();

        assert_eq!(report, GcReport { blocks_deleted: 1, bytes_reclaimed: 6 });
        assert!(store.exists(&live).unwrap());
        assert!(!store.exists(&dead).unwrap());
        assert_eq!(store.usage().unwrap(), StorageUsage { block_count: 1, total_bytes: 4 });
    }

    #[test]
    fn sweep_dry_run_and_grace_cutoff_do_not_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let old_enough = store.put(b"candidate").unwrap();
        let too_new = store.put(b"new").unwrap();

        let dry_run = store
            .sweep(&HashSet::new(), SystemTime::now() + std::time::Duration::from_secs(1), true)
            .unwrap();
        assert_eq!(dry_run, GcReport { blocks_deleted: 2, bytes_reclaimed: 12 });
        assert!(store.exists(&old_enough).unwrap());
        assert!(store.exists(&too_new).unwrap());

        let grace_skipped = store.sweep(&HashSet::new(), SystemTime::UNIX_EPOCH, false).unwrap();
        assert_eq!(grace_skipped, GcReport::default());
        assert!(store.exists(&old_enough).unwrap());
        assert!(store.exists(&too_new).unwrap());
        assert_eq!(store.usage().unwrap(), StorageUsage { block_count: 2, total_bytes: 12 });
    }

    #[test]
    fn sweep_is_noop_when_every_block_is_live() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let a = store.put(b"a").unwrap();
        let b = store.put(b"bb").unwrap();

        let report = store
            .sweep(
                &HashSet::from([a.clone(), b.clone()]),
                SystemTime::now() + std::time::Duration::from_secs(1),
                false,
            )
            .unwrap();

        assert_eq!(report, GcReport::default());
        assert!(store.exists(&a).unwrap());
        assert!(store.exists(&b).unwrap());
        assert_eq!(store.usage().unwrap(), StorageUsage { block_count: 2, total_bytes: 3 });
    }

    #[test]
    fn sweep_resumes_after_prior_partial_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let already_deleted = store.put(b"gone").unwrap();
        let remaining_a = store.put(b"left-a").unwrap();
        let remaining_b = store.put(b"left-bb").unwrap();

        store.delete(&already_deleted).unwrap();
        let report = store
            .sweep(&HashSet::new(), SystemTime::now() + std::time::Duration::from_secs(1), false)
            .unwrap();

        assert_eq!(report, GcReport { blocks_deleted: 2, bytes_reclaimed: 13 });
        assert!(!store.exists(&already_deleted).unwrap());
        assert!(!store.exists(&remaining_a).unwrap());
        assert!(!store.exists(&remaining_b).unwrap());
        assert_eq!(store.usage().unwrap(), StorageUsage::default());
    }
}
