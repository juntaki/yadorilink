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
use crate::io_diag::{self, Op};
use crate::traits::{BlockStore, ContentHash, GcReport, LocallyHashedBlock, StorageUsage};

/// One bulk-ingest block's outcome: its hash, the commit outcome, an
/// optional dirty-path to fsync, and its byte length -- see
/// `FsBlockStore::commit_batch`'s own `results` binding.
type BulkIngestBlockResult = Result<(ContentHash, BlockCommitOutcome, Option<PathBuf>, u64), StorageError>;

/// Single crate-wide boundary for removing a filesystem object. Block-store
/// deletion and materialization cleanup both pass through here so audits see
/// every physical removal at one capability seam.
pub(crate) fn remove_path(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)
}

/// Single crate-wide boundary for atomically replacing a filesystem path.
/// Callers remain responsible for their operation-specific durability and
/// containment checks.
pub(crate) fn rename_path(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

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
    /// M6-2B2 test-only barrier: called synchronously from `commit_batch`
    /// right before it returns, i.e. exactly at the `staged -> durable`
    /// boundary `BulkIngest`/`put_prepared_batch` sit on top of -- every
    /// block in the batch is already physically durable (written, synced,
    /// shard-dir synced) by the time this fires, but this function has not
    /// yet returned to ITS caller, so nothing downstream (FileRecord
    /// publish, provenance recording) has happened yet either. Tests use
    /// this to deterministically observe "durable but not yet authoritative"
    /// from another thread -- see `flush_durable_gates_authoritative_
    /// publication_deterministically`/`flush_durable_gates_receiver_
    /// provenance_deterministically`. Not `#[cfg(test)]`-gated (unlike
    /// `usage_scan_hook`, an internal-only unit-test seam) because these
    /// two invariant tests live in OTHER crates (`yadorilink-local-
    /// capture`, `yadorilink-peer-session`), which need `install_bulk_
    /// ingest_barrier_hook_for_tests` below to be a real, always-compiled
    /// public method -- `#[cfg(test)]` does not cross a crate boundary.
    /// Zero cost in production: one extra `Option`-checked `Mutex` lock
    /// per batch, never set outside a test.
    bulk_ingest_barrier_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Shard-tree directories this process created but has not yet made
    /// durable (i.e. has not yet fsynced the parent that contains their
    /// directory entry).
    ///
    /// Deferring the ancestor fsyncs to the end of a batch is what makes
    /// them collapsible, but it also widens the window in which a
    /// directory *exists* without being durable — and `exists()` alone
    /// cannot tell the two apart. Without this set, a second committer
    /// running concurrently could observe `root/aa` already there, skip
    /// the store-root fsync on that basis, publish a block underneath it
    /// and return `Ok` while the entry for `aa` was still only in page
    /// cache; a crash at that moment loses a block the caller was told was
    /// durable. Membership here means "seen to exist, but this process
    /// knows that is not yet a durability claim", so such a committer
    /// takes on the publish itself instead of trusting it.
    ///
    /// Entries are inserted *before* the `mkdir` that creates them, so
    /// there is no interval in which the directory is visible on disk but
    /// absent from this set, and removed only after the fsync that
    /// publishes them has returned `Ok`. Nothing in this store ever
    /// removes a shard directory (`delete`/`sweep` unlink block files and
    /// leave the tree standing), so a published entry never has to be
    /// invalidated. Stays small: it holds only what is in flight, never a
    /// map of the whole tree.
    unpublished_directories: Mutex<HashSet<PathBuf>>,
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

/// Which level of the `root/aa/bb` shard tree a directory fsync is
/// publishing. Every level goes through the identical `sync_directory`
/// call — this only separates the measurement counters, because the three
/// levels have very different call frequencies and telling them apart is
/// the whole reason the directory-fsync cost was findable at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirSyncKind {
    /// The store root, publishing a newly created `aa` prefix directory.
    StoreRoot,
    /// A `root/aa` prefix directory, publishing a newly created `bb` shard.
    Prefix,
    /// A `root/aa/bb` shard directory, publishing block files inside it.
    Shard,
}

impl DirSyncKind {
    fn op(self) -> Op {
        match self {
            DirSyncKind::StoreRoot => Op::DirFsyncRoot,
            DirSyncKind::Prefix => Op::DirFsyncFirstShard,
            DirSyncKind::Shard => Op::DirFsyncShard,
        }
    }
}

trait BlockCommitIo: Send + Sync {
    /// Creates the block's `root/aa/bb` shard directory (and its `root/aa`
    /// parent) if they are not already there. Deliberately does **not**
    /// fsync anything: making the newly created directory entries durable
    /// is the caller's job, so that a batch touching many shards under the
    /// same parents fsyncs each distinct parent once instead of once per
    /// block. The caller must still complete those syncs before reporting
    /// any block in the batch as committed — see
    /// `FsBlockStore::publish_shard_tree`.
    fn create_shard_directory(&self, shard: &Path) -> Result<(), StorageError>;
    fn write_temp_durable(&self, path: &Path, data: &[u8]) -> Result<(), StorageError>;
    fn publish_noreplace(&self, temp: &Path, final_path: &Path) -> Result<(), StorageError>;
    fn sync_directory(&self, directory: &Path, kind: DirSyncKind) -> Result<(), StorageError>;
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

/// Whether the `YADORILINK_DIAGNOSTIC_DISABLE_FSYNC=1` measurement switch
/// is on for this process. Read once through a `OnceLock` (the same shape
/// `chunker::durability_queue_byte_budget` already uses for its own
/// diagnostic override) rather than per call: the commit path issues
/// roughly one of these checks per block plus one per directory sync, and
/// an environment lookup per fsync is pure overhead on the hot path even
/// when the answer never changes. Unset — which is every production
/// process, since nothing in the shipping binaries sets it — is `false`,
/// so behaviour is unchanged.
fn fsync_diagnostically_disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED
        .get_or_init(|| std::env::var("YADORILINK_DIAGNOSTIC_DISABLE_FSYNC").as_deref() == Ok("1"))
}

struct StdBlockCommitIo;

/// The directory entries one block's commit is responsible for making
/// durable, decided by `FsBlockStore::reserve_shard_publish` before the
/// block's own I/O starts and discharged by
/// `FsBlockStore::publish_shard_tree` after it finishes.
///
/// Each field holds the *newly created directory itself*; the fsync that
/// publishes it is of that directory's PARENT (a directory entry becomes
/// durable when the directory containing it is synced), which is why
/// `prefix` costs a store-root fsync and `shard` costs a `root/aa` fsync.
#[derive(Clone, Debug, Default)]
struct ShardPublish {
    /// `root/aa`, when its entry in the store root is not durable yet.
    prefix: Option<PathBuf>,
    /// `root/aa/bb`, when its entry in `root/aa` is not durable yet.
    shard: Option<PathBuf>,
}

impl ShardPublish {
    fn is_empty(&self) -> bool {
        self.prefix.is_none() && self.shard.is_none()
    }
}

/// Every distinct directory fsync a batch of block commits owes, collected
/// across the batch so each one is issued exactly once however many blocks
/// contributed it.
///
/// This is what turns the shard tree's directory cost from per-block into
/// per-batch. With SHA-256-uniform hashes and a store that does not yet
/// hold the shard in question, nearly every block creates a new `root/aa/bb`
/// and a large fraction also create a new `root/aa` — so publishing each
/// creation immediately meant fsyncing the single shared store root once
/// per new prefix, and `root/aa` once per new shard, which together cost
/// more than the block files' own fsyncs.
#[derive(Debug, Default)]
struct PendingShardTree {
    /// Newly created `root/aa` directories. Publishing all of them takes
    /// exactly one fsync of the store root, however many there are.
    created_prefixes: Vec<PathBuf>,
    /// Newly created `root/aa/bb` directories, keyed by the `root/aa` that
    /// must be fsynced to publish them.
    created_shards: HashMap<PathBuf, Vec<PathBuf>>,
}

impl PendingShardTree {
    fn add(&mut self, publish: ShardPublish) {
        if let Some(prefix) = publish.prefix {
            self.created_prefixes.push(prefix);
        }
        if let Some(shard) = publish.shard {
            let prefix = shard.parent().expect("shard directories have a parent").to_path_buf();
            self.created_shards.entry(prefix).or_default().push(shard);
        }
    }

    fn is_empty(&self) -> bool {
        self.created_prefixes.is_empty() && self.created_shards.is_empty()
    }
}

enum BlockCommitOutcome {
    Deduplicated,
    PublishedNew,
    RepairedCorrupt,
}

impl BlockCommitIo for StdBlockCommitIo {
    fn create_shard_directory(&self, shard: &Path) -> Result<(), StorageError> {
        io_diag::time(Op::MkdirShard, 0, || fs::create_dir_all(shard))?;
        Ok(())
    }

    fn write_temp_durable(&self, path: &Path, data: &[u8]) -> Result<(), StorageError> {
        let mut file = io_diag::time(Op::OpenTemp, 0, || {
            OpenOptions::new().write(true).create_new(true).open(path)
        })?;
        io_diag::time(Op::WriteTemp, data.len() as u64, || file.write_all(data))?;
        // Diagnostic (re-added after an accidental `git checkout` reverted
        // it): `YADORILINK_DIAGNOSTIC_DISABLE_FSYNC=1` skips this fsync.
        // Temporary, isolates per-block durability I/O cost.
        if !fsync_diagnostically_disabled() {
            io_diag::time(Op::FsyncTemp, 0, || file.sync_all())?;
        }
        Ok(())
    }

    fn publish_noreplace(&self, temp: &Path, final_path: &Path) -> Result<(), StorageError> {
        // A hard link publishes the already-synced inode atomically and never
        // replaces an existing winner. Temp and final live in one shard.
        io_diag::time(Op::LinkPublish, 0, || fs::hard_link(temp, final_path))?;
        Ok(())
    }

    fn sync_directory(&self, directory: &Path, kind: DirSyncKind) -> Result<(), StorageError> {
        // Diagnostic: see `write_temp_durable`'s matching comment. Every
        // directory fsync in the commit path now runs through this one
        // method, so the switch covers all of them — it previously missed
        // the two ancestor syncs, which were the majority of them.
        if fsync_diagnostically_disabled() {
            return Ok(());
        }
        io_diag::time(kind.op(), 0, || sync_directory(directory))
    }

    fn remove_file(&self, path: &Path) -> Result<(), StorageError> {
        io_diag::time(Op::UnlinkTemp, 0, || remove_path(path))?;
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
        rename_path(source, dest)?;
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
            bulk_ingest_barrier_hook: Mutex::new(None),
            unpublished_directories: Mutex::new(HashSet::new()),
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
        let shard =
            hash.get(0..2).and_then(|prefix| u8::from_str_radix(prefix, 16).ok()).unwrap_or(0);
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
        let space = io_diag::time(Op::HeadroomCheck, 0, || {
            free_space::classify_volume(&self.root, self.headroom_override_bytes())
        })?;
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

    /// M6: intentionally does NOT call `write_usage_counter` -- a new block
    /// on the hot `put` path used to persist `.yadorilink-usage` to disk on
    /// every single successful commit (a full file rewrite, immediately
    /// after the block's own `write_temp_durable`+fsync+publish+directory-
    /// fsync sequence), which is pure overhead: `usage()` never reads that
    /// file while this process is alive -- it serves straight from this
    /// in-memory `usage` (updated below, exactly, every time), only falling
    /// back to `repair_usage_from_disk`'s full-tree scan when `usage_dirty`
    /// is set (corrupt-block repair, delete, or a checksum-mismatch self-
    /// heal -- none of which is the new-block path this function serves).
    /// The persisted counter was never this store's durability authority to
    /// begin with (see `new`'s own doc comment: every open already compares
    /// it against a real `scan_usage` and repairs on any mismatch) -- it
    /// only exists as a cheap warm-start hint for the NEXT process's own
    /// `new()`, and a `new()` that finds it stale after this change repairs
    /// it exactly the same way it always has, from the same startup scan.
    /// Do NOT set `usage_dirty` here as a substitute for the removed write:
    /// that flag means "the in-memory count itself may be wrong, trust
    /// nothing until a full-tree scan confirms it" -- not true here, since
    /// the two lines below keep `usage` exact unconditionally, with no
    /// fallible I/O in between to leave it in a state worth doubting.
    fn record_committed_block(&self, bytes: u64) {
        let mut usage = self.usage.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        usage.block_count += 1;
        usage.total_bytes += bytes;
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

    /// Decides which of `shard`'s ancestors this commit must make durable,
    /// and claims them so no concurrent commit can mistake "the directory
    /// is there" for "the directory is durable" (see
    /// `unpublished_directories`). Runs before the shard directory is
    /// created, and issues no fsync of its own.
    ///
    /// An ancestor already present when this process looked, and not
    /// claimed by an in-flight commit, is treated as durable — exactly the
    /// judgement the per-block path made before batching existed. An
    /// ancestor this process has not yet published is claimed even if
    /// another commit already claimed it: a redundant fsync of a directory
    /// costs one syscall, whereas a skipped one costs a block.
    fn reserve_shard_publish(&self, shard: &Path) -> ShardPublish {
        let prefix = shard.parent().expect("shard directories have a parent");
        let mut unpublished =
            self.unpublished_directories.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut claim = |directory: &Path| -> Option<PathBuf> {
            if unpublished.contains(directory) {
                return Some(directory.to_path_buf());
            }
            if io_diag::time(Op::StatShard, 0, || directory.exists()) {
                return None;
            }
            unpublished.insert(directory.to_path_buf());
            Some(directory.to_path_buf())
        };
        ShardPublish { prefix: claim(prefix), shard: claim(shard) }
    }

    /// Makes every directory entry a batch created durable, one fsync per
    /// distinct parent directory rather than one per block that needed it.
    ///
    /// Top-down (`root`, then each `root/aa`), so the shortest-lived
    /// crash window is the one that leaves a directory published before
    /// its contents rather than after. Callers must run this — and the
    /// shard-directory syncs that publish the block files themselves —
    /// before reporting any block in the batch as committed.
    fn publish_shard_tree(&self, pending: &PendingShardTree) -> Result<(), StorageError> {
        if pending.is_empty() {
            return Ok(());
        }
        if !pending.created_prefixes.is_empty() {
            // One fsync of the single shared store root publishes every
            // `aa` this batch created, however many that is.
            self.commit_io.sync_directory(&self.root, DirSyncKind::StoreRoot)?;
            self.mark_published(&pending.created_prefixes);
        }
        for (prefix, shards) in &pending.created_shards {
            self.commit_io.sync_directory(prefix, DirSyncKind::Prefix)?;
            self.mark_published(shards);
        }
        Ok(())
    }

    fn mark_published(&self, directories: &[PathBuf]) {
        let mut unpublished =
            self.unpublished_directories.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for directory in directories {
            unpublished.remove(directory);
        }
    }

    /// The only final-path publication primitive for block writes.
    fn commit_block(
        &self,
        hash: &str,
        data: &[u8],
        path: &Path,
    ) -> Result<BlockCommitOutcome, StorageError> {
        let pending = Mutex::new(PendingShardTree::default());
        let staged = self.commit_block_staged(hash, data, path, &pending);
        // Publish whatever was actually created regardless of outcome, for
        // the same reason `commit_batch` syncs its dirty shards on the
        // error path: a directory this call created must not be left
        // claimed-but-unpublished, and making it durable is harmless even
        // when the block that needed it never landed.
        let pending = pending.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.publish_shard_tree(&pending)?;
        let (outcome, dirty_shard) = staged?;
        if let Some(shard) = dirty_shard {
            self.commit_io.sync_directory(&shard, DirSyncKind::Shard)?;
        }
        Ok(outcome)
    }

    /// M6-2B2: identical to `commit_block` except it does NOT call
    /// `sync_directory` on the block's own shard directory itself --
    /// instead it returns that shard path (as `Some`) exactly when
    /// something new was actually written there (a fresh publish or a
    /// corrupt-block repair), so a caller committing many blocks in one
    /// batch (`BulkIngest`) can collect every distinct dirty shard across
    /// the whole batch and sync each ONE TIME after the batch, instead of
    /// once per block. With this store's two-level `root/aa/bb/hash`
    /// sharding and real (near-random SHA-256) hashes, a several-hundred-
    /// block transfer touches shard directories that are almost all
    /// distinct, so per-block shard-directory fsync was costing nearly as
    /// much as per-block file fsync -- this is what closes that gap.
    /// `commit_block` itself (the single-item `put`/`put_prepared` path)
    /// is unchanged in observable behavior: it still syncs immediately,
    /// every time, exactly as before this split.
    ///
    /// The shard tree's own directory entries are handled the same way:
    /// whatever ancestors this block has to create are claimed into
    /// `pending` here and left for the caller to publish once for the
    /// whole batch. `pending` is filled before any of the block's I/O
    /// runs, so a block that then fails still leaves its caller able to
    /// publish (and un-claim) the directories it created.
    fn commit_block_staged(
        &self,
        hash: &str,
        data: &[u8],
        path: &Path,
        pending: &Mutex<PendingShardTree>,
    ) -> Result<(BlockCommitOutcome, Option<PathBuf>), StorageError> {
        let shard = path.parent().expect("block paths have a shard directory").to_path_buf();
        let mut repaired_corrupt = false;
        if io_diag::time(Op::StatFinal, 0, || path.exists()) {
            let existing = io_diag::time(Op::DedupRead, 0, || fs::read(path))?;
            if Self::hash_bytes(&existing) == hash {
                // Nothing new written -- no shard directory became dirty.
                return Ok((BlockCommitOutcome::Deduplicated, None));
            }
            // A corrupt final path is not a valid copy of any block. Move it
            // into quarantine (preserving the corrupt bytes for analysis) and
            // durably record that removal before publishing its repair.
            repaired_corrupt = true;
            self.quarantine_corrupt_block(hash, path)?;
            self.commit_io.sync_directory(&shard, DirSyncKind::Shard)?;
        }

        let reserved = self.reserve_shard_publish(&shard);
        self.commit_io.create_shard_directory(&shard)?;
        // Handed over only once the directories exist. A failed
        // `create_dir_all` may still have created the `root/aa` half, so
        // the claim taken above is deliberately NOT released on that path:
        // leaving it standing means the next commit into the same subtree
        // treats the directory as unpublished and makes it durable itself,
        // where releasing it would let that commit mistake a
        // possibly-unpublished directory for a durable one.
        if !reserved.is_empty() {
            pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).add(reserved);
        }
        self.check_headroom(path, data.len() as u64)?;
        let tmp_path = unique_tmp_path(path);
        let publish = (|| {
            self.commit_io.write_temp_durable(&tmp_path, data)?;
            self.commit_io.publish_noreplace(&tmp_path, path)?;
            Ok::<(), StorageError>(())
        })();
        let _ = self.commit_io.remove_file(&tmp_path);
        match publish {
            Ok(()) if repaired_corrupt => Ok((BlockCommitOutcome::RepairedCorrupt, Some(shard))),
            Ok(()) => Ok((BlockCommitOutcome::PublishedNew, Some(shard))),
            Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A different store instance won the no-replace publish.
                // Treat it as dedup only after verifying its bytes. Nothing
                // THIS call wrote, so no shard dirtied from its perspective
                // -- but the winner's own commit already synced it.
                let winner = fs::read(path)?;
                if Self::hash_bytes(&winner) == hash {
                    Ok((BlockCommitOutcome::Deduplicated, None))
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

        let mut present = vec![false; hashes.len()];

        // Group hash indices by shard directory so each shard is
        // `read_dir`'d at most once, however many of the requested hashes
        // land in it, rather than one `stat` per hash.
        let mut by_shard: HashMap<PathBuf, Vec<usize>> = HashMap::new();
        for (i, hash) in hashes.iter().enumerate() {
            by_shard.entry(self.shard_dir_for_hash(hash)).or_default().push(i);
        }

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

    /// Shared commit/accounting body for `put` and `put_prepared` — the
    /// only difference between them is whether `hash` was just derived
    /// from `data` (`put`) or already known (`put_prepared`); everything
    /// after that point (locking, durability, usage accounting) is
    /// identical, so it lives here once.
    fn commit_with_known_hash(&self, hash: &str, data: &[u8]) -> Result<(), StorageError> {
        let path = self.path_for_hash(hash)?;
        // Keep accounting in the same critical section as publication. A
        // delete of this hash cannot land after publish but before the usage
        // increment and leave the counter permanently one block too high.
        let _hash_guard =
            self.hash_lock(hash).lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _usage_mutation = self.begin_usage_mutation();
        match self.commit_block(hash, data, &path)? {
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
        Ok(())
    }

    /// M6-2B2: the actual batch-commit body behind `BulkIngest::flush_
    /// durable`. Bounded-concurrency (`BULK_INGEST_CONCURRENCY` at a time,
    /// never the whole batch unboundedly parallel, never fully serial)
    /// write+publish for every staged block, then a SINGLE pass syncing
    /// every distinct shard directory the batch actually touched --
    /// closing the near-per-block shard-directory-fsync cost the batch
    /// file-write/fsync coalescing alone would have left on the table
    /// (see `commit_block_staged`'s own doc comment). Headroom is checked
    /// once for the batch's conservative worst case (every block new),
    /// not once per block. Usage accounting happens inside one
    /// `begin_usage_mutation` guard spanning the whole batch.
    ///
    /// `staged -> durable -> authoritative`: everything this function
    /// commits becomes durable (dirty shards synced) before it returns,
    /// but nothing about durability implies "authoritative" -- this
    /// function has no idea whether its caller is mid-capture, will
    /// publish a `FileRecord` referencing these blocks, or aborts before
    /// ever doing so. That's `BulkIngest`'s caller's job, one layer up.
    fn commit_batch(
        &self,
        batch: Vec<LocallyHashedBlock>,
    ) -> Result<BulkIngestOutcome, StorageError> {
        if batch.is_empty() {
            return Ok(BulkIngestOutcome::default());
        }

        // Conservative batch-granularity headroom check: assumes every
        // block in the batch is new (the worst case), checked once
        // instead of once per block. `check_headroom` was already a
        // best-effort availability snapshot on the per-block path, not a
        // hard atomic reservation -- this preserves that same property at
        // batch granularity, it does not weaken it.
        let total_bytes: u64 = batch.iter().map(|b| b.bytes().len() as u64).sum();
        let probe_path = self.path_for_hash(batch[0].hash())?;
        self.check_headroom(&probe_path, total_bytes)?;

        // Every shard-tree directory this batch creates, collected across
        // all of its blocks so each distinct parent is fsynced once below
        // instead of once per block that happened to need it.
        let pending_tree = Mutex::new(PendingShardTree::default());

        let results: Vec<BulkIngestBlockResult> = std::thread::scope(|scope| {
            let mut out = Vec::with_capacity(batch.len());
            for chunk in batch.chunks(BULK_INGEST_CONCURRENCY) {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|block| {
                        let hash = block.hash().clone();
                        let bytes = block.bytes();
                        let byte_len = bytes.len() as u64;
                        let pending_tree = &pending_tree;
                        scope.spawn(move || {
                            let path = self.path_for_hash(&hash)?;
                            let _hash_guard = self
                                .hash_lock(&hash)
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            let (outcome, dirty) =
                                self.commit_block_staged(&hash, bytes, &path, pending_tree)?;
                            Ok((hash, outcome, dirty, byte_len))
                        })
                    })
                    .collect();
                for handle in handles {
                    out.push(handle.join().unwrap_or_else(|_| {
                        Err(StorageError::Io(std::io::Error::other(
                            "bulk ingest worker thread panicked",
                        )))
                    }));
                }
            }
            out
        });

        let mut dirty_shards: HashSet<PathBuf> = HashSet::new();
        let mut committed_hashes = Vec::with_capacity(batch.len());
        let mut newly_published: Vec<u64> = Vec::new();
        let mut any_corrupt_repaired = false;
        let mut first_err: Option<StorageError> = None;
        for result in results {
            match result {
                Ok((hash, outcome, dirty, byte_len)) => {
                    if let Some(shard) = dirty {
                        dirty_shards.insert(shard);
                    }
                    match outcome {
                        BlockCommitOutcome::PublishedNew => newly_published.push(byte_len),
                        BlockCommitOutcome::RepairedCorrupt => any_corrupt_repaired = true,
                        BlockCommitOutcome::Deduplicated => {}
                    }
                    committed_hashes.push(hash);
                }
                Err(e) if first_err.is_none() => first_err = Some(e),
                Err(_) => {}
            }
        }

        // Sync whatever was actually touched regardless of outcome --
        // crash-safety property 3 (a crash/error mid-batch must leave
        // only harmless unreferenced content, never a torn/un-synced
        // write masquerading as complete). This runs even on the error
        // path below.
        //
        // Ancestors first, then the shards themselves: a block file is
        // only reachable after a crash if every directory entry between
        // the store root and its shard is durable, so publishing the tree
        // top-down means the tree is never durable ahead of its own
        // parent. Both halves complete before this function can report
        // any block as committed.
        let pending_tree =
            pending_tree.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.publish_shard_tree(&pending_tree)?;
        for shard in &dirty_shards {
            self.commit_io.sync_directory(shard, DirSyncKind::Shard)?;
        }
        if let Some(e) = first_err {
            return Err(e);
        }

        if !newly_published.is_empty() || any_corrupt_repaired {
            let _usage_mutation = self.begin_usage_mutation();
            for byte_len in newly_published {
                self.record_committed_block(byte_len);
            }
            if any_corrupt_repaired {
                self.usage_dirty.store(true, Ordering::Release);
            }
        }

        let hook = self
            .bulk_ingest_barrier_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(hook) = hook {
            hook();
        }

        Ok(BulkIngestOutcome { committed_hashes })
    }
}

/// M6-2B2: how many blocks' worth of temp-file-write+publish `BulkIngest::
/// flush_durable` runs concurrently within one batch. Deliberately small
/// and fixed, not tuned -- bounded concurrency onto the storage device is
/// the point (never the whole batch unboundedly parallel, never fully
/// serial, which was the pre-B2 default and the dominant per-block
/// serialization cost this slice exists to remove).
pub const BULK_INGEST_CONCURRENCY: usize = 4;

/// M6-2B2: what a `BulkIngest` batch actually committed durably --
/// every hash in `committed_hashes` (deduplicated or freshly published,
/// `BulkIngest` does not distinguish the two to its caller) is guaranteed
/// synced to disk by the time `flush_durable` returns `Ok`. This says
/// nothing about "authoritative" -- see `BulkIngest`'s own doc comment
/// for the `staged -> durable -> authoritative` boundary this type sits
/// on the `durable` side of.
#[derive(Debug, Default, Clone)]
pub struct BulkIngestOutcome {
    pub committed_hashes: Vec<ContentHash>,
}

/// M6-2B2: a bounded batch of blocks whose content this process already
/// hashed itself (`LocallyHashedBlock`, never a peer-claimed hash --
/// see that type's own doc comment for why), accumulated via
/// `stage_prepared` and committed all at once via `flush_durable`.
///
/// The invariant this type exists to enforce: **`staged -> durable ->
/// authoritative`**. A block that has only been `stage_prepared`'d --
/// even if the underlying bytes happen to already be sitting in this
/// process's memory or, transiently, on disk in a temp file -- has not
/// been committed to anything a caller outside this batch can observe.
/// `stage_prepared` does no I/O at all and cannot fail for any reason
/// related to the block itself (only a batch-size/memory concern a
/// caller might impose externally, which this type does not enforce).
/// Only `flush_durable` touches disk, and only once it returns `Ok` do
/// the batch's blocks become "durable": physically present, fsync'd,
/// and safe for a caller to now treat as available (e.g. record group
/// provenance for them, or -- source-side -- publish a `FileRecord`
/// that references them). Before that point, staged blocks are
/// completely inert from any OTHER consumer's perspective: they are not
/// in `present_blocks`, not in any provenance table, not referenced by
/// any `FileRecord`/DAG entry, because none of that state has been
/// touched yet. A capture that's staged blocks but never calls (or
/// never successfully completes) `flush_durable` -- process exit,
/// error, abandoned batch -- simply leaves nothing behind on disk for
/// those specific staged-but-unflushed blocks (they were never written)
/// and leaves the `FsBlockStore` exactly as it was before staging
/// began.
pub struct BulkIngest<'s> {
    store: &'s FsBlockStore,
    staged: Vec<LocallyHashedBlock>,
}

impl FsBlockStore {
    /// Starts a new bulk-ingest batch against this store. See
    /// `BulkIngest`'s own doc comment for the `staged -> durable ->
    /// authoritative` contract this exists to enforce.
    pub fn begin_bulk_ingest(&self) -> BulkIngest<'_> {
        BulkIngest { store: self, staged: Vec::new() }
    }

    /// Test-only seam (name says so; not `#[cfg(test)]`-gated because
    /// cross-crate invariant tests in `yadorilink-local-capture` and
    /// `yadorilink-peer-session` need to call this against a real
    /// production `FsBlockStore` from their own `#[cfg(test)]` code,
    /// which a same-crate `cfg(test)` field/method cannot reach). Installs
    /// a hook `commit_batch` calls synchronously right before it returns
    /// -- see `bulk_ingest_barrier_hook`'s own doc comment for exactly
    /// which invariant boundary this observes. Never call this outside a
    /// test.
    pub fn install_bulk_ingest_barrier_hook_for_tests(
        &self,
        hook: impl Fn() + Send + Sync + 'static,
    ) {
        *self.bulk_ingest_barrier_hook.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(Arc::new(hook));
    }
}

impl<'s> BulkIngest<'s> {
    /// Adds `block` to this batch. Pure in-memory bookkeeping -- no I/O,
    /// cannot fail, and (this is the invariant that matters) has no
    /// observable effect on the store from any OTHER caller's
    /// perspective until this batch's `flush_durable` is called and
    /// succeeds.
    pub fn stage_prepared(&mut self, block: LocallyHashedBlock) {
        self.staged.push(block);
    }

    /// How many blocks are currently staged (not yet flushed) in this
    /// batch -- a caller decides its own batch-size/flush-cadence policy
    /// using this, `BulkIngest` itself has no opinion on batch size.
    pub fn staged_len(&self) -> usize {
        self.staged.len()
    }

    /// Commits every currently-staged block durably (bounded-concurrency
    /// write+fsync, one shard-directory sync per distinct touched shard,
    /// batch-granularity headroom check and usage accounting) and clears
    /// the batch. On success, every hash in the returned
    /// `BulkIngestOutcome::committed_hashes` is now durable and safe for
    /// the caller to treat as available. On error, whatever WAS
    /// successfully durable-committed before the failing block is
    /// still durable (crash-safety property 3: harmless unreferenced
    /// content, not a torn write) -- but this method does not report
    /// which specific hashes those were on the error path; a caller that
    /// needs per-block partial-success detail on failure should flush
    /// smaller batches.
    pub fn flush_durable(&mut self) -> Result<BulkIngestOutcome, StorageError> {
        let batch = std::mem::take(&mut self.staged);
        self.store.commit_batch(batch)
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
pub(crate) fn sync_directory(path: &Path) -> Result<(), StorageError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn sync_directory(path: &Path) -> Result<(), StorageError> {
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
        self.commit_with_known_hash(&hash, data)?;
        Ok(hash)
    }

    /// M6-2B1.1: `put` above always derives `hash` from `data` itself
    /// (an unavoidable SHA-256 pass) before this same commit work runs —
    /// correct for any caller that doesn't already know the hash, but a
    /// caller that just computed it locally (`LocallyHashedBlock::
    /// from_bytes`, e.g. `chunker.rs`'s CDC loop, which needs the hash
    /// immediately to offer a block to a callback before this commit
    /// even starts) would otherwise pay for hashing the same bytes a
    /// second time here. `commit_with_known_hash` does the identical
    /// commit/accounting work `put` does, just skipping the hash
    /// derivation since `prepared` already carries a hash this process
    /// computed itself, fresh, from these exact bytes (see
    /// `LocallyHashedBlock`'s own doc comment for why that guarantee
    /// holds and why this is safe to trust without re-verifying here).
    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        self.commit_with_known_hash(prepared.hash(), prepared.bytes())
    }

    /// M6-2B2: real override — commits the whole slice as one
    /// `BulkIngest` batch (bounded-concurrency writes, one shard-
    /// directory sync per distinct touched shard, batch-granularity
    /// headroom/usage accounting) instead of `BlockStore::put_prepared_
    /// batch`'s default per-block loop. See `commit_batch`'s own doc
    /// comment for the full mechanism.
    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        self.commit_batch(prepared.to_vec()).map(|_outcome| ())
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
                let _ = self.commit_io.sync_directory(parent, DirSyncKind::Shard);
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
                    self.commit_io.sync_directory(parent, DirSyncKind::Shard)?;
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
    ///
    /// This crate has no dependency on `yadorilink-daemon`, so this can't
    /// reuse that crate's `daemon_state::run_blocking_sweep_offloaded`
    /// helper, which the same guard is otherwise consolidated behind for
    /// every same-crate call site there (`gc.rs`, `hydration.rs`,
    /// `maintenance/gc_idle.rs`, `maintenance/retention_expiry.rs`). If a
    /// third crate ever needs this exact guard, that's the point to
    /// consider pulling it into a small shared crate instead of copying it
    /// again.
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
        /// The block's `root/aa/bb` shard directory now exists. It is not
        /// yet durable at this point: the fsyncs that publish it are the
        /// `DirectoryDurable(StoreRoot)`/`DirectoryDurable(Prefix)` stages
        /// below, which a commit batches and issues once per distinct
        /// parent rather than once per block.
        ShardCreated,
        TempDurable,
        Published,
        DirectoryDurable(DirSyncKind),
    }

    struct RecordingCommitIo {
        inner: StdBlockCommitIo,
        completed: Mutex<Vec<CommitStage>>,
        /// Every directory actually fsynced, in order, so a test can assert
        /// both *which* directories a batch published and that it published
        /// each of them exactly once.
        synced: Mutex<Vec<PathBuf>>,
        fail_before: Option<CommitStage>,
    }

    impl RecordingCommitIo {
        fn new(fail_before: Option<CommitStage>) -> Self {
            Self {
                inner: StdBlockCommitIo,
                completed: Mutex::new(Vec::new()),
                synced: Mutex::new(Vec::new()),
                fail_before,
            }
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
        fn create_shard_directory(&self, shard: &Path) -> Result<(), StorageError> {
            self.inner.create_shard_directory(shard)?;
            self.complete(CommitStage::ShardCreated)
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

        fn sync_directory(&self, directory: &Path, kind: DirSyncKind) -> Result<(), StorageError> {
            if self.fail_before == Some(CommitStage::DirectoryDurable(kind)) {
                return self.complete(CommitStage::DirectoryDurable(kind));
            }
            self.inner.sync_directory(directory, kind)?;
            self.synced.lock().unwrap().push(directory.to_path_buf());
            self.complete(CommitStage::DirectoryDurable(kind))
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
                CommitStage::ShardCreated,
                CommitStage::TempDurable,
                CommitStage::Published,
                // The shard tree is published top-down, and all of it
                // before `put` returns: the store root (carrying the new
                // `aa` entry), then `root/aa` (carrying the new `bb`
                // entry), then the shard itself (carrying the block).
                CommitStage::DirectoryDurable(DirSyncKind::StoreRoot),
                CommitStage::DirectoryDurable(DirSyncKind::Prefix),
                CommitStage::DirectoryDurable(DirSyncKind::Shard),
            ]
        );
        let shard = store.path_for_hash(&hash).unwrap().parent().unwrap().to_path_buf();
        assert_eq!(
            *io.synced.lock().unwrap(),
            vec![store.root.clone(), shard.parent().unwrap().to_path_buf(), shard],
        );
    }

    #[test]
    fn block_commit_does_not_report_success_before_any_durability_stage() {
        let ancestors = [
            CommitStage::DirectoryDurable(DirSyncKind::StoreRoot),
            CommitStage::DirectoryDurable(DirSyncKind::Prefix),
        ];
        // The ancestor publishes appear even on the early-failure rows.
        // Once the shard directory has been created, making its entries
        // durable is owed regardless of whether the block that needed it
        // landed -- the same reason `commit_batch` syncs its dirty shards
        // on the error path. It publishes a directory that may stay empty,
        // never a block, so it cannot turn a failed commit into an
        // apparently successful one; and skipping it would leave the
        // directory claimed-but-unpublished, which is the state a
        // concurrent committer must never trust.
        let cases = [
            (CommitStage::ShardCreated, vec![]),
            (CommitStage::TempDurable, [&[CommitStage::ShardCreated][..], &ancestors].concat()),
            (
                CommitStage::Published,
                [&[CommitStage::ShardCreated, CommitStage::TempDurable][..], &ancestors].concat(),
            ),
            // Each level of the shard tree is its own durability
            // obligation: failing to publish ANY of the three -- the store
            // root's new `aa` entry, `root/aa`'s new `bb` entry, or the
            // block's own entry in the shard -- must fail the commit, not
            // just the innermost one. A block whose ancestor directory
            // entry never reached disk is unreachable after a crash, which
            // is indistinguishable from never having been written.
            (
                CommitStage::DirectoryDurable(DirSyncKind::StoreRoot),
                vec![CommitStage::ShardCreated, CommitStage::TempDurable, CommitStage::Published],
            ),
            (
                CommitStage::DirectoryDurable(DirSyncKind::Prefix),
                vec![
                    CommitStage::ShardCreated,
                    CommitStage::TempDurable,
                    CommitStage::Published,
                    CommitStage::DirectoryDurable(DirSyncKind::StoreRoot),
                ],
            ),
            (
                CommitStage::DirectoryDurable(DirSyncKind::Shard),
                vec![
                    CommitStage::ShardCreated,
                    CommitStage::TempDurable,
                    CommitStage::Published,
                    CommitStage::DirectoryDurable(DirSyncKind::StoreRoot),
                    CommitStage::DirectoryDurable(DirSyncKind::Prefix),
                ],
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
    fn new_block_puts_update_runtime_usage_without_touching_the_persisted_counter() {
        // M6: `record_committed_block` no longer calls `write_usage_counter`
        // -- this pins that the removal is real (the on-disk counter file
        // stays exactly as `new()` last wrote it, untouched by three more
        // `put`s) while `usage()` still reports the correct, immediately-
        // current total from the in-memory `StorageUsage` this same
        // function keeps exact. Both halves matter: a regression that
        // brought the disk write back would still pass an assertion on
        // `usage()` alone, and a regression that broke the in-memory update
        // would still pass an assertion on the persisted file alone.
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let persisted_after_open = fs::read_to_string(usage_counter_path(dir.path())).unwrap();

        store.put(b"one").unwrap();
        store.put(b"two-two").unwrap();
        store.put(b"three-three-three").unwrap();

        let usage = store.usage().unwrap();
        assert_eq!(usage.block_count, 3);
        assert_eq!(usage.total_bytes, 3 + 7 + 17);
        assert_eq!(
            fs::read_to_string(usage_counter_path(dir.path())).unwrap(),
            persisted_after_open,
            "a new-block put must not rewrite `.yadorilink-usage` -- this file should still \
             read exactly what `new()` wrote at open (an empty store's `0 0`), not reflect \
             any of the three puts above"
        );
    }

    #[test]
    fn duplicate_puts_do_not_increment_usage() {
        // Unaffected by this change (dedup never reaches `record_committed_
        // block` at all, see `put`'s `BlockCommitOutcome::Deduplicated`
        // arm) -- pinned explicitly anyway since it's a directly adjacent
        // invariant the same hot path must keep holding.
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();

        let first = store.put(b"same bytes").unwrap();
        let usage_after_first = store.usage().unwrap();
        assert_eq!(usage_after_first, StorageUsage { block_count: 1, total_bytes: 10 });

        let second = store.put(b"same bytes").unwrap();
        assert_eq!(second, first);
        let usage_after_duplicate = store.usage().unwrap();
        assert_eq!(usage_after_duplicate, usage_after_first);
    }

    #[test]
    fn reopen_recovers_correct_usage_from_the_block_tree_despite_a_stale_persisted_counter() {
        // The load-bearing correctness property this whole change depends
        // on: with per-put persistence removed, `.yadorilink-usage` is
        // expected to go stale across a run of puts -- `new()`'s own
        // startup scan (see its doc comment) is what's supposed to catch
        // and repair that, not this file staying fresh.
        let dir = tempfile::tempdir().unwrap();
        {
            // A second, independent store instance against the same root,
            // committing a block entirely AFTER the first instance closed
            // -- exactly the "many puts since the counter was last
            // flushed, then a crash/restart" shape this change makes
            // possible, since neither instance's puts below ever persist
            // past their own `new()`'s startup write.
            let store = FsBlockStore::new(dir.path()).unwrap();
            store.put(b"first block").unwrap();
        }
        {
            let store = FsBlockStore::new(dir.path()).unwrap();
            store.put(b"second block").unwrap();
        }
        // With per-put persistence removed, the counter on disk still only
        // reflects the block tree as of the SECOND instance's own `new()`
        // (1 block, 11 bytes) -- its own `put` above never touched the
        // file, so this is exactly the "old, once-correct-but-now-wrong"
        // staleness a real crash could produce, not simply an absent file
        // a weaker test could pass against by accident.
        let stale = StorageUsage { block_count: 1, total_bytes: 11 };
        assert_eq!(
            parse_usage_counter(&fs::read_to_string(usage_counter_path(dir.path())).unwrap()),
            Some(stale),
            "test setup check: the persisted counter must still read the stale value going \
             into the reopen below, or this test would not actually be exercising recovery"
        );

        // The reopen under test: `new()`'s own startup scan must win over
        // the stale persisted value, exactly as it already does for a
        // corrupt-block/delete-driven mismatch -- this change doesn't add
        // a new code path here, it just makes this existing path the ONLY
        // way a long-lived process's counter ever gets reconciled with
        // reality again after many puts.
        let reopened = FsBlockStore::new(dir.path()).unwrap();
        assert_eq!(
            reopened.usage().unwrap(),
            StorageUsage { block_count: 2, total_bytes: 11 + 12 },
            "reopen must recover the REAL usage from the physical block tree, not the stale \
             persisted counter this test deliberately left behind"
        );
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
        // `delete` publishes the unlink by syncing the block's own shard
        // directory, so that is the level whose failure this exercises.
        store.commit_io = Arc::new(RecordingCommitIo::new(Some(CommitStage::DirectoryDurable(
            DirSyncKind::Shard,
        ))));

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

    /// M6-2B1.1: `put_prepared` must store a block under exactly the hash
    /// `LocallyHashedBlock::from_bytes` computed for it — the same
    /// content, read back by that same hash, byte-for-byte — proving the
    /// prehashed commit path is a genuine substitute for `put`, not a
    /// shortcut that skips real durability/addressing.
    #[test]
    fn put_prepared_stores_under_the_hash_it_was_given() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();

        let content = b"M6-2B1.1 put_prepared content".to_vec();
        let prepared = LocallyHashedBlock::from_bytes(content.clone());
        let expected_hash = prepared.hash().clone();

        store.put_prepared(&prepared).unwrap();

        assert!(store.exists(&expected_hash).unwrap());
        assert_eq!(store.get(&expected_hash).unwrap(), content);
    }

    /// `put` (hashes internally) and `put_prepared` (given an already-
    /// computed hash) must be indistinguishable in their end result for
    /// the same bytes — same stored content, same resulting hash, same
    /// dedup behavior on a second write. This is the guarantee the whole
    /// M6-2B1.1 optimization rests on: threading a locally-computed hash
    /// through instead of recomputing it must never change WHAT gets
    /// stored or under what key, only how many times the bytes get
    /// hashed.
    #[test]
    fn put_prepared_is_behaviorally_identical_to_put_for_the_same_bytes() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();

        let content = b"identical content, two commit paths".to_vec();

        let hash_via_put = store.put(&content).unwrap();

        let store_dir2 = tempfile::tempdir().unwrap();
        let store2 = FsBlockStore::new(store_dir2.path()).unwrap();
        let prepared = LocallyHashedBlock::from_bytes(content.clone());
        store2.put_prepared(&prepared).unwrap();

        assert_eq!(
            &hash_via_put,
            prepared.hash(),
            "put and put_prepared must agree on the content hash for identical bytes"
        );
        assert_eq!(store.get(&hash_via_put).unwrap(), store2.get(prepared.hash()).unwrap());

        // Dedup: committing the SAME prepared block twice to the same
        // store must not double-count usage -- put_prepared shares put's
        // own BlockCommitOutcome::Deduplicated handling, not a separate,
        // possibly-inconsistent code path.
        let usage_before = store2.usage().unwrap();
        store2.put_prepared(&prepared).unwrap();
        assert_eq!(
            store2.usage().unwrap(),
            usage_before,
            "re-putting an identical prepared block must not double-count usage"
        );
    }

    /// `LocallyHashedBlock::bytes_arc` hands out a cheap clone of the
    /// SAME underlying allocation `put_prepared` commits from — not two
    /// independently-copied buffers that merely happen to contain equal
    /// bytes. `Arc::ptr_eq` distinguishes "same allocation" from
    /// "equal content", which is the actual property M6-2B1.1's
    /// zero-extra-copy design depends on.
    #[test]
    fn bytes_arc_shares_the_same_allocation_not_just_equal_content() {
        let prepared = LocallyHashedBlock::from_bytes(b"shared allocation check".to_vec());
        let handle_a = prepared.bytes_arc();
        let handle_b = prepared.bytes_arc();
        assert!(
            std::sync::Arc::ptr_eq(&handle_a, &handle_b),
            "bytes_arc() clones must point at the same underlying allocation, not copy it"
        );
        assert_eq!(&*handle_a, prepared.bytes());
    }

    // --- M6-2B2: BulkIngest crash-safety -----------------------------

    /// `stage_prepared` must be completely inert from any other
    /// consumer's perspective: a block sitting in a `BulkIngest` batch
    /// that hasn't been flushed yet must not be `present`, must not be
    /// `get`-able, and must not have moved `usage()` at all. This is the
    /// `staged` half of `staged -> durable -> authoritative` -- staging
    /// alone must never look like commitment to anything watching this
    /// store from outside the batch.
    #[test]
    fn staged_but_unflushed_blocks_are_invisible_to_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let usage_before = store.usage().unwrap();

        let block = LocallyHashedBlock::from_bytes(b"never flushed".to_vec());
        let hash = block.hash().clone();
        let mut ingest = store.begin_bulk_ingest();
        ingest.stage_prepared(block);
        assert_eq!(ingest.staged_len(), 1);

        assert!(!store.exists(&hash).unwrap(), "a staged-only block must not be present");
        assert!(store.get(&hash).is_err(), "a staged-only block must not be readable");
        assert_eq!(
            store.usage().unwrap(),
            usage_before,
            "staging must not move usage before flush_durable"
        );

        // Dropping the batch without ever flushing leaves the store
        // exactly as it was -- no partial write, nothing to clean up.
        drop(ingest);
        assert!(!store.exists(&hash).unwrap());
        assert_eq!(store.usage().unwrap(), usage_before);
    }

    /// A successful `flush_durable` must make every returned hash
    /// genuinely durable -- readable not just from the live `FsBlockStore`
    /// instance that wrote it, but after that instance is dropped and a
    /// FRESH store is reconstructed against the same on-disk directory
    /// (simulating a process restart). This is the `durable` half of the
    /// invariant: `flush_durable`'s own fsync work, not merely an
    /// in-process cache, is what makes the data safe.
    #[test]
    fn flush_durable_makes_every_committed_block_readable_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let blocks: Vec<LocallyHashedBlock> = (0..40)
            .map(|i| LocallyHashedBlock::from_bytes(format!("bulk block #{i}").into_bytes()))
            .collect();
        let hashes: Vec<ContentHash> = blocks.iter().map(|b| b.hash().clone()).collect();

        {
            let store = FsBlockStore::new(dir.path()).unwrap();
            let mut ingest = store.begin_bulk_ingest();
            for block in blocks {
                ingest.stage_prepared(block);
            }
            let outcome = ingest.flush_durable().unwrap();
            assert_eq!(outcome.committed_hashes.len(), 40);
        } // store dropped here -- nothing but the on-disk directory survives

        let reopened = FsBlockStore::new(dir.path()).unwrap();
        for (i, hash) in hashes.iter().enumerate() {
            assert!(reopened.exists(hash).unwrap(), "block #{i} missing after reopen");
            assert_eq!(
                reopened.get(hash).unwrap(),
                format!("bulk block #{i}").into_bytes(),
                "block #{i} content wrong after reopen"
            );
        }
        assert_eq!(reopened.usage().unwrap().block_count, 40);
    }

    /// An injected failure partway through a batch (using the existing
    /// `RecordingCommitIo` fail-injection double, same mechanism the
    /// single-block `commit_block` crash-safety tests already use) must
    /// leave only harmless, unreferenced content on disk -- never a torn
    /// write, and never a state where `flush_durable`'s `Err` return
    /// disagrees with what's actually readable. `BULK_INGEST_CONCURRENCY`
    /// is small enough (4) that a batch bigger than it guarantees at
    /// least one full concurrent chunk completes successfully before the
    /// chunk containing the injected failure, so this also exercises
    /// "some blocks really did commit before the failing one" rather than
    /// only the trivial all-or-nothing case.
    #[test]
    fn crash_mid_batch_leaves_only_harmless_unreferenced_content() {
        let dir = tempfile::tempdir().unwrap();
        let io = Arc::new(RecordingCommitIo::new(Some(CommitStage::Published)));
        let store = FsBlockStore::with_commit_io(dir.path(), io).unwrap();

        // More than BULK_INGEST_CONCURRENCY blocks so at least one whole
        // concurrent chunk has a real chance to finish before the
        // injected failure is hit by some other block in a later chunk
        // (chunk scheduling order isn't guaranteed per-block, only
        // bounded-concurrency -- the assertion below checks the
        // INVARIANT, not a specific block's fate).
        let blocks: Vec<LocallyHashedBlock> = (0..10)
            .map(|i| LocallyHashedBlock::from_bytes(format!("crash batch #{i}").into_bytes()))
            .collect();
        let hashes: Vec<ContentHash> = blocks.iter().map(|b| b.hash().clone()).collect();

        let mut ingest = store.begin_bulk_ingest();
        for block in blocks {
            ingest.stage_prepared(block);
        }
        let result = ingest.flush_durable();
        assert!(result.is_err(), "an injected mid-batch publish failure must surface as Err");

        // The invariant: for every block, EITHER it's fully present and
        // correctly readable, OR it's entirely absent -- there is no
        // third state (a corrupt/partial file, a directory desync, a
        // usage count that disagrees with what's actually on disk).
        let mut present_count = 0;
        for (i, hash) in hashes.iter().enumerate() {
            if store.exists(hash).unwrap() {
                present_count += 1;
                assert_eq!(
                    store.get(hash).unwrap(),
                    format!("crash batch #{i}").into_bytes(),
                    "a present block after a mid-batch crash must have fully-correct content, \
                     never a torn write"
                );
            }
        }
        // The real, trusted usage count (a full-tree scan) must agree
        // exactly with how many blocks are actually, physically present
        // -- the crash must never leave the in-memory/persisted count
        // pointing at more blocks than genuinely exist on disk.
        let scanned = scan_usage(dir.path()).unwrap();
        assert_eq!(
            scanned.block_count as usize, present_count,
            "usage accounting must never overcount past a mid-batch crash"
        );
    }

    /// The whole point of collecting the shard tree across a batch: a
    /// batch that creates many `root/aa/bb` shards under many `root/aa`
    /// prefixes must fsync the store root ONCE, each prefix ONCE and each
    /// shard ONCE -- not once per block that happened to need it.
    ///
    /// With SHA-256-uniform hashes and a fresh store, nearly every block
    /// creates a new shard and a large fraction create a new prefix too,
    /// so publishing each creation where it happened meant fsyncing the
    /// single shared store root dozens of times per batch to make the same
    /// directory durable over and over. The assertion below is exact
    /// (`== 1` per distinct directory), which is what makes it a real
    /// guard rather than an approximation of one.
    #[test]
    fn a_batch_publishes_each_shard_tree_directory_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let io = Arc::new(RecordingCommitIo::new(None));
        let store = FsBlockStore::with_commit_io(dir.path(), io.clone()).unwrap();

        let blocks: Vec<LocallyHashedBlock> = (0..200)
            .map(|i| LocallyHashedBlock::from_bytes(format!("shard tree #{i}").into_bytes()))
            .collect();

        // Two distinct shards under one prefix have to occur for the
        // prefix-level collapse to be exercised at all, so assert the
        // fixture actually produced that rather than trusting the odds.
        let mut shards_per_prefix: HashMap<String, HashSet<String>> = HashMap::new();
        for block in &blocks {
            shards_per_prefix
                .entry(block.hash()[0..2].to_string())
                .or_default()
                .insert(block.hash()[2..4].to_string());
        }
        assert!(
            shards_per_prefix.values().any(|shards| shards.len() > 1),
            "fixture must contain a prefix holding more than one shard, or this test \
             cannot observe the prefix-level collapse"
        );

        let expected_prefixes: HashSet<PathBuf> =
            shards_per_prefix.keys().map(|prefix| store.root.join(prefix)).collect();
        let expected_shards: HashSet<PathBuf> =
            blocks.iter().map(|block| store.shard_dir_for_hash(block.hash())).collect();

        let mut ingest = store.begin_bulk_ingest();
        for block in blocks {
            ingest.stage_prepared(block);
        }
        ingest.flush_durable().unwrap();

        let synced = io.synced.lock().unwrap().clone();
        let mut counts: HashMap<PathBuf, usize> = HashMap::new();
        for path in &synced {
            *counts.entry(path.clone()).or_default() += 1;
        }
        for (path, count) in &counts {
            assert_eq!(*count, 1, "{} was fsynced {} times, expected once", path.display(), count);
        }

        let mut expected: HashSet<PathBuf> = HashSet::new();
        expected.insert(store.root.clone());
        expected.extend(expected_prefixes.iter().cloned());
        expected.extend(expected_shards.iter().cloned());
        assert_eq!(
            counts.keys().cloned().collect::<HashSet<_>>(),
            expected,
            "a batch must publish exactly the store root, every prefix it created and every \
             shard it wrote into -- no more (redundant fsyncs) and no less (an unreachable block)"
        );
        assert!(
            expected_prefixes.len() > 1,
            "more than one prefix must have been created, so that collapsing the store-root \
             fsync to one is a real reduction and not a vacuous count"
        );
    }

    /// A directory that this process created but has not yet made durable
    /// must never be mistaken for a durable one just because it now
    /// `exists()`.
    ///
    /// This is the hazard that deferring the ancestor fsyncs to the end of
    /// a batch introduces, and it is the reason the deferral is safe. Two
    /// commits running concurrently can both land under the same
    /// `root/aa`: the first creates it, the second observes it already
    /// there. If the second concluded from that observation alone that
    /// `aa` was durable, it would skip the store-root fsync, publish its
    /// block and report it committed while the entry for `aa` was still
    /// only in page cache -- and a crash at that instant leaves the block
    /// unreachable even though its caller was told it was safe.
    #[test]
    fn a_created_but_unpublished_directory_is_never_treated_as_durable() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let prefix = store.root.join("ab");
        let first_shard = prefix.join("cd");
        let second_shard = prefix.join("ef");

        let first = store.reserve_shard_publish(&first_shard);
        assert_eq!(first.prefix.as_deref(), Some(prefix.as_path()));
        assert_eq!(first.shard.as_deref(), Some(first_shard.as_path()));
        // Exactly the state a concurrent committer would observe partway
        // through the first commit: on disk, not yet durable.
        fs::create_dir_all(&first_shard).unwrap();

        let second = store.reserve_shard_publish(&second_shard);
        assert_eq!(
            second.prefix.as_deref(),
            Some(prefix.as_path()),
            "a prefix that exists but has not been published yet must still be claimed"
        );

        let mut pending = PendingShardTree::default();
        pending.add(first);
        pending.add(second);
        fs::create_dir_all(&second_shard).unwrap();
        store.publish_shard_tree(&pending).unwrap();

        // Once published, the store root does not have to be fsynced again
        // for this prefix -- that saving is the entire point, and it is
        // only correct on the far side of the fsync above.
        let third = store.reserve_shard_publish(&prefix.join("99"));
        assert_eq!(third.prefix, None, "a published prefix must not cost another store-root fsync");
        assert_eq!(third.shard.as_deref(), Some(prefix.join("99").as_path()));
    }
}
