use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use crate::error::StorageError;
use crate::free_space::{self, VolumeFreeSpace};
use crate::traits::{BlockStore, ContentHash, GcReport, StorageUsage};

const GC_SWEEP_BATCH_SIZE: usize = 256;
const GC_SWEEP_BATCH_DELAY: Duration = Duration::from_millis(1);

/// Local filesystem-backed content-addressed block store.
///
/// Blocks are sharded under `<root>/<hash[0..2]>/<hash[2..4]>/<hash>` (git-object-style)
/// to avoid a single directory with millions of entries. The only paths ever
/// resolved are derived from validated hex-encoded SHA-256 hashes, so
/// caller-supplied strings can never escape `root` (see `validate_hash`).
pub struct FsBlockStore {
    root: PathBuf,
    usage: Mutex<StorageUsage>,
    /// add-resource-governance task 1.2/3.1: an explicit headroom override
    /// (bytes), live-reloadable via `set_headroom_override_bytes` without
    /// reconstructing the store — mirrors the "mutable-after-construction
    /// field + setter" pattern `PeerSyncSession::set_authorized_groups`
    /// already established for a daemon-config-driven value that must take
    /// effect without a restart. `None` means "use the default formula"
    /// (`free_space::effective_headroom_bytes`'s `max(1 GiB, 5%)`) —
    /// consulted for `free_space_state()`'s reporting unconditionally, and
    /// for `put()`'s preflight only when `headroom_enforced` (below) is set.
    headroom_override_bytes: Mutex<Option<u64>>,
    /// Whether `put()` actually gates writes on the headroom check at all
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
    /// so production behavior still matches design.md D3's "checks the
    /// volume before every block write" once actually running as a daemon;
    /// only a bare, ungoverned `FsBlockStore` stays inert.
    headroom_enforced: AtomicBool,
}

impl FsBlockStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        let usage = match read_usage_counter(&root)? {
            Some(usage) => usage,
            None => {
                let usage = scan_usage(&root)?;
                write_usage_counter(&root, usage)?;
                usage
            }
        };
        Ok(Self {
            root,
            usage: Mutex::new(usage),
            headroom_override_bytes: Mutex::new(None),
            headroom_enforced: AtomicBool::new(false),
        })
    }

    fn headroom_override_bytes(&self) -> Option<u64> {
        *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// task 3.1: before persisting a block write, query free space on the
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
        let updated = {
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
            *usage
        };
        write_usage_counter(&self.root, updated)
    }

    fn set_usage(&self, updated: StorageUsage) -> Result<(), StorageError> {
        *self.usage.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = updated;
        write_usage_counter(&self.root, updated)
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

        self.set_usage(scan_usage(&self.root)?)?;
        Ok(report)
    }

    /// `sync-performance` PERF-8: the actual batched presence check,
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

/// SEC-SYNC-1: appends a collision-free `.yadorilink-tmp` suffix to `path`'s
/// full filename — never `with_extension`, which *replaces* the extension
/// and previously produced a single **fixed** `<hash>.tmp` path shared by
/// every concurrent writer of that same hash. Also mixes in the current
/// process id and a per-process monotonic counter, mirroring
/// `chunker::unique_tmp_path` (COR-1, which fixed the exact same class of
/// bug for `reconstruct_file`'s write path) — so two concurrent `put()`s of
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

/// A valid block key is exactly a 64-character lowercase hex SHA-256 digest.
/// This rejects path traversal sequences, absolute paths, and anything else
/// that isn't a bare content hash, before it ever reaches the filesystem.
fn validate_hash(hash: &str) -> Result<(), StorageError> {
    if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(StorageError::InvalidPath(format!("not a valid content hash: {hash:?}")))
    }
}

impl BlockStore for FsBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        let hash = Self::hash_bytes(data);
        let path = self.path_for_hash(&hash)?;
        if path.exists() {
            // Identical content already stored — no-op (dedup).
            return Ok(hash);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // add-resource-governance task 3.1: preflight before any bytes
        // touch disk — must run after the dedup short-circuit above (a
        // dedup no-op needs no new space) but before the temp file below is
        // ever created, so a rejection here leaves nothing partially
        // written to clean up.
        self.check_headroom(&path, data.len() as u64)?;
        // Write to a unique-per-writer temp file then rename, so a crash
        // never leaves a partially-written block visible under its final
        // content-hash path, *and* (SEC-SYNC-1) two concurrent `put()`s of
        // the same hash never share a temp path and clobber each other —
        // see `unique_tmp_path`'s doc comment.
        let tmp_path = unique_tmp_path(&path);
        fs::write(&tmp_path, data)?;
        fs::rename(&tmp_path, &path)?;
        self.adjust_usage(1, data.len() as i64)?;
        Ok(hash)
    }

    /// Turns `put`'s preflight gate on or off — see `headroom_enforced`'s
    /// doc comment. `yadorilink-daemon` calls this with `true` once at
    /// startup (through `Arc<dyn BlockStore>`, hence this living on the
    /// trait rather than only as an inherent method); direct/test users of
    /// this crate that never call it get the pre-existing (pre-
    /// `add-resource-governance`) unthrottled behavior.
    fn set_headroom_enforced(&self, enforced: bool) {
        self.headroom_enforced.store(enforced, Ordering::Relaxed);
    }

    /// task 2.5-style live reload for the headroom check (task 1.2): applied
    /// to every subsequent `put()` call, no reconstruction needed.
    fn set_headroom_override_bytes(&self, headroom_bytes: Option<u64>) {
        *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner()) = headroom_bytes;
    }

    /// task 1.3/5.4: the block-store root's volume free-space snapshot,
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
        let data = fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(hash.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let actual = Self::hash_bytes(&data);
        if actual != hash {
            // SEC-SYNC-1 self-heal: a checksum mismatch here proves the
            // on-disk file is torn/corrupt garbage that does not match its
            // own content-addressed name — never valid content a caller
            // could legitimately want. Content-addressed storage makes
            // deleting it safe: a hash-named file whose bytes don't hash to
            // that name can never be the *only* copy of anything real (a
            // correct copy can always be re-fetched from any peer that has
            // it, or re-derived locally), so removing it here — rather than
            // leaving it in place to poison every future `put()`'s
            // `exists()` short-circuit forever — lets a subsequent `put()`
            // of the correct bytes re-materialize the block instead of the
            // referencing file staying permanently un-hydratable. Best
            // effort: if the removal itself fails, the mismatch is still
            // reported (the caller's retry path is unaffected either way).
            let _ = fs::remove_file(&path);
            return Err(StorageError::ChecksumMismatch { expected: hash.to_string(), actual });
        }
        Ok(data)
    }

    /// `sync-performance` PERF-4: skips the SHA-256 re-hash `get`
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
        let size = match fs::metadata(&path) {
            Ok(metadata) => Some(metadata.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(StorageError::Io(e)),
        };
        match fs::remove_file(&path) {
            Ok(()) => {
                if let Some(size) = size {
                    self.adjust_usage(-1, -(size as i64))?;
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        Ok(self.path_for_hash(hash)?.exists())
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
        Ok(*self.usage.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    /// add-block-store-gc task 3.2: delegates to the inherent
    /// `FsBlockStore::sweep` (already exercised directly by this module's
    /// own unit tests below) so `yadorilink-daemon`'s `Arc<dyn BlockStore>`
    /// can invoke it too — see the trait method's doc comment.
    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        FsBlockStore::sweep(self, live, grace_cutoff, dry_run)
    }

    /// `sync-performance` PERF-8: overrides the trait's N-`stat` default
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
    /// `#[tokio::test(flavor = "multi_thread", ...)]`). Outside a tokio
    /// runtime (plain `#[test]`s here) or on a current-thread runtime
    /// (the plain `#[tokio::test]`s used throughout
    /// `yadorilink-sync-core`), it just runs the work inline, exactly as
    /// the previous default did — behavior is unchanged in both cases.
    // add-deterministic-sync-testing: `madsim`'s tokio shim has no
    // `block_in_place`/`runtime_flavor` (its cooperative scheduler has no
    // real OS thread to block in place on) — under `--cfg madsim` this
    // always takes the same inline fallback the multi-thread fast path
    // above would take on any non-multi-thread runtime anyway (see this
    // method's doc comment), so correctness is unaffected; only the
    // off-executor-thread performance optimization is skipped under
    // simulation.
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
