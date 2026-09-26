//! `SegmentBlockStore` -- this device's canonical content-addressed block
//! storage.
//!
//! ```text
//! <root>/
//!   FORMAT                        a human-readable marker; the authority is index.sqlite3
//!   index.sqlite3                 canonical metadata: hash -> (segment, offset, length)
//!   segments/
//!     0000000000000001.seg        append-only, immutable below durable_end
//!     0000000000000002.seg
//! ```
//!
//! # Why not one file per block
//!
//! A content-addressed file per block makes every block its own durability
//! barrier, and barriers -- not bytes -- are what a small-file import
//! costs. Importing 100,000 50-byte files writes about 5 MB and pays
//! 100,000 `fsync`s for it, ~3.6 ms each on the reference host. Measured
//! directly at the block layer on ext4: 4,096 blocks cost 2.134 s with one
//! barrier per block, and 0.281 s when the same bytes were made durable by
//! a single filesystem-wide barrier -- a 7.6x difference that is entirely
//! the barrier count, since the bytes were identical.
//!
//! That whole-filesystem barrier is not a shipping option (it flushes
//! every other writer on the volume, it cannot say *which* write failed,
//! and it only makes sense where one process owns the filesystem). The
//! shipping answer is the same arithmetic reached legitimately: keep one
//! barrier per *group of blocks* instead of one per block, by making many
//! blocks share a physical destination. That is what a segment is.
//!
//! # The contract this does not change
//!
//! `staged -> durable -> authoritative` is unchanged and remains the
//! store's entire reason for existing. Only the middle step's physical
//! form changed:
//!
//! - **staged**: blocks exist in the caller's memory. Invisible to every
//!   other consumer -- not in `present_blocks`, not in any provenance
//!   table, not referenced by any `FileRecord`.
//! - **durable**: [`SegmentBlockStore::put_durable_batch`] returned
//!   receipts. The bytes are fsynced in a segment *and* the index
//!   transaction that maps them has committed, in that order.
//! - **authoritative**: the caller's own step, one layer up. This store
//!   has no idea whether its caller is mid-capture or about to publish.
//!
//! # The invariant
//!
//! **The index never names a block whose bytes are not already durable.**
//! Everything else here follows from it: see [`coordinator`] for the
//! ordering that establishes it, [`recovery`] for the three ways a crash
//! can leave the two out of step and what each does, and [`compaction`]
//! for how the rule survives moving bytes between segments.

mod compaction;
mod coordinator;
mod fault;
mod format;
mod index;
mod recovery;
mod segment;
pub mod testing;

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use crate::error::StorageError;
use crate::free_space::{self, VolumeFreeSpace};
use crate::io_diag::{self, Op};
use crate::traits::{
    hash_block_bytes, BlockStore, ContentHash, GcReport, LocallyHashedBlock, StorageUsage,
};

pub use compaction::{CompactionReport, COMPACTION_DEAD_RATIO, COMPACTION_MIN_DEAD_BYTES};
pub use coordinator::{DurableReceipt, GroupCommitLimits};
pub use fault::{CommitPoint, FaultPlan};
pub use recovery::RecoveryReport;

use coordinator::{ensure_segments_directory, raw_hash, DurabilityCoordinator};
use format::RAW_HASH_LEN;
use index::BlockIndex;
use segment::{read_record_payload, segment_path, RecordReadError};

/// The human-readable marker file. The authority on format is the index's
/// own `store_meta` row -- this exists so someone looking at the directory
/// can tell what it is, and so a directory that is plainly not one of
/// these is obvious at a glance.
const FORMAT_MARKER_FILE: &str = "FORMAT";

/// How many segment file descriptors the read path keeps open at once.
/// Reads concentrate on recent segments, so a small cache serves nearly
/// every read while leaving the process's descriptor budget alone.
const MAX_CACHED_SEGMENT_READERS: usize = 128;
const INDEX_FILE: &str = "index.sqlite3";

/// A store's full accounting, beyond what `BlockStore::usage`'s
/// two-number shape can carry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SegmentStoreUsage {
    pub live_blocks: u64,
    /// Payload bytes of live blocks -- the size of the content held.
    pub live_bytes: u64,
    /// Every byte the segment files occupy past their headers.
    pub physical_bytes: u64,
    /// Physical bytes no live block needs: superseded copies, deleted
    /// blocks, and the framing of both. Compaction's input.
    pub dead_bytes: u64,
    pub active_segments: u64,
    pub sealed_segments: u64,
    /// Segments whose files are awaiting deletion.
    pub retired_segments: u64,
}

/// What an offline scrub found. `unbacked_mappings` and `corrupt_records`
/// being empty is the store's central invariant holding; everything else
/// here is accounting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoreVerification {
    pub segments_scanned: u64,
    pub records_scanned: u64,
    pub bytes_scanned: u64,
    /// Blocks the index maps to a record that is not there. Every entry is
    /// a block the store would otherwise claim to hold and fail to serve.
    pub unbacked_mappings: Vec<ContentHash>,
    /// Blocks whose stored bytes do not hash to their own key. Only
    /// populated when payloads were verified.
    pub corrupt_records: Vec<ContentHash>,
    /// Complete records that no mapping names -- dead space, not damage.
    pub unindexed_records: u64,
    /// Segments whose last record does not reach `durable_end`. Should
    /// never happen: `durable_end` is only ever advanced to a record
    /// boundary that was already fsynced.
    pub segments_with_incomplete_tail: Vec<u64>,
}

impl StoreVerification {
    /// Whether the index and the segments agree about everything the store
    /// claims to hold.
    pub fn is_consistent(&self) -> bool {
        self.unbacked_mappings.is_empty()
            && self.corrupt_records.is_empty()
            && self.segments_with_incomplete_tail.is_empty()
    }
}

/// Local, segment-backed content-addressed block store.
///
/// Reads take no store-wide lock: a lookup in the index yields a
/// `(segment, offset, length)` and the bytes come back through a
/// positional read, concurrently with whatever the writer is appending. No
/// path this store takes holds a lock across an `fsync`.
pub struct SegmentBlockStore {
    root: PathBuf,
    index: Arc<BlockIndex>,
    coordinator: Arc<DurabilityCoordinator>,
    /// Read-only handles, opened on demand and bounded. Purely a cache:
    /// dropping an entry costs a reopen and nothing else, which is what
    /// makes both eviction under pressure and evicting a retired
    /// segment's handle safe.
    readers: RwLock<HashMap<u64, CachedReader>>,
    /// Monotonic tick stamped onto a cached handle whenever it is used, so
    /// eviction can pick the stalest one. Relaxed throughout: an
    /// approximate recency order is all an eviction policy needs.
    reader_clock: AtomicU64,
    headroom_enforced: AtomicBool,
    headroom_override_bytes: Mutex<Option<u64>>,
    /// Fires once a batch is durable and before its caller is told so --
    /// the `durable -> authoritative` boundary, observable from another
    /// thread. See [`SegmentBlockStore::install_durability_barrier_hook_for_tests`].
    durability_barrier_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    recovery_report: RecoveryReport,
}

/// One cached segment handle plus its recency stamp.
struct CachedReader {
    file: Arc<File>,
    last_used: AtomicU64,
}

impl SegmentBlockStore {
    /// Opens (creating if absent) the store at `root`, running recovery.
    ///
    /// Cost is proportional to the number of segments, not to the bytes
    /// they hold: no payload is read and nothing is hashed.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StorageError> {
        Self::with_limits(root, GroupCommitLimits::from_env())
    }

    pub fn with_limits(
        root: impl Into<PathBuf>,
        limits: GroupCommitLimits,
    ) -> Result<Self, StorageError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        ensure_segments_directory(&root)?;
        write_format_marker(&root)?;

        let index = Arc::new(BlockIndex::open(&root.join(INDEX_FILE))?);
        let recovered = recovery::recover(&root, &index)?;
        if !recovered.report.is_clean() {
            tracing::warn!(
                truncated = ?recovered.report.truncated_segments,
                truncated_bytes = recovered.report.truncated_bytes,
                orphans_removed = ?recovered.report.removed_orphan_segments,
                damaged = ?recovered.report.damaged_segments,
                dropped_mappings = recovered.report.dropped_mappings,
                reclaimed = ?recovered.report.reclaimed_segments,
                "block store recovered on open"
            );
        }
        let coordinator = Arc::new(DurabilityCoordinator::new(
            root.clone(),
            Arc::clone(&index),
            limits,
            recovered.next_segment_id,
        ));

        Ok(Self {
            root,
            index,
            coordinator,
            readers: RwLock::new(HashMap::new()),
            reader_clock: AtomicU64::new(0),
            headroom_enforced: AtomicBool::new(false),
            headroom_override_bytes: Mutex::new(None),
            durability_barrier_hook: Mutex::new(None),
            recovery_report: recovered.report,
        })
    }

    /// Default per-OS application data directory for the block store.
    pub fn default_root() -> Result<PathBuf, StorageError> {
        let base = dirs_next_app_data_dir().ok_or_else(|| {
            StorageError::InvalidPath("no application data directory available on this OS".into())
        })?;
        Ok(base.join("yadorilink").join("blocks"))
    }

    /// What opening this store had to repair. Empty on a clean open.
    pub fn recovery_report(&self) -> &RecoveryReport {
        &self.recovery_report
    }

    pub fn group_commit_limits(&self) -> GroupCommitLimits {
        self.coordinator.limits()
    }

    /// Commits every block in `prepared` as one durability group and
    /// returns a receipt per block, in order.
    ///
    /// This is the store's one write path -- `put`, `put_prepared` and
    /// `put_prepared_batch` are all this method with the receipts
    /// discarded. Returning `Ok` means every block is durable: its bytes
    /// are fsynced in a segment and the index transaction naming them has
    /// committed. Nothing upstream may become authoritative before that.
    pub fn put_durable_batch(
        &self,
        prepared: &[LocallyHashedBlock],
    ) -> Result<Vec<DurableReceipt>, StorageError> {
        if prepared.is_empty() {
            return Ok(Vec::new());
        }
        let total_bytes: u64 = prepared.iter().map(|block| block.bytes().len() as u64).sum();
        self.check_headroom(total_bytes)?;

        let receipts = self.coordinator.submit(Arc::new(prepared.to_vec()))?;

        // Durable, and not yet reported so. Everything a caller does with
        // these receipts happens after this point; a test that needs to
        // observe the boundary observes it here.
        let hook = self
            .durability_barrier_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(hook) = hook {
            hook();
        }
        Ok(receipts)
    }

    /// Full accounting: live, physical and dead bytes, and the segment
    /// census. Read straight out of the index's segment rows -- never a
    /// filesystem walk.
    pub fn detailed_usage(&self) -> Result<SegmentStoreUsage, StorageError> {
        let usage = self.index.usage()?;
        Ok(SegmentStoreUsage {
            live_blocks: usage.live_blocks,
            live_bytes: usage.live_payload_bytes,
            physical_bytes: usage.physical_bytes,
            dead_bytes: usage.dead_bytes(),
            active_segments: usage.active_segments,
            sealed_segments: usage.sealed_segments,
            retired_segments: usage.retired_segments,
        })
    }

    /// Rewrites every segment whose dead fraction has passed the
    /// thresholds, then deletes what that retired. Synchronous and bounded
    /// -- the caller decides when to spend the I/O, which for the daemon is
    /// its existing idle-GC schedule.
    pub fn compact_if_needed(&self) -> Result<CompactionReport, StorageError> {
        self.compact_with_thresholds(COMPACTION_DEAD_RATIO, COMPACTION_MIN_DEAD_BYTES)
    }

    /// `compact_if_needed` with explicit thresholds, so a test can trigger
    /// the same production path on a store far smaller than the shipping
    /// thresholds are sized for.
    pub fn compact_with_thresholds(
        &self,
        dead_ratio: f64,
        min_dead_bytes: u64,
    ) -> Result<CompactionReport, StorageError> {
        let mut total = CompactionReport::default();
        for candidate in compaction::candidates(&self.index, dead_ratio, min_dead_bytes)? {
            let report = compaction::compact_segment(
                &self.index,
                &self.coordinator,
                candidate.segment_id,
                |hash| {
                    let _reads = io_diag::attribute_reads(io_diag::ReadReason::Compaction);
                    self.get(hash)
                },
            )?;
            total.segments_compacted += report.segments_compacted;
            total.blocks_relocated += report.blocks_relocated;
            total.bytes_reclaimed += report.bytes_reclaimed;
            total.unreadable_blocks_dropped += report.unreadable_blocks_dropped;
        }
        self.reclaim_retired()?;
        Ok(total)
    }

    /// Compacts, but stops short of deleting the segments the compaction
    /// retired -- the exact state a crash between the mapping swap and the
    /// old file's removal leaves behind. A test reopens the store from
    /// here to prove recovery finishes the job. Never call this outside a
    /// test.
    pub fn compact_without_reclaim_for_tests(
        &self,
        dead_ratio: f64,
        min_dead_bytes: u64,
    ) -> Result<CompactionReport, StorageError> {
        let mut total = CompactionReport::default();
        for candidate in compaction::candidates(&self.index, dead_ratio, min_dead_bytes)? {
            let report = compaction::compact_segment(
                &self.index,
                &self.coordinator,
                candidate.segment_id,
                |hash| {
                    let _reads = io_diag::attribute_reads(io_diag::ReadReason::Compaction);
                    self.get(hash)
                },
            )?;
            total.segments_compacted += report.segments_compacted;
            total.blocks_relocated += report.blocks_relocated;
            total.bytes_reclaimed += report.bytes_reclaimed;
            total.unreadable_blocks_dropped += report.unreadable_blocks_dropped;
        }
        Ok(total)
    }

    /// Deletes the files of already-retired segments. Safe to call at any
    /// time; a file still held open elsewhere is simply left for later.
    pub fn reclaim_retired(&self) -> Result<u64, StorageError> {
        compaction::reclaim_retired_segments(&self.root, &self.index, |segment_id| {
            self.evict_reader(segment_id);
        })
    }

    /// Seals the segment currently being appended to, so the next group
    /// starts a new one. Compaction only ever considers sealed segments,
    /// so this is how a caller makes recently written data eligible.
    pub fn seal_active_segment(&self) -> Result<(), StorageError> {
        self.coordinator.seal_active_segment()
    }

    /// Ids of every segment the index knows, oldest first.
    pub fn segment_ids(&self) -> Result<Vec<u64>, StorageError> {
        Ok(self.index.segments()?.into_iter().map(|row| row.segment_id).collect())
    }

    /// Walks every segment's records and cross-checks them against the
    /// index. The offline path -- nothing on the hot path calls this, and
    /// its cost is proportional to the bytes the store holds, which is
    /// exactly why opening a store does not do it.
    ///
    /// Two directions, and they are not the same question:
    ///
    /// - **an index mapping with no record behind it** is a store that
    ///   would claim a block it cannot serve, which is the invariant
    ///   failing;
    /// - **a record no mapping names** is ordinary dead space (a deleted
    ///   block, a superseded copy, a group that was appended but never
    ///   committed), and is what compaction reclaims.
    ///
    /// `verify_payloads` additionally re-derives every record's SHA-256,
    /// which is what turns this from a structural check into a real
    /// integrity scrub.
    pub fn verify_store(&self, verify_payloads: bool) -> Result<StoreVerification, StorageError> {
        let mut report = StoreVerification::default();
        for row in self.index.segments()? {
            if row.state == index::SegmentState::Retired {
                continue;
            }
            let file = self.reader(row.segment_id)?;
            let scan = segment::scan_segment_records(&file, row.durable_end)?;
            if scan.segment_id != row.segment_id {
                return Err(StorageError::CorruptStore(format!(
                    "segment file for {} declares id {}",
                    row.segment_id, scan.segment_id
                )));
            }
            report.segments_scanned += 1;
            report.bytes_scanned += scan.complete_end.saturating_sub(format::SEGMENT_HEADER_LEN);
            if scan.complete_end < row.durable_end {
                tracing::warn!(
                    segment_id = row.segment_id,
                    complete_end = scan.complete_end,
                    durable_end = row.durable_end,
                    stopped_because = ?scan.stopped_because,
                    "segment's durable range ends past its last complete record"
                );
                report.segments_with_incomplete_tail.push(row.segment_id);
            }

            let mut found: HashMap<[u8; RAW_HASH_LEN], (u64, u32)> = HashMap::new();
            for record in &scan.records {
                report.records_scanned += 1;
                found.insert(record.hash, (record.record_offset, record.payload_len));
            }
            let mut cursor: Option<u64> = None;
            loop {
                let page = self.index.live_blocks_in_segment(row.segment_id, cursor, 4096)?;
                if page.is_empty() {
                    break;
                }
                cursor = page.last().map(|(_, location)| location.record_offset);
                for (raw, location) in page {
                    let hex_hash = hex::encode(raw);
                    let backed = found.remove(&raw).is_some_and(|(offset, payload_len)| {
                        offset == location.record_offset && payload_len == location.length
                    });
                    if !backed {
                        report.unbacked_mappings.push(hex_hash);
                    } else if verify_payloads
                        && !read_record_payload(&file, &location, &raw)
                            .is_ok_and(|payload| hash_block_bytes(&payload) == hex_hash)
                    {
                        report.corrupt_records.push(hex_hash);
                    }
                }
            }
            report.unindexed_records += found.len() as u64;
        }
        Ok(report)
    }

    fn check_headroom(&self, additional_bytes: u64) -> Result<(), StorageError> {
        if !self.headroom_enforced.load(Ordering::Relaxed) {
            return Ok(());
        }
        let override_bytes =
            *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner());
        let space = io_diag::time(Op::HeadroomCheck, 0, || {
            free_space::classify_volume(&self.root, override_bytes)
        })?;
        if space.would_breach(additional_bytes) {
            return Err(StorageError::DiskPressure {
                path: self.root.join(segment::SEGMENTS_DIR),
                volume: self.root.clone(),
                available_bytes: space.available_bytes,
                headroom_bytes: space.headroom_bytes,
            });
        }
        Ok(())
    }

    /// A read-only handle on one segment, opened once and shared.
    ///
    /// Bounded, because a file descriptor per segment is a descriptor per
    /// gigabyte of store: a large store would otherwise sit on thousands
    /// of open handles and meet the process limit, which on some hosts is
    /// as low as 256. Evicting is free -- the entry is purely a cache, and
    /// losing one costs a reopen. A handle already in flight keeps working
    /// after eviction because callers hold an `Arc`, not a borrow.
    ///
    /// Never a lock a reader waits behind for long: the read path takes a
    /// read lock on a hit, and the write lock only on a miss.
    fn reader(&self, segment_id: u64) -> Result<Arc<File>, StorageError> {
        let now = self.reader_clock.fetch_add(1, Ordering::Relaxed);
        if let Some(entry) = self.readers.read().unwrap_or_else(|p| p.into_inner()).get(&segment_id)
        {
            entry.last_used.store(now, Ordering::Relaxed);
            return Ok(Arc::clone(&entry.file));
        }
        let file = Arc::new(File::open(segment_path(&self.root, segment_id))?);
        let mut readers = self.readers.write().unwrap_or_else(|p| p.into_inner());
        if readers.len() >= MAX_CACHED_SEGMENT_READERS && !readers.contains_key(&segment_id) {
            if let Some(stalest) = readers
                .iter()
                .min_by_key(|(_, entry)| entry.last_used.load(Ordering::Relaxed))
                .map(|(id, _)| *id)
            {
                readers.remove(&stalest);
            }
        }
        let entry = readers
            .entry(segment_id)
            .or_insert_with(|| CachedReader { file, last_used: AtomicU64::new(now) });
        Ok(Arc::clone(&entry.file))
    }

    fn evict_reader(&self, segment_id: u64) {
        self.readers.write().unwrap_or_else(|p| p.into_inner()).remove(&segment_id);
    }

    /// The shared body of `get`/`get_unchecked`.
    ///
    /// Retries on content damage, but only when re-resolving the mapping
    /// shows it moved: that is the compaction race (a reader that resolved
    /// a location just before the swap and reached the file just after the
    /// old one was deleted), and it is a stale answer rather than damage.
    /// A mapping that still points where it did, at bytes that do not read
    /// back, is real damage -- and is dropped, so the block is honestly
    /// reported absent and can be re-acquired, rather than staying
    /// permanently present-but-unreadable.
    fn read_block(&self, hash: &str, verify_content: bool) -> Result<Vec<u8>, StorageError> {
        let raw = raw_hash(hash)?;
        for _ in 0..3 {
            let Some(location) = self.index.lookup(&raw)? else {
                return Err(StorageError::NotFound(hash.to_string()));
            };
            let file = match self.reader(location.segment_id) {
                Ok(file) => file,
                Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    if self.index.lookup(&raw)? != Some(location) {
                        continue;
                    }
                    self.drop_unreadable_mapping(&raw, hash, "segment file is missing");
                    return Err(StorageError::NotFound(hash.to_string()));
                }
                Err(e) => return Err(e),
            };

            let read = io_diag::time_block_read(u64::from(location.length), || {
                read_record_payload(&file, &location, &raw)
            });
            match read {
                Ok(payload) => {
                    if verify_content {
                        let actual = hash_block_bytes(&payload);
                        if actual != hash {
                            self.drop_unreadable_mapping(
                                &raw,
                                hash,
                                "stored bytes do not hash to their own key",
                            );
                            return Err(StorageError::ChecksumMismatch {
                                expected: hash.to_string(),
                                actual,
                            });
                        }
                    }
                    return Ok(payload);
                }
                Err(RecordReadError::Io(e)) => return Err(e),
                Err(damage) => {
                    if self.index.lookup(&raw)? != Some(location) {
                        self.evict_reader(location.segment_id);
                        continue;
                    }
                    self.drop_unreadable_mapping(&raw, hash, &damage.reason());
                    return Err(StorageError::ChecksumMismatch {
                        expected: hash.to_string(),
                        actual: "unreadable".to_string(),
                    });
                }
            }
        }
        Err(StorageError::NotFound(hash.to_string()))
    }

    /// Removes a mapping whose bytes cannot be served. Best effort on
    /// purpose: the caller's error is reported either way, and a store
    /// that could not even drop the mapping is in no worse shape than one
    /// that never tried.
    fn drop_unreadable_mapping(&self, raw: &[u8; RAW_HASH_LEN], hash: &str, reason: &str) {
        tracing::error!(
            block = hash,
            reason,
            "block store cannot serve an indexed block; dropping the mapping so the block is \
             reported absent and can be re-acquired"
        );
        let _ = self.index.remove_blocks(std::slice::from_ref(raw));
    }

    fn raw_hashes(hashes: &[ContentHash]) -> Result<Vec<[u8; RAW_HASH_LEN]>, StorageError> {
        hashes.iter().map(|hash| raw_hash(hash)).collect()
    }
}

// ---------------------------------------------------------------------
// Test seams. Public (not `#[cfg(test)]`) because the crash matrix lives
// in this crate's `tests/` directory and the durability-ordering
// invariants are asserted from other crates, neither of which `cfg(test)`
// reaches. Each costs one unset-`Option` check on the path it sits on.
// ---------------------------------------------------------------------
impl SegmentBlockStore {
    /// Installs a hook fired once a batch is durable and before its caller
    /// is told. Lets a test observe "durable but not yet authoritative"
    /// deterministically from another thread. Never call this outside a
    /// test.
    pub fn install_durability_barrier_hook_for_tests(
        &self,
        hook: impl Fn() + Send + Sync + 'static,
    ) {
        *self.durability_barrier_hook.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(Arc::new(hook));
    }

    /// Arms a crash or I/O failure at one commit boundary. See
    /// [`FaultPlan`]. Never call this outside a test.
    pub fn arm_commit_fault_for_tests(&self, plan: FaultPlan) {
        self.coordinator.arm_fault(Some(Arc::new(plan)));
    }

    pub fn clear_commit_fault_for_tests(&self) {
        self.coordinator.arm_fault(None);
    }

    /// Whether an injected crash has halted this handle. A halted store
    /// models a process that is gone: every operation fails until the
    /// store is reopened.
    pub fn is_halted_for_tests(&self) -> bool {
        self.coordinator.is_halted()
    }

    /// Rewrites one block's recorded ingest time, so a GC grace-window
    /// test does not have to wait out the real window. Never call this
    /// outside a test. [`testing::backdate_block`] is the same thing for a
    /// test that only has the store's directory.
    pub fn backdate_block_for_tests(
        &self,
        hash: &str,
        when: SystemTime,
    ) -> Result<(), StorageError> {
        let raw = raw_hash(hash)?;
        self.index.set_block_added_at(&raw, system_time_to_unix_nanos(when))
    }

    /// Drops this store's cached read handle for one segment, so a
    /// subsequent read reopens the file by name. Tests that delete a
    /// segment out from under a live store need this: on Unix an already
    /// open descriptor keeps serving an unlinked file, which is the very
    /// property that makes compaction safe and the very thing a
    /// missing-file test must defeat.
    pub fn evict_reader_for_tests(&self, segment_id: u64) {
        self.evict_reader(segment_id);
    }
}

impl BlockStore for SegmentBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        let prepared = LocallyHashedBlock::from_bytes(data.to_vec());
        let hash = prepared.hash().clone();
        self.put_durable_batch(std::slice::from_ref(&prepared))?;
        Ok(hash)
    }

    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        self.put_durable_batch(std::slice::from_ref(prepared)).map(|_| ())
    }

    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        self.put_durable_batch(prepared).map(|_| ())
    }

    /// Reads a block back and verifies it against its own content hash.
    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.read_block(hash, true)
    }

    /// Reads a block back WITHOUT re-deriving its SHA-256. The record's
    /// own framing is still checked -- the header must name this hash and
    /// the payload must match the checksum written beside it -- so this is
    /// not an unchecked read of arbitrary bytes; it skips only the
    /// cryptographic verification, which is the expensive half. See the
    /// trait method's doc comment for when a caller may use it.
    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.read_block(hash, false)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError> {
        let raw = raw_hash(hash)?;
        self.index.remove_blocks(std::slice::from_ref(&raw))?;
        Ok(())
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        Ok(self.index.lookup(&raw_hash(hash)?)?.is_some())
    }

    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        self.index.hashes_with_hex_prefix(prefix)
    }

    fn usage(&self) -> Result<StorageUsage, StorageError> {
        let usage = self.index.usage()?;
        Ok(StorageUsage { block_count: usage.live_blocks, total_bytes: usage.live_payload_bytes })
    }

    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        let live_raw: HashSet<[u8; RAW_HASH_LEN]> =
            live.iter().filter_map(|hash| raw_hash(hash).ok()).collect();
        let candidates =
            self.index.sweep_candidates(&live_raw, system_time_to_unix_nanos(grace_cutoff))?;
        let mut report = GcReport {
            blocks_deleted: candidates.len() as u64,
            bytes_reclaimed: candidates.iter().map(|(_, bytes)| *bytes).sum(),
        };
        if dry_run {
            return Ok(report);
        }
        let hashes: Vec<[u8; RAW_HASH_LEN]> =
            candidates.into_iter().map(|(hash, _)| hash).collect();
        let summary = self.index.remove_blocks(&hashes)?;
        report.blocks_deleted = summary.blocks_removed;
        report.bytes_reclaimed = summary.payload_bytes_removed;
        // GC is exactly when reclaiming physical space is wanted and
        // affordable, so the pass that decided blocks are dead is also the
        // one that gives their bytes back.
        self.compact_if_needed()?;
        Ok(report)
    }

    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError> {
        let raw = Self::raw_hashes(hashes)?;
        let summary = self.index.remove_blocks(&raw)?;
        self.compact_if_needed()?;
        Ok(GcReport {
            blocks_deleted: summary.blocks_removed,
            bytes_reclaimed: summary.payload_bytes_removed,
        })
    }

    fn set_headroom_enforced(&self, enforced: bool) {
        self.headroom_enforced.store(enforced, Ordering::Relaxed);
    }

    fn set_headroom_override_bytes(&self, headroom_bytes: Option<u64>) {
        *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner()) = headroom_bytes;
    }

    fn free_space(&self) -> Result<Option<VolumeFreeSpace>, StorageError> {
        let override_bytes =
            *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner());
        Ok(Some(free_space::classify_volume(&self.root, override_bytes)?))
    }

    /// One indexed batch lookup for the whole slice. The blocking work is
    /// a single SQLite read, but this is called synchronously from `async
    /// fn`s with no intervening `.await`, so it stays off a tokio worker
    /// thread when a multi-threaded runtime is current -- the same guard
    /// this method has always carried, for the same reason.
    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| self.present_blocks_indexed(hashes))
            }
            _ => self.present_blocks_indexed(hashes),
        }
    }
}

impl SegmentBlockStore {
    fn present_blocks_indexed(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        let raw = Self::raw_hashes(hashes)?;
        Ok(self.index.lookup_many(&raw)?.into_iter().map(|found| found.is_some()).collect())
    }
}

/// Writes the human-readable marker, and refuses a directory that already
/// holds a different one -- the cheap guard against opening something that
/// is not one of these stores at all.
fn write_format_marker(root: &Path) -> Result<(), StorageError> {
    let path = root.join(FORMAT_MARKER_FILE);
    let expected =
        format!("yadorilink-block-store\nformat_version={}\n", index::STORE_FORMAT_VERSION);
    match std::fs::read_to_string(&path) {
        Ok(found) if found == expected => Ok(()),
        Ok(found) => Err(StorageError::CorruptStore(format!(
            "{} declares {:?}, which this build does not read",
            path.display(),
            found.lines().next().unwrap_or_default()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::write(&path, expected)?;
            Ok(())
        }
        Err(e) => Err(StorageError::Io(e)),
    }
}

fn system_time_to_unix_nanos(when: SystemTime) -> i64 {
    when.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
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
