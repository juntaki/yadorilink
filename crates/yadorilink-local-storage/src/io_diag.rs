//! Measurement-only I/O and pipeline counters for the block store's
//! durability path.
//!
//! Exists for one question: for a large-file capture, `capture ->
//! producer_EOF` is dominated by something that is *not* chunk production
//! (chunking is ~1.8 s per GiB; the phase is ~11.2 s). Wall-clock totals
//! cannot distinguish "the producer is blocked behind durability" from
//! "durability is bandwidth-bound" from "durability is metadata-bound" --
//! and those three have completely different fixes. This module counts
//! calls, bytes and nanoseconds per *operation class* so the breakdown is
//! observed rather than inferred.
//!
//! **Off by default and inert.** Every recording site is guarded by a
//! single `Ordering::Relaxed` load of [`ENABLED`], which nothing in the
//! production binaries ever sets: only the crate's own `examples/` and
//! tests call [`set_enabled`]. When disabled, the cost of an
//! instrumentation site is that one atomic load -- no `Instant::now()`,
//! no atomic increment, no allocation. Nothing here changes control flow,
//! ordering, error handling or durability semantics whether it is on or
//! off.
//!
//! No unit tests live here on purpose: every counter is process-global,
//! and Rust runs a crate's tests in parallel threads of one binary, so a
//! test that armed [`set_enabled`] would both perturb and be perturbed by
//! whatever `fs_backend`'s own tests were committing at that moment. The
//! module's behaviour is exercised end to end by
//! `examples/durability_producer_bench.rs` instead, which owns its whole
//! process.
//!
//! Deliberately process-global rather than threaded through the store:
//! the operations being timed sit inside `BlockCommitIo`, which is a
//! private trait behind an `Arc<dyn ...>` shared by every store instance,
//! and the pipeline counters sit inside `chunker.rs`'s scoped background
//! committer. Plumbing a handle to both would have meant changing several
//! production signatures for a diagnostic, which is a worse trade than a
//! global that is switched off.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// One measured operation class. Ordering is the reporting order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Op {
    // ---- producer / queue pipeline (chunker.rs) ----
    /// `BackgroundBatchCommitter::submit` calls (all of them).
    Submit = 0,
    /// Time the chunk producer spent parked on `not_full`, i.e. blocked
    /// because the durability queue's byte budget was already full. Calls
    /// = number of `submit`s that actually had to wait at all.
    SubmitBlocked = 1,
    /// Time the single background committer thread spent parked on
    /// `not_empty` with nothing to commit, i.e. starved by the producer.
    /// The mirror image of `SubmitBlocked`: if this is large and
    /// `SubmitBlocked` is small, the queue is not the bottleneck.
    CommitterIdle = 2,
    /// Wall time inside `store.put_prepared_batch` on the committer
    /// thread. Bytes = batch bytes.
    CommitBatch = 3,
    /// Wall time the producer spent in `BackgroundBatchCommitter::finish`
    /// after reaching EOF, waiting for whatever is still queued to commit.
    /// This is the tail that sits *after* the producer is done, so it is
    /// the part of durability cost that never blocks chunk production --
    /// the phase breakdown's `producer_EOF -> drain_done`, not its
    /// `capture -> producer_EOF`. Separating the two matters: shrinking
    /// the tail does not speed up capture, and shrinking the blocking does
    /// not shrink the tail.
    FinishDrain = 17,

    // ---- per-block durability path (fs_backend.rs) ----
    /// `path.exists()` on the block's final content-addressed path, once
    /// per block at the top of `commit_block_staged`.
    StatFinal = 4,
    /// `fs::read` of an existing final path for the dedup hash compare.
    /// On a fresh store this should never fire; if it does, the workload
    /// is re-reading content it already has.
    DedupRead = 5,
    /// `exists()` probes on `root/aa` and `root/aa/bb` inside
    /// `reserve_shard_publish`.
    StatShard = 6,
    /// `fs::create_dir_all` for the block's `aa/bb` shard directory.
    MkdirShard = 7,
    /// `fsync` of the store root, publishing newly created `aa` prefix
    /// directories. Issued once per batch that created any, however many
    /// it created -- one fsync of one directory is all it takes to make
    /// every entry currently in it durable, and the store root is a single
    /// shared directory. Per single-block `put`, at most one.
    DirFsyncRoot = 8,
    /// `fsync` of a `root/aa`, publishing newly created `aa/bb` shard
    /// directories. Issued once per *distinct* `root/aa` that gained a new
    /// shard in the batch, not once per new shard.
    DirFsyncFirstShard = 9,
    /// `open(O_CREAT|O_EXCL)` of the block's temp file.
    OpenTemp = 10,
    /// `write_all` of the block's bytes into the temp file. Bytes = block
    /// size, so this column is the only place real write bandwidth shows.
    WriteTemp = 11,
    /// `fsync` of the block's temp file.
    FsyncTemp = 12,
    /// `hard_link` publishing the synced inode onto its final path.
    LinkPublish = 13,
    /// `unlink` of the temp file after publication.
    UnlinkTemp = 14,
    /// `fsync` of a shard directory, once per *distinct* dirty shard per
    /// batch (`commit_batch`'s single post-batch pass).
    DirFsyncShard = 15,
    /// `check_headroom`: a free-space `statvfs` when headroom enforcement
    /// is on, a single relaxed atomic load when it is off (the default).
    HeadroomCheck = 16,
}

const OP_COUNT: usize = 18;

const OP_NAMES: [&str; OP_COUNT] = [
    "submit",
    "submit_blocked",
    "committer_idle",
    "commit_batch",
    "stat_final",
    "dedup_read",
    "stat_shard",
    "mkdir_shard",
    "dir_fsync_root",
    "dir_fsync_first_shard",
    "open_temp",
    "write_temp",
    "fsync_temp",
    "link_publish",
    "unlink_temp",
    "dir_fsync_shard",
    "headroom_check",
    "finish_drain",
];

static ENABLED: AtomicBool = AtomicBool::new(false);
static CALLS: [AtomicU64; OP_COUNT] = [const { AtomicU64::new(0) }; OP_COUNT];
static NANOS: [AtomicU64; OP_COUNT] = [const { AtomicU64::new(0) }; OP_COUNT];
static BYTES: [AtomicU64; OP_COUNT] = [const { AtomicU64::new(0) }; OP_COUNT];

/// Whether recording is armed. A single relaxed load; this is the entire
/// cost of an instrumentation site in a production binary.
#[inline(always)]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Arms or disarms recording process-wide. Only examples and tests call
/// this.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Zeroes every counter. Call between measured runs.
pub fn reset() {
    for i in 0..OP_COUNT {
        CALLS[i].store(0, Ordering::Relaxed);
        NANOS[i].store(0, Ordering::Relaxed);
        BYTES[i].store(0, Ordering::Relaxed);
    }
}

/// Records one occurrence of `op`. Cheap enough to call unconditionally
/// once `enabled()` has already been checked.
#[inline]
pub fn record(op: Op, nanos: u64, bytes: u64) {
    let i = op as usize;
    CALLS[i].fetch_add(1, Ordering::Relaxed);
    NANOS[i].fetch_add(nanos, Ordering::Relaxed);
    BYTES[i].fetch_add(bytes, Ordering::Relaxed);
}

/// Runs `f`, timing it as `op` when recording is armed. When it is not,
/// this is `f()` plus one relaxed atomic load -- in particular no
/// `Instant::now()`, which is the only part with a cost worth avoiding on
/// a per-block path.
#[inline]
pub fn time<T>(op: Op, bytes: u64, f: impl FnOnce() -> T) -> T {
    if !enabled() {
        return f();
    }
    let start = Instant::now();
    let out = f();
    record(op, start.elapsed().as_nanos() as u64, bytes);
    out
}

/// One operation class's totals.
#[derive(Clone, Copy, Debug)]
pub struct OpStat {
    pub name: &'static str,
    pub calls: u64,
    pub nanos: u64,
    pub bytes: u64,
}

/// Reads every counter. Not atomic across ops -- take it while the
/// measured work is finished, not while it is running.
pub fn snapshot() -> Vec<OpStat> {
    (0..OP_COUNT)
        .map(|i| OpStat {
            name: OP_NAMES[i],
            calls: CALLS[i].load(Ordering::Relaxed),
            nanos: NANOS[i].load(Ordering::Relaxed),
            bytes: BYTES[i].load(Ordering::Relaxed),
        })
        .collect()
}

/// Reads a single counter.
pub fn stat(op: Op) -> OpStat {
    let i = op as usize;
    OpStat {
        name: OP_NAMES[i],
        calls: CALLS[i].load(Ordering::Relaxed),
        nanos: NANOS[i].load(Ordering::Relaxed),
        bytes: BYTES[i].load(Ordering::Relaxed),
    }
}
