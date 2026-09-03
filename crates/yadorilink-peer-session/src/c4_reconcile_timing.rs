//! TEMPORARY diagnostic (remove once the investigation it supports is
//! closed): aggregate wall-clock decomposition of `reconcile_group_paths`
//! and the C4-6 ordinary-batch path it drives.
//!
//! Pass 1 (module-level: `combined_heads`/`store_live_heads_for_path`
//! aggregates, `prepare_ordinary_projected_upsert`/`try_commit_ordinary_
//! batch` whole-call and sub-step aggregates) showed `ensure_blocks_
//! present` dominating a `wait_ready_first` 2,000-file run's clean 8/8
//! attempts (up to ~4.5s per block-presence-check call, for files that are
//! a few bytes each) -- but `ensure_blocks_present` itself bundles a local
//! presence/provenance preflight, per-block fetch/retry, hash/disk `store.
//! put`, and provenance/refusal SQLite writes into one span, so that alone
//! does not say which of those actually dominates. Pass 2 (this file's
//! current form) breaks `ensure_blocks_present` itself down into those
//! named stages so the real answer can be read off directly, per the
//! candidate causes:
//!   - wire request/reply latency (`fetch_block_raw`) -> block-serving/
//!     transport scheduling
//!   - `Busy` retry sleep -> `BlockServeEngine` admission/credits
//!   - `store.put` (CAS write, fsync-included) -> CAS/fsync behavior
//!   - `record_group_block_provenance`/`clear_block_fetch_refusal` (both
//!     execute inside the SAME `spawn_blocking` closure in the real code --
//!     timed individually here to tell them apart) -> writer_gate/
//!     transaction shape
//!   - preflight (`present_blocks`/`group_has_block_provenance_batch`/
//!     current-version metadata reads) -> SQLite read amplification
//!
//! Every aggregate here is a GLOBAL atomic, not attributed to one
//! `reconcile_group_paths` call -- `report_reconcile_group_paths_span`
//! (called once per `reconcile_group_paths` invocation, gated the same
//! `>1s` way the outer span already was) snapshots every aggregate
//! immediately before and after that one call and logs the DELTA. This is
//! NOT exact when another `reconcile_group_paths` call (e.g. the windowed
//! reprojection backstop) overlaps the same window -- confirmed happening
//! in Pass 1's own data (`prepare_total_ms` summed to >100% of `outer_ms`
//! across samples) -- so absolute percentages against a noisy global sum
//! are not trustworthy. The clean signal is a window where `path_count ==
//! ensure_blocks_present_count == 8` (or whatever this attempt's own path
//! count is): every block-preflight/fetch/store/provenance call in that
//! delta is then attributable to exactly this attempt's own 8 paths, not a
//! sibling caller's.
//!
//! Mirrors this crate's own `c4_diag` module shape (global atomics,
//! `reset`/`stats`, no per-call-site attribution).

use std::sync::atomic::{AtomicU64, Ordering};

/// Plain count/cumulative-time/max-time aggregate for one named span,
/// stored in nanoseconds so both millisecond (outer spans) and
/// microsecond (fine-grained inner stages) views can be read from the same
/// counter without losing precision either way.
struct TimingAgg {
    count: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
}

impl TimingAgg {
    const fn new() -> Self {
        Self { count: AtomicU64::new(0), total_ns: AtomicU64::new(0), max_ns: AtomicU64::new(0) }
    }

    fn record(&self, elapsed: std::time::Duration) {
        let ns = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_ns.fetch_add(ns, Ordering::Relaxed);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        self.total_ns.store(0, Ordering::Relaxed);
        self.max_ns.store(0, Ordering::Relaxed);
    }

    fn snapshot(&self) -> TimingSnapshot {
        let ns_total = self.total_ns.load(Ordering::Relaxed);
        let ns_max = self.max_ns.load(Ordering::Relaxed);
        TimingSnapshot {
            count: self.count.load(Ordering::Relaxed),
            total_ms: ns_total / 1_000_000,
            max_ms: ns_max / 1_000_000,
            total_us: ns_total / 1_000,
            max_us: ns_max / 1_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TimingSnapshot {
    pub count: u64,
    pub total_ms: u64,
    pub max_ms: u64,
    pub total_us: u64,
    pub max_us: u64,
}

impl TimingSnapshot {
    fn saturating_sub(self, earlier: TimingSnapshot) -> TimingSnapshot {
        TimingSnapshot {
            count: self.count.saturating_sub(earlier.count),
            total_ms: self.total_ms.saturating_sub(earlier.total_ms),
            total_us: self.total_us.saturating_sub(earlier.total_us),
            // max is a running max, not cumulative -- not meaningfully
            // diffable, so the delta view just carries the CURRENT max
            // (over the whole run, not just this call). See this module's
            // own doc comment.
            max_ms: self.max_ms,
            max_us: self.max_us,
        }
    }
}

// --- DAG resolution -----------------------------------------------------
static COMBINED_HEADS: TimingAgg = TimingAgg::new();
static STORE_LIVE_HEADS: TimingAgg = TimingAgg::new();

// --- prepare_ordinary_projected_upsert -----------------------------------
static PREPARE_TOTAL: TimingAgg = TimingAgg::new();
static ENSURE_BLOCKS_PRESENT: TimingAgg = TimingAgg::new();
static RECONSTRUCT_TEMP: TimingAgg = TimingAgg::new();

// --- ensure_blocks_present preflight (Pass 2) ----------------------------
static PREFLIGHT_PRESENT_BLOCKS: TimingAgg = TimingAgg::new();
static PREFLIGHT_PROVENANCE_BATCH: TimingAgg = TimingAgg::new();
static PREFLIGHT_METADATA_READS: TimingAgg = TimingAgg::new();

// --- fetch_and_store_one_block (Pass 2) ----------------------------------
static FETCH_AND_STORE_ONE_BLOCK: TimingAgg = TimingAgg::new();
static FETCH_BLOCK_RAW: TimingAgg = TimingAgg::new();
static NOT_FOUND_RETRY_SLEEP: TimingAgg = TimingAgg::new();
static BUSY_RETRY_SLEEP: TimingAgg = TimingAgg::new();
static BLOCK_VERIFY: TimingAgg = TimingAgg::new();
static STORE_PUT: TimingAgg = TimingAgg::new();
static PROVENANCE_WRITE: TimingAgg = TimingAgg::new();
static REFUSAL_CLEAR_WRITE: TimingAgg = TimingAgg::new();

static BLOCKS_TOTAL: AtomicU64 = AtomicU64::new(0);
static BLOCKS_ALREADY_LOCAL: AtomicU64 = AtomicU64::new(0);
static BLOCKS_FETCHED: AtomicU64 = AtomicU64::new(0);
static FETCH_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static OUTCOME_FOUND: AtomicU64 = AtomicU64::new(0);
static OUTCOME_NOT_FOUND: AtomicU64 = AtomicU64::new(0);
static OUTCOME_TIMED_OUT: AtomicU64 = AtomicU64::new(0);
static OUTCOME_BUSY: AtomicU64 = AtomicU64::new(0);
static OUTCOME_REJECTED: AtomicU64 = AtomicU64::new(0);
static OUTCOME_UNUSABLE: AtomicU64 = AtomicU64::new(0);

// --- try_commit_ordinary_batch -------------------------------------------
static COMMIT_TOTAL: TimingAgg = TimingAgg::new();
static PATH_LOCK_WAIT: TimingAgg = TimingAgg::new();
static CANDIDATE_REVALIDATION: TimingAgg = TimingAgg::new();
static OPEN_PROJECTED_UPSERTS_BATCH: TimingAgg = TimingAgg::new();
static PERSIST_RECONSTRUCTED_FILE: TimingAgg = TimingAgg::new();
static METADATA_FS_FINISH: TimingAgg = TimingAgg::new();
static FINALIZE_PROJECTED_MUTATIONS_BATCH: TimingAgg = TimingAgg::new();

pub fn reset() {
    COMBINED_HEADS.reset();
    STORE_LIVE_HEADS.reset();
    PREPARE_TOTAL.reset();
    ENSURE_BLOCKS_PRESENT.reset();
    RECONSTRUCT_TEMP.reset();
    PREFLIGHT_PRESENT_BLOCKS.reset();
    PREFLIGHT_PROVENANCE_BATCH.reset();
    PREFLIGHT_METADATA_READS.reset();
    FETCH_AND_STORE_ONE_BLOCK.reset();
    FETCH_BLOCK_RAW.reset();
    NOT_FOUND_RETRY_SLEEP.reset();
    BUSY_RETRY_SLEEP.reset();
    BLOCK_VERIFY.reset();
    STORE_PUT.reset();
    PROVENANCE_WRITE.reset();
    REFUSAL_CLEAR_WRITE.reset();
    BLOCKS_TOTAL.store(0, Ordering::Relaxed);
    BLOCKS_ALREADY_LOCAL.store(0, Ordering::Relaxed);
    BLOCKS_FETCHED.store(0, Ordering::Relaxed);
    FETCH_ATTEMPTS.store(0, Ordering::Relaxed);
    OUTCOME_FOUND.store(0, Ordering::Relaxed);
    OUTCOME_NOT_FOUND.store(0, Ordering::Relaxed);
    OUTCOME_TIMED_OUT.store(0, Ordering::Relaxed);
    OUTCOME_BUSY.store(0, Ordering::Relaxed);
    OUTCOME_REJECTED.store(0, Ordering::Relaxed);
    OUTCOME_UNUSABLE.store(0, Ordering::Relaxed);
    COMMIT_TOTAL.reset();
    PATH_LOCK_WAIT.reset();
    CANDIDATE_REVALIDATION.reset();
    OPEN_PROJECTED_UPSERTS_BATCH.reset();
    PERSIST_RECONSTRUCTED_FILE.reset();
    METADATA_FS_FINISH.reset();
    FINALIZE_PROJECTED_MUTATIONS_BATCH.reset();
}

pub fn record_combined_heads(elapsed: std::time::Duration) {
    COMBINED_HEADS.record(elapsed);
}
pub fn record_store_live_heads(elapsed: std::time::Duration) {
    STORE_LIVE_HEADS.record(elapsed);
}
pub fn record_prepare_total(elapsed: std::time::Duration) {
    PREPARE_TOTAL.record(elapsed);
}
pub fn record_ensure_blocks_present(elapsed: std::time::Duration) {
    ENSURE_BLOCKS_PRESENT.record(elapsed);
}
pub fn record_reconstruct_temp(elapsed: std::time::Duration) {
    RECONSTRUCT_TEMP.record(elapsed);
}
pub fn record_preflight_present_blocks(elapsed: std::time::Duration) {
    PREFLIGHT_PRESENT_BLOCKS.record(elapsed);
}
pub fn record_preflight_provenance_batch(elapsed: std::time::Duration) {
    PREFLIGHT_PROVENANCE_BATCH.record(elapsed);
}
pub fn record_preflight_metadata_reads(elapsed: std::time::Duration) {
    PREFLIGHT_METADATA_READS.record(elapsed);
}
pub fn record_fetch_and_store_one_block(elapsed: std::time::Duration) {
    FETCH_AND_STORE_ONE_BLOCK.record(elapsed);
}
pub fn record_fetch_block_raw(elapsed: std::time::Duration) {
    FETCH_BLOCK_RAW.record(elapsed);
}
pub fn record_not_found_retry_sleep(elapsed: std::time::Duration) {
    NOT_FOUND_RETRY_SLEEP.record(elapsed);
}
pub fn record_busy_retry_sleep(elapsed: std::time::Duration) {
    BUSY_RETRY_SLEEP.record(elapsed);
}
pub fn record_block_verify(elapsed: std::time::Duration) {
    BLOCK_VERIFY.record(elapsed);
}
pub fn record_store_put(elapsed: std::time::Duration) {
    STORE_PUT.record(elapsed);
}
pub fn record_provenance_write(elapsed: std::time::Duration) {
    PROVENANCE_WRITE.record(elapsed);
}
pub fn record_refusal_clear_write(elapsed: std::time::Duration) {
    REFUSAL_CLEAR_WRITE.record(elapsed);
}
pub fn record_commit_total(elapsed: std::time::Duration) {
    COMMIT_TOTAL.record(elapsed);
}
pub fn record_path_lock_wait(elapsed: std::time::Duration) {
    PATH_LOCK_WAIT.record(elapsed);
}
pub fn record_candidate_revalidation(elapsed: std::time::Duration) {
    CANDIDATE_REVALIDATION.record(elapsed);
}
pub fn record_open_projected_upserts_batch(elapsed: std::time::Duration) {
    OPEN_PROJECTED_UPSERTS_BATCH.record(elapsed);
}
pub fn record_persist_reconstructed_file(elapsed: std::time::Duration) {
    PERSIST_RECONSTRUCTED_FILE.record(elapsed);
}
pub fn record_metadata_fs_finish(elapsed: std::time::Duration) {
    METADATA_FS_FINISH.record(elapsed);
}
pub fn record_finalize_projected_mutations_batch(elapsed: std::time::Duration) {
    FINALIZE_PROJECTED_MUTATIONS_BATCH.record(elapsed);
}

pub fn record_blocks_total(n: usize) {
    BLOCKS_TOTAL.fetch_add(n as u64, Ordering::Relaxed);
}
pub fn record_blocks_already_local(n: usize) {
    BLOCKS_ALREADY_LOCAL.fetch_add(n as u64, Ordering::Relaxed);
}
pub fn record_block_fetched() {
    BLOCKS_FETCHED.fetch_add(1, Ordering::Relaxed);
}
pub fn record_fetch_attempt() {
    FETCH_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
}
/// `outcome` matches `FetchOutcome`'s own variant names (`Found`,
/// `NotFound`, `TimedOut`, `Busy`, `Rejected`, `Unusable`) so the call site
/// can pass `outcome.as_ref()`-style tagging without this module knowing
/// `FetchOutcome`'s type (avoids a dependency cycle/visibility issue --
/// `FetchOutcome` is private to `peer_session.rs`).
pub fn record_fetch_outcome(outcome: FetchOutcomeTag) {
    match outcome {
        FetchOutcomeTag::Found => OUTCOME_FOUND.fetch_add(1, Ordering::Relaxed),
        FetchOutcomeTag::NotFound => OUTCOME_NOT_FOUND.fetch_add(1, Ordering::Relaxed),
        FetchOutcomeTag::TimedOut => OUTCOME_TIMED_OUT.fetch_add(1, Ordering::Relaxed),
        FetchOutcomeTag::Busy => OUTCOME_BUSY.fetch_add(1, Ordering::Relaxed),
        FetchOutcomeTag::Rejected => OUTCOME_REJECTED.fetch_add(1, Ordering::Relaxed),
        FetchOutcomeTag::Unusable => OUTCOME_UNUSABLE.fetch_add(1, Ordering::Relaxed),
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOutcomeTag {
    Found,
    NotFound,
    TimedOut,
    Busy,
    Rejected,
    Unusable,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReconcileTimingStats {
    pub combined_heads: TimingSnapshot,
    pub store_live_heads: TimingSnapshot,
    pub prepare_total: TimingSnapshot,
    pub ensure_blocks_present: TimingSnapshot,
    pub reconstruct_temp: TimingSnapshot,
    pub preflight_present_blocks: TimingSnapshot,
    pub preflight_provenance_batch: TimingSnapshot,
    pub preflight_metadata_reads: TimingSnapshot,
    pub fetch_and_store_one_block: TimingSnapshot,
    pub fetch_block_raw: TimingSnapshot,
    pub not_found_retry_sleep: TimingSnapshot,
    pub busy_retry_sleep: TimingSnapshot,
    pub block_verify: TimingSnapshot,
    pub store_put: TimingSnapshot,
    pub provenance_write: TimingSnapshot,
    pub refusal_clear_write: TimingSnapshot,
    pub commit_total: TimingSnapshot,
    pub path_lock_wait: TimingSnapshot,
    pub candidate_revalidation: TimingSnapshot,
    pub open_projected_upserts_batch: TimingSnapshot,
    pub persist_reconstructed_file: TimingSnapshot,
    pub metadata_fs_finish: TimingSnapshot,
    pub finalize_projected_mutations_batch: TimingSnapshot,
    pub blocks_total: u64,
    pub blocks_already_local: u64,
    pub blocks_fetched: u64,
    pub fetch_attempts: u64,
    pub outcome_found: u64,
    pub outcome_not_found: u64,
    pub outcome_timed_out: u64,
    pub outcome_busy: u64,
    pub outcome_rejected: u64,
    pub outcome_unusable: u64,
}

pub fn stats() -> ReconcileTimingStats {
    ReconcileTimingStats {
        combined_heads: COMBINED_HEADS.snapshot(),
        store_live_heads: STORE_LIVE_HEADS.snapshot(),
        prepare_total: PREPARE_TOTAL.snapshot(),
        ensure_blocks_present: ENSURE_BLOCKS_PRESENT.snapshot(),
        reconstruct_temp: RECONSTRUCT_TEMP.snapshot(),
        preflight_present_blocks: PREFLIGHT_PRESENT_BLOCKS.snapshot(),
        preflight_provenance_batch: PREFLIGHT_PROVENANCE_BATCH.snapshot(),
        preflight_metadata_reads: PREFLIGHT_METADATA_READS.snapshot(),
        fetch_and_store_one_block: FETCH_AND_STORE_ONE_BLOCK.snapshot(),
        fetch_block_raw: FETCH_BLOCK_RAW.snapshot(),
        not_found_retry_sleep: NOT_FOUND_RETRY_SLEEP.snapshot(),
        busy_retry_sleep: BUSY_RETRY_SLEEP.snapshot(),
        block_verify: BLOCK_VERIFY.snapshot(),
        store_put: STORE_PUT.snapshot(),
        provenance_write: PROVENANCE_WRITE.snapshot(),
        refusal_clear_write: REFUSAL_CLEAR_WRITE.snapshot(),
        commit_total: COMMIT_TOTAL.snapshot(),
        path_lock_wait: PATH_LOCK_WAIT.snapshot(),
        candidate_revalidation: CANDIDATE_REVALIDATION.snapshot(),
        open_projected_upserts_batch: OPEN_PROJECTED_UPSERTS_BATCH.snapshot(),
        persist_reconstructed_file: PERSIST_RECONSTRUCTED_FILE.snapshot(),
        metadata_fs_finish: METADATA_FS_FINISH.snapshot(),
        finalize_projected_mutations_batch: FINALIZE_PROJECTED_MUTATIONS_BATCH.snapshot(),
        blocks_total: BLOCKS_TOTAL.load(Ordering::Relaxed),
        blocks_already_local: BLOCKS_ALREADY_LOCAL.load(Ordering::Relaxed),
        blocks_fetched: BLOCKS_FETCHED.load(Ordering::Relaxed),
        fetch_attempts: FETCH_ATTEMPTS.load(Ordering::Relaxed),
        outcome_found: OUTCOME_FOUND.load(Ordering::Relaxed),
        outcome_not_found: OUTCOME_NOT_FOUND.load(Ordering::Relaxed),
        outcome_timed_out: OUTCOME_TIMED_OUT.load(Ordering::Relaxed),
        outcome_busy: OUTCOME_BUSY.load(Ordering::Relaxed),
        outcome_rejected: OUTCOME_REJECTED.load(Ordering::Relaxed),
        outcome_unusable: OUTCOME_UNUSABLE.load(Ordering::Relaxed),
    }
}

fn sub_u64(after: u64, before: u64) -> u64 {
    after.saturating_sub(before)
}

/// Per-call decomposition for one `reconcile_group_paths` invocation --
/// call with the `stats()` snapshot taken before the call and the elapsed
/// time/attempt id/path counts, gated the same `>1s` way the pre-existing
/// outer span warning is. Logs named sub-totals against the outer elapsed
/// time so it is directly visible which component dominates. See this
/// module's own doc comment for the concurrent-call caveat on these
/// deltas, and for the "clean window" reading it recommends
/// (`ensure_blocks_present_count == path_count`).
#[allow(clippy::too_many_arguments)]
pub fn report_reconcile_group_paths_span(
    group_id: &str,
    audit_attempt_id: u64,
    outer_elapsed: std::time::Duration,
    path_count: usize,
    settled_count: usize,
    retry_count: usize,
    before: ReconcileTimingStats,
) {
    if outer_elapsed < std::time::Duration::from_secs(1) {
        return;
    }
    let after = stats();
    let d_combined_heads = after.combined_heads.saturating_sub(before.combined_heads);
    let d_store_live_heads = after.store_live_heads.saturating_sub(before.store_live_heads);
    let d_prepare_total = after.prepare_total.saturating_sub(before.prepare_total);
    let d_ensure_blocks_present =
        after.ensure_blocks_present.saturating_sub(before.ensure_blocks_present);
    let d_reconstruct_temp = after.reconstruct_temp.saturating_sub(before.reconstruct_temp);
    let d_preflight_present =
        after.preflight_present_blocks.saturating_sub(before.preflight_present_blocks);
    let d_preflight_provenance =
        after.preflight_provenance_batch.saturating_sub(before.preflight_provenance_batch);
    let d_preflight_metadata =
        after.preflight_metadata_reads.saturating_sub(before.preflight_metadata_reads);
    let d_fetch_and_store =
        after.fetch_and_store_one_block.saturating_sub(before.fetch_and_store_one_block);
    let d_fetch_block_raw = after.fetch_block_raw.saturating_sub(before.fetch_block_raw);
    let d_not_found_sleep =
        after.not_found_retry_sleep.saturating_sub(before.not_found_retry_sleep);
    let d_busy_sleep = after.busy_retry_sleep.saturating_sub(before.busy_retry_sleep);
    let d_block_verify = after.block_verify.saturating_sub(before.block_verify);
    let d_store_put = after.store_put.saturating_sub(before.store_put);
    let d_provenance_write = after.provenance_write.saturating_sub(before.provenance_write);
    let d_refusal_clear = after.refusal_clear_write.saturating_sub(before.refusal_clear_write);
    let d_commit_total = after.commit_total.saturating_sub(before.commit_total);
    let d_path_lock_wait = after.path_lock_wait.saturating_sub(before.path_lock_wait);
    let d_candidate_revalidation =
        after.candidate_revalidation.saturating_sub(before.candidate_revalidation);
    let d_open_batch =
        after.open_projected_upserts_batch.saturating_sub(before.open_projected_upserts_batch);
    let d_persist_file =
        after.persist_reconstructed_file.saturating_sub(before.persist_reconstructed_file);
    let d_metadata_fs = after.metadata_fs_finish.saturating_sub(before.metadata_fs_finish);
    let d_finalize = after
        .finalize_projected_mutations_batch
        .saturating_sub(before.finalize_projected_mutations_batch);

    let d_blocks_total = sub_u64(after.blocks_total, before.blocks_total);
    let d_blocks_already_local = sub_u64(after.blocks_already_local, before.blocks_already_local);
    let d_blocks_fetched = sub_u64(after.blocks_fetched, before.blocks_fetched);
    let d_fetch_attempts = sub_u64(after.fetch_attempts, before.fetch_attempts);
    let d_outcome_found = sub_u64(after.outcome_found, before.outcome_found);
    let d_outcome_not_found = sub_u64(after.outcome_not_found, before.outcome_not_found);
    let d_outcome_timed_out = sub_u64(after.outcome_timed_out, before.outcome_timed_out);
    let d_outcome_busy = sub_u64(after.outcome_busy, before.outcome_busy);
    let d_outcome_rejected = sub_u64(after.outcome_rejected, before.outcome_rejected);
    let d_outcome_unusable = sub_u64(after.outcome_unusable, before.outcome_unusable);

    let dag_resolution_ms = d_combined_heads.total_ms;
    let prepare_ms = d_prepare_total.total_ms;
    let commit_ms = d_commit_total.total_ms;
    let outer_ms = outer_elapsed.as_millis() as u64;
    let attributed_ms = dag_resolution_ms + prepare_ms + commit_ms;
    let unattributed_residual_ms = outer_ms.saturating_sub(attributed_ms);
    // A clean window: every block-level call in this delta is attributable
    // to exactly this attempt's own paths, not a sibling caller's -- see
    // this module's own doc comment.
    let clean_window = d_ensure_blocks_present.count as usize == path_count;

    tracing::warn!(
        group_id,
        audit_attempt_id,
        path_count,
        settled_count,
        retry_count,
        clean_window,
        outer_ms,
        dag_resolution_ms,
        dag_resolution_count = d_combined_heads.count,
        dag_resolution_max_ms = d_combined_heads.max_ms,
        store_live_heads_ms = d_store_live_heads.total_ms,
        store_live_heads_count = d_store_live_heads.count,
        prepare_total_ms = prepare_ms,
        prepare_total_count = d_prepare_total.count,
        ensure_blocks_present_ms = d_ensure_blocks_present.total_ms,
        ensure_blocks_present_count = d_ensure_blocks_present.count,
        ensure_blocks_present_max_ms = d_ensure_blocks_present.max_ms,
        reconstruct_temp_ms = d_reconstruct_temp.total_ms,
        reconstruct_temp_count = d_reconstruct_temp.count,
        // Pass 2: ensure_blocks_present's own internal decomposition.
        preflight_present_blocks_us = d_preflight_present.total_us,
        preflight_present_blocks_count = d_preflight_present.count,
        preflight_provenance_batch_us = d_preflight_provenance.total_us,
        preflight_provenance_batch_count = d_preflight_provenance.count,
        preflight_metadata_reads_us = d_preflight_metadata.total_us,
        preflight_metadata_reads_count = d_preflight_metadata.count,
        fetch_and_store_one_block_ms = d_fetch_and_store.total_ms,
        fetch_and_store_one_block_count = d_fetch_and_store.count,
        fetch_and_store_one_block_max_ms = d_fetch_and_store.max_ms,
        fetch_block_raw_ms = d_fetch_block_raw.total_ms,
        fetch_block_raw_count = d_fetch_block_raw.count,
        fetch_block_raw_max_ms = d_fetch_block_raw.max_ms,
        not_found_retry_sleep_ms = d_not_found_sleep.total_ms,
        not_found_retry_sleep_count = d_not_found_sleep.count,
        busy_retry_sleep_ms = d_busy_sleep.total_ms,
        busy_retry_sleep_count = d_busy_sleep.count,
        block_verify_us = d_block_verify.total_us,
        block_verify_count = d_block_verify.count,
        store_put_us = d_store_put.total_us,
        store_put_count = d_store_put.count,
        store_put_max_us = d_store_put.max_us,
        provenance_write_us = d_provenance_write.total_us,
        provenance_write_count = d_provenance_write.count,
        provenance_write_max_us = d_provenance_write.max_us,
        refusal_clear_write_us = d_refusal_clear.total_us,
        refusal_clear_write_count = d_refusal_clear.count,
        blocks_total = d_blocks_total,
        blocks_already_local = d_blocks_already_local,
        blocks_fetched = d_blocks_fetched,
        fetch_attempts = d_fetch_attempts,
        attempts_per_fetched_block = if d_blocks_fetched > 0 {
            d_fetch_attempts as f64 / d_blocks_fetched as f64
        } else {
            0.0
        },
        outcome_found = d_outcome_found,
        outcome_not_found = d_outcome_not_found,
        outcome_timed_out = d_outcome_timed_out,
        outcome_busy = d_outcome_busy,
        outcome_rejected = d_outcome_rejected,
        outcome_unusable = d_outcome_unusable,
        commit_total_ms = commit_ms,
        commit_total_count = d_commit_total.count,
        path_lock_wait_ms = d_path_lock_wait.total_ms,
        path_lock_wait_count = d_path_lock_wait.count,
        candidate_revalidation_ms = d_candidate_revalidation.total_ms,
        candidate_revalidation_count = d_candidate_revalidation.count,
        open_projected_upserts_batch_ms = d_open_batch.total_ms,
        persist_reconstructed_file_ms = d_persist_file.total_ms,
        persist_reconstructed_file_count = d_persist_file.count,
        metadata_fs_finish_ms = d_metadata_fs.total_ms,
        metadata_fs_finish_count = d_metadata_fs.count,
        finalize_projected_mutations_batch_ms = d_finalize.total_ms,
        unattributed_residual_ms,
        "C4_DIAG reconcile_group_paths timing decomposition"
    );
}
