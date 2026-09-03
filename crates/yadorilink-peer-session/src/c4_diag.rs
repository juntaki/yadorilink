//! Temporary diagnostic counters (remove once the investigation they
//! support is closed): plain counts and a `want_len` size distribution for
//! anti-entropy protocol traffic (`HeadsAnnounce` received, `ChangeRequest`
//! sent, `ChangeBatch` received, and how each received change classified —
//! new / already-known / orphaned — plus how many orphans a single
//! admission promoted). This does NOT track individual requests' identity,
//! fingerprints, or in-flight state, so it cannot by itself distinguish
//! "the same want is being re-requested while an earlier request for it is
//! still outstanding" from any other source of a high `change_requests_
//! sent` count or a high already-known ratio — those are read from
//! `changes_already_known`/`changes_new` alongside `request_want_len`, not
//! detected directly. Mirrors `yadorilink-sqlite-runtime`'s own
//! diagnostic-counter module shape (global atomics, `reset`/`stats`, no
//! per-call-site attribution since these are fixed call sites).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

static HEADS_ANNOUNCE_RECEIVED: AtomicU64 = AtomicU64::new(0);
static CHANGE_REQUESTS_SENT: AtomicU64 = AtomicU64::new(0);
static CHANGE_BATCHES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static CHANGES_RECEIVED_TOTAL: AtomicU64 = AtomicU64::new(0);
static CHANGES_NEW: AtomicU64 = AtomicU64::new(0);
static CHANGES_ALREADY_KNOWN: AtomicU64 = AtomicU64::new(0);
static CHANGES_ORPHANED: AtomicU64 = AtomicU64::new(0);
static PROMOTED_ORPHANS: AtomicU64 = AtomicU64::new(0);

// TEMPORARY (block-not-found root-cause investigation, remove once closed):
// the requester-side "peer reported block as not_found after retrying" log
// collapses at least two structurally different source-side outcomes into
// the same wire `DontHave` -- `BlockRequestCheckOutcome::NotReferenced`
// (the source's own record/DAG/retained-version lookup found no reference
// to this hash at all) and `CoalesceFailure::ReadFailed` (the hash IS
// referenced and provenance-verified, but the local content-store read
// itself failed). These counters, plus the two one-shot diagnostic dumps
// below, exist purely to tell those two apart without guessing from the
// requester's own log alone.
static DONT_HAVE_NOT_REFERENCED: AtomicU64 = AtomicU64::new(0);
static DONT_HAVE_STORE_READ_FAILED: AtomicU64 = AtomicU64::new(0);
static REJECTED_NO_PROVENANCE: AtomicU64 = AtomicU64::new(0);

/// TEMPORARY: fires exactly once per process, on the first
/// `BlockRequestCheckOutcome::NotReferenced` this device ever answers --
/// the call site uses this to gate a one-shot source-side diagnostic dump
/// (live record / DAG reference / retained-version reference / provenance /
/// content-store read, for that exact `(group_id, path, hash)`) rather than
/// dumping on every occurrence.
static NOT_REFERENCED_DUMPED: AtomicBool = AtomicBool::new(false);
/// TEMPORARY: same one-shot gate as `NOT_REFERENCED_DUMPED`, for the first
/// `CoalesceFailure::ReadFailed` this device ever hits.
static READ_FAILED_DUMPED: AtomicBool = AtomicBool::new(false);
/// TEMPORARY: same one-shot gate, for the first requester-side retry-
/// exhausted "not_found after retrying" this device ever hits -- gates a
/// dump of the REQUESTER's own view of that `(group_id, path, hash)`
/// (current record / authoring change / projection obligation /
/// materialization state).
static RETRY_EXHAUSTED_DUMPED: AtomicBool = AtomicBool::new(false);
/// TEMPORARY: bounds how many `ReadFailed` error strings get logged in
/// full (the error is otherwise discarded at the call site) -- enough to
/// see whether it's one recurring cause or several, without flooding a
/// long run's log.
const MAX_READ_FAILED_ERRORS_LOGGED: u64 = 5;

/// Bounded ring buffer of the most recent `want_len` values, so a
/// long-running process (this is production-path instrumentation, not
/// test-only) cannot grow this without limit. `stats()`'s percentiles are
/// therefore over the most recent `WANT_LEN_RING_CAPACITY` requests, not
/// the whole run since the last `reset()` -- adequate for this
/// investigation's own 30s-cadence snapshots, where recent behavior is
/// exactly what matters.
const WANT_LEN_RING_CAPACITY: usize = 4096;

struct WantLenRing {
    buf: Vec<usize>,
    next: usize,
    total_pushes: u64,
}

fn want_len_ring() -> &'static Mutex<WantLenRing> {
    static RING: std::sync::OnceLock<Mutex<WantLenRing>> = std::sync::OnceLock::new();
    RING.get_or_init(|| Mutex::new(WantLenRing { buf: Vec::new(), next: 0, total_pushes: 0 }))
}

pub fn reset() {
    HEADS_ANNOUNCE_RECEIVED.store(0, Ordering::Relaxed);
    CHANGE_REQUESTS_SENT.store(0, Ordering::Relaxed);
    CHANGE_BATCHES_RECEIVED.store(0, Ordering::Relaxed);
    CHANGES_RECEIVED_TOTAL.store(0, Ordering::Relaxed);
    CHANGES_NEW.store(0, Ordering::Relaxed);
    CHANGES_ALREADY_KNOWN.store(0, Ordering::Relaxed);
    CHANGES_ORPHANED.store(0, Ordering::Relaxed);
    PROMOTED_ORPHANS.store(0, Ordering::Relaxed);
    DONT_HAVE_NOT_REFERENCED.store(0, Ordering::Relaxed);
    DONT_HAVE_STORE_READ_FAILED.store(0, Ordering::Relaxed);
    REJECTED_NO_PROVENANCE.store(0, Ordering::Relaxed);
    NOT_REFERENCED_DUMPED.store(false, Ordering::Relaxed);
    READ_FAILED_DUMPED.store(false, Ordering::Relaxed);
    RETRY_EXHAUSTED_DUMPED.store(false, Ordering::Relaxed);
    let mut ring = want_len_ring().lock().unwrap_or_else(|p| p.into_inner());
    ring.buf.clear();
    ring.next = 0;
    ring.total_pushes = 0;
}

/// TEMPORARY: records one `BlockRequestCheckOutcome::NotReferenced`
/// answer. Returns `true` exactly once (the first call after the last
/// `reset()`) -- the call site dumps its one-shot source-side diagnostic
/// only when this returns `true`.
pub fn record_dont_have_not_referenced() -> bool {
    DONT_HAVE_NOT_REFERENCED.fetch_add(1, Ordering::Relaxed);
    NOT_REFERENCED_DUMPED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// TEMPORARY: records one `CoalesceFailure::ReadFailed` answer. Returns
/// `true` exactly once (the first call after the last `reset()`) -- the
/// call site dumps its one-shot source-side diagnostic only when this
/// returns `true`.
pub fn record_dont_have_store_read_failed() -> bool {
    DONT_HAVE_STORE_READ_FAILED.fetch_add(1, Ordering::Relaxed);
    READ_FAILED_DUMPED.compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed).is_ok()
}

/// TEMPORARY: whether the call site should still log this `ReadFailed`
/// error's own message in full -- bounded to the first
/// `MAX_READ_FAILED_ERRORS_LOGGED` occurrences so a long run's log isn't
/// flooded once the cause (if recurring) is already established.
pub fn should_log_read_failed_error() -> bool {
    DONT_HAVE_STORE_READ_FAILED.load(Ordering::Relaxed) <= MAX_READ_FAILED_ERRORS_LOGGED
}

pub fn record_rejected_no_provenance() {
    REJECTED_NO_PROVENANCE.fetch_add(1, Ordering::Relaxed);
}

/// TEMPORARY: records one requester-side retry-exhausted "not_found after
/// retrying" event. Returns `true` exactly once -- the call site dumps its
/// one-shot requester-side diagnostic only when this returns `true`.
pub fn record_retry_exhausted() -> bool {
    RETRY_EXHAUSTED_DUMPED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

pub fn record_heads_announce_received() {
    HEADS_ANNOUNCE_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

/// One `ChangeRequest` frame actually sent, carrying `want_len` hashes
/// (post-chunking -- one call per wire message, not per logical
/// `request_changes` invocation, so a caller whose `want` exceeded the
/// chunk size is correctly counted as multiple requests).
pub fn record_change_request_sent(want_len: usize) {
    CHANGE_REQUESTS_SENT.fetch_add(1, Ordering::Relaxed);
    let mut ring = want_len_ring().lock().unwrap_or_else(|p| p.into_inner());
    ring.total_pushes += 1;
    if ring.buf.len() < WANT_LEN_RING_CAPACITY {
        ring.buf.push(want_len);
    } else {
        let idx = ring.next;
        ring.buf[idx] = want_len;
    }
    ring.next = (ring.next + 1) % WANT_LEN_RING_CAPACITY;
}

pub fn record_change_batch_received(changes_len: usize) {
    CHANGE_BATCHES_RECEIVED.fetch_add(1, Ordering::Relaxed);
    CHANGES_RECEIVED_TOTAL.fetch_add(changes_len as u64, Ordering::Relaxed);
}

pub fn record_change_new() {
    CHANGES_NEW.fetch_add(1, Ordering::Relaxed);
}

pub fn record_change_already_known() {
    CHANGES_ALREADY_KNOWN.fetch_add(1, Ordering::Relaxed);
}

pub fn record_change_orphaned() {
    CHANGES_ORPHANED.fetch_add(1, Ordering::Relaxed);
}

/// `n` orphans promoted as a side effect of one admission (0 for an
/// ordinary admission with nothing waiting on it).
pub fn record_promoted_orphans(n: usize) {
    if n > 0 {
        PROMOTED_ORPHANS.fetch_add(n as u64, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WantLenStats {
    pub count: usize,
    pub mean: f64,
    pub p50: usize,
    pub p95: usize,
    pub max: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProtocolStats {
    pub heads_announce_received: u64,
    pub change_requests_sent: u64,
    pub change_batches_received: u64,
    pub changes_received_total: u64,
    pub changes_new: u64,
    pub changes_already_known: u64,
    pub changes_orphaned: u64,
    pub promoted_orphans: u64,
    pub want_len: WantLenStats,
    /// TEMPORARY (block-not-found root-cause investigation): see this
    /// module's own doc comment on the three counters these mirror.
    pub dont_have_not_referenced: u64,
    pub dont_have_store_read_failed: u64,
    pub rejected_no_provenance: u64,
}

pub fn stats() -> ProtocolStats {
    let ring = want_len_ring().lock().unwrap_or_else(|p| p.into_inner());
    let mut sorted: Vec<usize> = ring.buf.clone();
    sorted.sort_unstable();
    let count = sorted.len();
    let percentile = |p: f64| -> usize {
        if count == 0 {
            0
        } else {
            sorted[(((count - 1) as f64) * p).round() as usize]
        }
    };
    let want_len = WantLenStats {
        count,
        mean: if count > 0 { sorted.iter().sum::<usize>() as f64 / count as f64 } else { 0.0 },
        p50: percentile(0.50),
        p95: percentile(0.95),
        max: sorted.last().copied().unwrap_or(0),
    };
    ProtocolStats {
        heads_announce_received: HEADS_ANNOUNCE_RECEIVED.load(Ordering::Relaxed),
        change_requests_sent: CHANGE_REQUESTS_SENT.load(Ordering::Relaxed),
        change_batches_received: CHANGE_BATCHES_RECEIVED.load(Ordering::Relaxed),
        changes_received_total: CHANGES_RECEIVED_TOTAL.load(Ordering::Relaxed),
        changes_new: CHANGES_NEW.load(Ordering::Relaxed),
        changes_already_known: CHANGES_ALREADY_KNOWN.load(Ordering::Relaxed),
        changes_orphaned: CHANGES_ORPHANED.load(Ordering::Relaxed),
        promoted_orphans: PROMOTED_ORPHANS.load(Ordering::Relaxed),
        want_len,
        dont_have_not_referenced: DONT_HAVE_NOT_REFERENCED.load(Ordering::Relaxed),
        dont_have_store_read_failed: DONT_HAVE_STORE_READ_FAILED.load(Ordering::Relaxed),
        rejected_no_provenance: REJECTED_NO_PROVENANCE.load(Ordering::Relaxed),
    }
}
