//! TEMPORARY diagnostic (remove once the investigation it supports is
//! closed): attribution pass, Pass 3, for the C4 block-not-found/stall
//! investigation. `c4_reconcile_timing`'s Pass 1/2 aggregates are GLOBAL
//! atomics diffed before/after one `reconcile_group_paths` call
//! (`report_reconcile_group_paths_span`) -- that module's own doc comment
//! already flags the resulting ambiguity when calls overlap, and a real
//! run produced exactly that: `audit_attempt_id=460` was reported multiple
//! times with wildly different `outer_ms` (67683, 41561, 153410, then
//! back down to ~4000) because the SAME attempt id kept getting a fresh
//! before/after diff against whatever the global counters had accumulated
//! by the time each `>1s` gate re-fired, not because that one call
//! actually ran for 150+ seconds. This module replaces that mechanism for
//! `reconcile_group_paths` with per-invocation LOCAL timing:
//! [`ReconcileCallTimer`] is constructed once per call and threaded by
//! `&`/`Option<&>` reference through every function that call touches
//! (exactly like `peer_session::ReconcileProvenanceBatch` already is), so
//! every number it reports is provably scoped to THIS call, never a
//! sibling's. Its internals are still atomics -- not because state is
//! shared across calls, but because concurrent per-path/per-block work
//! WITHIN one call (`FuturesUnordered` block fetches, `spawn_blocking`
//! store/SQLite work) can run on different executor threads.
//!
//! Also carries the responder-side per-`BlockRequest` breakdown and the
//! requester-observed-RTT reporting the same follow-up asked for --
//! grouped here rather than in a third module since both halves exist for
//! the same short attribution pass and share the same lifecycle.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn ns(d: Duration) -> u64 {
    d.as_nanos().min(u64::MAX as u128) as u64
}

fn ms_of(nanos: u64) -> u64 {
    nanos / 1_000_000
}

static NEXT_RECONCILE_ID: AtomicU64 = AtomicU64::new(0);
static NEXT_RESPONDER_REQUEST_ID: AtomicU64 = AtomicU64::new(0);

/// Process-local, not wire-visible -- `BlockRequestHeaderFrame` carries no
/// correlation id ("the stream is the correlation", see its own doc
/// comment) and this pass was told not to add one to the wire protocol
/// solely for diagnostics. Useful only to tell apart two log lines from
/// the SAME responder process; correlating a responder-side line with the
/// requester-side line for the same logical request is done post hoc, by
/// `(group_id, hash_prefix, timestamp proximity)` -- both sides log both.
pub fn next_responder_request_id() -> u64 {
    NEXT_RESPONDER_REQUEST_ID.fetch_add(1, Ordering::Relaxed) + 1
}

/// Per-invocation, call-local timing for one `reconcile_group_paths` call
/// (and the `try_commit_ordinary_batch`/`prepare_ordinary_projected_upsert`
/// work it drives). See this module's own doc comment for why this
/// replaces `c4_reconcile_timing::report_reconcile_group_paths_span` for
/// this one call site.
pub struct ReconcileCallTimer {
    reconcile_id: u64,
    dag_resolution_ns: AtomicU64,
    ensure_blocks_present_ns: AtomicU64,
    provenance_flush_ns: AtomicU64,
    /// Writer-gate wait vs. actual SQLite transaction/fsync time, summed
    /// across every SQLite write this call's commit path made (provenance
    /// flush, `open_projected_upserts_batch`, `finalize_projected_
    /// mutations_batch`) -- see `add_sqlite_write`'s own doc comment for
    /// how the split is derived.
    writer_gate_wait_ns: AtomicU64,
    sqlite_transaction_ns: AtomicU64,
    ordinary_commit_ns: AtomicU64,
    blocks_fetched: AtomicU64,
    block_fetch_wait_ns: AtomicU64,
    store_put_ns: AtomicU64,
    /// Bumped once, by `finish`, when `outer_ms` clears the attribution
    /// run's own "unusually slow" bar -- read by the driving test to
    /// decide when to stop early (see the diagnostic run's own stop
    /// condition: 3 such calls, or a wall-clock cap).
    slow: AtomicU64,
}

/// Matches the attribution run's own stop condition ("3 reconcile calls
/// with outer_ms > 5000"), so the same constant governs both the log-level
/// classification below and the driving test's external stop check.
pub const SLOW_RECONCILE_THRESHOLD_MS: u64 = 5000;

static SLOW_RECONCILE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Total `ReconcileCallTimer::finish` calls whose `outer_ms` exceeded
/// [`SLOW_RECONCILE_THRESHOLD_MS`], since process start. The attribution
/// run's driver polls this (via the log it produces, or this accessor if
/// called in-process) to know when to stop.
pub fn slow_reconcile_count() -> u64 {
    SLOW_RECONCILE_COUNT.load(Ordering::Relaxed)
}

impl ReconcileCallTimer {
    pub fn new() -> Self {
        Self {
            reconcile_id: NEXT_RECONCILE_ID.fetch_add(1, Ordering::Relaxed) + 1,
            dag_resolution_ns: AtomicU64::new(0),
            ensure_blocks_present_ns: AtomicU64::new(0),
            provenance_flush_ns: AtomicU64::new(0),
            writer_gate_wait_ns: AtomicU64::new(0),
            sqlite_transaction_ns: AtomicU64::new(0),
            ordinary_commit_ns: AtomicU64::new(0),
            blocks_fetched: AtomicU64::new(0),
            block_fetch_wait_ns: AtomicU64::new(0),
            store_put_ns: AtomicU64::new(0),
            slow: AtomicU64::new(0),
        }
    }

    pub fn reconcile_id(&self) -> u64 {
        self.reconcile_id
    }

    pub fn add_dag_resolution(&self, elapsed: Duration) {
        self.dag_resolution_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    pub fn add_ensure_blocks_present(&self, elapsed: Duration) {
        self.ensure_blocks_present_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    pub fn add_provenance_flush(&self, elapsed: Duration) {
        self.provenance_flush_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    fn add_writer_gate_wait(&self, elapsed: Duration) {
        self.writer_gate_wait_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    fn add_sqlite_transaction(&self, elapsed: Duration) {
        self.sqlite_transaction_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    /// Records the writer_gate wait/hold split for ONE SQLite write this
    /// call made, from a narrow before/after diff of `yadorilink_sqlite_
    /// runtime::c4_diag`'s own (process-wide, but here narrowly windowed
    /// around exactly one write, not this whole `reconcile_group_paths`
    /// call) gate-acquisition wait counter -- see the call site's own
    /// comment for why this narrow a window is trustworthy where the old
    /// whole-call-span diff was not: `total_elapsed` is this call's own
    /// wrap around exactly one `write`/`write_immediate`, and `gate_wait`
    /// is that SAME window's own delta of the global wait-time counter, so
    /// nothing from a sibling call's writer_gate wait can leak in unless
    /// another writer's wait genuinely straddles this narrow window --
    /// far less likely than straddling a whole multi-file reconcile call.
    /// `sqlite_transaction_ms` is then simply what is left: actual
    /// transaction/fsync work, never spent waiting for the gate.
    pub fn add_sqlite_write(&self, total_elapsed: Duration, gate_wait: Duration) {
        let sqlite_txn = total_elapsed.saturating_sub(gate_wait);
        self.add_writer_gate_wait(gate_wait);
        self.add_sqlite_transaction(sqlite_txn);
    }
    pub fn add_ordinary_commit(&self, elapsed: Duration) {
        self.ordinary_commit_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    /// `elapsed` is the requester-observed `fetch_block_raw` round trip for
    /// ONE ATTEMPT at fetching a block (wire wait, from just before the
    /// request goes out to the response arriving) -- see `fetch_block_raw`'s
    /// own doc comment. Called on every attempt, including a block that
    /// needed a `NotFound`/`Busy` retry before succeeding, so this
    /// legitimately sums to more than `blocks_fetched * one RTT` for a
    /// call with any retries -- does NOT bump `blocks_fetched` itself, see
    /// [`Self::add_block_fetched`] for that (recorded once, at the block's
    /// own eventual success, not once per attempt).
    pub fn add_block_fetch_wait(&self, elapsed: Duration) {
        self.block_fetch_wait_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    /// One block newly fetched and durably `store.put` by this call --
    /// call exactly once per block, at its success, not once per attempt
    /// (see [`Self::add_block_fetch_wait`] for the attempt-scoped wire-wait
    /// sum).
    pub fn add_block_fetched(&self) {
        self.blocks_fetched.fetch_add(1, Ordering::Relaxed);
    }
    /// `elapsed` is the whole `spawn_blocking` round trip for one block's
    /// `store.put`, timed from the async caller's side (not just the
    /// closure body) -- so this also captures `spawn_blocking` queueing
    /// time, which `c4_reconcile_timing::STORE_PUT`'s in-closure timing
    /// deliberately excludes. Both views are available (that module's
    /// counters are untouched by this one), for cross-check.
    pub fn add_store_put(&self, elapsed: Duration) {
        self.store_put_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }

    /// Logs exactly one line for this call, unconditionally -- not gated
    /// by an elapsed threshold, unlike this crate's Pass 1/2 aggregate
    /// diagnostics -- since a threshold gate combined with a global-diff
    /// mechanism is exactly what produced the `audit_attempt_id=460`
    /// ambiguity this module exists to eliminate.
    pub fn finish(
        &self,
        group_id: &str,
        path_count: usize,
        settled_count: usize,
        retry_count: usize,
        outer_elapsed: Duration,
    ) {
        let outer_ms = outer_elapsed.as_millis() as u64;
        let dag_resolution_ms = ms_of(self.dag_resolution_ns.load(Ordering::Relaxed));
        let ensure_blocks_present_ms = ms_of(self.ensure_blocks_present_ns.load(Ordering::Relaxed));
        let provenance_flush_ms = ms_of(self.provenance_flush_ns.load(Ordering::Relaxed));
        let writer_gate_wait_ms = ms_of(self.writer_gate_wait_ns.load(Ordering::Relaxed));
        let sqlite_transaction_ms = ms_of(self.sqlite_transaction_ns.load(Ordering::Relaxed));
        let ordinary_commit_ms = ms_of(self.ordinary_commit_ns.load(Ordering::Relaxed));
        let blocks_fetched = self.blocks_fetched.load(Ordering::Relaxed);
        let block_fetch_wait_ms = ms_of(self.block_fetch_wait_ns.load(Ordering::Relaxed));
        let store_put_ms = ms_of(self.store_put_ns.load(Ordering::Relaxed));
        // `ordinary_commit_ms` already includes `provenance_flush_ms`
        // (`try_commit_ordinary_batch`'s own call is wrapped as one whole
        // span) -- summed separately anyway, exactly like this crate's
        // Pass 1/2 `attributed_ms` already does for `dag_resolution_ms`
        // vs. `commit_ms`, so `unattributed_ms` stays a useful "how much of
        // this call is NOT explained by any named component" signal, not a
        // strict partition.
        let attributed_ms = dag_resolution_ms + ensure_blocks_present_ms + ordinary_commit_ms;
        let unattributed_ms = outer_ms.saturating_sub(attributed_ms);
        if outer_ms > SLOW_RECONCILE_THRESHOLD_MS {
            self.slow.store(1, Ordering::Relaxed);
            SLOW_RECONCILE_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        tracing::info!(
            reconcile_id = self.reconcile_id,
            group_id,
            path_count,
            settled_count,
            retry_count,
            outer_ms,
            dag_resolution_ms,
            ensure_blocks_present_ms,
            provenance_flush_ms,
            writer_gate_wait_ms,
            sqlite_transaction_ms,
            ordinary_commit_ms,
            blocks_fetched,
            block_fetch_wait_ms,
            store_put_ms,
            unattributed_ms,
            "C4_ATTR reconcile_group_paths call-local timing"
        );
    }
}

impl Default for ReconcileCallTimer {
    fn default() -> Self {
        Self::new()
    }
}

// --- responder-side BlockRequest attribution --------------------------------

struct RespAgg {
    count: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
}
impl RespAgg {
    const fn new() -> Self {
        Self { count: AtomicU64::new(0), total_ns: AtomicU64::new(0), max_ns: AtomicU64::new(0) }
    }
    fn record(&self, d: Duration) {
        let n = ns(d);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_ns.fetch_add(n, Ordering::Relaxed);
        self.max_ns.fetch_max(n, Ordering::Relaxed);
    }
    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.count.load(Ordering::Relaxed),
            ms_of(self.total_ns.load(Ordering::Relaxed)),
            ms_of(self.max_ns.load(Ordering::Relaxed)),
        )
    }
}

static RESP_AUTHORIZATION: RespAgg = RespAgg::new();
static RESP_DISPATCH_WAIT: RespAgg = RespAgg::new();
static RESP_STORE_GET: RespAgg = RespAgg::new();
static RESP_COMPRESSION: RespAgg = RespAgg::new();
static RESP_SEND: RespAgg = RespAgg::new();
static RESP_TOTAL: RespAgg = RespAgg::new();
static REQ_RTT: RespAgg = RespAgg::new();

/// Shared by both the responder-side per-request log gate and the
/// requester-side RTT log gate -- "unusually slow BlockRequest", per the
/// attribution run's own spec.
const SLOW_BLOCK_REQUEST_THRESHOLD: Duration = Duration::from_millis(500);

/// One `BlockRequest` this device answered -- called exactly once per
/// request reaching `handle_block_request_with_credit`'s own send step
/// (every outcome that got far enough to read/compress/send: `Found`, a
/// `DontHave` from a read failure, or a `Rejected` size-mismatch; the
/// earlier authorization-reject/dispatch-busy early returns are cheap,
/// local-only checks with no store/compression/send work to attribute).
/// Updates the aggregate unconditionally; logs full per-request detail
/// only when `total` clears [`SLOW_BLOCK_REQUEST_THRESHOLD`], per the
/// attribution run's own spec ("Only emit detailed per-request logs
/// when... responder total > 500ms").
#[allow(clippy::too_many_arguments)]
pub fn report_responder(
    request_id: u64,
    group_id: &str,
    block_hash: &[u8],
    authorization: Duration,
    dispatch_wait: Duration,
    store_get: Duration,
    compression: Duration,
    send: Duration,
    total: Duration,
) {
    RESP_AUTHORIZATION.record(authorization);
    RESP_DISPATCH_WAIT.record(dispatch_wait);
    RESP_STORE_GET.record(store_get);
    RESP_COMPRESSION.record(compression);
    RESP_SEND.record(send);
    RESP_TOTAL.record(total);
    if total > SLOW_BLOCK_REQUEST_THRESHOLD {
        tracing::warn!(
            request_id,
            group_id,
            hash_prefix = %hex::encode(&block_hash[..block_hash.len().min(8)]),
            authorization_ms = authorization.as_millis() as u64,
            dispatch_wait_ms = dispatch_wait.as_millis() as u64,
            store_get_ms = store_get.as_millis() as u64,
            compression_ms = compression.as_millis() as u64,
            send_ms = send.as_millis() as u64,
            total_responder_ms = total.as_millis() as u64,
            "C4_ATTR slow BlockRequest (responder side)"
        );
    }
}

/// The requester-observed round trip for one `fetch_block_raw` call (see
/// that function's own doc comment for exactly what it measures). Updates
/// the aggregate unconditionally; logs full detail only when `rtt` clears
/// [`SLOW_BLOCK_REQUEST_THRESHOLD`]. There is no wire correlation id (see
/// this module's own doc comment), so correlating this line with a
/// specific responder-side `report_responder` line is done post hoc by
/// `(group_id, hash_prefix, timestamp proximity)`.
pub fn report_requester_rtt(group_id: &str, block_hash: &[u8], rtt: Duration) {
    REQ_RTT.record(rtt);
    if rtt > SLOW_BLOCK_REQUEST_THRESHOLD {
        tracing::warn!(
            group_id,
            hash_prefix = %hex::encode(&block_hash[..block_hash.len().min(8)]),
            requester_rtt_ms = rtt.as_millis() as u64,
            "C4_ATTR slow BlockRequest (requester-observed RTT)"
        );
    }
}

/// One-line aggregate summary (`count`/`avg_ms`/`max_ms` per stage) for
/// every "normal" (not individually logged) `BlockRequest`, plus the
/// requester-side RTT aggregate -- the attribution run's driving test logs
/// this periodically alongside its existing progress tick, satisfying
/// "keep aggregate count/total/max for normal requests" without a per-
/// request line for the common, fast case.
pub fn responder_and_requester_summary() -> String {
    let fmt = |name: &str, (count, total_ms, max_ms): (u64, u64, u64)| {
        let avg_ms = if count > 0 { total_ms / count } else { 0 };
        format!("{name}(n={count},avg_ms={avg_ms},max_ms={max_ms})")
    };
    format!(
        "{} {} {} {} {} {} {}",
        fmt("authorization", RESP_AUTHORIZATION.snapshot()),
        fmt("dispatch_wait", RESP_DISPATCH_WAIT.snapshot()),
        fmt("store_get", RESP_STORE_GET.snapshot()),
        fmt("compression", RESP_COMPRESSION.snapshot()),
        fmt("send", RESP_SEND.snapshot()),
        fmt("responder_total", RESP_TOTAL.snapshot()),
        fmt("requester_rtt", REQ_RTT.snapshot()),
    )
}

// --- Pass 4 (narrow follow-up): 5-stage BlockRequest timeline + runtime-lag
// probe ----------------------------------------------------------------
//
// Pass 3 (above) proved the multi-second block RTT is not responder
// APPLICATION work (`responder_total_ms` never exceeded 178ms while
// `requester_rtt_ms` reached 4.5s for the same request population). This
// pass narrows further: is the unexplained time genuine QUIC/network
// transit, or is one side's tokio runtime failing to schedule/wake the
// task promptly (which would show up as "the bytes arrived, but nothing
// was running to notice")?
//
// Each block request already opens its own dedicated QUIC stream (see
// `PeerBlockStream`'s own doc comment: "the stream is the correlation"),
// read/written directly by the one task driving it -- there is no shared
// receive-loop-plus-oneshot-dispatch layer for block streams to hook. The
// 5 requested stages map onto this crate's real call chain as:
//   T1 -- `fetch_block_over_stream`, right before sending the request header
//   T2 -- `serve_one_block_stream`, right after decoding the received
//         request header (this IS this architecture's receive/dispatch
//         point: the request is read and handed to `handle_block_request`
//         from here)
//   T3 -- `respond_to_block_request`, right after the reply header+body
//         have both been handed to `PeerBlockStream::send_message`/
//         `send_body` (the transport call returning is the earliest this
//         process can know the reply left for the transport to carry)
//   T4 -- `fetch_block_over_stream`, right after the reply HEADER is
//         received (before the body `.await`, i.e. before this stream's
//         "waiter" -- the same task -- resumes to fetch the body)
//   T5 -- `fetch_block_over_stream`, right after the reply BODY is
//         received (or immediately, for a bodyless outcome) -- the point
//         closest to "the future that was awaiting this is done"
//
// T2/T3 are visible only to the responder's own code, T1/T4/T5 only to
// the requester's -- there is no wire request_id to carry one side's
// `Instant`s to the other (see `BlockRequestHeaderFrame`'s own doc
// comment; Pass 3 was told not to add one solely for diagnostics, and
// this pass repeats that constraint). Both sides already log `hash_prefix`
// (Pass 3), which is a reliable join key for THIS workload (one block per
// file, no shared content) -- so each side reports its own `Instant`s as
// milliseconds since a process-wide epoch ([`epoch_ms`]), and every
// requester_send_to_responder_receive/responder_receive_to_reply_send/
// reply_send_to_requester_receive interval is computed by joining the two
// sides' log lines on `hash_prefix` during analysis, not in-process.
// `Instant` subtraction is valid across tasks/threads within one process
// (same monotonic clock), which is all this test harness ever needs: both
// simulated devices run in the SAME process.
static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

fn epoch() -> std::time::Instant {
    *EPOCH.get_or_init(std::time::Instant::now)
}

/// See this section's own doc comment for why milliseconds-since-a-shared-
/// process-epoch (not wall-clock time) is the right thing to log here.
pub fn epoch_ms(instant: std::time::Instant) -> u64 {
    instant.saturating_duration_since(epoch()).as_millis() as u64
}

/// Requester-side stage log: T1 (before send), T4 (reply header received),
/// T5 (reply body received / outcome resolved). Logged unconditionally,
/// not slow-gated like Pass 3's `report_requester_rtt` -- this pass needs
/// EVERY request's `T2`/`T3` counterpart from the responder side to be
/// joinable against, not just the ones that already looked slow from the
/// requester's own vantage point alone.
pub fn report_requester_stages(
    group_id: &str,
    block_hash: &[u8],
    t1: std::time::Instant,
    t4: std::time::Instant,
    t5: std::time::Instant,
) {
    tracing::info!(
        group_id,
        hash_prefix = %hex::encode(&block_hash[..block_hash.len().min(8)]),
        t1_ms = epoch_ms(t1),
        t4_ms = epoch_ms(t4),
        t5_ms = epoch_ms(t5),
        total_rtt_ms = t5.saturating_duration_since(t1).as_millis() as u64,
        requester_receive_to_future_resume_ms = t5.saturating_duration_since(t4).as_millis() as u64,
        "C4_ATTR5 requester block-fetch stage timestamps"
    );
}

/// Responder-side stage log: T2 (request received), T3 (reply handed to
/// the transport). Logged unconditionally -- see `report_requester_
/// stages`'s own doc comment for why.
pub fn report_responder_stages(
    group_id: &str,
    block_hash: &[u8],
    t2: std::time::Instant,
    t3: std::time::Instant,
) {
    tracing::info!(
        group_id,
        hash_prefix = %hex::encode(&block_hash[..block_hash.len().min(8)]),
        t2_ms = epoch_ms(t2),
        t3_ms = epoch_ms(t3),
        responder_receive_to_reply_send_ms = t3.saturating_duration_since(t2).as_millis() as u64,
        "C4_ATTR5 responder block-serve stage timestamps"
    );
}

/// Spawns a lightweight, permanent-for-this-process background task that
/// answers one question: is THIS process's tokio runtime keeping up with
/// its own timer wheel? Every ~50ms it asks to be woken again in 50ms and
/// measures how much longer than that the wake-up actually took -- a
/// runtime with every worker busy (blocked on synchronous work, or simply
/// saturated) delays even a bare timer's wake-up, which is the same
/// starvation that would delay noticing an already-arrived QUIC read.
/// Logs only when the lag exceeds 100ms, so a healthy run produces no
/// noise. `side` is a free-form tag (`"A"`/`"B"` for this investigation's
/// two simulated devices) -- both run on the SAME shared tokio runtime in
/// this test harness (one `#[tokio::test]`), so two probes mostly
/// corroborate each other, but are cheap enough to run both anyway, as
/// asked.
pub fn spawn_runtime_lag_probe(side: &'static str) {
    tokio::spawn(async move {
        loop {
            const TARGET: Duration = Duration::from_millis(50);
            const LOG_THRESHOLD: Duration = Duration::from_millis(100);
            let started = std::time::Instant::now();
            tokio::time::sleep(TARGET).await;
            let actual = started.elapsed();
            let lag = actual.saturating_sub(TARGET);
            if lag > LOG_THRESHOLD {
                tracing::warn!(
                    side,
                    lag_ms = lag.as_millis() as u64,
                    timestamp_ms = epoch_ms(std::time::Instant::now()),
                    "C4_ATTR runtime wake-up lag probe"
                );
            }
        }
    });
}
