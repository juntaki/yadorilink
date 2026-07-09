//! Coalesces raw filesystem events into windowed batches
//! (D3) before they reach
//! `LocalChangeProcessor`. Deliberately knows nothing about indexing,
//! chunking, or peers — it only decides *when* a set of paths should be
//! considered "one batch," leaving the caller (typically
//! `yadorilink-daemon::link_manager`) to turn that batch into actual work via
//! a separate executor task (), so this module owns none of that
//! I/O and stays cheaply unit-testable in isolation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::watcher::{FsChangeEvent, FsChangeKind};

/// Default quiet period: short (not Syncthing's ~10s default, )
/// because local-change detection is also relied on for the
/// edit-presence-awareness capability's lock-file responsiveness, which a
/// multi-second default would visibly regress.
pub const DEFAULT_QUIET_PERIOD: Duration = Duration::from_millis(300);
/// A continuously-busy folder still flushes at least this often, so a
/// long-running burst of activity doesn't delay every change indefinitely.
pub const DEFAULT_MAX_FLUSH_INTERVAL: Duration = Duration::from_secs(2);
/// Distinct paths changing within one window above this count switches
/// from per-path tracking to the full-rescan fallback ().
pub const DEFAULT_BURST_THRESHOLD: usize = 500;
/// Default capacity of the channel connecting the accumulator to its
/// executor () — small, since a flush is already a coalesced
/// unit of work; a handful of pending flushes is enough buffer that a
/// single slow flush never blocks the accumulator from continuing to
/// observe new events. What happens once even this
/// buffer is exhausted by a sustained backlog is hardened separately
/// (see `push_ready`).
pub const DEFAULT_EXECUTOR_CHANNEL_CAPACITY: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebounceConfig {
    pub quiet_period: Duration,
    pub max_flush_interval: Duration,
    pub burst_threshold: usize,
}

impl Default for DebounceConfig {
    fn default() -> Self {
        Self {
            quiet_period: DEFAULT_QUIET_PERIOD,
            max_flush_interval: DEFAULT_MAX_FLUSH_INTERVAL,
            burst_threshold: DEFAULT_BURST_THRESHOLD,
        }
    }
}

/// What one debounce window produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebounceFlush {
    /// Distinct paths that changed in this window, each with the last
    /// `FsChangeKind` observed for it (a path modified then removed
    /// within the window is reported as `Removed`, matching final
    /// on-disk state — ), and the wall-clock time (unix nanos)
    /// this accumulator last observed an event for that path — i.e. when
    /// the *raw* event was received here, not when this flush is finally
    /// dispatched (which can lag by up to `quiet_period`/
    /// `max_flush_interval`). `local_change.rs`'s `Removed` dispatch needs
    /// this real observed
    /// time for `SyncState::mark_deleted_at` — a tombstone stamped with
    /// dispatch time instead would be systematically later than a
    /// concurrent edit's own (never debounce-delayed) file mtime,
    /// regardless of which genuinely happened first.
    Paths(Vec<(PathBuf, FsChangeKind, i64)>),
    /// The number of distinct paths in this window exceeded
    /// `burst_threshold`; per-path tracking was discarded () —
    /// the caller should run a full reconciliation scan instead.
    BurstFallback,
}

/// Same shape as this crate's
/// other private `now_unix_nanos` helpers (`index.rs`, `peer_session.rs`,
/// `yadorilink-daemon::link_manager`) — captures the wall-clock time a raw
/// event is received here, for `DebounceFlush::Paths`'s third tuple
/// element.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

enum State {
    Idle,
    Accumulating {
        pending: HashMap<PathBuf, (FsChangeKind, i64)>,
        window_started_at: Instant,
        last_event_at: Instant,
    },
    /// Burst threshold was crossed; further events are observed (to know
    /// when the burst subsides) but not tracked individually.
    Bursting {
        last_event_at: Instant,
    },
}

/// Which entry `FlushPathRequest` should look for in `pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushMode {
    /// Look up `FlushPathRequest::path` itself, exactly.
    ExactPath,
    /// Look up a *different* pending entry that shares `path`'s parent
    /// directory and case-folded final path component (but not its exact
    /// bytes) — i.e. the other name a case-insensitive filesystem would
    /// treat as colliding with `path`. Only ever meaningful for a caller
    /// who already confirmed the target root is on a case-insensitive
    /// filesystem (`hazard::is_case_insensitive_filesystem`); this module
    /// doesn't know or care about filesystem case-sensitivity itself, it
    /// just does the lookup asked of it.
    CaseFoldSibling,
}

/// A targeted request to immediately hand back (and remove, so it is not
/// flushed a second time when its window's own timer later elapses) one
/// specific path's pending, undispatched entry, bypassing the normal
/// quiet-period/max-flush-interval timing entirely. This lets a caller
/// outside the accumulator (`yadorilink-daemon::link_manager`, on behalf of
/// `peer_session::PeerSyncSession::reconcile_one_file`) make sure a local
/// change still sitting in this accumulator is captured into the index
/// before a racing peer write or tombstone for the same path is
/// compared/applied — see `reconcile_one_file`'s call site for why this
/// must happen before, not after, that comparison.
pub struct FlushPathRequest {
    pub path: PathBuf,
    pub mode: FlushMode,
    /// `Some((found_path, kind, observed_at_unix_nanos))` if a matching
    /// entry was pending, undispatched (now removed from this
    /// accumulator's own state) — `found_path` is `path` itself for
    /// `FlushMode::ExactPath`, or the actual sibling key that matched for
    /// `FlushMode::CaseFoldSibling` (never byte-identical to `path` in
    /// that case). `None` if nothing matched — either because it had
    /// already been handed off to the executor (in which case the
    /// ordinary per-path index lock/version check the executor and
    /// `reconcile_one_file` both already go through is what serializes the
    /// two, the same as for any other already-dispatched change), or
    /// because no `FsChangeEvent` for it has ever reached this accumulator
    /// at all — a path can still be genuinely undiscovered by the watcher
    /// subsystem at this point — see `yadorilink-daemon::link_manager::
    /// LinkFlushHandle::capture_undiscovered_local_change`, the caller's
    /// fallback for this third case).
    pub reply: tokio::sync::oneshot::Sender<Option<(PathBuf, FsChangeKind, i64)>>,
}

/// A request to
/// immediately drain and hand back *every* currently-pending, undispatched
/// entry in this accumulator (not just one path), bypassing the normal
/// quiet-period/max-flush-interval timing entirely -- same rationale as
/// `FlushPathRequest`, but for "resuming a paused link must broadcast its
/// true current state, not whatever snapshot happened to already be
/// flushed into the index at that exact instant" rather than "reconciling
/// one specific incoming path." A local change made while a link was
/// paused is indexed immediately regardless of pause (`announce_local_
/// change`'s doc comment), but only once its own debounce window's quiet
/// period elapses -- resuming shortly after such a change (well within
/// that window) would otherwise broadcast a stale snapshot missing it,
/// with no second chance to send it until either another local change to
/// the same path, or the periodic full-index resync, happens to occur.
pub struct FlushAllRequest {
    /// Every entry that was pending, in no particular order; empty if
    /// nothing was pending (including while `Idle`/`Bursting`, where there
    /// is nothing per-path to drain).
    pub reply: tokio::sync::oneshot::Sender<Vec<(PathBuf, FsChangeKind, i64)>>,
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Runs the debounce accumulator ('s accumulator half, D7):
/// reads raw events from `events`, and delivers completed window batches
/// to `flush_tx`. Returns once `events` closes (the watcher stopped) or
/// `flush_tx` closes (the executor side is gone). Does no I/O beyond
/// these two channels — see the module doc comment for why.
///
/// Delivery to `flush_tx` races against continuing to read `events`
/// (): a completed window joins an internal delivery queue
/// rather than being sent with a blocking `.await` directly in the same
/// `select!` as event intake, so a slow or backed-up executor (not
/// draining `flush_tx` quickly) never stalls this task's ability to keep
/// observing and accumulating new filesystem events for the *next*
/// window in the meantime. Per-link delivery order is still preserved —
/// the queue is drained strictly front-to-back, one send at a time.
///
/// `overflowed` is `watcher::FolderWatcher`'s overflow flag ():
/// checked (and cleared) on every loop iteration. A set flag means the
/// watcher's own channel dropped at least one raw event since it was last
/// checked — precise per-path tracking is no longer trustworthy for
/// whatever window is in progress, so it's routed into the exact same
/// `Bursting` state and full-reconciliation recovery as an oversized
/// debounce burst (), rather than a second, separate fallback
/// mechanism.
///
/// `flush_requests` is the
/// targeted "flush now" channel (`FlushPathRequest`'s doc comment) —
/// serviced with higher priority than continuing to accumulate new events,
/// so a caller waiting on the reply is never stuck behind an unrelated
/// burst of activity for other paths.
pub async fn run_debouncer(
    config: DebounceConfig,
    mut events: mpsc::Receiver<FsChangeEvent>,
    flush_tx: mpsc::Sender<DebounceFlush>,
    overflowed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mut flush_requests: mpsc::Receiver<FlushPathRequest>,
    mut flush_all_requests: mpsc::Receiver<FlushAllRequest>,
) {
    let mut state = State::Idle;
    let mut ready_queue: std::collections::VecDeque<DebounceFlush> =
        std::collections::VecDeque::new();
    // Once the requester side is gone, stop polling `flush_requests`
    // entirely rather than let a closed channel's always-ready `None` spin
    // this loop — mirrors `ready_queue.is_empty()`'s guard on the
    // `send_front` branch below.
    let mut flush_requests_open = true;
    let mut flush_all_requests_open = true;

    loop {
        if overflowed.swap(false, std::sync::atomic::Ordering::Relaxed) {
            // : each of the three fallback triggers logs a
            // distinguishable reason.
            tracing::warn!(
                reason = "watcher_channel_overflow",
                "filesystem watcher channel overflowed; falling back to full reconciliation"
            );
            state = State::Bursting { last_event_at: Instant::now() };
        }

        let deadline = match &state {
            State::Idle => None,
            State::Accumulating { window_started_at, last_event_at, .. } => Some(std::cmp::min(
                *last_event_at + config.quiet_period,
                *window_started_at + config.max_flush_interval,
            )),
            State::Bursting { last_event_at } => Some(*last_event_at + config.quiet_period),
        };

        tokio::select! {
            biased;

            // Cancel-safe: only pops the front entry once it's actually
            // been sent; if this branch loses the race below, the queue
            // is untouched and the same entry is retried next iteration.
            result = send_front(&flush_tx, &ready_queue), if !ready_queue.is_empty() => {
                match result {
                    Ok(()) => { ready_queue.pop_front(); }
                    Err(()) => break, // executor side is gone
                }
            }

            // Serviced ahead of `events.recv()` (see this fn's doc comment):
            // a targeted flush request should never be left waiting behind
            // a caller that's still busy generating unrelated events.
            maybe_request = flush_requests.recv(), if flush_requests_open => {
                let Some(request) = maybe_request else {
                    flush_requests_open = false;
                    continue;
                };
                let (next_state, found) = match state {
                    State::Accumulating { mut pending, window_started_at, last_event_at } => {
                        let found = match request.mode {
                            FlushMode::ExactPath => pending
                                .remove(&request.path)
                                .map(|(kind, at)| (request.path.clone(), kind, at)),
                            FlushMode::CaseFoldSibling => {
                                let sibling = pending.keys().find(|candidate| {
                                    *candidate != &request.path
                                        && candidate.parent() == request.path.parent()
                                        && candidate.file_name().map(|n| n.to_string_lossy().to_lowercase())
                                            == request.path.file_name().map(|n| n.to_string_lossy().to_lowercase())
                                }).cloned();
                                sibling.and_then(|key| {
                                    pending.remove(&key).map(|(kind, at)| (key, kind, at))
                                })
                            }
                        };
                        let next = if pending.is_empty() {
                            State::Idle
                        } else {
                            State::Accumulating { pending, window_started_at, last_event_at }
                        };
                        (next, found)
                    }
                    other @ (State::Idle | State::Bursting { .. }) => (other, None),
                };
                state = next_state;
                let _ = request.reply.send(found);
            }

            maybe_request = flush_all_requests.recv(), if flush_all_requests_open => {
                let Some(request) = maybe_request else {
                    flush_all_requests_open = false;
                    continue;
                };
                let drained = match state {
                    State::Accumulating { pending, .. } => {
                        state = State::Idle;
                        pending.into_iter().map(|(path, (kind, at))| (path, kind, at)).collect()
                    }
                    other @ (State::Idle | State::Bursting { .. }) => {
                        state = other;
                        Vec::new()
                    }
                };
                let _ = request.reply.send(drained);
            }

            maybe_event = events.recv() => {
                let Some(event) = maybe_event else { break };
                let now = Instant::now();
                let observed_at = now_unix_nanos();
                state = match state {
                    State::Idle => {
                        let mut pending = HashMap::new();
                        pending.insert(event.path, (event.kind, observed_at));
                        State::Accumulating { pending, window_started_at: now, last_event_at: now }
                    }
                    State::Accumulating { mut pending, window_started_at, .. } => {
                        pending.insert(event.path, (event.kind, observed_at));
                        if pending.len() > config.burst_threshold {
                            tracing::warn!(
                                reason = "burst_threshold_exceeded",
                                burst_threshold = config.burst_threshold,
                                "too many distinct paths changed in one debounce window; falling back to full reconciliation"
                            );
                            State::Bursting { last_event_at: now }
                        } else {
                            State::Accumulating { pending, window_started_at, last_event_at: now }
                        }
                    }
                    State::Bursting { .. } => State::Bursting { last_event_at: now },
                };
            }

            _ = sleep_until_opt(deadline) => {
                let flush = match state {
                    State::Idle => unreachable!("no timer is armed while Idle"),
                    State::Accumulating { pending, .. } => DebounceFlush::Paths(
                        pending.into_iter().map(|(path, (kind, at))| (path, kind, at)).collect(),
                    ),
                    State::Bursting { .. } => DebounceFlush::BurstFallback,
                };
                push_ready(&mut ready_queue, flush);
                state = State::Idle;
            }
        }
    }
}

/// Pushes a completed window onto the delivery queue, collapsing it into
/// a single `BurstFallback` if the executor has fallen far enough behind
/// that the queue would otherwise grow without bound — this is the same
/// "too much changed to track precisely,
/// reconcile from scratch instead" recovery as the burst-threshold and
/// watcher-overflow triggers, applied to a third place bounded memory
/// matters: the queue between this accumulator and its executor.
fn push_ready(queue: &mut std::collections::VecDeque<DebounceFlush>, flush: DebounceFlush) {
    if queue.len() >= DEFAULT_EXECUTOR_CHANNEL_CAPACITY {
        tracing::warn!(
            reason = "executor_backlog",
            queued = queue.len(),
            "executor has fallen behind the accumulator; collapsing queued flushes into a full reconciliation"
        );
        queue.clear();
        queue.push_back(DebounceFlush::BurstFallback);
    } else {
        queue.push_back(flush);
    }
}

/// Sends a clone of the queue's front entry — cloning (rather than
/// popping first) is what makes the caller's `select!` branch cancel-safe:
/// if a competing branch wins the race, this future is simply dropped
/// mid-flight with the queue left untouched, ready to retry.
async fn send_front(
    flush_tx: &mpsc::Sender<DebounceFlush>,
    queue: &std::collections::VecDeque<DebounceFlush>,
) -> Result<(), ()> {
    let front = queue.front().cloned().expect("caller guards on !queue.is_empty()");
    flush_tx.send(front).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_overflow() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
    }

    /// A `flush_requests` receiver for tests that don't exercise
    /// the targeted-flush
    /// mechanism — the sender is simply dropped, so `run_debouncer` sees a
    /// closed channel and stops polling it (see `flush_requests_open`).
    fn no_flush_requests() -> mpsc::Receiver<FlushPathRequest> {
        let (_tx, rx) = mpsc::channel(1);
        rx
    }

    fn no_flush_all_requests() -> mpsc::Receiver<FlushAllRequest> {
        let (_tx, rx) = mpsc::channel(1);
        rx
    }

    fn short_config() -> DebounceConfig {
        DebounceConfig {
            quiet_period: Duration::from_millis(30),
            max_flush_interval: Duration::from_millis(150),
            burst_threshold: 5,
        }
    }

    /// Strips the per-path observed timestamp — most existing assertions
    /// only care about which paths/kinds flushed, not the exact wall-clock
    /// time attached to each.
    fn expect_paths(flush: DebounceFlush) -> Vec<(PathBuf, FsChangeKind)> {
        match flush {
            DebounceFlush::Paths(paths) => {
                paths.into_iter().map(|(path, kind, _at)| (path, kind)).collect()
            }
            DebounceFlush::BurstFallback => panic!("expected Paths, got BurstFallback"),
        }
    }

    /// A single event flushes after the quiet period, with the expected
    /// path and kind — the common case's latency floor.
    #[tokio::test]
    async fn single_event_flushes_after_the_quiet_period() {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        let started = Instant::now();
        events_tx
            .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
            .await
            .unwrap();

        let flush = tokio::time::timeout(Duration::from_secs(2), flush_rx.recv())
            .await
            .expect("timed out waiting for flush")
            .unwrap();
        let elapsed = started.elapsed();

        let paths = expect_paths(flush);
        assert_eq!(paths, vec![(PathBuf::from("a.txt"), FsChangeKind::CreatedOrModified)]);
        assert!(elapsed >= Duration::from_millis(30), "flushed too early: {elapsed:?}");
        assert!(elapsed < Duration::from_millis(500), "flush latency too high: {elapsed:?}");
    }

    /// The targeted
    /// "flush now" mechanism: a path with a pending, undispatched entry is
    /// handed back (and removed) immediately, well before the normal quiet
    /// period would otherwise flush it — and is never flushed a second
    /// time once its window's timer does elapse.
    #[tokio::test]
    async fn flush_path_request_hands_back_and_removes_a_pending_entry_immediately() {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        let (flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            flush_requests_rx,
            no_flush_all_requests(),
        ));

        events_tx
            .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
            .await
            .unwrap();
        // `send().await` only guarantees the event reached the channel
        // buffer, not that the spawned accumulator task has already polled
        // it into `pending` — give it a moment before racing a flush
        // request against it, well under the 30ms quiet period below.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let started = Instant::now();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        flush_requests_tx
            .send(FlushPathRequest {
                path: "a.txt".into(),
                mode: FlushMode::ExactPath,
                reply: reply_tx,
            })
            .await
            .unwrap();
        let found = tokio::time::timeout(Duration::from_secs(1), reply_rx)
            .await
            .expect("timed out waiting for the flush-request reply")
            .unwrap();
        let (found_path, found_kind, _found_at) =
            found.expect("expected a pending entry for a.txt");
        assert_eq!(found_path, PathBuf::from("a.txt"));
        assert_eq!(found_kind, FsChangeKind::CreatedOrModified);
        assert!(
            started.elapsed() < Duration::from_millis(20),
            "a targeted flush request must not wait for the normal quiet period: {:?}",
            started.elapsed()
        );

        // The normal window timer, still armed, must not re-deliver "a.txt"
        // now that it's been claimed by the targeted request above.
        let flush = tokio::time::timeout(Duration::from_millis(300), flush_rx.recv()).await;
        match flush {
            Ok(Some(DebounceFlush::Paths(paths))) => {
                assert!(
                    paths.is_empty(),
                    "already-claimed path must not be flushed again: {paths:?}"
                )
            }
            Ok(Some(DebounceFlush::BurstFallback)) => panic!("unexpected burst fallback"),
            Ok(None) => panic!("accumulator task ended unexpectedly"),
            Err(_) => {} // no flush at all is also an acceptable outcome
        }

        // A second request for the same path now finds nothing pending.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        flush_requests_tx
            .send(FlushPathRequest {
                path: "a.txt".into(),
                mode: FlushMode::ExactPath,
                reply: reply_tx,
            })
            .await
            .unwrap();
        let found_again =
            tokio::time::timeout(Duration::from_secs(1), reply_rx).await.unwrap().unwrap();
        assert_eq!(found_again, None);
    }

    /// `FlushMode::CaseFoldSibling` finds and removes a *different*
    /// pending path in the same directory whose final component is
    /// case-fold-equal to the requested one, leaving an exact-byte match
    /// (there is none here) or an unrelated path (`b.txt`) untouched.
    #[tokio::test]
    async fn flush_case_fold_sibling_finds_a_differently_cased_pending_entry() {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (flush_tx, _flush_rx) = mpsc::channel(16);
        let (flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            flush_requests_rx,
            no_flush_all_requests(),
        ));

        events_tx
            .send(FsChangeEvent {
                path: "Shared.bin".into(),
                kind: FsChangeKind::CreatedOrModified,
            })
            .await
            .unwrap();
        events_tx
            .send(FsChangeEvent { path: "b.txt".into(), kind: FsChangeKind::CreatedOrModified })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        flush_requests_tx
            .send(FlushPathRequest {
                path: "shared.bin".into(),
                mode: FlushMode::CaseFoldSibling,
                reply: reply_tx,
            })
            .await
            .unwrap();
        let found = tokio::time::timeout(Duration::from_secs(1), reply_rx).await.unwrap().unwrap();
        let (found_path, found_kind, _found_at) = found.expect("expected Shared.bin to be found");
        assert_eq!(found_path, PathBuf::from("Shared.bin"));
        assert_eq!(found_kind, FsChangeKind::CreatedOrModified);

        // A second request now finds nothing (already removed), and
        // `b.txt` was never a candidate to begin with.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        flush_requests_tx
            .send(FlushPathRequest {
                path: "shared.bin".into(),
                mode: FlushMode::CaseFoldSibling,
                reply: reply_tx,
            })
            .await
            .unwrap();
        let found_again =
            tokio::time::timeout(Duration::from_secs(1), reply_rx).await.unwrap().unwrap();
        assert_eq!(found_again, None);
    }

    /// `FlushAllRequest`
    /// drains every pending entry at once (not just one path), leaving the
    /// accumulator empty and back in `Idle` afterward.
    #[tokio::test]
    async fn flush_all_request_drains_every_pending_entry_at_once() {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        let (_flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
        let (flush_all_requests_tx, flush_all_requests_rx) = mpsc::channel(4);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            flush_requests_rx,
            flush_all_requests_rx,
        ));

        events_tx
            .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
            .await
            .unwrap();
        events_tx
            .send(FsChangeEvent { path: "b.txt".into(), kind: FsChangeKind::Removed })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        let started = Instant::now();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        flush_all_requests_tx.send(FlushAllRequest { reply: reply_tx }).await.unwrap();
        let mut drained =
            tokio::time::timeout(Duration::from_secs(1), reply_rx).await.unwrap().unwrap();
        drained.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            drained.into_iter().map(|(path, kind, _at)| (path, kind)).collect::<Vec<_>>(),
            vec![
                (PathBuf::from("a.txt"), FsChangeKind::CreatedOrModified),
                (PathBuf::from("b.txt"), FsChangeKind::Removed),
            ]
        );
        assert!(
            started.elapsed() < Duration::from_millis(20),
            "a flush-all request must not wait for the normal quiet period: {:?}",
            started.elapsed()
        );

        // Everything already having been drained, the normal window timer
        // (still armed a moment ago) must not re-deliver either path.
        let flush = tokio::time::timeout(Duration::from_millis(300), flush_rx.recv()).await;
        match flush {
            Ok(Some(DebounceFlush::Paths(paths))) => {
                assert!(
                    paths.is_empty(),
                    "already-drained paths must not be flushed again: {paths:?}"
                )
            }
            Ok(Some(DebounceFlush::BurstFallback)) => panic!("unexpected burst fallback"),
            Ok(None) => panic!("accumulator task ended unexpectedly"),
            Err(_) => {} // no flush at all is also an acceptable outcome
        }

        // A second flush-all request now finds nothing pending.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        flush_all_requests_tx.send(FlushAllRequest { reply: reply_tx }).await.unwrap();
        let drained_again =
            tokio::time::timeout(Duration::from_secs(1), reply_rx).await.unwrap().unwrap();
        assert!(drained_again.is_empty());
    }

    /// Multiple events for the same path within one window coalesce into
    /// one flush entry using the last-observed kind ().
    #[tokio::test]
    async fn repeated_events_for_the_same_path_coalesce_to_the_latest_kind() {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        events_tx
            .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
            .await
            .unwrap();
        events_tx
            .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
            .await
            .unwrap();
        events_tx
            .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::Removed })
            .await
            .unwrap();

        let flush = tokio::time::timeout(Duration::from_secs(2), flush_rx.recv())
            .await
            .expect("timed out waiting for flush")
            .unwrap();
        let paths = expect_paths(flush);
        assert_eq!(paths, vec![(PathBuf::from("a.txt"), FsChangeKind::Removed)]);
    }

    /// Events for different paths within one window all land in the same
    /// flush.
    #[tokio::test]
    async fn multiple_distinct_paths_in_one_window_flush_together() {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        for name in ["a.txt", "b.txt", "c.txt"] {
            events_tx
                .send(FsChangeEvent { path: name.into(), kind: FsChangeKind::CreatedOrModified })
                .await
                .unwrap();
        }

        let flush = tokio::time::timeout(Duration::from_secs(2), flush_rx.recv())
            .await
            .expect("timed out waiting for flush")
            .unwrap();
        let mut paths = expect_paths(flush);
        paths.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            paths,
            vec![
                (PathBuf::from("a.txt"), FsChangeKind::CreatedOrModified),
                (PathBuf::from("b.txt"), FsChangeKind::CreatedOrModified),
                (PathBuf::from("c.txt"), FsChangeKind::CreatedOrModified),
            ]
        );
    }

    /// Events for the same path split across two separate windows (a
    /// quiet period elapses between them) each get their own flush,
    /// rather than being merged into one.
    #[tokio::test]
    async fn events_split_across_two_windows_flush_separately() {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        events_tx
            .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
            .await
            .unwrap();
        let first =
            tokio::time::timeout(Duration::from_secs(2), flush_rx.recv()).await.unwrap().unwrap();
        assert_eq!(
            expect_paths(first),
            vec![(PathBuf::from("a.txt"), FsChangeKind::CreatedOrModified)]
        );

        events_tx
            .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::Removed })
            .await
            .unwrap();
        let second =
            tokio::time::timeout(Duration::from_secs(2), flush_rx.recv()).await.unwrap().unwrap();
        assert_eq!(expect_paths(second), vec![(PathBuf::from("a.txt"), FsChangeKind::Removed)]);
    }

    /// A continuously-busy path (a new event arrives before every quiet
    /// period elapses) still flushes at least once per `max_flush_interval`.
    #[tokio::test]
    async fn continuously_busy_path_flushes_at_max_interval() {
        let config = DebounceConfig {
            quiet_period: Duration::from_millis(500),
            max_flush_interval: Duration::from_millis(100),
            burst_threshold: 5,
        };
        let (events_tx, events_rx) = mpsc::channel(64);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        tokio::spawn(run_debouncer(
            config,
            events_rx,
            flush_tx,
            no_overflow(),
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        let keep_sending = tokio::spawn(async move {
            for _ in 0..20 {
                let _ = events_tx
                    .send(FsChangeEvent {
                        path: "busy.txt".into(),
                        kind: FsChangeKind::CreatedOrModified,
                    })
                    .await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        // With a 500ms quiet period that never elapses (events every
        // 20ms) but a 100ms max_flush_interval, a flush must still arrive
        // well before the 500ms quiet-period would ever fire on its own.
        let flush = tokio::time::timeout(Duration::from_millis(400), flush_rx.recv())
            .await
            .expect("max_flush_interval did not force a flush in time")
            .unwrap();
        assert_eq!(
            expect_paths(flush),
            vec![(PathBuf::from("busy.txt"), FsChangeKind::CreatedOrModified)]
        );
        keep_sending.abort();
    }

    /// Exceeding the burst threshold within one window switches to
    /// `BurstFallback` instead of a `Paths` batch ().
    #[tokio::test]
    async fn exceeding_burst_threshold_triggers_burst_fallback() {
        let (events_tx, events_rx) = mpsc::channel(64);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        // short_config()'s burst_threshold is 5.
        for i in 0..10 {
            events_tx
                .send(FsChangeEvent {
                    path: format!("file-{i}.txt").into(),
                    kind: FsChangeKind::CreatedOrModified,
                })
                .await
                .unwrap();
        }

        let flush = tokio::time::timeout(Duration::from_secs(2), flush_rx.recv())
            .await
            .expect("timed out waiting for flush")
            .unwrap();
        assert_eq!(flush, DebounceFlush::BurstFallback);
    }

    /// A quiet folder (`Idle` state, no timer armed) doesn't spuriously
    /// flush anything, and closing the events channel ends the debouncer
    /// cleanly.
    #[tokio::test]
    async fn idle_debouncer_ends_cleanly_when_the_events_channel_closes() {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        let handle = tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        drop(events_tx);
        handle.await.unwrap();
        assert!(flush_rx.recv().await.is_none());
    }

    /// : an artificially slow
    /// executor (here, a test task that only calls `flush_rx.recv()` after
    /// a deliberate delay) does not prevent the accumulator from
    /// continuing to observe and accumulate new events during that delay —
    /// the accumulator and executor are independently-scheduled tasks
    /// connected only by the flush channel, not one blocking loop.
    #[tokio::test]
    async fn a_slow_executor_does_not_block_the_accumulator_from_observing_new_events() {
        // Capacity 1: the *first* flush fills the wire channel completely
        // and stays unread for a while — if delivery were a blocking
        // `.await` inside the same loop that reads `events`, this alone
        // would already stall the accumulator. A second and third window
        // must still complete and queue up correctly while the executor
        // (this test) isn't draining at all.
        let (events_tx, events_rx) = mpsc::channel(64);
        let (flush_tx, mut flush_rx) = mpsc::channel(1);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        for name in ["first.txt", "second.txt", "third.txt"] {
            events_tx
                .send(FsChangeEvent { path: name.into(), kind: FsChangeKind::CreatedOrModified })
                .await
                .unwrap();
            // Longer than the quiet period, so each becomes its own
            // completed window before the next event is sent.
            tokio::time::sleep(Duration::from_millis(60)).await;
        }

        // Only now does the "executor" start draining — proving all three
        // windows completed independently of any consumer activity, and
        // arrive in the order they were produced.
        for expected in ["first.txt", "second.txt", "third.txt"] {
            let flush = tokio::time::timeout(Duration::from_secs(2), flush_rx.recv())
                .await
                .expect("a queued flush never arrived")
                .unwrap();
            assert_eq!(
                expect_paths(flush),
                vec![(PathBuf::from(expected), FsChangeKind::CreatedOrModified)]
            );
        }
    }

    #[derive(Clone, Default)]
    struct SharedLogBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedLogBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl SharedLogBuf {
        fn contains(&self, needle: &str) -> bool {
            String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
                .contains(needle)
        }
    }

    /// Each of the three fallback
    /// triggers logs a distinguishable reason. One `#[tokio::test]` (the
    /// default current-thread flavor) keeps everything on one OS thread,
    /// so a thread-local-default subscriber captures the debouncer task's
    /// log output correctly.
    #[tokio::test]
    async fn burst_threshold_trigger_logs_a_distinguishable_reason() {
        let buf = SharedLogBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let b = buf.clone();
                move || b.clone()
            })
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (events_tx, events_rx) = mpsc::channel(64);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        for i in 0..10 {
            events_tx
                .send(FsChangeEvent {
                    path: format!("file-{i}.txt").into(),
                    kind: FsChangeKind::CreatedOrModified,
                })
                .await
                .unwrap();
        }
        let flush =
            tokio::time::timeout(Duration::from_secs(2), flush_rx.recv()).await.unwrap().unwrap();
        assert_eq!(flush, DebounceFlush::BurstFallback);

        assert!(
            buf.contains("burst_threshold_exceeded"),
            "log did not mention the burst-threshold reason"
        );
    }

    #[tokio::test]
    async fn watcher_overflow_trigger_logs_a_distinguishable_reason() {
        let buf = SharedLogBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let b = buf.clone();
                move || b.clone()
            })
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (_events_tx, events_rx) = mpsc::channel(16);
        let (flush_tx, mut flush_rx) = mpsc::channel(16);
        let overflowed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            overflowed,
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        let flush =
            tokio::time::timeout(Duration::from_secs(2), flush_rx.recv()).await.unwrap().unwrap();
        assert_eq!(flush, DebounceFlush::BurstFallback);

        assert!(
            buf.contains("watcher_channel_overflow"),
            "log did not mention the watcher-overflow reason"
        );
    }

    /// Once the delivery queue
    /// reaches capacity (executor never drains), further completed
    /// windows collapse into a single `BurstFallback` instead of growing
    /// the queue without bound, and the collapse is logged with its own
    /// distinguishable reason.
    #[tokio::test]
    async fn executor_backlog_trigger_logs_a_distinguishable_reason_and_collapses_the_queue() {
        let buf = SharedLogBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let b = buf.clone();
                move || b.clone()
            })
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (events_tx, events_rx) = mpsc::channel(256);
        // Never drained during the test — forces the internal ready_queue
        // (not the wire channel) to fill past DEFAULT_EXECUTOR_CHANNEL_CAPACITY.
        let (flush_tx, mut flush_rx) = mpsc::channel(1);
        tokio::spawn(run_debouncer(
            short_config(),
            events_rx,
            flush_tx,
            no_overflow(),
            no_flush_requests(),
            no_flush_all_requests(),
        ));

        // One window per file, well separated so each completes on its
        // own — enough windows to exceed DEFAULT_EXECUTOR_CHANNEL_CAPACITY
        // (8) while nothing reads flush_rx. The gap between sends needs
        // real headroom above quiet_period (30ms), not just a few ms: if
        // the spawned debouncer task is slow to get scheduled (a slower/
        // more contended CI runner -- observed failing on windows-latest
        // at the old 40ms gap), several sends can queue up in its mpsc
        // channel before it's polled again, and it then processes them
        // back-to-back with nearly-identical Instant::now() reads, merging
        // what should have been separate windows into one and never
        // reaching the queue depth this test means to exercise.
        for i in 0..(DEFAULT_EXECUTOR_CHANNEL_CAPACITY + 4) {
            events_tx
                .send(FsChangeEvent {
                    path: format!("file-{i}.txt").into(),
                    kind: FsChangeKind::CreatedOrModified,
                })
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        // The debouncer task runs independently of this test's own
        // progress -- under CPU contention (many tests running in
        // parallel, or a slower CI runner) it can lag behind having
        // actually reached the queue-depth-8 collapse by the moment the
        // send loop above returns, so this polls for the log rather than
        // checking exactly once immediately (which raced and failed
        // intermittently even locally under `cargo test`'s default
        // parallelism, not just in CI).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !buf.contains("executor_backlog") && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            buf.contains("executor_backlog"),
            "log did not mention the executor-backlog reason"
        );

        // Now drain: the queue was collapsed, so what's left is a small,
        // bounded number of entries ending in a BurstFallback — not one
        // entry per file.
        let mut seen = 0;
        let mut saw_fallback = false;
        while let Ok(Some(flush)) =
            tokio::time::timeout(Duration::from_millis(500), flush_rx.recv()).await
        {
            seen += 1;
            if flush == DebounceFlush::BurstFallback {
                saw_fallback = true;
            }
            assert!(
                seen <= DEFAULT_EXECUTOR_CHANNEL_CAPACITY + 1,
                "queue was not bounded/collapsed"
            );
        }
        assert!(saw_fallback, "expected the collapsed backlog to end in a BurstFallback");
    }
}
