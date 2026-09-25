//! What makes reconciliation happen in production.
//!
//! # Mostly event-driven, with one backstop
//!
//! Correctness comes from comparing durable sets: whenever two peers
//! reconcile, they find every difference between them. So the three events
//! below are latency, not correctness — a missed wake costs the time until
//! the next one, which is exactly why it is safe for them to be a small set
//! of events rather than a periodic sweep.
//!
//! That is the whole reason the old anti-entropy timer existed and the events
//! don't need an equivalent: head announcement could miss a difference
//! permanently, so a sweep had to keep re-offering the whole frontier as a
//! rescue, where set reconciliation recomputes the whole difference from
//! durable state every time it runs.
//!
//! What set reconciliation does NOT protect against is one round of *itself*
//! finishing without staging everything it said it wanted:
//! `SyncStack::sync_with`'s own responder-side contract (`serve_bundles`'s
//! `load_bundles` call, `yadorilink-sync-protocol`) treats a hash the
//! initiator's reconcile round just offered but the responder's own bundle
//! load can no longer find as a stale snapshot, not an error — deliberately,
//! since disclosure is re-checked per hash rather than trusted from the
//! reconcile pass. A `SyncSummary` can therefore report `wanted > staged`
//! with no `Err` at all when the two race within the SAME peer's own store
//! (confirmed: a device's freshly-admitted content is briefly `servable`
//! before its bundle is independently loadable, which a burst of several
//! peers reconciling with it in the same instant can catch mid-window).
//! [`pump`]'s own per-attempt handling already tolerates that (`Ok(None)`/
//! `wanted == 0` are both quiet), but nothing before this backstop ever
//! asked *that exact pair* again — an isolated pairing with no further local
//! edit or netmap churn from either side sat on the wrong side of that
//! window forever. [`RECONCILIATION_BACKSTOP_INTERVAL`] re-raises
//! [`Wake::All`] on a fixed cadence for exactly this: cheap (a `sync_with`
//! that finds nothing new resolves in one round each side), and it needs no
//! state of its own because every re-attempt recomputes the difference from
//! current durable sets like any other wake here.
//!
//! # The three events
//!
//! ```text
//!   netmap changed        an (authorized peer, group) pair appeared or moved
//!   local possession      this device staged or admitted something
//!   peer reachable        a connection or address became usable
//! ```
//!
//! Each expands to a set of (peer, group) pairs and asks for a reconciliation
//! of each. Asking is cheap: `SyncStack::sync_with` is single-flighted per
//! (peer, group), so a burst of events during one pass earns exactly one
//! further pass rather than a queue of sessions.

use std::sync::Arc;

use tokio::sync::mpsc;
use yadorilink_replica_domain::ids::FolderGroupId;

use super::sync_stack::SyncAttempt;
use crate::daemon_state::DaemonState;

use super::sync_stack::SyncStack;

/// A reason to reconcile. Never a reason a *difference* exists — only a hint
/// that looking now is likely to be worth it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wake {
    /// Local possession of this group changed, so every peer authorized for
    /// it may now be behind us.
    Group(FolderGroupId),
    /// This peer became reachable, so every group we share with it is worth
    /// a look.
    Peer(String),
    /// One specific pairing became interesting — a netmap grant, typically.
    PeerGroup(String, FolderGroupId),
    /// Everything this device is currently authorized for is worth a look.
    ///
    /// Raised once at startup by `DaemonState::install_reconciliation_
    /// driver`, and then again on [`RECONCILIATION_BACKSTOP_INTERVAL`] by
    /// [`pump`]'s own timer.
    ///
    /// The startup raise exists because a driver that only reacts to
    /// transitions cannot know about the ones that happened before it
    /// existed, and there are always some: the netmap arrives during startup
    /// and raises its grants and addresses against a device that has no
    /// driver yet, and nothing re-raises them afterwards because they only
    /// fire on *change*. A steady netmap after that is silent, so a device
    /// could otherwise sit authorized, reachable and unreconciled
    /// indefinitely.
    ///
    /// The periodic raise exists for a narrower, later-discovered gap this
    /// module's own doc comment covers in full: one `sync_with` round can
    /// legitimately want something it never stages, with no error, when it
    /// races the responder's own store — and unlike every other transition
    /// here, nothing else notices that specific pairing needs asking again.
    ///
    /// Raised by `DaemonState::install_reconciliation_driver` *after* the
    /// driver is published, never by `start` — raised before publication it
    /// would close nothing: the pump could expand it against a snapshot of
    /// authorizations taken while producers still saw no driver, so a change
    /// landing in between would be in neither the snapshot nor the queue.
    /// After publication, every change is in one or the other. The periodic
    /// raise has no such ordering requirement (`pump` only starts once it is
    /// already receiving on `rx`), so it needs no equivalent guard.
    All,
}

/// How many reconciliations may be in flight at once across all peers.
///
/// Not a correctness bound. It keeps a netmap change that authorizes many
/// peers at once from opening a connection to all of them in the same
/// instant; the rest are not dropped, they wait their turn in the channel.
const MAX_CONCURRENT_SYNCS: usize = 8;

/// How often [`pump`] re-raises [`Wake::All`] on its own, closing the
/// `wanted > staged`-with-no-error window this module's own doc comment
/// describes — see there for why a periodic re-ask is needed at all despite
/// set reconciliation's own durable-set guarantee. Same order of cadence as
/// this crate's other convergence-adjacent backstops
/// (`engine_wrapper::RETIREMENT_BACKSTOP_INTERVAL` and siblings): loose on
/// purpose, since this exists to catch a rare race, not to carry ordinary
/// reconciliation latency.
const RECONCILIATION_BACKSTOP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Test-only hook overriding the value every subsequently-started
/// [`ReconciliationDriver`]'s backstop timer uses — same shape and same
/// reason as `DaemonState::set_default_materialization_repair_sweep_
/// interval_for_tests`: `pump` reads this once, when it builds its first
/// backstop deadline, so a caller must set this before starting any driver
/// whose backstop should already reflect it.
static RECONCILIATION_BACKSTOP_INTERVAL_OVERRIDE_FOR_TESTS: std::sync::OnceLock<
    std::sync::Mutex<Option<std::time::Duration>>,
> = std::sync::OnceLock::new();

/// Sets the default backstop interval every [`ReconciliationDriver`] started
/// after this call uses, process-wide. Set this before pairing any test
/// device whose reconciliation must not depend on
/// [`RECONCILIATION_BACKSTOP_INTERVAL`]'s full production cadence to close a
/// missed pairing.
pub fn set_default_reconciliation_backstop_interval_for_tests(interval: std::time::Duration) {
    *RECONCILIATION_BACKSTOP_INTERVAL_OVERRIDE_FOR_TESTS
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = Some(interval);
}

fn reconciliation_backstop_interval() -> std::time::Duration {
    RECONCILIATION_BACKSTOP_INTERVAL_OVERRIDE_FOR_TESTS
        .get()
        .and_then(|m| *m.lock().unwrap_or_else(|p| p.into_inner()))
        .unwrap_or(RECONCILIATION_BACKSTOP_INTERVAL)
}

/// Turns events into reconciliations.
pub struct ReconciliationDriver {
    stack: Arc<SyncStack>,
    wake: mpsc::UnboundedSender<Wake>,
    pump: tokio::task::JoinHandle<()>,
    /// Keeps a peer session for every authorized peer this stack's endpoint
    /// reaches. Held here because sessions ride this stack's lanes: when the
    /// driver goes, so does every session over it.
    sessions: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for ReconciliationDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReconciliationDriver")
    }
}

impl ReconciliationDriver {
    /// Start driving `stack` from `state`'s events.
    pub fn start(state: Arc<DaemonState>, stack: Arc<SyncStack>) -> Arc<Self> {
        let (wake, rx) = mpsc::unbounded_channel();
        let pump = tokio::spawn(pump(state.clone(), stack.clone(), rx));
        // Inbound blocks, service RPCs and snapshots reach their session
        // through the stack; outbound ones are attached at registration.
        stack.serve_peer_lanes();
        // The sessions those streams are served by, and that hydration,
        // repair and the convergence executor draw their content from: one
        // per authorized peer this endpoint can reach.
        let sessions = crate::peer_connectivity_runtime::keep_peer_sessions(&state, &stack);

        let driver = Arc::new(Self { stack, wake, pump, sessions });

        // A peer that reconciles with us learns the difference in both
        // directions, but only the initiating side fetches. When the side
        // that is behind is ours, the session hands the fact here and we
        // schedule our own pull through the ordinary path -- see
        // `SyncRuntime::when_behind`.
        //
        // Weak on purpose: the runtime outlives nothing here, but the driver
        // owns the stack that owns the runtime that would hold this hook, and
        // a strong reference would make that cycle keep the driver alive
        // after the daemon dropped it.
        // Weak, and nothing else captured: the driver owns the stack, the
        // stack owns the runtime, and the runtime holds this hook. Anything
        // strong in here would close that cycle and keep the whole stack
        // alive after the daemon dropped it.
        let weak = Arc::downgrade(&driver);
        driver.stack.when_behind(Arc::new(move |peer, group| {
            let Some(driver) = weak.upgrade() else {
                return;
            };
            // The hook speaks in endpoint identities; scheduling speaks in
            // devices. The netmap is what relates them, and it is read here
            // rather than remembered, so a peer unpinned since the session
            // opened resolves to nothing and schedules nothing.
            super::metrics::record_behind_wake();
            let Some(device) = driver.stack.device_for_peer(&peer) else {
                return;
            };
            driver.note_authorization(&device, &FolderGroupId(group.0));
        }));

        // The other half of that: when a pull succeeds, this device now holds
        // something its *other* peers may not. Without this, propagation is
        // one hop deep — a Change stops at the device that fetched it.
        let weak = Arc::downgrade(&driver);
        driver.stack.when_possession_grows(Arc::new(move |group: &FolderGroupId| {
            if let Some(driver) = weak.upgrade() {
                driver.note_local_change(group);
            }
        }));

        driver
    }

    /// The stack this driver drives, for callers that need to reach it
    /// directly (the admission coordinator, chiefly).
    pub fn stack(&self) -> &Arc<SyncStack> {
        &self.stack
    }

    /// Note an event. Never blocks, never fails in a way a caller must
    /// handle: if the pump is gone the daemon is shutting down, and a wake
    /// with nothing to receive it is simply a wake that buys no latency.
    pub fn note(&self, wake: Wake) {
        let _ = self.wake.send(wake);
    }

    /// Local possession of `group` changed.
    pub fn note_local_change(&self, group: &FolderGroupId) {
        self.note(Wake::Group(group.clone()));
    }

    /// `device_id` became reachable, or its address changed.
    pub fn note_peer_reachable(&self, device_id: &str) {
        self.note(Wake::Peer(device_id.to_string()));
    }

    /// The netmap now authorizes `device_id` for `group`.
    pub fn note_authorization(&self, device_id: &str, group: &FolderGroupId) {
        self.note(Wake::PeerGroup(device_id.to_string(), group.clone()));
    }
}

impl Drop for ReconciliationDriver {
    fn drop(&mut self) {
        self.pump.abort();
        self.sessions.abort();
    }
}

/// Per-(peer, group) backoff after a reconciliation attempt fails.
///
/// Found live during the 1 GiB direct-path canary: a device that had
/// accumulated a few abandoned full-replica group memberships -- still
/// authorized by the netmap, none locally linked any more, and each one
/// permanently undeletable once its device is the group's last full replica
/// (`share revoke`'s last-full-replica guard) -- saw a REAL transfer's own
/// reconciliation dial time out alongside the dead ones. [`Wake::All`]'s own
/// 30s backstop re-dispatched every authorized pair unconditionally, with no
/// memory of a pair having just failed, so a dead pair's `connect` re-spent
/// a full connect-deadline's worth of the shared `MAX_CONCURRENT_SYNCS`
/// budget on every single cycle, forever, competing with a healthy pair for
/// the exact same bounded concurrency.
///
/// Deliberately consulted only for [`Wake::All`]'s own ambient re-check, not
/// for [`Wake::Group`]/[`Wake::Peer`]/[`Wake::PeerGroup`]: those carry genuine
/// new information (a local edit, a fresh netmap grant) that is worth acting
/// on immediately regardless of how recently this exact pair last failed,
/// where the backstop is asking "anything I might have missed" with nothing
/// new to justify jumping the queue.
struct PairBackoff {
    state: std::sync::Mutex<std::collections::HashMap<(String, FolderGroupId), PairState>>,
}

struct PairState {
    attempts: u32,
    retry_after: tokio::time::Instant,
}

impl PairBackoff {
    fn new() -> Self {
        Self { state: std::sync::Mutex::new(std::collections::HashMap::new()) }
    }

    /// Whether `pair` may be attempted right now -- true for a pair with no
    /// recorded failure, or one whose backoff has already elapsed.
    fn eligible(&self, pair: &(String, FolderGroupId), now: tokio::time::Instant) -> bool {
        match self.state.lock().unwrap_or_else(|p| p.into_inner()).get(pair) {
            Some(state) => now >= state.retry_after,
            None => true,
        }
    }

    /// A pair's attempt ran (whether or not it found anything to do) --
    /// clear whatever backoff it had. Distinct from `Coalesced`/`NoAddress`,
    /// neither of which is evidence the pair is healthy: nothing new to say
    /// either way, so leave the existing backoff exactly as it was.
    fn clear(&self, pair: &(String, FolderGroupId)) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).remove(pair);
    }

    /// A pair's attempt failed -- schedule the next one no sooner than the
    /// backoff schedule allows, escalating with repeated failures.
    fn record_failure(&self, pair: (String, FolderGroupId), now: tokio::time::Instant) {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.entry(pair).or_insert(PairState { attempts: 0, retry_after: now });
        entry.retry_after =
            now + crate::supervise::BackoffConfig::DEAD_RECONCILIATION_PAIR.next(entry.attempts);
        entry.attempts = entry.attempts.saturating_add(1);
    }
}

/// Expand wakes into (peer, group) pairs and reconcile each.
async fn pump(
    state: Arc<DaemonState>,
    stack: Arc<SyncStack>,
    mut rx: mpsc::UnboundedReceiver<Wake>,
) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SYNCS));
    let backoff = Arc::new(PairBackoff::new());
    // Read once, right as this task starts: a caller sets the test override
    // (see its own doc comment) before `ReconciliationDriver::start` returns,
    // so this line's own scheduling — whichever worker thread first polls
    // this task, however soon after `tokio::spawn` handed it out — always
    // observes it.
    let mut backstop = tokio::time::interval(reconciliation_backstop_interval());
    // The construction instant already counts as the first tick; this loop's
    // own startup `Wake::All` (raised right after this pump exists, per
    // `DaemonState::install_reconciliation_driver`) already covers that
    // instant, so consume it here rather than firing a redundant expansion
    // before anything could possibly have changed.
    backstop.tick().await;

    loop {
        let wake = tokio::select! {
            wake = rx.recv() => match wake {
                Some(wake) => wake,
                None => return,
            },
            _ = backstop.tick() => Wake::All,
        };

        // Expanded here rather than at the call site, and from live netmap
        // state rather than from anything captured when the event was
        // raised. A grant revoked between the two must not still be acted
        // on, and one added must not be missed.
        //
        // Only `Wake::All`'s own ambient re-check is subject to backoff —
        // see `PairBackoff`'s own doc comment for why a targeted wake always
        // bypasses it.
        let is_ambient_recheck = matches!(wake, Wake::All);
        let pairs: Vec<(String, FolderGroupId)> = match wake {
            Wake::Group(group) => state
                .authority
                .authorized_peers_for_group(&group.0)
                .into_iter()
                .map(|peer| (peer, group.clone()))
                .collect(),
            Wake::Peer(device) => state
                .authority
                .authorized_groups_for_peer(&device)
                .into_iter()
                .map(|group| (device.clone(), FolderGroupId(group)))
                .collect(),
            Wake::PeerGroup(device, group) => vec![(device, group)],
            Wake::All => state
                .authority
                .authorized_peers_and_groups()
                .into_iter()
                .map(|(peer, group)| (peer, FolderGroupId(group)))
                .collect(),
        };

        for (peer, group) in pairs {
            // Disclosure is still decided inside the session, per group, on
            // current state — this filter only avoids dialling a peer we
            // already know we would tell nothing.
            if !state.group_is_servable(&group.0)
                || !state.authority.peer_is_writer(&peer, &group.0)
            {
                continue;
            }
            if is_ambient_recheck
                && !backoff.eligible(&(peer.clone(), group.clone()), tokio::time::Instant::now())
            {
                continue;
            }

            let Ok(slot) = slots.clone().acquire_owned().await else {
                return;
            };
            let stack = stack.clone();
            let backoff = backoff.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let pair = (peer.clone(), group.clone());
                match stack.sync_with(&peer, &group).await {
                    Ok(SyncAttempt::Ran(summary)) => {
                        backoff.clear(&pair);
                        super::metrics::record_session(summary.rounds, summary.wanted);
                        if summary.wanted == 0 {
                            return;
                        }
                        tracing::debug!(
                            peer = %peer,
                            group = %group.0,
                            wanted = summary.wanted,
                            staged = summary.staged,
                            rounds = summary.rounds,
                            "reconciled"
                        );
                    }
                    // A flight for this exact pair is already running; this
                    // call genuinely had nothing to add.
                    Ok(SyncAttempt::Coalesced) => {}
                    // The session did what it should: established that the
                    // peer is on another base and exchanged nothing. Not a
                    // failure to back off from; the claim is recorded for a
                    // merge, and asking again costs one advertisement.
                    Ok(SyncAttempt::MergeRequired) => {
                        backoff.clear(&pair);
                    }
                    // Nothing was attempted, and nothing will be until the
                    // netmap gains an address for this peer. Previously
                    // indistinguishable from coalescing, which is how a
                    // permanently unreachable peer could look healthy.
                    Ok(SyncAttempt::NoAddress) => {
                        tracing::debug!(
                            peer = %peer,
                            group = %group.0,
                            "no address for this peer; reconciliation not attempted"
                        );
                    }
                    Err(error) => {
                        // Nothing is repaired here on the spot, but this
                        // exact pairing is asked again once its backoff
                        // elapses — at the latest, by this pump's own
                        // backstop tick — and the next attempt recomputes
                        // the whole difference from durable state.
                        backoff.record_failure(pair, tokio::time::Instant::now());
                        tracing::debug!(
                            peer = %peer,
                            group = %group.0,
                            %error,
                            "reconciliation ended early"
                        );
                    }
                }
            });
        }
    }
}
