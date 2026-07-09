//! Shared, in-process state for the running daemon: the durable sync
//! index/block store (survives restarts, task 7.1), plus purely in-memory
//! bookkeeping the control socket (section 7.6/7.7) reports on — live peer
//! connectivity and per-link watcher tasks, neither of which makes sense
//! to persist.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use yadorilink_ipc_proto::shellipc::StatusPush;
use yadorilink_local_storage::BlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::peer_session::PeerSyncSession;
use yadorilink_sync_core::presence::PresenceEvent;
use yadorilink_sync_core::rate_limiter::RateLimiters;
use yadorilink_sync_core::types::FileRecord;

use crate::governance_config::GovernanceConfigStore;
use crate::link_manager::{run_disk_reconcile_backstop_sweep, run_retention_expiry_sweep};
use crate::reporting::ReportingStorage;
use crate::supervise;

/// add-file-version-history task 2.4: how often the retention-expiry sweep
/// runs — see its spawn site in `DaemonState::new` for why this is a much
/// longer interval than the other periodic sweeps in this file.
const RETENTION_EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
pub struct PeerStatusInfo {
    pub connected: bool,
    /// "direct" | "relay" | "disconnected"
    pub path_kind: String,
}

/// A presence signal received from a peer (task 9.4), plus enough to
/// decide when it's stale — `received_at_unix + ttl_seconds` in the past
/// means the sender hasn't refreshed it in a while (crashed, disconnected,
/// or genuinely stopped editing without a clean "editing stopped" signal)
/// and it should no longer be shown as "open elsewhere".
#[derive(Debug, Clone)]
pub struct ReceivedPresence {
    pub device_id: String,
    pub received_at_unix: i64,
    pub ttl_seconds: u32,
}

/// add-resource-governance task 3.4: a linked folder's Degraded
/// (disk-pressure) state — in-memory only, deliberately not persisted
/// (mirrors `paused_paths`'s "transient" rationale): it's re-derived from
/// live disk state on the very next preflight/re-check either way, so
/// persisting it across a restart would only risk it going stale.
#[derive(Debug, Clone)]
pub struct DegradedLinkInfo {
    /// Human-readable cause (the triggering `SyncError::DiskPressure`'s
    /// `Display`), shown by `yadorilink status`.
    pub reason: String,
    pub since_unix: i64,
    /// task 3.5: how many consecutive re-checks have found the link still
    /// under pressure — drives `BackoffConfig::DEGRADED_LINK_RECHECK`'s
    /// increasing interval. `0` for a link that just became degraded.
    pub backoff_attempt: u32,
    pub next_recheck_unix: i64,
}

/// This crate's own build version, parsed as semver — the "current
/// running version" `update::manifest::LocalContext` compares manifest
/// entries against. `CARGO_PKG_VERSION` is always the exact
/// `workspace.package.version` string (`Cargo.toml`), which is already
/// strict semver in this workspace, so a parse failure here would mean a
/// broken build, not a runtime condition to handle gracefully — falling
/// back to `0.0.0` (never matches any real applicable-update comparison
/// as "newer", so this fails closed to "never auto-update" rather than
/// panicking the whole daemon over a version-string typo).
fn current_crate_version() -> semver::Version {
    semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .unwrap_or_else(|_| semver::Version::new(0, 0, 0))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct DaemonState {
    pub device_id: String,
    pub sync_state: Arc<SyncState>,
    pub block_store: Arc<dyn BlockStore + Send + Sync>,
    /// device_id -> live connectivity, updated as `PeerChannel`s connect/upgrade.
    pub peer_statuses: Mutex<HashMap<String, PeerStatusInfo>>,
    /// device_id -> the running sync session, so local changes can be
    /// broadcast and (in principle) sessions torn down on ACL revocation.
    pub sessions: Mutex<HashMap<String, Arc<PeerSyncSession>>>,
    /// local_path -> the folder-watcher's tasks (the debounce accumulator
    /// and the executor that consumes its flushes — batch-sync-optimizations
    /// design D7 splits these into two independently-scheduled tasks),
    /// kept alive for as long as the link exists; all aborted together on
    /// unlink.
    pub link_tasks: Mutex<HashMap<String, Vec<JoinHandle<()>>>>,
    /// fix-local-edit-swallowed-by-self-echo-race: local_path -> that
    /// link's targeted-flush handle (task 1.1's chosen plumbing) — same
    /// key and lifetime as `link_tasks` (registered by `link_manager::
    /// start_link_watch`, removed by `stop_link_watch`). Consulted by
    /// `PendingLocalChangeFlush for DaemonState`
    /// (`link_manager::pending_local_change_flush_impl`) to find which
    /// link's debounce accumulator to ask, given a `group_id` (resolved to
    /// a `local_path` via `sync_state.list_links()`, the same lookup
    /// `peer_orchestrator::sync_roots_for_groups` already uses).
    pub link_flush_handles: Mutex<HashMap<String, Arc<crate::link_manager::LinkFlushHandle>>>,
    /// Absolute paths a shell-extension client has asked to pause
    /// individually (task 8's `ContextAction::PauseItem` — finer-grained
    /// than the whole-link pause in `SyncState`, and deliberately
    /// in-memory only: it's a transient UI action, not durable state).
    pub paused_paths: Mutex<HashSet<String>>,
    /// Fan-out for the shell-integration IPC (task 8.5): every connected
    /// shell-extension client subscribes and receives status pushes as
    /// local changes are indexed, instead of only ever answering queries.
    pub status_push_tx: broadcast::Sender<StatusPush>,
    /// Handed to every `PeerSyncSession` as its forwarding channel (see
    /// `PeerSyncSession::forward_tx`'s doc comment): a record one peer
    /// session adopts or resolves is sent here, and a background task
    /// (spawned in `new`) rebroadcasts it to this device's *other* peer
    /// sessions — full mesh propagation needs this explicit relay step.
    pub forward_tx: mpsc::UnboundedSender<(String, FileRecord)>,
    /// (group_id, path) this device is currently editing — set/cleared by
    /// `link_manager` on `LocalChangeOutcome::PresenceChanged`, consulted
    /// by the periodic TTL-refresh sweep (task 9.3) to know what's still
    /// worth re-announcing.
    pub active_local_edits: Mutex<HashSet<(String, String)>>,
    /// (group_id, path) -> the most recent presence signal *received*
    /// from a peer (task 9.4), independent of `active_local_edits` (this
    /// device's own edits never appear here, only what peers report).
    /// REL-6: entries whose TTL has elapsed are swept out of this map
    /// entirely by the periodic loop below, not just filtered out of
    /// `open_elsewhere`'s reads — otherwise a peer that signals
    /// `editing = true` and then crashes (never sending the matching
    /// `editing = false`) leaks one entry here forever.
    pub received_presence: Mutex<HashMap<(String, String), ReceivedPresence>>,
    /// Handed to every `PeerSyncSession` as its presence-forwarding
    /// channel (see `PeerSyncSession::presence_tx`'s doc comment): an
    /// incoming presence signal is sent here, and a background task
    /// (spawned in `new`) records it into `received_presence`.
    pub presence_tx: mpsc::UnboundedSender<PresenceEvent>,
    /// REL-10: group_id -> peer_device_id -> the batch of changed files
    /// most recently queued for that peer because `broadcast_change`'s
    /// `send_index_update` call failed (a transient channel/transport
    /// error, not necessarily permanent — the peer may just be
    /// mid-reconnect). The periodic retry sweep below re-attempts
    /// delivery once the peer's session is present again in `sessions`;
    /// `control_socket`'s `pending_changes_count` sums this for
    /// `yadorilink status`'s previously-hardcoded-to-0 `pending_changes`
    /// field.
    pending_changes: Mutex<HashMap<String, HashMap<String, Vec<FileRecord>>>>,
    /// REL-4 graceful-shutdown support: incremented for the duration of
    /// every `broadcast_change`/`broadcast_presence` fan-out so
    /// `main.rs`'s shutdown path can wait for in-flight broadcasts to
    /// drain (bounded by a timeout) before tearing the process down,
    /// instead of possibly cutting one off mid-send.
    in_flight_broadcasts: AtomicI64,
    /// REL-13: name -> still running, for every essential task `main.rs`
    /// supervises together (REL-8). Populated from the outside (`main.rs`
    /// sets this as it spawns/observes the exit of each task) since
    /// `DaemonState` doesn't own those tasks itself; read by the control
    /// socket's health handler.
    pub task_liveness: Mutex<HashMap<String, bool>>,
    /// REL-4: the control socket's `Shutdown` handler used to call
    /// `std::process::exit(0)` directly, a second shutdown path entirely
    /// separate from SIGTERM/SIGINT handling — neither aborted watcher
    /// tasks, checkpointed anything, or drained broadcasts. Sending `true`
    /// here instead routes it through the exact same graceful-shutdown
    /// code in `main.rs` that the signal handlers use; `main.rs` holds the
    /// matching `Receiver` (via `subscribe()`) in its top-level `select!`.
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// add-oss-usage-error-reporting: local consent/counters/error-candidate/
    /// queue storage (sections 1-2), the type section 3's IPC dispatch and
    /// severe-error hooks operate on. Opening this never writes anything
    /// to disk by itself (see `reporting::mod`'s doc comment), so adding
    /// this field is safe for every existing `DaemonState::new` call site,
    /// test or production.
    pub reporting: ReportingStorage,
    /// add-resource-governance section 5: on-disk persistence for the
    /// global rate limits / headroom override (`governance_config`'s doc
    /// comment). Opening this never writes anything to disk by itself,
    /// mirroring `reporting`'s "safe for every existing call site" property.
    pub governance_config: GovernanceConfigStore,
    /// add-resource-governance task 2.2/2.3: the single, shared upload/
    /// download token-bucket pair every `PeerSyncSession` this daemon
    /// constructs is wired to (`peer_orchestrator::spawn_peer_session`,
    /// via `PeerSyncSession::set_rate_limiters`) — this is what makes
    /// "concurrent per-peer fetches share one global ceiling" (task 2.3)
    /// true: they all draw from these exact two `Arc<TokenBucket>`
    /// instances, not independent per-session copies. Initialized from
    /// `governance_config` at construction; `apply_governance_config`
    /// re-reads config and updates these same buckets' rates in place
    /// (task 2.5's live reload) rather than replacing the `Arc`, so every
    /// already-connected session picks up a change on its very next token
    /// consumption.
    pub rate_limiters: Arc<RateLimiters>,
    /// Mirrors `enable_disk_headroom_enforcement`'s effect for the block
    /// store, but for `PeerSyncSession`s constructed *after* it's set:
    /// `peer_orchestrator::spawn_peer_session` reads this when wiring a
    /// newly-connected session's `set_headroom_enforced`. `false` by
    /// default (every test in this crate that drives real peer sessions —
    /// `multi_peer_hydration`, `e2e_three_devices`, etc. — goes through the
    /// exact same `spawn_peer_session`, so this needs the same "off unless
    /// `main.rs` opts in" default the block store gets).
    disk_headroom_enforcement_enabled: std::sync::atomic::AtomicBool,
    /// add-resource-governance task 3.4: local_path -> Degraded
    /// (disk-pressure) state for that link, entered by `mark_link_degraded`
    /// (called from wherever a `DiskPressure` error surfaces for a
    /// specific link — currently `hydration::hydrate_inner`) and cleared by
    /// the periodic re-check task spawned in `new` once a subsequent
    /// headroom check for that link's volume succeeds (task 3.5).
    pub degraded_links: Mutex<HashMap<String, DegradedLinkInfo>>,
    /// add-advanced-sync-operations section 2: bounded, in-memory
    /// dry-run-preview and audit state for folder-mode resolution actions
    /// (`crate::folder_ops`). Never persisted — a preview is only ever
    /// meaningful for the lifetime of the daemon process that computed it,
    /// and the audit trail is a diagnostic aid, not a durable record
    /// (mirrors `degraded_links`'/`paused_paths`'s own "transient,
    /// in-memory" precedent).
    pub folder_ops: crate::folder_ops::FolderOpsState,
    /// add-advanced-sync-operations section 4: bounded history of recent
    /// connection attempts (`crate::connection_trace`), feeding both the
    /// raw trace listing and the connectivity-doctor summary. Same
    /// "transient, in-memory, never persisted" treatment as `folder_ops`.
    pub connection_traces: crate::connection_trace::ConnectionTraceLog,
    /// add-observability-and-metrics section 1: bounded, in-memory
    /// per-active-transfer progress state (`crate::transfer_progress`),
    /// updated as blocks land during hydration and torn down automatically
    /// once a transfer completes, fails, or times out (its RAII guard's
    /// `Drop`). Same "transient, in-memory, never persisted" treatment as
    /// `connection_traces`.
    pub transfer_progress: crate::transfer_progress::TransferProgressTracker,
    /// add-observability-and-metrics section 2: bounded, in-memory recent
    /// sync-error ring buffer (`crate::recent_errors`), surfaced in
    /// `yadorilink status` so a stuck or failing sync is diagnosable
    /// without reading logs. Same "transient, in-memory, never persisted"
    /// treatment as `connection_traces`.
    pub recent_errors: crate::recent_errors::RecentErrorLog,
    /// add-automatic-updates task 2.1/2.2: check/download/verify/install
    /// orchestration, persisted update policy, and the pinned trust root
    /// for manifest signature verification.
    pub update_manager: Arc<crate::update::manager::UpdateManager>,
    /// add-automatic-updates task 2.4: incremented for the duration of
    /// every sync-critical write this daemon performs — the initial
    /// folder scan and every debounced flush's chunk/index/broadcast pass
    /// (`link_manager::start_link_watch`), and on-demand-sync's
    /// hydrate/evict/restore materialization writes (`hydration.rs`).
    /// Mirrors `in_flight_broadcasts` and `BroadcastGuard`'s exact
    /// counter-plus-RAII-guard shape, so a write path that returns early
    /// or panics still gets counted back out. `is_write_safe_point`
    /// (below) is exactly "this counter is zero" — install is deferred
    /// whenever it isn't, per design.md's "Safe Update Windows" decision.
    active_write_ops: AtomicI64,
    /// add-diagnostics-support-bundle task 2.2: when this `DaemonState`
    /// (i.e. this daemon process) was constructed — feeds the diagnostics
    /// bundle's coarse `daemon.uptime_bucket` field via `uptime()` below.
    /// In-memory only, like `task_liveness`/`degraded_links` above:
    /// naturally resets on every restart, which is exactly "time since
    /// this daemon started."
    started_at: std::time::Instant,
    /// add-block-store-gc task 3.1: unix seconds of the most recent
    /// local-change/peer-reconciliation/hydration activity — the idle
    /// scheduler (`gc::maybe_run_idle_sweep`) waits for this to be at
    /// least `gc::GC_IDLE_THRESHOLD` in the past before attempting a
    /// sweep. Updated by `begin_write_activity` (covers the local-change
    /// flush executor and hydration's hydrate/evict/restore paths — every
    /// existing call site of that guard) and by the forward-rebroadcast
    /// loop below (covers peer index reconciliation: a record a peer
    /// session just adopted/resolved). Initialized to "now" at
    /// construction, so a freshly-started daemon waits out a full idle
    /// period before its very first sweep rather than immediately racing
    /// startup's own link-resume/repair work.
    last_activity_unix: AtomicI64,
    /// add-block-store-gc tasks 3.2/3.4: GC scheduling coordination and
    /// last-run bookkeeping — see `gc::GcState`'s doc comment.
    pub gc: crate::gc::GcState,
}

/// RAII guard for `DaemonState::in_flight_broadcasts` — decrements on
/// drop so a broadcast that returns early (or panics) still gets counted
/// out, the same "can't forget to release" property a `MutexGuard` gives you.
struct BroadcastGuard<'a> {
    counter: &'a AtomicI64,
}

impl Drop for BroadcastGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// add-automatic-updates task 2.4: RAII guard for
/// `DaemonState::active_write_ops`, mirroring `BroadcastGuard` exactly.
pub struct WriteActivityGuard<'a> {
    counter: &'a AtomicI64,
}

impl Drop for WriteActivityGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl DaemonState {
    pub fn new(
        device_id: String,
        sync_state: Arc<SyncState>,
        block_store: Arc<dyn BlockStore + Send + Sync>,
    ) -> Arc<Self> {
        let (status_push_tx, _) = broadcast::channel(256);
        let (forward_tx, mut forward_rx) = mpsc::unbounded_channel::<(String, FileRecord)>();
        let (presence_tx, mut presence_rx) = mpsc::unbounded_channel::<PresenceEvent>();
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let governance_config = GovernanceConfigStore::new(crate::device_config::config_dir());
        // add-resource-governance task 1.1/2.1: apply whatever's on disk
        // (or the safe unlimited/no-override default if nothing's ever
        // been written) right away, so a freshly-started daemon's very
        // first session/block write already reflects a previous `limits
        // set`/headroom override rather than starting unlimited/unenforced
        // for a beat until something else calls `apply_governance_config`.
        let initial_governance = governance_config.load_or_default();
        let rate_limiters = Arc::new(RateLimiters::new(
            initial_governance.upload_limit_bytes_per_sec,
            initial_governance.download_limit_bytes_per_sec,
        ));
        // Rate limiting is always safe to wire in unconditionally (`0` =
        // unlimited = zero overhead, task 2.1), so every `DaemonState`,
        // test or production, gets the real configured/default rates.
        // Disk-headroom *enforcement* is deliberately NOT turned on here —
        // see `enable_disk_headroom_enforcement`'s doc comment for why
        // that's a separate, production-only opt-in `main.rs` calls
        // explicitly, mirroring `FsBlockStore`/`PeerSyncSession`'s own
        // "off by default" behavior at every other layer of this change.
        block_store.set_headroom_override_bytes(initial_governance.headroom_override_bytes);
        let state = Arc::new(Self {
            device_id,
            sync_state,
            block_store,
            peer_statuses: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            link_tasks: Mutex::new(HashMap::new()),
            link_flush_handles: Mutex::new(HashMap::new()),
            paused_paths: Mutex::new(HashSet::new()),
            status_push_tx,
            forward_tx,
            active_local_edits: Mutex::new(HashSet::new()),
            received_presence: Mutex::new(HashMap::new()),
            presence_tx,
            pending_changes: Mutex::new(HashMap::new()),
            in_flight_broadcasts: AtomicI64::new(0),
            task_liveness: Mutex::new(HashMap::new()),
            shutdown_tx,
            reporting: ReportingStorage::open_default(),
            governance_config,
            rate_limiters,
            disk_headroom_enforcement_enabled: std::sync::atomic::AtomicBool::new(false),
            degraded_links: Mutex::new(HashMap::new()),
            folder_ops: crate::folder_ops::FolderOpsState::new(),
            connection_traces: crate::connection_trace::ConnectionTraceLog::new(),
            transfer_progress: crate::transfer_progress::TransferProgressTracker::new(),
            recent_errors: crate::recent_errors::RecentErrorLog::new(),
            update_manager: Arc::new(crate::update::manager::UpdateManager::new(
                crate::device_config::config_dir(),
                current_crate_version(),
            )),
            active_write_ops: AtomicI64::new(0),
            started_at: std::time::Instant::now(),
            last_activity_unix: AtomicI64::new(now_unix()),
            gc: crate::gc::GcState::new(),
        });
        // add-automatic-updates task 2.5: recover from any update artifact
        // left unverified, or an install left mid-handoff, by a previous
        // run that crashed/was killed/lost power — before the periodic
        // scheduler (spawned below) or any control-socket update request
        // can observe (and potentially act on) stale state.
        state.update_manager.recover_on_startup();
        // add-automatic-updates task 2.2: periodic background update
        // checks with jitter, honoring `automatic_checks_enabled` (a
        // disabled policy just means this loop's iteration is a no-op,
        // not that the loop stops running — `yadorilink update check`
        // must still work regardless, per the spec's "Automatic checks
        // disabled" scenario). A failed check retries sooner
        // (`UPDATE_CHECK_RETRY`'s shorter, doubling backoff) than the
        // steady-state success interval (`UPDATE_CHECK_INTERVAL`).
        let update_state = state.clone();
        supervise::spawn_logged("daemon-state-update-check-scheduler", async move {
            let mut consecutive_failures: u32 = 0;
            loop {
                // design.md 2.2: "periodic update checks at daemon startup
                // and on an interval" — the startup check runs first
                // (immediately, no delay), and every subsequent iteration
                // waits out the jittered steady-state interval, or a
                // shorter jittered backoff after a failure.
                let checks_enabled =
                    update_state.update_manager.policy.load_or_default().automatic_checks_enabled;
                if checks_enabled {
                    match update_state.update_manager.check_now().await {
                        Ok(_) => consecutive_failures = 0,
                        Err(e) => {
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            tracing::warn!(error = %e, consecutive_failures, "update check failed");
                        }
                    }
                }
                let delay = if consecutive_failures == 0 {
                    supervise::BackoffConfig::UPDATE_CHECK_INTERVAL.next(0)
                } else {
                    supervise::BackoffConfig::UPDATE_CHECK_RETRY.next(consecutive_failures - 1)
                };
                tokio::time::sleep(delay).await;
            }
        });
        // add-oss-usage-error-reporting task 3.5: the background queue-retry
        // sweep, spawned unconditionally like the other periodic tasks
        // below — it is a no-op (no network call at all) until the user
        // opts into `queue_retry_enabled` and configures an endpoint, so
        // spawning it for every `DaemonState` (including test call sites)
        // is inert, matching how the presence-TTL-refresh task below is
        // already spawned unconditionally.
        crate::reporting::retry::spawn_periodic(state.clone());
        // REL-7/2.1: every one of `DaemonState`'s own background tasks
        // used to be a bare `tokio::spawn` with its `JoinHandle` dropped —
        // a panic partway through a single forwarded record or presence
        // event would silently stop mesh propagation/presence tracking
        // for the rest of the process's life with no log line at all.
        // `supervise::spawn_logged` doesn't restart these (unlike the
        // reconnect loops in `peer_orchestrator`/`yadorilink-transport`,
        // these consume an owned `mpsc::Receiver` that can't be recreated
        // per attempt the way `spawn_restarting`'s `make_task` expects),
        // but it does guarantee a loud `error`-level log naming the task
        // if it ever exits or panics, instead of a zombie behavior gap.
        let task_state = state.clone();
        supervise::spawn_logged("daemon-state-forward-rebroadcast", async move {
            while let Some((group_id, record)) = forward_rx.recv().await {
                // add-block-store-gc task 3.1: a record forwarded here is
                // exactly a peer session having just adopted/resolved an
                // incoming file — this is this crate's "peer-reconciliation
                // activity" signal for the GC idle scheduler.
                task_state.record_activity();
                task_state.broadcast_change(&group_id, vec![record]).await;
            }
            Ok(())
        });
        let presence_state = state.clone();
        supervise::spawn_logged("daemon-state-presence-record", async move {
            while let Some(event) = presence_rx.recv().await {
                presence_state.record_received_presence(event);
            }
            Ok(())
        });
        // Periodic TTL refresh (task 9.3): while a file is still in
        // `active_local_edits`, keep re-announcing it well within
        // `PRESENCE_TTL_SECS` so transient network hiccups never expire a
        // still-genuinely-open file on a peer's side. Also doubles as the
        // home for two other periodic sweeps that share the same natural
        // cadence: REL-6's expired-`received_presence` eviction and
        // REL-10's pending-broadcast retry.
        let refresh_state = state.clone();
        supervise::spawn_logged("daemon-state-presence-ttl-refresh", async move {
            loop {
                tokio::time::sleep(Duration::from_secs(
                    yadorilink_sync_core::presence::PRESENCE_REFRESH_INTERVAL_SECS,
                ))
                .await;
                let active: Vec<_> = refresh_state
                    .active_local_edits
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .iter()
                    .cloned()
                    .collect();
                for (group_id, path) in active {
                    refresh_state.broadcast_presence(&group_id, &path, true).await;
                }
                refresh_state.sweep_expired_received_presence();
                refresh_state.retry_pending_changes().await;
            }
        });
        // add-resource-governance task 3.5: a dedicated, short-interval
        // poll (not folded into the 30s presence-refresh loop above — the
        // whole point of `BackoffConfig::DEGRADED_LINK_RECHECK`'s 5s
        // *initial* interval is a link that degrades and recovers quickly
        // getting checked again promptly, not waiting out an unrelated
        // cadence) for every currently-Degraded link whose backoff window
        // has elapsed.
        let degraded_state = state.clone();
        supervise::spawn_logged("daemon-state-degraded-link-recheck", async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                degraded_state.recheck_degraded_links();
            }
        });
        // add-file-version-history task 2.4: the retention-expiry sweep —
        // "scheduled periodically ... and on daemon startup". Once
        // immediately (a daemon that was down for a while, or one whose
        // retention policy just changed, shouldn't wait a full interval
        // before its first sweep), then on a bounded interval. A
        // relatively long interval (unlike the 2s degraded-link recheck
        // above, which reacts to a transient, user-visible condition) is
        // appropriate here: retention expiry is a slow-moving housekeeping
        // concern — a version that's `RETENTION_EXPIRY_SWEEP_INTERVAL`
        // late to be swept is not a correctness problem, only a delayed
        // storage reclamation, and design.md's actual space reclamation is
        // deferred to `add-block-store-gc` regardless (this sweep only
        // ever drops the *index* row, per D5).
        run_retention_expiry_sweep(&state);
        let retention_state = state.clone();
        supervise::spawn_logged("daemon-state-retention-expiry-sweep", async move {
            loop {
                tokio::time::sleep(RETENTION_EXPIRY_SWEEP_INTERVAL).await;
                run_retention_expiry_sweep(&retention_state);
            }
        });
        // add-disk-reconcile-backstop: piggy-backs on the same cadence as
        // `PeerSyncSession`'s own periodic full-index resync
        // (`DEFAULT_FULL_INDEX_RESYNC_INTERVAL`) rather than a new,
        // independent timer — see that change's design.md for the cadence
        // trade-off. Not run once immediately at startup the way the
        // retention sweep above is: `start_link_watch`'s own initial
        // `scan_existing_files` already indexes everything present on disk
        // at daemon start, so an immediate add-only pass here would find
        // nothing new; the first sweep only matters once a watcher has had
        // a chance to miss something.
        let disk_reconcile_state = state.clone();
        supervise::spawn_logged("daemon-state-disk-reconcile-backstop-sweep", async move {
            loop {
                tokio::time::sleep(
                    yadorilink_sync_core::peer_session::DEFAULT_FULL_INDEX_RESYNC_INTERVAL,
                )
                .await;
                run_disk_reconcile_backstop_sweep(&disk_reconcile_state).await;
            }
        });
        // add-block-store-gc task 3.1/3.3: the idle-triggered GC scheduler,
        // modeled on this same `spawn_logged` periodic-task shape as every
        // other sweep in this file. Shares its poll tick with the
        // previously-uncalled `run_eviction_sweep` (task 3.3) — see
        // `gc::run_periodic_capacity_eviction_sweep`'s doc comment for why
        // that one doesn't need the same idle/write-safe-point gating GC
        // itself does.
        let gc_state = state.clone();
        supervise::spawn_logged("daemon-state-gc-idle-scheduler", async move {
            loop {
                tokio::time::sleep(crate::gc::GC_IDLE_POLL_INTERVAL).await;
                match crate::gc::maybe_run_idle_sweep(&gc_state, crate::gc::GC_IDLE_THRESHOLD).await
                {
                    None => {}
                    Some(Ok(report)) if report.blocks_deleted > 0 => {
                        tracing::info!(
                            blocks_deleted = report.blocks_deleted,
                            bytes_reclaimed = report.bytes_reclaimed,
                            "idle-triggered GC sweep reclaimed blocks"
                        );
                    }
                    Some(Ok(_)) => {}
                    // Benign: either another sweep (on-demand or this same
                    // loop's previous still-running iteration — shouldn't
                    // happen given the `.await` above, but the invariant
                    // holds either way) is in flight, or activity resumed
                    // between the idle check and the attempt.
                    Some(Err(
                        crate::gc::GcTriggerError::AlreadyRunning
                        | crate::gc::GcTriggerError::SyncBurstInProgress,
                    )) => {}
                    Some(Err(e @ crate::gc::GcTriggerError::Failed(_))) => {
                        tracing::warn!(error = %e, "idle-triggered GC sweep failed");
                    }
                }
                crate::gc::run_periodic_capacity_eviction_sweep(&gc_state);
            }
        });
        state
    }

    /// add-resource-governance task 3.4/3.5: marks `local_path` Degraded
    /// (disk-pressure), scheduling its next re-check via
    /// `BackoffConfig::DEGRADED_LINK_RECHECK` — a link already degraded has
    /// its backoff attempt count bumped (spacing repeated pressure further
    /// apart, task 3.5's "not a tight retry loop") rather than reset, and
    /// keeps its original `since_unix` onset time.
    pub fn mark_link_degraded(&self, local_path: &str, reason: String) {
        let mut degraded = self.degraded_links.lock().unwrap_or_else(|p| p.into_inner());
        let now = now_unix();
        let (since_unix, backoff_attempt) = match degraded.get(local_path) {
            Some(existing) => (existing.since_unix, existing.backoff_attempt + 1),
            None => (now, 0),
        };
        let next_recheck_unix = now
            + supervise::BackoffConfig::DEGRADED_LINK_RECHECK.next(backoff_attempt).as_secs()
                as i64;
        degraded.insert(
            local_path.to_string(),
            DegradedLinkInfo { reason, since_unix, backoff_attempt, next_recheck_unix },
        );
    }

    /// Clears `local_path`'s Degraded state, if any — a no-op if it wasn't
    /// degraded.
    pub fn clear_link_degraded(&self, local_path: &str) {
        self.degraded_links.lock().unwrap_or_else(|p| p.into_inner()).remove(local_path);
    }

    pub fn is_link_degraded(&self, local_path: &str) -> bool {
        self.degraded_links.lock().unwrap_or_else(|p| p.into_inner()).contains_key(local_path)
    }

    pub fn degraded_link_info(&self, local_path: &str) -> Option<DegradedLinkInfo> {
        self.degraded_links.lock().unwrap_or_else(|p| p.into_inner()).get(local_path).cloned()
    }

    /// task 3.5: re-checks free space for every Degraded link whose backoff
    /// window has elapsed, clearing it (task 3.4's "cleared once a
    /// subsequent headroom check for that link's volume succeeds") once
    /// the volume is no longer `Critical`, or rescheduling it (bumped
    /// backoff) if it's still under pressure. A link whose local folder no
    /// longer exists (unlinked while degraded) or whose free space can't
    /// currently be determined is left degraded rather than guessed clear.
    fn recheck_degraded_links(&self) {
        let now = now_unix();
        let due: Vec<(String, String)> = self
            .degraded_links
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(_, info)| info.next_recheck_unix <= now)
            .map(|(path, info)| (path.clone(), info.reason.clone()))
            .collect();
        if due.is_empty() {
            return;
        }
        let headroom_override = self.governance_config.load_or_default().headroom_override_bytes;
        for (local_path, reason) in due {
            let space = yadorilink_local_storage::free_space::classify_volume(
                std::path::Path::new(&local_path),
                headroom_override,
            );
            match space {
                Ok(space)
                    if space.classify()
                        != yadorilink_local_storage::free_space::FreeSpaceState::Critical =>
                {
                    tracing::info!(local_path = %local_path, "disk-pressure re-check succeeded; clearing Degraded state");
                    self.clear_link_degraded(&local_path);
                }
                _ => {
                    // Still under pressure (or undeterminable) — reschedule
                    // with a bumped backoff rather than leaving a stale
                    // `next_recheck_unix` in the past (which would make
                    // this a hot loop at the 2s poll interval).
                    self.mark_link_degraded(&local_path, reason);
                }
            }
        }
    }

    /// add-resource-governance task 2.5/5.2/5.3: re-reads the persisted
    /// governance config and applies it to the *same* shared
    /// `rate_limiters`/`block_store` instances (never replacing them) —
    /// this is what makes a `limits set`/headroom-override change take
    /// effect on already-connected sessions and the running block store
    /// without a daemon restart. Called once by `DaemonState::new` (via its
    /// own initial-load path) and again by the control socket's
    /// `limits set` / headroom-override handlers (section 5) after they
    /// persist a change.
    pub fn apply_governance_config(&self) {
        let config = self.governance_config.load_or_default();
        self.rate_limiters.upload.set_rate_bytes_per_sec(config.upload_limit_bytes_per_sec);
        self.rate_limiters.download.set_rate_bytes_per_sec(config.download_limit_bytes_per_sec);
        self.block_store.set_headroom_override_bytes(config.headroom_override_bytes);
    }

    /// add-resource-governance task 3.1/5.2: turns on the block store's
    /// disk-headroom preflight (`FsBlockStore::headroom_enforced`'s "off by
    /// default" flag) for this daemon's actual production block store.
    /// Deliberately **not** called from `DaemonState::new` itself — `new`
    /// is the one constructor every test in this crate (and
    /// `yadorilink-cli`'s daemon-backed tests) goes through too, and
    /// unconditionally enforcing the real default headroom formula against
    /// whatever this *host machine's* actual free space happens to be
    /// would make every test that writes a real block newly
    /// environment-dependent — confirmed a real, not hypothetical, risk
    /// elsewhere in this change (this dev machine is genuinely 96% full).
    /// `main.rs` calls this exactly once, right after constructing the real
    /// `DaemonState` for the `yadorilink-daemon` binary itself.
    pub fn enable_disk_headroom_enforcement(&self) {
        self.block_store.set_headroom_enforced(true);
        self.disk_headroom_enforcement_enabled.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether `enable_disk_headroom_enforcement` has been called —
    /// consulted by `peer_orchestrator::spawn_peer_session` when wiring a
    /// newly-connected session's own headroom preflight.
    pub fn disk_headroom_enforcement_enabled(&self) -> bool {
        self.disk_headroom_enforcement_enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// REL-6: drops every `received_presence` entry whose TTL has already
    /// elapsed, not just excluding it from `open_elsewhere`'s reads —
    /// otherwise a peer that signals `editing = true` and then crashes
    /// (or is killed) before ever sending the matching `editing = false`
    /// leaks one entry per such path here for the lifetime of the daemon.
    fn sweep_expired_received_presence(&self) {
        let mut received =
            self.received_presence.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = now_unix();
        let before = received.len();
        received
            .retain(|_, presence| now <= presence.received_at_unix + presence.ttl_seconds as i64);
        let removed = before - received.len();
        if removed > 0 {
            tracing::debug!(removed, "swept expired received_presence entries");
        }
    }

    /// REL-10: re-attempts delivery of every batch `broadcast_change`
    /// queued after a failed `send_index_update`, for any peer whose
    /// session is present again in `sessions` (a peer that's still
    /// disconnected is simply left queued for the next sweep — retrying
    /// against a session that doesn't exist yet would just fail the same
    /// way). Successful retries clear their entry; failures stay queued
    /// and are logged at `debug` (already logged at `warn` once, when
    /// first queued — no need to repeat that at every retry interval).
    async fn retry_pending_changes(&self) {
        let snapshot: Vec<(String, String, Vec<FileRecord>)> = {
            let pending =
                self.pending_changes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            pending
                .iter()
                .flat_map(|(group_id, per_peer)| {
                    per_peer.iter().map(|(peer_id, records)| {
                        (group_id.clone(), peer_id.clone(), records.clone())
                    })
                })
                .collect()
        };
        if snapshot.is_empty() {
            return;
        }
        for (group_id, peer_id, records) in snapshot {
            let Some(session) = self
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&peer_id)
                .cloned()
            else {
                continue; // peer still disconnected; retry next sweep
            };
            match session.send_index_update(&group_id, records).await {
                Ok(()) => self.clear_pending_change(&group_id, &peer_id),
                Err(e) => {
                    tracing::debug!(error = %e, peer = %peer_id, group_id = %group_id, "retrying queued broadcast still failing")
                }
            }
        }
    }

    fn queue_pending_change(&self, group_id: &str, peer_device_id: &str, records: Vec<FileRecord>) {
        let mut pending =
            self.pending_changes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let queued = pending
            .entry(group_id.to_string())
            .or_default()
            .entry(peer_device_id.to_string())
            .or_default();
        // Dedup by path: a newer failed batch for the same path
        // supersedes an older still-queued one for the same peer — no
        // point retrying a now-stale version once a fresher one exists.
        for record in records {
            if let Some(existing) = queued.iter_mut().find(|r| r.path == record.path) {
                *existing = record;
            } else {
                queued.push(record);
            }
        }
    }

    fn clear_pending_change(&self, group_id: &str, peer_device_id: &str) {
        let mut pending =
            self.pending_changes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(per_peer) = pending.get_mut(group_id) {
            per_peer.remove(peer_device_id);
            if per_peer.is_empty() {
                pending.remove(group_id);
            }
        }
    }

    /// `yadorilink status`'s per-folder `pending_changes` count (REL-10):
    /// total records still queued for retry across every peer for
    /// `group_id` — a path queued for two peers counts twice, matching
    /// "not yet acknowledged by every peer" from the doc comment this
    /// replaces (`control_socket.rs`'s old hardcoded `0`).
    pub fn pending_changes_count(&self, group_id: &str) -> u64 {
        let pending = self.pending_changes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        pending
            .get(group_id)
            .map(|per_peer| per_peer.values().map(|v| v.len() as u64).sum())
            .unwrap_or(0)
    }

    /// Same total as `pending_changes_count`, summed across every group —
    /// REL-13's health surface reports one process-wide number rather
    /// than per-folder detail.
    pub fn total_pending_changes(&self) -> u64 {
        let pending = self.pending_changes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.values().flat_map(|per_peer| per_peer.values()).map(|v| v.len() as u64).sum()
    }

    /// REL-4 graceful shutdown: blocks until no `broadcast_change`/
    /// `broadcast_presence` call is in flight, or `timeout` elapses,
    /// whichever comes first — best-effort draining rather than a hard
    /// guarantee (a peer session's send can itself hang on a dead
    /// connection; `yadorilink-transport`'s I/O timeouts, out of this
    /// crate's scope, bound that).
    pub async fn wait_for_broadcasts_to_drain(&self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = self.in_flight_broadcasts.load(Ordering::SeqCst);
            if remaining <= 0 {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(remaining, "timed out waiting for in-flight broadcasts to drain; proceeding with shutdown anyway");
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn begin_broadcast(&self) -> BroadcastGuard<'_> {
        self.in_flight_broadcasts.fetch_add(1, Ordering::SeqCst);
        BroadcastGuard { counter: &self.in_flight_broadcasts }
    }

    /// add-automatic-updates task 2.4: call around any sync-critical
    /// write (folder scan/flush processing in `link_manager.rs`,
    /// materialization writes in `hydration.rs`) so
    /// `is_write_safe_point` reports `false` for its duration. Public (not
    /// just crate-visible) since both call sites are in sibling modules
    /// of this same crate but need the exact same guard type
    /// `broadcast_change`'s own private `begin_broadcast` uses internally.
    pub fn begin_write_activity(&self) -> WriteActivityGuard<'_> {
        self.active_write_ops.fetch_add(1, Ordering::SeqCst);
        // add-block-store-gc task 3.1: every existing call site of this
        // guard (the local-change flush executor in `link_manager.rs`,
        // hydration's hydrate/evict/restore paths in `hydration.rs`) is
        // exactly the "local-change/hydration activity" the GC idle
        // scheduler needs to know about.
        self.record_activity();
        WriteActivityGuard { counter: &self.active_write_ops }
    }

    /// add-block-store-gc task 3.1: marks "now" as the most recent
    /// local-change/peer-reconciliation/hydration activity — see
    /// `last_activity_unix`'s doc comment for its two call sites.
    pub fn record_activity(&self) {
        self.last_activity_unix.store(now_unix(), Ordering::SeqCst);
    }

    /// add-block-store-gc task 3.1: how long it's been since the most
    /// recent recorded activity — the GC idle scheduler's own condition is
    /// exactly `idle_duration() >= gc::GC_IDLE_THRESHOLD`.
    pub fn idle_duration(&self) -> Duration {
        let last = self.last_activity_unix.load(Ordering::SeqCst);
        Duration::from_secs(now_unix().saturating_sub(last).max(0) as u64)
    }

    /// Test-only escape hatch: production code only ever calls
    /// `record_activity()` (always "now"); tests simulating having been
    /// idle for a while need to set an arbitrary past timestamp directly,
    /// without literally waiting out `gc::GC_IDLE_THRESHOLD`.
    #[cfg(test)]
    pub(crate) fn set_last_activity_unix_for_test(&self, unix: i64) {
        self.last_activity_unix.store(unix, Ordering::SeqCst);
    }

    /// design.md "Safe Update Timing": `true` exactly when no
    /// sync-critical write is currently in progress — the sole condition
    /// `update_ipc::install`/the periodic install-safe-point check
    /// (task 2.4) uses to decide whether to proceed or defer.
    pub fn is_write_safe_point(&self) -> bool {
        self.active_write_ops.load(Ordering::SeqCst) <= 0
    }

    /// add-diagnostics-support-bundle task 2.2: wall-clock time elapsed
    /// since this `DaemonState` was constructed — i.e. since this daemon
    /// process started. Used only to bucket `daemon.uptime_bucket` in the
    /// diagnostics bundle (`diagnostics_ipc::uptime_bucket`); never
    /// exposed as an exact duration anywhere reportable, matching this
    /// codebase's existing "coarse bucket, not an exact value"
    /// convention for anything that ends up in a report/bundle (see
    /// `UsagePayload.daemon_uptime_bucket`'s doc comment).
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// REL-13 health surface: records whether essential task `name` is
    /// currently running, from the outside (`main.rs` owns the essential
    /// `JoinSet`/REL-8 supervision itself; this is just where the result
    /// is published for `control_socket`'s health handler to read).
    pub fn set_task_alive(&self, name: &str, alive: bool) {
        self.task_liveness
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(name.to_string(), alive);
    }

    /// Broadcasts a batch of locally-changed files to every
    /// currently-connected peer session authorized for `group_id` (task
    /// 5.5's propagation half — see `peer_session::PeerSyncSession::shares_group`
    /// for why this filter matters, not just efficiency), as a single
    /// `IndexUpdate` wire message per peer rather than one message per
    /// file (batch-sync-optimizations design D5). A no-op for an empty batch.
    ///
    /// REL-10: a peer whose `send_index_update` call fails has its batch
    /// queued in `pending_changes` for the periodic retry sweep
    /// (`retry_pending_changes`) instead of being silently dropped.
    pub async fn broadcast_change(
        &self,
        group_id: &str,
        records: Vec<yadorilink_sync_core::types::FileRecord>,
    ) {
        if records.is_empty() {
            return;
        }
        let _in_flight = self.begin_broadcast(); // REL-4: let shutdown wait for this to finish
        let sessions: Vec<(String, Arc<PeerSyncSession>)> = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(id, s)| (id.clone(), s.clone()))
            .collect();
        for (peer_id, session) in sessions {
            if session.shares_group(group_id) {
                match session.send_index_update(group_id, records.clone()).await {
                    Ok(()) => self.clear_pending_change(group_id, &peer_id),
                    Err(e) => {
                        tracing::warn!(error = %e, peer = %peer_id, "failed to broadcast local changes to peer; queued for retry");
                        self.queue_pending_change(group_id, &peer_id, records.clone());
                    }
                }
            }
        }
    }

    /// Sends an edit-presence signal (task 9.3) to every currently-connected
    /// peer session authorized for `group_id` — the same fan-out shape as
    /// `broadcast_change`, for the presence-signal wire message instead.
    /// Presence signals are inherently ephemeral (superseded by the next
    /// refresh or an explicit "editing stopped") so, unlike file changes,
    /// a failed send here isn't queued for retry — only counted for
    /// REL-4's in-flight drain.
    pub async fn broadcast_presence(&self, group_id: &str, path: &str, editing: bool) {
        let _in_flight = self.begin_broadcast();
        let sessions: Vec<_> = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect();
        for session in sessions {
            if session.shares_group(group_id) {
                if let Err(e) = session
                    .send_presence_signal(
                        group_id,
                        path,
                        editing,
                        yadorilink_sync_core::presence::PRESENCE_TTL_SECS,
                    )
                    .await
                {
                    tracing::warn!(error = %e, "failed to broadcast presence signal to peer");
                }
            }
        }
    }

    fn record_received_presence(&self, event: PresenceEvent) {
        let key = (event.group_id, event.path);
        let mut received =
            self.received_presence.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if event.editing {
            received.insert(
                key,
                ReceivedPresence {
                    device_id: event.device_id,
                    received_at_unix: now_unix(),
                    ttl_seconds: event.ttl_seconds,
                },
            );
        } else {
            received.remove(&key);
        }
    }

    /// Whether `(group_id, path)` is currently reported open by another
    /// device, and not stale (task 9.4) — `None` if never reported, was
    /// explicitly reported closed, or the last signal's TTL has elapsed
    /// with no refresh.
    pub fn open_elsewhere(&self, group_id: &str, path: &str) -> Option<String> {
        let received =
            self.received_presence.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let presence = received.get(&(group_id.to_string(), path.to_string()))?;
        let expires_at = presence.received_at_unix + presence.ttl_seconds as i64;
        if now_unix() > expires_at {
            return None;
        }
        Some(presence.device_id.clone())
    }

    /// How many files in `group_id` are currently reported open elsewhere
    /// and not stale (task 9.4) — `yadorilink status`'s per-folder summary,
    /// the same "count, don't enumerate" shape as `conflict_count`.
    pub fn open_elsewhere_count(&self, group_id: &str) -> u64 {
        let received =
            self.received_presence.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = now_unix();
        received
            .iter()
            .filter(|((g, _), presence)| {
                g == group_id && now <= presence.received_at_unix + presence.ttl_seconds as i64
            })
            .count() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_local_storage::FsBlockStore;

    /// `YADORILINK_CONFIG_DIR` is a process-global env var (same pattern
    /// used by `tests/reporting_ipc.rs` and `yadorilink-cli`'s
    /// `tests/materialization.rs`) — every test in this module that
    /// touches it holds this mutex for its whole body, so concurrently-
    /// running tests in this same lib test binary never observe each
    /// other's override. Shared with `device_config.rs` and
    /// `reporting/retry.rs` (see `crate::test_support`'s doc comment) —
    /// a module-local mutex here alone does not serialize against those
    /// other modules' own tests touching the same env var.
    use crate::test_support::CONFIG_ENV_MUTEX;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        DaemonState::new("device-a".into(), sync_state, store)
    }

    /// task 9.4 / edit-presence-awareness spec "Stale presence signals
    /// expire": a signal whose TTL has elapsed since it was received (no
    /// refresh arrived in time) must no longer be reported as open.
    #[tokio::test]
    async fn stale_presence_signal_is_not_reported_as_open_elsewhere() {
        let state = test_state();
        state.received_presence.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(
            ("group-1".to_string(), "report.docx".to_string()),
            ReceivedPresence {
                device_id: "device-b".into(),
                received_at_unix: now_unix() - 100,
                ttl_seconds: 10, // expired 90 seconds ago
            },
        );

        assert_eq!(state.open_elsewhere("group-1", "report.docx"), None);
        assert_eq!(state.open_elsewhere_count("group-1"), 0);
    }

    /// The mirror case: a signal still within its TTL is reported open.
    #[tokio::test]
    async fn fresh_presence_signal_is_reported_as_open_elsewhere() {
        let state = test_state();
        state.received_presence.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(
            ("group-1".to_string(), "report.docx".to_string()),
            ReceivedPresence {
                device_id: "device-b".into(),
                received_at_unix: now_unix(),
                ttl_seconds: 90,
            },
        );

        assert_eq!(state.open_elsewhere("group-1", "report.docx"), Some("device-b".to_string()));
        assert_eq!(state.open_elsewhere_count("group-1"), 1);
    }

    /// task 9.4: an explicit "editing stopped" event clears the entry
    /// immediately, not just letting it expire naturally.
    #[tokio::test]
    async fn editing_stopped_event_clears_presence_immediately() {
        let state = test_state();
        state.record_received_presence(PresenceEvent {
            group_id: "group-1".into(),
            path: "report.docx".into(),
            device_id: "device-b".into(),
            editing: true,
            ttl_seconds: 90,
        });
        assert_eq!(state.open_elsewhere("group-1", "report.docx"), Some("device-b".to_string()));

        state.record_received_presence(PresenceEvent {
            group_id: "group-1".into(),
            path: "report.docx".into(),
            device_id: "device-b".into(),
            editing: false,
            ttl_seconds: 90,
        });
        assert_eq!(state.open_elsewhere("group-1", "report.docx"), None);
    }

    // --- add-resource-governance task 3.6: Degraded-link state tests ----

    /// task 3.6: a link enters Degraded on disk pressure — `is_link_degraded`
    /// flips true and the reason is recorded.
    #[tokio::test]
    async fn mark_link_degraded_makes_the_link_report_degraded_with_a_reason() {
        let state = test_state();
        assert!(!state.is_link_degraded("/links/photos"));

        state.mark_link_degraded("/links/photos", "disk pressure on /links/photos".to_string());

        assert!(state.is_link_degraded("/links/photos"));
        let info = state.degraded_link_info("/links/photos").unwrap();
        assert_eq!(info.reason, "disk pressure on /links/photos");
        assert_eq!(info.backoff_attempt, 0);
    }

    /// task 3.6: a link leaves Degraded once cleared — the mirror case,
    /// and the trigger `hydration::hydrate_inner`'s success path uses
    /// directly (a snappier recovery signal beyond the periodic re-check).
    #[tokio::test]
    async fn clear_link_degraded_removes_the_entry() {
        let state = test_state();
        state.mark_link_degraded("/links/photos", "disk pressure".to_string());
        assert!(state.is_link_degraded("/links/photos"));

        state.clear_link_degraded("/links/photos");
        assert!(!state.is_link_degraded("/links/photos"));
        // Clearing an already-clear (or never-degraded) link is a safe no-op.
        state.clear_link_degraded("/links/photos");
        assert!(!state.is_link_degraded("/links/photos"));
    }

    /// task 3.5/3.6: repeated disk pressure on the same link produces
    /// backoff re-checks, not a tight retry loop — each re-mark bumps the
    /// backoff attempt count and pushes `next_recheck_unix` further out
    /// (via `BackoffConfig::DEGRADED_LINK_RECHECK`'s doubling schedule),
    /// rather than resetting to the same short interval every time.
    #[tokio::test]
    async fn repeated_disk_pressure_increases_backoff_instead_of_resetting_it() {
        let state = test_state();
        state.mark_link_degraded("/links/photos", "disk pressure".to_string());
        let first = state.degraded_link_info("/links/photos").unwrap();
        assert_eq!(first.backoff_attempt, 0);

        state.mark_link_degraded("/links/photos", "disk pressure".to_string());
        let second = state.degraded_link_info("/links/photos").unwrap();
        assert_eq!(second.backoff_attempt, 1);
        assert!(
            second.next_recheck_unix >= first.next_recheck_unix,
            "backoff must not shrink on repeated pressure"
        );
        // The original onset time is preserved across re-marks, not reset —
        // `yadorilink status` should be able to report how long a link has
        // been degraded, not just "since the last re-check."
        assert_eq!(second.since_unix, first.since_unix);

        state.mark_link_degraded("/links/photos", "disk pressure".to_string());
        let third = state.degraded_link_info("/links/photos").unwrap();
        assert_eq!(third.backoff_attempt, 2);
        assert!(third.next_recheck_unix >= second.next_recheck_unix);
    }

    /// task 3.4: a Degraded link recovers once its volume's free-space
    /// check succeeds again — exercised through the real periodic
    /// `recheck_degraded_links` sweep (not just the mark/clear API
    /// directly), using an isolated `YADORILINK_CONFIG_DIR` so this test's
    /// governance config never touches the real host config directory
    /// (same pattern `tests/reporting_ipc.rs` already established for this
    /// exact env var).
    #[tokio::test]
    async fn recheck_degraded_links_clears_a_link_once_headroom_check_succeeds() {
        let _guard = CONFIG_ENV_MUTEX.lock().await;
        let config_dir = tempfile::tempdir().unwrap();
        std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());

        let state = test_state();
        let link_root = tempfile::tempdir().unwrap();
        let link_path = link_root.path().to_string_lossy().to_string();

        // Mark the link degraded directly (bypassing a real preflight
        // call) so this test only exercises the re-check/clear half.
        state.mark_link_degraded(&link_path, "disk pressure".to_string());
        assert!(state.is_link_degraded(&link_path));

        // A headroom override of `0` ("no headroom required") always
        // classifies as `Ok` for any real volume — configuring it via the
        // same `GovernanceConfigStore` `recheck_degraded_links` itself
        // reads simulates "space was freed" without needing a real
        // multi-gigabyte write.
        state.governance_config.set_headroom_override_bytes(Some(0)).unwrap();
        // Force the entry's backoff window to be due right now (avoids
        // this test waiting out even the 5s initial backoff).
        state
            .degraded_links
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&link_path)
            .unwrap()
            .next_recheck_unix = now_unix() - 1;

        state.recheck_degraded_links();

        assert!(
            !state.is_link_degraded(&link_path),
            "expected the link to clear once headroom check succeeds"
        );

        std::env::remove_var("YADORILINK_CONFIG_DIR");
    }

    /// task 3.4: the mirror case — a link stays Degraded (rescheduled with
    /// bumped backoff, not cleared) when its volume is still under
    /// pressure at re-check time.
    #[tokio::test]
    async fn recheck_degraded_links_reschedules_a_link_still_under_pressure() {
        let _guard = CONFIG_ENV_MUTEX.lock().await;
        let config_dir = tempfile::tempdir().unwrap();
        std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());

        let state = test_state();
        let link_root = tempfile::tempdir().unwrap();
        let link_path = link_root.path().to_string_lossy().to_string();

        state.mark_link_degraded(&link_path, "disk pressure".to_string());
        // A headroom override far larger than any real disk's free space
        // keeps this link `Critical` no matter what.
        state.governance_config.set_headroom_override_bytes(Some(u64::MAX / 2)).unwrap();
        state
            .degraded_links
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&link_path)
            .unwrap()
            .next_recheck_unix = now_unix() - 1;
        let before = state.degraded_link_info(&link_path).unwrap();

        state.recheck_degraded_links();

        assert!(state.is_link_degraded(&link_path), "still under pressure — must stay degraded");
        let after = state.degraded_link_info(&link_path).unwrap();
        assert!(
            after.backoff_attempt > before.backoff_attempt,
            "a still-failing re-check must bump backoff, not just repeat the same window"
        );

        std::env::remove_var("YADORILINK_CONFIG_DIR");
    }

    // --- add-crash-power-loss-recovery task 2.4/3.4: interrupted-update
    // recovery is wired into the exact same daemon-startup entry point
    // (`DaemonState::new`, the one `main.rs` calls before any watcher
    // resumes or any control-socket request can arrive) as this change's
    // own `cleanup_stale_temp_files`/`repair_interrupted_materializations`
    // calls. `add-automatic-updates` task 2.5 already built
    // `UpdateManager::recover_on_startup` and its own unit tests
    // (`update::manager::tests::recover_on_startup_*`) call it directly;
    // these two tests instead go through the real `DaemonState::new` used
    // by `main.rs`, with the on-disk `update_policy.json`/artifact state
    // written exactly as a crash would leave it (matching this change's
    // established "simulate the exact on-disk state a crash would leave"
    // standard from `materialization.rs`'s own crash tests), proving the
    // wiring itself rather than re-proving `recover_on_startup`'s own logic.

    /// Simulates a crash partway through downloading an update artifact:
    /// a stray `.partial` file on disk and a persisted policy still
    /// claiming `Downloading` with that path recorded, exactly what
    /// `UpdateManager::download_and_verify` would leave behind if the
    /// process died mid-transfer. A fresh daemon startup
    /// (`DaemonState::new`) must discard it before anything else can
    /// observe or act on the stale state.
    #[tokio::test]
    async fn daemon_startup_discards_an_unverified_download_left_by_a_crash() {
        let _guard = CONFIG_ENV_MUTEX.lock().await;
        let config_dir = tempfile::tempdir().unwrap();
        std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());

        let updates_dir = config_dir.path().join("updates");
        std::fs::create_dir_all(&updates_dir).unwrap();
        let partial = updates_dir.join("yadorilink-0.2.0.pkg.partial");
        std::fs::write(&partial, b"not yet verified - crash mid-download").unwrap();
        crate::update::policy::UpdatePolicyStore::new(config_dir.path())
            .save(&crate::update::policy::UpdatePolicy {
                state: crate::update::policy::UpdateState::Downloading,
                downloaded_artifact_path: Some(partial.clone()),
                downloaded_artifact_verified: false,
                ..Default::default()
            })
            .unwrap();

        // The real entry point `main.rs` calls at startup — not calling
        // `UpdateManager::recover_on_startup` directly.
        let state = test_state();

        assert!(
            !partial.exists(),
            "a crashed, never-verified download must be discarded on startup"
        );
        let policy = state.update_manager.policy.load().unwrap();
        assert_eq!(policy.state, crate::update::policy::UpdateState::Failed);
        assert!(!policy.downloaded_artifact_verified);
        assert_eq!(policy.downloaded_artifact_path, None);
        assert_eq!(policy.last_error_category.as_deref(), Some("update_interrupted_download"));

        std::env::remove_var("YADORILINK_CONFIG_DIR");
    }

    /// The mirror case: a crash partway through the install handoff
    /// (`UpdateManager::install_now` had already moved the policy to
    /// `Installing` before invoking the platform installer) must never be
    /// read by the next startup as a successful update — it must come
    /// back up recording `Failed`/`update_interrupted_install`, never
    /// silently assumed to have succeeded.
    #[tokio::test]
    async fn daemon_startup_marks_a_mid_install_crash_as_failed_not_successful() {
        let _guard = CONFIG_ENV_MUTEX.lock().await;
        let config_dir = tempfile::tempdir().unwrap();
        std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());

        crate::update::policy::UpdatePolicyStore::new(config_dir.path())
            .save(&crate::update::policy::UpdatePolicy {
                state: crate::update::policy::UpdateState::Installing,
                ..Default::default()
            })
            .unwrap();

        let state = test_state();

        let policy = state.update_manager.policy.load().unwrap();
        assert_eq!(policy.state, crate::update::policy::UpdateState::Failed);
        assert_eq!(policy.last_error_category.as_deref(), Some("update_interrupted_install"));

        std::env::remove_var("YADORILINK_CONFIG_DIR");
    }
}
