//! Shared, in-process state for the running daemon: the durable sync
//! index/block store (survives restarts), plus purely in-memory
//! bookkeeping the control socket (section 7.6/7.7) reports on — live peer
//! connectivity and per-link watcher tasks, neither of which makes sense
//! to persist.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use yadorilink_ipc_proto::shellipc::StatusPush;
use yadorilink_local_storage::BlockStore;
use yadorilink_sync_core::block_liveness::{
    BlockLivenessGate, BlockPhysicalDeletionGuard, BlockReferenceWriteGuard,
};
use yadorilink_sync_core::change::{ChangeAuth, PolicyUnavailable, VersionBlock, VersionHash};
use yadorilink_sync_core::custody::{CustodyStamp, FullReplicaCustody};
use yadorilink_sync_core::index::{
    DurabilityRoot, DurabilityRoots, HandoffLeaseState, RoleLossAction, RoleLossOperationState,
    SyncState,
};
use yadorilink_sync_core::peer_session::{
    BlockWriteActivityProvider, HandoffLeaseResponder, HandoffTicketResponder,
    PeerHandoffLeaseGrant, PeerHandoffTicketGrant, PeerSyncSession,
};
use yadorilink_sync_core::rate_limiter::RateLimiters;
use yadorilink_sync_core::types::FileRecord;

use crate::change_policy::GroupPolicyState;
use crate::governance_config::GovernanceConfigStore;
use crate::link_manager::{run_disk_reconcile_backstop_sweep, run_retention_expiry_sweep};
use crate::reporting::ReportingStorage;
use crate::supervise;

/// How often the retention-expiry sweep
/// runs — see its spawn site in `DaemonState::new` for why this is a much
/// longer interval than the other periodic sweeps in this file.
const RETENTION_EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
const MATERIALIZATION_REPAIR_SWEEP_INTERVAL: Duration = Duration::from_secs(90);
/// How often the role-loss-operation reconciliation sweep
/// (`run_role_loss_reconciliation_sweep`) retries any journal row left
/// mid-flight by a crash or a compensation attempt that couldn't reach the
/// coordination plane. Matches `MATERIALIZATION_REPAIR_SWEEP_INTERVAL`'s
/// cadence rather than the much longer retention-expiry one: a role-loss
/// split state is a user-visible correctness gap the same way a broken
/// materialization is, not a slow-moving housekeeping concern.
const ROLE_LOSS_RECONCILIATION_SWEEP_INTERVAL: Duration = Duration::from_secs(90);
/// Past this many compensation attempts for the same role-loss operation,
/// the sweep escalates its log level from `warn` to `error` — a visibility
/// aid only. The row itself is never abandoned or deleted regardless of how
/// many attempts it has accrued; see `DaemonState::compensate_role_loss_
/// operation`'s doc comment.
const ROLE_LOSS_COMPENSATION_ESCALATION_ATTEMPTS: i64 = 5;
/// Overall bound on `confirm_version_present_via_peer`'s concurrent fan-out
/// across every candidate peer. Each individual `request_version_present`
/// already enforces its own ~10s per-request timeout (`peer_session.rs`), and
/// every candidate is now queried concurrently rather than one after another,
/// so the realistic wall-clock cost of a full sweep is already that single
/// ~10s window regardless of how many peers are queried — not the old
/// N-peers-times-10s worst case. This wraps the whole fan-out in one slightly
/// longer timeout anyway, as a defense-in-depth backstop, rather than relying
/// solely on each query's own internal bound.
const VERSION_PRESENT_QUERY_OVERALL_TIMEOUT: Duration = Duration::from_secs(12);

/// Why a peer could not be connected. Rendered by the CLI and desktop app
/// as the reason a peer "cannot connect", and mapped verbatim onto the
/// control socket's peer-status wire fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachableCategory {
    /// No candidate address to try at all (no endpoints learned).
    NoCandidates,
    /// Candidates were probed but stayed silent — most often a symmetric
    /// NAT or CGNAT pair that cannot be traversed.
    NoResponse,
    /// No datagram could get out at all (even local/STUN probes failed).
    UdpBlocked,
    /// The peer answered but refused the handshake — a key or
    /// authorization mismatch, distinct from being unreachable on the
    /// network.
    HandshakeRefused,
}

impl UnreachableCategory {
    /// Stable wire/status slug.
    pub fn as_str(self) -> &'static str {
        match self {
            UnreachableCategory::NoCandidates => "no_candidates",
            UnreachableCategory::NoResponse => "no_response",
            UnreachableCategory::UdpBlocked => "udp_blocked",
            UnreachableCategory::HandshakeRefused => "handshake_refused",
        }
    }
}

/// A peer's live connectivity as tracked by the daemon and reported to the
/// CLI and desktop app. There is no operator-run relay: a peer is either
/// being connected, connected over a confirmed direct path, or cannot be
/// connected at all (with the reason it can't).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerReachability {
    /// Candidate paths are still being raced; not yet connected, but not
    /// yet given up on either.
    Connecting,
    /// A direct path to the peer is confirmed and in use.
    Connected,
    /// Transport is up, but sync protocol negotiation completed without the
    /// mandatory change-DAG capability.
    ProtocolIncompatible,
    /// The peer cannot currently be reached; carries why.
    Unreachable(UnreachableCategory),
}

impl PeerReachability {
    pub fn is_connected(self) -> bool {
        matches!(self, PeerReachability::Connected)
    }

    /// Stable wire/status slug: "connecting" | "connected" | "unreachable".
    pub fn as_str(self) -> &'static str {
        match self {
            PeerReachability::Connecting => "connecting",
            PeerReachability::Connected => "connected",
            PeerReachability::ProtocolIncompatible => "protocol_incompatible",
            PeerReachability::Unreachable(_) => "unreachable",
        }
    }

    /// The failure-category slug when unreachable, otherwise empty.
    pub fn unreachable_category_str(self) -> &'static str {
        match self {
            PeerReachability::Unreachable(category) => category.as_str(),
            PeerReachability::ProtocolIncompatible => "",
            _ => "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerStatusInfo {
    pub reachability: PeerReachability,
}

/// This device's local, UI-facing view of one group's durability — distinct
/// from the coordination-plane member/share count (which only tracks who is
/// *configured* to sync a group, not who durably holds its data right now)
/// and distinct from `DegradedLinkInfo` below (that's disk pressure, an
/// orthogonal axis). Answers "how safe is my data right now, from what this
/// daemon can currently confirm" — and must never overstate safety: a group
/// this daemon has no current basis to back up with a real confirmation
/// reports `DurabilityUnknown`, never `Healthy`.
///
/// See [`DaemonState::group_durability_status`] for how the unlatched
/// default is derived, and [`DaemonState::latch_group_durability_unknown`]
/// for the one place that pins a group to `DurabilityUnknown` regardless of
/// what it would otherwise derive to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupDurabilityStatus {
    /// This device or a confirmed peer is a whole-group full replica for
    /// the group's current head.
    Healthy,
    /// Configured for this group but still catching up to head (not every
    /// file materialized yet).
    Syncing,
    /// Coverage cannot currently be confirmed — most notably, right after a
    /// `--force` override bypassed the durability handoff gate for this
    /// group, until a later handoff check positively reconfirms whole-group
    /// coverage. The fail-safe default whenever this daemon has no other
    /// basis to report from either.
    DurabilityUnknown,
    /// A current file is confirmed to have no durable holder reachable
    /// anywhere — a positive negative, not merely "unconfirmed."
    KnownMissing,
}

/// A linked folder's Degraded
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
    /// how many consecutive re-checks have found the link still
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

fn spawn_materialization_repair_scheduler(state: Arc<DaemonState>) {
    supervise::spawn_logged("daemon-state-materialization-repair", async move {
        let mut interval = tokio::time::interval(MATERIALIZATION_REPAIR_SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let groups: HashSet<String> = match state.sync_state.list_links() {
                // An orphaned link's coordination-side authorization is
                // confirmed gone, so there is no valid peer edge left to
                // request a repair from -- skip it the same way a paused
                // link's watcher already keeps it out of this set in
                // practice (no `LinkFlushHandle` to drive repair against).
                Ok(links) => links
                    .into_iter()
                    .filter(|link| !link.orphaned)
                    .map(|link| link.group_id)
                    .collect(),
                Err(e) => {
                    tracing::warn!(error = %e, "materialization repair failed to list links");
                    continue;
                }
            };
            for group_id in groups {
                state.backfill_missing_change_history(&group_id).await;
                let candidates = {
                    let sessions = state.sessions.lock().unwrap_or_else(|p| p.into_inner());
                    let mut candidates: Vec<_> = sessions
                        .iter()
                        .filter(|(_, session)| session.shares_group(&group_id))
                        .map(|(peer_id, session)| (peer_id.clone(), session.clone()))
                        .collect();
                    candidates.sort_by(|a, b| a.0.cmp(&b.0));
                    candidates
                };
                if candidates.is_empty() {
                    continue;
                }
                let start = {
                    let mut cursors = state
                        .materialization_repair_cursors
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    let cursor = cursors.entry(group_id.clone()).or_insert(0);
                    let start = *cursor % candidates.len();
                    *cursor = (start + 1) % candidates.len();
                    start
                };
                let mut last_error = None;
                for offset in 0..candidates.len() {
                    let (peer_id, session) = &candidates[(start + offset) % candidates.len()];
                    match session.clone().reconcile_local_materialization_audit(&group_id).await {
                        Ok(()) => {
                            last_error = None;
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(
                                group_id,
                                peer = %peer_id,
                                error = %e,
                                "materialization repair peer failed; trying another peer"
                            );
                            last_error = Some(e);
                        }
                    }
                }
                if let Some(e) = last_error {
                    tracing::warn!(
                        group_id,
                        error = %e,
                        "materialization repair failed for every available peer"
                    );
                }
            }
        }
    });
}

/// Fix-saga: the startup + periodic reconciliation sweep for the role-loss
/// operation journal (`yadorilink_sync_core::index::RoleLossOperation`).
/// Scans every journal row regardless of which group it names and, per row:
///
/// - `LocalCommitted`/`Completed` (terminal): the operation's real outcome
///   was already reached by the write that landed this state; only the
///   follow-up delete never ran (a crash in that narrow window). Just
///   finishes the delete — no coordination-plane call needed.
/// - `Prepared`/`WorkerCommitted`/`Compensating`: every one of these means
///   this process cannot be sure the local change ever landed while the
///   Worker might already have committed the role loss (or, for
///   `Compensating`, a previous revert attempt itself didn't complete) — see
///   [`yadorilink_sync_core::index::RoleLossOperationState::Prepared`]'s doc
///   comment for why treating `Prepared` the same as `WorkerCommitted` here
///   is safe. All three are handed to
///   [`DaemonState::compensate_role_loss_operation`], which reverts the
///   source device back to `eager` on the coordination plane — the safe
///   direction (see that method's doc comment) — and is itself idempotent
///   and safe to call repeatedly.
///
/// Errors from an individual row's compensation attempt are logged (by
/// `compensate_role_loss_operation` itself) and otherwise swallowed here: a
/// row that can't be compensated this pass simply survives to the next
/// sweep, never abandoned.
///
/// `pub` (rather than the crate-private visibility every other call site in
/// this file gets) so integration tests can invoke exactly this function
/// directly and deterministically, instead of racing or waiting out
/// `ROLE_LOSS_RECONCILIATION_SWEEP_INTERVAL`'s real-time periodic spawn in
/// `DaemonState::new` — the same production entry point either way.
pub async fn run_role_loss_reconciliation_sweep(state: &Arc<DaemonState>) {
    let rows = match state.sync_state.list_role_loss_operations_in_states(&[
        RoleLossOperationState::Prepared,
        RoleLossOperationState::WorkerCommitted,
        RoleLossOperationState::LocalCommitted,
        RoleLossOperationState::Compensating,
        RoleLossOperationState::Completed,
    ]) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "role-loss reconciliation sweep failed to list journal rows");
            return;
        }
    };
    for op in rows {
        match op.state {
            RoleLossOperationState::LocalCommitted | RoleLossOperationState::Completed => {
                if let Err(e) = state.sync_state.delete_role_loss_operation(&op.operation_id) {
                    tracing::warn!(
                        error = %e,
                        operation_id = %op.operation_id,
                        "role-loss reconciliation sweep failed to delete a settled journal row"
                    );
                }
            }
            RoleLossOperationState::Prepared
            | RoleLossOperationState::WorkerCommitted
            | RoleLossOperationState::Compensating => {
                match state.compensate_role_loss_operation(&op.operation_id).await {
                    Ok(()) => {
                        tracing::info!(
                            operation_id = %op.operation_id,
                            group_id = %op.group_id,
                            "role-loss reconciliation sweep compensated an in-flight operation"
                        );
                    }
                    Err(_) => {
                        // Already logged inside `compensate_role_loss_operation`; the row
                        // stays `Compensating` for the next sweep to retry.
                    }
                }
            }
        }
    }
}

/// Confirms whether a full replica durably holds an exact file version — bound
/// by its `change::VersionHash`, with the ordered block list carried alongside
/// for the responder's explicit block/size check and `get()` verification —
/// so an on-demand device may reclaim its own cached copy. Injected onto
/// [`DaemonState`] so production performs the peer-to-peer version-present query
/// while unit tests supply a deterministic answer without a live peer.
pub trait CustodyConfirmer: Send + Sync {
    fn confirms_present(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp>;

    fn confirmation_still_valid(&self, group_id: &str, stamp: &CustodyStamp) -> bool;
}

#[cfg(test)]
impl<F: Fn(&str, &str, &VersionHash, &[VersionBlock]) -> bool + Send + Sync> CustodyConfirmer
    for F
{
    fn confirms_present(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        self(group_id, path, version_hash, blocks).then(|| CustodyStamp::new("test-peer".into(), 0))
    }

    fn confirmation_still_valid(&self, _group_id: &str, _stamp: &CustodyStamp) -> bool {
        true
    }
}

/// Production custody confirmer: performs the peer-to-peer version-present query
/// via [`DaemonState::confirm_version_present_via_peer`]. The eviction sweep is
/// synchronous, so this bridges to the async query with `block_in_place` —
/// valid because the daemon runs on a multi-threaded runtime and the sweep is
/// driven from an async task. Holds a weak reference so it never keeps the
/// daemon alive.
struct P2pCustodyConfirmer {
    state: std::sync::Weak<DaemonState>,
}

impl CustodyConfirmer for P2pCustodyConfirmer {
    fn confirms_present(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        let Some(state) = self.state.upgrade() else {
            return None;
        };
        let group_id = group_id.to_string();
        let path = path.to_string();
        let version_hash = *version_hash;
        let blocks = blocks.to_vec();
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move {
                state
                    .confirm_version_present_witness_via_peer(
                        &group_id,
                        &path,
                        version_hash,
                        &blocks,
                    )
                    .await
            })
        })
    }

    fn confirmation_still_valid(&self, group_id: &str, stamp: &CustodyStamp) -> bool {
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        state.membership_generation() == stamp.membership_generation()
            && state.peer_group_is_full_replica(stamp.peer_id(), group_id)
            && state.peer_is_writer(stamp.peer_id(), group_id)
    }
}

impl FullReplicaCustody for DaemonState {
    fn confirm_exact_version(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        self.full_replica_custody_confirmation(group_id, path, version_hash, blocks)
    }

    fn confirmation_still_valid(&self, group_id: &str, stamp: &CustodyStamp) -> bool {
        self.custody_confirmation_still_valid(group_id, stamp)
    }
}

#[derive(Default)]
struct PeerNetmapMetadata {
    signing_keys: HashMap<String, [u8; 32]>,
    writers: HashSet<(String, String)>,
    full_replicas: HashSet<(String, String)>,
}

/// The outcome of [`DaemonState::resolve_group_policy`] — the single
/// group-policy/authorization resolution point that both local emission and
/// inbound admission consume. Collapsing "not introduced", "not loaded yet",
/// "own-verification-stale", and "coordinator-flagged invalid" into one value
/// keeps the fail-closed decision in exactly one place.
pub enum GroupPolicyResolution {
    /// A verified policy snapshot is loaded; authorize against it.
    Verified(GroupPolicyState),
    /// Fail closed: the group's policy is stale (own verification failure or
    /// coordinator-flagged invalid), or it is already introduced but its
    /// verified policy has not loaded yet this run. No local emission, no
    /// admission — the same withholding the stale-policy case already gets.
    Withhold,
    /// The genuine pre-policy bootstrap window: the group has never been
    /// introduced and no snapshot has ever existed, so the placeholder stamp
    /// is still the legitimately accepted authorization on both sides.
    Bootstrap,
}

pub struct DaemonState {
    pub device_id: String,
    pub sync_state: Arc<SyncState>,
    pub block_store: Arc<dyn BlockStore + Send + Sync>,
    /// device_id -> live connectivity, updated as `PeerChannel`s connect/upgrade.
    pub peer_statuses: Mutex<HashMap<String, PeerStatusInfo>>,
    /// The merged set of this device's local endpoint candidates (LAN, IPv6
    /// host, port-mapped, server-reflexive), maintained by the NAT-traversal
    /// tasks. Held here so those tasks publish into it and the peer
    /// orchestrator can read the current set when offering candidates in a
    /// rendezvous request.
    pub nat_sink: Arc<yadorilink_transport::CandidateSink>,
    /// A change-driven view of `nat_sink`'s merged candidate set, for the
    /// candidate-reporting task and rendezvous offers.
    pub nat_candidates: tokio::sync::watch::Receiver<Vec<yadorilink_transport::Candidate>>,
    /// Passive NAT/firewall observations (STUN mappings, port-mapping status,
    /// hole-punch outcomes) gathered by the NAT-traversal tasks. The
    /// connectivity doctor classifies a snapshot of this into a NAT type.
    pub nat_observations: yadorilink_transport::ObservationLog,
    /// This device's single long-lived UDP socket, shared by every
    /// `PeerChannel` and by NAT candidate gathering so the advertised
    /// candidates describe the exact binding data flows on. Bound lazily on
    /// first use in production; the deterministic-simulation harness sets a
    /// pre-bound one via [`set_shared_socket`](DaemonState::set_shared_socket).
    pub shared_socket: tokio::sync::OnceCell<Arc<yadorilink_transport::TransportHub>>,
    /// This device's WireGuard static public key, seeded at startup so the
    /// transport hub's MAC1 initiation gate is keyed on it. Set once before the
    /// hub is first bound; absent only if identity was never available.
    pub device_static_public: std::sync::OnceLock<[u8; 32]>,
    /// This device's Ed25519 change-history signing key, wired once at startup
    /// when the device is registered. `None` (the default) leaves signed
    /// change-history emission off — see `set_device_signing_key`.
    pub device_signing_key: Mutex<Option<ed25519_dalek::SigningKey>>,
    /// One atomic view of every peer's netmap-derived signing key, writer
    /// authorization, and full-replica status. Keeping these under one lock
    /// prevents change admission and last-replica custody from observing a
    /// partially-applied revocation/demotion snapshot.
    peer_netmap_metadata: Mutex<PeerNetmapMetadata>,
    /// Monotonic counter bumped on every actual change to the netmap-derived
    /// authorization state above (`PeerNetmapMetadata::writers` /
    /// `PeerNetmapMetadata::full_replicas`). A version-present confirmation captures it
    /// before the peer round-trip and requires it unchanged after the reply, so
    /// a revoke/demote — or any membership churn — arriving during the wait
    /// fails the confirmation closed rather than trusting a now-stale ACK.
    membership_generation: std::sync::atomic::AtomicU64,
    /// Confirms whether a full replica durably holds a version's blocks before
    /// an on-demand device reclaims its cached copy. Injected so production does
    /// the peer-to-peer query while tests supply a deterministic answer.
    custody_confirmer: Mutex<Option<Arc<dyn CustodyConfirmer>>>,
    /// group_id -> current signed policy-log head coordinates from the latest
    /// coordination netmap full update. Used to verify a change's signed
    /// auth_seq/auth_epoch/policy_head_hash stamp after its signature verifies.
    group_policy_states: Mutex<HashMap<String, GroupPolicyState>>,
    /// group_id -> unix time its most recent policy snapshot FAILED
    /// verification. A group listed here is untrusted: its verified state has
    /// been dropped and change admission for it fails closed until a valid
    /// snapshot clears the mark, so a revoke a corrupt snapshot hid can never
    /// leave a revoked writer admitted. Presence is the stale flag; the value
    /// is the failure time for diagnostics.
    stale_policy_groups: Mutex<HashMap<String, i64>>,
    /// group_id -> next candidate offset for daemon-level materialization
    /// repair, so a slow or incomplete peer is not selected forever.
    materialization_repair_cursors: Mutex<HashMap<String, usize>>,
    /// device_id -> the running sync session, so local changes can be
    /// broadcast and (in principle) sessions torn down on ACL revocation.
    pub sessions: Mutex<HashMap<String, Arc<PeerSyncSession>>>,
    /// local_path -> the folder-watcher's tasks (the debounce accumulator
    /// and the executor that consumes its flushes — batch-processing changes
    /// splits these into two independently-scheduled tasks),
    /// kept alive for as long as the link exists; all aborted together on
    /// unlink.
    pub link_tasks: Mutex<HashMap<String, Vec<JoinHandle<()>>>>,
    /// local_path -> that
    /// link's targeted-flush handle — same
    /// key and lifetime as `link_tasks` (registered by `link_manager::
    /// start_link_watch`, removed by `stop_link_watch`). Consulted by
    /// `PendingLocalChangeFlush for DaemonState`
    /// (`link_manager::pending_local_change_flush_impl`) to find which
    /// link's debounce accumulator to ask, given a `group_id` (resolved to
    /// a `local_path` via `sync_state.list_links`, the same lookup
    /// `peer_orchestrator::sync_roots_for_groups` already uses).
    pub link_flush_handles: Mutex<HashMap<String, Arc<crate::link_manager::LinkFlushHandle>>>,
    /// Absolute paths a shell-extension client has asked to pause
    /// individually via `ContextAction::PauseItem` — finer-grained than
    /// the whole-link pause in `SyncState`, and deliberately in-memory
    /// only: it's a transient UI action, not durable state.
    pub paused_paths: Mutex<HashSet<String>>,
    /// Fan-out for the shell-integration IPC: every connected
    /// shell-extension client subscribes and receives status pushes as
    /// local changes are indexed, instead of only ever answering queries.
    pub status_push_tx: broadcast::Sender<StatusPush>,
    /// Handed to every `PeerSyncSession` as its forwarding channel (see
    /// `PeerSyncSession::forward_tx`'s doc comment): a record one peer
    /// session adopts or resolves is sent here, and a background task
    /// (spawned in `new`) rebroadcasts it to this device's *other* peer
    /// sessions — full mesh propagation needs this explicit rebroadcast step.
    pub forward_tx: mpsc::UnboundedSender<(String, FileRecord)>,
    /// Graceful-shutdown support: incremented for the duration of
    /// every `broadcast_change` fan-out so
    /// `main.rs`'s shutdown path can wait for in-flight broadcasts to
    /// drain (bounded by a timeout) before tearing the process down,
    /// instead of possibly cutting one off mid-send.
    in_flight_broadcasts: AtomicI64,
    /// name -> still running, for every essential task `main.rs`
    /// supervises together. Populated from the outside (`main.rs`
    /// sets this as it spawns/observes the exit of each task) since
    /// `DaemonState` doesn't own those tasks itself; read by the control
    /// socket's health handler.
    pub task_liveness: Mutex<HashMap<String, bool>>,
    /// The control socket's `Shutdown` handler used to call
    /// `std::process::exit(0)` directly, a second shutdown path entirely
    /// separate from SIGTERM/SIGINT handling — neither aborted watcher
    /// tasks, checkpointed anything, or drained broadcasts. Sending `true`
    /// here instead routes it through the exact same graceful-shutdown
    /// code in `main.rs` that the signal handlers use; `main.rs` holds the
    /// matching `Receiver` (via `subscribe`) in its top-level `select!`.
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Local consent/counters/error-candidate/
    /// queue storage, the type that IPC dispatch and
    /// severe-error hooks operate on. Opening this never writes anything
    /// to disk by itself (see `reporting::mod`'s doc comment), so adding
    /// this field is safe for every existing `DaemonState::new` call site,
    /// test or production.
    pub reporting: ReportingStorage,
    /// On-disk persistence for the
    /// global rate limits / headroom override (`governance_config`'s doc
    /// comment). Opening this never writes anything to disk by itself,
    /// mirroring `reporting`'s "safe for every existing call site" property.
    pub governance_config: GovernanceConfigStore,
    /// The single, shared upload/
    /// download token-bucket pair every `PeerSyncSession` this daemon
    /// constructs is wired to (`peer_orchestrator::spawn_peer_session`,
    /// via `PeerSyncSession::set_rate_limiters`) — this is what makes
    /// "concurrent per-peer fetches share one global ceiling"
    /// true: they all draw from these exact two `Arc<TokenBucket>`
    /// instances, not independent per-session copies. Initialized from
    /// `governance_config` at construction; `apply_governance_config`
    /// re-reads config and updates these same buckets' rates in place
    /// (live reload) rather than replacing the `Arc`, so every
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
    /// local_path -> Degraded
    /// (disk-pressure) state for that link, entered by `mark_link_degraded`
    /// (called from wherever a `DiskPressure` error surfaces for a
    /// specific link — currently `hydration::hydrate_inner`) and cleared by
    /// the periodic re-check task spawned in `new` once a subsequent
    /// headroom check for that link's volume succeeds.
    pub degraded_links: Mutex<HashMap<String, DegradedLinkInfo>>,
    /// group_id -> latched `DurabilityUnknown` override, set by
    /// [`Self::latch_group_durability_unknown`] whenever a force override
    /// bypasses this daemon's own durability handoff gate for that group.
    /// A group with NO entry here is not thereby "Healthy" — its status is
    /// still derived live (see [`Self::group_durability_status`]); presence
    /// here only ever pins a group to `DurabilityUnknown` until a later
    /// whole-group handoff re-check clears it. The set is loaded from and
    /// written through `SyncState` so force history survives restart.
    group_durability_latch: Mutex<HashMap<String, GroupDurabilityStatus>>,
    durability_latch_load_failed: AtomicBool,
    /// operation_id -> consecutive `TransientFailure` count from
    /// `pending_enrollment::reconcile`'s activate retries, so a
    /// coordination-plane outage (or any other unconfirmable activate) that
    /// outlasts `pending_enrollment::TRANSIENT_ESCALATION_THRESHOLD` sweeps
    /// is escalated -- a loud, stable log line, not just the ordinary
    /// per-sweep debug/info trace -- instead of retrying invisibly forever.
    /// The retry itself is never abandoned and the local link/marker are
    /// never rolled back on a mere attempt count (only a `Deleted` outcome
    /// does that): this is a visibility bound, not a correctness one.
    /// In-memory only, like `degraded_links` above: it resets on restart,
    /// which is fine -- a fresh process re-earns its own escalation budget
    /// rather than inheriting a stale one, and the coordination plane's own
    /// TTL sweep is the ultimate backstop regardless of how long this has
    /// been climbing.
    pending_enrollment_transient_attempts: Mutex<HashMap<String, u32>>,
    /// Bounded history of recent
    /// connection attempts (`crate::connection_trace`), feeding both the
    /// raw trace listing and the connectivity-doctor summary. Transient,
    /// in-memory, never persisted, like `degraded_links` above.
    pub connection_traces: crate::connection_trace::ConnectionTraceLog,
    /// Bounded, in-memory
    /// per-active-transfer progress state (`crate::transfer_progress`),
    /// updated as blocks land during hydration and torn down automatically
    /// once a transfer completes, fails, or times out (its RAII guard's
    /// `Drop`). Same "transient, in-memory, never persisted" treatment as
    /// `connection_traces`.
    pub transfer_progress: crate::transfer_progress::TransferProgressTracker,
    /// Bounded, in-memory recent
    /// sync-error ring buffer (`crate::recent_errors`), surfaced in
    /// `yadorilink status` so a stuck or failing sync is diagnosable
    /// without reading logs. Same "transient, in-memory, never persisted"
    /// treatment as `connection_traces`.
    pub recent_errors: crate::recent_errors::RecentErrorLog,
    /// Check/download/verify/install
    /// orchestration, persisted update policy, and the pinned trust root
    /// for manifest signature verification.
    pub update_manager: Arc<crate::update::manager::UpdateManager>,
    /// Incremented for the duration of
    /// every sync-critical write this daemon performs — the initial
    /// folder scan and every debounced flush's chunk/index/broadcast pass
    /// (`link_manager::start_link_watch`), and on-demand-sync's
    /// hydrate/evict/restore materialization writes (`hydration.rs`).
    /// Mirrors `in_flight_broadcasts` and `BroadcastGuard`'s exact
    /// counter-plus-RAII-guard shape, so a write path that returns early
    /// or panics still gets counted back out. `is_write_safe_point`
    /// (below) is exactly "this counter is zero" — install is deferred
    /// whenever it isn't, per the "Safe Update Windows" decision.
    active_write_ops: AtomicI64,
    /// Serializes block-reference creation against physical GC deletion.
    /// Sync writes hold a shared guard from block `put` through index
    /// commit; GC holds an exclusive guard from its live-set snapshot
    /// through the final deletion.
    block_liveness_gate: BlockLivenessGate,
    /// When this `DaemonState`
    /// (i.e. this daemon process) was constructed — feeds the diagnostics
    /// bundle's coarse `daemon.uptime_bucket` field via `uptime` below.
    /// In-memory only, like `task_liveness`/`degraded_links` above:
    /// naturally resets on every restart, which is exactly "time since
    /// this daemon started."
    started_at: std::time::Instant,
    /// Unix seconds of the most recent
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
    /// GC scheduling coordination and
    /// last-run bookkeeping — see `gc::GcState`'s doc comment.
    pub gc: crate::gc::GcState,
    /// This device's coordination-plane address + access token, set once at
    /// startup (`app.rs`, alongside the other production-only coordination
    /// wiring: signing-key backfill, NAT traversal, pending-enrollment
    /// reconcile) whenever a registered device and a stored access token are
    /// both available. `None` under the deterministic simulator, in most unit
    /// tests, and on a device that has never registered/logged in — every
    /// caller (currently only the handoff-lease request path,
    /// [`Self::request_handoff_lease`]) treats that as "coordination plane
    /// unavailable" and fails closed (no lease requested), the same
    /// unreachable-coordination-plane handling every other
    /// `coordination_client` call already has. A `OnceLock` rather than a
    /// `Mutex`/`RwLock`: this is set exactly once, early in startup, and never
    /// changes for the rest of the process's life (an access-token refresh
    /// from a later re-login is a pre-existing gap every other
    /// `coordination_client` caller in this daemon already has — see
    /// `pending_enrollment`'s module doc for the same accepted limitation).
    coordination_client_config: std::sync::OnceLock<CoordinationClientConfig>,
}

/// This device's coordination-plane address + access token — see
/// [`DaemonState::coordination_client_config`]'s doc comment.
#[derive(Debug, Clone)]
pub struct CoordinationClientConfig {
    pub addr: String,
    pub access_token: String,
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

/// RAII guard for
/// `DaemonState::active_write_ops`, mirroring `BroadcastGuard` exactly.
pub struct WriteActivityGuard<'a> {
    counter: &'a AtomicI64,
    _liveness: BlockReferenceWriteGuard<'a>,
}

impl Drop for WriteActivityGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl BlockWriteActivityProvider for DaemonState {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(self.begin_write_activity())
    }
}

/// The decision logic behind [`DaemonState::obtain_handoff_lease_from_peer`]:
/// whether a target's `HandoffLeaseGrant` actually covers this device's own
/// current durability-root set. Split out as a pure function -- no session,
/// no network, no coordination client -- so this one comparison (the entire
/// safety property `obtain_handoff_lease_from_peer` exists to enforce) is
/// directly unit-testable without a live peer. `None` on a mismatch means
/// the target is not actually caught up to `my_digest`'s exact set -- the
/// caller must decline this round, never relinquish its role on the
/// strength of a lease that doesn't cover what it currently holds.
fn handoff_lease_grant_matches_digest(
    grant: &PeerHandoffLeaseGrant,
    my_digest: [u8; 32],
) -> Option<String> {
    if grant.root_digest != my_digest {
        return None;
    }
    Some(grant.lease_id.clone())
}

/// Runs a blocking housekeeping sweep off the async worker pool when a
/// multi-thread runtime is available, otherwise inline on the current thread.
///
/// The periodic capacity-eviction (`gc::run_periodic_capacity_eviction_sweep`)
/// and retention-expiry (`run_retention_expiry_sweep`) sweeps are blocking
/// work: they park on the `BlockLivenessGate` condvar and do synchronous
/// SQLite / block-store I/O. Their periodic drivers run inside `spawn_logged`
/// async tasks (and the retention sweep also runs once directly on the async
/// startup path), so invoking them directly would block a tokio worker thread
/// and, under load, starve the pool. `block_in_place` hands the blocking work
/// off so the worker can keep servicing other tasks — mirroring the identical
/// offload guard the disk-pressure eviction sweep
/// (`hydration::preflight_disk_pressure`) and the GC sweep
/// (`gc::run_sweep_with_grace_cutoff`) already use.
///
/// When there is no multi-thread worker to offload onto (a current-thread
/// runtime, or called outside any runtime — e.g. tests), the plain synchronous
/// path is correct and cannot starve a worker pool.
fn run_blocking_sweep_offloaded(sweep: impl FnOnce()) {
    #[cfg(not(madsim))]
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(sweep);
            }
            _ => sweep(),
        }
    }
    // The deterministic simulator runs a single-threaded runtime whose tokio
    // shim exposes neither `runtime_flavor()` nor `block_in_place`; always take
    // the plain synchronous path there, identical to the `_ =>` branch above.
    #[cfg(madsim)]
    {
        sweep();
    }
}

impl DaemonState {
    /// Repairs index rows omitted from the DAG by a policy-withheld initial
    /// import. Called both immediately after a verified policy snapshot lands
    /// and by the periodic materialization audit as a long-horizon retry.
    pub(crate) async fn backfill_missing_change_history(&self, group_id: &str) {
        let Some(signing_key) = self.device_signing_key() else { return };
        let emitter = yadorilink_sync_core::dag_store::ChangeEmitter::new(
            self.device_id.clone(),
            signing_key,
        );
        match yadorilink_sync_core::dag_import::backfill_missing_history(
            &self.sync_state,
            group_id,
            &emitter,
        )
        .await
        {
            Ok(yadorilink_sync_core::dag_import::BackfillOutcome::Backfilled { paths }) => {
                tracing::info!(
                    group_id,
                    paths,
                    "repaired indexed paths missing from change history"
                );
                match self.sync_state.list_files(group_id) {
                    Ok(records) => self.broadcast_change(group_id, records).await,
                    Err(e) => tracing::warn!(
                        group_id,
                        error = %e,
                        "history repair committed but immediate heads announce could not be prepared"
                    ),
                }
            }
            Ok(yadorilink_sync_core::dag_import::BackfillOutcome::NothingMissing) => {}
            Err(e) => tracing::warn!(
                group_id,
                error = %e,
                "change-history coverage audit failed; will retry"
            ),
        }
    }

    pub fn new(
        device_id: String,
        sync_state: Arc<SyncState>,
        block_store: Arc<dyn BlockStore + Send + Sync>,
    ) -> Arc<Self> {
        let (status_push_tx, _) = broadcast::channel(256);
        let (forward_tx, mut forward_rx) = mpsc::unbounded_channel::<(String, FileRecord)>();
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let governance_config = GovernanceConfigStore::new(crate::device_config::config_dir());
        // Apply whatever's on disk
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
        // unlimited = zero overhead), so every `DaemonState`,
        // test or production, gets the real configured/default rates.
        // Disk-headroom *enforcement* is deliberately NOT turned on here —
        // see `enable_disk_headroom_enforcement`'s doc comment for why
        // that's a separate, production-only opt-in `main.rs` calls
        // explicitly, mirroring `FsBlockStore`/`PeerSyncSession`'s own
        // "off by default" behavior at every other layer of this change.
        block_store.set_headroom_override_bytes(initial_governance.headroom_override_bytes);
        let (persisted_durability_latches, durability_latch_load_failed) = match sync_state
            .list_durability_unknown_latches()
        {
            Ok(groups) => (groups, false),
            Err(error) => {
                tracing::error!(%error, "failed to load durability-unknown latches; failing status closed");
                (Vec::new(), true)
            }
        };
        let (nat_sink, nat_candidates) = yadorilink_transport::CandidateSink::new();
        let state = Arc::new(Self {
            device_id,
            sync_state,
            block_store,
            peer_statuses: Mutex::new(HashMap::new()),
            nat_sink,
            nat_candidates,
            nat_observations: yadorilink_transport::ObservationLog::new(),
            shared_socket: tokio::sync::OnceCell::new(),
            device_static_public: std::sync::OnceLock::new(),
            device_signing_key: Mutex::new(None),
            peer_netmap_metadata: Mutex::new(PeerNetmapMetadata::default()),
            membership_generation: std::sync::atomic::AtomicU64::new(0),
            custody_confirmer: Mutex::new(None),
            group_policy_states: Mutex::new(HashMap::new()),
            stale_policy_groups: Mutex::new(HashMap::new()),
            materialization_repair_cursors: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            link_tasks: Mutex::new(HashMap::new()),
            link_flush_handles: Mutex::new(HashMap::new()),
            paused_paths: Mutex::new(HashSet::new()),
            status_push_tx,
            forward_tx,
            in_flight_broadcasts: AtomicI64::new(0),
            task_liveness: Mutex::new(HashMap::new()),
            shutdown_tx,
            reporting: ReportingStorage::open_default(),
            governance_config,
            rate_limiters,
            disk_headroom_enforcement_enabled: std::sync::atomic::AtomicBool::new(false),
            degraded_links: Mutex::new(HashMap::new()),
            group_durability_latch: Mutex::new(
                persisted_durability_latches
                    .into_iter()
                    .map(|group_id| (group_id, GroupDurabilityStatus::DurabilityUnknown))
                    .collect(),
            ),
            durability_latch_load_failed: AtomicBool::new(durability_latch_load_failed),
            pending_enrollment_transient_attempts: Mutex::new(HashMap::new()),
            connection_traces: crate::connection_trace::ConnectionTraceLog::new(),
            transfer_progress: crate::transfer_progress::TransferProgressTracker::new(),
            recent_errors: crate::recent_errors::RecentErrorLog::new(),
            update_manager: Arc::new(crate::update::manager::UpdateManager::new(
                crate::device_config::config_dir(),
                current_crate_version(),
            )),
            active_write_ops: AtomicI64::new(0),
            block_liveness_gate: BlockLivenessGate::default(),
            started_at: std::time::Instant::now(),
            last_activity_unix: AtomicI64::new(now_unix()),
            gc: crate::gc::GcState::new(),
            coordination_client_config: std::sync::OnceLock::new(),
        });
        // Recover from any update artifact
        // left unverified, or an install left mid-handoff, by a previous
        // run that crashed/was killed/lost power — before the periodic
        // scheduler (spawned below) or any control-socket update request
        // can observe (and potentially act on) stale state.
        state.update_manager.recover_on_startup();
        {
            let weak_state = Arc::downgrade(&state);
            state.sync_state.set_local_change_auth_provider(Arc::new(move |group_id| {
                let Some(state) = weak_state.upgrade() else {
                    // The daemon is being torn down. Report the policy as
                    // unavailable rather than stamping a placeholder-auth
                    // change during shutdown.
                    return Err(PolicyUnavailable);
                };
                // Local emission resolves its authorization stamp through the
                // single group-policy resolver that inbound admission also
                // consumes (`NetmapChangeAuthenticator::accepts_change_auth`),
                // so both boundaries fail closed on exactly the same staleness
                // sources: own-verification-stale, coordinator-flagged invalid,
                // and an already-introduced group whose verified policy has not
                // loaded yet this run. Withholding keeps the emit path from
                // stamping a PLACEHOLDER local head every valid-policy peer
                // rejects (stranding it and everything chained on it); the edit
                // stays journaled dirty and re-emits with a real authorization
                // context once the group's policy resolves.
                match state.resolve_group_policy(group_id) {
                    GroupPolicyResolution::Verified(policy) => Ok(policy.change_auth()),
                    GroupPolicyResolution::Bootstrap => Ok(ChangeAuth::PLACEHOLDER),
                    GroupPolicyResolution::Withhold => Err(PolicyUnavailable),
                }
            }));
        }
        // Periodic background update
        // checks with jitter, honoring `automatic_checks_enabled` (a
        // disabled policy just means this loop's iteration is a no-op,
        // not that the loop stops running — `yadorilink update check`
        // must still work regardless, per the spec's "Automatic checks
        // disabled" scenario). A failed check retries sooner
        // (`UPDATE_CHECK_RETRY`'s shorter, doubling backoff) than the
        // steady-state success interval (`UPDATE_CHECK_INTERVAL`).
        // The periodic update-check scheduler is the daemon's only startup
        // path that performs a real outbound HTTP request (`reqwest`, via
        // `UpdateManager::check_now`). The deterministic simulator does not
        // virtualize `reqwest`, and there is no update endpoint to reach
        // in-sim, so this loop is not spawned there — its absence is inert
        // (an operator-facing background maintenance task, not part of the
        // sync data path). Production (`not(madsim)`) is unchanged; the
        // `UpdateManager` itself is still constructed above so
        // `yadorilink update check` and control-socket requests work.
        // Unit tests construct many short-lived states in one process. Starting
        // a real, immediate HTTP check for each one both leaks work past the
        // test body and can overwrite the update-policy fixture another test
        // is asserting. Integration tests still compile this crate normally,
        // so production-like scheduler coverage remains available there.
        #[cfg(not(any(madsim, test)))]
        {
            let update_state = state.clone();
            supervise::spawn_logged("daemon-state-update-check-scheduler", async move {
                let mut consecutive_failures: u32 = 0;
                loop {
                    // Periodic update checks at daemon startup
                    // and on an interval — the startup check runs first
                    // (immediately, no delay), and every subsequent iteration
                    // waits out the jittered steady-state interval, or a
                    // shorter jittered backoff after a failure.
                    let checks_enabled = update_state
                        .update_manager
                        .policy
                        .load_or_default()
                        .automatic_checks_enabled;
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
        }
        // The background queue-retry
        // sweep, spawned unconditionally like the other periodic tasks
        // below — it is a no-op (no network call at all) until the user
        // opts into `queue_retry_enabled` and configures an endpoint, so
        // spawning it for every `DaemonState` (including test call sites)
        // is inert, matching how the pending-broadcast-retry task below is
        // already spawned unconditionally.
        crate::reporting::retry::spawn_periodic(state.clone());
        spawn_materialization_repair_scheduler(state.clone());
        // Every one of `DaemonState`'s own background tasks
        // used to be a bare `tokio::spawn` with its `JoinHandle` dropped —
        // a panic partway through a single forwarded record
        // would silently stop mesh propagation
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
                // A record forwarded here is
                // exactly a peer session having just adopted/resolved an
                // incoming file — this is this crate's "peer-reconciliation
                // activity" signal for the GC idle scheduler.
                task_state.record_activity();
                task_state.broadcast_change(&group_id, vec![record]).await;
            }
            Ok(())
        });
        // A dedicated, short-interval poll for every currently-Degraded
        // link whose backoff window has elapsed. The whole point of
        // `BackoffConfig::DEGRADED_LINK_RECHECK`'s 5s *initial* interval is
        // a link that degrades and recovers quickly getting checked again
        // promptly, so this must not be folded into a slower housekeeping
        // cadence.
        let degraded_state = state.clone();
        supervise::spawn_logged("daemon-state-degraded-link-recheck", async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                degraded_state.recheck_degraded_links();
            }
        });
        // The retention-expiry sweep —
        // "scheduled periodically... and on daemon startup". Once
        // immediately (a daemon that was down for a while, or one whose
        // retention policy just changed, shouldn't wait a full interval
        // before its first sweep), then on a bounded interval. A
        // relatively long interval (unlike the 2s degraded-link recheck
        // above, which reacts to a transient, user-visible condition) is
        // appropriate here: retention expiry is a slow-moving housekeeping
        // concern — a version that's `RETENTION_EXPIRY_SWEEP_INTERVAL`
        // late to be swept is not a correctness problem, only a delayed
        // storage reclamation, and the actual space reclamation is
        // deferred to the block-store GC regardless (this sweep only
        // ever drops the *index* row, per ).
        run_blocking_sweep_offloaded(|| run_retention_expiry_sweep(&state));
        let retention_state = state.clone();
        supervise::spawn_logged("daemon-state-retention-expiry-sweep", async move {
            loop {
                tokio::time::sleep(RETENTION_EXPIRY_SWEEP_INTERVAL).await;
                run_blocking_sweep_offloaded(|| run_retention_expiry_sweep(&retention_state));
            }
        });
        // Fix-saga: startup + periodic reconciliation of any role-loss
        // operation left mid-flight by a crash — see
        // `run_role_loss_reconciliation_sweep`'s own doc comment. Unlike the
        // retention sweep just above, this one is async (its compensation
        // path makes a coordination-plane HTTP call), so "run once
        // immediately, then on an interval" is expressed as a single
        // spawned loop that sweeps at the top before its first sleep,
        // rather than a separate blocking call ahead of the spawn.
        let role_loss_state = state.clone();
        supervise::spawn_logged("daemon-state-role-loss-reconciliation-sweep", async move {
            loop {
                run_role_loss_reconciliation_sweep(&role_loss_state).await;
                tokio::time::sleep(ROLE_LOSS_RECONCILIATION_SWEEP_INTERVAL).await;
            }
        });
        // Piggy-backs on the same cadence as
        // `PeerSyncSession`'s own periodic full-index resync
        // (`DEFAULT_FULL_INDEX_RESYNC_INTERVAL`) rather than a new,
        // independent timer. Not run once immediately at startup the way the
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
        // The idle-triggered GC scheduler,
        // modeled on this same `spawn_logged` periodic-task shape as every
        // other sweep in this file. Shares its poll tick with the
        // Previously-uncalled `run_eviction_sweep` — see
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
                run_blocking_sweep_offloaded(|| {
                    crate::gc::run_periodic_capacity_eviction_sweep(&gc_state)
                });
            }
        });
        state
    }

    /// Seeds this device's WireGuard static public key for the transport hub's
    /// MAC1 initiation gate. Must be called before the hub is first bound (see
    /// [`ensure_shared_socket`](DaemonState::ensure_shared_socket)); a later
    /// call is a no-op.
    pub fn set_device_static_public(&self, public_bytes: [u8; 32]) {
        let _ = self.device_static_public.set(public_bytes);
    }

    /// Returns this device's transport hub, binding it on first use. All peer
    /// channels and the NAT prober/mapper drive this one endpoint so the
    /// advertised candidates describe the exact binding data flows on. A bind
    /// failure is surfaced to the caller (NAT/traversal is best-effort and
    /// must not panic the daemon).
    pub async fn ensure_shared_socket(
        &self,
    ) -> std::io::Result<Arc<yadorilink_transport::TransportHub>> {
        let device_public = self
            .device_static_public
            .get()
            .and_then(|bytes| yadorilink_transport::public_key_from_bytes(bytes).ok());
        self.shared_socket
            .get_or_try_init(|| async {
                let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0));
                yadorilink_transport::TransportHub::bind(addr, device_public).await
            })
            .await
            .cloned()
    }

    /// Installs a pre-bound transport hub (the deterministic-simulation harness
    /// binds one per device). A no-op if one is already set.
    pub fn set_shared_socket(&self, socket: Arc<yadorilink_transport::TransportHub>) {
        let _ = self.shared_socket.set(socket);
    }

    /// The shared UDP socket if it has been bound/installed yet, without
    /// binding one.
    pub fn shared_socket(&self) -> Option<Arc<yadorilink_transport::TransportHub>> {
        self.shared_socket.get().cloned()
    }

    /// Marks `local_path` Degraded
    /// (disk-pressure), scheduling its next re-check via
    /// `BackoffConfig::DEGRADED_LINK_RECHECK` — a link already degraded has
    /// its backoff attempt count bumped (spacing repeated pressure further
    /// apart, "not a tight retry loop") rather than reset, and
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

    /// Pins `group_id` to [`GroupDurabilityStatus::DurabilityUnknown`],
    /// overriding whatever it would otherwise derive to. The one call site
    /// today is `control_socket::ensure_unlink_keeps_a_full_replica`'s
    /// `--force` bypass: once this device's own durability handoff gate has
    /// been overridden for a group, the group's remaining local replica
    /// must not be able to report `Healthy` again until a real re-check
    /// says so, even if, moment to moment, its files happen to look fully
    /// materialized. Idempotent — latching an already-latched group is a
    /// no-op.
    pub fn latch_group_durability_unknown(
        &self,
        group_id: &str,
    ) -> Result<(), yadorilink_sync_core::SyncError> {
        self.sync_state.latch_group_durability_unknown(group_id)?;
        self.group_durability_latch
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group_id.to_string(), GroupDurabilityStatus::DurabilityUnknown);
        Ok(())
    }

    /// Clears a previously-latched `DurabilityUnknown` override for
    /// `group_id`, if any — meant to be called once a positive
    /// whole-group handoff re-confirmation is observed for it (today:
    /// [`Self::full_replica_handoff_ready`]'s own success path calls this
    /// directly, so any caller of
    /// [`Self::another_full_replica_is_ready`]/
    /// [`Self::another_full_replica_is_ready_excluding`] that confirms
    /// coverage again clears the latch as a side effect). A no-op if the
    /// group was never latched, or is not currently latched.
    pub fn clear_group_durability_latch(
        &self,
        group_id: &str,
    ) -> Result<(), yadorilink_sync_core::SyncError> {
        self.sync_state.clear_group_durability_unknown(group_id)?;
        self.group_durability_latch.lock().unwrap_or_else(|p| p.into_inner()).remove(group_id);
        Ok(())
    }

    /// Records one more consecutive `TransientFailure` activate outcome for
    /// `operation_id` and returns the new running count -- see
    /// `pending_enrollment_transient_attempts`'s doc comment. Never resets
    /// itself; the caller clears it explicitly once the marker resolves
    /// ([`Self::clear_pending_enrollment_transient_attempts`]).
    pub fn note_pending_enrollment_transient_attempt(&self, operation_id: &str) -> u32 {
        let mut attempts =
            self.pending_enrollment_transient_attempts.lock().unwrap_or_else(|p| p.into_inner());
        let count = attempts.entry(operation_id.to_string()).or_insert(0);
        *count += 1;
        *count
    }

    /// Drops `operation_id`'s transient-attempt counter, once its marker has
    /// resolved (activated, confirmed deleted, or its link is gone and it
    /// was canceled) and there is nothing left to escalate. A no-op if it
    /// was never tracked.
    pub fn clear_pending_enrollment_transient_attempts(&self, operation_id: &str) {
        self.pending_enrollment_transient_attempts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(operation_id);
    }

    /// Read-only peek at `operation_id`'s current transient-attempt count,
    /// for tests -- unlike `note_pending_enrollment_transient_attempt`, this
    /// never increments it.
    #[cfg(test)]
    pub fn pending_enrollment_transient_attempts_for(&self, operation_id: &str) -> u32 {
        self.pending_enrollment_transient_attempts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(operation_id)
            .copied()
            .unwrap_or(0)
    }

    /// This group's current local durability status: the latched override
    /// above if one is set, otherwise a value derived live from this
    /// group's own sync state. The derived default is deliberately
    /// conservative — it reports `Healthy` only when every current file is
    /// actually `Hydrated` locally, `Syncing` while any file is still
    /// catching up, and `DurabilityUnknown` (never `Healthy`) if the link's
    /// materialization counts can't even be read. Note this derived
    /// default does not itself perform a live peer handoff check (that's a
    /// network round-trip per group, too costly to run on every `status`
    /// call) — the `Healthy` it derives means "this device's own copy
    /// looks complete," not "a whole-group peer replica was just
    /// reconfirmed"; the latch above is what specifically tracks the
    /// stronger "coverage was actively bypassed" fact.
    pub fn group_durability_status(&self, group_id: &str) -> GroupDurabilityStatus {
        if self.durability_latch_load_failed.load(Ordering::SeqCst) {
            return GroupDurabilityStatus::DurabilityUnknown;
        }
        if let Some(latched) =
            self.group_durability_latch.lock().unwrap_or_else(|p| p.into_inner()).get(group_id)
        {
            return *latched;
        }
        match self.sync_state.materialization_counts(group_id) {
            Ok(counts) if counts.placeholder == 0 && counts.hydrating == 0 => {
                GroupDurabilityStatus::Healthy
            }
            Ok(_) => GroupDurabilityStatus::Syncing,
            Err(_) => GroupDurabilityStatus::DurabilityUnknown,
        }
    }

    /// re-checks free space for every Degraded link whose backoff
    /// window has elapsed, clearing it ("cleared once a
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

    /// Re-reads the persisted
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

    /// Turns on the block store's
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

    /// Records this device's Ed25519 change-history signing key. The real
    /// daemon binary calls this once at startup when the device is
    /// registered; a `DaemonState` built without it (every test that goes
    /// through `new` without wiring one) leaves change-history emission off,
    /// so behavior is byte-identical to before change history existed.
    pub fn set_device_signing_key(&self, signing_key: ed25519_dalek::SigningKey) {
        *self.device_signing_key.lock().unwrap_or_else(|p| p.into_inner()) = Some(signing_key);
    }

    /// This device's change-history signing key, if one has been wired.
    /// Consulted by `link_manager` when deciding whether to emit signed
    /// changes for a folder.
    pub fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        self.device_signing_key.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Mirrors a peer's pinned Ed25519 change-history signing key from the
    /// netmap so the change authenticator can verify that device's changes.
    pub fn record_peer_signing_key(&self, device_id: &str, key: [u8; 32]) {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .signing_keys
            .insert(device_id.to_string(), key);
    }

    /// The pinned Ed25519 signing key for `device_id`, if one is known.
    pub fn peer_signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .signing_keys
            .get(device_id)
            .copied()
    }

    /// Applies one peer's netmap entry as an authoritative snapshot. Every
    /// peer-scoped authorization set is replaced, not incrementally patched,
    /// so demotion/revocation cannot leave a stale writer or full-replica bit
    /// behind merely because the transport session was already connected.
    pub fn replace_peer_netmap_metadata(
        &self,
        device_id: &str,
        signing_key: Option<[u8; 32]>,
        authorized_groups: &HashSet<String>,
        full_replica_groups: &HashSet<String>,
    ) {
        let mut metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        let before_writers: HashSet<String> = metadata
            .writers
            .iter()
            .filter(|(peer, _)| peer == device_id)
            .map(|(_, group)| group.clone())
            .collect();
        let before_replicas: HashSet<String> = metadata
            .full_replicas
            .iter()
            .filter(|(peer, _)| peer == device_id)
            .map(|(_, group)| group.clone())
            .collect();
        let next_replicas: HashSet<String> =
            full_replica_groups.intersection(authorized_groups).cloned().collect();
        let key_changed = match signing_key {
            Some(key) => metadata.signing_keys.insert(device_id.to_string(), key) != Some(key),
            None => metadata.signing_keys.remove(device_id).is_some(),
        };
        metadata.writers.retain(|(peer, _)| peer != device_id);
        metadata
            .writers
            .extend(authorized_groups.iter().cloned().map(|group| (device_id.to_string(), group)));
        metadata.full_replicas.retain(|(peer, _)| peer != device_id);
        metadata
            .full_replicas
            .extend(next_replicas.iter().cloned().map(|group| (device_id.to_string(), group)));
        let changed =
            key_changed || before_writers != *authorized_groups || before_replicas != next_replicas;
        if changed {
            self.bump_membership_generation();
        }
        drop(metadata);
    }

    pub fn clear_peer_netmap_metadata(&self, device_id: &str) {
        self.replace_peer_netmap_metadata(device_id, None, &HashSet::new(), &HashSet::new());
    }

    /// Records (or clears) whether `device_id` may write `group_id`, derived
    /// from the netmap's per-group share roles.
    pub fn set_peer_group_writer(&self, device_id: &str, group_id: &str, is_writer: bool) {
        let mut metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        let key = (device_id.to_string(), group_id.to_string());
        let changed =
            if is_writer { metadata.writers.insert(key) } else { metadata.writers.remove(&key) };
        if changed {
            self.bump_membership_generation();
        }
        drop(metadata);
    }

    /// Current netmap-authorization generation. A version-present confirmation
    /// captures this before its peer round-trip and requires it unchanged after
    /// the reply (see [`Self::confirm_version_present_via_peer`]).
    pub fn membership_generation(&self) -> u64 {
        self.membership_generation.load(std::sync::atomic::Ordering::Acquire)
    }

    fn bump_membership_generation(&self) {
        self.membership_generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Whether `device_id` is authorized to write `group_id`.
    pub fn peer_is_writer(&self, device_id: &str, group_id: &str) -> bool {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .writers
            .contains(&(device_id.to_string(), group_id.to_string()))
    }

    /// Records (or clears) whether `device_id` syncs `group_id` as a full
    /// replica, derived content-blind from the netmap.
    pub fn set_peer_group_full_replica(
        &self,
        device_id: &str,
        group_id: &str,
        is_full_replica: bool,
    ) {
        let mut metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        let key = (device_id.to_string(), group_id.to_string());
        let changed = if is_full_replica {
            metadata.full_replicas.insert(key)
        } else {
            metadata.full_replicas.remove(&key)
        };
        if changed {
            self.bump_membership_generation();
        }
        drop(metadata);
    }

    /// Whether at least one OTHER device (any peer) is known to sync
    /// `group_id` as a full replica. This is the content-blind "a full replica
    /// for this group exists elsewhere" signal used both by the
    /// last-full-replica guard and by cache-reclamation custody.
    pub fn group_has_other_full_replica(&self, group_id: &str) -> bool {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .full_replicas
            .iter()
            .any(|(_device, g)| g == group_id)
    }

    /// Whether THIS device syncs `group_id` as a full replica (its link's
    /// storage mode is eager/"store everything"). A missing link or any lookup
    /// error is treated as "not a full replica" — the guard/custody callers
    /// only ever need the positive, and an absent link cannot be a replica.
    pub fn is_local_full_replica(&self, group_id: &str) -> bool {
        matches!(
            self.sync_state.materialization_policy_for_group(group_id),
            Ok(Some(yadorilink_sync_core::types::MaterializationPolicy::Eager))
        )
    }

    /// Whether `device_id` is currently recorded as a full replica of
    /// `group_id` (netmap-derived, content-blind).
    pub fn peer_group_is_full_replica(&self, device_id: &str, group_id: &str) -> bool {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .full_replicas
            .contains(&(device_id.to_string(), group_id.to_string()))
    }

    /// Installs the custody confirmer used by the on-demand reclamation gate.
    /// Production wires a peer-to-peer confirmer (below); tests inject a
    /// deterministic one so custody behavior can be exercised without a live
    /// peer.
    #[cfg(test)]
    pub fn set_custody_confirmer(&self, confirmer: Arc<dyn CustodyConfirmer>) {
        *self.custody_confirmer.lock().unwrap_or_else(|p| p.into_inner()) = Some(confirmer);
    }

    /// Wires the peer-to-peer custody confirmer. Physical cache reclamation is
    /// still disabled until confirmations carry crash-durable responder-side
    /// GC leases; this wiring preserves exact-version diagnostics and the
    /// generation-stamped implementation that the future lease flow will use.
    pub fn install_p2p_custody_confirmer(self: &Arc<Self>) {
        *self.custody_confirmer.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(Arc::new(P2pCustodyConfirmer { state: Arc::downgrade(self) }));
    }

    /// Fail-closed custody gate for on-demand cache reclamation: whether a full
    /// replica can be confirmed to *durably hold* `path`'s current version, so
    /// this on-demand device may delete its cached copy. Being *configured* as a
    /// full replica is not enough — an offline, behind, or block-missing replica
    /// must not confirm. Delegates to the installed [`CustodyConfirmer`]; with
    /// none installed (or none can confirm), it returns `false` and the blocks
    /// are retained.
    fn full_replica_custody_confirmation(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        let confirmer = self.custody_confirmer.lock().unwrap_or_else(|p| p.into_inner()).clone();
        match confirmer {
            Some(confirmer) => confirmer.confirms_present(group_id, path, version_hash, blocks),
            None => None,
        }
    }

    pub fn full_replica_custody_confirmed(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> bool {
        self.full_replica_custody_confirmation(group_id, path, version_hash, blocks).is_some()
    }

    fn custody_confirmation_still_valid(&self, group_id: &str, stamp: &CustodyStamp) -> bool {
        let confirmer = self.custody_confirmer.lock().unwrap_or_else(|p| p.into_inner()).clone();
        confirmer.is_some_and(|confirmer| confirmer.confirmation_still_valid(group_id, stamp))
    }

    /// Asks every currently-connected, currently-authorized full-replica peer
    /// whether it durably holds the exact version identified by
    /// `version_hash` (with `blocks` restating its ordered block list) — the
    /// exact version the caller (eviction) pinned and is about to reclaim —
    /// in parallel, and returns true as soon as any of them confirms. The
    /// version identity and block list are supplied by the caller, not
    /// re-read from the index here, so the answer is bound to the version
    /// being evicted rather than whatever the current record happens to be
    /// after a concurrent edit. Re-checks authorization against the current
    /// netmap-derived state (full-replica member and authorized writer) both
    /// before querying a peer and again before trusting its reply, and
    /// requires the netmap-authorization generation unchanged across the
    /// round-trip — so a peer revoked or demoted at any point during the
    /// (bounded) wait never confirms. Peer-to-peer only; never involves the
    /// coordination plane.
    ///
    /// Deliberately stays a per-file, exact-version check and is NOT routed
    /// through [`Self::full_replica_handoff_ready`]'s whole-group durability
    /// ROOT set (`SyncState::enumerate_group_durability_roots`): eviction
    /// custody only ever needs proof for the one version being reclaimed,
    /// never the group's whole retained history. GC unification — a future
    /// block-store sweep computing its live set from roots ∪
    /// hydration-in-progress (`MaterializationState::Hydrating`) ∪
    /// dirty/in-flight (`SyncState::list_dirty_paths`) ∪ a grace window — is
    /// out of scope here.
    ///
    /// A peer that hasn't advertised `supports_version_present` in its
    /// handshake `ClusterConfig` (`PeerSyncSession::version_present_negotiated`)
    /// is skipped entirely rather than queried: such a peer silently drops an
    /// unrecognized `VersionPresentQuery` instead of replying, so querying it
    /// would only spend its full per-request timeout for nothing. Querying
    /// every remaining candidate concurrently, instead of one after another,
    /// turns the old O(peers × per-request timeout) worst case into a single
    /// per-request timeout window regardless of peer count — see
    /// `VERSION_PRESENT_QUERY_OVERALL_TIMEOUT`'s doc comment.
    pub async fn confirm_version_present_via_peer(
        &self,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
    ) -> bool {
        self.confirm_version_present_witness_via_peer(group_id, path, version_hash, blocks)
            .await
            .is_some()
    }

    async fn confirm_version_present_witness_via_peer(
        &self,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        use futures_util::stream::{FuturesUnordered, StreamExt};

        let candidates: Vec<(String, Arc<PeerSyncSession>)> = self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(id, session)| (id.clone(), session.clone()))
            .filter(|(peer_id, session)| {
                self.peer_group_is_full_replica(peer_id, group_id)
                    && self.peer_is_writer(peer_id, group_id)
                    && session.version_present_negotiated()
            })
            .collect();
        if candidates.is_empty() {
            return None;
        }

        // Capture the authorization generation before the fan-out so a reply
        // can be rejected if the netmap changed while it was in flight.
        let epoch_before = self.membership_generation();
        let mut queries: FuturesUnordered<_> = candidates
            .into_iter()
            .map(|(peer_id, session)| async move {
                // Eviction custody: `for_handoff = false` requires the peer
                // to match its CURRENT record for this path, never a merely
                // retained version whose blocks retention could later
                // reclaim (which would leave this device, having already
                // dropped its own cached copy, with no durable holder).
                let confirmed = session
                    .request_version_present(group_id, path, version_hash, blocks, false)
                    .await;
                (peer_id, confirmed)
            })
            .collect();

        let confirmed_by_any = tokio::time::timeout(VERSION_PRESENT_QUERY_OVERALL_TIMEOUT, async {
            while let Some((peer_id, confirmed)) = queries.next().await {
                // Re-verify AFTER the reply: the peer must still be an
                // authorized full-replica writer AND the netmap-authorization
                // view must not have changed at all during the wait, so a
                // revoke/demote — or any membership churn — mid-round-trip
                // fails closed rather than trusting a now-stale ACK.
                if confirmed
                    && self.membership_generation() == epoch_before
                    && self.peer_group_is_full_replica(&peer_id, group_id)
                    && self.peer_is_writer(&peer_id, group_id)
                {
                    return Some(CustodyStamp::new(peer_id, epoch_before));
                }
            }
            None
        })
        .await;
        // A timed-out fan-out (the defense-in-depth backstop above, not the
        // expected case) is treated the same as "no peer confirmed" — fail
        // closed, matching every other unconfirmed outcome here.
        confirmed_by_any.unwrap_or(None)
    }

    /// Whether some OTHER full replica of `group_id` can be confirmed, right
    /// now, to durably hold the current version of EVERY file in the group —
    /// the gate an eager device must pass before it may give up its own
    /// full-replica status and demote to on-demand (see
    /// `control_socket`'s storage-mode-change handler). Without central
    /// storage a full replica is the only durable copy of a group's files, so
    /// this is fail-closed throughout: an unreadable file list, no single
    /// peer that holds the whole group, or any non-`File` record it cannot
    /// even classify all report "not ready" rather than risk a handoff that
    /// turns out to have nowhere durable to land. A group with no current
    /// files at all is vacuously ready — there is nothing to hand off.
    ///
    /// Readiness is decided PER PEER, not per file: it is not enough that
    /// every file is held by *some* peer (peer B could hold file1 and peer C
    /// hold file2 with neither holding both, which would still leave the
    /// group with zero complete durable copies). A handoff is ready only when
    /// at least one *single* connected, authorized full-replica writer peer
    /// is confirmed to hold every file — a genuine complete replica to hand
    /// off to. See [`Self::peer_holds_entire_group`].
    ///
    /// Only `RecordKind::File` records need confirming (directories and
    /// symlinks carry no blocks); a deleted record needs no durable holder
    /// either.
    ///
    /// Also backs the unlink durability gate
    /// (`control_socket::ensure_unlink_keeps_a_full_replica`): a device
    /// giving up its OWN eager status only ever needs to confirm some other
    /// peer is ready, which is exactly what this checks. Revoke/device-removal
    /// use the sibling [`Self::another_full_replica_is_ready_excluding`]
    /// instead, since there the device losing access is not the caller.
    pub async fn another_full_replica_is_ready(&self, group_id: &str) -> bool {
        self.full_replica_handoff_ready(group_id, None).await.is_some()
    }

    /// Like [`Self::another_full_replica_is_ready`], but a specific
    /// `excluded_device_id` is never counted as the confirming replica, even
    /// if it is currently connected and recorded as an eager full replica.
    /// Used by the revoke/device-removal readiness pre-check: the device
    /// about to lose access must not be allowed to count as its own handoff
    /// target — the whole point of the check is confirming some OTHER
    /// full replica is ready before that device is removed.
    pub async fn another_full_replica_is_ready_excluding(
        &self,
        group_id: &str,
        excluded_device_id: &str,
    ) -> bool {
        self.full_replica_handoff_ready(group_id, Some(excluded_device_id)).await.is_some()
    }

    /// Like [`Self::another_full_replica_is_ready`], but on success also
    /// returns the exact durability-root-set digest the confirmation was
    /// made against (`None` on a not-ready answer, same as the plain bool
    /// form). A caller about to COMMIT a daemon-driven role loss (unlink,
    /// demote) must capture this digest here and then re-fetch
    /// [`Self::local_durability_roots_digest`] immediately before the local
    /// commit, refusing (or requiring `--force`) if the two differ — see
    /// `control_socket::ensure_unlink_keeps_a_full_replica`/
    /// `set_storage_mode`. A changed digest means this device's own root set
    /// moved (a local edit landed) after the peer confirmed coverage of the
    /// OLD set, so that confirmation no longer proves anything about the new
    /// one — closing the TOCTOU window between check and commit.
    ///
    /// Only the non-excluding form is offered: the CLI-orchestrated
    /// revoke/device-remove commit happens on the coordination Worker, which
    /// this daemon cannot wrap in a re-check immediately before that commit —
    /// see `durability_force.rs`'s own doc comment for why that TOCTOU window
    /// is left as a documented, bounded gap instead.
    pub async fn full_replica_handoff_ready_digest(&self, group_id: &str) -> Option<[u8; 32]> {
        self.full_replica_handoff_ready(group_id, None).await.map(|(digest, _peer)| digest)
    }

    /// This device's own current durability-root-set digest for `group_id`,
    /// read fresh from the local index only — no peer round trip. See
    /// [`Self::full_replica_handoff_ready_digest`]'s doc comment for the
    /// re-confirm pattern this backs. `None` (fail closed) if the local
    /// enumeration itself errors.
    pub fn local_durability_roots_digest(&self, group_id: &str) -> Option<[u8; 32]> {
        self.durability_roots_for_group(group_id).map(|roots| roots.digest)
    }

    /// Records this device's coordination-plane address + access token —
    /// called once, early in `app.rs`'s startup path, whenever both are
    /// available. A no-op if already set (matches `OnceLock::set`'s own
    /// semantics; every production call site only ever calls this once
    /// anyway).
    pub fn set_coordination_client_config(&self, addr: String, access_token: String) {
        let _ =
            self.coordination_client_config.set(CoordinationClientConfig { addr, access_token });
    }

    /// This device's coordination-plane address + access token, if recorded
    /// — see [`Self::set_coordination_client_config`]'s doc comment for when
    /// it is (and, notably, isn't: most of this crate's own unit tests never
    /// call the setter) set.
    pub fn coordination_client_config(&self) -> Option<&CoordinationClientConfig> {
        self.coordination_client_config.get()
    }

    /// Fix-saga: opens a durable role-loss-operation journal row for a
    /// demote/unlink this device is about to drive as the SOURCE, BEFORE the
    /// coordination-worker role-loss commit itself — see
    /// [`yadorilink_sync_core::index::RoleLossOperation`]'s doc comment for
    /// the full state machine this row moves through. `local_path` is the
    /// link this operation concerns (both demote and unlink always name
    /// one).
    ///
    /// FAIL-CLOSED: the Prepared row is the durability mechanism this whole
    /// saga rests on, so its write is NOT best-effort. If it fails (a genuine
    /// local storage error), this returns `Err` and the caller
    /// (`control_socket`'s demote/unlink paths) MUST abort BEFORE calling
    /// `commit_handoff_role_loss` — committing the role loss on the Worker
    /// without a durable recovery record would reopen the exact split-state
    /// hole (Worker on-demand / local eager, with nothing to drive a retry)
    /// the journal exists to close. Aborting here is always safe: nothing has
    /// been committed on either side yet, so a failed Prepared write leaves no
    /// split, only a plain "couldn't start the operation, retry" error.
    pub fn open_role_loss_operation(
        &self,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
        action: RoleLossAction,
        local_path: &str,
    ) -> Result<String, String> {
        let operation_id = uuid::Uuid::new_v4().to_string();
        self.sync_state
            .insert_role_loss_operation(
                &operation_id,
                group_id,
                &self.device_id,
                target_device_id,
                Some(lease_id),
                action,
                Some(local_path),
                now_unix(),
            )
            .map(|()| operation_id)
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    group_id,
                    target_device_id,
                    "refusing to commit a handoff role loss: could not persist its durable \
                     rollback journal row (fail-closed; nothing has been committed yet)"
                );
                format!(
                    "could not record the durable rollback journal for this operation ({e}); \
                     nothing was committed, so it is safe to retry"
                )
            })
    }

    /// Advances a role-loss-operation journal row to `WorkerCommitted` —
    /// called immediately after the coordination-worker role-loss commit
    /// succeeds, so a crash from this point on is reconciled by the startup
    /// + periodic sweep (`run_role_loss_reconciliation_sweep`) instead of
    /// left as a split state. Best-effort: even if this write itself fails
    /// (row stays `Prepared`), the sweep treats a `Prepared` row the same as
    /// `WorkerCommitted` at reconciliation time — see
    /// [`yadorilink_sync_core::index::RoleLossOperationState::Prepared`]'s
    /// doc comment for why that's safe.
    pub fn mark_role_loss_worker_committed(&self, operation_id: &str, membership_generation: i64) {
        if let Err(e) = self.sync_state.mark_role_loss_worker_committed(
            operation_id,
            membership_generation,
            now_unix(),
        ) {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a role-loss operation journal row to WorkerCommitted"
            );
        }
    }

    /// Deletes a role-loss-operation journal row whose coordination-worker
    /// commit never happened (the Worker call itself failed or was refused)
    /// — nothing was committed on either side, so the row never protected
    /// anything real.
    pub fn discard_role_loss_operation(&self, operation_id: &str) {
        if let Err(e) = self.sync_state.delete_role_loss_operation(operation_id) {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to delete an abandoned role-loss operation journal row"
            );
        }
    }

    /// Closes out a role-loss-operation journal row on the normal success
    /// path: the coordination-worker commit AND the matching local
    /// policy/link change both landed. Advances to `LocalCommitted` then
    /// deletes the row — the same outcome as before this journal existed,
    /// just with a journal row written and cleaned up around it.
    pub fn settle_role_loss_operation_success(&self, operation_id: &str) {
        let now = now_unix();
        if let Err(e) = self.sync_state.advance_role_loss_operation(
            operation_id,
            RoleLossOperationState::LocalCommitted,
            now,
        ) {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a role-loss operation journal row to LocalCommitted"
            );
        }
        if let Err(e) = self.sync_state.delete_role_loss_operation(operation_id) {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to delete a LocalCommitted role-loss operation journal row; it will be \
                 cleaned up by the next reconciliation sweep"
            );
        }
    }

    /// Compensates a role-loss operation whose coordination-worker commit
    /// succeeded but whose matching local change never completed (a digest
    /// mismatch or a storage error in the local recheck-then-commit, or a
    /// crash before that local step ever ran). The SAFE recovery direction
    /// is to REVERT the Worker back to `eager` for the source device, not to
    /// force-complete the local demotion: the handoff target's lease/pin may
    /// have lapsed by the time this runs, so completing the demotion could
    /// end up releasing the only durable copy of the group's data. Reuses
    /// the existing storage-mode write (`coordination_client::
    /// set_storage_mode`, action `"eager"`) — the same call a PROMOTION
    /// already makes — since the Worker-side effect of every role-loss
    /// commit this journal wraps today (`commit_handoff_role_loss(...,
    /// "demote")`, for BOTH the demote and unlink call sites — see
    /// `control_socket.rs`) is exactly a `storage_mode` narrowing, so
    /// reverting it is exactly this one call, cleanly and idempotently.
    ///
    /// On success, advances the row to `Completed` and deletes it, returning
    /// `Ok(())`. On failure (coordination plane unreachable or refused),
    /// leaves the row at `Compensating`, bumps its retry counter (escalating
    /// the log level past `ROLE_LOSS_COMPENSATION_ESCALATION_ATTEMPTS`
    /// attempts, purely for visibility), and returns `Err` describing the
    /// failure. The row is NEVER deleted on a failed compensation attempt —
    /// the startup + periodic sweep (`run_role_loss_reconciliation_sweep`)
    /// retries it indefinitely until a revert is confirmed.
    ///
    /// A missing journal row (already reconciled by a concurrent attempt, or
    /// never written in the first place — see
    /// [`Self::open_role_loss_operation`]'s best-effort doc comment) is
    /// treated as already-compensated (`Ok(())`): there is nothing left here
    /// for this call to do.
    ///
    /// Carries only `(group_id, source_device_id, "eager")` to the
    /// coordination plane — no digest, path, or version content (INV-4;
    /// same as every other call in `coordination_client`).
    pub async fn compensate_role_loss_operation(&self, operation_id: &str) -> Result<(), String> {
        let Some(op) =
            self.sync_state.get_role_loss_operation(operation_id).map_err(|e| e.to_string())?
        else {
            return Ok(());
        };
        if op.state != RoleLossOperationState::Compensating {
            if let Err(e) = self.sync_state.advance_role_loss_operation(
                operation_id,
                RoleLossOperationState::Compensating,
                now_unix(),
            ) {
                tracing::warn!(
                    error = %e,
                    operation_id,
                    "failed to advance a role-loss operation journal row to Compensating"
                );
            }
        }
        let Some(config) = self.coordination_client_config() else {
            let attempts = self
                .sync_state
                .increment_role_loss_operation_attempts(operation_id, now_unix())
                .unwrap_or(op.attempts + 1);
            tracing::warn!(
                operation_id,
                group_id = %op.group_id,
                attempts,
                "role-loss compensation could not run: no coordination-plane config recorded; \
                 will retry once this device is connected"
            );
            return Err(
                "not connected to the coordination plane; the rollback will be retried once \
                 connectivity is restored"
                    .to_string(),
            );
        };
        let Some(lease_id) = op.lease_id.as_deref() else {
            tracing::warn!(
                operation_id,
                "legacy role-loss journal has no lease; treating it as superseded"
            );
            self.sync_state.delete_role_loss_operation(operation_id).map_err(|e| e.to_string())?;
            return Ok(());
        };
        match crate::coordination_client::compensate_handoff_role_loss(
            &config.addr,
            &config.access_token,
            &op.group_id,
            &op.source_device_id,
            &op.target_device_id,
            lease_id,
            op.worker_membership_generation,
        )
        .await
        {
            Ok(outcome) => {
                tracing::info!(
                    operation_id,
                    ?outcome,
                    "role-loss compensation reached a terminal outcome"
                );
                if let Err(e) = self.sync_state.advance_role_loss_operation(
                    operation_id,
                    RoleLossOperationState::Completed,
                    now_unix(),
                ) {
                    tracing::warn!(
                        error = %e,
                        operation_id,
                        "failed to advance a role-loss operation journal row to Completed"
                    );
                }
                if let Err(e) = self.sync_state.delete_role_loss_operation(operation_id) {
                    tracing::warn!(
                        error = %e,
                        operation_id,
                        "failed to delete a Completed role-loss operation journal row; it will \
                         be cleaned up by the next reconciliation sweep"
                    );
                }
                Ok(())
            }
            Err(e) => {
                let attempts = self
                    .sync_state
                    .increment_role_loss_operation_attempts(operation_id, now_unix())
                    .unwrap_or(op.attempts + 1);
                if attempts >= ROLE_LOSS_COMPENSATION_ESCALATION_ATTEMPTS {
                    tracing::error!(
                        error = %e,
                        operation_id,
                        group_id = %op.group_id,
                        attempts,
                        "role-loss compensation has failed repeatedly; this device's \
                         full-replica status for this group may still be inconsistent with the \
                         coordination plane"
                    );
                } else {
                    tracing::warn!(
                        error = %e,
                        operation_id,
                        group_id = %op.group_id,
                        attempts,
                        "role-loss compensation attempt failed; will retry"
                    );
                }
                Err(e)
            }
        }
    }

    /// Requests a full-replica-handoff lease for `group_id` — the daemon-side
    /// half of `RequestHandoffLeaseRequest`. Runs this device's own local
    /// readiness check first (reusing [`Self::full_replica_handoff_ready_
    /// digest`] exactly as-is: called TARGET-side here, it asks "does some
    /// other connected full-replica peer confirm holding everything I hold" —
    /// the same predicate `CheckFullReplicaHandoffReadyRequest` asks
    /// SOURCE-side, just invoked for the opposite purpose. Once sync has
    /// converged the two devices' durability-root sets, this device's own
    /// root set IS the group's current root set, so "a peer confirms holding
    /// everything I hold" and "I hold everything the group currently has" are
    /// the same fact from either side).
    ///
    /// On a positive local check, calls coordination-worker to actually issue
    /// the lease (giving a real `lease_id`), then — ONLY THEN — atomically
    /// re-enumerates this device's exact `(path, version_seq)` root rows AND
    /// records the local pin for them in one transaction
    /// ([`SyncState::record_handoff_lease_atomic`]), so no retention sweep
    /// can evict a row between enumerating it and pinning it (the gap
    /// [`SyncState::record_handoff_lease`] alone leaves — see its sibling's
    /// own doc comment). Ordering the Worker call first is what makes this
    /// atomic pin possible without a local schema change: the real
    /// Worker-issued `lease_id` is already in hand, so the single atomic
    /// write only ever inserts/updates one row keyed on it, never
    /// provisions a placeholder first.
    ///
    /// The atomic pin also returns the digest of exactly the set it pinned.
    /// If that digest no longer matches the readiness digest captured in
    /// step one — the root set moved between the readiness attestation and
    /// the atomic pin landing (e.g. a retention sweep evicted a root, or a
    /// new local version landed) — this aborts: it ATTEMPTS to release both
    /// the just-written local pin ([`SyncState::set_handoff_lease_state`],
    /// `Released`) and the just-granted Worker lease
    /// (`coordination_client::release_handoff_lease`), then returns `None`,
    /// exactly as if no lease had been obtained at all. Both releases are
    /// best-effort (each swallows its own error): if either fails, the
    /// local time-based pin expiry (`expires_at_unix`, the check
    /// `SyncState::leased_version_keys_for_group` actually enforces) and the
    /// Worker's own TTL sweep are the backstop, so nothing lingers past its
    /// expiry regardless — the same abandoned-lease model the design already
    /// relies on. This is a safe decline, not a data-loss risk: the caller
    /// (`control_socket`) treats `None` as "no lease this round" and the
    /// existing local digest-recapture-then-recheck gate
    /// (`SyncState::recheck_digest_then_remove_link`/`recheck_digest_then_
    /// set_materialization_policy`) is what actually protects the role-loss
    /// commit either way. The same best-effort Worker release is also
    /// attempted if the atomic local pin itself errors after a successful
    /// Worker POST, so no post-POST failure path leaves a granted Worker
    /// lease with no active cleanup attempt.
    ///
    /// Neither digest nor any pinned `(path, version_seq)` row is ever sent
    /// to coordination-worker: the lease request/release calls carry only
    /// `(group_id, target_device_id[, lease_id])`
    /// (`coordination_client::request_handoff_lease`/`release_handoff_
    /// lease`'s own doc comments) — the Worker adjudicates
    /// membership/eligibility only, never version content.
    ///
    /// Returns `None` if the local check fails, this device has no
    /// coordination-plane config recorded ([`Self::coordination_client_
    /// config`]), the coordination-plane request itself fails, the atomic
    /// local pin errors, or the digest-mismatch abort above fires — every
    /// case is treated identically by the caller (`control_socket`): no
    /// lease was requested or recorded.
    ///
    /// On success, also returns the digest of exactly the root set this
    /// grant pins (`pinned_digest`, equal to `attested_digest` by
    /// construction at this point) — used by [`HandoffLeaseResponder for
    /// DaemonState`] to answer an incoming peer-to-peer `HandoffLeaseRequest`
    /// with this device's own `root_digest`, exchanged directly with the
    /// requesting peer and never sent to coordination-worker.
    pub async fn request_handoff_lease(
        &self,
        group_id: &str,
    ) -> Option<(crate::coordination_client::HandoffLeaseGrant, [u8; 32])> {
        let attested_digest = self.full_replica_handoff_ready_digest(group_id).await?;
        let config = self.coordination_client_config.get()?;
        let grant = crate::coordination_client::request_handoff_lease(
            &config.addr,
            &config.access_token,
            group_id,
            &self.device_id,
        )
        .await?;
        // A best-effort Worker-side release of the lease just granted, for
        // every post-POST abort path below. Best-effort: a failure here just
        // means the Worker's own TTL sweep reclaims the lease instead (the
        // accepted abandoned-lease backstop), so it is logged-and-swallowed
        // inside `release_handoff_lease` rather than surfaced.
        let release_worker_lease = move |lease_id: String| async move {
            crate::coordination_client::release_handoff_lease(
                &config.addr,
                &config.access_token,
                group_id,
                &self.device_id,
                &lease_id,
            )
            .await;
        };

        // Trust-boundary check on the Worker-supplied TTL duration. A
        // non-positive `ttl_seconds` (which the current Worker never emits,
        // but a buggy or hostile coordination response could) would yield a
        // local pin deadline at or before now, so the pin would lapse
        // immediately and reopen the retention/GC race the lease exists to
        // close. Treat it as a failed lease: release the just-granted Worker
        // lease best-effort and return `None`, exactly like every other
        // "no usable lease this round" path here — the mandatory-lease
        // caller then fails closed, which is safe. `record_handoff_lease_
        // atomic` also rejects this structurally as defense in depth, but
        // catching it here avoids ever writing (and then having to release)
        // a doomed local pin.
        if grant.ttl_seconds <= 0 {
            tracing::warn!(
                group_id,
                lease_id = %grant.lease_id,
                ttl_seconds = grant.ttl_seconds,
                "handoff lease request aborted: coordination response carried a non-positive TTL; \
                 releasing Worker lease and declining this round"
            );
            release_worker_lease(grant.lease_id).await;
            return None;
        }

        // `grant.ttl_seconds` (a duration), never `grant.expires_at_unix` (the
        // Worker's own absolute expiry, stamped against the Worker's clock):
        // the local pin deadline `record_handoff_lease_atomic` derives from
        // this must come from THIS device's own clock (`now_unix()` below)
        // plus the TTL, so it can never be thrown off by skew between this
        // device's clock and the Worker's -- see that function's own doc
        // comment for the full rationale.
        let (pinned_digest, _pinned_versions) = match self.sync_state.record_handoff_lease_atomic(
            group_id,
            &grant.lease_id,
            now_unix(),
            grant.ttl_seconds,
        ) {
            Ok(pinned) => pinned,
            Err(e) => {
                // The atomic local pin errored after the Worker already
                // granted the lease -- attempt to release the Worker lease so
                // it does not sit granted with no local pin until its TTL
                // (symmetric with the digest-mismatch abort below).
                tracing::debug!(error = %e, group_id, lease_id = %grant.lease_id,
                    "handoff lease request aborted: atomic local pin failed; releasing Worker lease");
                release_worker_lease(grant.lease_id).await;
                return None;
            }
        };
        if pinned_digest != attested_digest {
            // The root set moved between the readiness attestation and the
            // atomic pin landing -- decline rather than hand out a lease that
            // no longer pins what was verified. Attempt to release both
            // halves; each release is best-effort, with the local time-based
            // pin expiry and the Worker TTL sweep as the backstop if either
            // fails.
            if let Err(e) = self
                .sync_state
                .set_handoff_lease_state(&grant.lease_id, HandoffLeaseState::Released)
            {
                tracing::debug!(error = %e, group_id, lease_id = %grant.lease_id,
                    "handoff lease digest-mismatch abort: could not release local pin");
            }
            tracing::info!(
                group_id,
                lease_id = %grant.lease_id,
                "handoff lease request aborted: durability-root set changed between readiness \
                 attestation and atomic pin; declining this round"
            );
            release_worker_lease(grant.lease_id).await;
            return None;
        }
        Some((grant, pinned_digest))
    }

    /// Releases both halves of a provisional lease owned by this target.
    /// The local pin is released even when coordination configuration is no
    /// longer available; Worker TTL remains the fallback for a failed POST.
    pub async fn release_owned_handoff_lease(&self, group_id: &str, lease_id: &str) {
        if let Err(e) =
            self.sync_state.set_handoff_lease_state(lease_id, HandoffLeaseState::Released)
        {
            tracing::debug!(
                error = %e,
                group_id,
                lease_id,
                "could not release local handoff lease pin"
            );
        }
        if let Some(config) = self.coordination_client_config.get() {
            crate::coordination_client::release_handoff_lease(
                &config.addr,
                &config.access_token,
                group_id,
                &self.device_id,
                lease_id,
            )
            .await;
        }
    }

    /// Source-side counterpart to [`Self::request_handoff_lease`]: asks a
    /// specific, already-confirmed target peer to run that same target-side
    /// flow on ITS device, over the peer-to-peer `HandoffLeaseRequest`/
    /// `HandoffLeaseGrant` exchange (`peer_session.rs`), and returns the
    /// resulting lease id only if the target's own attested `root_digest`
    /// matches `my_digest` — compared here, daemon-local, never sent to or
    /// asked of coordination-worker.
    ///
    /// `target_peer_device_id` must name a peer this device currently has a
    /// live session with (normally the exact peer
    /// [`Self::full_replica_handoff_ready_digest_and_peer`] just confirmed);
    /// no session for that id returns `None` immediately.
    ///
    /// Returns `None` — fail closed, never partially trusted — on every one
    /// of: no live session for that peer, the peer not granting (`granted =
    /// false` or an empty lease id, including a peer running a build that
    /// predates this message, which simply times out the same way), or a
    /// digest mismatch. A mismatch specifically means the target is not
    /// actually caught up to this device's exact current root set — the
    /// caller must NOT relinquish its own role on that basis, only decline
    /// this round.
    pub async fn obtain_handoff_lease_from_peer(
        &self,
        group_id: &str,
        target_peer_device_id: &str,
        my_digest: [u8; 32],
    ) -> Option<String> {
        let session = self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(target_peer_device_id)
            .cloned()?;
        let grant = session.request_handoff_lease_from_peer(group_id).await?;
        let lease_id = handoff_lease_grant_matches_digest(&grant, my_digest);
        if lease_id.is_none() {
            tracing::info!(
                group_id,
                target_device_id = %target_peer_device_id,
                "handoff lease request declined: target's attested durability-root digest \
                 does not match this device's own current digest; not relinquishing local role \
                 this round"
            );
            if let Err(e) = session.release_handoff_lease_to_peer(group_id, &grant.lease_id).await {
                tracing::debug!(
                    error = %e,
                    group_id,
                    lease_id = %grant.lease_id,
                    target_device_id = %target_peer_device_id,
                    "could not send digest-mismatched handoff lease release; TTL remains the backstop"
                );
            }
        }
        lease_id
    }

    /// The removed-device-ticket RESPONDER half of `HandoffTicketRequest`,
    /// run on THIS device's own `DaemonState` -- i.e. called on a device (B)
    /// that a DIFFERENT operating device (X) is in the process of removing/
    /// revoking, asking B to attest and hand off ITS OWN roots before it
    /// leaves. This is exactly the Stage-B SOURCE-side flow
    /// ([`Self::full_replica_handoff_ready_digest_and_peer`] +
    /// [`Self::obtain_handoff_lease_from_peer`]), reused verbatim: a removed
    /// device attesting its own roots to obtain a lease from some other
    /// confirmed peer IS the source-side handoff flow, just triggered by a
    /// different caller (X, over the new `HandoffTicketRequest` wire
    /// message, rather than this device's own unlink/demote code path).
    ///
    /// Returns `None` -- which the wire responder
    /// (`HandoffTicketResponder for DaemonState` below) turns into `granted
    /// = false` -- when: this device's own root set for `group_id` is
    /// non-empty and no connected peer confirms holding all of it (the
    /// digest mismatch/no-confirming-peer case is exactly what closes the
    /// #3 gap: X could not have attested this on B's behalf, and B itself
    /// could not either this round), or the confirmed peer's own coordi-
    /// nation-plane round trip fails (see [`Self::obtain_handoff_lease_
    /// from_peer`]'s doc comment for the full list of sub-cases, all
    /// collapsed to `None` there already).
    ///
    /// An EMPTY root set is vacuously ready (see [`Self::full_replica_
    /// handoff_ready`]'s own doc comment) and needs no lease -- this
    /// returns `Some` with `lease_id: None`/`target_device_id: None` in that
    /// case, which the wire responder reports as `granted = true` with an
    /// empty `lease_id`/`target_device_id`. X cannot bind such a ticket to a
    /// lease-guarded commit (there is no target to name), so it is not
    /// usable as a removal ticket by X's atomic wiring even though it is a
    /// perfectly valid "nothing to hand off" answer.
    ///
    /// `target_device_id` is the SAME confirming peer
    /// [`Self::full_replica_handoff_ready_digest_and_peer`] already learned
    /// and [`Self::obtain_handoff_lease_from_peer`] requested the lease
    /// from -- this is what closes the previously-disclosed gap where the
    /// ticket carried a lease id but no target to atomically re-verify it
    /// against at removal time.
    ///
    /// `expires_at_unix` is always `0` here: propagating the confirming
    /// peer's real expiry would require changing [`Self::obtain_handoff_
    /// lease_from_peer`]'s public signature (used unmodified by Stage B),
    /// and the ticket's `expires_at_unix` is documented (see
    /// `HandoffTicketGrant`'s proto doc comment) as carried only for X to
    /// record/log, never re-verified -- X's actual decision now rests on
    /// presenting `(lease_id, target_device_id)` to a lease-guarded commit,
    /// not on the `granted` bool alone.
    pub async fn obtain_own_handoff_ticket(
        &self,
        group_id: &str,
    ) -> Option<PeerHandoffTicketGrant> {
        let (digest, peer) = self.full_replica_handoff_ready_digest_and_peer(group_id).await?;
        let (lease_id, target_device_id) = match peer {
            None => (None, None),
            Some(peer_id) => {
                let lease_id =
                    self.obtain_handoff_lease_from_peer(group_id, &peer_id, digest).await?;
                (Some(lease_id), Some(peer_id))
            }
        };
        Some(PeerHandoffTicketGrant { lease_id, target_device_id, expires_at_unix: 0 })
    }

    /// The removed-device-ticket REQUESTER half: run on the OPERATING
    /// device's (X's) own `DaemonState` to ask a DIFFERENT device (`device_
    /// id`, the one being removed/revoked) to attest and hand off its own
    /// roots for `group_id`, over the peer-to-peer `HandoffTicketRequest`/
    /// `HandoffTicketGrant` exchange (`peer_session.rs`). Backs
    /// `durability_force.rs`'s cross-device gate: a `Some` result for every
    /// at-risk group lets the removal proceed WITHOUT `--force`.
    ///
    /// Returns `None` -- collapsed identically, matching this crate's other
    /// fail-closed daemon-side checks -- for every one of: no live session
    /// for `device_id` on this daemon (the device is offline/unreachable
    /// from X's point of view), the request timing out, or the device's own
    /// attestation declining (its root set isn't fully confirmed by any
    /// peer it can reach). X never needs to (and structurally cannot: this
    /// method never reads or compares X's own root index) distinguish these
    /// -- the design's whole point is that X cannot attest a different
    /// device's roots, so this always routes the decision through the
    /// removed device itself, never through X's local view.
    pub async fn obtain_handoff_ticket_from_device(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> Option<PeerHandoffTicketGrant> {
        let session =
            self.sessions.lock().unwrap_or_else(|p| p.into_inner()).get(device_id).cloned()?;
        session.request_handoff_ticket_from_peer(group_id).await
    }

    /// Asks the removed device that created a ticket to route its release to
    /// the target peer that owns the corresponding lease and local pin.
    pub async fn release_handoff_ticket_from_device(
        &self,
        group_id: &str,
        device_id: &str,
        target_device_id: &str,
        lease_id: &str,
    ) {
        let session =
            self.sessions.lock().unwrap_or_else(|p| p.into_inner()).get(device_id).cloned();
        if let Some(session) = session {
            if let Err(e) =
                session.release_handoff_ticket_to_peer(group_id, target_device_id, lease_id).await
            {
                tracing::debug!(
                    error = %e,
                    group_id,
                    device_id,
                    target_device_id,
                    lease_id,
                    "could not send removed-device ticket release; TTL remains the backstop"
                );
            }
        }
    }

    /// Like [`Self::full_replica_handoff_ready_digest`], but also returns the
    /// device id of the specific peer that confirmed coverage — `None` for a
    /// vacuously-ready empty root set (there is no "the confirming peer" when
    /// nothing needed confirming). Used by call sites that need to name a
    /// concrete handoff TARGET for coordination-worker's role-loss commit
    /// endpoint (`crate::coordination_client::commit_handoff_role_loss`),
    /// not just a yes/no answer — currently only
    /// `control_socket::ensure_unlink_keeps_a_full_replica`. Only the
    /// non-excluding form is offered, matching `full_replica_handoff_ready_
    /// digest`'s own doc comment on why.
    pub async fn full_replica_handoff_ready_digest_and_peer(
        &self,
        group_id: &str,
    ) -> Option<([u8; 32], Option<String>)> {
        self.full_replica_handoff_ready(group_id, None).await
    }

    /// Shared implementation behind
    /// [`Self::another_full_replica_is_ready`],
    /// [`Self::another_full_replica_is_ready_excluding`],
    /// [`Self::full_replica_handoff_ready_digest`], and
    /// [`Self::full_replica_handoff_ready_digest_and_peer`]; see their doc
    /// comments for the semantics `excluded_device_id` (`None` for the
    /// non-excluding forms) adds. Returns the confirmed root-set digest (and,
    /// when a real peer confirmed it — `None` for the vacuously-ready empty
    /// root set — that peer's device id) on success, `None` if not ready.
    async fn full_replica_handoff_ready(
        &self,
        group_id: &str,
        excluded_device_id: Option<&str>,
    ) -> Option<([u8; 32], Option<String>)> {
        // Enumerate every durability root (current + retained superseded +
        // trash-restorable; see `SyncState::enumerate_group_durability_roots`)
        // once, up front, so each candidate peer is checked against the same
        // set. Fail closed if the enumeration itself errors.
        let roots = self.durability_roots_for_group(group_id)?;
        // Nothing to hand off — vacuously ready. Deliberately does NOT clear a
        // post-force `DurabilityUnknown` latch: an empty root set is not a
        // positive coverage confirmation (an all-deleted, retention-expired
        // group looks the same as one that genuinely never had files), so
        // clearing here could hide exactly the uncertainty the latch was set
        // to preserve. Only a real peer-confirmed whole-group hold below
        // clears it.
        if roots.roots.is_empty() {
            return Some((roots.digest, None));
        }
        let sessions: Vec<(String, Arc<PeerSyncSession>)> = self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(id, session)| (id.clone(), session.clone()))
            .collect();
        for (peer_id, session) in sessions {
            if excluded_device_id == Some(peer_id.as_str()) {
                continue;
            }
            if !self.peer_group_is_full_replica(&peer_id, group_id)
                || !self.peer_is_writer(&peer_id, group_id)
            {
                continue;
            }
            if self.peer_holds_entire_group(&peer_id, &session, group_id, &roots.roots).await {
                // A whole-group handoff target is confirmed again: any
                // post-force `DurabilityUnknown` latch for this group no
                // longer reflects reality, so clear it back toward
                // whatever the group's live sync state now derives to.
                if let Err(error) = self.clear_group_durability_latch(group_id) {
                    tracing::warn!(%error, group_id, "failed to clear persistent durability latch");
                }
                return Some((roots.digest, Some(peer_id)));
            }
        }
        None
    }

    /// This group's durability-root set — current + retained superseded +
    /// trash-restorable versions (`SyncState::enumerate_group_durability_
    /// roots`), plus its digest. `None` (fail closed) if the underlying
    /// enumeration errors.
    fn durability_roots_for_group(&self, group_id: &str) -> Option<DurabilityRoots> {
        self.sync_state.enumerate_group_durability_roots(group_id).ok()
    }

    /// Whether one specific peer — `peer_id`, reached over its own `session`
    /// — durably holds EVERY root in `roots` (the group's whole durability
    /// root set: current + retained superseded + trash-restorable versions,
    /// as `(path, change::VersionHash)` pairs). This is the per-peer counterpart to
    /// [`Self::confirm_version_present_via_peer`]'s per-file/any-peer query:
    /// it pins one peer and requires that same peer to confirm the whole
    /// set, so a complete durable replica is proven, not a fragmentary one
    /// assembled across several incomplete peers.
    ///
    /// Fail-closed and authorization-guarded exactly like
    /// `confirm_version_present_via_peer`: for each root it captures the
    /// netmap-authorization generation before the round-trip and, after the
    /// reply, requires the generation unchanged AND the peer still an
    /// authorized full-replica writer — so a revoke/demote (or any
    /// membership churn) arriving mid-check fails the whole thing closed.
    /// Short-circuits on the first root this peer cannot confirm.
    ///
    /// Every root's `version_hash` is sent alongside its block hashes/sizes
    /// (see the loop below), but that alone does not protect against a peer
    /// whose `VersionPresentQuery` responder predates the exact-hash
    /// requirement: such a peer never looks at `version_hash` and answers
    /// on block-hash agreement alone, which is exactly the false-positive
    /// (two distinct versions sharing an identical block list, e.g. an
    /// mtime-only edit) this whole check exists to close. A peer must
    /// advertise `PeerSyncSession::version_hash_exact_negotiated` before it
    /// is ever asked a whole-group durability query at all; a peer that
    /// hasn't is skipped here rather than queried and trusted.
    async fn peer_holds_entire_group(
        &self,
        peer_id: &str,
        session: &Arc<PeerSyncSession>,
        group_id: &str,
        roots: &[DurabilityRoot],
    ) -> bool {
        if !session.version_hash_exact_negotiated() {
            return false;
        }
        for root in roots {
            let epoch_before = self.membership_generation();
            // Whole-group handoff: `for_handoff = true` lets the peer confirm a
            // root against any version it still retains (current OR retained
            // history), since a handoff must cover every durability root, not
            // just current heads.
            if !session
                .request_version_present(
                    group_id,
                    &root.path,
                    root.version_hash,
                    &root.blocks,
                    true,
                )
                .await
            {
                return false;
            }
            // Re-verify AFTER the reply: the peer must still be an authorized
            // full-replica writer, and the netmap-authorization view must not
            // have changed at all during the wait. Anything else fails closed
            // rather than trusting a now-stale ACK.
            if self.membership_generation() != epoch_before
                || !self.peer_group_is_full_replica(peer_id, group_id)
                || !self.peer_is_writer(peer_id, group_id)
            {
                return false;
            }
        }
        true
    }

    pub fn replace_group_policy_states(&self, states: HashMap<String, GroupPolicyState>) {
        *self.group_policy_states.lock().unwrap_or_else(|p| p.into_inner()) = states;
    }

    pub fn group_policy_state(&self, group_id: &str) -> Option<GroupPolicyState> {
        self.group_policy_states.lock().unwrap_or_else(|p| p.into_inner()).get(group_id).cloned()
    }

    /// Marks `group_id`'s policy state untrusted because its latest snapshot
    /// failed verification. Change admission for the group fails closed until
    /// [`clear_group_policy_stale`](Self::clear_group_policy_stale) resets it.
    /// Records the failure time; the caller logs the reason.
    pub fn mark_group_policy_stale(&self, group_id: &str) {
        self.stale_policy_groups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group_id.to_string(), now_unix());
        let sessions: Vec<_> =
            self.sessions.lock().unwrap_or_else(|p| p.into_inner()).values().cloned().collect();
        for session in sessions {
            session.revoke_group(group_id);
        }
    }

    /// Clears any stale marker for `group_id` — its policy snapshot verified
    /// again, so admission may resume trusting the verified history.
    pub fn clear_group_policy_stale(&self, group_id: &str) {
        self.stale_policy_groups.lock().unwrap_or_else(|p| p.into_inner()).remove(group_id);
    }

    /// Whether `group_id`'s policy state is currently untrusted (its last
    /// snapshot failed verification and no valid one has replaced it). Both
    /// the daemon's own verification failures and coordinator-flagged
    /// `policyInvalidGroupIds` funnel through `mark_group_policy_stale`, so
    /// this single predicate covers every "do not trust this group" source.
    pub fn is_group_policy_stale(&self, group_id: &str) -> bool {
        self.stale_policy_groups.lock().unwrap_or_else(|p| p.into_inner()).contains_key(group_id)
    }

    /// Whether this device has already been introduced to `group_id` — it is
    /// linked locally, or the netmap has named some peer as a writer for it.
    /// An introduced group that has no verified policy state loaded is not a
    /// genuinely policy-free group; it is one whose real policy this process
    /// has not resolved yet this run (the startup window before the netmap
    /// orchestrator's first fetch), so its authorization must fail closed
    /// rather than fall back to a placeholder stamp.
    fn group_is_introduced(&self, group_id: &str) -> bool {
        if self
            .peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .writers
            .iter()
            .any(|(_, gid)| gid.as_str() == group_id)
        {
            return true;
        }
        self.sync_state
            .list_links()
            .map(|links| links.iter().any(|link| link.group_id == group_id))
            .unwrap_or(false)
    }

    /// The single group-policy/authorization resolution point that every
    /// staleness source funnels through, so both local emission
    /// (`DaemonState::new`'s local-change auth provider) and inbound admission
    /// (`NetmapChangeAuthenticator::accepts_change_auth`) fail closed on the
    /// same conditions instead of each re-deriving the `None`/stale handling
    /// ad hoc:
    ///
    /// - own-verification-stale or coordinator-flagged invalid (both recorded
    ///   via [`mark_group_policy_stale`](Self::mark_group_policy_stale)) →
    ///   [`Withhold`](GroupPolicyResolution::Withhold);
    /// - a verified snapshot is loaded →
    ///   [`Verified`](GroupPolicyResolution::Verified);
    /// - no verified snapshot, not stale, but the group is already introduced
    ///   (linked or a known writer exists) → the policy simply has not loaded
    ///   yet this run → [`Withhold`](GroupPolicyResolution::Withhold);
    /// - otherwise the genuine pre-policy bootstrap window (never introduced,
    ///   no snapshot has ever existed) → [`Bootstrap`](GroupPolicyResolution::Bootstrap),
    ///   where the placeholder stamp is still legitimate on both sides.
    pub fn resolve_group_policy(&self, group_id: &str) -> GroupPolicyResolution {
        if self.is_group_policy_stale(group_id) {
            return GroupPolicyResolution::Withhold;
        }
        if let Some(policy) = self.group_policy_state(group_id) {
            return GroupPolicyResolution::Verified(policy);
        }
        if self.group_is_introduced(group_id) {
            GroupPolicyResolution::Withhold
        } else {
            GroupPolicyResolution::Bootstrap
        }
    }

    /// Graceful shutdown: blocks until no `broadcast_change`
    /// call is in flight, or `timeout` elapses,
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

    /// Call around any sync-critical
    /// write (folder scan/flush processing in `link_manager.rs`,
    /// materialization writes in `hydration.rs`) so
    /// `is_write_safe_point` reports `false` for its duration. Public (not
    /// just crate-visible) since both call sites are in sibling modules
    /// of this same crate but need the exact same guard type
    /// `broadcast_change`'s own private `begin_broadcast` uses internally.
    pub fn begin_write_activity(&self) -> WriteActivityGuard<'_> {
        let liveness = self.block_liveness_gate.begin_reference_write();
        self.active_write_ops.fetch_add(1, Ordering::SeqCst);
        // Every existing call site of this
        // guard (the local-change flush executor in `link_manager.rs`,
        // hydration's hydrate/evict/restore paths in `hydration.rs`) is
        // exactly the "local-change/hydration activity" the GC idle
        // scheduler needs to know about.
        self.record_activity();
        WriteActivityGuard { counter: &self.active_write_ops, _liveness: liveness }
    }

    pub(crate) fn begin_block_deletion(&self) -> BlockPhysicalDeletionGuard<'_> {
        self.block_liveness_gate.begin_physical_deletion()
    }

    pub(crate) fn block_liveness_gate(&self) -> &BlockLivenessGate {
        &self.block_liveness_gate
    }

    /// Marks "now" as the most recent
    /// local-change/peer-reconciliation/hydration activity — see
    /// `last_activity_unix`'s doc comment for its two call sites.
    pub fn record_activity(&self) {
        self.last_activity_unix.store(now_unix(), Ordering::SeqCst);
    }

    /// How long it's been since the most
    /// recent recorded activity — the GC idle scheduler's own condition is
    /// exactly `idle_duration >= gc::GC_IDLE_THRESHOLD`.
    pub fn idle_duration(&self) -> Duration {
        let last = self.last_activity_unix.load(Ordering::SeqCst);
        Duration::from_secs(now_unix().saturating_sub(last).max(0) as u64)
    }

    /// Test-only escape hatch: production code only ever calls
    /// `record_activity` (always "now"); tests simulating having been
    /// idle for a while need to set an arbitrary past timestamp directly,
    /// without literally waiting out `gc::GC_IDLE_THRESHOLD`.
    #[cfg(test)]
    pub(crate) fn set_last_activity_unix_for_test(&self, unix: i64) {
        self.last_activity_unix.store(unix, Ordering::SeqCst);
    }

    /// Per the "Safe Update Timing" decision: `true` exactly when no
    /// sync-critical write is currently in progress — the sole condition
    /// `update_ipc::install`/the periodic install-safe-point check
    ///  uses to decide whether to proceed or defer.
    pub fn is_write_safe_point(&self) -> bool {
        self.active_write_ops.load(Ordering::SeqCst) <= 0
    }

    /// Wall-clock time elapsed
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

    /// Health surface: records whether essential task `name` is
    /// currently running, from the outside (`main.rs` owns the essential
    /// `JoinSet`/supervision itself; this is just where the result
    /// is published for `control_socket`'s health handler to read).
    pub fn set_task_alive(&self, name: &str, alive: bool) {
        self.task_liveness
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(name.to_string(), alive);
    }

    /// Propagates a batch of just-committed file records to every peer
    /// that shares `group_id` (see `peer_session::PeerSyncSession::shares_group`
    /// for why this filter matters, not just efficiency). A no-op for an
    /// empty batch.
    ///
    /// Every peer gets an immediate authoritative heads announce
    /// (`announce_local_commit`) so it learns the new commit right away.
    /// Without this the peer would not see the new heads until the next
    /// periodic heads re-announce (a reconnect or the periodic audit),
    /// which can lag a local commit by over a minute. The announce makes
    /// the peer pull exactly the ancestry it lacks.
    ///
    /// A failed announce is only logged: the periodic audit re-announces
    /// heads, so the peer still converges — the same warn-only handling
    /// every other heads announce uses, with no per-commit retry queue.
    /// `records` is therefore only used to decide that there is anything
    /// to announce at all; the DAG commit itself is already durable before
    /// this is called, and the heads announce carries no file payload.
    pub async fn broadcast_change(
        &self,
        group_id: &str,
        records: Vec<yadorilink_sync_core::types::FileRecord>,
    ) {
        if records.is_empty() {
            return;
        }
        let _in_flight = self.begin_broadcast(); // let shutdown wait for this to finish
        let sessions: Vec<(String, Arc<PeerSyncSession>)> = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(id, s)| (id.clone(), s.clone()))
            .collect();
        for (peer_id, session) in sessions {
            if !session.shares_group(group_id) {
                continue;
            }
            if let Err(e) = session.announce_local_commit(group_id).await {
                tracing::warn!(
                    error = %e,
                    peer = %peer_id,
                    "failed to announce local commit heads to peer; \
                     will converge on next periodic audit"
                );
            }
        }
    }
}

/// Bridges an incoming peer-to-peer `HandoffLeaseRequest` (`peer_session.rs`)
/// to this device's own target-side lease machinery
/// ([`DaemonState::request_handoff_lease`]) — installed onto every
/// constructed session via `PeerSyncSession::set_handoff_lease_responder`
/// (`peer_orchestrator.rs`), the same "daemon injects real behavior into a
/// session" shape `PendingLocalChangeFlush for DaemonState` uses
/// (`link_manager.rs`). `self.request_handoff_lease(group_id)` below resolves
/// to the inherent method of the same name (Rust always prefers an inherent
/// method over a trait method of the same name on the same receiver type),
/// not a recursive call into this trait method.
impl HandoffLeaseResponder for DaemonState {
    fn request_handoff_lease<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>> {
        Box::pin(async move {
            let (grant, root_digest) = self.request_handoff_lease(group_id).await?;
            Some(PeerHandoffLeaseGrant {
                lease_id: grant.lease_id,
                root_digest,
                expires_at_unix: grant.expires_at_unix,
            })
        })
    }

    fn release_handoff_lease<'a>(
        &'a self,
        group_id: &'a str,
        lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move { self.release_owned_handoff_lease(group_id, lease_id).await })
    }
}

/// Bridges an incoming peer-to-peer `HandoffTicketRequest` (`peer_session.
/// rs`) -- sent by a DIFFERENT device (X) that is removing/revoking THIS
/// device -- to this device's own removed-device-ticket machinery
/// ([`DaemonState::obtain_own_handoff_ticket`]) -- installed onto every
/// constructed session via `PeerSyncSession::set_handoff_ticket_responder`
/// (`peer_orchestrator.rs`), the same shape `HandoffLeaseResponder for
/// DaemonState` above uses. `self.obtain_own_handoff_ticket(group_id)` below
/// resolves to the inherent method of the same name, not a recursive call
/// into this trait method.
impl HandoffTicketResponder for DaemonState {
    fn request_handoff_ticket<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>> {
        Box::pin(async move { self.obtain_own_handoff_ticket(group_id).await })
    }

    fn release_handoff_ticket<'a>(
        &'a self,
        group_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let session = self
                .sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(target_device_id)
                .cloned();
            if let Some(session) = session {
                if let Err(e) = session.release_handoff_lease_to_peer(group_id, lease_id).await {
                    tracing::debug!(
                        error = %e,
                        group_id,
                        target_device_id,
                        lease_id,
                        "could not forward removed-device ticket release; TTL remains the backstop"
                    );
                }
            }
        })
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

    #[tokio::test]
    async fn custody_stamp_revalidation_rejects_wrong_peer_generation_change_and_demotion() {
        let state = test_state();
        state.set_peer_group_writer("peer-b", "group-a", true);
        state.set_peer_group_full_replica("peer-b", "group-a", true);
        let confirmer = P2pCustodyConfirmer { state: Arc::downgrade(&state) };
        let stamp = CustodyStamp::new("peer-b".into(), state.membership_generation());

        assert!(confirmer.confirmation_still_valid("group-a", &stamp));
        assert!(!confirmer.confirmation_still_valid(
            "group-a",
            &CustodyStamp::new("peer-c".into(), stamp.membership_generation())
        ));

        state.set_peer_group_writer("peer-c", "unrelated-group", true);
        assert!(!confirmer.confirmation_still_valid("group-a", &stamp));

        let current_stamp = CustodyStamp::new("peer-b".into(), state.membership_generation());
        assert!(confirmer.confirmation_still_valid("group-a", &current_stamp));
        state.set_peer_group_full_replica("peer-b", "group-a", false);
        assert!(!confirmer.confirmation_still_valid("group-a", &current_stamp));
    }

    // --- Mandatory handoff-lease digest-match decision (source side) ----

    /// The safety property this whole mechanism exists for: a target's
    /// grant whose attested `root_digest` matches the source's own current
    /// digest yields the lease id, so the source may present it.
    #[test]
    fn handoff_lease_grant_digest_match_yields_the_lease_id() {
        let digest = [7u8; 32];
        let grant = PeerHandoffLeaseGrant {
            lease_id: "lease-abc".to_string(),
            root_digest: digest,
            expires_at_unix: 12345,
        };
        assert_eq!(
            handoff_lease_grant_matches_digest(&grant, digest),
            Some("lease-abc".to_string())
        );
    }

    /// A digest MISMATCH must decline (`None`), never yield a lease id --
    /// the target attested a different root set than what this device
    /// currently holds, so the lease does not cover it. This is exactly the
    /// case the caller must treat as "do not relinquish the local role."
    #[test]
    fn handoff_lease_grant_digest_mismatch_declines() {
        let mut other_digest = [7u8; 32];
        other_digest[0] = 8;
        let grant = PeerHandoffLeaseGrant {
            lease_id: "lease-abc".to_string(),
            root_digest: other_digest,
            expires_at_unix: 12345,
        };
        assert_eq!(handoff_lease_grant_matches_digest(&grant, [7u8; 32]), None);
    }

    // --- Degraded-link state tests ----

    /// a link enters Degraded on disk pressure — `is_link_degraded`
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

    /// a link leaves Degraded once cleared — the mirror case,
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

    /// Repeated disk pressure on the same link produces
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

    /// a Degraded link recovers once its volume's free-space
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

    /// the mirror case — a link stays Degraded (rescheduled with
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

    // --- Interrupted-update
    // recovery is wired into the exact same daemon-startup entry point
    // (`DaemonState::new`, the one `main.rs` calls before any watcher
    // resumes or any control-socket request can arrive) as the
    // `cleanup_stale_temp_files`/`repair_interrupted_materializations`
    // calls. `UpdateManager::recover_on_startup` already has its own unit
    // tests (`update::manager::tests::recover_on_startup_*`); these two
    // tests instead go through the real `DaemonState::new` used
    // by `main.rs`, with the on-disk `update_policy.json`/artifact state
    // written exactly as a crash would leave it (matching the
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

    #[tokio::test]
    async fn release_owned_handoff_lease_releases_local_pin_and_worker_lease() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let state = test_state();
        let server = MockServer::start().await;
        state.set_coordination_client_config(server.uri(), "test-token".into());
        state
            .sync_state
            .record_handoff_lease(
                "group-release",
                "lease-release",
                [9u8; 32],
                &[],
                now_unix(),
                now_unix() + 900,
            )
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/shares/groups/group-release/handoff/lease/lease-release/release"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        state.release_owned_handoff_lease("group-release", "lease-release").await;

        let leases = state.sync_state.list_handoff_leases_for_group("group-release").unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].state, HandoffLeaseState::Released);
    }

    /// The digest-mismatch abort path: if the group's durability-root set
    /// changes between the readiness digest `request_handoff_lease` captures
    /// up front and the atomic local pin that follows the coordination-worker
    /// round trip, the mismatch must be caught, both halves of the
    /// now-meaningless lease released, and `None` returned — never a lease
    /// that claims to pin a set it no longer actually matches. The mismatch
    /// is engineered deterministically, not via a timing race: the mock
    /// coordination-worker handler below only runs once the real HTTP
    /// request has actually been sent — which is strictly after
    /// `full_replica_handoff_ready_digest` already ran synchronously earlier
    /// in `request_handoff_lease` — and it inserts a new file into the group
    /// before answering, so the atomic pin that follows the response
    /// re-enumerates a set the readiness check never saw.
    #[tokio::test]
    async fn request_handoff_lease_aborts_and_releases_both_pins_on_a_digest_mismatch() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};
        use yadorilink_sync_core::version_vector::VersionVector;

        let state = test_state();
        let server = MockServer::start().await;
        state.set_coordination_client_config(server.uri(), "test-token".into());

        let sync_state_for_handler = state.sync_state.clone();
        Mock::given(method("POST"))
            .and(path("/shares/groups/group-1/handoff/lease"))
            .respond_with(move |_req: &Request| {
                let mut version = VersionVector::new();
                version.increment("device-b");
                sync_state_for_handler
                    .upsert_file_with_origin(
                        "group-1",
                        &FileRecord {
                            path: "b.txt".to_string(),
                            size: 5,
                            mtime_unix_nanos: 0,
                            version,
                            blocks: vec![],
                            deleted: false,
                        },
                        "device-b",
                    )
                    .unwrap();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "leaseId": "lease-xyz",
                    "expiresAt": now_unix() + 900,
                    "ttlSeconds": 900,
                }))
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/shares/groups/group-1/handoff/lease/lease-xyz/release"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        // `group-1` starts EMPTY, so `full_replica_handoff_ready_digest`'s
        // check is vacuously satisfied (an empty root set needs no
        // confirming peer) — the readiness digest captured here is the
        // empty-set digest, before the mock handler above adds `b.txt`.
        let grant = state.request_handoff_lease("group-1").await;

        assert!(
            grant.is_none(),
            "a digest mismatch between attestation and atomic pin must decline, not grant"
        );

        // The local pin must have been written (provisionally) and then
        // explicitly released, not left dangling as a live-looking
        // 'provisional' row.
        let local_leases = state.sync_state.list_handoff_leases_for_group("group-1").unwrap();
        assert_eq!(local_leases.len(), 1);
        assert_eq!(local_leases[0].lease_id, "lease-xyz");
        assert_eq!(local_leases[0].state, HandoffLeaseState::Released);

        // The coordination-worker's copy must have been released too — the
        // release endpoint (and only it, once) was actually called.
        let requests = server.received_requests().await.unwrap();
        let release_calls = requests
            .iter()
            .filter(|r| r.url.path() == "/shares/groups/group-1/handoff/lease/lease-xyz/release")
            .count();
        assert_eq!(
            release_calls, 1,
            "the Worker-side lease must be explicitly released exactly once"
        );
    }

    /// The symmetric-cleanup path: if the atomic LOCAL pin errors AFTER the
    /// Worker has already granted the lease, `request_handoff_lease` must
    /// still attempt to release the Worker-side lease (so it does not sit
    /// granted with no local pin until its TTL) and return `None`, exactly
    /// like the digest-mismatch abort. The local storage error is forced
    /// deterministically: the sync database is file-backed, and a second
    /// connection drops the `handoff_leases` table between the Worker POST
    /// (mocked to succeed) and the atomic pin's `INSERT` into that table, so
    /// the pin fails with a genuine storage error while the durability-root
    /// enumeration that precedes it still reads the intact `files` table.
    #[tokio::test]
    async fn request_handoff_lease_releases_the_worker_lease_when_the_local_pin_fails() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("sync.db");
        let sync_state = Arc::new(SyncState::open(&db_path).unwrap());
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);

        let server = MockServer::start().await;
        state.set_coordination_client_config(server.uri(), "test-token".into());

        // The POST handler drops `handoff_leases` out from under the pool via
        // an independent connection to the same file before answering, so the
        // atomic pin's INSERT that follows the response hits a genuine "no
        // such table" storage error. `files` is untouched, so the
        // enumeration inside the atomic call still succeeds — only the pin
        // write fails, which is exactly the post-POST error path under test.
        let db_path_for_handler = db_path.clone();
        Mock::given(method("POST"))
            .and(path("/shares/groups/group-1/handoff/lease"))
            .respond_with(move |_req: &Request| {
                let conn = rusqlite::Connection::open(&db_path_for_handler).unwrap();
                conn.execute("DROP TABLE handoff_leases", []).unwrap();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "leaseId": "lease-xyz",
                    "expiresAt": now_unix() + 900,
                    "ttlSeconds": 900,
                }))
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/shares/groups/group-1/handoff/lease/lease-xyz/release"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let grant = state.request_handoff_lease("group-1").await;

        assert!(
            grant.is_none(),
            "a failed local pin after a granted lease must decline, not grant"
        );

        // The Worker-side lease must have been released best-effort, even
        // though the local pin never landed.
        let requests = server.received_requests().await.unwrap();
        let release_calls = requests
            .iter()
            .filter(|r| r.url.path() == "/shares/groups/group-1/handoff/lease/lease-xyz/release")
            .count();
        assert_eq!(
            release_calls, 1,
            "a local-pin error after a granted lease must still release the Worker lease"
        );
    }

    /// The clock-skew bug this change closes, end to end: a coordination
    /// Worker whose clock runs BEHIND this target device's own is simulated
    /// by mocking a grant whose absolute `expiresAt` already reads as being
    /// in the past relative to this device's own clock, alongside a normal,
    /// still-valid `ttlSeconds`. Before the fix, `request_handoff_lease`
    /// stored that stale absolute value verbatim as the local pin deadline,
    /// so the very next local retention sweep would have dropped the pin
    /// immediately -- reopening the GC race the lease exists to close. After
    /// the fix, the local pin is derived from this device's own clock plus
    /// `ttlSeconds` (plus the fixed safety margin) and is unaffected by the
    /// Worker's stale absolute value.
    #[tokio::test]
    async fn request_handoff_lease_pins_locally_from_this_devices_own_clock_even_when_the_workers_absolute_expiry_is_already_stale(
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let state = test_state();
        let server = MockServer::start().await;
        state.set_coordination_client_config(server.uri(), "test-token".into());

        let ttl_seconds = 900i64;
        Mock::given(method("POST"))
            .and(path("/shares/groups/group-1/handoff/lease"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "leaseId": "lease-skewed",
                // Already in the past relative to this device's own clock --
                // simulating a coordination Worker whose clock runs behind
                // this target's. Under the pre-fix behavior (storing this
                // verbatim as the local pin deadline) the local pin would
                // already read as expired the instant it lands.
                "expiresAt": now_unix() - 10_000,
                "ttlSeconds": ttl_seconds,
            })))
            .mount(&server)
            .await;

        // `group-1` starts empty, so the readiness check is vacuously
        // satisfied (see the digest-mismatch test above) -- what is under
        // test here is the local pin deadline arithmetic, not readiness.
        let local_now_before_request = now_unix();
        let (grant, _root_digest) = state
            .request_handoff_lease("group-1")
            .await
            .expect("an empty root set is vacuously ready; the grant must still be produced");
        let local_now_after_request = now_unix();
        assert_eq!(grant.ttl_seconds, ttl_seconds);

        let leases = state.sync_state.list_handoff_leases_for_group("group-1").unwrap();
        assert_eq!(leases.len(), 1);
        let recorded = &leases[0];
        assert_eq!(recorded.lease_id, "lease-skewed");

        // The recorded LOCAL expiry must not already be in the past just
        // because the Worker's absolute `expiresAt` was stale -- it must sit
        // close to this device's own now + ttl (+ the fixed safety margin).
        let earliest_local_now = local_now_before_request.min(local_now_after_request);
        let latest_local_now = local_now_before_request.max(local_now_after_request);
        assert!(
            recorded.expires_at_unix > latest_local_now,
            "the local pin must not read as already expired just because the Worker's absolute \
             expiresAt was stale relative to this device's own clock"
        );
        let earliest_deadline =
            earliest_local_now + ttl_seconds + SyncState::HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS;
        let latest_deadline =
            latest_local_now + ttl_seconds + SyncState::HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS;
        assert!(
            recorded.expires_at_unix >= earliest_deadline - 5
                && recorded.expires_at_unix <= latest_deadline + 5,
            "the local pin deadline must equal this device's own now + ttlSeconds (+ a fixed \
             safety margin), not the Worker's stale absolute expiresAt; got {}, expected in {}..={}",
            recorded.expires_at_unix,
            earliest_deadline,
            latest_deadline
        );
    }

    /// Trust-boundary fail-closed: a coordination grant carrying a
    /// non-positive `ttlSeconds` (a buggy/hostile response the current Worker
    /// never emits) must be rejected -- `request_handoff_lease` returns
    /// `None`, records NO local pin, and best-effort releases the Worker-side
    /// lease -- rather than deriving a too-short local deadline that would
    /// lapse immediately and reopen the GC race. Checked for both a zero and
    /// a negative TTL.
    #[tokio::test]
    async fn request_handoff_lease_rejects_a_non_positive_worker_ttl_and_records_no_pin() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for bad_ttl in [0i64, -30] {
            let state = test_state();
            let server = MockServer::start().await;
            state.set_coordination_client_config(server.uri(), "test-token".into());

            Mock::given(method("POST"))
                .and(path("/shares/groups/group-1/handoff/lease"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "leaseId": "lease-badttl",
                    "expiresAt": now_unix() + 900,
                    "ttlSeconds": bad_ttl,
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/shares/groups/group-1/handoff/lease/lease-badttl/release"))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;

            // `group-1` starts empty -> readiness is vacuously satisfied, so
            // the request reaches the TTL boundary check under test.
            let grant = state.request_handoff_lease("group-1").await;
            assert!(
                grant.is_none(),
                "a non-positive Worker ttl ({bad_ttl}) must decline, not grant"
            );

            // No local pin was written for the rejected grant.
            let local_leases = state.sync_state.list_handoff_leases_for_group("group-1").unwrap();
            assert!(
                local_leases.is_empty(),
                "a rejected non-positive-ttl grant must record no local pin"
            );

            // The Worker-side lease was released best-effort exactly once.
            let requests = server.received_requests().await.unwrap();
            let release_calls = requests
                .iter()
                .filter(|r| {
                    r.url.path() == "/shares/groups/group-1/handoff/lease/lease-badttl/release"
                })
                .count();
            assert_eq!(
                release_calls, 1,
                "a rejected non-positive-ttl grant must still release the Worker lease"
            );
        }
    }

    // --- Removed-device handoff ticket (Stage C) -------------------------

    /// An empty root set is vacuously ready and needs no lease -- the
    /// responder half must grant a ticket with no `lease_id`, not decline
    /// just because there is no confirming peer to ask (there is nothing to
    /// hand off in the first place). No session/coordination config needed
    /// at all for this case.
    #[tokio::test]
    async fn own_ticket_for_an_empty_root_set_is_granted_with_no_lease_id() {
        let state = test_state();
        let grant = state
            .obtain_own_handoff_ticket("empty-group")
            .await
            .expect("an empty root set is vacuously ready and must still grant a ticket");
        assert_eq!(grant.lease_id, None);
        assert_eq!(grant.target_device_id, None);
    }

    /// `obtain_handoff_ticket_from_device` is the OFFLINE-detection seam: no
    /// live session for the named device (this daemon has never connected
    /// to it, or the connection already tore down) must fail closed
    /// immediately, with no timeout and no attempt to attest anything --
    /// this is exactly what routes an offline removed device to the
    /// existing #3 interim in `durability_force.rs`.
    #[tokio::test]
    async fn obtain_ticket_from_an_unreachable_device_is_none() {
        let state = test_state();
        assert!(
            state.obtain_handoff_ticket_from_device("group-1", "device-b").await.is_none(),
            "no live session for the target device must be treated as offline/unreachable"
        );
    }

    #[tokio::test]
    async fn forced_durability_unknown_latch_survives_daemon_restart() {
        let database_dir = tempfile::tempdir().unwrap();
        let database_path = database_dir.path().join("sync-state.sqlite");
        let before_restart = SyncState::open(&database_path).unwrap();
        before_restart.latch_group_durability_unknown("group-1").unwrap();
        drop(before_restart);

        let restarted_store_dir = tempfile::tempdir().unwrap();
        let restarted = DaemonState::new(
            "device-a".into(),
            Arc::new(SyncState::open(&database_path).unwrap()),
            Arc::new(FsBlockStore::new(restarted_store_dir.path()).unwrap()),
        );

        assert_eq!(
            restarted.group_durability_status("group-1"),
            GroupDurabilityStatus::DurabilityUnknown,
            "force history must remain latched after reopening the durable index"
        );
        restarted.clear_group_durability_latch("group-1").unwrap();
        let after_clear = SyncState::open(&database_path).unwrap();
        assert!(after_clear.list_durability_unknown_latches().unwrap().is_empty());
    }

    // --- Startup-window placeholder-auth race (watcher before policy load) ---
    //
    // `app::run` resumes every already-linked folder's filesystem watcher
    // (`link_manager::start_link_watch`, driven by `sync_state.list_links()`)
    // before it spawns the peer/netmap orchestrator task that eventually
    // calls `replace_group_policy_states`. Until that first netmap fetch
    // completes, `group_policy_state(group_id)` is `None` for every group —
    // including one that already has real, established policy elsewhere in
    // the swarm and is only missing it locally because this process just
    // started. The local-emission auth provider registered below
    // (`DaemonState::new`) cannot tell that case apart from a group that has
    // never had any policy at all, and falls back to `ChangeAuth::PLACEHOLDER`
    // for both.

    /// A local edit for an *already-linked* group (so it is exactly the set
    /// of groups `app::run`'s watcher-resume loop restarts synchronously,
    /// before the orchestrator task is even spawned) must not be committed to
    /// the DAG with a placeholder authorization stamp while this process has
    /// not yet resolved the group's real policy state — the same withholding
    /// the group's *stale*-policy case already gets (see
    /// `local_change::stale_policy_withholds_the_dag_change_but_keeps_the_path_journaled_dirty`
    /// in `yadorilink-sync-core`). A peer that already holds the group's real
    /// policy accepts a placeholder-auth change only when its own policy
    /// chain is empty (`GroupPolicyState::author_was_writer_at`); a group with
    /// real history elsewhere fails that check on every such peer, so the
    /// change just committed here can never replicate — and neither can
    /// anything chained on top of it, since the DAG is hash-linked.
    ///
    /// This currently fails: nothing distinguishes "never had policy" from
    /// "policy not loaded by this process yet", so the provider takes the
    /// same `unwrap_or(ChangeAuth::PLACEHOLDER)` branch either way and the
    /// change lands in the DAG.
    #[tokio::test]
    async fn local_edit_before_policy_load_must_not_enter_the_dag_with_a_placeholder_stamp_for_an_already_linked_group(
    ) {
        use yadorilink_sync_core::change::{FileMeta, Op, SyncPath};
        use yadorilink_sync_core::dag_store::ChangeEmitter;
        use yadorilink_sync_core::types::RecordKind;
        use yadorilink_sync_core::version_vector::VersionVector;

        let state = test_state();
        let group = "group-1";

        // The group is already linked locally -- exactly the precondition
        // `app::run` checks (`sync_state.list_links()`) before resuming its
        // watcher ahead of the orchestrator. A brand-new group being shared
        // for the first time never reaches this state before its own policy
        // is established, so this precondition is what separates "existing
        // group, not loaded yet" from "genuinely policy-free group".
        state.sync_state.add_link("/links/photos", group).unwrap();

        // The startup-gap precondition: the orchestrator has not completed
        // its first netmap fetch, so nothing has populated policy state for
        // this group, and — distinct from the case
        // `is_group_policy_stale` guards — it is not marked stale either.
        assert!(state.group_policy_state(group).is_none());
        assert!(!state.is_group_policy_stale(group));

        // A local edit races ahead of that fetch, through the daemon's real
        // local-emission auth provider (the one `DaemonState::new` registers
        // on `sync_state`), exactly as a live watcher callback would drive it.
        let emitter =
            ChangeEmitter::new("device-a", ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]));
        let version = yadorilink_sync_core::change::FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        let mut vv = VersionVector::new();
        vv.increment("device-a");
        let record = FileRecord {
            path: "note.txt".into(),
            size: 0,
            mtime_unix_nanos: 0,
            version: vv,
            blocks: vec![],
            deleted: false,
        };

        let result = state.sync_state.upsert_file_emitting_change(
            group,
            &record,
            "device-a",
            vec![Op::Create { path: SyncPath("note.txt".into()), version: version.version_hash }],
            &[version],
            None,
            &emitter,
        );

        // The fix: an already-linked group's policy merely being unresolved
        // since startup must not be treated like a genuinely policy-free group
        // and stamped PLACEHOLDER. The unified resolver reports it `Withhold`
        // (introduced-but-not-loaded-yet), so local emission fails closed with
        // `PolicyUnavailable` — withheld exactly like the stale-policy case
        // (`local_change::stale_policy_withholds_...`), keeping the edit
        // journaled dirty to re-emit with a real authorization context once
        // the group's real policy loads, rather than landing a placeholder
        // stamp every valid-policy peer rejects.
        assert!(
            matches!(result, Err(yadorilink_sync_core::SyncError::PolicyUnavailable)),
            "local emission for an already-linked, policy-not-yet-loaded group must withhold \
             (PolicyUnavailable), not stamp a placeholder-auth change; got {result:?}"
        );
        assert!(
            state.sync_state.dag_group_heads(group).unwrap().is_empty(),
            "an already-linked group whose policy state has not loaded yet this run must not get \
             a placeholder-auth change committed to its DAG"
        );
    }
}
